// Package certwatcher provides a Caddy TLS certificate manager module that
// watches certificate and key files on disk via fsnotify, and serves the
// latest certificate during TLS handshakes without requiring a config reload.
//
// This is particularly useful in Kubernetes environments where cert-manager
// rotates certificates by atomically swapping symlinks in projected volumes.
//
// NOTE: The self-healing watcher, debounce, and poll infrastructure here
// intentionally duplicates similar code in the filewatcher package. Both
// modules live in different Caddy module namespaces with fundamentally different
// interfaces and event semantics, so we keep them independent for clarity
// rather than introducing a shared abstraction.
//
// # Module ID
//
// tls.get_certificate.file
//
// # Caddyfile Usage
//
//	:9443 {
//	    tls {
//	        get_certificate file {
//	            cert /mnt/serving-cert/tls.crt
//	            key  /mnt/serving-cert/tls.key
//	        }
//	    }
//	}
package certwatcher

import (
	"context"
	"crypto/tls"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(new(FileWatcher))
}

// FileWatcher is a Caddy TLS certificate manager that watches cert/key files
// and serves the latest version from memory during TLS handshakes.
type FileWatcher struct {
	// Path to the PEM-encoded certificate file.
	CertFile string `json:"cert_file"`

	// Path to the PEM-encoded private key file.
	KeyFile string `json:"key_file"`

	// How long to wait after the last filesystem event before reloading
	// the certificate. Kubernetes symlink rotation produces multiple events;
	// debouncing avoids redundant reloads.
	// Default: 5s
	Debounce caddy.Duration `json:"debounce,omitempty"`

	// How often to re-read the certificate files as a fallback for missed
	// fsnotify events. Kubernetes symlink swaps can occasionally be missed.
	// Default: 5m. Set to 0 in Caddyfile to disable polling.
	Poll caddy.Duration `json:"poll,omitempty"`

	cert     atomic.Pointer[tls.Certificate]
	logger   *zap.Logger
	stop     chan struct{}
	stopOnce sync.Once
}

// CaddyModule returns the Caddy module information.
func (*FileWatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.file",
		New: func() caddy.Module { return new(FileWatcher) },
	}
}

// Provision validates configuration, loads the initial certificate, and starts
// the filesystem watcher goroutine.
func (fw *FileWatcher) Provision(ctx caddy.Context) error {
	fw.logger = ctx.Logger()
	fw.stop = make(chan struct{})

	if fw.CertFile == "" {
		return fmt.Errorf("cert_file is required")
	}
	if fw.KeyFile == "" {
		return fmt.Errorf("key_file is required")
	}
	if fw.Debounce == 0 {
		fw.Debounce = caddy.Duration(5 * time.Second)
	}
	if fw.Poll == 0 {
		fw.Poll = caddy.Duration(5 * time.Minute)
	}

	if err := fw.loadCert(); err != nil {
		return fmt.Errorf("loading initial certificate: %v", err)
	}

	watcher, err := fw.createWatcher()
	if err != nil {
		return fmt.Errorf("creating fsnotify watcher: %v", err)
	}

	go fw.watchLoop(watcher)

	if time.Duration(fw.Poll) > 0 {
		go fw.pollLoop()
	}

	return nil
}

// GetCertificate returns the most recently loaded certificate. It is called
// by Caddy during every TLS handshake.
func (fw *FileWatcher) GetCertificate(_ context.Context, _ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := fw.cert.Load()
	if cert == nil {
		return nil, fmt.Errorf("no certificate loaded")
	}
	return cert, nil
}

// Cleanup signals the watcher goroutine to stop.
func (fw *FileWatcher) Cleanup() error {
	fw.stopOnce.Do(func() { close(fw.stop) })
	return nil
}

func (fw *FileWatcher) loadCert() error {
	cert, err := tls.LoadX509KeyPair(fw.CertFile, fw.KeyFile)
	if err != nil {
		return err
	}
	fw.cert.Store(&cert)
	return nil
}

func (fw *FileWatcher) createWatcher() (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// Watch the parent directories rather than individual files.
	// Kubernetes rotates projected volumes via atomic symlink replacement
	// in the parent directory; watching a file directly would lose the watch.
	dirs := uniqueDirs(fw.CertFile, fw.KeyFile)
	for _, dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()
			return nil, fmt.Errorf("watching directory %q: %v", dir, err)
		}
	}

	return watcher, nil
}

// watchLoop processes fsnotify events and self-heals if the watcher closes
// unexpectedly. The initial watcher is passed from Provision() to avoid a
// race between goroutine launch and event delivery.
func (fw *FileWatcher) watchLoop(initialWatcher *fsnotify.Watcher) {
	const maxBackoff = 30 * time.Second
	backoff := 1 * time.Second
	watcher := initialWatcher

	fw.logger.Info("watching for certificate changes",
		zap.String("cert", fw.CertFile),
		zap.String("key", fw.KeyFile),
		zap.Duration("debounce", time.Duration(fw.Debounce)),
		zap.Duration("poll", time.Duration(fw.Poll)))

	for {
		exited := fw.runWatcher(watcher)
		watcher.Close() //nolint:errcheck

		if exited {
			return
		}

		fw.logger.Warn("fsnotify watcher closed unexpectedly, recreating",
			zap.Duration("backoff", backoff))

		for {
			select {
			case <-fw.stop:
				return
			case <-time.After(backoff):
			}

			var err error
			watcher, err = fw.createWatcher()
			if err != nil {
				fw.logger.Error("failed to recreate fsnotify watcher, retrying",
					zap.Error(err), zap.Duration("backoff", backoff))
				backoff = min(backoff*2, maxBackoff)
				continue
			}

			fw.logger.Info("fsnotify watcher recreated successfully")
			backoff = 1 * time.Second
			break
		}
	}
}

func (fw *FileWatcher) runWatcher(watcher *fsnotify.Watcher) bool {
	var debounceTimer *time.Timer
	debounceCh := make(chan struct{}, 1)

	for {
		select {
		case <-fw.stop:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return true

		case event, ok := <-watcher.Events:
			if !ok {
				return false
			}
			fw.logger.Debug("fsnotify event", zap.String("event", event.String()))
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(time.Duration(fw.Debounce), func() {
				select {
				case debounceCh <- struct{}{}:
				default:
				}
			})

		case err, ok := <-watcher.Errors:
			if !ok {
				return false
			}
			fw.logger.Error("fsnotify error", zap.Error(err))

		case <-debounceCh:
			if err := fw.loadCert(); err != nil {
				fw.logger.Error("failed to reload certificate", zap.Error(err))
			} else {
				fw.logger.Info("certificate reloaded successfully")
			}
		}
	}
}

func (fw *FileWatcher) pollLoop() {
	ticker := time.NewTicker(time.Duration(fw.Poll))
	defer ticker.Stop()

	for {
		select {
		case <-fw.stop:
			return
		case <-ticker.C:
			if err := fw.loadCert(); err != nil {
				fw.logger.Warn("poll: failed to reload certificate", zap.Error(err))
			} else {
				fw.logger.Debug("poll: certificate reloaded")
			}
		}
	}
}

// UnmarshalCaddyfile parses the Caddyfile configuration for this module.
//
//	get_certificate file {
//	    cert <path>
//	    key  <path>
//	    debounce <duration>
//	    poll <duration>
//	}
func (fw *FileWatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume module name

	for d.NextBlock(0) {
		switch d.Val() {
		case "cert":
			if !d.NextArg() {
				return d.ArgErr()
			}
			fw.CertFile = d.Val()
		case "key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			fw.KeyFile = d.Val()
		case "debounce":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid debounce duration: %v", err)
			}
			fw.Debounce = caddy.Duration(dur)
		case "poll":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid poll duration: %v", err)
			}
			if dur == 0 {
				fw.Poll = caddy.Duration(-1)
			} else {
				fw.Poll = caddy.Duration(dur)
			}
		default:
			return d.Errf("unrecognized option: %s", d.Val())
		}
	}

	return nil
}

func uniqueDirs(paths ...string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, p := range paths {
		dir := filepath.Dir(p)
		if _, ok := seen[dir]; !ok {
			seen[dir] = struct{}{}
			result = append(result, dir)
		}
	}
	return result
}

var (
	_ caddy.Module          = (*FileWatcher)(nil)
	_ caddy.Provisioner     = (*FileWatcher)(nil)
	_ caddy.CleanerUpper    = (*FileWatcher)(nil)
	_ caddyfile.Unmarshaler = (*FileWatcher)(nil)
)
