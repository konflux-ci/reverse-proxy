// Package filewatcher provides a Caddy app module with two behaviors:
//
//  1. Watch directories and send SIGUSR1 on changes (for CA trust pool reload)
//  2. Cache file contents in memory via atomic pointers (for zero-alloc token injection)
//
// The first behavior triggers a full Caddy config reload when CA bundles change.
// The second provides an efficient alternative to Caddy's {file.*} placeholder,
// which reads the file from disk on every request. Our plugin caches file
// content in memory via atomic pointers — zero allocations and zero syscalls
// per request.
//
// # Module ID
//
// file_watcher
//
// # Caddyfile Usage
//
//	{
//	    file_watcher {
//	        watch /var/run/secrets/kubernetes.io/serviceaccount
//	        watch /mnt/trusted-ca
//	        cache kube_token /var/run/secrets/konflux-ci.dev/serviceaccount/token
//	        cache backend_token /var/run/secrets/konflux-ci.dev/backend/token
//	        debounce 5s
//	        poll 10s
//	    }
//	}
package filewatcher

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(new(App))
	httpcaddyfile.RegisterGlobalOption("file_watcher", parseGlobalOption)
}

// App is a Caddy app module that provides two file-watching behaviors:
//   - Watch paths: directories whose changes trigger SIGUSR1 (config reload)
//   - Cache paths: files whose content is cached in atomic pointers for
//     zero-allocation per-request access
type App struct {
	// Directories to watch for changes that trigger SIGUSR1.
	Watch []string `json:"watch,omitempty"`

	// Files to cache in memory. Map of logical name to file path.
	// Values are accessible via GetValue/GetAll from the middleware.
	Cache map[string]string `json:"cache,omitempty"`

	// How long to wait after the last filesystem event before sending SIGUSR1.
	// Only applies to watch paths, not cache paths (cache updates are instant).
	// Default: 5s
	Debounce caddy.Duration `json:"debounce,omitempty"`

	// How often to re-read cached files as a fallback for missed fsnotify events.
	// Kubernetes symlink swaps can occasionally be missed by inotify.
	// Default: 10s. Set to 0 in Caddyfile to disable polling.
	Poll caddy.Duration `json:"poll,omitempty"`

	// Cached file contents, keyed by logical name.
	values map[string]*atomic.Pointer[string]

	logger   *zap.Logger
	stop     chan struct{}
	stopOnce sync.Once

	// signalFn sends the reload signal. Overridable for testing.
	signalFn func() error
}

// CaddyModule returns the Caddy module information.
func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "file_watcher",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision validates configuration, sets defaults, and loads initial cache values.
func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	a.stop = make(chan struct{})

	if len(a.Watch) == 0 && len(a.Cache) == 0 {
		return fmt.Errorf("at least one watch or cache path is required")
	}
	if a.Debounce == 0 {
		a.Debounce = caddy.Duration(5 * time.Second)
	}
	if a.Poll == 0 {
		a.Poll = caddy.Duration(10 * time.Second)
	}
	// Negative means explicitly disabled (user set poll -1 or poll 0 in Caddyfile)
	if a.signalFn == nil {
		a.signalFn = func() error {
			return syscall.Kill(os.Getpid(), syscall.SIGUSR1)
		}
	}

	// Initialize cache values
	a.values = make(map[string]*atomic.Pointer[string], len(a.Cache))
	for name, path := range a.Cache {
		ptr := &atomic.Pointer[string]{}
		a.values[name] = ptr
		if err := a.loadFile(name, path); err != nil {
			return fmt.Errorf("loading cached file %q (%s): %v", name, path, err)
		}
	}

	return nil
}

// Start begins watching directories and cached file paths.
func (a *App) Start() error {
	watcher, err := a.createWatcher()
	if err != nil {
		return err
	}

	a.logger.Info("file watcher started",
		zap.Strings("watch_paths", a.Watch),
		zap.Any("cache_files", a.Cache),
		zap.Duration("debounce", time.Duration(a.Debounce)),
		zap.Duration("poll", time.Duration(a.Poll)))

	go a.watchLoop(watcher)

	if len(a.Cache) > 0 && time.Duration(a.Poll) > 0 {
		go a.pollLoop()
	}

	return nil
}

func (a *App) createWatcher() (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating fsnotify watcher: %v", err)
	}

	for _, dir := range a.Watch {
		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()
			return nil, fmt.Errorf("watching directory %q: %v", dir, err)
		}
	}

	cacheDirs := a.cacheParentDirs()
	for _, dir := range cacheDirs {
		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()
			return nil, fmt.Errorf("watching cache directory %q: %v", dir, err)
		}
	}

	return watcher, nil
}

// Stop signals watcher goroutines to exit.
func (a *App) Stop() error {
	a.stopOnce.Do(func() { close(a.stop) })
	return nil
}

// GetValue returns the cached content of a file by its logical name.
func (a *App) GetValue(name string) (string, bool) {
	ptr, ok := a.values[name]
	if !ok {
		return "", false
	}
	val := ptr.Load()
	if val == nil {
		return "", false
	}
	return *val, true
}

// GetAll returns a snapshot of all cached values.
func (a *App) GetAll() map[string]string {
	result := make(map[string]string, len(a.values))
	for name, ptr := range a.values {
		if val := ptr.Load(); val != nil {
			result[name] = *val
		}
	}
	return result
}

const maxCacheFileSize = 1 << 20 // 1 MB

func (a *App) loadFile(name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	data, err := io.ReadAll(io.LimitReader(f, maxCacheFileSize+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxCacheFileSize {
		return fmt.Errorf("file %s exceeds maximum %d bytes", path, maxCacheFileSize)
	}

	content := strings.TrimRight(string(data), "\n")
	a.values[name].Store(&content)
	return nil
}

func (a *App) reloadAllCached(trigger string) {
	for name, path := range a.Cache {
		if err := a.loadFile(name, path); err != nil {
			a.logger.Warn("failed to reload cached file",
				zap.String("name", name),
				zap.String("path", path),
				zap.String("trigger", trigger),
				zap.Error(err))
		} else {
			a.logger.Info("cached file reloaded",
				zap.String("name", name),
				zap.String("path", path),
				zap.String("trigger", trigger))
		}
	}
}

func (a *App) cacheParentDirs() []string {
	seen := make(map[string]struct{})
	var dirs []string
	for _, path := range a.Cache {
		dir := filepath.Dir(path)
		if _, ok := seen[dir]; !ok {
			seen[dir] = struct{}{}
			dirs = append(dirs, dir)
		}
	}
	// Remove dirs that overlap with Watch paths to avoid double-watching
	watchSet := make(map[string]struct{}, len(a.Watch))
	for _, w := range a.Watch {
		watchSet[w] = struct{}{}
	}
	var result []string
	for _, d := range dirs {
		if _, ok := watchSet[d]; !ok {
			result = append(result, d)
		}
	}
	return result
}

// isCacheEvent returns true if the fsnotify event's path is within a
// directory that contains one of the cached files.
func (a *App) isCacheEvent(eventPath string) bool {
	eventDir := filepath.Dir(eventPath)
	for _, path := range a.Cache {
		if filepath.Dir(path) == eventDir {
			return true
		}
	}
	return false
}

// isWatchEvent returns true if the fsnotify event's path is within one of
// the configured Watch directories (not a cache-only directory).
func (a *App) isWatchEvent(eventPath string) bool {
	eventDir := filepath.Dir(eventPath)
	for _, dir := range a.Watch {
		if eventDir == dir {
			return true
		}
	}
	return false
}

// watchLoop processes fsnotify events and self-heals if the watcher closes
// unexpectedly. The initial watcher is passed from Start() to avoid a race
// between goroutine launch and event delivery.
func (a *App) watchLoop(initialWatcher *fsnotify.Watcher) {
	const maxBackoff = 30 * time.Second
	backoff := 1 * time.Second
	watcher := initialWatcher

	for {
		exited := a.runWatcher(watcher)
		watcher.Close() //nolint:errcheck

		if exited {
			return
		}

		// Channel closed unexpectedly — recreate with backoff
		a.logger.Warn("fsnotify watcher closed unexpectedly, recreating",
			zap.Duration("backoff", backoff))

		for {
			select {
			case <-a.stop:
				return
			case <-time.After(backoff):
			}

			var err error
			watcher, err = a.createWatcher()
			if err != nil {
				a.logger.Error("failed to recreate fsnotify watcher, retrying",
					zap.Error(err), zap.Duration("backoff", backoff))
				backoff = min(backoff*2, maxBackoff)
				continue
			}

			a.logger.Info("fsnotify watcher recreated successfully")
			backoff = 1 * time.Second
			break
		}
	}
}

// runWatcher processes events from the given watcher until stop is signaled
// (returns true) or the watcher channels close unexpectedly (returns false).
func (a *App) runWatcher(watcher *fsnotify.Watcher) bool {
	var debounceTimer *time.Timer
	debounceCh := make(chan struct{}, 1)

	for {
		select {
		case <-a.stop:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return true

		case event, ok := <-watcher.Events:
			if !ok {
				return false
			}
			a.logger.Debug("fsnotify event", zap.String("event", event.String()))

			if len(a.Cache) > 0 && a.isCacheEvent(event.Name) {
				a.reloadAllCached("fsnotify")
			}

			// SIGUSR1 for watch paths uses debounce — only trigger for events
			// in watch directories, not for cache-only directory events.
			if len(a.Watch) > 0 && a.isWatchEvent(event.Name) {
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(time.Duration(a.Debounce), func() {
					select {
					case debounceCh <- struct{}{}:
					default:
					}
				})
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return false
			}
			a.logger.Error("fsnotify error", zap.Error(err))

		case <-debounceCh:
			a.logger.Info("file change detected, sending SIGUSR1 for config reload")
			if err := a.signalFn(); err != nil {
				a.logger.Error("failed to send SIGUSR1", zap.Error(err))
			}
		}
	}
}

func (a *App) pollLoop() {
	ticker := time.NewTicker(time.Duration(a.Poll))
	defer ticker.Stop()

	for {
		select {
		case <-a.stop:
			return
		case <-ticker.C:
			a.reloadAllCached("poll")
		}
	}
}

// UnmarshalCaddyfile parses the Caddyfile global option block.
//
//	file_watcher {
//	    watch <path>
//	    cache <name> <path>
//	    debounce <duration>
//	    poll <duration>
//	}
func (a *App) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume module name

	for d.NextBlock(0) {
		switch d.Val() {
		case "watch":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.Watch = append(a.Watch, d.Val())
		case "cache":
			if !d.NextArg() {
				return d.ArgErr()
			}
			name := d.Val()
			if !d.NextArg() {
				return d.ArgErr()
			}
			path := d.Val()
			if a.Cache == nil {
				a.Cache = make(map[string]string)
			}
			a.Cache[name] = path
		case "debounce":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid debounce duration: %v", err)
			}
			a.Debounce = caddy.Duration(dur)
		case "poll":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid poll duration: %v", err)
			}
			if dur == 0 {
				a.Poll = caddy.Duration(-1)
			} else {
				a.Poll = caddy.Duration(dur)
			}
		default:
			return d.Errf("unrecognized option: %s", d.Val())
		}
	}

	return nil
}

func parseGlobalOption(d *caddyfile.Dispenser, existingVal interface{}) (interface{}, error) {
	app := new(App)
	if err := app.UnmarshalCaddyfile(d); err != nil {
		return nil, err
	}
	return httpcaddyfile.App{
		Name:  "file_watcher",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

var (
	_ caddy.App             = (*App)(nil)
	_ caddy.Module          = (*App)(nil)
	_ caddy.Provisioner     = (*App)(nil)
	_ caddyfile.Unmarshaler = (*App)(nil)
)
