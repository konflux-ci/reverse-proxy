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
//	        cache watson_auth /mnt/watson-config/BASIC_AUTH {
//	            default ""
//	        }
//	        debounce 5s
//	        poll 10s
//	    }
//	}
package filewatcher

import (
	"encoding/json"
	"errors"
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

	// Files to cache in memory. Map of logical name to cache entry.
	// Values are accessible via GetValue/GetAll from the middleware.
	Cache map[string]*CacheEntry `json:"cache,omitempty"`

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

// CacheEntry defines a single cached file with optional default behavior.
// When Default is nil the file is required (Caddy fails to start if missing).
// When Default is non-nil the value is used when the file does not exist.
type CacheEntry struct {
	Path    string  `json:"path"`
	Default *string `json:"default,omitempty"`
}

func (e *CacheEntry) UnmarshalJSON(data []byte) error {
	// Backward compat: accept a bare string as a required entry.
	var path string
	if err := json.Unmarshal(data, &path); err == nil {
		e.Path = path
		return nil
	}

	type alias CacheEntry
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*e = CacheEntry(a)
	return nil
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
	for name, entry := range a.Cache {
		if entry == nil {
			return fmt.Errorf("cache entry %q is nil", name)
		}
		if strings.TrimSpace(entry.Path) == "" {
			return fmt.Errorf("cache entry %q has an empty path", name)
		}
		ptr := &atomic.Pointer[string]{}
		a.values[name] = ptr
		if _, err := a.loadFile(name, entry.Path); err != nil {
			if errors.Is(err, os.ErrNotExist) && entry.Default != nil {
				a.values[name].Store(entry.Default)
				a.logger.Info("cached file not found, using default",
					zap.String("name", name),
					zap.String("path", entry.Path))
				continue
			}
			return fmt.Errorf("loading cached file %q (%s): %v", name, entry.Path, err)
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

	cacheSummary := make(map[string]string, len(a.Cache))
	for name, entry := range a.Cache {
		label := entry.Path
		if entry.Default != nil {
			label += " (optional)"
		}
		cacheSummary[name] = label
	}
	a.logger.Info("file watcher started",
		zap.Strings("watch_paths", a.Watch),
		zap.Any("cache_files", cacheSummary),
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
			if errors.Is(err, os.ErrNotExist) && a.isDirOptional(dir) {
				a.logger.Info("skipping watch for missing optional cache directory",
					zap.String("dir", dir))
				continue
			}
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

// loadFile reads the file at path into the cache. It returns true if the
// content changed compared to the previously cached value.
func (a *App) loadFile(name, path string) (changed bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close() //nolint:errcheck

	data, err := io.ReadAll(io.LimitReader(f, maxCacheFileSize+1))
	if err != nil {
		return false, err
	}
	if int64(len(data)) > maxCacheFileSize {
		return false, fmt.Errorf("file %s exceeds maximum %d bytes", path, maxCacheFileSize)
	}

	content := strings.TrimRight(string(data), "\n")
	if prev := a.values[name].Load(); prev != nil && *prev == content {
		return false, nil
	}
	a.values[name].Store(&content)
	return true, nil
}

func (a *App) reloadAllCached(trigger string) {
	for name, entry := range a.Cache {
		changed, err := a.loadFile(name, entry.Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && entry.Default != nil {
				if prev := a.values[name].Load(); prev == nil || *prev != *entry.Default {
					a.values[name].Store(entry.Default)
					a.logger.Warn("cached file missing, reverted to default",
						zap.String("name", name),
						zap.String("path", entry.Path),
						zap.String("trigger", trigger))
				}
			} else {
				a.logger.Warn("failed to reload cached file",
					zap.String("name", name),
					zap.String("path", entry.Path),
					zap.String("trigger", trigger),
					zap.Error(err))
			}
		} else if changed {
			a.logger.Info("cached file reloaded",
				zap.String("name", name),
				zap.String("path", entry.Path),
				zap.String("trigger", trigger))
		}
	}
}

func (a *App) cacheParentDirs() []string {
	seen := make(map[string]struct{})
	var dirs []string
	for _, entry := range a.Cache {
		dir := filepath.Dir(entry.Path)
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

func (a *App) isDirOptional(dir string) bool {
	found := false
	for _, entry := range a.Cache {
		if filepath.Dir(entry.Path) == dir {
			found = true
			if entry.Default == nil {
				return false
			}
		}
	}
	return found
}

// isCacheEvent returns true if the fsnotify event's path is within a
// directory that contains one of the cached files.
func (a *App) isCacheEvent(eventPath string) bool {
	eventDir := filepath.Dir(eventPath)
	for _, entry := range a.Cache {
		if filepath.Dir(entry.Path) == eventDir {
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
//	    cache <name> <path> {
//	        default <value>
//	        required
//	    }
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
				a.Cache = make(map[string]*CacheEntry)
			}
			entry := &CacheEntry{Path: path}
			for d.NextBlock(1) {
				switch d.Val() {
				case "default":
					if !d.NextArg() {
						return d.ArgErr()
					}
					defVal := d.Val()
					entry.Default = &defVal
				case "required":
					if d.NextArg() {
						return d.Errf("'required' takes no arguments")
					}
				default:
					return d.Errf("unrecognized cache option: %s", d.Val())
				}
			}
			a.Cache[name] = entry
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
