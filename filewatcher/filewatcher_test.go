package filewatcher

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/onsi/gomega"
	"go.uber.org/zap"
)

func newTestApp(t *testing.T, paths []string) *App {
	t.Helper()
	return &App{
		Watch:    paths,
		Debounce: caddy.Duration(100 * time.Millisecond),
		Poll:     caddy.Duration(10 * time.Second),
		stop:     make(chan struct{}),
		logger:   zap.NewNop(),
		signalFn: func() error { return nil },
		values:   make(map[string]*atomic.Pointer[string]),
	}
}

func newTestAppWithCache(t *testing.T, cache map[string]string) *App {
	t.Helper()
	app := &App{
		Cache:    cache,
		Debounce: caddy.Duration(100 * time.Millisecond),
		Poll:     caddy.Duration(10 * time.Second),
		stop:     make(chan struct{}),
		logger:   zap.NewNop(),
		signalFn: func() error { return nil },
		values:   make(map[string]*atomic.Pointer[string]),
	}
	for name := range cache {
		app.values[name] = &atomic.Pointer[string]{}
	}
	return app
}

// --- Watch (SIGUSR1) tests ---

func TestProvisionMissingPaths(t *testing.T) {
	g := gomega.NewWithT(t)
	app := &App{}
	err := app.Provision(caddy.Context{})
	g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("at least one watch or cache path")))
}

func TestProvisionSetsDefaults(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	app := &App{Watch: []string{dir}}
	g.Expect(app.Provision(caddy.Context{})).To(gomega.Succeed())

	g.Expect(time.Duration(app.Debounce)).To(gomega.Equal(5 * time.Second))
	g.Expect(time.Duration(app.Poll)).To(gomega.Equal(10 * time.Second))
	g.Expect(app.signalFn).NotTo(gomega.BeNil())
}

func TestStartFailsOnInvalidDirectory(t *testing.T) {
	g := gomega.NewWithT(t)

	app := newTestApp(t, []string{"/nonexistent/path/that/does/not/exist"})
	err := app.Start()
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("watching directory"))
}

func TestFileChangeTriggersSignal(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	var signalCount atomic.Int32

	app := newTestApp(t, []string{dir})
	app.signalFn = func() error {
		signalCount.Add(1)
		return nil
	}

	g.Expect(app.Start()).To(gomega.Succeed())
	defer app.Stop() //nolint:errcheck

	err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("fake-ca"), 0644)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	g.Eventually(func() int32 {
		return signalCount.Load()
	}, 2*time.Second, 50*time.Millisecond).Should(gomega.BeNumerically(">=", 1))
}

func TestDebounceCoalescesMultipleEvents(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	var signalCount atomic.Int32

	app := newTestApp(t, []string{dir})
	app.Debounce = caddy.Duration(300 * time.Millisecond)
	app.signalFn = func() error {
		signalCount.Add(1)
		return nil
	}

	g.Expect(app.Start()).To(gomega.Succeed())
	defer app.Stop() //nolint:errcheck

	for i := range 5 {
		err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("ca-%d.crt", i)), []byte("fake-ca"), 0644)
		g.Expect(err).NotTo(gomega.HaveOccurred())
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)

	count := signalCount.Load()
	g.Expect(count).To(gomega.BeNumerically("<=", 2),
		"debounce should coalesce rapid events, got %d signals", count)
	g.Expect(count).To(gomega.BeNumerically(">=", 1),
		"should have received at least 1 signal")
}

func TestStopPreventsSignal(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	var signalCount atomic.Int32

	app := newTestApp(t, []string{dir})
	app.Debounce = caddy.Duration(50 * time.Millisecond)
	app.signalFn = func() error {
		signalCount.Add(1)
		return nil
	}

	g.Expect(app.Start()).To(gomega.Succeed())
	g.Expect(app.Stop()).To(gomega.Succeed())

	time.Sleep(100 * time.Millisecond)

	err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("fake-ca"), 0644)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	time.Sleep(200 * time.Millisecond)
	g.Expect(signalCount.Load()).To(gomega.Equal(int32(0)))
}

func TestMultipleWatchPaths(t *testing.T) {
	g := gomega.NewWithT(t)

	dir1 := t.TempDir()
	dir2 := t.TempDir()
	var signalCount atomic.Int32

	app := newTestApp(t, []string{dir1, dir2})
	app.signalFn = func() error {
		signalCount.Add(1)
		return nil
	}

	g.Expect(app.Start()).To(gomega.Succeed())
	defer app.Stop() //nolint:errcheck

	err := os.WriteFile(filepath.Join(dir2, "ca.crt"), []byte("fake-ca"), 0644)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	g.Eventually(func() int32 {
		return signalCount.Load()
	}, 2*time.Second, 50*time.Millisecond).Should(gomega.BeNumerically(">=", 1))
}

// --- Cache tests ---

func TestProvisionLoadsCacheFiles(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	g.Expect(os.WriteFile(tokenPath, []byte("my-secret-token\n"), 0644)).To(gomega.Succeed())

	app := &App{Cache: map[string]string{"kube_token": tokenPath}}
	g.Expect(app.Provision(caddy.Context{})).To(gomega.Succeed())

	val, ok := app.GetValue("kube_token")
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(val).To(gomega.Equal("my-secret-token"))
}

func TestProvisionTrimsTrailingNewline(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	g.Expect(os.WriteFile(tokenPath, []byte("token-val\n\n"), 0644)).To(gomega.Succeed())

	app := &App{Cache: map[string]string{"t": tokenPath}}
	g.Expect(app.Provision(caddy.Context{})).To(gomega.Succeed())

	val, _ := app.GetValue("t")
	g.Expect(val).To(gomega.Equal("token-val"))
}

func TestProvisionFailsOnMissingCacheFile(t *testing.T) {
	g := gomega.NewWithT(t)

	app := &App{Cache: map[string]string{"missing": "/nonexistent/file"}}
	err := app.Provision(caddy.Context{})
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("loading cached file"))
}

func TestGetValueUnknownName(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	g.Expect(os.WriteFile(tokenPath, []byte("x"), 0644)).To(gomega.Succeed())

	app := &App{Cache: map[string]string{"known": tokenPath}}
	g.Expect(app.Provision(caddy.Context{})).To(gomega.Succeed())

	_, ok := app.GetValue("unknown")
	g.Expect(ok).To(gomega.BeFalse())
}

func TestGetAllReturnsSnapshot(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	g.Expect(os.WriteFile(filepath.Join(dir, "a"), []byte("val-a"), 0644)).To(gomega.Succeed())
	g.Expect(os.WriteFile(filepath.Join(dir, "b"), []byte("val-b"), 0644)).To(gomega.Succeed())

	app := &App{Cache: map[string]string{
		"file_a": filepath.Join(dir, "a"),
		"file_b": filepath.Join(dir, "b"),
	}}
	g.Expect(app.Provision(caddy.Context{})).To(gomega.Succeed())

	all := app.GetAll()
	g.Expect(all).To(gomega.HaveLen(2))
	g.Expect(all["file_a"]).To(gomega.Equal("val-a"))
	g.Expect(all["file_b"]).To(gomega.Equal("val-b"))
}

func TestCacheUpdateOnFileChange(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	g.Expect(os.WriteFile(tokenPath, []byte("original"), 0644)).To(gomega.Succeed())

	app := newTestAppWithCache(t, map[string]string{"tok": tokenPath})
	_, err := app.loadFile("tok", tokenPath)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	g.Expect(app.Start()).To(gomega.Succeed())
	defer app.Stop() //nolint:errcheck

	// Update the file
	g.Expect(os.WriteFile(tokenPath, []byte("rotated"), 0644)).To(gomega.Succeed())

	// Cache should be updated nearly instantly (no debounce for cache)
	g.Eventually(func() string {
		val, _ := app.GetValue("tok")
		return val
	}, 2*time.Second, 50*time.Millisecond).Should(gomega.Equal("rotated"))
}

func TestCachePollFallback(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	g.Expect(os.WriteFile(tokenPath, []byte("initial"), 0644)).To(gomega.Succeed())

	app := newTestAppWithCache(t, map[string]string{"tok": tokenPath})
	app.Poll = caddy.Duration(100 * time.Millisecond)
	_, err := app.loadFile("tok", tokenPath)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Start only the poll loop (simulates missed fsnotify event)
	go app.pollLoop()
	defer app.Stop() //nolint:errcheck

	// Update file (won't be caught by fsnotify since we didn't start the full watcher)
	g.Expect(os.WriteFile(tokenPath, []byte("polled-value"), 0644)).To(gomega.Succeed())

	g.Eventually(func() string {
		val, _ := app.GetValue("tok")
		return val
	}, 1*time.Second, 50*time.Millisecond).Should(gomega.Equal("polled-value"))
}

func TestKubernetesSymlinkRotation(t *testing.T) {
	g := gomega.NewWithT(t)

	// Simulate K8s projected volume structure:
	// /dir/..data -> ..2024_01_01 (symlink to timestamped dir)
	// /dir/token -> ..data/token (symlink through ..data)
	baseDir := t.TempDir()

	// Create initial timestamped directory with token
	ts1Dir := filepath.Join(baseDir, "..2024_01_01")
	g.Expect(os.Mkdir(ts1Dir, 0755)).To(gomega.Succeed())
	g.Expect(os.WriteFile(filepath.Join(ts1Dir, "token"), []byte("token-v1"), 0644)).To(gomega.Succeed())

	// Create ..data symlink
	dataLink := filepath.Join(baseDir, "..data")
	g.Expect(os.Symlink(ts1Dir, dataLink)).To(gomega.Succeed())

	// Create token symlink through ..data
	tokenLink := filepath.Join(baseDir, "token")
	g.Expect(os.Symlink(filepath.Join("..data", "token"), tokenLink)).To(gomega.Succeed())

	app := newTestAppWithCache(t, map[string]string{"tok": tokenLink})
	_, err := app.loadFile("tok", tokenLink)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	g.Expect(app.Start()).To(gomega.Succeed())
	defer app.Stop() //nolint:errcheck

	val, _ := app.GetValue("tok")
	g.Expect(val).To(gomega.Equal("token-v1"))

	// Simulate K8s atomic symlink rotation:
	// 1. Create new timestamped directory
	ts2Dir := filepath.Join(baseDir, "..2024_01_02")
	g.Expect(os.Mkdir(ts2Dir, 0755)).To(gomega.Succeed())
	g.Expect(os.WriteFile(filepath.Join(ts2Dir, "token"), []byte("token-v2"), 0644)).To(gomega.Succeed())

	// 2. Atomically replace ..data symlink (rename is atomic on same filesystem)
	tmpLink := filepath.Join(baseDir, "..data_tmp")
	g.Expect(os.Symlink(ts2Dir, tmpLink)).To(gomega.Succeed())
	g.Expect(os.Rename(tmpLink, dataLink)).To(gomega.Succeed())

	// fsnotify should detect the rename in the parent directory
	g.Eventually(func() string {
		val, _ := app.GetValue("tok")
		return val
	}, 2*time.Second, 50*time.Millisecond).Should(gomega.Equal("token-v2"))
}

func TestCacheOnlyAppNeedsNoWatch(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	g.Expect(os.WriteFile(tokenPath, []byte("val"), 0644)).To(gomega.Succeed())

	app := &App{Cache: map[string]string{"tok": tokenPath}}
	g.Expect(app.Provision(caddy.Context{})).To(gomega.Succeed())
	g.Expect(app.Start()).To(gomega.Succeed())
	defer app.Stop() //nolint:errcheck

	val, ok := app.GetValue("tok")
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(val).To(gomega.Equal("val"))
}

func TestParseGlobalOption(t *testing.T) {
	g := gomega.NewWithT(t)

	input := `file_watcher {
		watch /mnt/ca-bundle
		cache kube_token /var/run/secrets/token
		debounce 3s
		poll 15s
	}`

	d := caddyfile.NewTestDispenser(input)
	result, err := parseGlobalOption(d, nil)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	appResult, ok := result.(httpcaddyfile.App)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(appResult.Name).To(gomega.Equal("file_watcher"))

	var parsed App
	g.Expect(json.Unmarshal(appResult.Value, &parsed)).To(gomega.Succeed())
	g.Expect(parsed.Watch).To(gomega.Equal([]string{"/mnt/ca-bundle"}))
	g.Expect(parsed.Cache).To(gomega.HaveKeyWithValue("kube_token", "/var/run/secrets/token"))
	g.Expect(parsed.Debounce).To(gomega.Equal(caddy.Duration(3 * time.Second)))
	g.Expect(parsed.Poll).To(gomega.Equal(caddy.Duration(15 * time.Second)))
}

func TestLoadFileChangedReturnValue(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	g.Expect(os.WriteFile(tokenPath, []byte("secret-v1"), 0644)).To(gomega.Succeed())

	app := newTestAppWithCache(t, map[string]string{"tok": tokenPath})

	// First load always reports changed.
	changed, err := app.loadFile("tok", tokenPath)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(changed).To(gomega.BeTrue())

	// Reload with same content reports no change.
	changed, err = app.loadFile("tok", tokenPath)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(changed).To(gomega.BeFalse())

	// Modify the file, reload reports changed.
	g.Expect(os.WriteFile(tokenPath, []byte("secret-v2"), 0644)).To(gomega.Succeed())
	changed, err = app.loadFile("tok", tokenPath)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(changed).To(gomega.BeTrue())
}

func TestParseGlobalOptionPollZeroDisables(t *testing.T) {
	g := gomega.NewWithT(t)

	input := `file_watcher {
		watch /mnt/ca
		poll 0
	}`

	d := caddyfile.NewTestDispenser(input)
	result, err := parseGlobalOption(d, nil)
	g.Expect(err).ToNot(gomega.HaveOccurred())

	appResult := result.(httpcaddyfile.App)
	var parsed App
	g.Expect(json.Unmarshal(appResult.Value, &parsed)).To(gomega.Succeed())
	g.Expect(time.Duration(parsed.Poll)).To(gomega.BeNumerically("<", 0))
}
