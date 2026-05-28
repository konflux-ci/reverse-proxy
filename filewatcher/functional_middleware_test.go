package filewatcher_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/konflux-ci/reverse-proxy/filewatcher"
	"github.com/onsi/gomega"
)

func freePortForMiddleware(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() //nolint:errcheck
	return port
}

// TestMiddlewareFunctionalCaddyfile starts a full Caddy server configured via
// Caddyfile with:
//   - file_watcher global option caching a token file
//   - inject_cached_vars middleware injecting {http.vars.kube_token}
//   - reverse_proxy using header_up with the injected var
//
// It verifies that:
// 1. The Caddyfile adapter correctly parses the file_watcher global option
// 2. The upstream receives the correct Authorization header
// 3. After rotating the token file, the upstream receives the new token
func TestMiddlewareFunctionalCaddyfile(t *testing.T) {
	g := gomega.NewWithT(t)

	tokenDir := t.TempDir()
	tokenPath := filepath.Join(tokenDir, "token")
	g.Expect(os.WriteFile(tokenPath, []byte("initial-token-value"), 0644)).To(gomega.Succeed())

	var lastAuthHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "OK")
	}))
	defer upstream.Close()

	caddyPort := freePortForMiddleware(t)
	adminPort := freePortForMiddleware(t)

	caddyfileContent := fmt.Sprintf(`{
	admin 127.0.0.1:%d
	order inject_cached_vars before reverse_proxy
	file_watcher {
		cache kube_token %s
		poll 100ms
	}
}

:%d {
	route {
		inject_cached_vars
		reverse_proxy %s {
			header_up Authorization "Bearer {http.vars.kube_token}"
		}
	}
}
`, adminPort, tokenPath, caddyPort, upstream.Listener.Addr().String())

	adapter := caddyconfig.GetAdapter("caddyfile")
	g.Expect(adapter).NotTo(gomega.BeNil())

	jsonCfg, _, err := adapter.Adapt([]byte(caddyfileContent), nil)
	g.Expect(err).NotTo(gomega.HaveOccurred(), "Caddyfile adaptation failed")

	g.Expect(caddy.Load(jsonCfg, true)).To(gomega.Succeed())
	defer caddy.Stop() //nolint:errcheck

	time.Sleep(300 * time.Millisecond)

	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/", caddyPort)

	resp, err := client.Get(url)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
	g.Expect(lastAuthHeader).To(gomega.Equal("Bearer initial-token-value"))

	g.Expect(os.WriteFile(tokenPath, []byte("rotated-token-value"), 0644)).To(gomega.Succeed())

	time.Sleep(500 * time.Millisecond)

	resp, err = client.Get(url)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
	g.Expect(lastAuthHeader).To(gomega.Equal("Bearer rotated-token-value"))
}
