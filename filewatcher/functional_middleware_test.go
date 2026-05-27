package filewatcher_test

import (
	"encoding/json"
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

// TestMiddlewareFunctional starts a full Caddy server with:
//   - file_watcher app caching a token file
//   - inject_watched_files middleware injecting {http.vars.kube_token}
//   - reverse_proxy using header_up with the injected var
//
// It verifies that:
// 1. The upstream receives the correct Authorization header
// 2. After rotating the token file, the upstream receives the new token
func TestMiddlewareFunctional(t *testing.T) {
	g := gomega.NewWithT(t)

	// Create token file
	tokenDir := t.TempDir()
	tokenPath := filepath.Join(tokenDir, "token")
	g.Expect(os.WriteFile(tokenPath, []byte("initial-token-value"), 0644)).To(gomega.Succeed())

	// Start upstream that captures the Authorization header
	var lastAuthHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "OK")
	}))
	defer upstream.Close()

	caddyPort := freePortForMiddleware(t)
	adminPort := freePortForMiddleware(t)

	// Use JSON config for full control over handler ordering
	cfg := map[string]any{
		"admin": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", adminPort)},
		"apps": map[string]any{
			"file_watcher": map[string]any{
				"cache": map[string]string{
					"kube_token": tokenPath,
				},
				"poll": "100ms",
			},
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen": []string{fmt.Sprintf(":%d", caddyPort)},
						"routes": []any{
							map[string]any{
								"handle": []any{
									map[string]any{
										"handler": "subroute",
										"routes": []any{
											map[string]any{
												"handle": []any{
													map[string]any{
														"handler": "inject_watched_files",
													},
													map[string]any{
														"handler": "reverse_proxy",
														"upstreams": []any{
															map[string]any{
																"dial": upstream.Listener.Addr().String(),
															},
														},
														"headers": map[string]any{
															"request": map[string]any{
																"set": map[string]any{
																	"Authorization": []string{"Bearer {http.vars.kube_token}"},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	jsonCfg, err := json.Marshal(cfg)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	g.Expect(caddy.Load(jsonCfg, true)).To(gomega.Succeed())
	defer caddy.Stop() //nolint:errcheck

	time.Sleep(300 * time.Millisecond)

	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/", caddyPort)

	// Step 1: Verify upstream receives the initial token
	resp, err := client.Get(url)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
	g.Expect(lastAuthHeader).To(gomega.Equal("Bearer initial-token-value"))

	// Step 2: Rotate the token file
	g.Expect(os.WriteFile(tokenPath, []byte("rotated-token-value"), 0644)).To(gomega.Succeed())

	// Wait for fsnotify + poll to pick it up
	time.Sleep(500 * time.Millisecond)

	// Step 3: Verify upstream receives the rotated token
	resp, err = client.Get(url)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
	g.Expect(lastAuthHeader).To(gomega.Equal("Bearer rotated-token-value"))
}
