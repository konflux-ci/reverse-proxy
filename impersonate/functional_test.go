package impersonate_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/konflux-ci/reverse-proxy/impersonate"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// These functional tests verify the impersonate Caddy handler within a fully
// running Caddy server, wired with forward_auth and reverse_proxy — mirroring
// the Konflux production proxy configuration.
//
// Each test starts three components:
//   - authMock:       a dummy oauth2-proxy that returns auth response headers
//   - headerCapture:  a dummy upstream backend that records incoming headers
//   - Caddy:          loaded from a Caddyfile via the adapter with the full
//                     forward_auth → impersonate → reverse_proxy handler chain
//
// The tests send HTTP requests through Caddy and assert that the backend
// receives the correct impersonation headers. This validates that the plugin
// integrates correctly with Caddy's forward_auth header copying and
// request_header stripping.

// headerCapture records all request headers and returns them as JSON.
// It acts as a stand-in for an upstream backend (e.g. Kubernetes API).
type headerCapture struct {
	last http.Header
}

func (h *headerCapture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.last = r.Header.Clone()
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(r.Header)
	_, _ = w.Write(out)
}

// authMock simulates oauth2-proxy's /oauth2/auth endpoint. It returns 200
// with X-Auth-Request-Email and X-Auth-Request-Groups response headers.
type authMock struct {
	user   string
	groups string
}

func (a *authMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.user != "" {
		w.Header().Set("X-Auth-Request-Email", a.user)
	}
	if a.groups != "" {
		w.Header().Set("X-Auth-Request-Groups", a.groups)
	}
	w.WriteHeader(http.StatusOK)
}

// caddyfileBuilder generates a Caddyfile string given the admin port, listen
// port, auth address, and backend address.
type caddyfileBuilder func(adminPort, listenPort int, authAddr, backendAddr string) string

// setupProxy spins up the auth mock, backend capture, and a Caddy instance,
// wired together with the given Caddyfile builder. It registers cleanup for
// all three. Returns the backend (for header assertions) and the Caddy port
// to send requests to.
func setupProxy(user, groups string, buildCaddyfile caddyfileBuilder) (*headerCapture, int) {
	backend := &headerCapture{}
	backendSrv := httptest.NewServer(backend)
	DeferCleanup(backendSrv.Close)

	authSrv := httptest.NewServer(&authMock{user: user, groups: groups})
	DeferCleanup(authSrv.Close)

	caddyPort := freePort()
	adminPort := freePort()
	startCaddyFromCaddyfile(
		buildCaddyfile(adminPort, caddyPort, hostPort(authSrv), hostPort(backendSrv)))

	return backend, caddyPort
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	port := l.Addr().(*net.TCPAddr).Port
	Expect(l.Close()).To(Succeed())
	return port
}

func startCaddyFromCaddyfile(caddyfileContent string) {
	adapter := caddyconfig.GetAdapter("caddyfile")
	Expect(adapter).NotTo(BeNil(), "caddyfile adapter not registered")

	jsonCfg, _, err := adapter.Adapt([]byte(caddyfileContent), nil)
	Expect(err).NotTo(HaveOccurred(), "failed to adapt caddyfile")

	Expect(caddy.Load(jsonCfg, true)).To(Succeed(), "failed to load caddy config")
	DeferCleanup(func() { _ = caddy.Stop() })
}

func hostPort(srv *httptest.Server) string {
	return srv.Listener.Addr().String()
}

func httpGet(url string, extraHeaders ...map[string]string) *http.Response {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	for _, h := range extraHeaders {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	defer func() {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}()
	return resp
}

// kubeImpersonationCaddyfile mirrors the Konflux production config: strip
// client-supplied impersonation headers, authenticate via forward_auth,
// translate groups with the impersonate handler, then proxy to the backend.
func kubeImpersonationCaddyfile(adminPort, listenPort int, authAddr, backendAddr string) string {
	return fmt.Sprintf(`{
	admin 127.0.0.1:%d
}

:%d {
	route {
		request_header -Impersonate-User
		request_header -Impersonate-Group

		forward_auth %s {
			uri /oauth2/auth
			copy_headers X-Auth-Request-Email X-Auth-Request-Groups
		}

		impersonate

		reverse_proxy %s
	}
}
`, adminPort, listenPort, authAddr, backendAddr)
}

// nsListerCaddyfile targets the namespace-lister service using custom
// X-User / X-Group headers instead of the default Impersonate-* headers.
func nsListerCaddyfile(adminPort, listenPort int, authAddr, backendAddr string) string {
	return fmt.Sprintf(`{
	admin 127.0.0.1:%d
}

:%d {
	route {
		forward_auth %s {
			uri /oauth2/auth
			copy_headers X-Auth-Request-Email X-Auth-Request-Groups
		}

		impersonate {
			target_user  X-User
			target_group X-Group
		}

		reverse_proxy %s
	}
}
`, adminPort, listenPort, authAddr, backendAddr)
}

var _ = Describe("Impersonate handler functional tests", func() {
	// Each test spins up a real Caddy instance configured with the full
	// forward_auth → impersonate → reverse_proxy chain, an auth mock
	// standing in for oauth2-proxy, and a header-capture backend standing
	// in for the Kubernetes API. Requests go through Caddy end-to-end.

	It("sets Impersonate-User and splits groups into individual Impersonate-Group headers", func() {
		backend, port := setupProxy("alice@example.com", "developers,platform-team", kubeImpersonationCaddyfile)

		resp := httpGet(fmt.Sprintf("http://127.0.0.1:%d/api/v1/pods", port))
		Expect(resp.StatusCode).To(Equal(http.StatusOK))

		Expect(backend.last.Get("Impersonate-User")).To(Equal("alice@example.com"))
		Expect(backend.last.Values("Impersonate-Group")).To(Equal(
			[]string{"developers", "platform-team", "system:authenticated"}))
	})

	It("writes X-User and X-Group when configured for namespace-lister", func() {
		backend, port := setupProxy("bob@example.com", "ops,sre", nsListerCaddyfile)

		resp := httpGet(fmt.Sprintf("http://127.0.0.1:%d/api/namespaces", port))
		Expect(resp.StatusCode).To(Equal(http.StatusOK))

		Expect(backend.last.Get("X-User")).To(Equal("bob@example.com"))
		Expect(backend.last.Values("X-Group")).To(Equal(
			[]string{"ops", "sre", "system:authenticated"}))
		Expect(backend.last.Get("Impersonate-User")).To(BeEmpty())
	})

	It("includes system:authenticated even when the auth proxy returns no groups", func() {
		backend, port := setupProxy("carol@example.com", "", kubeImpersonationCaddyfile)

		httpGet(fmt.Sprintf("http://127.0.0.1:%d/test", port))

		Expect(backend.last.Get("Impersonate-User")).To(Equal("carol@example.com"))
		Expect(backend.last.Values("Impersonate-Group")).To(Equal(
			[]string{"system:authenticated"}))
	})

	It("forwards all 15 groups without the 10-group limit of the old regex hack", func() {
		backend, port := setupProxy(
			"dave@example.com",
			"g1,g2,g3,g4,g5,g6,g7,g8,g9,g10,g11,g12,g13,g14,g15",
			kubeImpersonationCaddyfile)

		httpGet(fmt.Sprintf("http://127.0.0.1:%d/test", port))

		groups := backend.last.Values("Impersonate-Group")
		Expect(groups).To(HaveLen(16))
		Expect(groups[:15]).To(Equal(
			[]string{"g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8",
				"g9", "g10", "g11", "g12", "g13", "g14", "g15"}))
		Expect(groups[15]).To(Equal("system:authenticated"))
	})

	It("strips malicious client-supplied Impersonate-* headers before authentication", func() {
		backend, port := setupProxy("eve@example.com", "devs", kubeImpersonationCaddyfile)

		httpGet(fmt.Sprintf("http://127.0.0.1:%d/test", port), map[string]string{
			"Impersonate-User":  "attacker@evil.com",
			"Impersonate-Group": "cluster-admin",
		})

		Expect(backend.last.Get("Impersonate-User")).To(Equal("eve@example.com"))
		Expect(backend.last.Values("Impersonate-Group")).To(Equal(
			[]string{"devs", "system:authenticated"}))
	})
})
