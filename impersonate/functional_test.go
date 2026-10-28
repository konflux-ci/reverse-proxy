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
// Request specs start three components:
//   - authMock:       a dummy oauth2-proxy that returns auth response headers
//   - headerCapture:  a dummy upstream backend that records incoming headers
//   - Caddy:          loaded from a Caddyfile with reject_identity_headers on
//                     the site, then forward_auth, impersonate, and reverse_proxy
//
// The tests send HTTP requests through Caddy and assert that the backend
// receives the correct impersonation headers. This validates that the plugin
// integrates correctly with Caddy's forward_auth header copying and the
// site-level reject_identity_headers handler.

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
	Expect(loadCaddyfile(caddyfileContent)).To(Succeed(), "failed to load caddy config")
}

// loadCaddyfile adapts a Caddyfile and loads it. Callers that expect failure
// put "admin off" in the file: Caddy binds the admin listener before handler
// provisioning, and a failed load never becomes the current config, so
// caddy.Stop cannot release that listener.
func loadCaddyfile(caddyfileContent string) error {
	adapter := caddyconfig.GetAdapter("caddyfile")
	Expect(adapter).NotTo(BeNil(), "caddyfile adapter not registered")

	jsonCfg, _, err := adapter.Adapt([]byte(caddyfileContent), nil)
	Expect(err).NotTo(HaveOccurred(), "failed to adapt caddyfile")

	DeferCleanup(func() { _ = caddy.Stop() })
	return caddy.Load(jsonCfg, true)
}

func hostPort(srv *httptest.Server) string {
	return srv.Listener.Addr().String()
}

func requestIdentityHeader(url string) (int, string) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	req.Header.Set("Impersonate-User", "attacker")

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return resp.StatusCode, string(body)
}

func httpGet(url string) *http.Response {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	defer func() {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}()
	return resp
}

// kubeImpersonationCaddyfile mirrors the Konflux production config: reject
// client-supplied identity headers, authenticate via forward_auth,
// translate groups with the impersonate handler, then proxy to the backend.
func kubeImpersonationCaddyfile(adminPort, listenPort int, authAddr, backendAddr string) string {
	return fmt.Sprintf(`{
	admin 127.0.0.1:%d
}

:%d {
	reject_identity_headers
	route {
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
	reject_identity_headers
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
	// Request specs spin up a real Caddy instance with reject_identity_headers
	// outside the route, then forward_auth, impersonate, and reverse_proxy.
	// An auth mock stands in for oauth2-proxy, and a header-capture backend
	// stands in for the Kubernetes API. Requests go through Caddy end-to-end.

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

	It("fails to load when impersonate is used without reject_identity_headers", func() {
		listenPort := freePort()
		err := loadCaddyfile(fmt.Sprintf(`{
	admin off
}

:%d {
	route {
		impersonate
		respond "ok"
	}
}
`, listenPort))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("same request path"))
	})

	It("fails to load when reject_identity_headers is only on another route", func() {
		listenPort := freePort()
		// The directive is on this server, but only the /other* handle runs it.
		err := loadCaddyfile(fmt.Sprintf(`{
	admin off
}

:%d {
	handle /other* {
		reject_identity_headers
		respond "other"
	}
	handle {
		route {
			impersonate
			respond "ok"
		}
	}
}
`, listenPort))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("same request path"))
	})

	It("fails to load when impersonate precedes reject_identity_headers in a route", func() {
		listenPort := freePort()
		// route keeps source order, so the reject handler runs too late.
		err := loadCaddyfile(fmt.Sprintf(`{
	admin off
}

:%d {
	route {
		impersonate
		reject_identity_headers
		respond "ok"
	}
}
`, listenPort))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("same request path"))
	})

	It("rejects a client identity header when each handle has its own reject_identity_headers", func() {
		backend := &headerCapture{}
		backendSrv := httptest.NewServer(backend)
		DeferCleanup(backendSrv.Close)

		listenPort := freePort()
		adminPort := freePort()
		backendAddr := hostPort(backendSrv)
		startCaddyFromCaddyfile(fmt.Sprintf(`{
	admin 127.0.0.1:%d
}

:%d {
	handle /a* {
		reject_identity_headers
		route {
			impersonate
			reverse_proxy %s
		}
	}
	handle /b* {
		reject_identity_headers
		route {
			impersonate
			reverse_proxy %s
		}
	}
}
`, adminPort, listenPort, backendAddr, backendAddr))

		for _, path := range []string{"/a", "/b"} {
			status, body := requestIdentityHeader(fmt.Sprintf("http://127.0.0.1:%d%s", listenPort, path))
			Expect(status).To(Equal(http.StatusBadRequest))
			Expect(body).To(ContainSubstring("Impersonate-User"))
			Expect(body).NotTo(ContainSubstring("attacker"))
			Expect(backend.last).To(BeNil())
		}
	})

	It("does not return 500 when a loaded config reaches impersonate", func() {
		// The safety net returns 500 only when reject_identity_headers did
		// not run on this request. A config that loaded has already placed
		// that handler upstream, so the request is proxied.
		backend, port := setupProxy("alice@example.com", "developers", kubeImpersonationCaddyfile)

		resp := httpGet(fmt.Sprintf("http://127.0.0.1:%d/test", port))

		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		Expect(backend.last).NotTo(BeNil())
		Expect(backend.last.Get("Impersonate-User")).To(Equal("alice@example.com"))
	})

	It("rejects a client identity header with 400 and does not proxy", func() {
		backend, port := setupProxy("alice@example.com", "developers", kubeImpersonationCaddyfile)

		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/test", port), nil)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Impersonate-User", "attacker")

		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		Expect(err).NotTo(HaveOccurred())

		Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
		Expect(string(body)).To(ContainSubstring("Impersonate-User"))
		Expect(string(body)).NotTo(ContainSubstring("attacker"))
		Expect(backend.last).To(BeNil())
	})
})
