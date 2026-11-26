package impersonate_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func loadJSONRoutes(port int, routes string) error {
	DeferCleanup(func() { _ = caddy.Stop() })
	return caddy.Load([]byte(fmt.Sprintf(`{
		"admin":{"disabled":true},
		"apps":{"http":{"servers":{"test":{
			"listen":["127.0.0.1:%d"],
			"routes":%s
		}}}}
	}`, port, routes)), true)
}

var _ = Describe("Identity guard routing", func() {
	DescribeTable("runs before authentication",
		func(perHandle bool) {
			g := NewWithT(GinkgoT())
			var authCalls atomic.Int32
			auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				authCalls.Add(1)
				w.Header().Set("X-Auth-Request-Email", "alice@example.com")
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(auth.Close)
			backend := &headerCapture{}
			upstream := httptest.NewServer(backend)
			DeferCleanup(upstream.Close)
			port := freePort()
			directives := fmt.Sprintf(`
				reject_identity_headers
				forward_auth %s {
					uri /oauth2/auth
					copy_headers X-Auth-Request-Email
				}
				route {
					impersonate
					reverse_proxy %s
				}
			`, hostPort(auth), hostPort(upstream))
			if perHandle {
				directives = "handle {\n" + directives + "\n}"
			}
			startCaddyFromCaddyfile(fmt.Sprintf("{\nadmin off\n}\n:%d {\n%s\n}", port, directives))
			url := fmt.Sprintf("http://127.0.0.1:%d/", port)

			status, body := requestIdentityHeader(url)
			g.Expect(status).To(Equal(http.StatusBadRequest))
			g.Expect(body).To(ContainSubstring("Impersonate-User"))
			g.Expect(authCalls.Load()).To(BeZero())
			g.Expect(backend.last).To(BeNil())

			resp := httpGet(url)
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK))
			g.Expect(authCalls.Load()).To(Equal(int32(1)))
			g.Expect(backend.last.Get("Impersonate-User")).To(Equal("alice@example.com"))
		},
		Entry("at site level", false),
		Entry("inside a handle", true),
	)

	DescribeTable("loads guarded JSON routes through Caddy provisioning",
		func(routes string) {
			g := NewWithT(GinkgoT())
			port := freePort()
			g.Expect(loadJSONRoutes(port, routes)).To(Succeed())
			url := fmt.Sprintf("http://127.0.0.1:%d/", port)
			g.Expect(httpGet(url).StatusCode).To(Equal(http.StatusOK))
			status, _ := requestIdentityHeader(url)
			g.Expect(status).To(Equal(http.StatusBadRequest))
		},
		Entry("guard in an earlier route", `[
			{"handle":[{"handler":"reject_identity_headers"}]},
			{"handle":[{"handler":"impersonate"},{"handler":"static_response","body":"ok"}]}
		]`),
		Entry("already provisioned subroute before another impersonate handler", `[
			{"handle":[
				{"handler":"reject_identity_headers"},
				{"handler":"subroute","routes":[{"handle":[{"handler":"impersonate"}]}]}
			]},
			{"handle":[{"handler":"impersonate"},{"handler":"static_response","body":"ok"}]}
		]`),
		Entry("guard inherited by a nested error route", `[
			{"handle":[
				{"handler":"reject_identity_headers"},
				{"handler":"subroute",
					"routes":[{"handle":[{"handler":"error","error":"test error","status_code":503}]}],
					"errors":{"routes":[{"handle":[
						{"handler":"impersonate"},{"handler":"static_response","body":"ok","status_code":200}
					]}]}
				}
			]}
		]`),
	)

	DescribeTable("rejects a grouped guard that can be skipped",
		func(terminal bool) {
			g := NewWithT(GinkgoT())
			// /bypass satisfies the group first, skipping its matcherless guard.
			// Even a terminal fallback cannot make the final route unreachable.
			routes := fmt.Sprintf(`[{"handle":[{"handler":"subroute","routes":[
				{"group":"g","match":[{"path":["/bypass"]}],"handle":[
					{"handler":"vars","selected":true}
				]},
				{"group":"g","terminal":%t,"handle":[
					{"handler":"reject_identity_headers"},
					{"handler":"impersonate"}
				]},
				{"handle":[{"handler":"impersonate"},{"handler":"static_response","body":"ok"}]}
			]}]}]`, terminal)
			g.Expect(loadJSONRoutes(freePort(), routes)).To(MatchError(ContainSubstring("same request path")))
		},
		Entry("nonterminal guard", false),
		Entry("terminal guard", true),
	)
})
