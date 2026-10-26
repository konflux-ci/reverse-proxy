package impersonate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/onsi/gomega"
)

func TestRejectIdentityHeaders(t *testing.T) {
	headers := []string{
		"X-Auth-Request-Id-Token",
		"X-Auth-Request-Email",
		"X-Auth-Request-Groups",
		"Impersonate-User",
		"Impersonate-Group",
		"Impersonate-Uid",
		"Impersonate-Extra-Scopes",
		"X-User",
		"X-Group",
	}

	for _, name := range headers {
		t.Run(name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			h := &RejectIdentityHeaders{}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set(name, "secret-value")
			r.Header.Set("Authorization", "Bearer client")

			rec := httptest.NewRecorder()
			called := false
			err := h.ServeHTTP(rec, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
				called = true
				return nil
			}))

			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(called).To(gomega.BeFalse())
			g.Expect(rec.Code).To(gomega.Equal(http.StatusBadRequest))
			g.Expect(rec.Body.String()).To(gomega.ContainSubstring(name))
			g.Expect(rec.Body.String()).NotTo(gomega.ContainSubstring("secret-value"))
			g.Expect(rec.Body.String()).NotTo(gomega.ContainSubstring("Bearer client"))
		})
	}
}

func TestRejectIdentityHeadersEmptyValue(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &RejectIdentityHeaders{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Impersonate-User", "")

	rec := httptest.NewRecorder()
	called := false
	err := h.ServeHTTP(rec, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		called = true
		return nil
	}))

	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(called).To(gomega.BeFalse())
	g.Expect(rec.Code).To(gomega.Equal(http.StatusBadRequest))
	g.Expect(rec.Body.String()).To(gomega.ContainSubstring("Impersonate-User"))
}

func TestRejectIdentityHeadersAllowsOtherHeaders(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &RejectIdentityHeaders{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer client")
	r.Header.Set("Accept", "application/json")

	rec := httptest.NewRecorder()
	var got http.Header
	err := h.ServeHTTP(rec, r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
		got = r.Header.Clone()
		return nil
	}))

	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(got.Get("Authorization")).To(gomega.Equal("Bearer client"))
	g.Expect(got.Get("Accept")).To(gomega.Equal("application/json"))
}

func TestImpersonateRequiresRejectIdentityHeaders(t *testing.T) {
	g := gomega.NewWithT(t)

	g.Expect((&Handler{}).Provision(caddy.Context{})).NotTo(gomega.Succeed())

	empty := &caddyhttp.Server{}
	ctx := caddy.Context{Context: context.WithValue(context.Background(), caddyhttp.ServerCtxKey, empty)}
	g.Expect((&Handler{}).Provision(ctx)).NotTo(gomega.Succeed())
}
