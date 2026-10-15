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

func TestStripClientHeaders(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &StripHandler{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Auth-Request-Id-Token", "eyJ.eyJ.sig")
	r.Header.Set("Impersonate-User", "attacker")
	r.Header.Set("Impersonate-Group", "system:masters")
	r.Header.Set("Impersonate-Uid", "1")
	r.Header.Set("Impersonate-Extra-scopes", "admin")
	r.Header.Set("X-User", "attacker")
	r.Header.Set("X-Group", "attacker")
	r.Header.Set("X-Auth-Request-Email", "alice@example.com")
	r.Header.Set("X-Auth-Request-Groups", "devs")
	r.Header.Set("Authorization", "Bearer client")

	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	g.Expect(err).NotTo(gomega.HaveOccurred())

	for _, name := range []string{
		"X-Auth-Request-Id-Token",
		"X-Auth-Request-Email",
		"X-Auth-Request-Groups",
		"Impersonate-User",
		"Impersonate-Group",
		"Impersonate-Uid",
		"Impersonate-Extra-Scopes",
		"X-User",
		"X-Group",
	} {
		g.Expect(r.Header.Values(name)).To(gomega.BeEmpty())
	}
	g.Expect(r.Header.Get("Authorization")).To(gomega.Equal("Bearer client"))
}

func TestImpersonateRequiresStrip(t *testing.T) {
	g := gomega.NewWithT(t)

	unmarked := &caddyhttp.Server{}
	ctx := caddy.Context{Context: context.WithValue(context.Background(), caddyhttp.ServerCtxKey, unmarked)}
	g.Expect((&Handler{}).Provision(ctx)).NotTo(gomega.Succeed())

	marked := &caddyhttp.Server{}
	markedCtx := caddy.Context{Context: context.WithValue(context.Background(), caddyhttp.ServerCtxKey, marked)}
	g.Expect(markServerStripped(markedCtx)).To(gomega.Succeed())
	g.Expect((&Handler{}).Provision(markedCtx)).To(gomega.Succeed())
}
