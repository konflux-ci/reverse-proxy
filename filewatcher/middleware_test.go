package filewatcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/onsi/gomega"
)

// withVarsCtx attaches a vars map to the request context so SetVar/GetVar work.
func withVarsCtx(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	return r.WithContext(ctx)
}

func TestMiddlewareInjectsVars(t *testing.T) {
	g := gomega.NewWithT(t)

	tokenVal := "my-token-value"
	otherVal := "other-value"

	app := &App{
		values: map[string]*atomic.Pointer[string]{
			"kube_token":    {},
			"backend_token": {},
		},
	}
	app.values["kube_token"].Store(&tokenVal)
	app.values["backend_token"].Store(&otherVal)

	m := &Middleware{app: app}

	r := withVarsCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()

	var capturedKube, capturedBackend string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		capturedKube, _ = caddyhttp.GetVar(r.Context(), "kube_token").(string)
		capturedBackend, _ = caddyhttp.GetVar(r.Context(), "backend_token").(string)
		return nil
	})

	err := m.ServeHTTP(w, r, next)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(capturedKube).To(gomega.Equal("my-token-value"))
	g.Expect(capturedBackend).To(gomega.Equal("other-value"))
}

func TestMiddlewareEmptyCache(t *testing.T) {
	g := gomega.NewWithT(t)

	app := &App{
		values: make(map[string]*atomic.Pointer[string]),
	}
	m := &Middleware{app: app}

	r := withVarsCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()

	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	err := m.ServeHTTP(w, r, next)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(nextCalled).To(gomega.BeTrue())
}

func TestMiddlewareIntegrationWithApp(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	g.Expect(os.WriteFile(tokenPath, []byte("live-token"), 0644)).To(gomega.Succeed())

	app := &App{Cache: map[string]*CacheEntry{"tok": {Path: tokenPath}}}
	g.Expect(app.Provision(caddy.Context{})).To(gomega.Succeed())

	m := &Middleware{app: app}

	r := withVarsCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()

	var captured string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		captured, _ = caddyhttp.GetVar(r.Context(), "tok").(string)
		return nil
	})

	err := m.ServeHTTP(w, r, next)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(captured).To(gomega.Equal("live-token"))
}
