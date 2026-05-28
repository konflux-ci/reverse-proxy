package filewatcher

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("inject_cached_vars", parseCaddyfileMiddleware)
}

// Middleware is an HTTP handler that injects all cached file values from the
// filewatcher app module into the request context as {http.vars.*} placeholders.
// This enables zero-allocation per-request access to token file contents.
type Middleware struct {
	app *App
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.inject_cached_vars",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision obtains a reference to the filewatcher app module.
func (m *Middleware) Provision(ctx caddy.Context) error {
	appModule, err := ctx.App("file_watcher")
	if err != nil {
		return err
	}
	app, ok := appModule.(*App)
	if !ok {
		return fmt.Errorf("unexpected file_watcher app type: %T", appModule)
	}
	m.app = app
	return nil
}

// ServeHTTP injects all cached values into the request context as variables,
// accessible as {http.vars.<name>} in downstream handlers.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	for name, ptr := range m.app.values {
		if val := ptr.Load(); val != nil {
			caddyhttp.SetVar(r.Context(), name, *val)
		}
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile parses the inject_cached_vars directive (no arguments).
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	return nil
}

func parseCaddyfileMiddleware(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

var (
	_ caddy.Module                = (*Middleware)(nil)
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
