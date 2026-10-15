package impersonate

import (
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(StripHandler{})
	httpcaddyfile.RegisterHandlerDirective("strip_request_headers", parseStripCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("strip_request_headers", httpcaddyfile.Before, "handle")
}

var strippedHeaders = []string{
	"X-Auth-Request-Id-Token",
	"X-Auth-Request-Email",
	"X-Auth-Request-Groups",
	"Impersonate-User",
	"Impersonate-Group",
	"Impersonate-Uid",
	"X-User",
	"X-Group",
}

const impersonateExtraPrefix = "Impersonate-Extra-"

// strippedServers records each server whose strip_request_headers handler
// was provisioned. The key is the *caddyhttp.Server from the provision context.
var strippedServers sync.Map

// StripHandler deletes a fixed set of client-supplied headers before the
// next handler runs. The directive takes no arguments.
type StripHandler struct{}

// CaddyModule returns the Caddy module information. The module is registered
// in the http.handlers namespace as "strip_request_headers".
func (StripHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.strip_request_headers",
		New: func() caddy.Module { return new(StripHandler) },
	}
}

// Provision records that this server strips client-supplied headers.
func (h *StripHandler) Provision(ctx caddy.Context) error {
	return markServerStripped(ctx)
}

// ServeHTTP deletes the fixed spoofable header set, including every
// Impersonate-Extra-* header, then calls the next handler.
func (h StripHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	for _, name := range strippedHeaders {
		r.Header.Del(name)
	}
	for name := range r.Header {
		if strings.HasPrefix(name, impersonateExtraPrefix) {
			r.Header.Del(name)
		}
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile parses the strip_request_headers directive.
// The directive accepts no arguments.
func (h *StripHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

// markServerStripped stores the server from ctx so later checks can tell
// that strip_request_headers was provisioned on it. A missing context, a
// missing server, or a value of the wrong type returns an error.
func markServerStripped(ctx caddy.Context) error {
	if ctx.Context == nil {
		return errors.New("strip_request_headers: server context is missing or has the wrong type")
	}
	server, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	if !ok || server == nil {
		return errors.New("strip_request_headers: server context is missing or has the wrong type")
	}
	strippedServers.Store(server, struct{}{})
	return nil
}

// parseStripCaddyfile registers strip_request_headers as a Caddyfile
// handler directive via httpcaddyfile.RegisterHandlerDirective.
func parseStripCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler StripHandler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

var (
	_ caddy.Provisioner           = (*StripHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*StripHandler)(nil)
	_ caddyfile.Unmarshaler       = (*StripHandler)(nil)
)
