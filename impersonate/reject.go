package impersonate

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(RejectIdentityHeaders{})
	httpcaddyfile.RegisterHandlerDirective("reject_identity_headers", parseRejectCaddyfile)
	// Before handle: a site-level directive runs for every request, ahead of
	// route and handle blocks. forward_auth writes the same header names later.
	httpcaddyfile.RegisterDirectiveOrder("reject_identity_headers", httpcaddyfile.Before, "handle")
}

var rejectedHeaders = []string{
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

// requestIdentityCheckedKey is set only after reject_identity_headers has
// accepted this request. Load rejects a route that can reach impersonate
// without that handler; this mark is the per-request backstop.
type requestIdentityCheckedKey struct{}

func markRequestIdentityChecked(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), requestIdentityCheckedKey{}, struct{}{})
	return r.WithContext(ctx)
}

func requestIdentityChecked(r *http.Request) bool {
	_, ok := r.Context().Value(requestIdentityCheckedKey{}).(struct{})
	return ok
}

// RejectIdentityHeaders refuses a request that carries a client-supplied
// identity header. The directive takes no arguments. Authorization is allowed.
type RejectIdentityHeaders struct {
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information. The module is registered
// in the http.handlers namespace as "reject_identity_headers".
func (RejectIdentityHeaders) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.reject_identity_headers",
		New: func() caddy.Module { return new(RejectIdentityHeaders) },
	}
}

// Provision stores the logger used when a request is rejected.
func (h *RejectIdentityHeaders) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	return nil
}

// ServeHTTP returns 400 when the request contains a disallowed identity
// header, including an empty value and any Impersonate-Extra-* header.
// The response names the header and omits its value. Other requests are
// passed through unchanged.
func (h RejectIdentityHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	name, reject := rejectedIdentityHeader(r.Header)
	if !reject {
		return next.ServeHTTP(w, markRequestIdentityChecked(r))
	}
	if h.logger != nil {
		h.logger.Warn("rejected request with a disallowed identity header",
			zap.String("header", name))
	}
	msg := fmt.Sprintf("request contains disallowed header %q; retry without it", name)
	http.Error(w, msg, http.StatusBadRequest)
	return nil
}

// UnmarshalCaddyfile parses the reject_identity_headers directive.
// The directive accepts no arguments.
func (h *RejectIdentityHeaders) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

// rejectedIdentityHeader reports the first disallowed header present on h.
// A header with an empty value still counts as present.
func rejectedIdentityHeader(h http.Header) (string, bool) {
	for _, name := range rejectedHeaders {
		if _, ok := h[name]; ok {
			return name, true
		}
	}
	for name := range h {
		if strings.HasPrefix(name, impersonateExtraPrefix) {
			return name, true
		}
	}
	return "", false
}

// parseRejectCaddyfile registers reject_identity_headers as a Caddyfile
// handler directive via httpcaddyfile.RegisterHandlerDirective.
func parseRejectCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler RejectIdentityHeaders
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

var (
	_ caddy.Provisioner           = (*RejectIdentityHeaders)(nil)
	_ caddyhttp.MiddlewareHandler = (*RejectIdentityHeaders)(nil)
	_ caddyfile.Unmarshaler       = (*RejectIdentityHeaders)(nil)
)
