// Package impersonate provides a Caddy HTTP handler middleware that translates
// an authenticated identity into Kubernetes-style impersonation headers.
//
// User identity is copied from a source header (default X-Auth-Request-Email)
// to Impersonate-User. Groups come from the ID token's JSON array, not from a
// comma-separated header. oauth2-proxy joins the groups claim with commas and
// no quoting, so a group whose name contains a comma is indistinguishable
// from two groups. Dex already stores those names in the ID token as a JSON
// array, and oauth2-proxy puts that raw token on the /oauth2/auth response
// as Authorization: Bearer <id_token> when --set-authorization-header is set.
//
// The handler is designed to run immediately after an authentication proxy
// such as oauth2-proxy, and it relies on that proxy to verify the JWT. This
// code does not check the signature, issuer, or audience. The Caddy route
// must list the token header in forward_auth copy_headers. Caddy then
// deletes the client-supplied value and copies the proxy's verified token
// onto the request before this handler reads it. A route that skips that
// copy accepts a client-supplied compact JWT as the group list. After the
// handler reads the token it deletes that header, including when parsing
// fails, so the JWT is not proxied upstream.
//
// Groups with the prefix system: are dropped, except the exact group
// system:authenticated. The exact groups kubeadm:cluster-admins,
// cluster-admins, and dedicated-admins are dropped too. Other groups are
// impersonated. A dropped group does not fail the request. always_include
// entries that this denylist would drop are rejected when the handler is
// provisioned. The default always_include value is system:authenticated,
// and a group that is already present is not added again.
//
// token_groups off skips the ID token. The handler still copies the user,
// sends only always_include, and deletes Authorization so a client bearer
// is not proxied. It does not require Authorization. source_groups and
// separator are rejected when the Caddyfile is loaded.
//
// # Caddyfile Usage
//
//	route {
//	    forward_auth 127.0.0.1:6000 {
//	        uri /oauth2/auth
//	        copy_headers X-Auth-Request-Email Authorization
//	    }
//	    impersonate
//	    reverse_proxy https://kubernetes.default.svc { ... }
//	}
//
// All options with their defaults shown:
//
//	impersonate {
//	    source_user     X-Auth-Request-Email
//	    source_id_token Authorization
//	    groups_claim    groups
//	    target_user     Impersonate-User
//	    target_group    Impersonate-Group
//	    always_include  system:authenticated
//	    token_groups    on
//	}
//
// Skip token groups and send only the static group list:
//
//	impersonate {
//	    token_groups off
//	}
package impersonate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const authenticatedGroup = "system:authenticated"

// init registers the impersonate HTTP handler and its Caddyfile directive.
func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("impersonate", parseCaddyfile)
}

// Handler is a Caddy HTTP middleware that reads a user identity and an ID
// token and sets impersonation headers before passing the request on.
// It is designed to run after an authentication proxy. The proxy verifies
// the JWT; this handler only reads the groups claim from the header that
// forward_auth copied out of the proxy's response.
type Handler struct {
	// Header containing the authenticated user's identity (email).
	// Default: X-Auth-Request-Email
	SourceUser string `json:"source_user,omitempty"`

	// Header containing the ID token. A leading "Bearer " prefix is stripped
	// once; the remainder is the compact JWT. A value with no prefix is the
	// compact JWT itself.
	// Default: Authorization. Rejected when token groups are off.
	SourceIDToken string `json:"source_id_token,omitempty"`

	// JWT claim that holds the group names as a JSON array of strings.
	// Default: groups. Rejected when token groups are off.
	GroupsClaim string `json:"groups_claim,omitempty"`

	// Header name to set for the user identity.
	// Default: Impersonate-User
	TargetUser string `json:"target_user,omitempty"`

	// Header name to set for each group (one header per group).
	// Default: Impersonate-Group
	TargetGroup string `json:"target_group,omitempty"`

	// Groups that are always added. A group the denylist would drop is a
	// provision error. Default: ["system:authenticated"]
	AlwaysInclude []string `json:"always_include,omitempty"`

	// When false, groups are not read from the ID token. nil means on.
	TokenGroups *bool `json:"token_groups,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information. The module is registered
// in the http.handlers namespace as "impersonate".
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.impersonate",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets defaults and rejects configuration that would impersonate
// a reserved or platform-admin group.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()

	if h.SourceUser == "" {
		h.SourceUser = "X-Auth-Request-Email"
	}
	if h.TargetUser == "" {
		h.TargetUser = "Impersonate-User"
	}
	if h.TargetGroup == "" {
		h.TargetGroup = "Impersonate-Group"
	}
	if h.AlwaysInclude == nil {
		h.AlwaysInclude = []string{authenticatedGroup}
	}
	for _, g := range h.AlwaysInclude {
		if groupDenied(g) {
			return fmt.Errorf(
				"always_include group %q is reserved and cannot be impersonated", g)
		}
	}
	if !h.tokenGroupsEnabled() {
		if h.SourceIDToken != "" || h.GroupsClaim != "" {
			return errors.New(
				"token_groups off cannot be combined with source_id_token or groups_claim")
		}
		return nil
	}
	if h.SourceIDToken == "" {
		h.SourceIDToken = "Authorization"
	}
	if h.GroupsClaim == "" {
		h.GroupsClaim = "groups"
	}
	return nil
}

// ServeHTTP copies the user, reads groups from the ID token unless
// token_groups is off, and passes the request to the next handler.
// The token header is expected to be the value forward_auth copied from
// the authentication proxy. This handler does not verify it. A missing or
// malformed token returns 401. The token header is removed before the next
// handler runs and before that error is returned. token_groups off does
// not read the token, and still removes Authorization.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if user := r.Header.Get(h.SourceUser); user != "" {
		r.Header.Set(h.TargetUser, user)
	}

	var tokenGroups []string
	if h.tokenGroupsEnabled() {
		raw := r.Header.Get(h.SourceIDToken)
		r.Header.Del(h.SourceIDToken)
		var err error
		tokenGroups, err = groupsFromToken(raw, h.GroupsClaim)
		if err != nil {
			h.logger.Warn("failed to read groups from ID token", zap.Error(err))
			return caddyhttp.Error(http.StatusUnauthorized, err)
		}
	} else {
		// SourceIDToken stays empty in this mode, so the header to drop is
		// the default bearer header rather than the configured name.
		r.Header.Del("Authorization")
	}

	h.writeGroups(r, tokenGroups)
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile parses the "impersonate" Caddyfile directive.
// source_groups and separator are rejected. token_groups accepts on or off.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	for d.NextBlock(0) {
		if err := h.unmarshalOption(d); err != nil {
			return err
		}
	}
	return nil
}

// unmarshalOption parses the Caddyfile directive at the dispenser's current token.
func (h *Handler) unmarshalOption(d *caddyfile.Dispenser) error {
	switch d.Val() {
	case "source_user":
		return unmarshalHeader(d, &h.SourceUser)
	case "source_id_token":
		return unmarshalHeader(d, &h.SourceIDToken)
	case "groups_claim":
		return unmarshalHeader(d, &h.GroupsClaim)
	case "target_user":
		return unmarshalHeader(d, &h.TargetUser)
	case "target_group":
		return unmarshalHeader(d, &h.TargetGroup)
	case "always_include":
		args := d.RemainingArgs()
		if len(args) == 0 {
			return d.ArgErr()
		}
		h.AlwaysInclude = append(h.AlwaysInclude, args...)
		return nil
	case "token_groups":
		return h.unmarshalTokenGroups(d)
	case "source_groups", "separator":
		return d.Errf("%s is no longer supported; read groups from the ID token", d.Val())
	default:
		return d.Errf("unrecognized option: %s", d.Val())
	}
}

// unmarshalHeader reads one header-name argument and stores it in dest.
func unmarshalHeader(d *caddyfile.Dispenser, dest *string) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	*dest = d.Val()
	return nil
}

// unmarshalTokenGroups reads "on" or "off" into TokenGroups.
// Any other argument, or a missing argument, is an error.
func (h *Handler) unmarshalTokenGroups(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	switch d.Val() {
	case "on":
		on := true
		h.TokenGroups = &on
	case "off":
		off := false
		h.TokenGroups = &off
	default:
		return d.Errf("token_groups must be \"on\" or \"off\"")
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

// parseCaddyfile is the adapter that registers "impersonate" as a
// Caddyfile handler directive via httpcaddyfile.RegisterHandlerDirective.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

// tokenGroupsEnabled reports whether groups are read from the ID token.
// A nil TokenGroups means they are read.
func (h Handler) tokenGroupsEnabled() bool {
	return h.TokenGroups == nil || *h.TokenGroups
}

// writeGroups replaces TargetGroup with the allowed token groups, then
// appends AlwaysInclude. A denied group is logged and skipped. A group that
// is already present is not added again.
func (h Handler) writeGroups(r *http.Request, tokenGroups []string) {
	r.Header.Del(h.TargetGroup)
	seen := make(map[string]struct{}, len(tokenGroups)+len(h.AlwaysInclude))
	add := func(name string) {
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		r.Header.Add(h.TargetGroup, name)
	}
	for _, g := range tokenGroups {
		if groupDenied(g) {
			h.logger.Info(
				"dropped group that cannot be impersonated",
				zap.String("group", g),
			)
			continue
		}
		add(g)
	}
	for _, g := range h.AlwaysInclude {
		add(g)
	}
}

var (
	errMissingIDToken       = errors.New("missing ID token")
	errNotCompactJWT        = errors.New("ID token is not a compact JWT")
	errBadPayloadEncoding   = errors.New("ID token payload is not valid base64url")
	errPayloadNotObject     = errors.New("ID token payload is not a JSON object")
	errGroupsNotStringArray = errors.New("group claim is not a JSON array of strings")
	errEmptyGroup           = errors.New("group claim contains an empty string")
)

// groupsFromToken decodes the compact JWT in raw and returns the string
// array stored under claim. One leading "Bearer " prefix is removed. A value
// with no prefix is the compact JWT itself. It does not verify the token:
// the authentication proxy already did, and raw must be the header that
// proxy returned. An absent claim or JSON null returns no groups and a nil
// error.
func groupsFromToken(raw, claim string) ([]string, error) {
	if raw == "" {
		return nil, errMissingIDToken
	}
	token, _ := strings.CutPrefix(raw, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, errNotCompactJWT
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errBadPayloadEncoding
	}
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 || payload[0] != '{' {
		return nil, errPayloadNotObject
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil || claims == nil {
		return nil, errPayloadNotObject
	}
	rawClaim, ok := claims[claim]
	if !ok || bytes.Equal(bytes.TrimSpace(rawClaim), []byte("null")) {
		return nil, nil
	}
	var groups []string
	if err := json.Unmarshal(rawClaim, &groups); err != nil {
		return nil, errGroupsNotStringArray
	}
	if slices.Contains(groups, "") {
		return nil, errEmptyGroup
	}
	return groups, nil
}

// groupDenied reports whether name must not be impersonated.
// The match is case-sensitive, matching Kubernetes.
func groupDenied(name string) bool {
	if name != authenticatedGroup && strings.HasPrefix(name, "system:") {
		return true
	}
	switch name {
	case "kubeadm:cluster-admins", "cluster-admins", "dedicated-admins":
		return true
	default:
		return false
	}
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
