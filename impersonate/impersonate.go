// Package impersonate provides a Caddy HTTP handler middleware that translates
// authentication headers from an auth proxy (e.g. oauth2-proxy) into
// Kubernetes-style impersonation headers or generic user/group headers.
//
// # Problem
//
// The Kubernetes API requires each group to be sent as a separate
// Impersonate-Group HTTP header. However, oauth2-proxy returns all groups
// in a single comma-separated X-Auth-Request-Groups header
// (e.g. "group1,group2,group3"). Stock Caddy has no built-in way to split
// one header value into multiple headers with the same name.
//
// # Solution
//
// This module registers an HTTP handler (http.handlers.impersonate) that
// reads a user identity and a delimited group list from source headers,
// splits the groups, and writes each as an individual target header. It
// supports an unlimited number of groups, trims whitespace, skips empty
// values, and always appends configurable static groups (by default
// "system:authenticated").
//
// The handler is also usable for non-Kubernetes targets that expect
// similar multi-valued headers (e.g. X-User / X-Group for namespace-lister).
//
// # Caddyfile Usage
//
// Kubernetes API impersonation with defaults (zero config):
//
//	route {
//	    forward_auth 127.0.0.1:6000 {
//	        uri /oauth2/auth
//	        copy_headers X-Auth-Request-Email X-Auth-Request-Groups
//	    }
//	    impersonate
//	    reverse_proxy https://kubernetes.default.svc { ... }
//	}
//
// All options with their defaults shown:
//
//	impersonate {
//	    source_user   X-Auth-Request-Email
//	    source_groups X-Auth-Request-Groups
//	    target_user   Impersonate-User
//	    target_group  Impersonate-Group
//	    always_include system:authenticated
//	    separator     ,
//	}
//
// Namespace-lister variant (custom target headers):
//
//	impersonate {
//	    target_user  X-User
//	    target_group X-Group
//	}
package impersonate

import (
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("impersonate", parseCaddyfile)
}

// Handler is a Caddy HTTP middleware that reads user and group information
// from auth-proxy response headers and sets them as impersonation headers
// on the request before passing it to the next handler.
type Handler struct {
	// Header containing the authenticated user's identity (email).
	// Default: X-Auth-Request-Email
	SourceUser string `json:"source_user,omitempty"`

	// Header containing the authenticated user's groups as a delimited string.
	// Default: X-Auth-Request-Groups
	SourceGroups string `json:"source_groups,omitempty"`

	// Header name to set for the user identity.
	// Default: Impersonate-User
	TargetUser string `json:"target_user,omitempty"`

	// Header name to set for each group (one header per group).
	// Default: Impersonate-Group
	TargetGroup string `json:"target_group,omitempty"`

	// Groups that are always added regardless of what the auth proxy returns.
	// Default: ["system:authenticated"]
	AlwaysInclude []string `json:"always_include,omitempty"`

	// Delimiter used to split the source groups header.
	// Default: ","
	Separator string `json:"separator,omitempty"`

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

// Provision sets up the handler by applying default values for any
// fields not explicitly configured and initializing the logger.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()

	if h.SourceUser == "" {
		h.SourceUser = "X-Auth-Request-Email"
	}
	if h.SourceGroups == "" {
		h.SourceGroups = "X-Auth-Request-Groups"
	}
	if h.TargetUser == "" {
		h.TargetUser = "Impersonate-User"
	}
	if h.TargetGroup == "" {
		h.TargetGroup = "Impersonate-Group"
	}
	if h.Separator == "" {
		h.Separator = ","
	}
	if h.AlwaysInclude == nil {
		h.AlwaysInclude = []string{"system:authenticated"}
	}

	return nil
}

// ServeHTTP reads the source user/groups headers, translates them into
// target headers, and passes the request to the next handler.
//
// Processing order:
//  1. Copy SourceUser → TargetUser (skip if source is empty).
//  2. Delete any pre-existing TargetGroup headers.
//  3. Split SourceGroups by Separator, trim whitespace, skip empty values,
//     and add each as an individual TargetGroup header.
//  4. Append all AlwaysInclude groups as additional TargetGroup headers.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	user := r.Header.Get(h.SourceUser)
	if user != "" {
		r.Header.Set(h.TargetUser, user)
	}

	r.Header.Del(h.TargetGroup)

	groupsRaw := r.Header.Get(h.SourceGroups)
	if groupsRaw != "" {
		for g := range strings.SplitSeq(groupsRaw, h.Separator) {
			g = strings.TrimSpace(g)
			if g != "" {
				r.Header.Add(h.TargetGroup, g)
			}
		}
	}

	for _, g := range h.AlwaysInclude {
		r.Header.Add(h.TargetGroup, g)
	}

	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile parses the "impersonate" Caddyfile directive. It accepts
// an optional block with the following subdirectives:
//
//   - source_user <header>     — header to read user identity from
//   - source_groups <header>   — header to read comma-separated groups from
//   - target_user <header>     — header name to set for user identity
//   - target_group <header>    — header name to add for each group
//   - always_include <groups>  — space-separated groups always appended
//   - separator <string>       — delimiter for splitting source groups
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	for d.NextBlock(0) {
		switch d.Val() {
		case "source_user":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.SourceUser = d.Val()
		case "source_groups":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.SourceGroups = d.Val()
		case "target_user":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.TargetUser = d.Val()
		case "target_group":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.TargetGroup = d.Val()
		case "always_include":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.AlwaysInclude = append(h.AlwaysInclude, args...)
		case "separator":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.Separator = d.Val()
		default:
			return d.Errf("unrecognized option: %s", d.Val())
		}
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

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
