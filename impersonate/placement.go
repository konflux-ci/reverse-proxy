package impersonate

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	rejectIdentityHeadersHandler = "reject_identity_headers"
	impersonateHandler           = "impersonate"
	subrouteHandler              = "subroute"
)

var (
	errIdentityGuardMissing = errors.New(
		"impersonate requires reject_identity_headers on this server")
	errIdentityGuardPath = errors.New(
		"impersonate requires reject_identity_headers earlier on the same request path")
)

// requireRejectBeforeImpersonate fails config load when any impersonate
// handler on this server can run without reject_identity_headers earlier
// on the same request path.
//
// The check reads route JSON (HandlersRaw) for routes being provisioned and
// compiled Handlers for earlier routes. Caddy fills Handlers and clears
// HandlersRaw after every handler in a route has finished Provision.
//
// A reject handler covers later handlers in its own chain, nested subroutes
// that appear after it, and later sibling routes only when its own route has
// no matcher or group. A reject inside one handle block does not cover
// impersonate in another handle block.
func requireRejectBeforeImpersonate(ctx caddy.Context) error {
	if ctx.Context == nil {
		return errIdentityGuardMissing
	}
	server, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	if !ok || server == nil {
		return errIdentityGuardMissing
	}
	return identityGuardCoversServer(server)
}

func identityGuardCoversServer(server *caddyhttp.Server) error {
	walk := &guardWalk{}
	if err := walk.routes(server.Routes, false); err != nil {
		return err
	}
	if server.Errors != nil {
		if err := walk.routes(server.Errors.Routes, false); err != nil {
			return err
		}
	}
	for _, route := range server.NamedRoutes {
		if route == nil {
			continue
		}
		if err := walk.routes(caddyhttp.RouteList{*route}, false); err != nil {
			return err
		}
	}
	if walk.found == 0 {
		return errIdentityGuardMissing
	}
	return nil
}

// guardWalk counts impersonate handlers while checking that each one is
// downstream of reject_identity_headers.
type guardWalk struct {
	found int
}

// handlerHead is the part of a handler's JSON this check needs.
type handlerHead struct {
	Handler string                     `json:"handler"`
	Routes  caddyhttp.RouteList        `json:"routes"`
	Errors  *caddyhttp.HTTPErrorConfig `json:"errors"`
}

func (w *guardWalk) routes(routes caddyhttp.RouteList, inherited bool) error {
	coveredForLater := inherited
	for i := range routes {
		setsGuard, err := w.handlers(routes[i], coveredForLater)
		if err != nil {
			return err
		}
		if !routeMatchesEveryRequest(routes[i]) {
			continue
		}
		if setsGuard {
			coveredForLater = true
		}
		if routes[i].Terminal {
			break
		}
	}
	return nil
}

// handlers walks one route's middleware chain. covered is true when an
// earlier handler on this path already rejects identity headers. setsGuard
// reports that this chain itself contains reject_identity_headers, which
// covers later sibling routes only when this route matches every request.
func (w *guardWalk) handlers(route caddyhttp.Route, covered bool) (bool, error) {
	heads, err := routeHandlerHeads(route)
	if err != nil {
		return false, err
	}
	setsGuard := false
	for _, head := range heads {
		switch head.Handler {
		case rejectIdentityHeadersHandler:
			covered = true
			setsGuard = true
		case impersonateHandler:
			w.found++
			if !covered {
				return false, errIdentityGuardPath
			}
		case subrouteHandler:
			if err := w.routes(head.Routes, covered); err != nil {
				return false, err
			}
			if head.Errors != nil {
				if err := w.routes(head.Errors.Routes, covered); err != nil {
					return false, err
				}
			}
		}
	}
	return setsGuard, nil
}

// routeHandlerHeads exposes the same routing information before and after
// provisioning. Keep compiled subroutes intact so their compiled children
// remain visible to the recursive walk.
func routeHandlerHeads(route caddyhttp.Route) ([]handlerHead, error) {
	if len(route.HandlersRaw) > 0 {
		heads := make([]handlerHead, len(route.HandlersRaw))
		for i, msg := range route.HandlersRaw {
			if err := json.Unmarshal(msg, &heads[i]); err != nil {
				return nil, fmt.Errorf("impersonate: reading route handler: %w", err)
			}
		}
		return heads, nil
	}

	heads := make([]handlerHead, 0, len(route.Handlers))
	for _, handler := range route.Handlers {
		switch h := handler.(type) {
		case *RejectIdentityHeaders:
			heads = append(heads, handlerHead{Handler: rejectIdentityHeadersHandler})
		case *Handler:
			heads = append(heads, handlerHead{Handler: impersonateHandler})
		case *caddyhttp.Subroute:
			heads = append(heads, handlerHead{Handler: subrouteHandler, Routes: h.Routes, Errors: h.Errors})
		}
	}
	return heads, nil
}

func routeMatchesEveryRequest(route caddyhttp.Route) bool {
	// Even a matcherless route can be skipped when another route in its group
	// already matched. It cannot establish a guard or terminate every path.
	return route.Group == "" && len(route.MatcherSetsRaw) == 0 && len(route.MatcherSets) == 0
}
