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
// The check reads route JSON (HandlersRaw) rather than the compiled handler
// list. Caddy fills Route.Handlers only after every handler in that route
// has finished Provision, so the compiled list is still empty while
// impersonate is being set up. HandlersRaw is already populated.
//
// A reject handler covers later handlers in its own chain, nested subroutes
// that appear after it, and later sibling routes only when its own route has
// no matcher. A reject inside one handle block does not cover impersonate
// in another handle block.
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
		setsGuard, err := w.handlers(routes[i].HandlersRaw, coveredForLater)
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
func (w *guardWalk) handlers(raw []json.RawMessage, covered bool) (bool, error) {
	setsGuard := false
	for _, msg := range raw {
		var head handlerHead
		if err := json.Unmarshal(msg, &head); err != nil {
			return false, fmt.Errorf("impersonate: reading route handler: %w", err)
		}
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

func routeMatchesEveryRequest(route caddyhttp.Route) bool {
	return len(route.MatcherSetsRaw) == 0 && len(route.MatcherSets) == 0
}
