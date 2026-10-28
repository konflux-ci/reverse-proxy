package impersonate

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"github.com/onsi/gomega"
)

func TestIdentityGuardPlacement(t *testing.T) {
	cases := []struct {
		name    string
		routes  string
		wantErr error
	}{
		{
			name: "reject then impersonate",
			routes: `[
				{"handle":[
					{"handler":"reject_identity_headers"},
					{"handler":"impersonate"}
				]}
			]`,
		},
		{
			name: "site reject covers a nested route",
			routes: `[
				{"handle":[
					{"handler":"reject_identity_headers"},
					{"handler":"subroute","routes":[
						{"handle":[{"handler":"impersonate"}]}
					]}
				]}
			]`,
		},
		{
			name: "reject on an earlier matcherless route covers the next",
			routes: `[
				{"handle":[{"handler":"reject_identity_headers"}]},
				{"handle":[{"handler":"impersonate"}]}
			]`,
		},
		{
			name: "reject and impersonate share a matched route",
			routes: `[
				{"match":[{"path":["/api/*"]}],"handle":[
					{"handler":"reject_identity_headers"},
					{"handler":"impersonate"}
				]}
			]`,
		},
		{
			name: "each matched route has its own reject",
			routes: `[
				{"match":[{"path":["/a*"]}],"handle":[
					{"handler":"reject_identity_headers"},
					{"handler":"impersonate"}
				]},
				{"match":[{"path":["/b*"]}],"handle":[
					{"handler":"reject_identity_headers"},
					{"handler":"impersonate"}
				]}
			]`,
		},
		{
			name: "impersonate before reject",
			routes: `[
				{"handle":[
					{"handler":"impersonate"},
					{"handler":"reject_identity_headers"}
				]}
			]`,
			wantErr: errIdentityGuardPath,
		},
		{
			name: "reject on another matched route",
			routes: `[
				{"match":[{"path":["/other*"]}],"handle":[
					{"handler":"reject_identity_headers"}
				]},
				{"handle":[{"handler":"subroute","routes":[
					{"handle":[{"handler":"impersonate"}]}
				]}]}
			]`,
			wantErr: errIdentityGuardPath,
		},
		{
			name:    "impersonate with no reject",
			routes:  `[{"handle":[{"handler":"impersonate"}]}]`,
			wantErr: errIdentityGuardPath,
		},
		{
			name: "nested error route has its own reject",
			routes: `[{"handle":[{"handler":"subroute","errors":{"routes":[
				{"handle":[{"handler":"reject_identity_headers"},{"handler":"impersonate"}]}
			]}}]}]`,
		},
		{
			name: "nested error route cannot inherit a guard from the primary subroutes",
			routes: `[{"handle":[{"handler":"subroute",
				"routes":[{"handle":[{"handler":"reject_identity_headers"}]}],
				"errors":{"routes":[{"handle":[{"handler":"impersonate"}]}]}
			}]}]`,
			wantErr: errIdentityGuardPath,
		},
		{
			name: "unconditional terminal route makes later handlers unreachable",
			routes: `[
				{"terminal":true,"handle":[{"handler":"reject_identity_headers"},{"handler":"impersonate"}]},
				{"handle":[{"handler":"impersonate"}]}
			]`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			server := serverWithRoutes(t, tc.routes)
			err := identityGuardCoversServer(server)
			if tc.wantErr == nil {
				g.Expect(err).NotTo(gomega.HaveOccurred())
				return
			}
			g.Expect(err).To(gomega.MatchError(tc.wantErr))
		})
	}
}

func TestIdentityGuardErrorAndNamedRoutes(t *testing.T) {
	g := gomega.NewWithT(t)

	unguarded := serverWithRoutes(t, `[{"handle":[{"handler":"impersonate"}]}]`)
	guarded := serverWithRoutes(t, `[
		{"handle":[
			{"handler":"reject_identity_headers"},
			{"handler":"impersonate"}
		]}
	]`)

	g.Expect(identityGuardCoversServer(&caddyhttp.Server{
		Routes: guarded.Routes,
		Errors: &caddyhttp.HTTPErrorConfig{Routes: unguarded.Routes},
	})).To(gomega.MatchError(errIdentityGuardPath))

	named := unguarded.Routes[0]
	g.Expect(identityGuardCoversServer(&caddyhttp.Server{
		Routes:      guarded.Routes,
		NamedRoutes: map[string]*caddyhttp.Route{"extra": &named},
	})).To(gomega.MatchError(errIdentityGuardPath))
}

func TestAdaptedCaddyfileGuardPlacement(t *testing.T) {
	g := gomega.NewWithT(t)

	g.Expect(guardErrorForCaddyfile(t, `{
		admin off
	}

	:8080 {
		reject_identity_headers
		route {
			impersonate
			respond "ok"
		}
	}`)).NotTo(gomega.HaveOccurred())

	err := guardErrorForCaddyfile(t, `{
		admin off
	}

	:8080 {
		handle /other* {
			reject_identity_headers
			respond "other"
		}
		handle {
			route {
				impersonate
				respond "ok"
			}
		}
	}`)
	g.Expect(err).To(gomega.MatchError(errIdentityGuardPath))
}

func serverWithRoutes(t *testing.T, raw string) *caddyhttp.Server {
	t.Helper()
	var routes caddyhttp.RouteList
	gomega.NewWithT(t).Expect(json.Unmarshal([]byte(raw), &routes)).To(gomega.Succeed())
	return &caddyhttp.Server{Routes: routes}
}

func guardErrorForCaddyfile(t *testing.T, caddyfile string) error {
	t.Helper()
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter not registered")
	}
	raw, _, err := adapter.Adapt([]byte(caddyfile), nil)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	var cfg struct {
		Apps struct {
			HTTP caddyhttp.App `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	var saw bool
	var guardErr error
	for name, srv := range cfg.Apps.HTTP.Servers {
		err := identityGuardCoversServer(srv)
		if errors.Is(err, errIdentityGuardMissing) {
			continue
		}
		if saw {
			t.Fatalf("server %s: more than one server contains impersonate", name)
		}
		saw = true
		guardErr = err
	}
	if !saw {
		t.Fatalf("no server contained impersonate\n%s", raw)
	}
	return guardErr
}
