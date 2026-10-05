package impersonate

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/onsi/gomega"
)

func provision(t *testing.T, h *Handler) {
	t.Helper()
	g := gomega.NewWithT(t)
	g.Expect(h.Provision(caddy.Context{})).To(gomega.Succeed())
}

func boolPtr(v bool) *bool { return &v }

func compactJWT(t *testing.T, payload string) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(payload)) + ".sig"
}

func groupsJWT(t *testing.T, groups []string) string {
	t.Helper()
	payload, err := json.Marshal(map[string][]string{"groups": groups})
	gomega.NewWithT(t).Expect(err).NotTo(gomega.HaveOccurred())
	return compactJWT(t, string(payload))
}

func requestWithUser(user string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if user != "" {
		r.Header.Set("X-Auth-Request-Email", user)
	}
	return r
}

func requestWithToken(t *testing.T, user, token string) *http.Request {
	t.Helper()
	r := requestWithUser(user)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// captureNext is a caddyhttp.Handler that captures the request headers
// as seen by the next handler in the chain.
type captureNext struct {
	header http.Header
	called bool
}

func (c *captureNext) ServeHTTP(_ http.ResponseWriter, r *http.Request) error {
	c.called = true
	c.header = r.Header.Clone()
	return nil
}

func serve(t *testing.T, h *Handler, r *http.Request) http.Header {
	t.Helper()
	g := gomega.NewWithT(t)
	header, called := serveCapture(t, h, r)
	g.Expect(called).To(gomega.BeTrue())
	return header
}

func serveCapture(t *testing.T, h *Handler, r *http.Request) (http.Header, bool) {
	t.Helper()
	w := httptest.NewRecorder()
	next := &captureNext{}
	err := h.ServeHTTP(w, r, next)
	gomega.NewWithT(t).Expect(err).NotTo(gomega.HaveOccurred())
	return next.header, next.called
}

func expectUnauthorized(t *testing.T, err error) {
	t.Helper()
	g := gomega.NewWithT(t)
	var he caddyhttp.HandlerError
	g.Expect(errors.As(err, &he)).To(gomega.BeTrue())
	g.Expect(he.StatusCode).To(gomega.Equal(http.StatusUnauthorized))
}

func TestDefaultsSetImpersonateUser(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, requestWithToken(t, "alice@example.com", groupsJWT(t, nil)))
	g.Expect(got.Get("Impersonate-User")).To(gomega.Equal("alice@example.com"))
}

func TestCommaInGroupNameStaysOneGroup(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	name := "team-a,system:masters"
	got := serve(t, h, requestWithToken(t, "alice@example.com", groupsJWT(t, []string{name})))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{name, "system:authenticated"}))
}

func TestSeveralGroups(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, requestWithToken(t, "alice@example.com", groupsJWT(t,
		[]string{"developers", "admins", "ops"})))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"developers", "admins", "ops", "system:authenticated"}))
}

func TestGroupNamePreservesSpaces(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, requestWithToken(t, "alice@example.com", groupsJWT(t, []string{" devs "})))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{" devs ", "system:authenticated"}))
}

func TestRawJWTWithoutBearerPrefix(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	r := requestWithUser("alice@example.com")
	r.Header.Set("Authorization", groupsJWT(t, []string{"devs"}))

	got := serve(t, h, r)
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "system:authenticated"}))
	g.Expect(got.Get("Authorization")).To(gomega.BeEmpty())
}

func TestAbsentGroupsClaimStillAddsAlwaysInclude(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, requestWithToken(t, "alice@example.com", compactJWT(t, `{}`)))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"system:authenticated"}))
}

func TestNullGroupsClaimStillAddsAlwaysInclude(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	token := compactJWT(t, `{"groups":null}`)
	got := serve(t, h, requestWithToken(t, "alice@example.com", token))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"system:authenticated"}))
}

func TestEmptyGroupsArrayStillAddsAlwaysInclude(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, requestWithToken(t, "alice@example.com", groupsJWT(t, []string{})))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"system:authenticated"}))
}

func TestJSONStringClaimIsUnauthorized(t *testing.T) {
	h := &Handler{}
	provision(t, h)

	r := requestWithToken(t, "alice@example.com", compactJWT(t, `{"groups":"team-a,system:masters"}`))
	err := h.ServeHTTP(httptest.NewRecorder(), r, &captureNext{})
	expectUnauthorized(t, err)
}

func TestEmptyGroupElementIsUnauthorized(t *testing.T) {
	h := &Handler{}
	provision(t, h)

	r := requestWithToken(t, "alice@example.com", groupsJWT(t, []string{"devs", ""}))
	err := h.ServeHTTP(httptest.NewRecorder(), r, &captureNext{})
	expectUnauthorized(t, err)
}

func TestMalformedTokenIsUnauthorized(t *testing.T) {
	cases := []struct {
		name    string
		header  string
		payload string
	}{
		{name: "missing header"},
		{name: "not compact", header: "Bearer not-a-jwt"},
		{name: "two parts", header: "Bearer a.b"},
		{name: "four parts", header: "Bearer a.b.c.d"},
		{name: "empty signature", header: "Bearer a.b."},
		{name: "bad base64", header: "Bearer aaa.!!!!.sig"},
		{name: "payload array", payload: `["developers"]`},
		{name: "payload null", payload: `null`},
		{name: "payload string", payload: `"developers"`},
		{name: "groups number", payload: `{"groups":1}`},
		{name: "groups object", payload: `{"groups":{"name":"devs"}}`},
		{name: "groups mixed", payload: `{"groups":["devs",1]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{}
			provision(t, h)

			r := requestWithUser("alice@example.com")
			switch {
			case tc.header != "":
				r.Header.Set("Authorization", tc.header)
			case tc.payload != "":
				r.Header.Set("Authorization", "Bearer "+compactJWT(t, tc.payload))
			}

			next := &captureNext{}
			err := h.ServeHTTP(httptest.NewRecorder(), r, next)
			expectUnauthorized(t, err)
			gomega.NewWithT(t).Expect(next.called).To(gomega.BeFalse())
		})
	}
}

func TestAuthorizationStrippedAfterSuccess(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	r := requestWithToken(t, "alice@example.com", groupsJWT(t, []string{"devs"}))
	got := serve(t, h, r)
	g.Expect(got.Get("Authorization")).To(gomega.BeEmpty())
	g.Expect(r.Header.Get("Authorization")).To(gomega.BeEmpty())
}

func TestAuthorizationStrippedAfterUnauthorized(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	r := requestWithUser("alice@example.com")
	r.Header.Set("Authorization", "not-a-jwt")
	next := &captureNext{}
	err := h.ServeHTTP(httptest.NewRecorder(), r, next)
	expectUnauthorized(t, err)
	g.Expect(next.called).To(gomega.BeFalse())
	g.Expect(r.Header.Get("Authorization")).To(gomega.BeEmpty())
}

func TestPrivilegedGroupsDropped(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	commaName := "acme,system:masters"
	token := groupsJWT(t, []string{
		"team-a",
		"system:masters",
		"system:cluster-admins",
		"system:authenticated",
		"system:authenticated:oauth",
		"cluster-admins",
		"dedicated-admins",
		"kubeadm:cluster-admins",
		commaName,
	})
	got := serve(t, h, requestWithToken(t, "alice@example.com", token))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"team-a", "system:authenticated", commaName}))
}

func TestNonReservedGroupsKept(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	token := groupsJWT(t, []string{
		"System:masters",
		"cluster-admin",
		"dedicated-admin",
		"kubeadm:other",
	})
	got := serve(t, h, requestWithToken(t, "alice@example.com", token))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal([]string{
		"System:masters",
		"cluster-admin",
		"dedicated-admin",
		"kubeadm:other",
		"system:authenticated",
	}))
}

func TestDuplicateGroupsSentOnce(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	token := groupsJWT(t, []string{"team-a", "team-a", "system:authenticated"})
	got := serve(t, h, requestWithToken(t, "alice@example.com", token))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"team-a", "system:authenticated"}))
}

func TestNoUserHeaderSkipsTargetUser(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, requestWithToken(t, "", groupsJWT(t, []string{"developers"})))
	g.Expect(got.Get("Impersonate-User")).To(gomega.BeEmpty())
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"developers", "system:authenticated"}))
}

func TestCustomTargetHeaders(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{
		TargetUser:  "X-User",
		TargetGroup: "X-Group",
	}
	provision(t, h)

	got := serve(t, h, requestWithToken(t, "alice@example.com", groupsJWT(t, []string{"devs", "ops"})))
	g.Expect(got.Get("X-User")).To(gomega.Equal("alice@example.com"))
	g.Expect(got.Values("X-Group")).To(gomega.Equal(
		[]string{"devs", "ops", "system:authenticated"}))
	g.Expect(got.Get("Impersonate-User")).To(gomega.BeEmpty())
}

func TestCustomTokenHeaderAndClaim(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{
		SourceIDToken: "X-Id-Token",
		GroupsClaim:   "roles",
	}
	provision(t, h)

	payload, err := json.Marshal(map[string][]string{"roles": {"devs"}})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	r := requestWithUser("alice@example.com")
	r.Header.Set("X-Id-Token", "Bearer "+compactJWT(t, string(payload)))
	r.Header.Set("Authorization", "leave-me")

	got := serve(t, h, r)
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "system:authenticated"}))
	g.Expect(got.Get("X-Id-Token")).To(gomega.BeEmpty())
	g.Expect(r.Header.Get("X-Id-Token")).To(gomega.BeEmpty())
	g.Expect(got.Get("Authorization")).To(gomega.Equal("leave-me"))
}

func TestAlwaysIncludeEmpty(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{AlwaysInclude: []string{}}
	provision(t, h)

	got := serve(t, h, requestWithToken(t, "alice@example.com", groupsJWT(t, []string{"devs"})))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal([]string{"devs"}))
}

func TestAlwaysIncludeMultiple(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{
		AlwaysInclude: []string{"system:authenticated", "extra-group"},
	}
	provision(t, h)

	got := serve(t, h, requestWithToken(t, "alice@example.com", groupsJWT(t, []string{"devs"})))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "system:authenticated", "extra-group"}))
}

func TestPreExistingTargetGroupsCleared(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	r := requestWithToken(t, "alice@example.com", groupsJWT(t, []string{"devs"}))
	r.Header.Set("Impersonate-Group", "should-be-removed")

	got := serve(t, h, r)
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "system:authenticated"}))
}

func TestProvisionRejectsDeniedAlwaysInclude(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{AlwaysInclude: []string{"system:masters"}}
	err := h.Provision(caddy.Context{})
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("system:masters"))
}

func TestProvisionAllowsAuthenticatedAlwaysInclude(t *testing.T) {
	h := &Handler{AlwaysInclude: []string{"system:authenticated", "team-a"}}
	provision(t, h)
}

func TestTokenGroupsOffSkipsToken(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{TokenGroups: boolPtr(false)}
	provision(t, h)

	r := requestWithUser("alice@example.com")
	r.Header.Set("Authorization", "Bearer "+groupsJWT(t, []string{"team-a", "system:masters"}))
	r.Header.Add("Impersonate-Group", "client-supplied")

	got := serve(t, h, r)
	g.Expect(got.Get("Impersonate-User")).To(gomega.Equal("alice@example.com"))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"system:authenticated"}))
	g.Expect(got.Get("Authorization")).To(gomega.BeEmpty())
	g.Expect(r.Header.Get("Authorization")).To(gomega.BeEmpty())
}

func TestTokenGroupsOffMissingAuthorizationSucceeds(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{TokenGroups: boolPtr(false)}
	provision(t, h)

	got := serve(t, h, requestWithUser("alice@example.com"))
	g.Expect(got.Get("Impersonate-User")).To(gomega.Equal("alice@example.com"))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"system:authenticated"}))
}

func TestTokenGroupsOffCustomAlwaysInclude(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{
		TokenGroups:   boolPtr(false),
		AlwaysInclude: []string{"ns-reader", "extra"},
	}
	provision(t, h)

	r := requestWithUser("alice@example.com")
	r.Header.Set("Impersonate-Group", "client-supplied")

	got := serve(t, h, r)
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"ns-reader", "extra"}))
	g.Expect(got.Get("Authorization")).To(gomega.BeEmpty())
}

func TestTokenGroupsOnIsDefault(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{TokenGroups: boolPtr(true)}
	provision(t, h)

	got := serve(t, h, requestWithToken(t, "alice@example.com", groupsJWT(t, []string{"devs"})))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "system:authenticated"}))
}

func TestProvisionRejectsTokenGroupsOffWithTokenOptions(t *testing.T) {
	g := gomega.NewWithT(t)

	withHeader := &Handler{TokenGroups: boolPtr(false), SourceIDToken: "Authorization"}
	g.Expect(withHeader.Provision(caddy.Context{})).To(gomega.HaveOccurred())

	withClaim := &Handler{TokenGroups: boolPtr(false), GroupsClaim: "groups"}
	g.Expect(withClaim.Provision(caddy.Context{})).To(gomega.HaveOccurred())
}

func TestUnmarshalRejectsRemovedDirectives(t *testing.T) {
	g := gomega.NewWithT(t)

	for _, input := range []string{
		"impersonate {\n\tsource_groups X-Auth-Request-Groups\n}",
		"impersonate {\n\tseparator ,\n}",
	} {
		var h Handler
		err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
		g.Expect(err).To(gomega.HaveOccurred())
	}
}

func TestUnmarshalTokenGroups(t *testing.T) {
	g := gomega.NewWithT(t)

	var off Handler
	g.Expect(off.UnmarshalCaddyfile(caddyfile.NewTestDispenser(
		"impersonate {\n\ttoken_groups off\n}"))).To(gomega.Succeed())
	g.Expect(off.TokenGroups).NotTo(gomega.BeNil())
	g.Expect(*off.TokenGroups).To(gomega.BeFalse())

	var on Handler
	g.Expect(on.UnmarshalCaddyfile(caddyfile.NewTestDispenser(
		"impersonate {\n\ttoken_groups on\n}"))).To(gomega.Succeed())
	g.Expect(on.TokenGroups).NotTo(gomega.BeNil())
	g.Expect(*on.TokenGroups).To(gomega.BeTrue())

	var bad Handler
	err := bad.UnmarshalCaddyfile(caddyfile.NewTestDispenser(
		"impersonate {\n\ttoken_groups maybe\n}"))
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestUnmarshalTokenOptions(t *testing.T) {
	g := gomega.NewWithT(t)

	var h Handler
	err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(`impersonate {
		source_id_token X-Id-Token
		groups_claim roles
		source_user X-User-Email
		target_user X-User
		target_group X-Group
		always_include team-a
	}`))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(h.SourceIDToken).To(gomega.Equal("X-Id-Token"))
	g.Expect(h.GroupsClaim).To(gomega.Equal("roles"))
	g.Expect(h.SourceUser).To(gomega.Equal("X-User-Email"))
	g.Expect(h.TargetUser).To(gomega.Equal("X-User"))
	g.Expect(h.TargetGroup).To(gomega.Equal("X-Group"))
	g.Expect(h.AlwaysInclude).To(gomega.Equal([]string{"team-a"}))
}

var _ caddyhttp.Handler = (*captureNext)(nil)
