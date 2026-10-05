package impersonate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/onsi/gomega"
	"go.uber.org/zap"
)

// blockDispenser returns a dispenser positioned on the first option inside
// an impersonate block.
func blockDispenser(t *testing.T, block string) *caddyfile.Dispenser {
	t.Helper()
	g := gomega.NewWithT(t)
	d := caddyfile.NewTestDispenser("impersonate {\n\t" + block + "\n}")
	g.Expect(d.Next()).To(gomega.BeTrue())
	g.Expect(d.NextBlock(0)).To(gomega.BeTrue())
	return d
}

func TestInitRegistersModule(t *testing.T) {
	g := gomega.NewWithT(t)

	info, err := caddy.GetModule("http.handlers.impersonate")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(info.ID).To(gomega.Equal(caddy.ModuleID("http.handlers.impersonate")))
	g.Expect(info.New()).To(gomega.BeAssignableToTypeOf(&Handler{}))
}

func TestCaddyModule(t *testing.T) {
	g := gomega.NewWithT(t)

	info := Handler{}.CaddyModule()
	g.Expect(info.ID).To(gomega.Equal(caddy.ModuleID("http.handlers.impersonate")))
	g.Expect(info.New()).To(gomega.BeAssignableToTypeOf(&Handler{}))
}

func TestProvisionSetsDefaults(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	g.Expect(h.Provision(caddy.Context{})).To(gomega.Succeed())
	g.Expect(h.SourceUser).To(gomega.Equal("X-Auth-Request-Email"))
	g.Expect(h.SourceIDToken).To(gomega.Equal("Authorization"))
	g.Expect(h.GroupsClaim).To(gomega.Equal("groups"))
	g.Expect(h.TargetUser).To(gomega.Equal("Impersonate-User"))
	g.Expect(h.TargetGroup).To(gomega.Equal("Impersonate-Group"))
	g.Expect(h.AlwaysInclude).To(gomega.Equal([]string{authenticatedGroup}))
	g.Expect(h.logger).NotTo(gomega.BeNil())
}

func TestParseCaddyfile(t *testing.T) {
	g := gomega.NewWithT(t)

	d := caddyfile.NewTestDispenser("impersonate {\n\ttoken_groups off\n}")
	got, err := parseCaddyfile(httpcaddyfile.Helper{Dispenser: d})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	h, ok := got.(*Handler)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(h.TokenGroups).NotTo(gomega.BeNil())
	g.Expect(*h.TokenGroups).To(gomega.BeFalse())
}

func TestTokenGroupsEnabled(t *testing.T) {
	g := gomega.NewWithT(t)

	g.Expect(Handler{}.tokenGroupsEnabled()).To(gomega.BeTrue())
	g.Expect(Handler{TokenGroups: boolPtr(true)}.tokenGroupsEnabled()).To(gomega.BeTrue())
	g.Expect(Handler{TokenGroups: boolPtr(false)}.tokenGroupsEnabled()).To(gomega.BeFalse())
}

func TestGroupDenied(t *testing.T) {
	g := gomega.NewWithT(t)

	denied := []string{
		"system:masters",
		"system:cluster-admins",
		"system:authenticated:oauth",
		"system:nodes",
		"kubeadm:cluster-admins",
		"cluster-admins",
		"dedicated-admins",
	}
	for _, name := range denied {
		g.Expect(groupDenied(name)).To(gomega.BeTrue(), name)
	}

	kept := []string{
		"system:authenticated",
		"System:masters",
		"cluster-admin",
		"dedicated-admin",
		"kubeadm:other",
		"team-a",
	}
	for _, name := range kept {
		g.Expect(groupDenied(name)).To(gomega.BeFalse(), name)
	}
}

func TestWriteGroups(t *testing.T) {
	g := gomega.NewWithT(t)

	h := Handler{
		TargetGroup:   "Impersonate-Group",
		AlwaysInclude: []string{authenticatedGroup, "extra"},
		logger:        zap.NewNop(),
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Add("Impersonate-Group", "client-supplied")

	h.writeGroups(r, []string{
		"team-a",
		"system:masters",
		"team-a",
		authenticatedGroup,
	})

	g.Expect(r.Header.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"team-a", authenticatedGroup, "extra"}))
}

func TestGroupsFromToken(t *testing.T) {
	g := gomega.NewWithT(t)

	got, err := groupsFromToken(
		"Bearer "+groupsJWT(t, []string{"team-a,system:masters", " devs "}),
		"groups",
	)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(got).To(gomega.Equal([]string{"team-a,system:masters", " devs "}))

	got, err = groupsFromToken(groupsJWT(t, []string{"devs"}), "groups")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(got).To(gomega.Equal([]string{"devs"}))

	payload, err := json.Marshal(map[string][]string{"roles": {"ops"}})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	got, err = groupsFromToken(compactJWT(t, string(payload)), "roles")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(got).To(gomega.Equal([]string{"ops"}))

	got, err = groupsFromToken(compactJWT(t, `{}`), "groups")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(got).To(gomega.BeNil())

	got, err = groupsFromToken(compactJWT(t, `{"groups":null}`), "groups")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(got).To(gomega.BeNil())

	got, err = groupsFromToken(groupsJWT(t, []string{}), "groups")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(got).To(gomega.BeEmpty())
}

func TestGroupsFromTokenErrors(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		payload string
		want    error
	}{
		{name: "missing token", want: errMissingIDToken},
		{name: "not a compact jwt", raw: "not-a-jwt", want: errNotCompactJWT},
		{name: "empty signature", raw: "a.b.", want: errNotCompactJWT},
		{name: "only one bearer prefix is stripped", raw: "Bearer Bearer x", want: errNotCompactJWT},
		{name: "bad base64", raw: "aaa.!!!!.sig", want: errBadPayloadEncoding},
		{name: "whitespace payload", payload: "   ", want: errPayloadNotObject},
		{name: "object that is not valid json", payload: "{", want: errPayloadNotObject},
		{name: "array payload", payload: `["devs"]`, want: errPayloadNotObject},
		{name: "null payload", payload: `null`, want: errPayloadNotObject},
		{name: "string claim", payload: `{"groups":"a,b"}`, want: errGroupsNotStringArray},
		{name: "number claim", payload: `{"groups":1}`, want: errGroupsNotStringArray},
		{name: "empty element", payload: `{"groups":["devs",""]}`, want: errEmptyGroup},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			raw := tc.raw
			if tc.payload != "" {
				raw = compactJWT(t, tc.payload)
			}
			got, err := groupsFromToken(raw, "groups")
			g.Expect(got).To(gomega.BeNil())
			g.Expect(err).To(gomega.MatchError(tc.want))
		})
	}
}

func TestUnmarshalHeader(t *testing.T) {
	g := gomega.NewWithT(t)

	d := caddyfile.NewTestDispenser("source_user X-User-Email")
	g.Expect(d.Next()).To(gomega.BeTrue())
	var dest string
	g.Expect(unmarshalHeader(d, &dest)).To(gomega.Succeed())
	g.Expect(dest).To(gomega.Equal("X-User-Email"))

	missing := caddyfile.NewTestDispenser("source_user")
	g.Expect(missing.Next()).To(gomega.BeTrue())
	g.Expect(unmarshalHeader(missing, &dest)).To(gomega.HaveOccurred())
}

func TestUnmarshalTokenGroupsReadsOnOff(t *testing.T) {
	g := gomega.NewWithT(t)

	onDisp := caddyfile.NewTestDispenser("token_groups on")
	g.Expect(onDisp.Next()).To(gomega.BeTrue())
	on := &Handler{}
	g.Expect(on.unmarshalTokenGroups(onDisp)).To(gomega.Succeed())
	g.Expect(on.TokenGroups).NotTo(gomega.BeNil())
	g.Expect(*on.TokenGroups).To(gomega.BeTrue())

	offDisp := caddyfile.NewTestDispenser("token_groups off")
	g.Expect(offDisp.Next()).To(gomega.BeTrue())
	off := &Handler{}
	g.Expect(off.unmarshalTokenGroups(offDisp)).To(gomega.Succeed())
	g.Expect(*off.TokenGroups).To(gomega.BeFalse())

	for _, input := range []string{"token_groups", "token_groups maybe", "token_groups off extra"} {
		d := caddyfile.NewTestDispenser(input)
		g.Expect(d.Next()).To(gomega.BeTrue())
		g.Expect((&Handler{}).unmarshalTokenGroups(d)).To(gomega.HaveOccurred(), input)
	}
}

func TestUnmarshalOptionErrors(t *testing.T) {
	g := gomega.NewWithT(t)

	blocks := []string{
		"always_include",
		"not_an_option",
		"source_user",
		"source_id_token",
		"groups_claim",
		"target_user",
		"target_group",
	}
	for _, block := range blocks {
		err := (&Handler{}).unmarshalOption(blockDispenser(t, block))
		g.Expect(err).To(gomega.HaveOccurred(), block)
	}
}

func TestUnmarshalCaddyfileRejectsIncompleteOptions(t *testing.T) {
	g := gomega.NewWithT(t)

	inputs := []string{
		"impersonate {\n\talways_include\n}",
		"impersonate {\n\tnot_an_option\n}",
		"impersonate {\n\tsource_user\n}",
		"impersonate {\n\tsource_id_token\n}",
		"impersonate {\n\tgroups_claim\n}",
		"impersonate {\n\ttarget_user\n}",
		"impersonate {\n\ttarget_group\n}",
		"impersonate {\n\ttoken_groups\n}",
		"impersonate {\n\ttoken_groups off extra\n}",
	}
	for _, input := range inputs {
		var h Handler
		err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
		g.Expect(err).To(gomega.HaveOccurred(), input)
	}
}
