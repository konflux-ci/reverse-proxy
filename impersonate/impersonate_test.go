package impersonate

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/onsi/gomega"
)

func provision(t *testing.T, h *Handler) {
	t.Helper()
	g := gomega.NewWithT(t)
	g.Expect(h.Provision(caddy.Context{})).To(gomega.Succeed())
}

func newRequest(user, groups string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if user != "" {
		r.Header.Set("X-Auth-Request-Email", user)
	}
	if groups != "" {
		r.Header.Set("X-Auth-Request-Groups", groups)
	}
	return r
}

// captureNext is a caddyhttp.Handler that captures the request headers
// as seen by the next handler in the chain.
type captureNext struct {
	header http.Header
}

func (c *captureNext) ServeHTTP(_ http.ResponseWriter, r *http.Request) error {
	c.header = r.Header.Clone()
	return nil
}

func serve(t *testing.T, h *Handler, r *http.Request) http.Header {
	t.Helper()
	g := gomega.NewWithT(t)
	w := httptest.NewRecorder()
	next := &captureNext{}
	g.Expect(h.ServeHTTP(w, r, next)).To(gomega.Succeed())
	return next.header
}

func TestDefaultsSetImpersonateUser(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", ""))
	g.Expect(got.Get("Impersonate-User")).To(gomega.Equal("alice@example.com"))
}

func TestSingleGroup(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "developers"))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"developers", "system:authenticated"}))
}

func TestMultipleGroups(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "developers,admins,ops"))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"developers", "admins", "ops", "system:authenticated"}))
}

func TestManyGroups(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	input := "g1,g2,g3,g4,g5,g6,g7,g8,g9,g10,g11,g12,g13,g14,g15"
	got := serve(t, h, newRequest("alice@example.com", input))
	groups := got.Values("Impersonate-Group")
	g.Expect(groups).To(gomega.HaveLen(16))
	g.Expect(groups[0]).To(gomega.Equal("g1"))
	g.Expect(groups[14]).To(gomega.Equal("g15"))
	g.Expect(groups[15]).To(gomega.Equal("system:authenticated"))
}

func TestEmptyGroupsStillAddsAlwaysInclude(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", ""))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"system:authenticated"}))
}

func TestNoUserHeaderSkipsTargetUser(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("", "developers"))
	g.Expect(got.Get("Impersonate-User")).To(gomega.BeEmpty())
}

func TestCustomTargetHeaders(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{
		TargetUser:  "X-User",
		TargetGroup: "X-Group",
	}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs,ops"))
	g.Expect(got.Get("X-User")).To(gomega.Equal("alice@example.com"))
	g.Expect(got.Values("X-Group")).To(gomega.Equal(
		[]string{"devs", "ops", "system:authenticated"}))
	g.Expect(got.Get("Impersonate-User")).To(gomega.BeEmpty())
}

func TestAlwaysIncludeEmpty(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{AlwaysInclude: []string{}}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs"))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs"}))
}

func TestAlwaysIncludeMultiple(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{
		AlwaysInclude: []string{"system:authenticated", "extra-group"},
	}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs"))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "system:authenticated", "extra-group"}))
}

func TestGroupsWithSpaces(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs , ops , admins"))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "ops", "admins", "system:authenticated"}))
}

func TestCustomSeparator(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{Separator: ";"}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs;ops;admins"))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "ops", "admins", "system:authenticated"}))
}

func TestPreExistingTargetGroupsCleared(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	r := newRequest("alice@example.com", "devs")
	r.Header.Set("Impersonate-Group", "should-be-removed")

	got := serve(t, h, r)
	g.Expect(got.Values("Impersonate-Group")).NotTo(gomega.ContainElement("should-be-removed"))
}

func TestEmptyGroupValuesSkipped(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs,,ops,"))
	g.Expect(got.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "ops", "system:authenticated"}))
}

var _ caddyhttp.Handler = (*captureNext)(nil)
