package impersonate

import (
	"errors"
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

type serveResult struct {
	header http.Header
	status int
	called bool
}

func serve(t *testing.T, h *Handler, r *http.Request) serveResult {
	t.Helper()
	w := httptest.NewRecorder()
	next := &captureNext{}
	err := h.ServeHTTP(w, r, next)
	status := w.Code
	if err != nil {
		var handlerErr caddyhttp.HandlerError
		if errors.As(err, &handlerErr) {
			status = handlerErr.StatusCode
		}
	}
	return serveResult{
		header: next.header,
		status: status,
		called: next.header != nil,
	}
}

func TestDefaultsSetImpersonateUser(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", ""))
	g.Expect(got.header.Get("Impersonate-User")).To(gomega.Equal("alice@example.com"))
}

func TestSourceHeadersStripped(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs"))
	g.Expect(got.header.Get("X-Auth-Request-Email")).To(gomega.BeEmpty())
	g.Expect(got.header.Get("X-Auth-Request-Groups")).To(gomega.BeEmpty())
}

func TestSingleGroup(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "developers"))
	g.Expect(got.header.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"developers", "system:authenticated"}))
}

func TestMultipleGroups(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "developers,admins,ops"))
	g.Expect(got.header.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"developers", "admins", "ops", "system:authenticated"}))
}

func TestManyGroups(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	input := "g1,g2,g3,g4,g5,g6,g7,g8,g9,g10,g11,g12,g13,g14,g15"
	got := serve(t, h, newRequest("alice@example.com", input))
	groups := got.header.Values("Impersonate-Group")
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
	g.Expect(got.header.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"system:authenticated"}))
}

func TestEmptyUserReturns401(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("", "developers"))
	g.Expect(got.status).To(gomega.Equal(http.StatusUnauthorized))
	g.Expect(got.called).To(gomega.BeFalse(), "next handler should not be called")
}

func TestWhitespaceOnlyUserReturns401(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Auth-Request-Email", "   ")

	got := serve(t, h, r)
	g.Expect(got.status).To(gomega.Equal(http.StatusUnauthorized))
	g.Expect(got.called).To(gomega.BeFalse(), "next handler should not be called")
}

func TestCustomTargetHeaders(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{
		TargetUser:  "X-User",
		TargetGroup: "X-Group",
	}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs,ops"))
	g.Expect(got.header.Get("X-User")).To(gomega.Equal("alice@example.com"))
	g.Expect(got.header.Values("X-Group")).To(gomega.Equal(
		[]string{"devs", "ops", "system:authenticated"}))
	g.Expect(got.header.Get("Impersonate-User")).To(gomega.BeEmpty())
}

func TestCustomTargetStillStripsK8sHeaders(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{
		TargetUser:  "X-User",
		TargetGroup: "X-Group",
	}
	provision(t, h)

	r := newRequest("alice@example.com", "devs")
	r.Header.Set("Impersonate-User", "attacker@evil.com")
	r.Header.Set("Impersonate-Group", "cluster-admin")
	r.Header.Set("Impersonate-Uid", "fake-uid")

	got := serve(t, h, r)
	g.Expect(got.header.Get("Impersonate-User")).To(gomega.BeEmpty())
	g.Expect(got.header.Get("Impersonate-Group")).To(gomega.BeEmpty())
	g.Expect(got.header.Get("Impersonate-Uid")).To(gomega.BeEmpty())
	g.Expect(got.header.Get("X-User")).To(gomega.Equal("alice@example.com"))
}

func TestSourceTargetOverlapRejected(t *testing.T) {
	g := gomega.NewWithT(t)

	t.Run("SourceUser == TargetUser", func(*testing.T) {
		h := &Handler{
			SourceUser: "X-Identity",
			TargetUser: "X-Identity",
		}
		g.Expect(h.Provision(caddy.Context{})).To(gomega.MatchError(gomega.ContainSubstring("must not be the same")))
	})

	t.Run("SourceGroups == TargetGroup", func(*testing.T) {
		h := &Handler{
			SourceGroups: "X-Groups",
			TargetGroup:  "X-Groups",
		}
		g.Expect(h.Provision(caddy.Context{})).To(gomega.MatchError(gomega.ContainSubstring("must not be the same")))
	})

	t.Run("cross-field: SourceUser == TargetGroup", func(*testing.T) {
		h := &Handler{
			SourceUser:  "X-Shared",
			TargetGroup: "X-Shared",
		}
		g.Expect(h.Provision(caddy.Context{})).To(gomega.MatchError(gomega.ContainSubstring("must not be the same")))
	})
}

func TestReservedImpersonateHeaderRejected(t *testing.T) {
	g := gomega.NewWithT(t)

	t.Run("source_user is Impersonate-Uid", func(*testing.T) {
		h := &Handler{SourceUser: "Impersonate-Uid"}
		g.Expect(h.Provision(caddy.Context{})).To(gomega.MatchError(gomega.ContainSubstring("reserved Impersonate-*")))
	})

	t.Run("source_groups is Impersonate-Extra-Scopes", func(*testing.T) {
		h := &Handler{SourceGroups: "Impersonate-Extra-Scopes"}
		g.Expect(h.Provision(caddy.Context{})).To(gomega.MatchError(gomega.ContainSubstring("reserved Impersonate-*")))
	})
}

func TestAlwaysIncludeEmptyEntryRejected(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{AlwaysInclude: []string{"valid", ""}}
	g.Expect(h.Provision(caddy.Context{})).To(gomega.MatchError(gomega.ContainSubstring("empty or whitespace-only")))
}

func TestAlwaysIncludeEmpty(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{AlwaysInclude: []string{}}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs"))
	g.Expect(got.header.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs"}))
}

func TestAlwaysIncludeMultiple(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{
		AlwaysInclude: []string{"system:authenticated", "extra-group"},
	}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs"))
	g.Expect(got.header.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "system:authenticated", "extra-group"}))
}

func TestGroupsWithSpaces(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs , ops , admins"))
	g.Expect(got.header.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "ops", "admins", "system:authenticated"}))
}

func TestCustomSeparator(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{Separator: ";"}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs;ops;admins"))
	g.Expect(got.header.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "ops", "admins", "system:authenticated"}))
}

func TestPreExistingTargetGroupsCleared(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	r := newRequest("alice@example.com", "devs")
	r.Header.Set("Impersonate-Group", "should-be-removed")

	got := serve(t, h, r)
	g.Expect(got.header.Values("Impersonate-Group")).NotTo(gomega.ContainElement("should-be-removed"))
}

func TestEmptyGroupValuesSkipped(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	got := serve(t, h, newRequest("alice@example.com", "devs,,ops,"))
	g.Expect(got.header.Values("Impersonate-Group")).To(gomega.Equal(
		[]string{"devs", "ops", "system:authenticated"}))
}

func TestPreExistingTargetUserCleared(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	r := newRequest("alice@example.com", "devs")
	r.Header.Set("Impersonate-User", "attacker@evil.com")

	got := serve(t, h, r)
	g.Expect(got.header.Get("Impersonate-User")).To(gomega.Equal("alice@example.com"))
}

func TestImpersonateUidCleared(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	r := newRequest("alice@example.com", "devs")
	r.Header.Set("Impersonate-Uid", "fake-uid-12345")

	got := serve(t, h, r)
	g.Expect(got.header.Get("Impersonate-Uid")).To(gomega.BeEmpty())
}

func TestImpersonateExtraCleared(t *testing.T) {
	g := gomega.NewWithT(t)

	h := &Handler{}
	provision(t, h)

	r := newRequest("alice@example.com", "devs")
	r.Header.Set("Impersonate-Extra-Scopes", "cluster-admin")
	r.Header.Set("Impersonate-Extra-Reason", "testing")

	got := serve(t, h, r)
	g.Expect(got.header.Get("Impersonate-Extra-Scopes")).To(gomega.BeEmpty())
	g.Expect(got.header.Get("Impersonate-Extra-Reason")).To(gomega.BeEmpty())
}

var _ caddyhttp.Handler = (*captureNext)(nil)
