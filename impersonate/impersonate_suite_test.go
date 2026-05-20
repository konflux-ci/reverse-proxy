package impersonate_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestImpersonate(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Impersonate Suite")
}
