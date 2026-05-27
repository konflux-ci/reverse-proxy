package certwatcher

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/onsi/gomega"
)

func generateSelfSignedCert(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn, "localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func writeCert(t *testing.T, dir, cn string) {
	t.Helper()
	certPEM, keyPEM := generateSelfSignedCert(t, cn)
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestProvisionMissingCertFile(t *testing.T) {
	g := gomega.NewWithT(t)
	fw := &FileWatcher{KeyFile: "/tmp/key.pem"}
	err := fw.Provision(caddy.Context{})
	g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("cert_file is required")))
}

func TestProvisionMissingKeyFile(t *testing.T) {
	g := gomega.NewWithT(t)
	fw := &FileWatcher{CertFile: "/tmp/cert.pem"}
	err := fw.Provision(caddy.Context{})
	g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("key_file is required")))
}

func TestProvisionInvalidCertPath(t *testing.T) {
	g := gomega.NewWithT(t)
	fw := &FileWatcher{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}
	err := fw.Provision(caddy.Context{})
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("loading initial certificate"))
}

func TestLoadAndServeCertificate(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	writeCert(t, dir, "test.example.com")

	fw := &FileWatcher{
		CertFile: filepath.Join(dir, "tls.crt"),
		KeyFile:  filepath.Join(dir, "tls.key"),
	}

	g.Expect(fw.loadCert()).To(gomega.Succeed())

	cert, err := fw.GetCertificate(context.Background(), &tls.ClientHelloInfo{})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(cert).NotTo(gomega.BeNil())

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(parsed.Subject.CommonName).To(gomega.Equal("test.example.com"))
}

func TestGetCertificateBeforeLoad(t *testing.T) {
	g := gomega.NewWithT(t)
	fw := &FileWatcher{}
	_, err := fw.GetCertificate(context.Background(), &tls.ClientHelloInfo{})
	g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no certificate loaded")))
}

func TestCertRotationPickedUp(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	writeCert(t, dir, "original.example.com")

	fw := &FileWatcher{
		CertFile: filepath.Join(dir, "tls.crt"),
		KeyFile:  filepath.Join(dir, "tls.key"),
		Debounce: caddy.Duration(100 * time.Millisecond),
		stop:     make(chan struct{}),
	}

	g.Expect(fw.loadCert()).To(gomega.Succeed())

	cert, _ := fw.GetCertificate(context.Background(), &tls.ClientHelloInfo{})
	parsed, _ := x509.ParseCertificate(cert.Certificate[0])
	g.Expect(parsed.Subject.CommonName).To(gomega.Equal("original.example.com"))

	// Simulate cert rotation
	writeCert(t, dir, "rotated.example.com")
	g.Expect(fw.loadCert()).To(gomega.Succeed())

	cert, _ = fw.GetCertificate(context.Background(), &tls.ClientHelloInfo{})
	parsed, _ = x509.ParseCertificate(cert.Certificate[0])
	g.Expect(parsed.Subject.CommonName).To(gomega.Equal("rotated.example.com"))
}

func TestUniqueDirs(t *testing.T) {
	g := gomega.NewWithT(t)

	dirs := uniqueDirs("/mnt/certs/tls.crt", "/mnt/certs/tls.key")
	g.Expect(dirs).To(gomega.HaveLen(1))
	g.Expect(dirs[0]).To(gomega.Equal("/mnt/certs"))

	dirs = uniqueDirs("/mnt/cert/tls.crt", "/mnt/key/tls.key")
	g.Expect(dirs).To(gomega.HaveLen(2))
}

func TestDefaultDebounce(t *testing.T) {
	g := gomega.NewWithT(t)

	dir := t.TempDir()
	writeCert(t, dir, "test.example.com")

	fw := &FileWatcher{
		CertFile: filepath.Join(dir, "tls.crt"),
		KeyFile:  filepath.Join(dir, "tls.key"),
	}
	g.Expect(fw.Provision(caddy.Context{})).To(gomega.Succeed())
	defer fw.Cleanup() //nolint:errcheck

	g.Expect(time.Duration(fw.Debounce)).To(gomega.Equal(5 * time.Second))
}
