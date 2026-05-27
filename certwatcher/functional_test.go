package certwatcher_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/konflux-ci/reverse-proxy/certwatcher"
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
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

func writeCertFiles(t *testing.T, dir string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() //nolint:errcheck
	return port
}

func peerCertCN(t *testing.T, addr string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
	})
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("no peer certificates received")
	}
	return certs[0].Subject.CommonName
}

// TestServingCertRotation verifies that certwatcher picks up a rotated serving
// certificate without any Caddy reload. It:
// 1. Writes cert-v1 (CN=original.example.com) to disk
// 2. Starts Caddy with get_certificate file pointing at those files
// 3. Connects via TLS and asserts the CN is "original.example.com"
// 4. Writes cert-v2 (CN=rotated.example.com) to disk
// 5. Waits for debounce + reload
// 6. Connects again and asserts the CN is now "rotated.example.com"
func TestServingCertRotation(t *testing.T) {
	g := gomega.NewWithT(t)

	certDir := t.TempDir()

	// Write initial cert
	cert1PEM, key1PEM := generateSelfSignedCert(t, "original.example.com")
	writeCertFiles(t, certDir, cert1PEM, key1PEM)

	certPath := filepath.Join(certDir, "tls.crt")
	keyPath := filepath.Join(certDir, "tls.key")

	listenPort := freePort(t)
	adminPort := freePort(t)

	caddyfileContent := fmt.Sprintf(`{
	admin 127.0.0.1:%d
	auto_https disable_redirects
	local_certs
}

https://localhost:%d {
	tls {
		get_certificate file {
			cert %s
			key  %s
			debounce 200ms
		}
	}
	respond "hello"
}
`, adminPort, listenPort, certPath, keyPath)

	adapter := caddyconfig.GetAdapter("caddyfile")
	g.Expect(adapter).NotTo(gomega.BeNil())

	jsonCfg, _, err := adapter.Adapt([]byte(caddyfileContent), nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	g.Expect(caddy.Load(jsonCfg, true)).To(gomega.Succeed())
	defer caddy.Stop() //nolint:errcheck

	// Wait for Caddy to be ready
	time.Sleep(300 * time.Millisecond)

	addr := fmt.Sprintf("127.0.0.1:%d", listenPort)

	// Step 1: Verify initial cert is served
	cn := peerCertCN(t, addr)
	g.Expect(cn).To(gomega.Equal("original.example.com"))

	// Step 2: Rotate the cert on disk
	cert2PEM, key2PEM := generateSelfSignedCert(t, "rotated.example.com")
	writeCertFiles(t, certDir, cert2PEM, key2PEM)

	// Step 3: Wait for debounce (200ms) + processing margin
	time.Sleep(500 * time.Millisecond)

	// Step 4: Verify new cert is served without any reload
	cn = peerCertCN(t, addr)
	g.Expect(cn).To(gomega.Equal("rotated.example.com"))
}
