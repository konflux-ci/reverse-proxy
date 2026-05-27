package filewatcher_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/konflux-ci/reverse-proxy/certwatcher"
	_ "github.com/konflux-ci/reverse-proxy/filewatcher"
	"github.com/onsi/gomega"
)

// caBundle holds a generated CA and its PEM encoding.
type caBundle struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func generateCA(t *testing.T, cn string) *caBundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return &caBundle{cert: cert, key: key, certPEM: certPEM}
}

func generateSignedCert(t *testing.T, ca *caBundle, cn string, sans ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     append([]string{cn}, sans...),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
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

// TestCARotationWithReload verifies the full integration scenario:
// 1. Start a TLS upstream signed by CA-1
// 2. Start Caddy configured to trust CA-1, proxying to the upstream
// 3. Verify requests succeed (Caddy trusts CA-1)
// 4. Replace the CA file with CA-2 (upstream still uses cert from CA-1)
// 5. Reload Caddy (simulates SIGUSR1) — Caddy should re-read CA trust
// 6. Verify requests now fail (Caddy trusts CA-2, upstream cert signed by CA-1)
// 7. Replace upstream with cert signed by CA-2
// 8. Verify requests succeed again
func TestCARotationWithReload(t *testing.T) {
	g := gomega.NewWithT(t)

	// Generate two CAs
	ca1 := generateCA(t, "CA-1")
	ca2 := generateCA(t, "CA-2")

	// Generate upstream server cert signed by CA-1
	upstreamCert1, upstreamKey1 := generateSignedCert(t, ca1, "localhost")

	// Set up CA directory
	caDir := t.TempDir()
	caFile := filepath.Join(caDir, "ca.crt")
	g.Expect(os.WriteFile(caFile, ca1.certPEM, 0644)).To(gomega.Succeed())

	// Start TLS upstream server signed by CA-1
	cert1, err := tls.X509KeyPair(upstreamCert1, upstreamKey1)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "upstream OK")
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{cert1}}
	upstream.StartTLS()
	defer upstream.Close()

	upstreamAddr := upstream.Listener.Addr().String()

	// Start Caddy with trust pool pointing to our CA file
	caddyPort := freePort(t)
	adminPort := freePort(t)

	caddyfile := fmt.Sprintf(`{
	admin 127.0.0.1:%d
}

:%d {
	reverse_proxy https://%s {
		transport http {
			tls_trust_pool file %s
			tls_server_name localhost
		}
	}
}
`, adminPort, caddyPort, upstreamAddr, caFile)

	adapter := caddyconfig.GetAdapter("caddyfile")
	g.Expect(adapter).NotTo(gomega.BeNil())

	jsonCfg, _, err := adapter.Adapt([]byte(caddyfile), nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	g.Expect(caddy.Load(jsonCfg, true)).To(gomega.Succeed())
	defer caddy.Stop() //nolint:errcheck

	// Wait for Caddy to be ready
	time.Sleep(200 * time.Millisecond)

	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/", caddyPort)

	// Step 1: Verify requests succeed with CA-1
	resp, err := client.Get(url)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
	g.Expect(string(body)).To(gomega.Equal("upstream OK"))

	// Step 2: Replace CA file with CA-2
	g.Expect(os.WriteFile(caFile, ca2.certPEM, 0644)).To(gomega.Succeed())

	// Step 3: Reload Caddy config (simulates what SIGUSR1 does)
	g.Expect(caddy.Load(jsonCfg, true)).To(gomega.Succeed())
	time.Sleep(200 * time.Millisecond)

	// Step 4: Requests should now fail because upstream cert is signed by CA-1
	// but Caddy now trusts CA-2
	resp, err = client.Get(url)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_ = resp.Body.Close()
	g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusBadGateway))

	// Step 5: Replace upstream with cert signed by CA-2
	upstreamCert2, upstreamKey2 := generateSignedCert(t, ca2, "localhost")
	cert2, err := tls.X509KeyPair(upstreamCert2, upstreamKey2)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Update the upstream server's certificate
	upstream.TLS.Certificates = []tls.Certificate{cert2}

	// Step 6: Verify requests succeed again
	resp, err = client.Get(url)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	g.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
	g.Expect(string(body)).To(gomega.Equal("upstream OK"))
}
