package nodeca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// agentCSR makes a certificate request the way an agent does: key generated
// locally, never transmitted.
func agentCSR(t *testing.T, commonName string) (csrPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

func TestNewCAAndRoundTrip(t *testing.T) {
	ca, err := NewCA(10 * 365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Fingerprint() == "" || len(ca.Fingerprint()) != 64 {
		t.Errorf("fingerprint = %q, want 64 hex characters", ca.Fingerprint())
	}

	keyPEM, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	// Reloading from stored PEM must produce a CA that signs the same way;
	// otherwise a panel restart orphans every certificate it issued.
	reloaded, err := Load(ca.CertPEM(), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Fingerprint() != ca.Fingerprint() {
		t.Error("the reloaded CA has a different fingerprint")
	}

	csrPEM, _ := agentCSR(t, "ignored")
	issued, err := reloaded.SignAgent(csrPEM, "node-uuid-1", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAgainst(t, ca.CertPEM(), issued.CertPEM, x509.ExtKeyUsageClientAuth); err != nil {
		t.Errorf("a certificate from the reloaded CA does not verify against the original: %v", err)
	}
}

// The CSR is attacker-controlled: whatever subject it asks for must be
// discarded, because the certificate's common name is what tells the server
// which node is connecting.
func TestSignAgentIgnoresTheRequestedSubject(t *testing.T) {
	ca, err := NewCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, _ := agentCSR(t, "some-other-node")
	issued, err := ca.SignAgent(csrPEM, "the-real-node", 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert := parse(t, issued.CertPEM)
	if got := NodeUUIDFromCommonName(cert); got != "the-real-node" {
		t.Fatalf("common name = %q, want the-real-node", got)
	}
	if cert.IsCA {
		t.Error("an agent certificate was issued as a CA")
	}
	// Client auth only: an agent certificate must not be usable to pretend to
	// be the panel.
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			t.Error("an agent certificate claims server auth")
		}
	}
}

func TestSignAgentCannotOutliveTheCA(t *testing.T) {
	ca, err := NewCA(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, _ := agentCSR(t, "node")
	issued, err := ca.SignAgent(csrPEM, "node", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if issued.NotAfter.After(ca.NotAfter()) {
		t.Errorf("the agent certificate outlives the CA: %v > %v", issued.NotAfter, ca.NotAfter())
	}
}

func TestSignAgentRejectsBadRequests(t *testing.T) {
	ca, err := NewCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Not PEM at all.
	if _, err := ca.SignAgent([]byte("not pem"), "node", time.Hour); err == nil {
		t.Error("a non-PEM request was signed")
	}
	// PEM, but a certificate rather than a request.
	if _, err := ca.SignAgent(ca.CertPEM(), "node", time.Hour); err == nil {
		t.Error("a certificate was accepted as a request")
	}
	// A request whose signature does not match its key proves nothing.
	csrPEM, _ := agentCSR(t, "node")
	block, _ := pem.Decode(csrPEM)
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	tampered := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: block.Bytes})
	if _, err := ca.SignAgent(tampered, "node", time.Hour); err == nil {
		t.Error("a tampered request was signed")
	}
	// No node to sign for.
	csrPEM, _ = agentCSR(t, "node")
	if _, err := ca.SignAgent(csrPEM, "", time.Hour); err == nil {
		t.Error("a request with no node uuid was signed")
	}
}

// An RSA key in a CSR is not something to sign just because it was asked for.
func TestParseCSRRejectsNonECDSAKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "node"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if _, err := ParseCSR(csrPEM); err == nil {
		t.Error("an RSA request was accepted")
	}
}

func TestSignServerNamesHostsCorrectly(t *testing.T) {
	ca, err := NewCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.SignServer([]string{"panel.example.com", "185.68.184.144", "::1"}, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(keyPEM); block == nil {
		t.Fatal("the returned key is not PEM")
	}
	cert := parse(t, certPEM)

	// A bare IP in DNSNames verifies for nothing, which is exactly the
	// mistake this test exists to catch.
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "panel.example.com" {
		t.Errorf("DNSNames = %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 2 {
		t.Errorf("IPAddresses = %v, want the two IPs", cert.IPAddresses)
	}
	if err := verifyAgainst(t, ca.CertPEM(), certPEM, x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("the server certificate does not verify against the CA: %v", err)
	}
}

// Two CAs must not issue certificates the other accepts; that is the whole
// point of pinning one.
func TestCertificatesDoNotVerifyAcrossCAs(t *testing.T) {
	first, err := NewCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint() == second.Fingerprint() {
		t.Fatal("two CAs share a fingerprint")
	}

	csrPEM, _ := agentCSR(t, "node")
	issued, err := first.SignAgent(csrPEM, "node", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAgainst(t, second.CertPEM(), issued.CertPEM, x509.ExtKeyUsageClientAuth); err == nil {
		t.Error("a certificate from one CA verified against another")
	}
}

func TestSerialsAreUnique(t *testing.T) {
	ca, err := NewCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		csrPEM, _ := agentCSR(t, "node")
		issued, err := ca.SignAgent(csrPEM, "node", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if seen[issued.Serial] {
			t.Fatalf("serial %s was issued twice", issued.Serial)
		}
		seen[issued.Serial] = true
		if strings.ToLower(issued.Serial) != issued.Serial {
			t.Errorf("serial %q is not lowercase hex", issued.Serial)
		}
	}
}

func TestFingerprintPEM(t *testing.T) {
	ca, err := NewCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := FingerprintPEM(ca.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	if got != ca.Fingerprint() {
		t.Errorf("FingerprintPEM = %q, want %q", got, ca.Fingerprint())
	}
	if _, err := FingerprintPEM([]byte("not pem")); err == nil {
		t.Error("FingerprintPEM accepted something that is not PEM")
	}
}

func TestLoadRejectsRubbish(t *testing.T) {
	ca, err := NewCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load([]byte("nope"), keyPEM); err == nil {
		t.Error("Load accepted a certificate that is not PEM")
	}
	if _, err := Load(ca.CertPEM(), []byte("nope")); err == nil {
		t.Error("Load accepted a key that is not PEM")
	}
}

func parse(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	cert, err := parseCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// verifyAgainst checks a certificate the way crypto/tls will at handshake
// time, which is the only check that matters.
func verifyAgainst(t *testing.T, caPEM, certPEM []byte, usage x509.ExtKeyUsage) error {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("the CA certificate did not go into a pool")
	}
	cert := parse(t, certPEM)
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{usage},
	})
	return err
}
