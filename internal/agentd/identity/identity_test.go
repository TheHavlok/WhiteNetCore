package identity

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thehavlok/whitenet/internal/panel/nodeca"
)

func newIdentity(t *testing.T) *Identity {
	t.Helper()
	dir := t.TempDir()
	return New(
		filepath.Join(dir, "agent.key"),
		filepath.Join(dir, "agent.crt"),
		filepath.Join(dir, "main-ca.crt"),
	)
}

// The whole enrolment handshake, against the real CA: key on the node, CSR
// out, certificate in.
func TestEnrolmentRoundTrip(t *testing.T) {
	ca, err := nodeca.NewCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id := newIdentity(t)

	if id.Enrolled() {
		t.Fatal("a fresh identity claims to be enrolled")
	}

	csrPEM, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	// The private key must be on disk and never in the request.
	if _, err := os.Stat(id.KeyPath); err != nil {
		t.Fatalf("the key was not written: %v", err)
	}
	if strings.Contains(string(csrPEM), "PRIVATE KEY") {
		t.Fatal("the certificate request contains a private key")
	}
	info, err := os.Stat(id.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key permissions = %o, want 600", perm)
	}

	issued, err := ca.SignAgent(csrPEM, "node-uuid-42", 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(issued.CertPEM, ca.CertPEM(), ca.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if !id.Enrolled() {
		t.Fatal("not enrolled after saving a certificate")
	}

	uuid, err := id.NodeUUID()
	if err != nil {
		t.Fatal(err)
	}
	if uuid != "node-uuid-42" {
		t.Errorf("node uuid = %q", uuid)
	}

	tlsCfg, err := id.ClientTLS("panel.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Error("the TLS configuration has no client certificate")
	}
	if tlsCfg.RootCAs == nil {
		t.Error("the TLS configuration has no CA pool")
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("min TLS version = %x, want 1.3", tlsCfg.MinVersion)
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("the agent's own connection skips verification")
	}
}

// The key must survive a second CSR: a renewal keeps the node's identity.
func TestKeyIsStable(t *testing.T) {
	id := newIdentity(t)
	first, err := id.EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := id.EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) {
		t.Fatal("EnsureKey generated a new key on the second call")
	}
}

// A CA fingerprint that does not match the install command means the agent is
// talking to the wrong server, which must not be enrolled against.
func TestSaveRejectsAWrongFingerprint(t *testing.T) {
	ca, err := nodeca.NewCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, err := nodeca.NewCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id := newIdentity(t)
	csrPEM, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ca.SignAgent(csrPEM, "node", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(issued.CertPEM, ca.CertPEM(), other.Fingerprint()); err == nil {
		t.Fatal("a mismatched CA fingerprint was accepted")
	}
	if id.Enrolled() {
		t.Error("a rejected enrolment still wrote the certificate")
	}
}

// A certificate from a different CA than the one presented, or for a different
// key, is useless and must be caught now rather than at every handshake.
func TestSaveRejectsMismatches(t *testing.T) {
	ca, err := nodeca.NewCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, err := nodeca.NewCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	id := newIdentity(t)
	csrPEM, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ca.SignAgent(csrPEM, "node", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Right certificate, wrong CA alongside it.
	if err := id.Save(issued.CertPEM, other.CertPEM(), ""); err == nil {
		t.Error("a certificate that does not verify against the given CA was accepted")
	}

	// A certificate issued for someone else's key.
	stranger := newIdentity(t)
	strangerCSR, err := stranger.CSR()
	if err != nil {
		t.Fatal(err)
	}
	strangerCert, err := ca.SignAgent(strangerCSR, "node", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(strangerCert.CertPEM, ca.CertPEM(), ""); err == nil {
		t.Error("a certificate for a different key was accepted")
	}

	// Nothing at all.
	if err := id.Save(nil, ca.CertPEM(), ""); err == nil {
		t.Error("an empty certificate was accepted")
	}
	if err := id.Save(issued.CertPEM, []byte("not pem"), ""); err == nil {
		t.Error("a CA that is not PEM was accepted")
	}
}

// The enrolment TLS configuration must verify the server by the pinned
// fingerprint, and must refuse to exist without one.
func TestEnrolTLS(t *testing.T) {
	ca, err := nodeca.NewCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := EnrolTLS("panel.example.com", ca.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("no peer verification was installed")
	}

	// What the server really sends: its own certificate, then the CA.
	serverCertPEM, _, err := ca.SignServer([]string{"panel.example.com"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{derOf(t, serverCertPEM), derOf(t, ca.CertPEM())}
	if err := cfg.VerifyPeerCertificate(chain, nil); err != nil {
		t.Errorf("the real chain was rejected: %v", err)
	}

	// Matching the pin is not enough. A server that presents the genuine CA
	// next to a leaf of its own must be refused, or pinning would prove
	// nothing.
	other, err := nodeca.NewCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	foreignLeafPEM, _, err := other.SignServer([]string{"panel.example.com"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mixed := [][]byte{derOf(t, foreignLeafPEM), derOf(t, ca.CertPEM())}
	if err := cfg.VerifyPeerCertificate(mixed, nil); err == nil {
		t.Error("a leaf from another CA was accepted next to the pinned CA")
	}

	// A chain that does not contain the pinned certificate at all.
	otherServerPEM, _, err := other.SignServer([]string{"panel.example.com"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{
		derOf(t, otherServerPEM), derOf(t, other.CertPEM()),
	}, nil); err == nil {
		t.Error("a chain from another CA was accepted")
	}

	// The wrong host name must fail even with the right CA.
	wrongName, err := EnrolTLS("not-the-panel.example.com", ca.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongName.VerifyPeerCertificate(chain, nil); err == nil {
		t.Error("a certificate for another host was accepted")
	}

	if err := cfg.VerifyPeerCertificate(nil, nil); err == nil {
		t.Error("an empty chain was accepted")
	}

	for _, bad := range []string{"", "not-hex", "abcd"} {
		if _, err := EnrolTLS("panel.example.com", bad); err == nil {
			t.Errorf("EnrolTLS accepted the fingerprint %q", bad)
		}
	}
}

func TestNeedsRenewal(t *testing.T) {
	ca, err := nodeca.NewCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id := newIdentity(t)
	csrPEM, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	// A certificate valid for an hour.
	issued, err := ca.SignAgent(csrPEM, "node", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(issued.CertPEM, ca.CertPEM(), ""); err != nil {
		t.Fatal(err)
	}

	if id.NeedsRenewal(time.Minute) {
		t.Error("a certificate with an hour left wants renewing within a minute")
	}
	if !id.NeedsRenewal(2 * time.Hour) {
		t.Error("a certificate with an hour left does not want renewing within two")
	}

	notAfter, err := id.NotAfter()
	if err != nil {
		t.Fatal(err)
	}
	if notAfter.Before(time.Now()) {
		t.Error("the certificate is already expired")
	}
}

func TestRemove(t *testing.T) {
	ca, err := nodeca.NewCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id := newIdentity(t)
	csrPEM, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ca.SignAgent(csrPEM, "node", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(issued.CertPEM, ca.CertPEM(), ""); err != nil {
		t.Fatal(err)
	}
	if err := id.Remove(); err != nil {
		t.Fatal(err)
	}
	if id.Enrolled() {
		t.Error("still enrolled after Remove")
	}
	// Removing twice must be harmless.
	if err := id.Remove(); err != nil {
		t.Errorf("second Remove: %v", err)
	}
}

func derOf(t *testing.T, certPEM []byte) []byte {
	t.Helper()
	cert, err := parseCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert.Raw
}
