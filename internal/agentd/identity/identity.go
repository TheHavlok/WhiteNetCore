// Package identity is the agent's half of mutual TLS: its key pair, the
// certificate Main issued, and the CA it pins.
//
// The private key is generated on the node and never leaves it. Enrolment
// sends a certificate request and gets a certificate back, so a copy of the
// panel's database cannot impersonate a node and a copy of a node cannot be
// used to issue more.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Identity is what the agent has on disk.
type Identity struct {
	KeyPath  string
	CertPath string
	CAPath   string
}

// New points an Identity at the agent's files.
func New(keyPath, certPath, caPath string) *Identity {
	return &Identity{KeyPath: keyPath, CertPath: certPath, CAPath: caPath}
}

// Enrolled reports whether the agent already has everything it needs. An
// agent that is enrolled never enrols again: the token is spent and the
// certificate is what proves it.
func (id *Identity) Enrolled() bool {
	for _, path := range []string{id.KeyPath, id.CertPath, id.CAPath} {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

// EnsureKey returns the agent's private key, generating it on first use.
//
// The key is reused across enrolments and renewals: rotating it would mean the
// node's identity changes, and there is no reason for it to.
func (id *Identity) EnsureKey() (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(id.KeyPath)
	if err == nil {
		return parseKey(raw)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("identity: read %s: %w", id.KeyPath, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("identity: marshal key: %w", err)
	}
	if err := writeSecret(id.KeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return key, nil
}

// CSR builds the certificate request for enrolment or renewal.
//
// The subject is a placeholder: Main rewrites it with the node's uuid, because
// a node does not get to decide which node it is.
func (id *Identity) CSR() ([]byte, error) {
	key, err := id.EnsureKey()
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "whitenet-agent"},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("identity: create certificate request: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// Save stores the certificate Main issued and the CA to verify Main with.
//
// expectedFingerprint, when set, is the CA fingerprint from the install
// command. Checking it here is what makes enrolment safe over a connection
// that was not yet authenticated: a wrong server's CA is rejected before it is
// ever trusted.
func (id *Identity) Save(certPEM, caPEM []byte, expectedFingerprint string) error {
	if len(certPEM) == 0 || len(caPEM) == 0 {
		return errors.New("identity: the server returned no certificate")
	}
	caCert, err := parseCertificate(caPEM)
	if err != nil {
		return err
	}
	if expectedFingerprint != "" {
		got := fingerprint(caCert)
		if !strings.EqualFold(got, strings.TrimSpace(expectedFingerprint)) {
			return fmt.Errorf("identity: the server's CA fingerprint is %s, the install command pinned %s",
				got, expectedFingerprint)
		}
	}

	cert, err := parseCertificate(certPEM)
	if err != nil {
		return err
	}
	// A certificate that does not verify against the CA it came with is
	// useless, and finding that out now beats finding out at every handshake.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("identity: the CA certificate could not be used")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("identity: the issued certificate does not verify against the CA: %w", err)
	}
	// And one that does not match the key on this node would fail at the
	// handshake with a much less helpful message.
	key, err := id.EnsureKey()
	if err != nil {
		return err
	}
	certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certKey.Equal(&key.PublicKey) {
		return errors.New("identity: the issued certificate is for a different key")
	}

	if err := writeSecret(id.CertPath, certPEM); err != nil {
		return err
	}
	return writeSecret(id.CAPath, caPEM)
}

// NodeUUID is the node's uuid, read from the certificate's common name. The
// agent uses it in logs; the server reads it from the connection rather than
// trusting what the agent says.
func (id *Identity) NodeUUID() (string, error) {
	cert, err := id.certificate()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(cert.Subject.CommonName), nil
}

// NotAfter is when the agent's certificate expires, so it can renew in good
// time rather than discovering the problem when it cannot connect.
func (id *Identity) NotAfter() (time.Time, error) {
	cert, err := id.certificate()
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// NeedsRenewal reports whether the certificate expires within the window.
func (id *Identity) NeedsRenewal(window time.Duration) bool {
	notAfter, err := id.NotAfter()
	if err != nil {
		// No certificate at all needs enrolment, not renewal; the caller
		// checks Enrolled first.
		return false
	}
	return time.Now().Add(window).After(notAfter)
}

// ClientTLS builds the configuration for the agent's connection to Main.
func (id *Identity) ClientTLS(serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(id.CertPath, id.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("identity: load key pair: %w", err)
	}
	caPEM, err := os.ReadFile(id.CAPath)
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", id.CAPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("identity: %s is not a usable CA certificate", id.CAPath)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		// Main's certificate is issued by the pinned CA, so public trust is
		// irrelevant and TLS 1.2 is not worth supporting between two
		// components shipped together.
		MinVersion: tls.VersionTLS13,
	}, nil
}

// EnrolTLS builds the configuration for the one call made before the agent has
// a certificate.
//
// The CA is not known yet, so the server's certificate cannot be verified the
// usual way. Instead the fingerprint from the install command is checked
// against the chain the server presents. Verification is not skipped - it is
// done by hand, against the thing the operator pinned.
func EnrolTLS(serverName, caFingerprint string) (*tls.Config, error) {
	expected := strings.ToLower(strings.TrimSpace(caFingerprint))
	if expected == "" {
		return nil, errors.New("identity: enrolment needs the CA fingerprint from the install command")
	}
	if _, err := hex.DecodeString(expected); err != nil || len(expected) != 64 {
		return nil, fmt.Errorf("identity: %q is not a SHA-256 fingerprint", caFingerprint)
	}

	return &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
		// The chain is checked below instead.
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("identity: the server presented no certificate")
			}
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					return fmt.Errorf("identity: the server's certificate did not parse: %w", err)
				}
				certs = append(certs, cert)
			}

			// Find the certificate the install command pinned. It is the CA,
			// which the server sends alongside its own.
			var pinned *x509.Certificate
			for _, cert := range certs {
				sum := sha256.Sum256(cert.Raw)
				if hex.EncodeToString(sum[:]) == expected {
					pinned = cert
					break
				}
			}
			if pinned == nil {
				return fmt.Errorf("identity: none of the server's certificates match the pinned fingerprint %s", expected)
			}

			// Matching is not enough: the leaf has to actually be issued by
			// the pinned certificate, or a server could present the real CA
			// next to a leaf of its own.
			roots := x509.NewCertPool()
			roots.AddCert(pinned)
			intermediates := x509.NewCertPool()
			for _, cert := range certs[1:] {
				if cert.Equal(pinned) {
					continue
				}
				intermediates.AddCert(cert)
			}
			if _, err := certs[0].Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				DNSName:       serverName,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				return fmt.Errorf("identity: the server's certificate does not chain to the pinned CA: %w", err)
			}
			return nil
		},
	}, nil
}

// Remove deletes the identity. The agent does this when Main says the node was
// deleted, so a decommissioned node does not keep a usable certificate.
func (id *Identity) Remove() error {
	var errs []error
	for _, path := range []string{id.CertPath, id.CAPath, id.KeyPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("identity: remove %s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

func (id *Identity) certificate() (*x509.Certificate, error) {
	raw, err := os.ReadFile(id.CertPath)
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", id.CertPath, err)
	}
	return parseCertificate(raw)
}

func parseKey(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("identity: the key file is not PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity: parse key: %w", err)
	}
	return key, nil
}

func parseCertificate(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("identity: the certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity: parse certificate: %w", err)
	}
	return cert, nil
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// writeSecret writes a file only the agent can read, atomically.
func writeSecret(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("identity: create %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return fmt.Errorf("identity: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("identity: rename %s: %w", path, err)
	}
	return nil
}
