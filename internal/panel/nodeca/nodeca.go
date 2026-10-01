// Package nodeca is Main's certificate authority for agents.
//
// Agents authenticate with mutual TLS against this CA and nothing else: no
// shared secret that leaks into a process list, no bearer token that works
// forever once copied. A node is enrolled once with a single-use token, gets a
// certificate, and from then on the connection itself is the proof.
//
// The CA's private key lives in the database, encrypted with the panel's
// master key. That is a deliberate trade: a file on disk would survive losing
// the database and vice versa, and losing both at once is the same event for a
// single-host deployment.
package nodeca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Subject names. The common name of an agent certificate is the node's uuid,
// so the server knows which node a connection belongs to from the certificate
// alone - there is no "which node are you" message to get wrong or to lie in.
const (
	Organization = "WhiteNet"
	CACommonName = "WhiteNet Node CA"
)

// CA is a certificate authority.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// certPEM is kept so handing the CA to an agent does not re-encode it
	// every time.
	certPEM []byte
}

// NewCA creates a authority valid for the given lifetime.
//
// P-256 and ECDSA rather than RSA: the handshake is between two machines that
// both support it, and a smaller certificate matters when it travels in an
// install command.
func NewCA(validFor time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("nodeca: generate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{Organization},
			CommonName:   CACommonName,
		},
		NotBefore: now.Add(-5 * time.Minute), // tolerate a little clock skew
		NotAfter:  now.Add(validFor),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		// A CA that can only sign certificates: no server or client auth with
		// the CA key itself.
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("nodeca: self-sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("nodeca: parse own certificate: %w", err)
	}
	return &CA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// Load rebuilds a CA from stored PEM.
func Load(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("nodeca: the key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		// Also accept PKCS#8, which is what some tools write.
		anyKey, pkcs8Err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if pkcs8Err != nil {
			return nil, fmt.Errorf("nodeca: parse key: %w", err)
		}
		ecKey, ok := anyKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("nodeca: the key is %T, want an ECDSA key", anyKey)
		}
		key = ecKey
	}
	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// CertPEM is the CA certificate, which agents pin at enrolment.
func (ca *CA) CertPEM() []byte { return ca.certPEM }

// KeyPEM is the CA private key, for storing encrypted.
func (ca *CA) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return nil, fmt.Errorf("nodeca: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// NotAfter is when the CA expires. Every certificate it issues is capped at
// this, so the panel can warn before anything lapses.
func (ca *CA) NotAfter() time.Time { return ca.cert.NotAfter }

// Fingerprint is the SHA-256 of the CA certificate, as lowercase hex.
//
// This is what goes into the install command: the agent pins it before it
// trusts anything, so a first connection to the wrong server fails instead of
// enrolling against it.
func (ca *CA) Fingerprint() string { return Fingerprint(ca.cert) }

// Fingerprint is the SHA-256 of a certificate's DER, as lowercase hex.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// FingerprintPEM is Fingerprint for a PEM-encoded certificate.
func FingerprintPEM(certPEM []byte) (string, error) {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return "", err
	}
	return Fingerprint(cert), nil
}

// Issued is a certificate the CA signed.
type Issued struct {
	CertPEM     []byte
	Serial      string
	Fingerprint string
	NotBefore   time.Time
	NotAfter    time.Time
}

// SignAgent signs a certificate request from an agent.
//
// The subject is rewritten rather than taken from the request: a CSR is
// attacker-controlled input, and the one thing this certificate means is "I am
// node X". Only the public key is taken from it.
func (ca *CA) SignAgent(csrPEM []byte, nodeUUID string, validFor time.Duration) (*Issued, error) {
	if nodeUUID == "" {
		return nil, errors.New("nodeca: no node uuid to sign for")
	}
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	notAfter := now.Add(validFor)
	// An agent certificate cannot outlive the CA that signed it.
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{Organization},
			CommonName:   nodeUUID,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("nodeca: sign agent certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("nodeca: parse issued certificate: %w", err)
	}
	return &Issued{
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Serial:      serialString(serial),
		Fingerprint: Fingerprint(cert),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
	}, nil
}

// SignServer signs the certificate Main presents to agents.
//
// Agents verify it against the pinned CA, so it needs no public trust and the
// names can be whatever the panel is reached by, including a bare IP.
func (ca *CA) SignServer(hosts []string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("nodeca: generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	notAfter := now.Add(validFor)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}

	commonName := "whitenet-main"
	if len(hosts) > 0 {
		commonName = hosts[0]
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{Organization},
			CommonName:   commonName,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, host := range hosts {
		addHost(template, host)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("nodeca: sign server certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("nodeca: marshal server key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		nil
}

// ParseCSR decodes and verifies a certificate request. A CSR whose signature
// does not match its own public key proves nothing, so it is rejected before
// anything is read out of it.
func ParseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("nodeca: the certificate request is not PEM")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("nodeca: expected a certificate request, got a %q block", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("nodeca: parse certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("nodeca: the certificate request is not self-signed correctly: %w", err)
	}
	// Reject a key the panel would not have chosen: a 1024-bit RSA key in a
	// CSR is not something to sign because the requester asked nicely.
	switch pub := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve.Params().BitSize < 256 {
			return nil, fmt.Errorf("nodeca: the request's curve is only %d bits", pub.Curve.Params().BitSize)
		}
	default:
		return nil, fmt.Errorf("nodeca: the request's key is %T, want an ECDSA key", csr.PublicKey)
	}
	return csr, nil
}

// NodeUUIDFromCommonName extracts the node uuid an agent certificate asserts.
func NodeUUIDFromCommonName(cert *x509.Certificate) string {
	return strings.TrimSpace(cert.Subject.CommonName)
}

func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("nodeca: the certificate is not PEM")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("nodeca: expected a certificate, got a %q block", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("nodeca: parse certificate: %w", err)
	}
	return cert, nil
}

// addHost puts a name in the right place: an IP in IPAddresses, anything else
// in DNSNames. Getting this wrong means a certificate that verifies for
// nothing.
func addHost(template *x509.Certificate, host string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	if ip := parseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
		return
	}
	template.DNSNames = append(template.DNSNames, host)
}

func randomSerial() (*big.Int, error) {
	// 128 random bits: unique without a counter, which matters because the
	// panel may issue from more than one process.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("nodeca: random serial: %w", err)
	}
	// Zero is not a valid serial.
	return serial.Add(serial, big.NewInt(1)), nil
}

func serialString(serial *big.Int) string {
	return strings.ToLower(serial.Text(16))
}
