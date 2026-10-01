// Package keygen generates the key material the panel's buttons produce:
// Reality key pairs, short ids, UUIDs, Shadowsocks keys and passwords.
//
// Every format here has to match what xray-core expects byte for byte, which
// is why each one says where its encoding comes from. A Reality key in the
// wrong base64 alphabet, for instance, loads without complaint and then fails
// every handshake.
package keygen

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// RealityKeyPair is an x25519 key pair for REALITY.
type RealityKeyPair struct {
	// PrivateKey goes into the inbound's realitySettings.privateKey.
	PrivateKey string `json:"private_key"`
	// PublicKey goes to the client as `pbk`.
	PublicKey string `json:"public_key"`
}

// NewRealityKeyPair generates a REALITY key pair.
//
// Both halves are raw base64url without padding, which is the encoding
// `xray x25519` prints and the only one the client parsers accept.
func NewRealityKeyPair() (RealityKeyPair, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return RealityKeyPair{}, fmt.Errorf("keygen: generate x25519 key: %w", err)
	}
	return RealityKeyPair{
		PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()),
		PublicKey:  base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
	}, nil
}

// RealityPublicKey derives the public half from a private key, so the panel
// can show the client's `pbk` for an inbound whose key was pasted in rather
// than generated.
func RealityPublicKey(privateKey string) (string, error) {
	raw, err := decodeKey(privateKey)
	if err != nil {
		return "", err
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("keygen: %q is not an x25519 private key: %w", privateKey, err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// decodeKey accepts the base64 variants a key may arrive in: `xray x25519`
// prints raw base64url, but keys get copied through tools that pad them or use
// the standard alphabet.
func decodeKey(encoded string) ([]byte, error) {
	trimmed := strings.TrimSpace(encoded)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if raw, err := enc.DecodeString(trimmed); err == nil && len(raw) == 32 {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("keygen: %q is not a 32-byte base64 key", encoded)
}

// NewShortID generates a REALITY short id.
//
// It is hex of one to eight bytes; the panel defaults to eight, which is the
// longest and therefore the one that identifies a client set most precisely.
func NewShortID(bytes int) (string, error) {
	if bytes <= 0 || bytes > 8 {
		return "", fmt.Errorf("keygen: a short id is 1 to 8 bytes, got %d", bytes)
	}
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("keygen: generate short id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// NewShortIDs generates a set of distinct short ids, which is what an inbound
// usually wants: one per client group.
func NewShortIDs(count, bytes int) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, count)
	for len(out) < count {
		id, err := NewShortID(bytes)
		if err != nil {
			return nil, err
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out, nil
}

// NewUUID is the identity for VLESS and VMess.
func NewUUID() string { return uuid.NewString() }

// NewPassword generates a password for Trojan, Hysteria2 and legacy
// Shadowsocks.
//
// Base64url of 24 random bytes: 32 characters, no punctuation that needs
// escaping in a URL or a shell, and 192 bits of entropy, which is far past
// anything that could be guessed.
func NewPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("keygen: generate password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// NewShadowsocks2022Key generates a key for a 2022 method.
//
// The length is fixed by the method - 16 bytes for the aes-128 variants, 32
// for the others - and the encoding is standard base64 *with* padding, which
// is what sing-shadowsocks parses. Getting either wrong is an inbound that
// refuses to start.
func NewShadowsocks2022Key(method string) (string, error) {
	size, err := Shadowsocks2022KeySize(method)
	if err != nil {
		return "", err
	}
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("keygen: generate shadowsocks key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// Shadowsocks2022KeySize is how many bytes a 2022 method's key needs.
func Shadowsocks2022KeySize(method string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "2022-blake3-aes-128-gcm":
		return 16, nil
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "2022-blake3-chacha8-poly1305":
		return 32, nil
	default:
		return 0, fmt.Errorf("keygen: %q is not a shadowsocks 2022 method", method)
	}
}

// NewHexKey generates a key as hex of the given length in characters, which is
// what the DNS tunnel's key file wants: it reads the file as text and insists
// on an exact length.
func NewHexKey(length int) (string, error) {
	if length <= 0 || length%2 != 0 {
		return "", fmt.Errorf("keygen: a hex key length must be a positive even number, got %d", length)
	}
	raw := make([]byte, length/2)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("keygen: generate hex key: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// NewFluxSecret generates a flux channel's AES-256-GCM secret: 64 hex
// characters, matching what the flux stack's key file holds.
func NewFluxSecret() (string, error) { return NewHexKey(64) }

// LegacyShadowsocksMethods are the methods the panel offers for the
// non-2022 protocol. The list is what xray-core's loader accepts.
func LegacyShadowsocksMethods() []string {
	return []string{
		"aes-128-gcm",
		"aes-256-gcm",
		"chacha20-ietf-poly1305",
		"xchacha20-ietf-poly1305",
	}
}

// Shadowsocks2022Methods are the 2022 methods the panel offers.
//
// Only the aes ones can serve several users, because they are the only ones
// with per-user key derivation, so the panel marks the others accordingly.
func Shadowsocks2022Methods() []string {
	return []string{
		"2022-blake3-aes-128-gcm",
		"2022-blake3-aes-256-gcm",
		"2022-blake3-chacha20-poly1305",
	}
}

// SupportsMultipleUsers reports whether a Shadowsocks method can serve more
// than one user on one inbound.
func SupportsMultipleUsers(method string) bool {
	normalized := strings.ToLower(strings.TrimSpace(method))
	if !strings.HasPrefix(normalized, "2022-") {
		// Legacy methods take a per-user password, so any of them can.
		return true
	}
	return strings.Contains(normalized, "aes")
}
