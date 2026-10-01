package keygen

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// A generated Reality key pair must be the encoding xray-core and every client
// parser expect, and the public half must really belong to the private one.
func TestRealityKeyPair(t *testing.T) {
	pair, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Raw base64url, no padding: 32 bytes becomes 43 characters.
	for name, key := range map[string]string{"private": pair.PrivateKey, "public": pair.PublicKey} {
		if len(key) != 43 {
			t.Errorf("%s key = %q (%d characters), want 43", name, key, len(key))
		}
		if strings.ContainsAny(key, "+/=") {
			t.Errorf("%s key uses the standard base64 alphabet or padding: %q", name, key)
		}
		raw, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil || len(raw) != 32 {
			t.Errorf("%s key does not decode to 32 bytes: %v", name, err)
		}
	}

	// The public half has to be derivable from the private one, or a client
	// configured from the panel cannot complete a handshake.
	derived, err := RealityPublicKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if derived != pair.PublicKey {
		t.Errorf("derived public key = %q, want %q", derived, pair.PublicKey)
	}
}

func TestRealityKeyPairsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		pair, err := NewRealityKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if seen[pair.PrivateKey] {
			t.Fatal("a Reality private key was generated twice")
		}
		seen[pair.PrivateKey] = true
	}
}

// A key pasted in by hand arrives in whatever base64 the tool it came from
// used, and all of those have to work.
func TestRealityPublicKeyAcceptsBase64Variants(t *testing.T) {
	pair, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	variants := map[string]string{
		"raw url":         base64.RawURLEncoding.EncodeToString(raw),
		"padded url":      base64.URLEncoding.EncodeToString(raw),
		"raw standard":    base64.RawStdEncoding.EncodeToString(raw),
		"padded standard": base64.StdEncoding.EncodeToString(raw),
		"with whitespace": " " + base64.RawURLEncoding.EncodeToString(raw) + "\n",
	}
	for name, variant := range variants {
		got, err := RealityPublicKey(variant)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != pair.PublicKey {
			t.Errorf("%s: derived %q, want %q", name, got, pair.PublicKey)
		}
	}

	for _, bad := range []string{"", "not base64", "c2hvcnQ="} {
		if _, err := RealityPublicKey(bad); err == nil {
			t.Errorf("the key %q was accepted", bad)
		}
	}
}

func TestShortIDs(t *testing.T) {
	for size := 1; size <= 8; size++ {
		id, err := NewShortID(size)
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != size*2 {
			t.Errorf("a %d-byte short id is %q (%d characters)", size, id, len(id))
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Errorf("short id %q is not hex", id)
		}
	}
	for _, bad := range []int{0, -1, 9, 100} {
		if _, err := NewShortID(bad); err == nil {
			t.Errorf("a %d-byte short id was accepted", bad)
		}
	}

	ids, err := NewShortIDs(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatal("NewShortIDs returned a duplicate")
		}
		seen[id] = true
	}
	if len(ids) != 8 {
		t.Errorf("got %d short ids, want 8", len(ids))
	}
}

func TestUUID(t *testing.T) {
	first := NewUUID()
	if _, err := uuid.Parse(first); err != nil {
		t.Fatalf("%q is not a uuid: %v", first, err)
	}
	if first == NewUUID() {
		t.Fatal("two generated uuids are identical")
	}
}

func TestPassword(t *testing.T) {
	password, err := NewPassword()
	if err != nil {
		t.Fatal(err)
	}
	// 24 bytes raw base64url is 32 characters with nothing that needs
	// escaping in a URL or a shell.
	if len(password) != 32 {
		t.Errorf("password = %q (%d characters)", password, len(password))
	}
	if strings.ContainsAny(password, "+/=\"'\\ ") {
		t.Errorf("password contains a character that needs escaping: %q", password)
	}
	other, err := NewPassword()
	if err != nil {
		t.Fatal(err)
	}
	if password == other {
		t.Fatal("two generated passwords are identical")
	}
}

// The 2022 methods fix their key length, and the encoding is standard base64
// with padding. Both have to be right or the inbound will not start.
func TestShadowsocks2022Keys(t *testing.T) {
	cases := map[string]int{
		"2022-blake3-aes-128-gcm":       16,
		"2022-blake3-aes-256-gcm":       32,
		"2022-blake3-chacha20-poly1305": 32,
	}
	for method, size := range cases {
		if got, err := Shadowsocks2022KeySize(method); err != nil || got != size {
			t.Errorf("%s key size = %d, %v; want %d", method, got, err, size)
		}
		key, err := NewShadowsocks2022Key(method)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			t.Errorf("%s key %q is not standard base64: %v", method, key, err)
			continue
		}
		if len(raw) != size {
			t.Errorf("%s key decodes to %d bytes, want %d", method, len(raw), size)
		}
		if bytes.Equal(raw, make([]byte, size)) {
			t.Errorf("%s key is all zeros", method)
		}
	}

	for _, bad := range []string{"", "aes-256-gcm", "2022-blake3-rot13"} {
		if _, err := NewShadowsocks2022Key(bad); err == nil {
			t.Errorf("the method %q produced a key", bad)
		}
	}
}

// Only the aes 2022 methods have per-user key derivation, so only they can
// serve several users on one inbound. The panel has to tell an operator that
// before they pick one.
func TestSupportsMultipleUsers(t *testing.T) {
	multi := []string{
		"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
	}
	for _, method := range multi {
		if !SupportsMultipleUsers(method) {
			t.Errorf("%s should support several users", method)
		}
	}
	if SupportsMultipleUsers("2022-blake3-chacha20-poly1305") {
		t.Error("the 2022 chacha method cannot serve several users")
	}
}

func TestHexKeys(t *testing.T) {
	// The DNS tunnel reads its key file as text and insists on the exact
	// length for the method, so the generator has to hit it exactly.
	for _, length := range []int{16, 24, 32, 64} {
		key, err := NewHexKey(length)
		if err != nil {
			t.Fatal(err)
		}
		if len(key) != length {
			t.Errorf("a %d-character key is %q (%d characters)", length, key, len(key))
		}
		if _, err := hex.DecodeString(key); err != nil {
			t.Errorf("key %q is not hex", key)
		}
	}
	for _, bad := range []int{0, -2, 7} {
		if _, err := NewHexKey(bad); err == nil {
			t.Errorf("a %d-character hex key was accepted", bad)
		}
	}

	secret, err := NewFluxSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 64 {
		t.Errorf("a flux secret is %q (%d characters), want 64", secret, len(secret))
	}
}

func TestMethodListsAreUsable(t *testing.T) {
	for _, method := range Shadowsocks2022Methods() {
		if _, err := Shadowsocks2022KeySize(method); err != nil {
			t.Errorf("the panel offers %s but cannot size its key: %v", method, err)
		}
	}
	if len(LegacyShadowsocksMethods()) == 0 {
		t.Error("no legacy shadowsocks methods are offered")
	}
}
