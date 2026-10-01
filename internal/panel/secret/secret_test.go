package secret

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

const testKey = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

func TestSealOpenRoundTrip(t *testing.T) {
	box, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{"", "reality-private-key", "ключ с юникодом"} {
		sealed, err := box.SealString(plaintext)
		if err != nil {
			t.Fatalf("seal %q: %v", plaintext, err)
		}
		if bytes.Contains(sealed, []byte(plaintext)) && plaintext != "" {
			t.Fatalf("seal %q leaked the plaintext", plaintext)
		}
		got, err := box.OpenString(sealed)
		if err != nil {
			t.Fatalf("open %q: %v", plaintext, err)
		}
		if got != plaintext {
			t.Fatalf("round trip: got %q want %q", got, plaintext)
		}
	}
}

// Two seals of the same value must differ, or equal secrets would be
// recognisable in a database dump.
func TestSealIsRandomised(t *testing.T) {
	box, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	a, err := box.SealString("same")
	if err != nil {
		t.Fatal(err)
	}
	b, err := box.SealString("same")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext are identical")
	}
}

func TestSealNilStaysNil(t *testing.T) {
	box, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if sealed != nil {
		t.Fatalf("seal(nil) = %v, want nil", sealed)
	}
	opened, err := box.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	if opened != nil {
		t.Fatalf("open(nil) = %v, want nil", opened)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	a, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New("f00f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.SealString("secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("opening with the wrong master key succeeded")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	box, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.SealString("secret")
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0x01
	if _, err := box.Open(sealed); err == nil {
		t.Fatal("opening tampered ciphertext succeeded")
	}
}

func TestOpenRejectsUnknownVersion(t *testing.T) {
	box, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.SealString("secret")
	if err != nil {
		t.Fatal(err)
	}
	sealed[0] = 99
	if _, err := box.Open(sealed); !errors.Is(err, ErrVersion) {
		t.Fatalf("open with unknown version: got %v, want ErrVersion", err)
	}
}

func TestOpenRejectsShortInput(t *testing.T) {
	box, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := box.Open([]byte{Version1, 0x00}); !errors.Is(err, ErrCiphertext) {
		t.Fatalf("open short input: got %v, want ErrCiphertext", err)
	}
}

func TestParseKeyAcceptsHexBase64AndPassphrase(t *testing.T) {
	hexKey, err := ParseKey(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(hexKey) != MasterKeyBytes {
		t.Fatalf("hex key length = %d", len(hexKey))
	}

	b64 := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	b64Key, err := ParseKey(b64)
	if err != nil {
		t.Fatal(err)
	}
	if len(b64Key) != MasterKeyBytes {
		t.Fatalf("base64 key length = %d", len(b64Key))
	}

	// Anything else is hashed, so an arbitrary passphrase still yields a
	// usable 32-byte key.
	passKey, err := ParseKey("a long operator passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if len(passKey) != MasterKeyBytes {
		t.Fatalf("passphrase key length = %d", len(passKey))
	}

	if _, err := ParseKey(""); !errors.Is(err, ErrNoKey) {
		t.Fatalf("empty key: got %v, want ErrNoKey", err)
	}
}

func TestNewMasterKeyIsHexAndUnique(t *testing.T) {
	a, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(a)
	if err != nil || len(raw) != MasterKeyBytes {
		t.Fatalf("generated key is not 32 hex bytes: %q (%v)", a, err)
	}
	b, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two generated master keys are identical")
	}
}
