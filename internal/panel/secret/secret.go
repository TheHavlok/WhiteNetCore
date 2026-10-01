// Package secret encrypts the values the panel must store but must not store
// in the clear: Reality private keys, user passwords, TOTP seeds, OpenFlux
// channel keys, the node CA's private key and the rendered desired state.
//
// One master key, supplied by the configuration and never written to the
// database, protects all of them. The ciphertext layout is deliberately
// boring: a version byte, the nonce, then AES-256-GCM output. The version
// byte is what makes a future key rotation or cipher change possible without
// guessing at what an old row contains.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Version1 is AES-256-GCM with a random 12-byte nonce.
const Version1 byte = 1

// MasterKeyBytes is the size of a raw master key.
const MasterKeyBytes = 32

var (
	// ErrNoKey is returned by New when the master key is empty.
	ErrNoKey = errors.New("secret: master key is empty")
	// ErrCiphertext is returned for input that is not a well-formed box.
	ErrCiphertext = errors.New("secret: malformed ciphertext")
	// ErrVersion is returned for a box written by a newer version.
	ErrVersion = errors.New("secret: unsupported ciphertext version")
)

// Box seals and opens values under one master key.
type Box struct {
	aead cipher.AEAD
}

// New builds a Box from a master key given as 64 hex characters, as standard
// base64, or as any other string. A string that is neither hex nor base64 of
// exactly 32 bytes is hashed with SHA-256, so a long passphrase in a config
// file works without the operator having to know about key sizes - but
// ParseKey is what the configuration loader uses, so a short passphrase is
// rejected before it ever reaches here.
func New(masterKey string) (*Box, error) {
	key, err := ParseKey(masterKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: new gcm: %w", err)
	}
	return &Box{aead: aead}, nil
}

// ParseKey turns the configured master key into 32 raw bytes.
func ParseKey(masterKey string) ([]byte, error) {
	if masterKey == "" {
		return nil, ErrNoKey
	}
	if raw, err := hex.DecodeString(masterKey); err == nil && len(raw) == MasterKeyBytes {
		return raw, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(masterKey); err == nil && len(raw) == MasterKeyBytes {
		return raw, nil
	}
	sum := sha256.Sum256([]byte(masterKey))
	return sum[:], nil
}

// NewMasterKey returns a fresh master key as 64 hex characters, for the
// install script and the "generate" helper in the panel.
func NewMasterKey() (string, error) {
	raw := make([]byte, MasterKeyBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("secret: read random: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// Seal encrypts plaintext. Sealing nil returns nil so a NULL column stays
// NULL rather than becoming an encrypted empty string.
func (b *Box) Seal(plaintext []byte) ([]byte, error) {
	if plaintext == nil {
		return nil, nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secret: read nonce: %w", err)
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+b.aead.Overhead())
	out = append(out, Version1)
	out = append(out, nonce...)
	return b.aead.Seal(out, nonce, plaintext, nil), nil
}

// SealString is Seal for text values.
func (b *Box) SealString(s string) ([]byte, error) {
	return b.Seal([]byte(s))
}

// Open decrypts a box produced by Seal. A value that was tampered with, or
// encrypted under a different master key, fails here rather than returning
// garbage.
func (b *Box) Open(box []byte) ([]byte, error) {
	if box == nil {
		return nil, nil
	}
	if len(box) < 1+b.aead.NonceSize()+b.aead.Overhead() {
		return nil, ErrCiphertext
	}
	if box[0] != Version1 {
		return nil, fmt.Errorf("%w: %d", ErrVersion, box[0])
	}
	nonce := box[1 : 1+b.aead.NonceSize()]
	plaintext, err := b.aead.Open(nil, nonce, box[1+b.aead.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("secret: open: %w", err)
	}
	return plaintext, nil
}

// OpenString is Open for text values.
func (b *Box) OpenString(box []byte) (string, error) {
	plaintext, err := b.Open(box)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
