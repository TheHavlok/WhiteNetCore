// Package auth hashes admin passwords and checks one-time codes.
//
// Both are small enough to own: the password hash is argon2id with its
// parameters recorded in the string, so they can be raised later without
// invalidating existing hashes, and TOTP is RFC 6238, which is a HMAC and a
// truncation.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2 parameters. These are the defaults for an interactive login on a
// small VPS: 64 MiB and one pass over it takes well under a second on one
// core, which is the budget a login has.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// ErrInvalidHash is returned for a stored hash this package cannot read.
var ErrInvalidHash = errors.New("auth: the stored password hash is malformed")

// ErrWrongPassword is returned when the password does not match. It is
// deliberately the same error whatever was wrong with it.
var ErrWrongPassword = errors.New("auth: wrong password")

// HashPassword returns a PHC-formatted argon2id hash.
//
// The parameters travel in the string, so raising them later is a matter of
// re-hashing on the next successful login rather than a migration.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("auth: empty password")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// CheckPassword verifies a password against a stored hash.
//
// The comparison is constant time, which matters here: the hash is per-user,
// so a timing difference would leak how much of a guess was right.
func CheckPassword(password, encoded string) error {
	params, salt, want, err := decodeHash(encoded)
	if err != nil {
		return err
	}
	got := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrWrongPassword
	}
	return nil
}

// NeedsRehash reports whether a stored hash used weaker parameters than the
// current ones, so a login can quietly upgrade it.
func NeedsRehash(encoded string) bool {
	params, _, _, err := decodeHash(encoded)
	if err != nil {
		return true
	}
	return params.memory < argonMemory || params.time < argonTime || params.threads < argonThreads
}

type hashParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func decodeHash(encoded string) (params hashParams, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=...,t=...,p=...", salt, key
	if len(parts) != 6 || parts[1] != "argon2id" {
		return hashParams{}, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return hashParams{}, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return hashParams{}, nil, nil, fmt.Errorf("%w: argon2 version %d", ErrInvalidHash, version)
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.time, &params.threads); err != nil {
		return hashParams{}, nil, nil, ErrInvalidHash
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return hashParams{}, nil, nil, ErrInvalidHash
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return hashParams{}, nil, nil, ErrInvalidHash
	}
	return params, salt, key, nil
}
