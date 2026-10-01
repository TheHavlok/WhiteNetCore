package auth

import "encoding/base32"

// base32NoPad encodes an ASCII secret the way an authenticator app would see
// it, so the RFC 6238 vectors can be fed through the same code path a real
// secret takes.
func base32NoPad(ascii string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(ascii))
}
