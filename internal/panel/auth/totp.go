package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 specifies HMAC-SHA1, and authenticator apps implement that
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters. Six digits over thirty seconds with HMAC-SHA1 is what every
// authenticator app assumes; changing any of it means codes that do not match.
const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	// totpSkew is how many periods either side are accepted, which covers a
	// phone whose clock is a little off and a code typed as it rolls over.
	totpSkew = 1
	// secretLen is 20 bytes, the length RFC 4226 recommends for HMAC-SHA1.
	secretLen = 20
)

// ErrWrongCode is returned for a code that does not match.
var ErrWrongCode = errors.New("auth: wrong one-time code")

// NewTOTPSecret returns a fresh secret as base32 without padding, which is
// what authenticator apps and otpauth:// URLs use.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, secretLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: generate two-factor secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// TOTPURL builds the otpauth:// URL an authenticator app scans.
func TOTPURL(issuer, account, secret string) string {
	// The label is "Issuer:account" and the issuer is repeated as a
	// parameter; apps use the parameter and show the label.
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(int(totpPeriod.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPCode computes the code for a point in time.
func TOTPCode(secret string, at time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return code(key, uint64(at.Unix())/uint64(totpPeriod.Seconds())), nil
}

// CheckTOTP verifies a code, accepting one period either side.
//
// The comparison is constant time. Without that, an attacker could learn the
// right code digit by digit from how long the check took.
func CheckTOTP(secret, given string, at time.Time) error {
	given = strings.TrimSpace(strings.ReplaceAll(given, " ", ""))
	if len(given) != totpDigits {
		return ErrWrongCode
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return err
	}
	counter := uint64(at.Unix()) / uint64(totpPeriod.Seconds())

	var matched int
	for offset := -totpSkew; offset <= totpSkew; offset++ {
		candidate := code(key, counter+uint64(offset))
		// Every candidate is compared, and the result is accumulated rather
		// than returned early, so the time taken does not depend on which one
		// matched.
		matched |= subtle.ConstantTimeCompare([]byte(candidate), []byte(given))
	}
	if matched != 1 {
		return ErrWrongCode
	}
	return nil
}

func decodeSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		// Some apps hand back a padded secret.
		key, err = base32.StdEncoding.DecodeString(normalized)
		if err != nil {
			return nil, fmt.Errorf("auth: the two-factor secret is not base32: %w", err)
		}
	}
	if len(key) == 0 {
		return nil, errors.New("auth: the two-factor secret is empty")
	}
	return key, nil
}

// code is the HOTP truncation from RFC 4226.
func code(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// The low nibble of the last byte picks where to read four bytes from.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod)
}
