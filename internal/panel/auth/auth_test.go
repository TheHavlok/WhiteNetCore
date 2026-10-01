package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPasswordRoundTrip(t *testing.T) {
	const password = "correct horse battery staple"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash = %q, want an argon2id PHC string", hash)
	}
	if strings.Contains(hash, password) {
		t.Fatal("the hash contains the password")
	}
	if err := CheckPassword(password, hash); err != nil {
		t.Fatal(err)
	}
	if err := CheckPassword("wrong", hash); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password gave %v, want ErrWrongPassword", err)
	}
}

// Two hashes of the same password must differ, or equal passwords would be
// recognisable in a database dump.
func TestPasswordHashIsSalted(t *testing.T) {
	first, err := HashPassword("same")
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword("same")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two hashes of the same password are identical")
	}
	// And both must still verify.
	for _, hash := range []string{first, second} {
		if err := CheckPassword("same", hash); err != nil {
			t.Error(err)
		}
	}
}

func TestPasswordRejections(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Error("an empty password was hashed")
	}
	for _, bad := range []string{
		"",
		"not a hash",
		"$argon2id$v=19$m=65536,t=3,p=2$notbase64!$alsonot!",
		"$argon2i$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0$a2V5",
		"$argon2id$v=1$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0$a2V5",
		"$argon2id$v=19$nonsense$c2FsdHNhbHRzYWx0$a2V5",
	} {
		if err := CheckPassword("x", bad); err == nil {
			t.Errorf("the hash %q was accepted", bad)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	current, err := HashPassword("x")
	if err != nil {
		t.Fatal(err)
	}
	if NeedsRehash(current) {
		t.Error("a freshly made hash wants rehashing")
	}
	// A hash made with weaker parameters should be upgraded on next login.
	weak := "$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0c2E$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5"
	if !NeedsRehash(weak) {
		t.Error("a weaker hash does not want rehashing")
	}
	if !NeedsRehash("rubbish") {
		t.Error("an unreadable hash does not want rehashing")
	}
}

func TestTOTPRoundTrip(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	// 20 bytes in base32 without padding is 32 characters.
	if len(secret) != 32 {
		t.Errorf("secret = %q (%d characters)", secret, len(secret))
	}

	now := time.Now()
	code, err := TOTPCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("code = %q, want six digits", code)
	}
	if err := CheckTOTP(secret, code, now); err != nil {
		t.Fatal(err)
	}
	// Spaces are how people type codes off a screen.
	if err := CheckTOTP(secret, code[:3]+" "+code[3:], now); err != nil {
		t.Errorf("a code with a space was rejected: %v", err)
	}
}

// A code typed as it rolls over must still work, and one from last week must
// not.
func TestTOTPSkew(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	previous, err := TOTPCode(secret, now.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckTOTP(secret, previous, now); err != nil {
		t.Errorf("the previous period's code was rejected: %v", err)
	}

	next, err := TOTPCode(secret, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckTOTP(secret, next, now); err != nil {
		t.Errorf("the next period's code was rejected: %v", err)
	}

	stale, err := TOTPCode(secret, now.Add(-10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckTOTP(secret, stale, now); !errors.Is(err, ErrWrongCode) {
		t.Errorf("a ten-minute-old code gave %v, want ErrWrongCode", err)
	}
}

func TestTOTPRejections(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "000000"} {
		if err := CheckTOTP(secret, bad, now); err == nil {
			t.Errorf("the code %q was accepted", bad)
		}
	}
	if err := CheckTOTP("not base32!", "123456", now); err == nil {
		t.Error("an unreadable secret was accepted")
	}
	if err := CheckTOTP("", "123456", now); err == nil {
		t.Error("an empty secret was accepted")
	}
}

// Known-answer test from RFC 6238's appendix B: the ASCII secret
// "12345678901234567890" at T=59 gives 287082 for SHA-1.
func TestTOTPAgainstRFC6238(t *testing.T) {
	// The RFC gives the secret as ASCII; authenticator apps use base32, so it
	// is encoded here the same way a real secret would be.
	const asciiSecret = "12345678901234567890"
	secret := base32NoPad(asciiSecret)

	code, err := TOTPCode(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" {
		t.Fatalf("code at T=59 = %s, want 287082 (RFC 6238 appendix B)", code)
	}

	// And the next vector, T=1111111109.
	code, err = TOTPCode(secret, time.Unix(1111111109, 0))
	if err != nil {
		t.Fatal(err)
	}
	if code != "081804" {
		t.Fatalf("code at T=1111111109 = %s, want 081804", code)
	}
}

func TestTOTPURL(t *testing.T) {
	url := TOTPURL("WhiteNet", "admin", "ABCDEFGHIJKLMNOP")
	for _, want := range []string{
		"otpauth://totp/",
		"secret=ABCDEFGHIJKLMNOP",
		"issuer=WhiteNet",
		"digits=6",
		"period=30",
		"algorithm=SHA1",
	} {
		if !strings.Contains(url, want) {
			t.Errorf("the otpauth URL is missing %s: %s", want, url)
		}
	}
}
