package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected PHC %q", h)
	}
	if !VerifyPassword(h, "correct horse battery staple") {
		t.Fatal("correct password rejected")
	}
	for _, bad := range []string{"", "correct horse battery stapl", strings.Repeat("x", MaxPasswordLen+1)} {
		if VerifyPassword(h, bad) {
			t.Fatalf("wrong password %q accepted", bad)
		}
	}
	for _, phc := range []string{"", "$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=999999999,t=3,p=4$c2FsdA$aGFzaA", "$argon2id$v=19$m=65536,t=3,p=4$!!$aGFzaA"} {
		if VerifyPassword(phc, "x") {
			t.Fatalf("malformed hash %q accepted", phc)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	for pw, ok := range map[string]bool{
		"short":                  false,
		"alicealicealice":        false, // contains username
		"MyPassword12345":        false, // common
		"tr0ub4dor&3-xkcd-horse": true,
	} {
		err := CheckPasswordPolicy(pw, "alice")
		if (err == nil) != ok {
			t.Errorf("%q: err = %v", pw, err)
		}
	}
	p, err := GeneratePassword()
	if err != nil || CheckPasswordPolicy(p, "admin") != nil {
		t.Fatalf("generated password %q fails policy: %v", p, err)
	}
}

func TestTOTP(t *testing.T) {
	// RFC 6238 test vector (SHA1, secret "12345678901234567890", T=59 -> 94287082 (8 digits) -> 287082).
	secret := []byte("12345678901234567890")
	if got := TOTPCode(secret, time.Unix(59, 0)); got != "287082" {
		t.Fatalf("TOTP(59) = %s", got)
	}
	now := time.Unix(1_700_000_000, 0)
	code := TOTPCode(secret, now)
	step, err := ValidateTOTP(secret, code, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateTOTP(secret, code, now, step); err == nil {
		t.Fatal("replayed code accepted")
	}
	if _, err := ValidateTOTP(secret, TOTPCode(secret, now.Add(-30*time.Second)), now, 0); err != nil {
		t.Fatal("previous step within skew rejected")
	}
	if _, err := ValidateTOTP(secret, TOTPCode(secret, now.Add(-90*time.Second)), now, 0); err == nil {
		t.Fatal("code outside window accepted")
	}
	if _, err := ValidateTOTP(secret, "12345", now, 0); err == nil {
		t.Fatal("short code accepted")
	}
	if !strings.HasPrefix(TOTPURL("Stellwerk", "alice", secret), "otpauth://totp/Stellwerk:alice?") {
		t.Fatal("bad otpauth url")
	}
}

func TestPepperHash(t *testing.T) {
	p := Pepper([]byte(strings.Repeat("k", 32)))
	q := Pepper([]byte(strings.Repeat("q", 32)))
	tok, err := RandomToken(PrefixEnrollment)
	if err != nil || !strings.HasPrefix(tok, PrefixEnrollment) {
		t.Fatal(err)
	}
	if string(p.HashToken(tok)) == string(q.HashToken(tok)) {
		t.Fatal("pepper not mixed in")
	}
}

func TestKeyedLimiter(t *testing.T) {
	l := NewKeyedLimiter(60, 2)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	if !l.Allow("a") || !l.Allow("a") || l.Allow("a") {
		t.Fatal("burst not enforced")
	}
	if !l.Allow("b") {
		t.Fatal("keys not independent")
	}
	now = now.Add(time.Second)
	if !l.Allow("a") {
		t.Fatal("no refill")
	}
}
