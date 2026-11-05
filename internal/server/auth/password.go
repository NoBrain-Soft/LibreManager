// Package auth implements local authentication: Argon2id passwords, TOTP,
// WebAuthn, server-side sessions, token hashing and login throttling
// (ARCHITECTURE.md §6.4, ADR-0009).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (RFC 9106 second recommended option, memory-hard).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
	// MinPasswordLen is the minimum length for new passwords.
	MinPasswordLen = 12
	// MaxPasswordLen bounds hashing cost.
	MaxPasswordLen = 1024
)

// ErrPasswordPolicy is wrapped by password policy violations.
var ErrPasswordPolicy = errors.New("password does not meet policy")

// HashPassword returns an Argon2id PHC string.
func HashPassword(pw string) (string, error) {
	if len(pw) > MaxPasswordLen {
		return "", ErrPasswordPolicy
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// VerifyPassword checks pw against a PHC string in constant time.
func VerifyPassword(phc, pw string) bool {
	if len(pw) > MaxPasswordLen {
		return false
	}
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	// Refuse absurd parameters from a tampered hash (DoS).
	if m == 0 || m > 1<<20 || t == 0 || t > 10 || p == 0 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want))) //nolint:gosec // len bounded above
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified against for unknown users so that response time
// does not reveal whether an account exists.
var dummyHash = func() string {
	h, err := HashPassword("stellwerk-dummy-password-for-timing")
	if err != nil {
		panic(err)
	}
	return h
}()

// BurnPasswordCheck performs a password verification with the same cost as
// a real one.
func BurnPasswordCheck(pw string) { _ = VerifyPassword(dummyHash, pw) }

// CheckPasswordPolicy validates a new password.
func CheckPasswordPolicy(pw, username string) error {
	n := utf8.RuneCountInString(pw)
	switch {
	case n < MinPasswordLen:
		return fmt.Errorf("%w: at least %d characters required", ErrPasswordPolicy, MinPasswordLen)
	case len(pw) > MaxPasswordLen:
		return fmt.Errorf("%w: too long", ErrPasswordPolicy)
	case strings.EqualFold(pw, username) || strings.Contains(strings.ToLower(pw), strings.ToLower(username)) && len(username) >= 4:
		return fmt.Errorf("%w: must not contain the username", ErrPasswordPolicy)
	}
	lower := strings.ToLower(pw)
	for _, bad := range []string{"password", "123456789", "qwertyuiop", "stellwerk", "letmein", "changeme"} {
		if strings.Contains(lower, bad) {
			return fmt.Errorf("%w: too common", ErrPasswordPolicy)
		}
	}
	return nil
}

// GeneratePassword returns a random one-time password (~120 bits).
func GeneratePassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: %w", err)
	}
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = alphabet[int(c)%len(alphabet)]
	}
	// Groups of 6 for readability.
	s := string(out)
	return s[0:6] + "-" + s[6:12] + "-" + s[12:18] + "-" + s[18:24], nil
}
