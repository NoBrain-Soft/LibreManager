package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA1 for authenticator compatibility
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// TOTP parameters (RFC 6238 defaults, compatible with all authenticator apps).
const (
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1 // accept ±1 step
)

// ErrTOTPInvalid is returned for wrong or replayed codes.
var ErrTOTPInvalid = errors.New("invalid TOTP code")

// NewTOTPSecret returns a random 160-bit secret.
func NewTOTPSecret() ([]byte, error) {
	s := make([]byte, 20)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	return s, nil
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// TOTPBase32 encodes a secret for display.
func TOTPBase32(secret []byte) string { return b32.EncodeToString(secret) }

// TOTPURL returns an otpauth:// URL for QR codes.
func TOTPURL(issuer, account string, secret []byte) string {
	v := url.Values{}
	v.Set("secret", TOTPBase32(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}

func hotp(secret []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", code)
}

// TOTPCode returns the code for time t (tests, enrollment check).
func TOTPCode(secret []byte, t time.Time) string {
	return hotp(secret, uint64(t.Unix())/totpPeriod) //nolint:gosec // unix time is positive
}

// ValidateTOTP checks code for time now and returns the matched time step.
// lastStep is the last accepted step; codes at or before it are rejected
// (replay protection). The caller must persist the returned step
// atomically (only forward).
func ValidateTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, error) {
	if len(code) != totpDigits {
		return 0, ErrTOTPInvalid
	}
	cur := now.Unix() / totpPeriod
	matched := int64(-1)
	for d := -totpSkew; d <= totpSkew; d++ {
		step := cur + int64(d)
		if step <= 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(secret, uint64(step))), []byte(code)) == 1 { //nolint:gosec // step > 0
			matched = step
		}
	}
	if matched < 0 || matched <= lastStep {
		return 0, ErrTOTPInvalid
	}
	return matched, nil
}
