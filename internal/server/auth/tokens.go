package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Token prefixes make leaked secrets recognizable (secret scanners).
const (
	PrefixEnrollment = "swk_enr_"
	PrefixAPIToken   = "swk_api_"
	PrefixSession    = "" // session tokens are opaque cookie values
)

// RandomToken returns prefix + 32 random bytes (base64url).
func RandomToken(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Pepper is a server-side secret mixed into stored token hashes, so a
// database dump alone does not allow offline guessing (CLAUDE.md rule 7).
type Pepper []byte

// LoadPepper reads a base64 pepper file.
func LoadPepper(path string) (Pepper, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("auth: pepper: %w", err)
	}
	p, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(p) < 32 {
		return nil, fmt.Errorf("auth: pepper file %s is invalid", path)
	}
	return Pepper(p), nil
}

// HashToken returns HMAC-SHA256(pepper, token).
func (p Pepper) HashToken(token string) []byte {
	m := hmac.New(sha256.New, p)
	m.Write([]byte(token))
	return m.Sum(nil)
}

// HashSessionToken hashes a session cookie value (no pepper needed: 256-bit
// random tokens are not guessable; the hash prevents use of a DB dump).
func HashSessionToken(token string) []byte {
	s := sha256.Sum256([]byte(token))
	return s[:]
}
