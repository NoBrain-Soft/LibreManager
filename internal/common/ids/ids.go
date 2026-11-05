// Package ids generates and validates identifiers (UUIDv7, CLAUDE.md conventions).
package ids

import (
	"fmt"

	"github.com/google/uuid"
)

// New returns a new UUIDv7 string.
func New() string {
	return uuid.Must(uuid.NewV7()).String()
}

// NewUUID returns a new UUIDv7.
func NewUUID() uuid.UUID {
	return uuid.Must(uuid.NewV7())
}

// Parse parses a canonical (36 character, lowercase or uppercase) UUID string.
// Non-canonical forms (urn:, braces, no dashes) are rejected so that an
// identifier has exactly one textual representation.
func Parse(s string) (uuid.UUID, error) {
	if len(s) != 36 {
		return uuid.Nil, fmt.Errorf("ids: invalid uuid length %d", len(s))
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("ids: %w", err)
	}
	if u == uuid.Nil {
		return uuid.Nil, fmt.Errorf("ids: nil uuid")
	}
	return u, nil
}

// Valid reports whether s is a canonical, non-nil UUID.
func Valid(s string) bool {
	_, err := Parse(s)
	return err == nil
}

// Canonical returns the lowercase canonical form of s, or an error.
func Canonical(s string) (string, error) {
	u, err := Parse(s)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}
