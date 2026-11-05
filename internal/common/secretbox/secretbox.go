// Package secretbox seals small secrets (CA keys, job-signing key, session
// recordings) at rest with XChaCha20-Poly1305 under a 32-byte master key.
//
// Format: "SWK1" || 24-byte nonce || ciphertext+tag. The purpose string is
// bound as associated data so a sealed blob cannot be swapped for another
// one (e.g. the intermediate key file for the job-signing key file).
package secretbox

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the master key size.
const KeySize = chacha20poly1305.KeySize

var magic = []byte("SWK1")

// ErrOpen is returned for any failure to authenticate/decrypt.
var ErrOpen = errors.New("secretbox: cannot open sealed data")

// Key is a master key.
type Key [KeySize]byte

// NewKey generates a random key.
func NewKey() (*Key, error) {
	var k Key
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	return &k, nil
}

// Seal encrypts plaintext for purpose.
func Seal(key *Key, purpose string, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	out := make([]byte, 0, len(magic)+len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, magic...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, []byte(purpose)), nil
}

// Open decrypts data sealed for purpose.
func Open(key *Key, purpose string, sealed []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	ns := aead.NonceSize()
	if len(sealed) < len(magic)+ns+aead.Overhead() || string(sealed[:len(magic)]) != string(magic) {
		return nil, ErrOpen
	}
	nonce := sealed[len(magic) : len(magic)+ns]
	pt, err := aead.Open(nil, nonce, sealed[len(magic)+ns:], []byte(purpose))
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// EncodeKey returns the base64 text form of a key (for key files).
func EncodeKey(k *Key) string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// ParseKey parses the base64 text form.
func ParseKey(s string) (*Key, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != KeySize {
		return nil, errors.New("secretbox: invalid key encoding")
	}
	var k Key
	copy(k[:], b)
	return &k, nil
}

// LoadKeyFile reads a base64 key file. It refuses files readable by group
// or others.
func LoadKeyFile(path string) (*Key, error) {
	path = filepath.Clean(path)
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secretbox: key file %s has insecure permissions %v", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	return ParseKey(string(b))
}

// WriteKeyFile writes a key with mode 0600 (fails if the file exists).
func WriteKeyFile(path string, k *Key) error {
	return WriteFileExclusive(path, []byte(EncodeKey(k)+"\n"))
}

// WriteFileExclusive creates path with mode 0600, failing if it exists.
func WriteFileExclusive(path string, data []byte) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("secretbox: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("secretbox: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("secretbox: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("secretbox: %w", err)
	}
	return nil
}

// SealFile seals plaintext and writes it exclusively with mode 0600.
func SealFile(key *Key, purpose, path string, plaintext []byte) error {
	b, err := Seal(key, purpose, plaintext)
	if err != nil {
		return err
	}
	return WriteFileExclusive(path, b)
}

// OpenFile reads and opens a sealed file.
func OpenFile(key *Key, purpose, path string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	return Open(key, purpose, b)
}
