package secretbox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSealOpen(t *testing.T) {
	k, _ := NewKey()
	other, _ := NewKey()
	sealed, err := Seal(k, "pki/intermediate", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(k, "pki/intermediate", sealed)
	if err != nil || string(pt) != "secret" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	for name, tc := range map[string]struct {
		key     *Key
		purpose string
		data    []byte
	}{
		"wrong key":     {other, "pki/intermediate", sealed},
		"wrong purpose": {k, "signer/jobkey", sealed},
		"tampered":      {k, "pki/intermediate", tampered},
		"truncated":     {k, "pki/intermediate", sealed[:10]},
		"bad magic":     {k, "pki/intermediate", append([]byte("XXXX"), sealed[4:]...)},
		"empty":         {k, "pki/intermediate", nil},
	} {
		if _, err := Open(tc.key, tc.purpose, tc.data); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: err = %v, want ErrOpen", name, err)
		}
	}
}

func TestKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "master.key")
	k, _ := NewKey()
	if err := WriteKeyFile(p, k); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKeyFile(p)
	if err != nil || *got != *k {
		t.Fatalf("LoadKeyFile: %v", err)
	}
	if err := WriteKeyFile(p, k); err == nil {
		t.Fatal("overwrote existing key file")
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(p); err == nil {
		t.Fatal("world-readable key file accepted")
	}
}

func TestParseKeyRejectsBadLength(t *testing.T) {
	if _, err := ParseKey("AAAA"); err == nil {
		t.Fatal("short key accepted")
	}
}
