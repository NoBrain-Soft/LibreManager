package ids

import "testing"

func TestNewIsV7AndValid(t *testing.T) {
	id := New()
	u, err := Parse(id)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Version() != 7 {
		t.Fatalf("version = %d, want 7", u.Version())
	}
}

func TestParseRejectsNonCanonical(t *testing.T) {
	for _, s := range []string{
		"",
		"00000000-0000-0000-0000-000000000000",
		"urn:uuid:0190f1c4-7c3b-7a8e-9b0e-1b2c3d4e5f60",
		"{0190f1c4-7c3b-7a8e-9b0e-1b2c3d4e5f60}",
		"0190f1c47c3b7a8e9b0e1b2c3d4e5f60",
		"0190f1c4-7c3b-7a8e-9b0e-1b2c3d4e5f6g",
		"../../etc/passwd/../../../../../../x",
	} {
		if Valid(s) {
			t.Errorf("Valid(%q) = true, want false", s)
		}
	}
}

func TestCanonicalLowercases(t *testing.T) {
	got, err := Canonical("0190F1C4-7C3B-7A8E-9B0E-1B2C3D4E5F60")
	if err != nil {
		t.Fatal(err)
	}
	if got != "0190f1c4-7c3b-7a8e-9b0e-1b2c3d4e5f60" {
		t.Fatalf("got %q", got)
	}
}
