package validate

import "testing"

func TestValidators(t *testing.T) {
	ok := func(name string, f func(string) bool, good, bad []string) {
		for _, s := range good {
			if !f(s) {
				t.Errorf("%s(%q) = false", name, s)
			}
		}
		for _, s := range bad {
			if f(s) {
				t.Errorf("%s(%q) = true", name, s)
			}
		}
	}
	ok("PackageName", PackageName, []string{"openssl", "libc6:amd64", "g++", "python3.11"}, []string{"", "-o", "a b", "x;y", "$(id)"})
	ok("UnitName", UnitName, []string{"nginx.service", "getty@tty1.service"}, []string{"nginx", "-x.service", "../a.service", "a b.service"})
	ok("AccountName", AccountName, []string{"ops", "_svc", "a.b-c"}, []string{"Root", "1abc", "", "a b"})
	ok("MetricName", MetricName, []string{"stellwerk_cpu_seconds_total"}, []string{"node_cpu", "stellwerk_", "stellwerk_a-b"})
	ok("LabelName", LabelName, []string{"mode", "device"}, []string{"__name__", "1a", "a-b"})
	ok("CheckID", CheckID, []string{"SSH-001", "TIME-001"}, []string{"ssh-001", "SSH-1"})
}

func TestText(t *testing.T) {
	if got := Text("a\x00b\nc\xffd", 100); got != "a?b?c?d" {
		t.Fatalf("got %q", got)
	}
	if got := Text("äöü", 4); got != "äö" {
		t.Fatalf("got %q", got)
	}
}
