package journal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// parseEntry decodes a native-protocol datagram (test helper).
func parseEntry(t *testing.T, b []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	for len(b) > 0 {
		nl := bytes.IndexByte(b, '\n')
		if nl < 0 {
			t.Fatalf("unterminated field: %q", b)
		}
		line := b[:nl]
		if eq := bytes.IndexByte(line, '='); eq >= 0 {
			out[string(line[:eq])] = string(line[eq+1:])
			b = b[nl+1:]
			continue
		}
		name := string(line)
		b = b[nl+1:]
		if len(b) < 8 {
			t.Fatalf("short binary field %s", name)
		}
		n := binary.LittleEndian.Uint64(b[:8])
		b = b[8:]
		if uint64(len(b)) < n+1 || b[n] != '\n' {
			t.Fatalf("bad binary field %s", name)
		}
		out[name] = string(b[:n])
		b = b[n+1:]
	}
	return out
}

func listen(t *testing.T) (string, *net.UnixConn) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "journal.sock")
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: p, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return p, c
}

func TestSendNativeProtocol(t *testing.T) {
	sock, srv := listen(t)
	var fb bytes.Buffer
	c := &Client{Identifier: "stellwerk-agent-helper", Socket: sock, Fallback: &fb}
	defer c.Close()

	err := c.Send(PriNotice, "executing job\nsecond line", map[string]string{
		"STELLWERK_JOB_ID":       "0190a0b0-0000-7000-8000-000000000001",
		"STELLWERK_ACTION":       "pkg_upgrade",
		"STELLWERK_REQUESTED_BY": "alice=evil\nINJECTED=1",
	})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := parseEntry(t, buf[:n])
	want := map[string]string{
		"PRIORITY":               "5",
		"SYSLOG_IDENTIFIER":      "stellwerk-agent-helper",
		"MESSAGE":                "executing job\nsecond line",
		"STELLWERK_JOB_ID":       "0190a0b0-0000-7000-8000-000000000001",
		"STELLWERK_ACTION":       "pkg_upgrade",
		"STELLWERK_REQUESTED_BY": "alice=evil\nINJECTED=1",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d fields: %v", len(got), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["INJECTED"]; ok {
		t.Fatal("newline in value injected a field")
	}
	if fb.Len() != 0 {
		t.Fatalf("unexpected fallback output %q", fb.String())
	}
}

func TestFallbackWhenSocketMissing(t *testing.T) {
	var fb bytes.Buffer
	c := &Client{Identifier: "x", Socket: filepath.Join(t.TempDir(), "absent.sock"), Fallback: &fb}
	defer c.Close()
	if err := c.Send(PriWarning, "job rejected\x1b[31m", map[string]string{"STELLWERK_DECISION": "rejected"}); err != nil {
		t.Fatal(err)
	}
	line := fb.String()
	if !strings.HasPrefix(line, "<4>x: ") || !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("fallback line %q", line)
	}
	if strings.ContainsRune(line, 0x1b) {
		t.Fatal("control characters must be escaped in fallback output")
	}
	if !strings.Contains(line, `STELLWERK_DECISION="rejected"`) {
		t.Fatalf("missing field in %q", line)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestFallbackErrorIsReported(t *testing.T) {
	c := &Client{Identifier: "x", Socket: filepath.Join(t.TempDir(), "absent.sock"), Fallback: failWriter{}}
	defer c.Close()
	if err := c.Send(PriInfo, "m", nil); err == nil {
		t.Fatal("expected error when both journald and fallback fail")
	}
}

func TestRejectsInvalidFields(t *testing.T) {
	c := &Client{Identifier: "x", Socket: filepath.Join(t.TempDir(), "absent.sock"), Fallback: &bytes.Buffer{}}
	for _, k := range []string{"", "lower", "_TRUSTED", "1ABC", "MESSAGE", "PRIORITY", "SYSLOG_IDENTIFIER", "A-B", strings.Repeat("A", 65)} {
		if err := c.Send(PriInfo, "m", map[string]string{k: "v"}); !errors.Is(err, ErrInvalidField) {
			t.Errorf("field %q: err = %v", k, err)
		}
	}
	tooMany := map[string]string{}
	for i := range maxFields + 1 {
		tooMany[fmt.Sprintf("F%d", i)] = "v"
	}
	if err := c.Send(PriInfo, "m", tooMany); err == nil {
		t.Error("expected error for too many fields")
	}
}

func TestValueIsClipped(t *testing.T) {
	sock, srv := listen(t)
	c := &Client{Identifier: "x", Socket: sock}
	defer c.Close()
	if err := c.Send(PriInfo, strings.Repeat("a", maxFieldValue*2), nil); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128<<10)
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := parseEntry(t, buf[:n])["MESSAGE"]; len(got) != maxFieldValue {
		t.Fatalf("message length %d", len(got))
	}
}

func FuzzAppendField(f *testing.F) {
	f.Add("hello")
	f.Add("a\nb")
	f.Add("")
	f.Fuzz(func(t *testing.T, v string) {
		b := appendField(nil, "F", v)
		got := parseEntry(t, b)
		want := clip(v)
		if got["F"] != want {
			t.Fatalf("round trip %q -> %q", want, got["F"])
		}
	})
}
