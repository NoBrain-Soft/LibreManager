package shell

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/secretbox"
)

func TestRecordingRoundTripAndTamper(t *testing.T) {
	dir := t.TempDir()
	key, _ := secretbox.NewKey()
	sid := ids.New()
	t0 := time.Unix(1000, 0)
	r, err := NewRecorder(dir, sid, key, 80, 24, "web1", t0)
	if err != nil {
		t.Fatal(err)
	}
	r.Output(t0.Add(time.Second), []byte("hello\r\n"))
	r.Resize(t0.Add(2*time.Second), 100, 30)
	r.Output(t0.Add(8*time.Second), []byte("bye\xff\r\n"))
	sum, err := r.Close(t0.Add(9 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	cast, err := Open(r.Path, sid, key, sum)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(cast)), "\n")
	if len(lines) != 4 || !strings.Contains(lines[0], `"version":2`) || !strings.Contains(lines[1], "hello") || !strings.Contains(lines[2], `"r","100x30"`) {
		t.Fatalf("cast:\n%s", cast)
	}
	raw, _ := os.ReadFile(r.Path)
	if strings.Contains(string(raw), "hello") {
		t.Fatal("recording not encrypted")
	}
	if _, err := Open(r.Path, ids.New(), key, nil); err == nil {
		t.Fatal("opened with wrong session id")
	}
	raw[len(raw)-1] ^= 1
	_ = os.WriteFile(r.Path, raw, 0o600)
	if _, err := Open(r.Path, sid, key, sum); err == nil {
		t.Fatal("tampered recording accepted")
	}
	if _, err := Open(r.Path, sid, key, nil); err == nil {
		t.Fatal("tampered chunk accepted")
	}
}
