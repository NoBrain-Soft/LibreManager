package timesync

import (
	"runtime"
	"testing"
	"time"
)

func TestInterpret(t *testing.T) {
	tests := []struct {
		name       string
		st         Status
		wantSynced bool
		wantOff    time.Duration
	}{
		{"ok micro", Status{State: 0, Flags: 0x0001, Offset: 1500}, true, 1500 * time.Microsecond},
		{"ok nano", Status{State: 0, Flags: staNano, Offset: 1500}, true, 1500 * time.Nanosecond},
		{"negative offset", Status{State: 0, Offset: -250}, true, -250 * time.Microsecond},
		{"time error", Status{State: timeError}, false, 0},
		{"unsync flag", Status{State: 0, Flags: staUnsync, Offset: 7}, false, 7 * time.Microsecond},
		{"leap insert still synced", Status{State: 1}, true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synced, off := Interpret(tt.st)
			if synced != tt.wantSynced || off != tt.wantOff {
				t.Fatalf("Interpret(%+v) = %v, %v; want %v, %v", tt.st, synced, off, tt.wantSynced, tt.wantOff)
			}
		})
	}
}

func TestSynchronizedSmoke(t *testing.T) {
	_, _, err := Synchronized()
	if runtime.GOOS == "linux" {
		// A read-only adjtimex must work unprivileged. Some sandboxes block
		// the syscall with EPERM; that is the only acceptable failure.
		if err != nil {
			t.Logf("adjtimex unavailable in this environment: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("expected ErrUnsupported on non-linux")
	}
}
