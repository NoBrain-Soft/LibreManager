// Package timesync reports whether the kernel clock is synchronized, using a
// read-only adjtimex(2) query (the same source chrony, systemd-timesyncd and
// ntpd feed). It is shared by the agent core (metrics) and the helper
// (TIME-001 check, job time-window enforcement) and deliberately has no
// dependencies besides golang.org/x/sys.
//
// A read-only adjtimex needs no privileges, but it belongs to systemd's
// @clock syscall group: units using SystemCallFilter=@system-service must
// also allow "adjtimex" (and must not set ProtectClock=yes).
package timesync

import (
	"errors"
	"time"
)

// Kernel constants (include/uapi/linux/timex.h).
const (
	timeError = 5      // TIME_ERROR: clock not synchronized
	staUnsync = 0x0040 // STA_UNSYNC
	staNano   = 0x2000 // STA_NANO: offset is in ns instead of µs
)

// ErrUnsupported is returned on platforms without adjtimex.
var ErrUnsupported = errors.New("timesync: unsupported platform")

// Status is the raw subset of struct timex this package interprets.
type Status struct {
	// State is the adjtimex return value (TIME_OK ... TIME_ERROR).
	State int
	// Flags is timex.status (STA_* bits).
	Flags int64
	// Offset is timex.offset in µs, or ns when STA_NANO is set.
	Offset int64
}

// Interpret converts a raw kernel status into (synchronized, offset).
func Interpret(s Status) (bool, time.Duration) {
	synced := s.State != timeError && s.Flags&staUnsync == 0
	off := time.Duration(s.Offset)
	if s.Flags&staNano == 0 {
		off *= time.Microsecond
	}
	return synced, off
}

// Synchronized reports whether the kernel considers the clock synchronized
// and the current PLL offset.
func Synchronized() (bool, time.Duration, error) {
	st, err := query()
	if err != nil {
		return false, 0, err
	}
	synced, off := Interpret(st)
	return synced, off, nil
}
