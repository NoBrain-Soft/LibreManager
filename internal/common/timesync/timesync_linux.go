//go:build linux

package timesync

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func query() (Status, error) {
	var tx unix.Timex // Modes == 0: read-only query
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return Status{}, fmt.Errorf("timesync: adjtimex: %w", err)
	}
	return Status{State: state, Flags: int64(tx.Status), Offset: int64(tx.Offset)}, nil
}
