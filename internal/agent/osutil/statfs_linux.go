//go:build linux

package osutil

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Statfs calls statfs(2).
func Statfs(path string) (FSStats, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return FSStats{}, fmt.Errorf("osutil: statfs %s: %w", path, err)
	}
	bs := uint64(st.Frsize) //nolint:gosec // block sizes are positive
	if bs == 0 {
		bs = uint64(st.Bsize) //nolint:gosec // block sizes are positive
	}
	return FSStats{
		Type:      int64(st.Type), //nolint:unconvert // field type differs by GOARCH
		BlockSize: bs,
		Blocks:    st.Blocks,
		Bfree:     st.Bfree,
		Bavail:    st.Bavail,
		Files:     st.Files,
		Ffree:     st.Ffree,
	}, nil
}
