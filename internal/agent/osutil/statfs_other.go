//go:build !linux

package osutil

import "errors"

// Statfs is only implemented on Linux.
func Statfs(string) (FSStats, error) { return FSStats{}, errors.New("osutil: statfs unsupported") }
