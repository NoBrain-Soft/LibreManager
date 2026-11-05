//go:build !linux

package timesync

func query() (Status, error) { return Status{}, ErrUnsupported }
