package osutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// ErrTooLarge is returned when a file exceeds the caller's size limit.
var ErrTooLarge = errors.New("osutil: file exceeds size limit")

// ErrNotRegular is returned for FIFOs, devices, sockets and directories.
var ErrNotRegular = errors.New("osutil: not a regular file")

// ReadFileLimit reads a regular file of at most max bytes. It opens with
// O_NONBLOCK and checks the type with fstat, so a FIFO planted in a scanned
// directory can never block the agent. /proc and /sys attribute files are
// regular files and work as expected.
func ReadFileLimit(path string, max int64) ([]byte, error) {
	f, err := OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("osutil: read %s: %w", path, err)
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("osutil: %s: %w (%d bytes)", path, ErrTooLarge, max)
	}
	return data, nil
}

// OpenRegular opens path read-only without blocking and verifies that it is
// a regular file.
func OpenRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("osutil: open: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("osutil: stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("osutil: %s: %w", path, ErrNotRegular)
	}
	return f, nil
}

// ReadString reads a small file and returns its content with surrounding
// whitespace trimmed.
func ReadString(path string, max int64) (string, error) {
	data, err := ReadFileLimit(path, max)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ReadUint reads a file holding a single unsigned integer (sysfs/procfs
// attribute style).
func ReadUint(path string) (uint64, error) {
	s, err := ReadString(path, 64)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("osutil: parse %s: %w", path, err)
	}
	return v, nil
}
