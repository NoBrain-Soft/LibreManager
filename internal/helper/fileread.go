package helper

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

var errLinkedFile = errors.New("file has multiple hard links")

// fileRead streams an allow-listed file. The requested path already passed
// policy (in admit); the symlink-resolved path must pass it as well, and is
// then opened without following any symlink, so a link (or a swapped path
// component) can never lead into a denied location.
func (s *Server) fileRead(out *jobOutput, pol *policy.Policy, fr *agentv1.FileRead) *agentv1.JobFinished {
	resolved, err := filepath.EvalSymlinks(fr.GetPath())
	if err != nil {
		return failed("cannot resolve path")
	}
	ev := policy.Evaluator{P: pol, Users: s.cfg.Users}
	if err := ev.CheckFileRead(resolved); err != nil {
		return rejected(err)
	}
	f, err := openNoFollow(resolved)
	if err != nil {
		return failed(fmt.Sprintf("cannot open %s: %v", resolved, errors.Unwrap(err)))
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return failed("not a regular file")
	}
	// A hard link is another name for the same inode; it could alias a
	// denied file (e.g. /etc/shadow) under an allowed path.
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Nlink != 1 {
		return rejected(errLinkedFile)
	}
	limit := pol.Limits.MaxFileReadBytes
	if mb := fr.GetMaxBytes(); mb > 0 && mb < limit {
		limit = mb
	}
	limit = min(limit, maxJobOutput)
	n, err := io.Copy(out.stream(agentv1.OutputStream_OUTPUT_STREAM_STDOUT), io.LimitReader(f, int64(limit))) //nolint:gosec // limit <= 4 MiB
	if err != nil {
		return failed("read error")
	}
	if st.Size() > n {
		out.info(fmt.Sprintf("[stellwerk] file truncated at %d of %d bytes", n, st.Size()))
	}
	return &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_SUCCEEDED, Message: resolved}
}

// openNoFollow opens path read-only refusing any symlink in any component
// (openat2 RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS). Kernels without
// openat2 (< 5.6) fall back to O_NOFOLLOW, which protects the last
// component only. O_NONBLOCK keeps a FIFO from blocking the open.
func openNoFollow(path string) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOCTTY | unix.O_NONBLOCK | unix.O_NOFOLLOW
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(flags), //nolint:gosec // positive flag bits
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if errors.Is(err, unix.ENOSYS) {
		fd, err = unix.Open(path, flags, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	return os.NewFile(uintptr(fd), path), nil
}
