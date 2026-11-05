package collect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
)

// maxFilesystems bounds the number of reported filesystems (series budget).
const maxFilesystems = 128

// filesystemCollector reports usage of real filesystems from the host's
// mount table and statfs(2). Labels: mountpoint, device, fstype.
//
//	stellwerk_filesystem_size_bytes, _avail_bytes, _free_bytes  gauge
//	stellwerk_filesystem_files, _files_free                     gauge
//	stellwerk_filesystem_readonly                               gauge (0/1)
//
// Bind mounts are deduplicated by device; pseudo and container-internal
// filesystems are skipped (osutil.RealFilesystem). Network filesystems are
// included; statfs runs with a timeout so a hung server cannot block
// collection. Mounts that are shadowed in the agent's own mount namespace
// (e.g. /home under ProtectHome=yes shows a tmpfs) are skipped rather than
// reported with wrong numbers.
type filesystemCollector struct {
	procRoot string
	rootFS   string
	statfs   *osutil.GuardedStatfs
	log      *slog.Logger
}

func newFilesystemCollector(o Options) *filesystemCollector {
	return &filesystemCollector{
		procRoot: o.ProcRoot,
		rootFS:   o.RootFS,
		statfs:   &osutil.GuardedStatfs{Fn: o.Statfs, Timeout: o.StatfsTimeout},
		log:      o.Logger,
	}
}

func (c *filesystemCollector) Name() string { return "filesystem" }

func (c *filesystemCollector) Collect(ctx context.Context, emit func(Sample)) error {
	mounts, err := osutil.ReadMountInfo(c.procRoot)
	if err != nil {
		return fmt.Errorf("read mountinfo: %w", err)
	}
	for _, m := range osutil.SelectFilesystems(mounts, maxFilesystems) {
		st, err := c.statfs.Statfs(ctx, filepath.Join(c.rootFS, m.MountPoint))
		if err != nil {
			if errors.Is(err, osutil.ErrStatfsTimeout) {
				c.log.Warn("statfs timed out; skipping filesystem", "mountpoint", m.MountPoint, "fstype", m.FSType)
			}
			continue
		}
		if shadowed(m, st) {
			continue
		}
		labels := []string{
			"device", osutil.Clean(m.Source, 256),
			"fstype", osutil.Clean(m.FSType, 64),
			"mountpoint", osutil.Clean(m.MountPoint, 256),
		}
		bs := float64(st.BlockSize)
		emit(sample("stellwerk_filesystem_size_bytes", float64(st.Blocks)*bs, labels...))
		emit(sample("stellwerk_filesystem_free_bytes", float64(st.Bfree)*bs, labels...))
		emit(sample("stellwerk_filesystem_avail_bytes", float64(st.Bavail)*bs, labels...))
		emit(sample("stellwerk_filesystem_files", float64(st.Files), labels...))
		emit(sample("stellwerk_filesystem_files_free", float64(st.Ffree), labels...))
		ro := 0.0
		if m.ReadOnly() {
			ro = 1
		}
		emit(sample("stellwerk_filesystem_readonly", ro, labels...))
	}
	return nil
}

// shadowed reports a mount whose path, in the agent's mount namespace, is
// covered by a tmpfs/ramfs although the host mounts a different filesystem
// there (systemd ProtectHome=yes / InaccessiblePaths=).
func shadowed(m osutil.Mount, st osutil.FSStats) bool {
	if m.FSType == "tmpfs" || m.FSType == "ramfs" {
		return false
	}
	return st.Type == osutil.TmpfsMagic || st.Type == osutil.RamfsMagic
}
