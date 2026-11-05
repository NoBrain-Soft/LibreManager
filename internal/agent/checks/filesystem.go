package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// --- FS-001 ------------------------------------------------------------------

var systemBinDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"}

const (
	maxFSEntries = 20000
	maxFSDepth   = 3
)

// expectedSetID lists set-uid/set-gid programs shipped by common Debian,
// Ubuntu and RHEL-family packages. Anything else is reported (warn), since
// the agent cannot ask the package database who owns a file.
var expectedSetID = map[string]bool{
	"passwd": true, "su": true, "sudo": true, "sudoedit": true, "mount": true, "umount": true,
	"chsh": true, "chfn": true, "newgrp": true, "sg": true, "gpasswd": true, "chage": true, "expiry": true,
	"pkexec": true, "ping": true, "ping6": true, "arping": true, "traceroute6.iputils": true,
	"fusermount": true, "fusermount3": true, "newuidmap": true, "newgidmap": true,
	"crontab": true, "at": true, "wall": true, "write": true, "write.ul": true, "bsd-write": true,
	"unix_chkpwd": true, "unix2_chkpwd": true, "pam_timestamp_check": true, "pam_extrausers_chkpwd": true,
	"ssh-agent": true, "dotlockfile": true, "mail-lock": true, "mail-unlock": true, "mail-touchlock": true,
	"lockfile": true, "procmail": true, "locate": true, "mlocate": true, "plocate": true, "slocate": true,
	"mount.nfs": true, "mount.nfs4": true, "umount.nfs": true, "umount.nfs4": true, "mount.cifs": true,
	"mount.smb3": true, "mount.ecryptfs_private": true, "ntfs-3g": true, "screen": true,
	"pppd": true, "exim4": true, "postdrop": true, "postqueue": true, "sendmail.sendmail": true,
	"userhelper": true, "usernetctl": true, "netreport": true, "grub2-set-bootflag": true, "staprun": true,
	"Xorg": true, "Xorg.wrap": true, "ksu": true, "doas": true, "lppasswd": true, "seunshare": true,
	"vmware-user-suid-wrapper": true,
}

type fsScan struct {
	ctx        context.Context
	entries    int
	truncated  bool
	seenDirs   map[[2]uint64]bool
	writable   []string
	setID      []string
	unexpected []string
}

func dirKey(fi os.FileInfo) ([2]uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return [2]uint64{}, false
	}
	return [2]uint64{uint64(st.Dev), st.Ino}, true //nolint:unconvert // Dev width differs per arch
}

// walk scans dir (on disk) reported as host path hostDir. Symlinks are
// never followed; directories already visited (e.g. /bin -> /usr/bin) are
// skipped.
func (s *fsScan) walk(dir, hostDir string, depth int) {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return
	}
	if k, ok := dirKey(fi); ok {
		if s.seenDirs[k] {
			return
		}
		s.seenDirs[k] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if s.entries >= maxFSEntries {
			s.truncated = true
			return
		}
		s.entries++
		if s.entries%1024 == 0 && s.ctx.Err() != nil {
			s.truncated = true
			return
		}
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		p := path.Join(hostDir, e.Name())
		mode := info.Mode()
		if mode.Perm()&0o002 != 0 {
			s.writable = append(s.writable, p)
		}
		if mode.IsDir() {
			if depth < maxFSDepth {
				s.walk(filepath.Join(dir, e.Name()), p, depth+1)
			}
			continue
		}
		if mode.IsRegular() && mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
			s.setID = append(s.setID, p)
			if !expectedSetID[e.Name()] {
				s.unexpected = append(s.unexpected, p)
			}
		}
	}
}

// examples lists the first paths (sorted) that fit into one evidence value.
func examples(paths []string) string {
	slices.Sort(paths)
	return joinCapped(paths)
}

func checkFilePermissions(ctx context.Context, r *runState) result {
	s := &fsScan{ctx: ctx, seenDirs: map[[2]uint64]bool{}}
	scanned := 0
	for _, d := range systemBinDirs {
		if isDir(r.rootPath(d)) {
			scanned++
			s.walk(r.rootPath(d), d, 0)
		}
	}
	if scanned == 0 {
		return errResult("no system binary directory found", nil)
	}
	kvs := []string{
		"world_writable", fmt.Sprint(len(s.writable)),
		"setuid_setgid", fmt.Sprint(len(s.setID)),
		"unexpected_setuid_setgid", fmt.Sprint(len(s.unexpected)),
		"entries_scanned", fmt.Sprint(s.entries),
	}
	if s.truncated {
		kvs = append(kvs, "truncated", "true")
	}
	if len(s.writable) > 0 {
		kvs = append(kvs, "world_writable_paths", examples(s.writable))
	}
	if len(s.unexpected) > 0 {
		kvs = append(kvs, "unexpected_setuid_setgid_paths", examples(s.unexpected))
	}
	switch {
	case len(s.writable) > 0:
		return fail(plural(len(s.writable), "world-writable entry", "world-writable entries")+" in system binary directories", kvs...)
	case len(s.unexpected) > 0:
		return warn(plural(len(s.unexpected), "unexpected set-uid/set-gid program", "unexpected set-uid/set-gid programs")+" in system binary directories", kvs...)
	}
	return pass("no world-writable entries or unexpected set-uid/set-gid programs in system binary directories", kvs...)
}

// --- FS-002 ------------------------------------------------------------------

type mountEntry struct {
	mountPoint string
	options    []string
	fstype     string
}

// unescapeMount decodes the octal escapes (\040 etc.) of mountinfo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseMountinfo parses /proc/<pid>/mountinfo (proc(5)).
func parseMountinfo(data []byte) []mountEntry {
	var out []mountEntry
	eachLine(data, func(l string) bool {
		f := strings.Fields(l)
		sep := slices.Index(f, "-")
		if len(f) < 7 || sep < 6 || sep+1 >= len(f) {
			return true
		}
		out = append(out, mountEntry{
			mountPoint: unescapeMount(f[4]),
			options:    strings.Split(f[5], ","),
			fstype:     f[sep+1],
		})
		return len(out) < 100000
	})
	return out
}

// lastMount returns the topmost mount at mp.
func lastMount(ms []mountEntry, mp string) (mountEntry, bool) {
	for i := len(ms) - 1; i >= 0; i-- {
		if ms[i].mountPoint == mp {
			return ms[i], true
		}
	}
	return mountEntry{}, false
}

func checkTmpMounts(_ context.Context, r *runState) result {
	// The agent runs with PrivateTmp=yes, so its own mount namespace has
	// private /tmp bind mounts; init's view (pid 1) is the host's.
	var data []byte
	source := ""
	var errs []error
	for _, p := range []string{"1/mountinfo", "self/mountinfo"} {
		d, err := readCapped(r.procPath(p), 16<<20)
		if err == nil {
			data, source = d, "/proc/"+p
			break
		}
		errs = append(errs, err)
	}
	if data == nil {
		return errResult("cannot read mountinfo", errors.Join(errs...))
	}
	ms := parseMountinfo(data)
	kvs := []string{"source", source}
	var missing, notSeparate []string
	for _, mp := range []string{"/tmp", "/var/tmp"} {
		m, ok := lastMount(ms, mp)
		if !ok {
			notSeparate = append(notSeparate, mp)
			kvs = append(kvs, mp, "not a separate mount")
			continue
		}
		var lacks []string
		for _, want := range []string{"nodev", "nosuid"} {
			if !slices.Contains(m.options, want) {
				lacks = append(lacks, want)
			}
		}
		kvs = append(kvs, mp, m.fstype+" "+strings.Join(m.options, ","))
		if len(lacks) > 0 {
			missing = append(missing, mp+" lacks "+strings.Join(lacks, ","))
		}
	}
	switch {
	case len(missing) > 0:
		return fail(strings.Join(missing, "; "), kvs...)
	case len(notSeparate) > 0:
		return warn(strings.Join(notSeparate, " and ")+" not mounted separately (cannot enforce nodev,nosuid)", kvs...)
	}
	return pass("/tmp and /var/tmp are mounted nodev,nosuid", kvs...)
}
