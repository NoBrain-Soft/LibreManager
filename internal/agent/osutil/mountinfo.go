package osutil

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// Mount is one line of /proc/<pid>/mountinfo (proc(5)).
type Mount struct {
	ID, Parent   int
	Major, Minor uint32
	// Root is the path within the filesystem that forms the mount's root
	// (not "/" for bind mounts of subdirectories and btrfs subvolumes).
	Root       string
	MountPoint string
	// Options are the per-mount options (ro, nosuid, ...).
	Options []string
	FSType  string
	Source  string
	// SuperOptions are the per-superblock options.
	SuperOptions []string
}

// ReadOnly reports whether the mount or its superblock is read-only.
func (m Mount) ReadOnly() bool {
	return hasOpt(m.Options, "ro") || hasOpt(m.SuperOptions, "ro")
}

// Device returns "major:minor".
func (m Mount) Device() string {
	return strconv.FormatUint(uint64(m.Major), 10) + ":" + strconv.FormatUint(uint64(m.Minor), 10)
}

func hasOpt(opts []string, want string) bool {
	for _, o := range opts {
		if o == want {
			return true
		}
	}
	return false
}

// Limits for mountinfo parsing. Container hosts can have thousands of mounts.
const (
	MaxMountInfoBytes = 8 << 20
	maxMounts         = 20000
)

// ReadMountInfo reads the mount table of PID 1 (the host's view, with the
// real ro/rw flags even when the agent runs under ProtectSystem=strict) and
// falls back to the agent's own table when /proc is mounted with hidepid.
func ReadMountInfo(procRoot string) ([]Mount, error) {
	var firstErr error
	for _, p := range []string{"1/mountinfo", "self/mountinfo"} {
		data, err := ReadFileLimit(filepath.Join(procRoot, p), MaxMountInfoBytes)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		mounts, err := ParseMountInfo(data)
		if err != nil {
			return nil, err
		}
		if len(mounts) > 0 {
			return mounts, nil
		}
	}
	if firstErr == nil {
		firstErr = errors.New("osutil: empty mountinfo")
	}
	return nil, firstErr
}

// ParseMountInfo parses mountinfo content. Malformed lines are skipped.
func ParseMountInfo(data []byte) ([]Mount, error) {
	var out []Mount
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		m, ok := parseMountLine(sc.Text())
		if !ok {
			continue
		}
		out = append(out, m)
		if len(out) >= maxMounts {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("osutil: parse mountinfo: %w", err)
	}
	return out, nil
}

func parseMountLine(line string) (Mount, bool) {
	// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return Mount{}, false
	}
	sep := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			sep = i
			break
		}
	}
	if sep < 0 || sep+3 > len(fields) {
		return Mount{}, false
	}
	id, err1 := strconv.Atoi(fields[0])
	parent, err2 := strconv.Atoi(fields[1])
	majStr, minStr, ok := strings.Cut(fields[2], ":")
	if err1 != nil || err2 != nil || !ok {
		return Mount{}, false
	}
	maj, err3 := strconv.ParseUint(majStr, 10, 32)
	minor, err4 := strconv.ParseUint(minStr, 10, 32)
	if err3 != nil || err4 != nil {
		return Mount{}, false
	}
	m := Mount{
		ID:         id,
		Parent:     parent,
		Major:      uint32(maj),
		Minor:      uint32(minor),
		Root:       UnescapeMount(fields[3]),
		MountPoint: UnescapeMount(fields[4]),
		Options:    strings.Split(fields[5], ","),
		FSType:     UnescapeMount(fields[sep+1]),
		Source:     UnescapeMount(fields[sep+2]),
	}
	if sep+3 < len(fields) {
		m.SuperOptions = strings.Split(fields[sep+3], ",")
	}
	return m, true
}

// UnescapeMount decodes the octal escapes (\040 space, \011 tab, \012
// newline, \134 backslash) the kernel uses in mount tables.
func UnescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && isOctal(s, i+1) {
			v, _ := strconv.ParseUint(s[i+1:i+4], 8, 8)
			b.WriteByte(byte(v))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(s string, i int) bool {
	if i+3 > len(s) {
		return false
	}
	for j := i; j < i+3; j++ {
		if s[j] < '0' || s[j] > '7' {
			return false
		}
	}
	// \400 and above do not fit in a byte.
	return s[i] <= '3'
}

// pseudoFS are filesystem types that never hold user data worth reporting.
var pseudoFS = map[string]bool{
	"autofs": true, "binfmt_misc": true, "bpf": true, "cgroup": true, "cgroup2": true,
	"configfs": true, "debugfs": true, "devpts": true, "devtmpfs": true, "efivarfs": true,
	"fusectl": true, "hugetlbfs": true, "mqueue": true, "nsfs": true, "overlay": true,
	"aufs": true, "proc": true, "procfs": true, "pstore": true, "ramfs": true,
	"rpc_pipefs": true, "securityfs": true, "selinuxfs": true, "squashfs": true,
	"erofs": true, "sysfs": true, "tracefs": true, "iso9660": true, "udf": true,
	"nfsd": true, "shiftfs": true, "none": true, "rootfs": true,
	"fuse.lxcfs": true, "fuse.gvfsd-fuse": true, "fuse.portal": true,
	"fuse.snapfuse": true, "fuse.xdg-document-portal": true,
}

// tmpfsKeep are the tmpfs mount points worth monitoring (a full /run or
// /dev/shm breaks services). Other tmpfs instances (per-user runtime dirs,
// credentials, cgroup roots) are ephemeral noise.
var tmpfsKeep = map[string]bool{"/dev/shm": true, "/run": true, "/tmp": true, "/var/tmp": true}

// excludedMountPrefixes are pseudo or container-internal trees.
var excludedMountPrefixes = []string{
	"/proc", "/sys", "/dev", "/run/credentials", "/run/user", "/run/netns",
	"/run/containerd", "/run/docker", "/var/lib/docker", "/var/lib/containers",
	"/var/lib/kubelet", "/var/lib/lxcfs", "/snap",
}

// IsPseudoFS reports whether fstype is a pseudo filesystem type.
func IsPseudoFS(fstype string) bool { return pseudoFS[fstype] }

// RealFilesystem reports whether a mount should be reported as a filesystem
// (metrics and inventory): no pseudo filesystems, no container-internal
// trees, and tmpfs only at a few well-known locations.
func RealFilesystem(m Mount) bool {
	if m.FSType == "" || pseudoFS[m.FSType] {
		return false
	}
	if m.FSType == "tmpfs" {
		return tmpfsKeep[m.MountPoint]
	}
	if m.MountPoint == "/dev/shm" {
		return true
	}
	for _, p := range excludedMountPrefixes {
		if m.MountPoint == p || strings.HasPrefix(m.MountPoint, p+"/") {
			return false
		}
	}
	return strings.HasPrefix(m.MountPoint, "/")
}

// SelectFilesystems filters mounts with RealFilesystem and deduplicates bind
// mounts (and btrfs subvolumes of one filesystem) by device number, keeping
// the mount whose root is "/" or else the shortest mount point. At most max
// entries are returned (max <= 0: no limit), in mount table order.
func SelectFilesystems(mounts []Mount, max int) []Mount {
	best := make(map[[2]uint32]int)
	for i, m := range mounts {
		if !RealFilesystem(m) {
			continue
		}
		key := [2]uint32{m.Major, m.Minor}
		j, ok := best[key]
		if !ok || better(m, mounts[j]) {
			best[key] = i
		}
	}
	out := make([]Mount, 0, len(best))
	for i, m := range mounts {
		if j, ok := best[[2]uint32{m.Major, m.Minor}]; ok && j == i {
			out = append(out, m)
			if max > 0 && len(out) >= max {
				break
			}
		}
	}
	return out
}

func better(a, b Mount) bool {
	if (a.Root == "/") != (b.Root == "/") {
		return a.Root == "/"
	}
	return len(a.MountPoint) < len(b.MountPoint)
}
