package inventory

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path"
	"sort"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// utmp record layout on x86_64 and aarch64 (glibc, 384 bytes; ut_tv uses
// 32-bit fields for compatibility with 32-bit userspace).
const (
	utmpSize      = 384
	utmpUserProc  = 7
	utmpTypeOff   = 0
	utmpUserOff   = 44
	utmpUserLen   = 32
	utmpTvSecOff  = 340
	lastlogSize   = 292 // int32 ll_time + char[32] + char[256]
	maxLastlogUID = 1 << 24
)

// nonInteractiveShells never allow a login session.
var nonInteractiveShells = map[string]bool{
	"nologin": true, "false": true, "sync": true, "shutdown": true, "halt": true, "true": true,
}

// Users returns the UserAccounts section from /etc/passwd and /etc/group,
// with last logins from /var/log/lastlog and /var/log/wtmp (best effort)
// and sudo rules from the PrivilegedReader when available.
func (c *Collector) Users(ctx context.Context) (*agentv1.InventorySection, error) {
	accts := &agentv1.UserAccounts{}
	passwd, err := osutil.ReadFileLimit(c.path("etc", "passwd"), 16<<20)
	if err != nil {
		return nil, err //nolint:wrapcheck // already descriptive
	}
	entries := osutil.ParsePasswd(passwd, maxUsers)
	lastLogin := c.wtmpLastLogins()
	ll := c.openLastlog()
	defer ll.Close()
	for _, e := range entries {
		u := &agentv1.UserAccount{
			Name:        osutil.Clean(e.Name, maxShort),
			Uid:         e.UID,
			Gid:         e.GID,
			Home:        osutil.Clean(e.Home, maxPath),
			Shell:       osutil.Clean(e.Shell, maxPath),
			Interactive: e.Shell != "" && !nonInteractiveShells[path.Base(e.Shell)],
		}
		u.LastLoginUnix = max(lastLogin[e.Name], ll.get(e.UID))
		accts.Users = append(accts.Users, u)
	}
	sort.SliceStable(accts.Users, func(i, j int) bool { return accts.Users[i].GetUid() < accts.Users[j].GetUid() })
	accts.Users, _ = capBySize(accts.Users, budgetUsers)

	if group, err := osutil.ReadFileLimit(c.path("etc", "group"), 16<<20); err == nil {
		for _, g := range osutil.ParseGroup(group, maxGroups) {
			accts.Groups = append(accts.Groups, &agentv1.UserGroup{
				Name:    osutil.Clean(g.Name, maxShort),
				Gid:     g.GID,
				Members: cleanList(g.Members, maxGroupMembers, maxShort),
			})
		}
		sort.SliceStable(accts.Groups, func(i, j int) bool { return accts.Groups[i].GetGid() < accts.Groups[j].GetGid() })
		accts.Groups, _ = capBySize(accts.Groups, budgetGroups)
	}

	if c.Privileged != nil {
		if rules, err := c.Privileged.SudoRules(ctx); err == nil {
			accts.SudoRules = cleanList(rules, maxSudoRules, maxText)
			total := 0
			for i, r := range accts.SudoRules {
				total += len(r) + 4
				if total > budgetSudo {
					accts.SudoRules = accts.SudoRules[:i]
					break
				}
			}
		} else {
			c.log().Debug("sudo rules unavailable", "error", err)
		}
	}
	return newSection(accts)
}

// wtmpLastLogins returns the latest USER_PROCESS login time per user name
// from the tail of /var/log/wtmp.
func (c *Collector) wtmpLastLogins() map[string]int64 {
	out := make(map[string]int64)
	f, err := osutil.OpenRegular(c.path("var", "log", "wtmp"))
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return out
	}
	size := fi.Size() - fi.Size()%utmpSize
	start := max(0, size-maxWtmpTail)
	start -= start % utmpSize
	buf := make([]byte, size-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return out
	}
	parseWtmp(buf, out)
	return out
}

func parseWtmp(buf []byte, out map[string]int64) {
	for off := 0; off+utmpSize <= len(buf); off += utmpSize {
		rec := buf[off : off+utmpSize]
		if int16(binary.LittleEndian.Uint16(rec[utmpTypeOff:])) != utmpUserProc { //nolint:gosec // bit reinterpretation
			continue
		}
		user := rec[utmpUserOff : utmpUserOff+utmpUserLen]
		if i := bytes.IndexByte(user, 0); i >= 0 {
			user = user[:i]
		}
		if len(user) == 0 {
			continue
		}
		ts := int64(int32(binary.LittleEndian.Uint32(rec[utmpTvSecOff:]))) //nolint:gosec // bit reinterpretation
		if ts > out[string(user)] {
			out[string(user)] = ts
		}
	}
}

// lastlog reads /var/log/lastlog, a sparse file of fixed-size records
// indexed by uid. A nil *lastlog (file unavailable) returns 0 for every uid.
type lastlog struct{ f *os.File }

func (c *Collector) openLastlog() *lastlog {
	f, err := osutil.OpenRegular(c.path("var", "log", "lastlog"))
	if err != nil {
		return nil
	}
	return &lastlog{f: f}
}

func (l *lastlog) get(uid uint32) int64 {
	if l == nil || uid >= maxLastlogUID {
		return 0
	}
	var b [4]byte
	if _, err := l.f.ReadAt(b[:], int64(uid)*lastlogSize); err != nil {
		return 0
	}
	return int64(binary.LittleEndian.Uint32(b[:]))
}

// Close releases the file.
func (l *lastlog) Close() {
	if l != nil {
		_ = l.f.Close()
	}
}
