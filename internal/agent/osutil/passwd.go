package osutil

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// PasswdEntry is one /etc/passwd line.
type PasswdEntry struct {
	Name  string
	UID   uint32
	GID   uint32
	Gecos string
	Home  string
	Shell string
}

// GroupEntry is one /etc/group line.
type GroupEntry struct {
	Name    string
	GID     uint32
	Members []string
}

// ParsePasswd parses passwd(5) content, skipping comments, NIS compat lines
// ("+"/"-") and malformed entries. At most max entries are returned
// (max <= 0: no limit).
func ParsePasswd(data []byte, max int) []PasswdEntry {
	var out []PasswdEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1024), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if skipAccountLine(line) {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 7 || f[0] == "" {
			continue
		}
		uid, err1 := strconv.ParseUint(f[2], 10, 32)
		gid, err2 := strconv.ParseUint(f[3], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, PasswdEntry{Name: f[0], UID: uint32(uid), GID: uint32(gid), Gecos: f[4], Home: f[5], Shell: f[6]})
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}

// ParseGroup parses group(5) content like ParsePasswd.
func ParseGroup(data []byte, max int) []GroupEntry {
	var out []GroupEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if skipAccountLine(line) {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 4 || f[0] == "" {
			continue
		}
		gid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			continue
		}
		g := GroupEntry{Name: f[0], GID: uint32(gid)}
		if f[3] != "" {
			for m := range strings.SplitSeq(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					g.Members = append(g.Members, m)
				}
			}
		}
		out = append(out, g)
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}

func skipAccountLine(line string) bool {
	return line == "" || line[0] == '#' || line[0] == '+' || line[0] == '-'
}
