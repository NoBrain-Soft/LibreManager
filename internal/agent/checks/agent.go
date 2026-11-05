package checks

import (
	"context"
	"strconv"
	"strings"
)

// semver is a parsed "vMAJOR.MINOR.PATCH[-pre][+build]".
type semver struct {
	nums [3]int64
	pre  []string
}

func parseSemver(s string) (semver, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if core == "" || len(parts) > 3 {
		return semver{}, false
	}
	var v semver
	for i, p := range parts {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil || n < 0 {
			return semver{}, false
		}
		v.nums[i] = n
	}
	if hasPre {
		if pre == "" {
			return semver{}, false
		}
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compareSemver orders versions like semver 2.0: a release sorts after its
// pre-releases; numeric identifiers sort before alphanumeric ones.
func compareSemver(a, b semver) int {
	for i := range a.nums {
		if c := cmpInt(a.nums[i], b.nums[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		na, ea := strconv.ParseInt(a.pre[i], 10, 64)
		nb, eb := strconv.ParseInt(b.pre[i], 10, 64)
		var c int
		switch {
		case ea == nil && eb == nil:
			c = cmpInt(na, nb)
		case ea == nil:
			c = -1
		case eb == nil:
			c = 1
		default:
			c = strings.Compare(a.pre[i], b.pre[i])
		}
		if c != 0 {
			return c
		}
	}
	return cmpInt(int64(len(a.pre)), int64(len(b.pre)))
}

func checkAgentVersion(_ context.Context, r *runState) result {
	cur, latest := r.env.AgentVersion, r.env.LatestAgentVersion
	if latest == "" {
		return na("latest agent version unknown", "agent_version", cur)
	}
	kvs := []string{"agent_version", cur, "latest_version", latest}
	c, ok1 := parseSemver(cur)
	l, ok2 := parseSemver(latest)
	if !ok1 || !ok2 {
		return na("agent version is not comparable (development build?)", kvs...)
	}
	if compareSemver(c, l) < 0 {
		return warn("agent "+cur+" is older than the latest release "+latest, kvs...)
	}
	return pass("agent is up to date", kvs...)
}
