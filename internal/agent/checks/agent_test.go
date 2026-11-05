package checks

import (
	"testing"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

func TestAgentVersion(t *testing.T) {
	for _, tc := range []struct {
		cur, latest string
		want        agentv1.CheckStatus
	}{
		{"v0.3.0", "", NA},
		{"dev", "v0.3.0", NA},
		{"", "v0.3.0", NA},
		{"v0.3.0", "garbage", NA},
		{"v0.2.9", "v0.3.0", WARN},
		{"0.3.0", "v0.3.0", PASS},
		{"v0.4.0", "v0.3.0", PASS},
		{"v0.3.0-rc.1", "v0.3.0", WARN},
		{"v0.3.0+build.5", "v0.3.0", PASS},
		{"v1.10.0", "v1.9.9", PASS},
		{"v1", "v1.0.1", WARN},
	} {
		r := runCheck(t, Env{AgentVersion: tc.cur, LatestAgentVersion: tc.latest}, "AGT-001")
		if r.GetStatus() != tc.want {
			t.Errorf("%q vs %q: %s, want %s", tc.cur, tc.latest, r.GetStatus(), tc.want)
		}
	}
}

func TestCompareSemver(t *testing.T) {
	order := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0"}
	for i := 0; i+1 < len(order); i++ {
		a, ok1 := parseSemver(order[i])
		b, ok2 := parseSemver(order[i+1])
		if !ok1 || !ok2 {
			t.Fatalf("parse %q/%q", order[i], order[i+1])
		}
		if compareSemver(a, b) >= 0 || compareSemver(b, a) <= 0 || compareSemver(a, a) != 0 {
			t.Errorf("%s < %s violated", order[i], order[i+1])
		}
	}
	for _, bad := range []string{"", "v", "1.2.3.4", "1.x", "-1.0.0", "1.0.0-", "dev"} {
		if _, ok := parseSemver(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}
