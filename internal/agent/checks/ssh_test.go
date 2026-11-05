package checks

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

var sshIDs = []string{"SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005", "SSH-006", "SSH-007", "SSH-008", "SSH-009", "SSH-010"}

func allStatus(st agentv1.CheckStatus) map[string]agentv1.CheckStatus {
	m := map[string]agentv1.CheckStatus{}
	for _, id := range sshIDs {
		m[id] = st
	}
	return m
}

func TestSSHChecks(t *testing.T) {
	debian := td(t, "root/debian")
	empty := t.TempDir()
	legacy := allStatus(PASS)
	legacy["SSH-001"] = WARN
	tests := []struct {
		name string
		root string
		priv Privileged
		want map[string]agentv1.CheckStatus
	}{
		{"hardened", debian, &fakePriv{sshd: sshdFixture(t, "hardened.txt")}, allStatus(PASS)},
		{"weak", debian, &fakePriv{sshd: sshdFixture(t, "weak.txt")}, allStatus(FAIL)},
		{"legacy openssh", debian, &fakePriv{sshd: sshdFixture(t, "legacy.txt")}, legacy},
		{"helper unavailable", debian, nil, allStatus(ERROR)},
		{"helper error", debian, &fakePriv{sshdErr: errors.New("helper error: policy: denied")}, allStatus(ERROR)},
		{"sshd missing per helper", debian, &fakePriv{sshdErr: fmt.Errorf("%w: sshd", ErrNotInstalled)}, allStatus(NA)},
		{"sshd missing, no helper", empty, nil, allStatus(NA)},
		{"sshd missing, helper fails", empty, &fakePriv{sshdErr: errors.New("exit 255")}, allStatus(NA)},
		{"keys missing", debian, &fakePriv{sshd: map[string]string{"port": "22"}}, allStatus(ERROR)},
		{"empty config", debian, &fakePriv{sshd: map[string]string{}}, allStatus(ERROR)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := runIDs(t, Env{Root: tc.root, Privileged: tc.priv}, sshIDs...)
			for id, want := range tc.want {
				expectStatus(t, res[id], want)
				assertNoSecrets(t, res[id])
			}
		})
	}
}

func TestSSHEvidence(t *testing.T) {
	res := runIDs(t, Env{Root: td(t, "root/debian"), Privileged: &fakePriv{sshd: sshdFixture(t, "weak.txt")}}, sshIDs...)
	expectEvidence(t, res["SSH-001"], "permitrootlogin", "yes")
	expectEvidence(t, res["SSH-006"], "weak", "aes128-cbc, 3des-cbc, arcfour256")
	expectEvidence(t, res["SSH-007"], "weak", "hmac-sha1, hmac-md5-etm@openssh.com, hmac-sha1-96")
	expectEvidence(t, res["SSH-008"], "weak", "diffie-hellman-group14-sha1, diffie-hellman-group1-sha1, diffie-hellman-group-exchange-sha1")
	expectEvidence(t, res["SSH-009"], "logingracetime", "120")
	if w := res["SSH-007"].GetEvidence()["weak"]; strings.Contains(w, "hmac-sha2-256") || strings.Contains(w, "umac-64") {
		t.Fatalf("strong MACs reported as weak: %q", w)
	}
}

func TestSSHEvaluators(t *testing.T) {
	tests := []struct {
		name string
		eval func(map[string]string) result
		cfg  map[string]string
		want agentv1.CheckStatus
	}{
		{"root no", evalPermitRootLogin, map[string]string{"permitrootlogin": "no"}, PASS},
		{"root keys", evalPermitRootLogin, map[string]string{"permitrootlogin": "prohibit-password"}, WARN},
		{"root forced", evalPermitRootLogin, map[string]string{"permitrootlogin": "forced-commands-only"}, WARN},
		{"root yes", evalPermitRootLogin, map[string]string{"permitrootlogin": "yes"}, FAIL},
		{"root odd", evalPermitRootLogin, map[string]string{"permitrootlogin": "maybe"}, WARN},
		{"root missing", evalPermitRootLogin, map[string]string{}, ERROR},
		{"kbd fallback", sshNo("kbd", "kbdinteractiveauthentication", "challengeresponseauthentication"), map[string]string{"challengeresponseauthentication": "yes"}, FAIL},
		{"kbd preferred", sshNo("kbd", "kbdinteractiveauthentication", "challengeresponseauthentication"), map[string]string{"kbdinteractiveauthentication": "no", "challengeresponseauthentication": "yes"}, PASS},
		{"bool odd", sshNo("x", "x11forwarding"), map[string]string{"x11forwarding": "sometimes"}, WARN},
		{"tries 4", evalMaxAuthTries, map[string]string{"maxauthtries": "4"}, PASS},
		{"tries 5", evalMaxAuthTries, map[string]string{"maxauthtries": "5"}, FAIL},
		{"tries junk", evalMaxAuthTries, map[string]string{"maxauthtries": "four"}, WARN},
		{"tries negative", evalMaxAuthTries, map[string]string{"maxauthtries": "-1"}, WARN},
		{"grace 60", evalLoginGraceTime, map[string]string{"logingracetime": "60"}, PASS},
		{"grace 1m", evalLoginGraceTime, map[string]string{"logingracetime": "1m"}, PASS},
		{"grace 61", evalLoginGraceTime, map[string]string{"logingracetime": "61"}, FAIL},
		{"grace 1m30s", evalLoginGraceTime, map[string]string{"logingracetime": "1m30s"}, FAIL},
		{"grace unlimited", evalLoginGraceTime, map[string]string{"logingracetime": "0"}, FAIL},
		{"grace junk", evalLoginGraceTime, map[string]string{"logingracetime": "soon"}, WARN},
		{"ciphers empty", sshAlgorithms("ciphers", "cipher", weakCipher), map[string]string{"ciphers": " , "}, ERROR},
		{"ciphers none", sshAlgorithms("ciphers", "cipher", weakCipher), map[string]string{"ciphers": "none"}, FAIL},
		{"ciphers upper", sshAlgorithms("ciphers", "cipher", weakCipher), map[string]string{"ciphers": "AES256-CBC"}, FAIL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.eval(tc.cfg); got.status != tc.want {
				t.Fatalf("status %v, want %v (%q)", got.status, tc.want, got.summary)
			}
		})
	}
}

func TestWeakAlgorithms(t *testing.T) {
	for _, tc := range []struct {
		alg  string
		fn   func(string) bool
		weak bool
	}{
		{"chacha20-poly1305@openssh.com", weakCipher, false},
		{"aes256-gcm@openssh.com", weakCipher, false},
		{"aes128-ctr", weakCipher, false},
		{"aes256-cbc", weakCipher, true},
		{"rijndael-cbc@lysator.liu.se", weakCipher, true},
		{"arcfour", weakCipher, true},
		{"blowfish-cbc", weakCipher, true},
		{"cast128-cbc", weakCipher, true},
		{"3des-cbc", weakCipher, true},
		{"hmac-sha2-256-etm@openssh.com", weakMAC, false},
		{"hmac-sha2-512", weakMAC, false},
		{"umac-128-etm@openssh.com", weakMAC, false},
		{"hmac-sha1-etm@openssh.com", weakMAC, false},
		{"hmac-sha1", weakMAC, true},
		{"hmac-sha1-96", weakMAC, true},
		{"hmac-sha1-96-etm@openssh.com", weakMAC, true},
		{"hmac-md5", weakMAC, true},
		{"hmac-md5-etm@openssh.com", weakMAC, true},
		{"hmac-ripemd160", weakMAC, true},
		{"curve25519-sha256", weakKex, false},
		{"sntrup761x25519-sha512@openssh.com", weakKex, false},
		{"mlkem768x25519-sha256", weakKex, false},
		{"ecdh-sha2-nistp256", weakKex, false},
		{"diffie-hellman-group14-sha256", weakKex, false},
		{"diffie-hellman-group-exchange-sha256", weakKex, false},
		{"diffie-hellman-group1-sha1", weakKex, true},
		{"diffie-hellman-group14-sha1", weakKex, true},
		{"diffie-hellman-group-exchange-sha1", weakKex, true},
		{"gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==", weakKex, true},
		{"rsa1024-sha1", weakKex, true},
	} {
		if got := tc.fn(tc.alg); got != tc.weak {
			t.Errorf("%s: weak=%v, want %v", tc.alg, got, tc.weak)
		}
	}
}

func TestParseSSHDuration(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
		ok   bool
	}{
		{"0", 0, true}, {"120", 120, true}, {"2m", 120, true}, {"1h30m", 5400, true}, {"1d", 86400, true},
		{"1w", 604800, true}, {"10s", 10, true}, {"1M5", 65, true},
		{"", 0, false}, {"m", 0, false}, {"5x", 0, false}, {"-1", 0, false}, {"99999999999", 0, false}, {"9999999w", 0, false},
	} {
		got, err := parseSSHDuration(tc.in)
		if (err == nil) != tc.ok || (tc.ok && got != tc.want) {
			t.Errorf("%q: %d, %v; want %d ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

func TestParseSSHDConfig(t *testing.T) {
	cfg := ParseSSHDConfig([]byte("PermitRootLogin   no\nciphers a,b\n\n# comment\nhostkey /a\nhostkey /b\nport\n"))
	if cfg["permitrootlogin"] != "no" || cfg["ciphers"] != "a,b" || cfg["hostkey"] != "/a" || cfg["port"] != "" {
		t.Fatalf("parsed %v", cfg)
	}
	if _, ok := cfg["# comment"]; ok {
		t.Fatal("comment parsed as key")
	}
}
