package install

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

func TestScriptAndCommand(t *testing.T) {
	p := Params{AgentEndpoint: "stellwerk.example.internal:8443", CAPEM: pem, CAFingerprint: "AB:CD"}
	s, err := Script(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(s), "CENTRAL='stellwerk.example.internal:8443'") || strings.Contains(string(s), " -k ") {
		t.Fatal("script content unexpected")
	}
	cmd := Command(p, s, "swk_enr_x")
	if !strings.Contains(cmd, "--cacert /tmp/stellwerk-ca.pem") || !strings.Contains(cmd, "--token-stdin") {
		t.Fatalf("command: %s", cmd)
	}
	for _, bad := range []Params{
		{AgentEndpoint: "x'; rm -rf / #:1", CAPEM: pem},
		{AgentEndpoint: "a:1", CAPEM: "not a pem"},
		{AgentEndpoint: "a:1", CAPEM: pem + "CAEOF\nrm -rf /\n"},
	} {
		if _, err := Script(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestHandlerServesOnlyPackages(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stellwerk-agent_latest_amd64.deb"), []byte("deb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.key"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := Handler(func() (Params, error) { return Params{AgentEndpoint: "a:8443", CAPEM: pem}, nil }, dir)
	get := func(p string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		return rec.Code
	}
	if get("/install/packages/stellwerk-agent_latest_amd64.deb") != 200 || get("/install/agent.sh") != 200 || get("/install/ca.pem") != 200 {
		t.Fatal("expected files not served")
	}
	for _, p := range []string{"/install/packages/secret.key", "/install/packages/..%2fsecret.key", "/install/packages/../../etc/passwd"} {
		if c := get(p); c == 200 {
			t.Errorf("%s served", p)
		}
	}
}
