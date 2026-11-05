package api_test

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/common/envelope"
	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/secretbox"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	centralv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/central/v1"
	"github.com/nobrain-soft/libremanager/internal/server/api"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/config"
	"github.com/nobrain-soft/libremanager/internal/server/signer"
	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
	"github.com/nobrain-soft/libremanager/internal/server/store/storetest"
)

// signerAdapter calls the in-process signer service as a client.
type signerAdapter struct{ svc *signer.Service }

func (a signerAdapter) SignJobs(ctx context.Context, in *centralv1.SignJobsRequest, _ ...grpc.CallOption) (*centralv1.SignJobsResponse, error) {
	return a.svc.SignJobs(ctx, in)
}

func (a signerAdapter) ListKeys(ctx context.Context, in *centralv1.ListKeysRequest, _ ...grpc.CallOption) (*centralv1.ListKeysResponse, error) {
	return a.svc.ListKeys(ctx, in)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type harness struct {
	t     *testing.T
	st    *store.Store
	srv   *httptest.Server
	clock *clock
	keys  envelope.KeyRing
	url   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st := storetest.New(t)
	h := &harness{t: t, st: st, clock: &clock{t: time.Now()}}
	mk, _ := secretbox.NewKey()
	dir := t.TempDir()
	pub, err := signer.GenerateKeyFile(mk, dir+"/jobkey")
	if err != nil {
		t.Fatal(err)
	}
	js, _ := signer.LoadKeyFile(mk, dir+"/jobkey")
	svc, err := signer.NewService(js, dir+"/sig.log")
	if err != nil {
		t.Fatal(err)
	}
	h.keys = envelope.KeyRing{}
	_, _ = h.keys.Add(pub)

	var srvURL string
	cfg := &config.Config{AgentEndpoint: "gw.example.internal:8443", DataDir: dir, VictoriaMetricsURL: "http://127.0.0.1:1"}
	apiKey, _ := secretbox.NewKey()
	var s *api.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.Handler().ServeHTTP(w, r) })
	h.srv = httptest.NewTLSServer(handler)
	t.Cleanup(h.srv.Close)
	srvURL = h.srv.URL
	cfg.PublicURL = srvURL
	s, err = api.New(api.Deps{
		Cfg: cfg, Store: st, Audit: audit.New(st), MasterKey: apiKey, Pepper: auth.Pepper(make([]byte, 32)),
		WebhookToken: "hook-token", Signer: signerAdapter{svc}, CAPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		CAFP: "AB:CD", Now: h.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.url = srvURL
	return h
}

type client struct {
	h    *harness
	c    *http.Client
	csrf string
}

func (h *harness) client() *client {
	jar, _ := cookiejar.New(nil)
	c := h.srv.Client()
	c.Jar = jar
	return &client{h: h, c: c}
}

func (c *client) do(method, path string, body any, out any) (int, map[string]any) {
	c.h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.h.url+"/api/v1"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", c.h.url)
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var generic map[string]any
	_ = json.Unmarshal(raw, &generic)
	if out != nil {
		_ = json.Unmarshal(raw, out)
	}
	return resp.StatusCode, generic
}

func (c *client) refreshCSRF() {
	var s struct {
		CSRF  string `json:"csrf_token"`
		State string `json:"state"`
	}
	if code, _ := c.do("GET", "/auth/session", nil, &s); code == 200 {
		c.csrf = s.CSRF
	}
}

func errCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

// createUser inserts a user with a password and optional TOTP secret and
// binds the given role (optionally scoped).
func (h *harness) createUser(name, password, role string, group *uuid.UUID, totp []byte) uuid.UUID {
	h.t.Helper()
	ctx := context.Background()
	hash, _ := auth.HashPassword(password)
	u, err := h.st.Q.CreateUser(ctx, db.CreateUserParams{ID: ids.NewUUID(), Username: name, PasswordHash: &hash, MfaRequired: true})
	if err != nil {
		h.t.Fatal(err)
	}
	r, _ := h.st.Q.GetRoleByName(ctx, role)
	if err := h.st.Q.CreateRoleBinding(ctx, db.CreateRoleBindingParams{ID: ids.NewUUID(), UserID: u.ID, RoleID: r.ID, HostGroupID: group}); err != nil {
		h.t.Fatal(err)
	}
	return u.ID
}

func (h *harness) loginWithTOTPEnrollment(c *client, user, pw string) []byte {
	h.t.Helper()
	var lr struct{ State string }
	code, body := c.do("POST", "/auth/login", map[string]string{"username": user, "password": pw}, &lr)
	if code != 200 || lr.State != "pending_mfa_enrollment" {
		h.t.Fatalf("login: %d %v %+v", code, body, lr)
	}
	c.refreshCSRF()
	var en struct{ Secret string }
	if code, body := c.do("POST", "/auth/totp/enroll", nil, &en); code != 200 {
		h.t.Fatalf("enroll: %d %v", code, body)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(en.Secret)
	if err != nil {
		h.t.Fatal(err)
	}
	code, body = c.do("POST", "/auth/totp/confirm", map[string]string{"code": auth.TOTPCode(secret, h.clock.Now())}, &lr)
	if code != 200 || lr.State != "active" {
		h.t.Fatalf("confirm: %d %v", code, body)
	}
	c.refreshCSRF()
	return secret
}

func TestLoginStateMachineAndCSRF(t *testing.T) {
	h := newHarness(t)
	// Break-glass style user: one-time password + forced change.
	ctx := context.Background()
	hash, _ := auth.HashPassword("one-time-Passw0rd-x")
	u, _ := h.st.Q.CreateUser(ctx, db.CreateUserParams{ID: ids.NewUUID(), Username: "admin", PasswordHash: &hash, PasswordChangeRequired: true, MfaRequired: true})
	r, _ := h.st.Q.GetRoleByName(ctx, "admin")
	_ = h.st.Q.CreateRoleBinding(ctx, db.CreateRoleBindingParams{ID: ids.NewUUID(), UserID: u.ID, RoleID: r.ID})

	c := h.client()
	if code, _ := c.do("GET", "/hosts", nil, nil); code != 401 {
		t.Fatalf("unauthenticated hosts: %d", code)
	}
	var lr struct{ State string }
	if code, _ := c.do("POST", "/auth/login", map[string]string{"username": "admin", "password": "wrong"}, nil); code != 401 {
		t.Fatalf("wrong password: %d", code)
	}
	if code, _ := c.do("POST", "/auth/login", map[string]string{"username": "nobody", "password": "x"}, nil); code != 401 {
		t.Fatalf("unknown user: %d", code)
	}
	if code, _ := c.do("POST", "/auth/login", map[string]string{"username": "admin", "password": "one-time-Passw0rd-x"}, &lr); code != 200 || lr.State != "pending_password_change" {
		t.Fatalf("login: %d %+v", code, lr)
	}
	// Pending session cannot use the API.
	if code, _ := c.do("GET", "/hosts", nil, nil); code != 401 {
		t.Fatalf("pending session reached /hosts: %d", code)
	}
	// State-changing call without CSRF token is rejected.
	if code, _ := c.do("POST", "/auth/password", map[string]string{"current_password": "one-time-Passw0rd-x", "new_password": "a-much-better-secret-42"}, nil); code != 403 {
		t.Fatalf("no CSRF: %d", code)
	}
	c.refreshCSRF()
	if code, b := c.do("POST", "/auth/password", map[string]string{"current_password": "one-time-Passw0rd-x", "new_password": "short"}, nil); code != 400 {
		t.Fatalf("weak password: %d %v", code, b)
	}
	if code, b := c.do("POST", "/auth/password", map[string]string{"current_password": "one-time-Passw0rd-x", "new_password": "a-much-better-secret-42"}, &lr); code != 200 || lr.State != "pending_mfa_enrollment" {
		t.Fatalf("change password: %d %v", code, b)
	}
	c.refreshCSRF()
	var en struct{ Secret string }
	if code, _ := c.do("POST", "/auth/totp/enroll", nil, &en); code != 200 {
		t.Fatalf("totp enroll: %d", code)
	}
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(en.Secret)
	if code, _ := c.do("POST", "/auth/totp/confirm", map[string]string{"code": "000000"}, nil); code != 401 {
		t.Fatalf("bad totp: %d", code)
	}
	if code, _ := c.do("POST", "/auth/totp/confirm", map[string]string{"code": auth.TOTPCode(secret, h.clock.Now())}, &lr); code != 200 || lr.State != "active" {
		t.Fatalf("totp confirm: %d %+v", code, lr)
	}
	c.refreshCSRF()
	if code, _ := c.do("GET", "/hosts", nil, nil); code != 200 {
		t.Fatalf("active session hosts: %d", code)
	}

	// Cross-origin state change is rejected even with a valid CSRF token.
	req, _ := http.NewRequest("POST", h.url+"/api/v1/host-groups", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("X-CSRF-Token", c.csrf)
	resp, err := c.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-origin POST: %d", resp.StatusCode)
	}

	// Logout, then login requires MFA (pending_mfa), replayed code rejected.
	if code, _ := c.do("POST", "/auth/logout", nil, nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	c2 := h.client()
	if code, _ := c2.do("POST", "/auth/login", map[string]string{"username": "admin", "password": "a-much-better-secret-42"}, &lr); code != 200 || lr.State != "pending_mfa" {
		t.Fatalf("second login: %d %+v", code, lr)
	}
	c2.refreshCSRF()
	usedCode := auth.TOTPCode(secret, h.clock.Now())
	if code, _ := c2.do("POST", "/auth/mfa/totp", map[string]string{"code": usedCode}, nil); code != 401 {
		t.Fatalf("replayed TOTP code accepted: %d", code)
	}
	h.clock.Advance(31 * time.Second)
	if code, _ := c2.do("POST", "/auth/mfa/totp", map[string]string{"code": auth.TOTPCode(secret, h.clock.Now())}, &lr); code != 200 || lr.State != "active" {
		t.Fatalf("mfa: %d %+v", code, lr)
	}

	res, err := audit.Verify(ctx, h.st.Q)
	if err != nil || !res.OK || res.Checked < 4 {
		t.Fatalf("audit chain: %+v %v", res, err)
	}
}

func TestLockoutAfterFailures(t *testing.T) {
	h := newHarness(t)
	h.createUser("bob", "correct-horse-battery-9", "viewer", nil, nil)
	c := h.client()
	for range 5 {
		c.do("POST", "/auth/login", map[string]string{"username": "bob", "password": "nope"}, nil)
	}
	code, body := c.do("POST", "/auth/login", map[string]string{"username": "bob", "password": "correct-horse-battery-9"}, nil)
	if code != 429 || errCode(body) != "rate_limited" {
		t.Fatalf("locked account login: %d %v", code, body)
	}
}

func TestRBACStepupAndSignedJobs(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	mkGroup := func(name string) uuid.UUID {
		g, err := h.st.Q.CreateHostGroup(ctx, db.CreateHostGroupParams{ID: ids.NewUUID(), Name: name, Settings: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		return g.ID
	}
	mkHost := func(name string, g uuid.UUID) uuid.UUID {
		hh, err := h.st.Q.CreateHost(ctx, db.CreateHostParams{ID: ids.NewUUID(), Hostname: name, Labels: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		_ = h.st.Q.AddHostToGroup(ctx, db.AddHostToGroupParams{HostID: hh.ID, HostGroupID: g})
		return hh.ID
	}
	web, dbg := mkGroup("web"), mkGroup("db")
	hWeb, hDB := mkHost("web1", web), mkHost("db1", dbg)

	h.createUser("olga", "operator-password-77", "operator", &web, nil)
	h.createUser("vic", "viewer-password-777", "viewer", nil, nil)

	op := h.client()
	secret := h.loginWithTOTPEnrollment(op, "olga", "operator-password-77")
	_ = secret

	// Scoped operator sees only web hosts.
	var hosts []map[string]any
	if code, _ := op.do("GET", "/hosts", nil, &hosts); code != 200 || len(hosts) != 1 || hosts[0]["hostname"] != "web1" {
		t.Fatalf("hosts visible to scoped operator: %v", hosts)
	}
	if code, _ := op.do("GET", "/hosts/"+hDB.String(), nil, nil); code != 404 {
		t.Fatalf("out-of-scope host detail: %d", code)
	}

	// Refresh (low risk) works without step-up... but step-up from enrollment is
	// still fresh; expire it first.
	h.clock.Advance(6 * time.Minute)
	job := map[string]any{"type": "pkg_refresh", "targets": map[string]any{"host_ids": []string{hWeb.String()}}}
	var created struct {
		ID     string `json:"id"`
		Counts struct{ Total int }
	}
	if code, b := op.do("POST", "/jobs", job, &created); code != 201 || created.Counts.Total != 1 {
		t.Fatalf("low-risk job: %d %v", code, b)
	}
	// Out-of-scope target is forbidden.
	job["targets"] = map[string]any{"host_ids": []string{hDB.String()}}
	if code, _ := op.do("POST", "/jobs", job, nil); code != 403 {
		t.Fatalf("out-of-scope job: %d", code)
	}
	// Medium risk needs step-up.
	up := map[string]any{"type": "pkg_upgrade", "params": map[string]any{"scope": "security"}, "targets": map[string]any{"host_group_ids": []string{web.String()}}}
	if code, b := op.do("POST", "/jobs", up, nil); code != 403 || errCode(b) != "stepup_required" {
		t.Fatalf("upgrade without step-up: %d %v", code, b)
	}
	if code, b := op.do("POST", "/auth/mfa/totp", map[string]string{"code": auth.TOTPCode(secret, h.clock.Now())}, nil); code != 200 {
		t.Fatalf("step-up: %d %v", code, b)
	}
	if code, b := op.do("POST", "/jobs", up, &created); code != 201 {
		t.Fatalf("upgrade with step-up: %d %v", code, b)
	}
	// Package install is not in the operator role.
	inst := map[string]any{"type": "pkg_install", "params": map[string]any{"packages": []string{"nmap"}}, "targets": map[string]any{"host_ids": []string{hWeb.String()}}}
	if code, _ := op.do("POST", "/jobs", inst, nil); code != 403 {
		t.Fatalf("operator install: %d", code)
	}
	// Invalid parameters never reach the signer.
	bad := map[string]any{"type": "pkg_upgrade", "params": map[string]any{"scope": "named", "packages": []string{"-oAPT::x=1"}}, "targets": map[string]any{"host_ids": []string{hWeb.String()}}}
	if code, _ := op.do("POST", "/jobs", bad, nil); code != 400 {
		t.Fatalf("invalid package name: %d", code)
	}

	// The queued envelope is valid for exactly that host.
	tg, err := h.st.Q.GetJobTarget(ctx, db.GetJobTargetParams{JobID: uuid.MustParse(created.ID), HostID: hWeb})
	if err != nil || tg.Status != "queued" {
		t.Fatalf("target: %+v %v", tg, err)
	}
	var sj agentv1.SignedJob
	if err := proto.Unmarshal(tg.SignedEnvelope, &sj); err != nil {
		t.Fatal(err)
	}
	v := &envelope.Verifier{Keys: h.keys, HostID: hWeb.String(), Nonces: envelope.NewMemoryNonceStore(nil)}
	j, err := v.Verify(&sj)
	if err != nil || j.GetRequestedBy() != "olga" || j.GetPkgUpgrade().GetScope() != agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY {
		t.Fatalf("envelope: %v %v", j, err)
	}

	// Viewer cannot create jobs or see users.
	vc := h.client()
	h.loginWithTOTPEnrollment(vc, "vic", "viewer-password-777")
	if code, _ := vc.do("POST", "/jobs", map[string]any{"type": "pkg_refresh", "targets": map[string]any{"host_ids": []string{hWeb.String()}}}, nil); code != 403 {
		t.Fatalf("viewer job: %d", code)
	}
	if code, _ := vc.do("GET", "/users", nil, nil); code != 403 {
		t.Fatalf("viewer users: %d", code)
	}
	// Viewer cannot open a shell.
	if code, _ := vc.do("POST", "/hosts/"+hWeb.String()+"/shell", map[string]any{}, nil); code != 403 {
		t.Fatalf("viewer shell: %d", code)
	}
}

func TestEnrollmentTokenStoredHashed(t *testing.T) {
	h := newHarness(t)
	h.createUser("root2", "admin-password-1234", "admin", nil, nil)
	c := h.client()
	h.loginWithTOTPEnrollment(c, "root2", "admin-password-1234")
	var out struct {
		Secret         string `json:"secret"`
		InstallCommand string `json:"install_command"`
	}
	if code, b := c.do("POST", "/enrollment-tokens", map[string]any{"description": "web", "max_uses": 3}, &out); code != 201 {
		t.Fatalf("create token: %d %v", code, b)
	}
	if !strings.HasPrefix(out.Secret, auth.PrefixEnrollment) || !strings.Contains(out.InstallCommand, "--token-stdin") ||
		!strings.Contains(out.InstallCommand, "https://gw.example.internal:8443/install/agent.sh") {
		t.Fatalf("token response: %+v", out)
	}
	var count int
	if err := h.st.Pool.QueryRow(context.Background(), "SELECT count(*) FROM enrollment_tokens WHERE position($1::bytea in token_hash) > 0", []byte(out.Secret)).Scan(&count); err != nil || count != 0 {
		t.Fatalf("plaintext token stored: %d %v", count, err)
	}
	if code, _ := c.do("GET", "/enrollment-tokens", nil, nil); code != 200 {
		t.Fatalf("list tokens: %d", code)
	}
}

func TestAlertmanagerWebhookAuth(t *testing.T) {
	h := newHarness(t)
	post := func(tok string) int {
		req, _ := http.NewRequest("POST", h.url+"/api/v1/alertmanager/webhook",
			strings.NewReader(`{"alerts":[{"status":"firing","labels":{"alertname":"DiskFull","severity":"critical"},"startsAt":"2026-11-05T10:00:00Z","fingerprint":"abc"}]}`))
		req.Header.Set("Content-Type", "application/json")
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := h.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post(""); c != 401 {
		t.Fatalf("no token: %d", c)
	}
	if c := post("wrong"); c != 401 {
		t.Fatalf("wrong token: %d", c)
	}
	if c := post("hook-token"); c != 204 {
		t.Fatalf("valid token: %d", c)
	}
	n, _ := h.st.Q.CountFiringAlerts(context.Background())
	if n != 1 {
		t.Fatalf("firing alerts = %d", n)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	resp, err := h.srv.Client().Get(h.url + "/api/v1/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") || resp.Header.Get("X-Content-Type-Options") != "nosniff" ||
		resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: %v", resp.Header)
	}
}
