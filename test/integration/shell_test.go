package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/secretbox"
	"github.com/nobrain-soft/libremanager/internal/server/api"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/config"
	"github.com/nobrain-soft/libremanager/internal/server/gateway"
	"github.com/nobrain-soft/libremanager/internal/server/shell"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

type wsMsg struct {
	Type   string `json:"type"`
	Data   string `json:"data,omitempty"`
	Code   int    `json:"code,omitempty"`
	Reason string `json:"reason,omitempty"`
	Cols   int    `json:"cols,omitempty"`
	Rows   int    `json:"rows,omitempty"`
}

// TestShellEndToEnd opens a recorded shell through every hop:
// browser WebSocket -> API (RBAC, step-up, signer grant, recording) ->
// gateway control socket -> agent ShellSession stream -> helper PTY.
func TestShellEndToEnd(t *testing.T) {
	w := setup(t)
	ctx := w.ctx

	apiKey, _ := secretbox.NewKey()
	control, cc, err := gateway.DialControl(w.controlSck)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	cfg := &config.Config{AgentEndpoint: "localhost:8443", DataDir: filepath.Join(w.dir, "central-data"), VictoriaMetricsURL: "http://127.0.0.1:1"}
	var srv *api.Server
	hs := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { srv.Handler().ServeHTTP(rw, r) }))
	defer hs.Close()
	cfg.PublicURL = hs.URL
	srv, err = api.New(api.Deps{Cfg: cfg, Store: w.st, Audit: audit.New(w.st), MasterKey: apiKey, Pepper: auth.Pepper(bytes.Repeat([]byte{1}, 32)),
		Signer: signerClient{w.signer}, Control: control, CAPEM: "x", CAFP: "x"})
	if err != nil {
		t.Fatal(err)
	}
	// Shell identity: users pick the account, "ops" here.
	settings := api.DefaultSettings()
	sb, _ := json.Marshal(settings)
	_ = w.st.Q.PutSetting(ctx, db.PutSettingParams{Key: "settings", Value: sb})

	// A shell-user with TOTP enrolled.
	pw := "correct-horse-shell-42"
	hash, _ := auth.HashPassword(pw)
	u, err := w.st.Q.CreateUser(ctx, db.CreateUserParams{ID: ids.NewUUID(), Username: "sam", PasswordHash: &hash, MfaRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := auth.NewTOTPSecret()
	sealed, _ := secretbox.Seal(apiKey, "user/totp:"+u.ID.String(), secret)
	if _, err := w.st.Pool.Exec(ctx, "UPDATE users SET totp_secret = $1 WHERE id = $2", sealed, u.ID); err != nil {
		t.Fatal(err)
	}
	role, _ := w.st.Q.GetRoleByName(ctx, "shell-user")
	_ = w.st.Q.CreateRoleBinding(ctx, db.CreateRoleBindingParams{ID: ids.NewUUID(), UserID: u.ID, RoleID: role.ID})

	jar, _ := cookiejar.New(nil)
	client := hs.Client()
	client.Jar = jar
	csrf := ""
	call := func(method, path string, body any, out any) int {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequestWithContext(ctx, method, hs.URL+"/api/v1"+path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Origin", hs.URL)
		req.Header.Set("X-CSRF-Token", csrf)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if out != nil {
			_ = json.Unmarshal(raw, out)
		}
		return resp.StatusCode
	}
	if code := call("POST", "/auth/login", map[string]string{"username": "sam", "password": pw}, nil); code != 200 {
		t.Fatalf("login: %d", code)
	}
	var sess struct {
		CSRF string `json:"csrf_token"`
	}
	call("GET", "/auth/session", nil, &sess)
	csrf = sess.CSRF
	if code := call("POST", "/auth/mfa/totp", map[string]string{"code": auth.TOTPCode(secret, time.Now())}, nil); code != 200 {
		t.Fatalf("mfa: %d", code)
	}
	call("GET", "/auth/session", nil, &sess)
	csrf = sess.CSRF

	// Root is refused (central allow_root off + no shell.root permission).
	if code := call("POST", "/hosts/"+w.hostID.String()+"/shell", map[string]any{"unix_user": "root"}, nil); code != 403 {
		t.Fatalf("root shell: %d", code)
	}
	var created struct {
		ID            string `json:"id"`
		WebsocketPath string `json:"websocket_path"`
	}
	if code := call("POST", "/hosts/"+w.hostID.String()+"/shell", map[string]any{"unix_user": "ops", "cols": 100, "rows": 30}, &created); code != 201 {
		t.Fatalf("create shell: %d", code)
	}

	wsURL := "wss" + strings.TrimPrefix(hs.URL, "https") + created.WebsocketPath
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(dctx, wsURL, &websocket.DialOptions{HTTPClient: client, HTTPHeader: http.Header{"Origin": {hs.URL}}})
	if err != nil {
		t.Fatalf("websocket: %v", err)
	}
	defer conn.CloseNow()

	read := func() wsMsg {
		_, b, err := conn.Read(dctx)
		if err != nil {
			t.Fatalf("ws read: %v", err)
		}
		var m wsMsg
		_ = json.Unmarshal(b, &m)
		return m
	}
	send := func(m wsMsg) {
		b, _ := json.Marshal(m)
		if err := conn.Write(dctx, websocket.MessageText, b); err != nil {
			t.Fatal(err)
		}
	}
	if m := read(); m.Type != "ready" {
		t.Fatalf("first message %+v", m)
	}
	send(wsMsg{Type: "resize", Cols: 120, Rows: 40})
	send(wsMsg{Type: "input", Data: base64.StdEncoding.EncodeToString([]byte("echo marker-$((40+2)); exit\n"))})
	var out strings.Builder
	exited := false
	for !exited {
		m := read()
		switch m.Type {
		case "output":
			b, _ := base64.StdEncoding.DecodeString(m.Data)
			out.Write(b)
		case "exit":
			exited = true
			t.Logf("exit: code=%d reason=%q", m.Code, m.Reason)
		}
	}
	if !strings.Contains(out.String(), "marker-42") || !strings.Contains(out.String(), "This session is recorded") {
		t.Fatalf("shell output: %q", out.String())
	}

	// Session closed, recorded, decryptable and hash-verified.
	var rec db.GetShellSessionRow
	w.waitFor("session ended", func() bool {
		rec, err = w.st.Q.GetShellSession(ctx, mustUUID(created.ID))
		return err == nil && rec.EndedAt != nil
	})
	cast, err := shell.Open(filepath.Join(cfg.RecordingsDir(), rec.RecordingRef), created.ID, apiKey, rec.RecordingSha256)
	if err != nil {
		t.Fatalf("open recording: %v", err)
	}
	if !strings.Contains(string(cast), "marker-42") || !strings.Contains(string(cast), `"r","120x40"`) {
		t.Fatalf("recording content: %s", cast)
	}
	if !w.journal.has("accepted") {
		t.Fatal("no journald entry on host")
	}
	// A grant is single use: reconnecting with the same session fails.
	if _, _, err := websocket.Dial(dctx, wsURL, &websocket.DialOptions{HTTPClient: client, HTTPHeader: http.Header{"Origin": {hs.URL}}}); err == nil {
		t.Fatal("shell grant reused")
	}
	res, err := audit.Verify(ctx, w.st.Q)
	if err != nil || !res.OK {
		t.Fatalf("audit chain: %+v %v", res, err)
	}
}
