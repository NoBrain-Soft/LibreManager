package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/validate"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	centralv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/central/v1"
	"github.com/nobrain-soft/libremanager/internal/server/api/apigen"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/events"
	"github.com/nobrain-soft/libremanager/internal/server/rbac"
	"github.com/nobrain-soft/libremanager/internal/server/shell"
	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// grantValidity is how long a granted session waits for the WebSocket.
const grantValidity = 60 * time.Second

type pendingGrant struct {
	userID    uuid.UUID
	username  string
	hostID    uuid.UUID
	hostname  string
	unixUser  string
	grant     *agentv1.SignedJob
	cols      int
	rows      int
	maxDur    time.Duration
	idle      time.Duration
	expiresAt time.Time
}

// effectiveShell merges fleet defaults with the host's group overrides
// (most restrictive allow_root wins: root requires every source to allow it).
func (s *Server) effectiveShell(ctx context.Context, hostID uuid.UUID) (apigen.ShellIdentityMode, string, bool, error) {
	fleet := s.settings.get(ctx).Shell
	mode, shared, allowRoot := fleet.DefaultIdentity, fleet.SharedAccount, fleet.AllowRoot
	refs, err := s.d.Store.Q.ListHostGroupRefs(ctx, []uuid.UUID{hostID})
	if err != nil {
		return mode, shared, false, err
	}
	for _, r := range refs {
		var gs groupSettings
		if json.Unmarshal(r.Settings, &gs) != nil {
			continue
		}
		if gs.Shell.Identity != nil {
			mode = *gs.Shell.Identity
		}
		if gs.Shell.SharedAccount != nil && *gs.Shell.SharedAccount != "" {
			shared = *gs.Shell.SharedAccount
		}
		if gs.Shell.AllowRoot != nil && !*gs.Shell.AllowRoot {
			allowRoot = false
		} else if gs.Shell.AllowRoot != nil && *gs.Shell.AllowRoot && fleet.AllowRoot {
			allowRoot = true
		}
	}
	return mode, shared, allowRoot, nil
}

// CreateShellSession implements apigen.ServerInterface.
func (s *Server) CreateShellSession(w http.ResponseWriter, r *http.Request, hostID apigen.HostId) {
	ctx := r.Context()
	if !s.canHost(w, r, hostID, rbac.ShellOpen) || !s.requireStepup(w, r) {
		return
	}
	var in apigen.ShellSessionCreate
	if !decode(w, r, &in) {
		return
	}
	h, err := s.d.Store.Q.GetHost(ctx, hostID)
	if err != nil {
		notFound(w)
		return
	}
	if !h.Connected || h.Status != "active" {
		writeError(w, http.StatusConflict, "conflict", "host is not connected")
		return
	}
	mode, shared, allowRoot, err := s.effectiveShell(ctx, hostID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	u := userFrom(ctx)
	var unixUser string
	switch mode {
	case apigen.Shared:
		unixUser = shared
	case apigen.PerUser:
		unixUser = u.Username
	default:
		unixUser = deref(in.UnixUser)
		if unixUser == "" {
			unixUser = shared
		}
	}
	if !validate.AccountName(unixUser) {
		invalid(w, fmt.Sprintf("%q is not a valid unix account name", unixUser))
		return
	}
	if unixUser == "root" {
		ok, err := principalFrom(ctx).CanOnHost(ctx, s.d.Store.Q, rbac.ShellRoot, hostID)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if !allowRoot || !ok {
			writeError(w, http.StatusForbidden, "forbidden", "root shells are not allowed")
			return
		}
	}
	cols, rows := 120, 32
	if in.Cols != nil {
		cols = min(max(*in.Cols, 10), 1000)
	}
	if in.Rows != nil {
		rows = min(max(*in.Rows, 5), 1000)
	}
	fleet := s.settings.get(ctx).Shell
	maxDur := time.Duration(fleet.MaxDurationMinutes) * time.Minute
	idle := time.Duration(fleet.IdleTimeoutMinutes) * time.Minute
	sessionID := ids.NewUUID()
	jobID := ids.NewUUID()
	if s.d.Signer == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "signer unavailable")
		return
	}
	resp, err := s.d.Signer.SignJobs(ctx, &centralv1.SignJobsRequest{
		Template: &agentv1.Job{JobId: jobID.String(), RequestedBy: u.Username, Action: &agentv1.Job_Shell{Shell: &agentv1.ShellGrant{
			SessionId: sessionID.String(), UnixUser: unixUser, Cols: uint32(cols), Rows: uint32(rows), //nolint:gosec // clamped
			MaxDurationS: uint32(maxDur.Seconds()), IdleTimeoutS: uint32(idle.Seconds()), Record: true,
		}}},
		HostIds: []string{hostID.String()},
	})
	if err != nil || len(resp.GetEnvelopes()) != 1 {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "signer refused the shell grant")
		return
	}
	err = s.d.Store.InTx(ctx, func(q *db.Queries, _ pgxTx) error {
		if err := q.CreateShellSession(ctx, db.CreateShellSessionParams{ID: sessionID, HostID: hostID, UserID: &u.ID,
			Username: u.Username, UnixUser: unixUser, JobID: &jobID}); err != nil {
			return err
		}
		_, err := s.d.Audit.LogTx(ctx, q, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "shell.grant", Target: "host:" + hostID.String(),
			Details: map[string]any{"session_id": sessionID.String(), "unix_user": unixUser, "hostname": h.Hostname}})
		return err
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.shellMu.Lock()
	for k, g := range s.shellGrants {
		if s.d.Now().After(g.expiresAt) {
			delete(s.shellGrants, k)
		}
	}
	s.shellGrants[sessionID.String()] = &pendingGrant{userID: u.ID, username: u.Username, hostID: hostID, hostname: h.Hostname,
		unixUser: unixUser, grant: resp.GetEnvelopes()[0].GetSigned(), cols: cols, rows: rows, maxDur: maxDur, idle: idle,
		expiresAt: s.d.Now().Add(grantValidity)}
	s.shellMu.Unlock()
	path := fmt.Sprintf("/api/v1/hosts/%s/shell/%s", hostID, sessionID)
	writeJSON(w, http.StatusCreated, apigen.ShellSession{Id: sessionID, HostId: hostID, Hostname: &h.Hostname, Username: u.Username,
		UnixUser: unixUser, StartedAt: s.d.Now(), WebsocketPath: &path})
}

type wsMsg struct {
	Type   string `json:"type"`
	Data   string `json:"data,omitempty"`
	Cols   int    `json:"cols,omitempty"`
	Rows   int    `json:"rows,omitempty"`
	Code   int    `json:"code,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// ConnectShell implements apigen.ServerInterface (WebSocket).
func (s *Server) ConnectShell(w http.ResponseWriter, r *http.Request, hostID apigen.HostId, sessionID apigen.SessionId) {
	ctx := r.Context()
	u := userFrom(ctx)
	s.shellMu.Lock()
	g := s.shellGrants[sessionID.String()]
	delete(s.shellGrants, sessionID.String()) // single use
	s.shellMu.Unlock()
	if g == nil || g.userID != u.ID || g.hostID != hostID || s.d.Now().After(g.expiresAt) {
		notFound(w)
		return
	}
	if s.d.Control == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "gateway unavailable")
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{s.d.Cfg.PublicHost()}})
	if err != nil {
		return
	}
	ws.SetReadLimit(256 << 10)
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), g.maxDur+time.Minute)
	defer cancel()
	s.shellMu.Lock()
	s.activeShells[sessionID.String()] = cancel
	s.shellMu.Unlock()
	defer func() {
		s.shellMu.Lock()
		delete(s.activeShells, sessionID.String())
		s.shellMu.Unlock()
	}()

	reason, bytesIn, bytesOut, recRef, recSum := s.runShell(sctx, ws, g, sessionID.String())
	bg := context.WithoutCancel(ctx)
	if err := s.d.Store.Q.EndShellSession(bg, db.EndShellSessionParams{ID: sessionID, EndReason: validate.Text(reason, 256),
		RecordingRef: recRef, RecordingSha256: recSum, BytesIn: bytesIn, BytesOut: bytesOut}); err != nil {
		slog.ErrorContext(bg, "end shell session", "err", err)
	}
	s.d.Audit.LogBestEffort(bg, audit.Entry{Actor: "user:" + g.username, ActorIP: clientIP(ctx), Action: "shell.end", Target: "host:" + hostID.String(),
		Details: map[string]any{"session_id": sessionID.String(), "reason": reason, "bytes_in": bytesIn, "bytes_out": bytesOut}})
	_ = ws.Close(websocket.StatusNormalClosure, "session ended")
}

func (s *Server) runShell(ctx context.Context, ws *websocket.Conn, g *pendingGrant, sid string) (string, int64, int64, string, []byte) {
	now := s.d.Now()
	rec, err := shell.NewRecorder(s.d.Cfg.RecordingsDir(), sid, s.d.MasterKey, g.cols, g.rows, g.username+"@"+g.hostname+" as "+g.unixUser, now)
	if err != nil {
		slog.ErrorContext(ctx, "cannot create recording; refusing unrecorded session", "err", err)
		_ = wsWrite(ctx, ws, wsMsg{Type: "exit", Code: -1, Reason: "recording unavailable"})
		return "recording unavailable", 0, 0, "", nil
	}
	var recSum []byte
	recRef := filepath.Base(rec.Path)
	defer func() {
		if recSum == nil {
			recSum, _ = rec.Close(s.d.Now())
		}
	}()
	relay, err := s.d.Control.ShellRelay(ctx)
	if err != nil {
		return "gateway unavailable", 0, 0, recRef, nil
	}
	if err := relay.Send(&centralv1.ShellRelayRequest{Payload: &centralv1.ShellRelayRequest_Attach{Attach: &centralv1.ShellRelayAttach{
		SessionId: sid, HostId: g.hostID.String(), Grant: g.grant}}}); err != nil {
		return "gateway unavailable", 0, 0, recRef, nil
	}
	first, err := relay.Recv()
	if err != nil || first.GetReady() == nil {
		reason := "agent did not open the shell"
		if err != nil {
			reason = err.Error()
		}
		_ = wsWrite(ctx, ws, wsMsg{Type: "exit", Code: -1, Reason: reason})
		recSum, _ = rec.Close(s.d.Now())
		return reason, 0, 0, recRef, recSum
	}
	_ = wsWrite(ctx, ws, wsMsg{Type: "ready"})
	events.Publish(ctx, s.d.Store, events.Event{Type: events.HostUpdated, HostID: g.hostID.String(), Message: "shell opened"})

	var in, out atomic.Int64
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	done := make(chan string, 3)
	// gateway -> browser
	go func() {
		for {
			m, err := relay.Recv()
			if err != nil {
				done <- "connection to host lost"
				return
			}
			if ex := m.GetExit(); ex != nil {
				_ = wsWrite(ctx, ws, wsMsg{Type: "exit", Code: int(ex.GetExitCode()), Reason: ex.GetReason()})
				done <- "shell exited: " + ex.GetReason()
				return
			}
			if o := m.GetOutput(); len(o) > 0 {
				out.Add(int64(len(o)))
				rec.Output(s.d.Now(), o)
				if err := wsWrite(ctx, ws, wsMsg{Type: "output", Data: base64.StdEncoding.EncodeToString(o)}); err != nil {
					done <- "browser disconnected"
					return
				}
			}
		}
	}()
	// browser -> gateway
	go func() {
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				done <- "browser disconnected"
				return
			}
			var m wsMsg
			if json.Unmarshal(data, &m) != nil {
				continue
			}
			switch m.Type {
			case "input":
				b, err := base64.StdEncoding.DecodeString(m.Data)
				if err != nil || len(b) == 0 || len(b) > 64<<10 {
					continue
				}
				in.Add(int64(len(b)))
				lastActivity.Store(time.Now().UnixNano())
				if relay.Send(&centralv1.ShellRelayRequest{Payload: &centralv1.ShellRelayRequest_Input{Input: b}}) != nil {
					done <- "connection to host lost"
					return
				}
			case "resize":
				if m.Cols < 10 || m.Cols > 1000 || m.Rows < 5 || m.Rows > 1000 {
					continue
				}
				rec.Resize(s.d.Now(), m.Cols, m.Rows)
				_ = relay.Send(&centralv1.ShellRelayRequest{Payload: &centralv1.ShellRelayRequest_Resize{Resize: &agentv1.ShellResize{
					Cols: uint32(m.Cols), Rows: uint32(m.Rows)}}}) //nolint:gosec // validated
			}
		}
	}()
	// idle watchdog
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, lastActivity.Load())) > g.idle {
					done <- "idle timeout"
					return
				}
			}
		}
	}()
	var reason string
	select {
	case reason = <-done:
	case <-ctx.Done():
		reason = "terminated"
		if ctx.Err() == context.DeadlineExceeded {
			reason = "maximum duration reached"
		}
	}
	_ = relay.Send(&centralv1.ShellRelayRequest{Payload: &centralv1.ShellRelayRequest_Close{Close: &agentv1.ShellClose{Reason: reason}}})
	_ = relay.CloseSend()
	_ = wsWrite(context.WithoutCancel(ctx), ws, wsMsg{Type: "exit", Code: -1, Reason: reason})
	recSum, _ = rec.Close(s.d.Now())
	return reason, in.Load(), out.Load(), recRef, recSum
}

func wsWrite(ctx context.Context, ws *websocket.Conn, m wsMsg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return ws.Write(wctx, websocket.MessageText, b)
}

func shellJSON(s db.ListShellSessionsRow) apigen.ShellSession {
	return apigen.ShellSession{Id: s.ID, HostId: s.HostID, Hostname: &s.Hostname, Username: s.Username, UnixUser: s.UnixUser,
		StartedAt: s.StartedAt, EndedAt: s.EndedAt, EndReason: &s.EndReason, HasRecording: ptr(s.RecordingRef != "")}
}

// ListShellSessions implements apigen.ServerInterface.
func (s *Server) ListShellSessions(w http.ResponseWriter, r *http.Request, params apigen.ListShellSessionsParams) {
	ctx := r.Context()
	p := principalFrom(ctx)
	limit := int32(100)
	if params.Limit != nil && *params.Limit > 0 && *params.Limit <= 500 {
		limit = int32(*params.Limit) //nolint:gosec // bounded
	}
	rows, err := s.d.Store.Q.ListShellSessions(ctx, db.ListShellSessionsParams{HostID: params.HostId, Lim: limit})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	review := p.HasGlobal(rbac.ShellReview)
	u := userFrom(ctx)
	out := []apigen.ShellSession{}
	for _, x := range rows {
		if review || (x.UserID != nil && *x.UserID == u.ID) {
			out = append(out, shellJSON(x))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// TerminateShellSession implements apigen.ServerInterface (kill switch).
func (s *Server) TerminateShellSession(w http.ResponseWriter, r *http.Request, id apigen.SessionId) {
	ctx := r.Context()
	sess, err := s.d.Store.Q.GetShellSession(ctx, id)
	if store.IsNotFound(err) {
		notFound(w)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	u := userFrom(ctx)
	own := sess.UserID != nil && *sess.UserID == u.ID
	if !own && !principalFrom(ctx).HasGlobal(rbac.ShellReview) {
		forbidden(w)
		return
	}
	s.shellMu.Lock()
	cancel := s.activeShells[id.String()]
	s.shellMu.Unlock()
	if cancel == nil {
		writeError(w, http.StatusConflict, "conflict", "session is not active on this server")
		return
	}
	cancel()
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "shell.terminate", Target: "shell:" + id.String()})
	w.WriteHeader(http.StatusNoContent)
}

// GetShellRecording implements apigen.ServerInterface.
func (s *Server) GetShellRecording(w http.ResponseWriter, r *http.Request, id apigen.SessionId) {
	if !requireGlobal(w, r, rbac.ShellReview) {
		return
	}
	ctx := r.Context()
	sess, err := s.d.Store.Q.GetShellSession(ctx, id)
	if store.IsNotFound(err) || (err == nil && sess.RecordingRef == "") {
		notFound(w)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if sess.EndedAt == nil {
		writeError(w, http.StatusConflict, "conflict", "session still running")
		return
	}
	path := filepath.Join(s.d.Cfg.RecordingsDir(), filepath.Base(sess.RecordingRef))
	cast, err := shell.Open(path, id.String(), s.d.MasterKey, sess.RecordingSha256)
	if err != nil {
		if os.IsNotExist(err) {
			notFound(w)
			return
		}
		s.internalError(w, r, err)
		return
	}
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "shell.recording_view", Target: "shell:" + id.String()})
	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", id.String()+".cast"))
	_, _ = w.Write(cast)
}

// --- events WebSocket

// ConnectEvents implements apigen.ServerInterface.
func (s *Server) ConnectEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := principalFrom(ctx)
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{s.d.Cfg.PublicHost()}})
	if err != nil {
		return
	}
	ws.SetReadLimit(4096)
	cctx := ws.CloseRead(context.WithoutCancel(ctx))
	ch, unsub := s.d.Hub.Subscribe()
	defer unsub()
	visible := map[string]bool{}
	allowed := func(e events.Event) bool {
		if e.HostID == "" {
			return p.HasAnywhere(rbac.HostView)
		}
		if v, ok := visible[e.HostID]; ok {
			return v
		}
		id, err := uuid.Parse(e.HostID)
		if err != nil {
			return false
		}
		ok, _ := p.CanOnHost(cctx, s.d.Store.Q, rbac.HostView, id)
		visible[e.HostID] = ok
		return ok
	}
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	// Re-check the session periodically so logout/expiry ends the stream.
	token, _ := ctx.Value(keySessionToken).(string)
	for {
		select {
		case <-cctx.Done():
			return
		case <-ping.C:
			if _, err := s.sessions.Peek(cctx, token); err != nil {
				_ = ws.Close(websocket.StatusPolicyViolation, "session expired")
				return
			}
			pctx, cancel := context.WithTimeout(cctx, 10*time.Second)
			err := ws.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		case e := <-ch:
			if !allowed(e) {
				continue
			}
			b, _ := json.Marshal(e)
			wctx, cancel := context.WithTimeout(cctx, 10*time.Second)
			err := ws.Write(wctx, websocket.MessageText, b)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
