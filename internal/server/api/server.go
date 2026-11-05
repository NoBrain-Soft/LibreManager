// Package api implements `stellwerk-server api` (ARCHITECTURE.md §5.3):
// the REST API defined in api/openapi.yaml, WebSockets for events and
// shells, and the embedded web UI. It never holds the job-signing key; it
// requests signatures from the signer over a unix socket.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/nobrain-soft/libremanager/internal/common/secretbox"
	centralv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/central/v1"
	"github.com/nobrain-soft/libremanager/internal/server/api/apigen"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/config"
	"github.com/nobrain-soft/libremanager/internal/server/events"
	"github.com/nobrain-soft/libremanager/internal/server/install"
	"github.com/nobrain-soft/libremanager/internal/server/store"
)

// Deps are the API server dependencies.
type Deps struct {
	Cfg          *config.Config
	Store        *store.Store
	Audit        *audit.Logger
	MasterKey    *secretbox.Key
	Pepper       auth.Pepper
	WebhookToken string
	Signer       centralv1.SignerServiceClient
	Control      centralv1.GatewayControlServiceClient
	Hub          *events.Hub
	WebAuthn     *webauthn.WebAuthn
	CAPEM        string
	CAFP         string
	// UI serves the single-page app (may be nil).
	UI  http.Handler
	Now func() time.Time
	// VMClient queries VictoriaMetrics.
	VMClient *http.Client
}

// Server implements apigen.ServerInterface.
type Server struct {
	d        Deps
	sessions *auth.Sessions
	settings *settingsStore

	loginIPLimit   *auth.KeyedLimiter
	loginUserLimit *auth.KeyedLimiter

	shellMu      sync.Mutex
	shellGrants  map[string]*pendingGrant
	activeShells map[string]context.CancelFunc
}

var _ apigen.ServerInterface = (*Server)(nil)

// New creates the API server.
func New(d Deps) (*Server, error) {
	if d.Store == nil || d.Audit == nil || d.MasterKey == nil || d.Cfg == nil {
		return nil, errors.New("api: incomplete deps")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.VMClient == nil {
		d.VMClient = &http.Client{Timeout: 20 * time.Second}
	}
	if d.Hub == nil {
		d.Hub = events.NewHub()
	}
	s := &Server{
		d:              d,
		settings:       &settingsStore{st: d.Store, key: d.MasterKey},
		loginIPLimit:   auth.NewKeyedLimiter(20, 10),
		loginUserLimit: auth.NewKeyedLimiter(10, 5),
		shellGrants:    map[string]*pendingGrant{},
		activeShells:   map[string]context.CancelFunc{},
	}
	s.sessions = &auth.Sessions{Q: d.Store.Q, Now: d.Now, Policy: func(ctx context.Context) auth.SessionPolicy {
		st := s.settings.get(ctx)
		p := auth.DefaultSessionPolicy
		p.Idle = time.Duration(st.Session.IdleMinutes) * time.Minute
		p.Absolute = time.Duration(st.Session.AbsoluteHours) * time.Hour
		return p
	}}
	return s, nil
}

// Handler returns the complete HTTP handler (API + UI).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	apigen.HandlerWithOptions(s, apigen.StdHTTPServerOptions{
		BaseURL:    "/api/v1",
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeError(w, http.StatusBadRequest, "invalid", err.Error())
		},
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.d.Store.Pool.Ping(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "unavailable", "database unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	if s.d.UI != nil {
		mux.Handle("/", s.d.UI)
	}
	return s.middleware(mux)
}

func (s *Server) installParams() install.Params {
	return install.Params{AgentEndpoint: s.d.Cfg.AgentEndpoint, CAPEM: s.d.CAPEM, CAFingerprint: s.d.CAFP}
}

// --- JSON helpers

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("write response", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	var e apiError
	e.Error.Code = code
	e.Error.Message = msg
	writeJSON(w, status, e)
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "internal error", "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "internal error")
}

func notFound(w http.ResponseWriter) { writeError(w, http.StatusNotFound, "not_found", "not found") }

func forbidden(w http.ResponseWriter) {
	writeError(w, http.StatusForbidden, "forbidden", "you do not have permission for this action")
}

func invalid(w http.ResponseWriter, msg string) { writeError(w, http.StatusBadRequest, "invalid", msg) }

// decode reads a JSON body (size limited by middleware), rejecting unknown fields.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		invalid(w, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func ptr[T any](v T) *T { return &v }
