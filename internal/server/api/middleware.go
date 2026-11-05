package api

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/rbac"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

type ctxKey int

const (
	keySession ctxKey = iota
	keyUser
	keyPrincipal
	keyClientIP
	keySessionToken
)

// MaxBodyBytes bounds request bodies.
const MaxBodyBytes = 1 << 20

// CSP is the Content-Security-Policy for the UI and API (CLAUDE.md rule 8).
// style-src allows inline styles because xterm.js injects <style> elements;
// scripts are strictly same-origin.
const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// Paths reachable without a session.
var publicPaths = map[string]bool{
	"/api/v1/auth/login":           true,
	"/api/v1/alertmanager/webhook": true,
}

// Paths reachable with a pending (not yet active) session, per state.
var pendingPaths = map[string]map[string]bool{
	auth.StatePendingMFA: {
		"/api/v1/auth/mfa/totp": true, "/api/v1/auth/mfa/webauthn/begin": true, "/api/v1/auth/mfa/webauthn/finish": true,
	},
	auth.StatePendingPasswordChange: {
		"/api/v1/auth/password": true,
	},
	auth.StatePendingMFAEnrollment: {
		"/api/v1/auth/totp/enroll": true, "/api/v1/auth/totp/confirm": true,
		"/api/v1/auth/webauthn/register/begin": true, "/api/v1/auth/webauthn/register/finish": true,
	},
}

var anyStatePaths = map[string]bool{"/api/v1/auth/session": true, "/api/v1/auth/logout": true}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() { //nolint:contextcheck // recovery logs with the request context
			if rec := recover(); rec != nil {
				slog.ErrorContext(r.Context(), "panic in handler", "panic", rec, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal", "internal error")
			}
		}()
		s.securityHeaders(w)
		ip := s.clientIP(r)
		ctx := context.WithValue(r.Context(), keyClientIP, ip)
		r = r.WithContext(ctx)

		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)

		stateChanging := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		isWS := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
		if (stateChanging || isWS) && !s.sameOrigin(r) {
			writeError(w, http.StatusForbidden, "forbidden", "cross-origin request rejected")
			return
		}
		if stateChanging && r.ContentLength != 0 && r.URL.Path != "/api/v1/alertmanager/webhook" {
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				writeError(w, http.StatusUnsupportedMediaType, "invalid", "Content-Type must be application/json")
				return
			}
		}

		if publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			s.logRequest(r, start)
			return
		}
		token := auth.TokenFromRequest(r)
		sess, err := s.sessions.Lookup(ctx, token)
		if err != nil {
			auth.ClearCookie(w)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "login required")
			return
		}
		if stateChanging && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.CsrfToken)) != 1 {
			writeError(w, http.StatusForbidden, "forbidden", "missing or invalid CSRF token")
			return
		}
		if sess.State != auth.StateActive && !anyStatePaths[r.URL.Path] && !pendingPaths[sess.State][r.URL.Path] {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "login not complete ("+sess.State+")")
			return
		}
		user, err := s.d.Store.Q.GetUser(ctx, sess.UserID)
		if err != nil || user.Disabled {
			_ = s.d.Store.Q.DeleteSession(ctx, sess.IDHash)
			auth.ClearCookie(w)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "login required")
			return
		}
		ctx = context.WithValue(ctx, keySession, sess)
		ctx = context.WithValue(ctx, keyUser, &user)
		ctx = context.WithValue(ctx, keySessionToken, token)
		if sess.State == auth.StateActive {
			p, err := rbac.Load(ctx, s.d.Store.Q, user.ID, user.Username)
			if err != nil {
				s.internalError(w, r, err)
				return
			}
			ctx = context.WithValue(ctx, keyPrincipal, p)
		}
		next.ServeHTTP(w, r.WithContext(ctx)) //nolint:contextcheck // ctx is derived from r.Context()
		s.logRequest(r, start)
	})
}

func (s *Server) logRequest(r *http.Request, start time.Time) {
	slog.DebugContext(r.Context(), "request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
}

func (s *Server) securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", CSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	if strings.HasPrefix(s.d.Cfg.PublicURL, "https://") {
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

// sameOrigin enforces that state-changing and WebSocket requests come from
// the panel's own origin (defense in depth on top of SameSite=Strict).
func (s *Server) sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		return o == s.publicOrigin()
	}
	// Non-browser clients (Alertmanager) send no Origin; browsers always
	// send Sec-Fetch-Site on modern versions.
	sfs := r.Header.Get("Sec-Fetch-Site")
	return sfs == "" || sfs == "same-origin" || sfs == "none"
}

func (s *Server) publicOrigin() string {
	u, err := url.Parse(s.d.Cfg.PublicURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	trusted := false
	for _, n := range s.d.Cfg.TrustedProxies {
		if n.Contains(ip) {
			trusted = true
			break
		}
	}
	if trusted {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if c := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); c != nil {
				return c.String()
			}
		}
	}
	return ip.String()
}

// --- context accessors

func sessionFrom(ctx context.Context) *db.Session {
	s, _ := ctx.Value(keySession).(*db.Session)
	return s
}
func userFrom(ctx context.Context) *db.User { u, _ := ctx.Value(keyUser).(*db.User); return u }
func principalFrom(ctx context.Context) *rbac.Principal {
	p, _ := ctx.Value(keyPrincipal).(*rbac.Principal)
	return p
}
func clientIP(ctx context.Context) string { s, _ := ctx.Value(keyClientIP).(string); return s }

// actor returns the audit actor string for the request.
func actor(ctx context.Context) string {
	if u := userFrom(ctx); u != nil {
		return "user:" + u.Username
	}
	return "anonymous"
}

// requireGlobal checks a global permission and writes 403 if missing.
func requireGlobal(w http.ResponseWriter, r *http.Request, perm string) bool {
	p := principalFrom(r.Context())
	if p == nil || !p.HasGlobal(perm) {
		forbidden(w)
		return false
	}
	return true
}

// requireStepup checks for a fresh step-up authentication.
func (s *Server) requireStepup(w http.ResponseWriter, r *http.Request) bool {
	sess := sessionFrom(r.Context())
	if ok, _ := s.sessions.StepupValid(r.Context(), sess); !ok {
		writeError(w, http.StatusForbidden, "stepup_required", "re-authenticate with your security key or TOTP to continue")
		return false
	}
	return true
}
