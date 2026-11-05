package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// CookieName uses the __Host- prefix: Secure, Path=/, no Domain.
const CookieName = "__Host-stellwerk_session"

// Session states.
const (
	StatePendingMFA            = "pending_mfa"
	StatePendingPasswordChange = "pending_password_change"
	StatePendingMFAEnrollment  = "pending_mfa_enrollment"
	StateActive                = "active"
)

// ErrNoSession is returned when no valid session exists.
var ErrNoSession = errors.New("no valid session")

// SessionPolicy holds timeouts (from settings).
type SessionPolicy struct {
	Idle     time.Duration
	Absolute time.Duration
	// Pending sessions (login not finished) live this long.
	Pending time.Duration
	// Stepup validity (ARCHITECTURE.md §6.4: 5 min).
	Stepup time.Duration
}

// DefaultSessionPolicy matches ARCHITECTURE.md §6.4.
var DefaultSessionPolicy = SessionPolicy{Idle: 30 * time.Minute, Absolute: 8 * time.Hour, Pending: 10 * time.Minute, Stepup: 5 * time.Minute}

// Sessions manages server-side sessions.
type Sessions struct {
	Q      *db.Queries
	Policy func(ctx context.Context) SessionPolicy
	Now    func() time.Time
}

func (s *Sessions) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Sessions) policy(ctx context.Context) SessionPolicy {
	if s.Policy != nil {
		return s.Policy(ctx)
	}
	return DefaultSessionPolicy
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create starts a session in state and returns the cookie token.
func (s *Sessions) Create(ctx context.Context, q *db.Queries, userID uuid.UUID, state, ip, ua string, mfaVerified bool) (string, time.Time, error) {
	token, err := randomString(32)
	if err != nil {
		return "", time.Time{}, err
	}
	csrf, err := randomString(32)
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now()
	p := s.policy(ctx)
	exp := now.Add(p.Absolute)
	if state != StateActive {
		exp = now.Add(p.Pending)
	}
	var mfaAt *time.Time
	if mfaVerified {
		mfaAt = &now
	}
	if len(ua) > 256 {
		ua = ua[:256]
	}
	if err := q.CreateSession(ctx, db.CreateSessionParams{
		IDHash: HashSessionToken(token), UserID: userID, State: state, CsrfToken: csrf,
		Ip: ip, UserAgent: ua, ExpiresAt: exp, MfaAt: mfaAt, StepupAt: mfaAt,
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("auth: create session: %w", err)
	}
	return token, exp, nil
}

// Lookup returns the session for a cookie token, enforcing absolute and
// idle expiry, and records activity.
func (s *Sessions) Lookup(ctx context.Context, token string) (*db.Session, error) {
	return s.lookup(ctx, token, true)
}

// Peek is Lookup without recording activity (for long-lived sockets, which
// must not keep an idle session alive).
func (s *Sessions) Peek(ctx context.Context, token string) (*db.Session, error) {
	return s.lookup(ctx, token, false)
}

func (s *Sessions) lookup(ctx context.Context, token string, touch bool) (*db.Session, error) {
	if token == "" || len(token) > 128 {
		return nil, ErrNoSession
	}
	h := HashSessionToken(token)
	sess, err := s.Q.GetSession(ctx, h)
	if store.IsNotFound(err) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, fmt.Errorf("auth: session: %w", err)
	}
	now := s.now()
	p := s.policy(ctx)
	if !now.Before(sess.ExpiresAt) || (sess.State == StateActive && now.Sub(sess.LastSeenAt) > p.Idle) {
		_ = s.Q.DeleteSession(ctx, h)
		return nil, ErrNoSession
	}
	// Avoid a write per request: touch at most once per minute.
	if touch && now.Sub(sess.LastSeenAt) > time.Minute {
		_ = s.Q.TouchSession(ctx, h)
	}
	return &sess, nil
}

// StepupValid reports whether the session has a fresh step-up.
func (s *Sessions) StepupValid(ctx context.Context, sess *db.Session) (bool, time.Time) {
	if sess.StepupAt == nil {
		return false, time.Time{}
	}
	until := sess.StepupAt.Add(s.policy(ctx).Stepup)
	return s.now().Before(until), until
}

// SetCookie writes the session cookie.
func SetCookie(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: token, Path: "/", Expires: exp,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

// ClearCookie removes the session cookie.
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

// TokenFromRequest returns the session cookie value.
func TokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
