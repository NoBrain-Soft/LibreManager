package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/secretbox"
	"github.com/nobrain-soft/libremanager/internal/common/version"
	"github.com/nobrain-soft/libremanager/internal/server/api/apigen"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/rbac"
	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

type pgxTx = pgx.Tx

func versionString() string { return version.Version }

const (
	maxLoginFailures = 5
	lockMinutes      = 15
	totpPurpose      = "user/totp"
)

func (s *Server) hasFactors(ctx context.Context, u *db.User) (bool, bool, int64) {
	n, _ := s.d.Store.Q.CountWebauthnCredentials(ctx, u.ID)
	totp := u.TotpSecret != nil
	return totp || n > 0, totp, n
}

func (s *Server) mfaRequired(ctx context.Context, u *db.User) bool {
	return u.MfaRequired || s.settings.get(ctx).Security.MfaRequired
}

// nextState decides where a login goes next. MFA is verified before a
// forced password change so that a stolen password alone cannot be used
// to lock the owner out.
func (s *Server) nextState(ctx context.Context, u *db.User, mfaVerified bool) string {
	has, _, _ := s.hasFactors(ctx, u)
	switch {
	case has && !mfaVerified:
		return auth.StatePendingMFA
	case u.PasswordChangeRequired:
		return auth.StatePendingPasswordChange
	case !has && s.mfaRequired(ctx, u):
		return auth.StatePendingMFAEnrollment
	default:
		return auth.StateActive
	}
}

func (s *Server) mfaMethods(ctx context.Context, u *db.User) *[]apigen.LoginResultMfaMethods {
	_, totp, n := s.hasFactors(ctx, u)
	var m []apigen.LoginResultMfaMethods
	if n > 0 {
		m = append(m, apigen.Webauthn)
	}
	if totp && s.settings.get(ctx).Security.AllowTotp {
		m = append(m, apigen.Totp)
	}
	return &m
}

// transition rotates the session into the next state (new token + CSRF).
func (s *Server) transition(w http.ResponseWriter, r *http.Request, u *db.User, mfaVerified bool) {
	ctx := r.Context()
	if old := sessionFrom(ctx); old != nil {
		_ = s.d.Store.Q.DeleteSession(ctx, old.IDHash)
		mfaVerified = mfaVerified || old.MfaAt != nil
	}
	state := s.nextState(ctx, u, mfaVerified)
	token, exp, err := s.sessions.Create(ctx, s.d.Store.Q, u.ID, state, clientIP(ctx), r.UserAgent(), mfaVerified)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	auth.SetCookie(w, token, exp)
	if state == auth.StateActive {
		_ = s.d.Store.Q.RecordLoginSuccess(ctx, u.ID)
		s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: "user:" + u.Username, ActorIP: clientIP(ctx), Action: "auth.login", Target: "user:" + u.Username,
			Details: map[string]any{"mfa": mfaVerified}})
	}
	writeJSON(w, http.StatusOK, apigen.LoginResult{State: apigen.SessionState(state), MfaMethods: s.mfaMethods(ctx, u)})
}

// Login implements apigen.ServerInterface.
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in apigen.LoginRequest
	if !decode(w, r, &in) {
		return
	}
	username := strings.ToLower(strings.TrimSpace(in.Username))
	if !s.loginIPLimit.Allow(clientIP(ctx)) || !s.loginUserLimit.Allow(username) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts, try again later")
		return
	}
	fail := func(reason string) {
		s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: "anonymous", ActorIP: clientIP(ctx), Action: "auth.login_failed",
			Target: "user:" + validateText(username), Details: map[string]any{"reason": reason}})
		writeError(w, http.StatusUnauthorized, "unauthenticated", "invalid username or password")
	}
	u, err := s.d.Store.Q.GetUserByUsername(ctx, username)
	if err != nil {
		auth.BurnPasswordCheck(in.Password)
		if !store.IsNotFound(err) {
			s.internalError(w, r, err)
			return
		}
		fail("unknown user")
		return
	}
	if u.Disabled || u.PasswordHash == nil {
		auth.BurnPasswordCheck(in.Password)
		fail("disabled")
		return
	}
	if u.LockedUntil != nil && s.d.Now().Before(*u.LockedUntil) {
		auth.BurnPasswordCheck(in.Password)
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many failed attempts, account temporarily locked")
		return
	}
	if !auth.VerifyPassword(*u.PasswordHash, in.Password) {
		if _, err := s.d.Store.Q.RecordLoginFailure(ctx, db.RecordLoginFailureParams{ID: u.ID, MaxFailures: maxLoginFailures, LockMinutes: lockMinutes}); err != nil {
			s.internalError(w, r, err)
			return
		}
		fail("bad password")
		return
	}
	_ = s.d.Store.Q.RecordLoginSuccess(ctx, u.ID)
	r = r.WithContext(context.WithValue(ctx, keySession, (*db.Session)(nil)))
	s.transition(w, r, &u, false)
}

func validateText(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// Logout implements apigen.ServerInterface.
func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if sess := sessionFrom(ctx); sess != nil {
		_ = s.d.Store.Q.DeleteSession(ctx, sess.IDHash)
		s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "auth.logout"})
	}
	auth.ClearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) userJSON(ctx context.Context, u *db.User) apigen.User {
	has, _, _ := s.hasFactors(ctx, u)
	return apigen.User{
		Id: u.ID, Username: u.Username, DisplayName: u.DisplayName, Email: u.Email, Disabled: u.Disabled,
		MfaRequired: u.MfaRequired, MfaEnrolled: &has, LastLoginAt: u.LastLoginAt, CreatedAt: u.CreatedAt,
	}
}

// GetSession implements apigen.ServerInterface.
func (s *Server) GetSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, u := sessionFrom(ctx), userFrom(ctx)
	_, totp, n := s.hasFactors(ctx, u)
	info := apigen.SessionInfo{
		State: apigen.SessionState(sess.State), User: s.userJSON(ctx, u), CsrfToken: sess.CsrfToken,
		ExpiresAt: sess.ExpiresAt, Permissions: []string{},
	}
	info.Mfa.Totp = totp
	info.Mfa.Webauthn = int(n)
	if p := principalFrom(ctx); p != nil {
		info.Permissions = p.GlobalPermissions()
		scoped := []apigen.ScopedPermission{}
		for _, sp := range p.ScopedPermissions() {
			scoped = append(scoped, apigen.ScopedPermission{Permission: sp.Permission, HostGroupId: sp.GroupID})
		}
		info.ScopedPermissions = &scoped
	}
	if ok, until := s.sessions.StepupValid(ctx, sess); ok {
		info.StepupValidUntil = &until
	}
	writeJSON(w, http.StatusOK, info)
}

// ChangePassword implements apigen.ServerInterface.
func (s *Server) ChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := userFrom(ctx)
	var in apigen.ChangePasswordRequest
	if !decode(w, r, &in) {
		return
	}
	if u.PasswordHash == nil || !auth.VerifyPassword(*u.PasswordHash, in.CurrentPassword) {
		writeError(w, http.StatusForbidden, "forbidden", "current password is wrong")
		return
	}
	if in.NewPassword == in.CurrentPassword {
		invalid(w, "the new password must differ from the current one")
		return
	}
	if err := auth.CheckPasswordPolicy(in.NewPassword, u.Username); err != nil {
		invalid(w, err.Error())
		return
	}
	h, err := auth.HashPassword(in.NewPassword)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.d.Store.Q.SetUserPassword(ctx, db.SetUserPasswordParams{ID: u.ID, PasswordHash: &h, PasswordChangeRequired: false}); err != nil {
		s.internalError(w, r, err)
		return
	}
	// Invalidate every other session of this user.
	_ = s.d.Store.Q.DeleteUserSessionsExcept(ctx, db.DeleteUserSessionsExceptParams{UserID: u.ID, IDHash: sessionFrom(ctx).IDHash})
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "auth.password_change", Target: "user:" + u.Username})
	u.PasswordChangeRequired = false
	s.transition(w, r, u, false)
}

// --- TOTP

// VerifyTotp implements apigen.ServerInterface (login MFA or step-up).
func (s *Server) VerifyTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, sess := userFrom(ctx), sessionFrom(ctx)
	var in apigen.TotpCode
	if !decode(w, r, &in) {
		return
	}
	if !s.settings.get(ctx).Security.AllowTotp || u.TotpSecret == nil {
		writeError(w, http.StatusForbidden, "forbidden", "TOTP is not available for this account")
		return
	}
	if !s.loginUserLimit.Allow("totp:" + u.Username) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts")
		return
	}
	secret, err := secretbox.Open(s.d.MasterKey, totpPurpose+":"+u.ID.String(), u.TotpSecret)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	step, err := auth.ValidateTOTP(secret, in.Code, s.d.Now(), u.TotpLastStep)
	if err == nil {
		// Atomic forward-only counter update closes the race between two
		// concurrent submissions of the same code.
		if n, uerr := s.d.Store.Q.SetTotpLastStep(ctx, db.SetTotpLastStepParams{ID: u.ID, TotpLastStep: step}); uerr != nil || n == 0 {
			err = auth.ErrTOTPInvalid
		}
	}
	if err != nil {
		s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "auth.mfa_failed", Details: map[string]any{"method": "totp"}})
		writeError(w, http.StatusUnauthorized, "unauthenticated", "invalid code")
		return
	}
	s.mfaSucceeded(w, r, u, sess, "totp")
}

func (s *Server) mfaSucceeded(w http.ResponseWriter, r *http.Request, u *db.User, sess *db.Session, method string) {
	ctx := r.Context()
	if sess.State == auth.StateActive {
		if err := s.d.Store.Q.SetSessionStepup(ctx, db.SetSessionStepupParams{IDHash: sess.IDHash, StepupAt: ptr(s.d.Now())}); err != nil {
			s.internalError(w, r, err)
			return
		}
		s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "auth.stepup", Details: map[string]any{"method": method}})
		writeJSON(w, http.StatusOK, apigen.LoginResult{State: apigen.SessionStateActive})
		return
	}
	s.transition(w, r, u, true)
}

// BeginTotpEnrollment implements apigen.ServerInterface.
func (s *Server) BeginTotpEnrollment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, sess := userFrom(ctx), sessionFrom(ctx)
	if !s.settings.get(ctx).Security.AllowTotp {
		writeError(w, http.StatusForbidden, "forbidden", "TOTP is disabled by policy; register a security key")
		return
	}
	if sess.State == auth.StateActive {
		if has, _, _ := s.hasFactors(ctx, u); has && !s.requireStepup(w, r) {
			return
		}
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	sealed, err := secretbox.Seal(s.d.MasterKey, totpPurpose+":"+u.ID.String(), secret)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.d.Store.Q.SetTotpPending(ctx, db.SetTotpPendingParams{ID: u.ID, TotpPendingSecret: sealed}); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, apigen.TotpEnrollment{
		Secret: auth.TOTPBase32(secret), OtpauthUrl: auth.TOTPURL("Stellwerk", u.Username, secret),
	})
}

// ConfirmTotpEnrollment implements apigen.ServerInterface.
func (s *Server) ConfirmTotpEnrollment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, sess := userFrom(ctx), sessionFrom(ctx)
	var in apigen.TotpCode
	if !decode(w, r, &in) {
		return
	}
	if u.TotpPendingSecret == nil {
		invalid(w, "no TOTP enrollment in progress")
		return
	}
	secret, err := secretbox.Open(s.d.MasterKey, totpPurpose+":"+u.ID.String(), u.TotpPendingSecret)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	step, err := auth.ValidateTOTP(secret, in.Code, s.d.Now(), 0)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "invalid code")
		return
	}
	if err := s.d.Store.Q.ActivateTotp(ctx, db.ActivateTotpParams{ID: u.ID, TotpLastStep: step}); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "auth.mfa_enroll", Details: map[string]any{"method": "totp"}})
	nu, err := s.d.Store.Q.GetUser(ctx, u.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if sess.State == auth.StateActive {
		writeJSON(w, http.StatusOK, apigen.LoginResult{State: apigen.SessionStateActive})
		return
	}
	s.transition(w, r, &nu, true)
}

// DisableTotp implements apigen.ServerInterface.
func (s *Server) DisableTotp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := userFrom(ctx)
	if !s.requireStepup(w, r) {
		return
	}
	if n, _ := s.d.Store.Q.CountWebauthnCredentials(ctx, u.ID); n == 0 && s.mfaRequired(ctx, u) {
		writeError(w, http.StatusConflict, "conflict", "MFA is required: register a security key before removing TOTP")
		return
	}
	if err := s.d.Store.Q.ClearTotp(ctx, u.ID); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "auth.mfa_remove", Details: map[string]any{"method": "totp"}})
	w.WriteHeader(http.StatusNoContent)
}

// --- WebAuthn

func (s *Server) waUser(ctx context.Context, u *db.User) (*auth.WebAuthnUser, error) {
	rows, err := s.d.Store.Q.ListWebauthnCredentials(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	return auth.LoadWebAuthnUser(*u, rows)
}

func (s *Server) saveCeremony(ctx context.Context, sess *db.Session, kind string, data *webauthn.SessionData) error {
	b, err := json.Marshal(auth.Ceremony{Kind: kind, Data: *data})
	if err != nil {
		return err
	}
	return s.d.Store.Q.SetSessionWebauthn(ctx, db.SetSessionWebauthnParams{IDHash: sess.IDHash, WebauthnSession: b})
}

func (s *Server) loadCeremony(ctx context.Context, sess *db.Session, kind string) (*webauthn.SessionData, error) {
	if len(sess.WebauthnSession) == 0 {
		return nil, errors.New("no ceremony")
	}
	var c auth.Ceremony
	if err := json.Unmarshal(sess.WebauthnSession, &c); err != nil || c.Kind != kind {
		return nil, errors.New("no ceremony")
	}
	_ = s.d.Store.Q.SetSessionWebauthn(ctx, db.SetSessionWebauthnParams{IDHash: sess.IDHash, WebauthnSession: nil})
	if !c.Data.Expires.IsZero() && s.d.Now().After(c.Data.Expires) {
		return nil, errors.New("ceremony expired")
	}
	return &c.Data, nil
}

// BeginWebauthnLogin implements apigen.ServerInterface.
func (s *Server) BeginWebauthnLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, sess := userFrom(ctx), sessionFrom(ctx)
	if s.d.WebAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "WebAuthn not configured")
		return
	}
	wu, err := s.waUser(ctx, u)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(wu.Credentials) == 0 {
		writeError(w, http.StatusForbidden, "forbidden", "no security key registered")
		return
	}
	assertion, data, err := s.d.WebAuthn.BeginLogin(wu)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.saveCeremony(ctx, sess, "login", data); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

// FinishWebauthnLogin implements apigen.ServerInterface.
func (s *Server) FinishWebauthnLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, sess := userFrom(ctx), sessionFrom(ctx)
	if s.d.WebAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "WebAuthn not configured")
		return
	}
	data, err := s.loadCeremony(ctx, sess, "login")
	if err != nil {
		invalid(w, "no WebAuthn login in progress")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		invalid(w, "invalid credential")
		return
	}
	wu, err := s.waUser(ctx, u)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	cred, err := s.d.WebAuthn.ValidateLogin(wu, *data, parsed)
	if err != nil {
		s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "auth.mfa_failed", Details: map[string]any{"method": "webauthn"}})
		writeError(w, http.StatusUnauthorized, "unauthenticated", "security key verification failed")
		return
	}
	if cred.Authenticator.CloneWarning {
		s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "auth.webauthn_clone_warning"})
		writeError(w, http.StatusUnauthorized, "unauthenticated", "security key signature counter regressed (possible clone)")
		return
	}
	cb, _ := json.Marshal(cred)
	_ = s.d.Store.Q.UpdateWebauthnCredentialUse(ctx, db.UpdateWebauthnCredentialUseParams{
		UserID: u.ID, CredentialID: cred.ID, Credential: cb, SignCount: int64(cred.Authenticator.SignCount),
	})
	s.mfaSucceeded(w, r, u, sess, "webauthn")
}

// BeginWebauthnRegistration implements apigen.ServerInterface.
func (s *Server) BeginWebauthnRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, sess := userFrom(ctx), sessionFrom(ctx)
	if s.d.WebAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "WebAuthn not configured")
		return
	}
	if sess.State == auth.StateActive {
		if has, _, _ := s.hasFactors(ctx, u); has && !s.requireStepup(w, r) {
			return
		}
	}
	wu, err := s.waUser(ctx, u)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	creation, data, err := s.d.WebAuthn.BeginRegistration(wu, webauthn.WithExclusions(wu.CredentialDescriptors()))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.saveCeremony(ctx, sess, "register", data); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

// FinishWebauthnRegistration implements apigen.ServerInterface.
func (s *Server) FinishWebauthnRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, sess := userFrom(ctx), sessionFrom(ctx)
	var in struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		invalid(w, "name must be 1-64 characters")
		return
	}
	data, err := s.loadCeremony(ctx, sess, "register")
	if err != nil {
		invalid(w, "no registration in progress")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(in.Credential)
	if err != nil {
		invalid(w, "invalid credential")
		return
	}
	wu, err := s.waUser(ctx, u)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	cred, err := s.d.WebAuthn.CreateCredential(wu, *data, parsed)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "registration verification failed")
		return
	}
	cb, _ := json.Marshal(cred)
	if err := s.d.Store.Q.CreateWebauthnCredential(ctx, db.CreateWebauthnCredentialParams{
		ID: ids.NewUUID(), UserID: u.ID, CredentialID: cred.ID, Credential: cb, Name: validateText(in.Name), SignCount: int64(cred.Authenticator.SignCount),
	}); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "auth.mfa_enroll", Details: map[string]any{"method": "webauthn", "name": in.Name}})
	if sess.State == auth.StateActive {
		writeJSON(w, http.StatusOK, apigen.LoginResult{State: apigen.SessionStateActive})
		return
	}
	s.transition(w, r, u, true)
}

// ListWebauthnCredentials implements apigen.ServerInterface.
func (s *Server) ListWebauthnCredentials(w http.ResponseWriter, r *http.Request) {
	rows, err := s.d.Store.Q.ListWebauthnCredentials(r.Context(), userFrom(r.Context()).ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apigen.WebauthnCredential, 0, len(rows))
	for _, c := range rows {
		out = append(out, apigen.WebauthnCredential{Id: c.ID, Name: c.Name, CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// DeleteWebauthnCredential implements apigen.ServerInterface.
func (s *Server) DeleteWebauthnCredential(w http.ResponseWriter, r *http.Request, credentialID apigen.CredentialId) {
	ctx := r.Context()
	u := userFrom(ctx)
	if !s.requireStepup(w, r) {
		return
	}
	n, _ := s.d.Store.Q.CountWebauthnCredentials(ctx, u.ID)
	if n <= 1 && u.TotpSecret == nil && s.mfaRequired(ctx, u) {
		writeError(w, http.StatusConflict, "conflict", "MFA is required: this is your last factor")
		return
	}
	deleted, err := s.d.Store.Q.DeleteWebauthnCredential(ctx, db.DeleteWebauthnCredentialParams{ID: credentialID, UserID: u.ID})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if deleted == 0 {
		notFound(w)
		return
	}
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "auth.mfa_remove", Details: map[string]any{"method": "webauthn"}})
	w.WriteHeader(http.StatusNoContent)
}

// stepupOrAdmin is a helper for user administration endpoints.
func (s *Server) adminWithStepup(w http.ResponseWriter, r *http.Request) bool {
	return requireGlobal(w, r, rbac.AdminUsers) && s.requireStepup(w, r)
}

var _ = time.Second
