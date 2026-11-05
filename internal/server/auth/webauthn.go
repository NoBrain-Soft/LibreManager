package auth

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// NewWebAuthn configures the relying party from the public URL.
func NewWebAuthn(publicURL string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(publicURL)
	if err != nil {
		return nil, fmt.Errorf("auth: webauthn: %w", err)
	}
	origin := u.Scheme + "://" + u.Host
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Stellwerk",
		RPID:          u.Hostname(),
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
			ResidentKey:      protocol.ResidentKeyRequirementDiscouraged,
		},
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: webauthn: %w", err)
	}
	return w, nil
}

// WebAuthnUser adapts a user + credentials to webauthn.User.
type WebAuthnUser struct {
	ID          uuid.UUID
	Name        string
	Display     string
	Credentials []webauthn.Credential
}

// WebAuthnID implements webauthn.User.
func (u *WebAuthnUser) WebAuthnID() []byte { return u.ID[:] }

// WebAuthnName implements webauthn.User.
func (u *WebAuthnUser) WebAuthnName() string { return u.Name }

// WebAuthnDisplayName implements webauthn.User.
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.Display != "" {
		return u.Display
	}
	return u.Name
}

// WebAuthnCredentials implements webauthn.User.
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// LoadWebAuthnUser builds the adapter from DB rows.
func LoadWebAuthnUser(user db.User, rows []db.WebauthnCredential) (*WebAuthnUser, error) {
	wu := &WebAuthnUser{ID: user.ID, Name: user.Username, Display: user.DisplayName}
	for _, r := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal(r.Credential, &c); err != nil {
			return nil, fmt.Errorf("auth: credential %s: %w", r.ID, err)
		}
		wu.Credentials = append(wu.Credentials, c)
	}
	return wu, nil
}

// CredentialDescriptors lists the user's credentials (for exclusion lists).
func (u *WebAuthnUser) CredentialDescriptors() []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(u.Credentials))
	for _, c := range u.Credentials {
		out = append(out, c.Descriptor())
	}
	return out
}

// Ceremony is stored in sessions.webauthn_session between begin and finish.
type Ceremony struct {
	Kind string               `json:"kind"` // "login" or "register"
	Data webauthn.SessionData `json:"data"`
}
