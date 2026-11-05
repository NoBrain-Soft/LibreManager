package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nobrain-soft/libremanager/internal/common/secretbox"
	"github.com/nobrain-soft/libremanager/internal/common/validate"
	"github.com/nobrain-soft/libremanager/internal/server/api/apigen"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/rbac"
	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

const (
	settingsKey       = "settings"
	secretsKey        = "settings.secrets"
	secretsPurpose    = "settings/secrets"
	settingsCacheTime = 10 * time.Second
)

// notificationSecrets are write-only values, sealed with the API master key.
type notificationSecrets struct {
	SMTPPassword   string            `json:"smtp_password"`
	WebhookSecrets map[string]string `json:"webhook_secrets"`
}

// DefaultSettings reflects the owner's decisions (docs/adr/0009, §12):
// local accounts with MFA, metrics 30 d, audit ≥ 1 y, recordings 90 d,
// mail + webhook notifications optional, configurable shell identity.
func DefaultSettings() apigen.Settings {
	var s apigen.Settings
	s.Session.IdleMinutes = 30
	s.Session.AbsoluteHours = 8
	s.Security.MfaRequired = true
	s.Security.AllowTotp = true
	s.Retention.MetricsDays = 30
	s.Retention.AuditDays = 400
	s.Retention.RecordingsDays = 90
	s.Retention.JobOutputDays = 90
	s.Notifications.Email.Enabled = false
	s.Notifications.Webhooks = []apigen.WebhookTarget{}
	s.Shell = apigen.ShellSettings{
		DefaultIdentity: apigen.Choose, SharedAccount: "ops", AllowRoot: false,
		MaxDurationMinutes: 240, IdleTimeoutMinutes: 15,
	}
	return s
}

type settingsStore struct {
	st  *store.Store
	key *secretbox.Key

	mu      sync.Mutex
	cached  *apigen.Settings
	expires time.Time
}

func (ss *settingsStore) get(ctx context.Context) apigen.Settings {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.cached != nil && time.Now().Before(ss.expires) {
		return *ss.cached
	}
	s := DefaultSettings()
	if raw, err := ss.st.Q.GetSetting(ctx, settingsKey); err == nil {
		_ = json.Unmarshal(raw, &s)
	}
	if s.Notifications.Webhooks == nil {
		s.Notifications.Webhooks = []apigen.WebhookTarget{}
	}
	ss.cached = &s
	ss.expires = time.Now().Add(settingsCacheTime)
	return s
}

func (ss *settingsStore) secrets(ctx context.Context) notificationSecrets {
	var sec notificationSecrets
	raw, err := ss.st.Q.GetSetting(ctx, secretsKey)
	if err != nil {
		return sec
	}
	var sealed []byte
	if json.Unmarshal(raw, &sealed) != nil {
		return sec
	}
	pt, err := secretbox.Open(ss.key, secretsPurpose, sealed)
	if err != nil {
		return sec
	}
	_ = json.Unmarshal(pt, &sec)
	return sec
}

func (ss *settingsStore) put(ctx context.Context, q *db.Queries, s apigen.Settings, sec notificationSecrets) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := q.PutSetting(ctx, db.PutSettingParams{Key: settingsKey, Value: b}); err != nil {
		return err
	}
	pt, err := json.Marshal(sec)
	if err != nil {
		return err
	}
	sealed, err := secretbox.Seal(ss.key, secretsPurpose, pt)
	if err != nil {
		return err
	}
	sb, _ := json.Marshal(sealed)
	if err := q.PutSetting(ctx, db.PutSettingParams{Key: secretsKey, Value: sb}); err != nil {
		return err
	}
	ss.mu.Lock()
	ss.cached = nil
	ss.mu.Unlock()
	return nil
}

func redact(s apigen.Settings) apigen.Settings {
	s.Notifications.Email.SmtpPassword = ptr("")
	hooks := make([]apigen.WebhookTarget, len(s.Notifications.Webhooks))
	for i, h := range s.Notifications.Webhooks {
		h.Secret = ptr("")
		hooks[i] = h
	}
	s.Notifications.Webhooks = hooks
	return s
}

// GetSettings implements apigen.ServerInterface.
func (s *Server) GetSettings(w http.ResponseWriter, r *http.Request) {
	if !requireGlobal(w, r, rbac.AdminSettings) {
		return
	}
	writeJSON(w, http.StatusOK, redact(s.settings.get(r.Context())))
}

func validateSettings(in apigen.Settings) error {
	switch {
	case in.Session.IdleMinutes < 5 || in.Session.IdleMinutes > 1440,
		in.Session.AbsoluteHours < 1 || in.Session.AbsoluteHours > 168:
		return fmt.Errorf("session timeouts out of range")
	case in.Retention.AuditDays < 365:
		return fmt.Errorf("audit retention must be at least 365 days")
	case in.Retention.MetricsDays < 1 || in.Retention.RecordingsDays < 1 || in.Retention.JobOutputDays < 1:
		return fmt.Errorf("retention must be positive")
	case in.Shell.SharedAccount != "" && !validate.AccountName(in.Shell.SharedAccount):
		return fmt.Errorf("invalid shared account name")
	case in.Shell.MaxDurationMinutes < 1 || in.Shell.MaxDurationMinutes > 1440 || in.Shell.IdleTimeoutMinutes < 1:
		return fmt.Errorf("shell limits out of range")
	}
	switch in.Shell.DefaultIdentity {
	case apigen.Shared, apigen.PerUser, apigen.Choose:
	default:
		return fmt.Errorf("invalid shell identity mode")
	}
	if in.Shell.DefaultIdentity == apigen.Shared && in.Shell.SharedAccount == "" {
		return fmt.Errorf("shared identity needs a shared account")
	}
	if len(in.Notifications.Webhooks) > 20 {
		return fmt.Errorf("too many webhooks")
	}
	names := map[string]bool{}
	for _, h := range in.Notifications.Webhooks {
		u, err := url.Parse(h.Url)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("webhook %q: URL must be https://", h.Name)
		}
		if h.Name == "" || names[h.Name] {
			return fmt.Errorf("webhook names must be unique and non-empty")
		}
		names[h.Name] = true
	}
	e := in.Notifications.Email
	if e.Enabled {
		if e.SmtpHost == nil || *e.SmtpHost == "" || e.From == nil || *e.From == "" || e.To == nil || len(*e.To) == 0 {
			return fmt.Errorf("email notifications need smtp_host, from and to")
		}
		if strings.ContainsAny(*e.From+strings.Join(*e.To, ""), "\r\n") {
			return fmt.Errorf("invalid email address")
		}
	}
	return nil
}

// UpdateSettings implements apigen.ServerInterface.
func (s *Server) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if !requireGlobal(w, r, rbac.AdminSettings) || !s.requireStepup(w, r) {
		return
	}
	var in apigen.Settings
	if !decode(w, r, &in) {
		return
	}
	if in.Notifications.Webhooks == nil {
		in.Notifications.Webhooks = []apigen.WebhookTarget{}
	}
	if err := validateSettings(in); err != nil {
		invalid(w, err.Error())
		return
	}
	ctx := r.Context()
	sec := s.settings.secrets(ctx)
	if p := in.Notifications.Email.SmtpPassword; p != nil && *p != "" {
		sec.SMTPPassword = *p
	}
	newSecrets := map[string]string{}
	for i, h := range in.Notifications.Webhooks {
		if h.Secret != nil && *h.Secret != "" {
			newSecrets[h.Name] = *h.Secret
		} else if old, ok := sec.WebhookSecrets[h.Name]; ok {
			newSecrets[h.Name] = old
		}
		in.Notifications.Webhooks[i].Secret = nil
	}
	sec.WebhookSecrets = newSecrets
	in.Notifications.Email.SmtpPassword = nil
	err := s.d.Store.InTx(ctx, func(q *db.Queries, _ pgxTx) error {
		if err := s.settings.put(ctx, q, in, sec); err != nil {
			return err
		}
		_, err := s.d.Audit.LogTx(ctx, q, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "settings.update", Target: "settings"})
		return err
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, redact(s.settings.get(ctx)))
}

// GetSystemInfo implements apigen.ServerInterface.
func (s *Server) GetSystemInfo(w http.ResponseWriter, r *http.Request) {
	info := apigen.SystemInfo{
		Version: versionString(), CaFingerprint: s.d.CAFP, AgentEndpoint: s.d.Cfg.AgentEndpoint, PublicUrl: s.d.Cfg.PublicURL,
	}
	if counts, err := s.d.Store.Q.DashboardCounts(r.Context()); err == nil {
		info.ConnectedAgents = ptr(int(counts.Connected))
	}
	writeJSON(w, http.StatusOK, info)
}
