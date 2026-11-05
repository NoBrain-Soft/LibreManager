package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nobrain-soft/libremanager/internal/server/api/apigen"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/notify"
	"github.com/nobrain-soft/libremanager/internal/server/rbac"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// RunBackground runs the event hub, notifier and retention jobs until ctx
// is done.
func (s *Server) RunBackground(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { s.d.Hub.Run(ctx, s.d.Store) })
	wg.Go(func() { s.loop(ctx, 15*time.Second, s.notifyPending) })
	wg.Go(func() { s.loop(ctx, time.Hour, s.retention) })
	if err := s.d.Store.Q.CloseDanglingShellSessions(ctx); err != nil {
		slog.WarnContext(ctx, "close dangling shell sessions", "err", err)
	}
	wg.Wait()
}

func (s *Server) loop(ctx context.Context, every time.Duration, fn func(context.Context)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		fn(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) messageFor(a db.ListUnnotifiedAlertsRow) notify.Message {
	verb := "FIRING"
	if a.Status == "resolved" {
		verb = "RESOLVED"
	}
	host := a.Hostname
	subject := fmt.Sprintf("[Stellwerk %s] %s", verb, a.Name)
	if host != "" {
		subject += " on " + host
	}
	link := s.d.Cfg.PublicURL + "/alerts"
	if a.HostID != nil {
		link = s.d.Cfg.PublicURL + "/hosts/" + a.HostID.String()
	}
	text := fmt.Sprintf("%s\n\nAlert:    %s\nStatus:   %s\nSeverity: %s\nHost:     %s\nSince:    %s\n\n%s\n",
		a.Summary, a.Name, a.Status, a.Severity, host, a.StartsAt.UTC().Format(time.RFC3339), link)
	return notify.Message{Subject: subject, Text: text, Severity: a.Severity, Status: a.Status, Alert: a.Name, Host: host,
		Time: a.UpdatedAt, Link: link}
}

func (s *Server) deliver(ctx context.Context, m notify.Message, onlyWebhook string) []error {
	st := s.settings.get(ctx)
	sec := s.settings.secrets(ctx)
	var errs []error
	e := st.Notifications.Email
	if e.Enabled && onlyWebhook == "" {
		cfg := notify.SMTP{Host: deref(e.SmtpHost), Port: deref(e.SmtpPort), Username: deref(e.SmtpUsername),
			Password: sec.SMTPPassword, StartTLS: deref(e.Starttls), From: deref(e.From), To: deref(e.To)}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := notify.SendEmail(cctx, cfg, m); err != nil {
			errs = append(errs, err)
		}
		cancel()
	}
	client := &http.Client{Timeout: 15 * time.Second}
	for _, h := range st.Notifications.Webhooks {
		if !h.Enabled || (onlyWebhook != "" && h.Name != onlyWebhook) {
			continue
		}
		if h.MinSeverity != nil && notify.SeverityRank(m.Severity) < notify.SeverityRank(string(*h.MinSeverity)) {
			continue
		}
		if err := notify.SendWebhook(ctx, client, notify.Webhook{Name: h.Name, URL: h.Url, Secret: sec.WebhookSecrets[h.Name]}, m); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (s *Server) notifyPending(ctx context.Context) {
	rows, err := s.d.Store.Q.ListUnnotifiedAlerts(ctx)
	if err != nil {
		slog.WarnContext(ctx, "list unnotified alerts", "err", err)
		return
	}
	for _, a := range rows {
		for _, err := range s.deliver(ctx, s.messageFor(a), "") {
			slog.WarnContext(ctx, "notification failed", "alert", a.Name, "err", err)
		}
		// Mark even on failure: alerts stay visible in the UI; retry storms
		// against a broken SMTP server help nobody.
		_ = s.d.Store.Q.MarkAlertNotified(ctx, a.ID)
	}
}

// TestNotification implements apigen.ServerInterface.
func (s *Server) TestNotification(w http.ResponseWriter, r *http.Request) {
	if !requireGlobal(w, r, rbac.AdminSettings) {
		return
	}
	var in apigen.NotificationTestRequest
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	m := notify.Message{Subject: "[Stellwerk] Test notification", Text: "This is a test notification sent by " + userFrom(ctx).Username + ".\n",
		Severity: "info", Status: "test", Alert: "Test", Time: s.d.Now()}
	var errs []error
	switch in.Channel {
	case apigen.Email:
		st := s.settings.get(ctx)
		if !st.Notifications.Email.Enabled {
			invalid(w, "email notifications are disabled")
			return
		}
		errs = s.deliver(ctx, m, "")
		// deliver() also hits webhooks; only report email errors.
		var mailErrs []error
		for _, e := range errs {
			if strings.Contains(e.Error(), "smtp") {
				mailErrs = append(mailErrs, e)
			}
		}
		errs = mailErrs
	case apigen.Webhook:
		name := deref(in.WebhookName)
		if name == "" {
			invalid(w, "webhook_name required")
			return
		}
		errs = s.deliver(ctx, m, name)
	default:
		invalid(w, "unknown channel")
		return
	}
	if len(errs) > 0 {
		writeError(w, http.StatusBadGateway, "unavailable", errs[0].Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) retention(ctx context.Context) {
	st := s.settings.get(ctx)
	q := s.d.Store.Q
	if n, err := q.DeleteExpiredSessions(ctx, int32(st.Session.IdleMinutes)); err == nil && n > 0 { //nolint:gosec // bounded setting
		slog.DebugContext(ctx, "expired sessions removed", "count", n)
	}
	if n, err := q.DeleteOldJobOutput(ctx, int32(st.Retention.JobOutputDays)); err == nil && n > 0 { //nolint:gosec // bounded setting
		slog.InfoContext(ctx, "old job output removed", "rows", n)
	}
	days := max(st.Retention.AuditDays, 365)
	err := s.d.Store.InTx(ctx, func(tq *db.Queries, _ pgxTx) error {
		if err := tq.EnableAuditRetention(ctx); err != nil {
			return err
		}
		n, err := tq.DeleteOldAudit(ctx, int32(days)) //nolint:gosec // bounded setting
		if err != nil || n == 0 {
			return err
		}
		_, err = s.d.Audit.LogTx(ctx, tq, audit.Entry{Actor: "system", Action: "audit.retention", Details: map[string]any{"deleted": n, "days": days}})
		return err
	})
	if err != nil {
		slog.WarnContext(ctx, "audit retention", "err", err)
	}
	old, err := q.ListOldRecordings(ctx, int32(st.Retention.RecordingsDays)) //nolint:gosec // bounded setting
	if err != nil {
		return
	}
	for _, o := range old {
		p := filepath.Join(s.d.Cfg.RecordingsDir(), filepath.Base(o.RecordingRef))
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			continue
		}
		_ = q.ClearRecordingRef(ctx, o.ID)
	}
}
