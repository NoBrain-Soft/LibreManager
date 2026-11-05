// Package notify delivers alert notifications by email (SMTP) and generic
// webhooks (HMAC-signed JSON). Both channels are optional (owner decision).
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Message is one notification.
type Message struct {
	Subject  string            `json:"subject"`
	Text     string            `json:"text"`
	Severity string            `json:"severity"`
	Status   string            `json:"status"`
	Alert    string            `json:"alert"`
	Host     string            `json:"host,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Time     time.Time         `json:"time"`
	Link     string            `json:"link,omitempty"`
}

// SMTP configures email delivery.
type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	StartTLS bool
	From     string
	To       []string
}

func headerSafe(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }

// SendEmail sends m via SMTP. TLS certificates are always verified; with
// StartTLS the upgrade is mandatory (no silent plaintext fallback). Port
// 465 uses implicit TLS.
func SendEmail(ctx context.Context, c SMTP, m Message) error {
	if c.Host == "" || c.From == "" || len(c.To) == 0 {
		return errors.New("notify: incomplete SMTP settings")
	}
	port := c.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(port))
	d := &net.Dialer{Timeout: 15 * time.Second}
	tlsCfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	var err error
	if port == 465 {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("notify: smtp dial: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("notify: smtp: %w", err)
	}
	defer cl.Close()
	if port != 465 && c.StartTLS {
		if err := cl.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("notify: starttls: %w", err)
		}
	}
	if c.Username != "" {
		// smtp.PlainAuth refuses to send credentials over unencrypted
		// connections to non-localhost servers.
		if err := cl.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return fmt.Errorf("notify: smtp auth: %w", err)
		}
	}
	if err := cl.Mail(c.From); err != nil {
		return fmt.Errorf("notify: smtp: %w", err)
	}
	for _, rcpt := range c.To {
		if err := cl.Rcpt(rcpt); err != nil {
			return fmt.Errorf("notify: smtp rcpt: %w", err)
		}
	}
	wc, err := cl.Data()
	if err != nil {
		return fmt.Errorf("notify: smtp: %w", err)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\nAuto-Submitted: auto-generated\r\n\r\n",
		headerSafe(c.From), headerSafe(strings.Join(c.To, ", ")), mime.QEncoding.Encode("utf-8", headerSafe(m.Subject)),
		time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString(strings.ReplaceAll(m.Text, "\n", "\r\n"))
	b.WriteString("\r\n")
	if _, err := wc.Write(b.Bytes()); err != nil {
		return fmt.Errorf("notify: smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("notify: smtp: %w", err)
	}
	return cl.Quit()
}

// Webhook configures a webhook target.
type Webhook struct {
	Name   string
	URL    string
	Secret string
}

// Signature computes the X-Stellwerk-Signature header value.
func Signature(secret string, ts string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// SendWebhook POSTs m as JSON; with a secret it adds
// X-Stellwerk-Timestamp and X-Stellwerk-Signature = HMAC-SHA256(secret, ts "." body).
func SendWebhook(ctx context.Context, client *http.Client, h Webhook, m Message) error {
	if !strings.HasPrefix(h.URL, "https://") {
		return errors.New("notify: webhook URL must be https")
	}
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Stellwerk-Notifier/1")
	if h.Secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("X-Stellwerk-Timestamp", ts)
		req.Header.Set("X-Stellwerk-Signature", Signature(h.Secret, ts, body))
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: webhook %s: %w", h.Name, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("notify: webhook %s: status %d", h.Name, resp.StatusCode)
	}
	return nil
}

// SeverityRank orders severities for min_severity filtering.
func SeverityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 3
	case "warning", "high", "medium":
		return 2
	default:
		return 1
	}
}
