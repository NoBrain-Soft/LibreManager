package audit

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// cursorKey stores the last exported audit id.
const cursorKey = "audit.export.cursor"

// Exporter forwards audit entries to a SIEM as RFC 5424 syslog messages
// over TLS with RFC 5425 octet-counting framing (ARCHITECTURE.md §6.6, T9).
// Each message carries the entry's chain hash, so the SIEM holds an
// independent anchor of the chain.
type Exporter struct {
	Store *store.Store
	// Addr is host:port of the syslog TLS receiver.
	Addr string
	// RootCAs verifies the receiver (nil = system roots). TLS verification
	// is always on.
	RootCAs  *x509.CertPool
	Hostname string
	Interval time.Duration
}

// LoadCA reads a PEM bundle for the receiver.
func LoadCA(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-provided path
	if err != nil {
		return nil, fmt.Errorf("audit export: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("audit export: no certificates in %s", path)
	}
	return pool, nil
}

// Run exports continuously until ctx is done.
func (e *Exporter) Run(ctx context.Context) {
	iv := e.Interval
	if iv == 0 {
		iv = 10 * time.Second
	}
	backoff := iv
	for ctx.Err() == nil {
		n, err := e.ExportOnce(ctx)
		if err != nil {
			slog.WarnContext(ctx, "audit export failed", "addr", e.Addr, "err", err)
			backoff = min(backoff*2, 5*time.Minute)
		} else {
			backoff = iv
			if n > 0 {
				slog.DebugContext(ctx, "audit entries exported", "count", n)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

func (e *Exporter) cursor(ctx context.Context) int64 {
	raw, err := e.Store.Q.GetSetting(ctx, cursorKey)
	if err != nil {
		return 0
	}
	var id int64
	_ = json.Unmarshal(raw, &id)
	return id
}

// ExportOnce sends all entries after the cursor and advances it. It
// returns the number of entries sent.
func (e *Exporter) ExportOnce(ctx context.Context) (int, error) {
	last := e.cursor(ctx)
	rows, err := e.Store.Q.AuditBatchAfter(ctx, db.AuditBatchAfterParams{ID: last, Limit: 1000})
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	host, _, err := net.SplitHostPort(e.Addr)
	if err != nil {
		return 0, fmt.Errorf("audit export: %w", err)
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: e.RootCAs, ServerName: host}}
	conn, err := d.DialContext(ctx, "tcp", e.Addr)
	if err != nil {
		return 0, fmt.Errorf("audit export: dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	w := bufio.NewWriter(conn)
	for _, r := range rows {
		msg := FormatRFC5424(e.Hostname, r)
		if _, err := fmt.Fprintf(w, "%d %s", len(msg), msg); err != nil {
			return 0, fmt.Errorf("audit export: write: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return 0, fmt.Errorf("audit export: flush: %w", err)
	}
	b, _ := json.Marshal(rows[len(rows)-1].ID)
	if err := e.Store.Q.PutSetting(ctx, db.PutSettingParams{Key: cursorKey, Value: b}); err != nil {
		return 0, fmt.Errorf("audit export: cursor: %w", err)
	}
	return len(rows), nil
}

func sdEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(s)
}

func headerField(s string, max int) string {
	if s == "" {
		return "-"
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(out) < max; i++ {
		if c := s[i]; c > 32 && c < 127 {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return string(out)
}

// FormatRFC5424 renders one entry. PRI 85 = facility authpriv(10) × 8 +
// severity notice(5). Structured data uses a private enterprise id.
func FormatRFC5424(hostname string, r db.AuditLog) string {
	sd := fmt.Sprintf(`[stellwerk@32473 id="%d" actor="%s" ip="%s" action="%s" target="%s" hash="%s" prev="%s"]`,
		r.ID, sdEscape(r.Actor), sdEscape(r.ActorIp), sdEscape(r.Action), sdEscape(r.Target), HexHash(r.Hash), HexHash(r.PrevHash))
	return fmt.Sprintf("<85>1 %s %s stellwerk - %s %s %s",
		r.Ts.UTC().Format("2006-01-02T15:04:05.000000Z"), headerField(hostname, 255), headerField(r.Action, 32), sd, string(r.Details))
}

// ParseOctetFrame reads one RFC 5425 frame (for tests / receivers).
func ParseOctetFrame(r *bufio.Reader) (string, error) {
	lenStr, err := r.ReadString(' ')
	if err != nil {
		return "", err //nolint:wrapcheck // io.EOF recognizable
	}
	n, err := strconv.Atoi(strings.TrimSpace(lenStr))
	if err != nil || n <= 0 || n > 1<<20 {
		return "", fmt.Errorf("audit export: bad frame length %q", lenStr)
	}
	buf := make([]byte, n)
	if _, err := ioReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
