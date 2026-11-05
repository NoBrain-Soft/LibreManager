// Package journal is a minimal writer for the systemd-journald native
// protocol (one datagram per entry on /run/systemd/journal/socket).
//
// The agent core and the root helper use it to leave a forensic trail of
// every job on the host itself (ARCHITECTURE.md §6.3, CLAUDE.md rule 9).
// When the journal socket is absent or a send fails, the entry is written
// to the fallback writer (stderr by default) as a single escaped line, so
// an entry is never silently lost.
package journal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// DefaultSocket is journald's native protocol socket.
const DefaultSocket = "/run/systemd/journal/socket"

// Syslog priorities (RFC 5424 severities) used for PRIORITY.
const (
	PriErr     = 3
	PriWarning = 4
	PriNotice  = 5
	PriInfo    = 6
	PriDebug   = 7
)

// Limits keep every entry well below the AF_UNIX datagram limit.
const (
	maxFieldValue = 16 << 10
	maxFields     = 64
	maxFieldName  = 64
)

// ErrInvalidField is returned for field names journald would reject.
var ErrInvalidField = errors.New("journal: invalid field name")

// Writer sends one structured entry. Field names must be uppercase
// letters, digits and underscores, must not start with a digit or an
// underscore, and must not be MESSAGE, PRIORITY or SYSLOG_IDENTIFIER
// (those are set by the writer).
type Writer interface {
	Send(priority int, msg string, fields map[string]string) error
}

// Client implements Writer.
type Client struct {
	// Identifier is SYSLOG_IDENTIFIER (e.g. "stellwerk-agent").
	Identifier string
	// Socket defaults to DefaultSocket.
	Socket string
	// Fallback receives entries that could not be sent to journald.
	// Defaults to os.Stderr.
	Fallback io.Writer

	mu   sync.Mutex
	fd   int
	open bool
}

// New returns a client for identifier using the default socket.
func New(identifier string) *Client {
	return &Client{Identifier: identifier}
}

// Send implements Writer.
func (c *Client) Send(priority int, msg string, fields map[string]string) error {
	if priority < 0 || priority > 7 {
		priority = PriInfo
	}
	if len(fields) > maxFields {
		return fmt.Errorf("journal: too many fields (%d)", len(fields))
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		if !ValidFieldName(k) || reserved(k) {
			return fmt.Errorf("%w: %q", ErrInvalidField, k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b []byte
	b = appendField(b, "PRIORITY", strconv.Itoa(priority))
	b = appendField(b, "SYSLOG_IDENTIFIER", c.Identifier)
	b = appendField(b, "MESSAGE", msg)
	for _, k := range keys {
		b = appendField(b, k, fields[k])
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.sendLocked(b); err == nil {
		return nil
	}
	return c.fallbackLocked(priority, msg, keys, fields)
}

func (c *Client) sendLocked(b []byte) error {
	if !c.open {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("journal: socket: %w", err)
		}
		c.fd, c.open = fd, true
	}
	sock := c.Socket
	if sock == "" {
		sock = DefaultSocket
	}
	if err := unix.Sendto(c.fd, b, 0, &unix.SockaddrUnix{Name: sock}); err != nil {
		return fmt.Errorf("journal: send: %w", err)
	}
	return nil
}

func (c *Client) fallbackLocked(priority int, msg string, keys []string, fields map[string]string) error {
	w := c.Fallback
	if w == nil {
		w = os.Stderr
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "<%d>%s: %s", priority, c.Identifier, strconv.Quote(clip(msg)))
	for _, k := range keys {
		fmt.Fprintf(&sb, " %s=%s", k, strconv.Quote(clip(fields[k])))
	}
	sb.WriteByte('\n')
	if _, err := io.WriteString(w, sb.String()); err != nil {
		return fmt.Errorf("journal: fallback write: %w", err)
	}
	return nil
}

// Close releases the socket.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open {
		err := unix.Close(c.fd)
		c.open = false
		if err != nil {
			return fmt.Errorf("journal: close: %w", err)
		}
	}
	return nil
}

// ValidFieldName reports whether name is acceptable to journald as a
// user-supplied field.
func ValidFieldName(name string) bool {
	if name == "" || len(name) > maxFieldName || name[0] == '_' || (name[0] >= '0' && name[0] <= '9') {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '_' {
			return false
		}
	}
	return true
}

func reserved(k string) bool {
	return k == "MESSAGE" || k == "PRIORITY" || k == "SYSLOG_IDENTIFIER"
}

func clip(v string) string {
	if len(v) > maxFieldValue {
		return v[:maxFieldValue]
	}
	return v
}

// appendField encodes one field. Values containing a newline use the
// binary form: NAME '\n' <uint64 LE length> <value> '\n'.
func appendField(b []byte, name, value string) []byte {
	value = clip(value)
	if !strings.ContainsRune(value, '\n') {
		b = append(b, name...)
		b = append(b, '=')
		b = append(b, value...)
		return append(b, '\n')
	}
	b = append(b, name...)
	b = append(b, '\n')
	b = binary.LittleEndian.AppendUint64(b, uint64(len(value)))
	b = append(b, value...)
	return append(b, '\n')
}
