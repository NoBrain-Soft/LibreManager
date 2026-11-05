// Package shell records interactive sessions as asciicast v2, encrypted at
// rest in independently sealed chunks (ARCHITECTURE.md §6.5).
package shell

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/secretbox"
)

const (
	chunkSize     = 64 << 10
	flushInterval = 5 * time.Second
	// MaxRecordingBytes caps a single recording (plaintext).
	MaxRecordingBytes = 256 << 20
)

func purpose(sessionID string, n uint64) string {
	return "recording:" + sessionID + ":" + strconv.FormatUint(n, 10)
}

// Recorder writes an encrypted asciicast v2 file.
type Recorder struct {
	mu        sync.Mutex
	f         *os.File
	key       *secretbox.Key
	sessionID string
	start     time.Time
	buf       bytes.Buffer
	n         uint64
	h         interface {
		io.Writer
		Sum([]byte) []byte
	}
	total     int64
	lastFlush time.Time
	truncated bool
	Path      string
}

// NewRecorder creates <dir>/<sessionID>.cast.swk.
func NewRecorder(dir, sessionID string, key *secretbox.Key, cols, rows int, title string, now time.Time) (*Recorder, error) {
	if !ids.Valid(sessionID) {
		return nil, errors.New("shell: invalid session id")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("shell: recordings dir: %w", err)
	}
	path := filepath.Join(dir, sessionID+".cast.swk")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("shell: create recording: %w", err)
	}
	r := &Recorder{f: f, key: key, sessionID: sessionID, start: now, h: sha256.New(), lastFlush: now, Path: path}
	hdr, _ := json.Marshal(map[string]any{"version": 2, "width": cols, "height": rows, "timestamp": now.Unix(), "title": title,
		"env": map[string]string{"TERM": "xterm-256color"}})
	r.buf.Write(hdr)
	r.buf.WriteByte('\n')
	return r, nil
}

func (r *Recorder) event(t time.Time, kind, data string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil || r.truncated {
		return
	}
	line, _ := json.Marshal([]any{t.Sub(r.start).Seconds(), kind, data})
	if r.total+int64(len(line)) > MaxRecordingBytes {
		r.truncated = true
		line, _ = json.Marshal([]any{t.Sub(r.start).Seconds(), "o", "\r\n[recording truncated: size limit]\r\n"})
	}
	r.buf.Write(line)
	r.buf.WriteByte('\n')
	r.total += int64(len(line)) + 1
	if r.buf.Len() >= chunkSize || t.Sub(r.lastFlush) >= flushInterval {
		_ = r.flushLocked(t)
	}
}

// Output records terminal output.
func (r *Recorder) Output(t time.Time, data []byte) {
	r.event(t, "o", string(bytes.ToValidUTF8(data, []byte("?"))))
}

// Resize records a terminal resize.
func (r *Recorder) Resize(t time.Time, cols, rows int) {
	r.event(t, "r", fmt.Sprintf("%dx%d", cols, rows))
}

func (r *Recorder) flushLocked(t time.Time) error {
	if r.buf.Len() == 0 {
		return nil
	}
	sealed, err := secretbox.Seal(r.key, purpose(r.sessionID, r.n), r.buf.Bytes())
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(sealed))) //nolint:gosec // chunk bounded
	for _, b := range [][]byte{hdr[:], sealed} {
		if _, err := r.f.Write(b); err != nil {
			return fmt.Errorf("shell: write recording: %w", err)
		}
		_, _ = r.h.Write(b)
	}
	r.n++
	r.buf.Reset()
	r.lastFlush = t
	return nil
}

// Close flushes and closes, returning the SHA-256 of the encrypted file.
func (r *Recorder) Close(t time.Time) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil, errors.New("shell: recorder closed")
	}
	err := r.flushLocked(t)
	if serr := r.f.Sync(); err == nil {
		err = serr
	}
	if cerr := r.f.Close(); err == nil {
		err = cerr
	}
	r.f = nil
	return r.h.Sum(nil), err
}

// Open decrypts a recording into asciicast v2 text, verifying chunk order
// (chunks are bound to their index and session) and the file hash.
func Open(path, sessionID string, key *secretbox.Key, wantSHA []byte) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("shell: read recording: %w", err)
	}
	if len(wantSHA) > 0 {
		sum := sha256.Sum256(data)
		if !bytes.Equal(sum[:], wantSHA) {
			return nil, errors.New("shell: recording hash mismatch (file modified)")
		}
	}
	var out bytes.Buffer
	for n := uint64(0); len(data) > 0; n++ {
		if len(data) < 4 {
			return nil, errors.New("shell: truncated recording")
		}
		l := int(binary.BigEndian.Uint32(data[:4]))
		if l > len(data)-4 {
			return nil, errors.New("shell: truncated recording")
		}
		pt, err := secretbox.Open(key, purpose(sessionID, n), data[4:4+l])
		if err != nil {
			return nil, fmt.Errorf("shell: chunk %d: %w", n, err)
		}
		out.Write(pt)
		data = data[4+l:]
	}
	return out.Bytes(), nil
}
