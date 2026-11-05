package envelope

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultNonceCapacity bounds the number of remembered nonces. When full,
// new jobs are rejected (fail closed) until entries expire.
const DefaultNonceCapacity = 100_000

// ErrNonceStoreFull is returned when the nonce cache is at capacity.
var ErrNonceStoreFull = errors.New("envelope: nonce store full")

// MemoryNonceStore is an in-memory NonceStore.
type MemoryNonceStore struct {
	mu       sync.Mutex
	entries  map[string]time.Time
	capacity int
	now      func() time.Time
}

// NewMemoryNonceStore returns an empty in-memory store. now may be nil.
func NewMemoryNonceStore(now func() time.Time) *MemoryNonceStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryNonceStore{entries: map[string]time.Time{}, capacity: DefaultNonceCapacity, now: now}
}

// SetCapacity changes the capacity (for tests and tuning).
func (m *MemoryNonceStore) SetCapacity(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.capacity = n
}

// CheckAndStore implements NonceStore.
func (m *MemoryNonceStore) CheckAndStore(nonce []byte, until time.Time) error {
	if len(nonce) != NonceSize {
		return fmt.Errorf("%w: invalid nonce", ErrMalformed)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	k := string(nonce)
	if exp, ok := m.entries[k]; ok && now.Before(exp) {
		return ErrReplay
	}
	if len(m.entries) >= m.capacity {
		m.pruneLocked(now)
		if len(m.entries) >= m.capacity {
			return ErrNonceStoreFull
		}
	}
	m.entries[k] = until
	return nil
}

// Len returns the number of stored entries (including expired ones not yet pruned).
func (m *MemoryNonceStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

func (m *MemoryNonceStore) pruneLocked(now time.Time) {
	for k, exp := range m.entries {
		if !now.Before(exp) {
			delete(m.entries, k)
		}
	}
}

// FileNonceStore persists nonces to an append-only file so that replay
// protection survives restarts of the agent or the socket-activated helper.
// Each line is "<hex nonce> <unix expiry>". The file is compacted on open.
type FileNonceStore struct {
	mem  *MemoryNonceStore
	mu   sync.Mutex
	path string
	f    *os.File
}

// OpenFileNonceStore loads (and compacts) the store at path, creating it
// with mode 0600 if needed.
func OpenFileNonceStore(path string, now func() time.Time) (*FileNonceStore, error) {
	mem := NewMemoryNonceStore(now)
	if err := loadNonceFile(path, mem); err != nil {
		return nil, err
	}
	// Compact: rewrite live entries to a temp file and rename.
	tmp := path + ".tmp"
	tf, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("nonce store: %w", err)
	}
	w := bufio.NewWriter(tf)
	nowT := mem.now()
	for k, exp := range mem.entries {
		if nowT.Before(exp) {
			fmt.Fprintf(w, "%s %d\n", hex.EncodeToString([]byte(k)), exp.Unix())
		} else {
			delete(mem.entries, k)
		}
	}
	if err := w.Flush(); err != nil {
		_ = tf.Close()
		return nil, fmt.Errorf("nonce store: %w", err)
	}
	if err := tf.Sync(); err != nil {
		_ = tf.Close()
		return nil, fmt.Errorf("nonce store: %w", err)
	}
	if err := tf.Close(); err != nil {
		return nil, fmt.Errorf("nonce store: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("nonce store: %w", err)
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("nonce store: %w", err)
	}
	return &FileNonceStore{mem: mem, path: path, f: f}, nil
}

func loadNonceFile(path string, mem *MemoryNonceStore) error {
	f, err := os.Open(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("nonce store: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue // tolerate a torn last line
		}
		n, err := hex.DecodeString(fields[0])
		if err != nil || len(n) != NonceSize {
			continue
		}
		exp, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		mem.entries[string(n)] = time.Unix(exp, 0)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("nonce store: %w", err)
	}
	return nil
}

// CheckAndStore implements NonceStore. The entry is durably written before
// success is reported.
func (s *FileNonceStore) CheckAndStore(nonce []byte, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.mem.CheckAndStore(nonce, until); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(s.f, "%s %d\n", hex.EncodeToString(nonce), until.Unix()); err != nil {
		return fmt.Errorf("nonce store: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("nonce store: %w", err)
	}
	return nil
}

// Close closes the underlying file.
func (s *FileNonceStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}
