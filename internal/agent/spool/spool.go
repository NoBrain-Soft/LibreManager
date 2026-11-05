// Package spool is the agent's offline metrics buffer (ARCHITECTURE.md
// §5.1): when central is unreachable, self-contained MetricsBatch messages
// are appended to an on-disk ring and replayed oldest-first on reconnect.
//
// # On-disk format
//
// The spool directory (mode 0700) holds segment files "seg-<seq>.spool"
// (mode 0600), a "cursor" file recording how far the oldest segment has been
// drained, and a ".lock" file (flock) that keeps two agents from sharing a
// spool. A segment is a sequence of records:
//
//	magic  uint32 LE  "SWSL"
//	length uint32 LE  payload length
//	crc    uint32 LE  CRC-32C over timestamp + payload
//	ts     int64  LE  batch timestamp (unix ms), used for max-age expiry
//	payload           protobuf-encoded MetricsBatch
//
// Records are only appended. On open every segment is scanned: a torn write
// at the tail of the newest segment is truncated away, and corrupt records
// anywhere are skipped by resynchronizing on the next magic with a valid
// checksum. Corruption never stops the agent.
//
// # Limits and delivery
//
// The total size is bounded by maxBytes (oldest segments are dropped) and
// records older than maxAge are discarded. Drain delivers records
// oldest-first and removes a record only after send succeeded. The drain
// position is persisted periodically, so a crash can cause a few batches to
// be replayed twice (at-least-once); identical samples are deduplicated by
// the TSDB. Appends are not fsynced individually (the kernel flushes within
// seconds); segments are fsynced when they are sealed and on Close.
package spool

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Defaults (ARCHITECTURE.md §5.1).
const (
	DefaultMaxBytes = 50 << 20
	DefaultMaxAge   = 24 * time.Hour
)

const (
	recordMagic       uint32 = 0x4c535753 // "SWSL" in little-endian byte order
	headerSize               = 20
	maxRecordSize            = 8 << 20
	minMaxBytes              = 16 << 10
	segPrefix                = "seg-"
	segSuffix                = ".spool"
	cursorFile               = "cursor"
	lockFile                 = ".lock"
	cursorSize               = 20
	cursorSaveEvery          = 32
	maxSegmentSize           = 8 << 20
	minSegmentSize           = 4 << 10
	segmentsPerBudget        = 16
	fileMode                 = 0o600
	dirMode                  = 0o700
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Errors.
var (
	ErrClosed   = errors.New("spool: closed")
	ErrTooLarge = errors.New("spool: batch too large")
	ErrBusy     = errors.New("spool: drain already in progress")
	ErrLocked   = errors.New("spool: directory is locked by another process")
)

type recMeta struct {
	off int64 // record start (header)
	n   uint32
	ts  int64
}

type segment struct {
	seq  uint64
	path string
	size int64 // bytes on disk
	recs []recMeta
}

// Stats describes the spool's state.
type Stats struct {
	Records  int
	Bytes    int64
	Segments int
	// Dropped counts records discarded because of maxBytes, maxAge or
	// corruption since Open.
	Dropped uint64
}

// Spool is a bounded, crash-safe on-disk queue of MetricsBatch messages. It
// is safe for concurrent use; Append may run while Drain is sending.
type Spool struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
	maxAge   time.Duration
	segMax   int64
	now      func() time.Time
	log      *slog.Logger

	segs     []*segment // oldest first; the last one is the active segment
	nextSeq  uint64     // never lower than any seq on disk or in the cursor
	active   *os.File
	head     int // index of the next record to drain in segs[0]
	total    int64
	count    int
	dropped  uint64
	lock     *os.File
	closed   bool
	draining bool
	unsaved  int
}

// Open opens or creates the spool in dir. maxBytes <= 0 and maxAge <= 0
// select the defaults (50 MB, 24 h).
func Open(dir string, maxBytes int64, maxAge time.Duration) (*Spool, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	maxBytes = max(maxBytes, minMaxBytes)
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	s := &Spool{
		dir:      dir,
		maxBytes: maxBytes,
		maxAge:   maxAge,
		segMax:   max(minSegmentSize, min(maxSegmentSize, maxBytes/segmentsPerBudget)),
		now:      time.Now,
		log:      slog.Default().With("component", "spool"),
	}
	if err := s.prepareDir(); err != nil {
		return nil, err
	}
	if err := s.acquireLock(); err != nil {
		return nil, err
	}
	if err := s.load(); err != nil {
		s.releaseLock()
		return nil, err
	}
	return s, nil
}

func (s *Spool) prepareDir() error {
	if err := os.MkdirAll(s.dir, dirMode); err != nil {
		return fmt.Errorf("spool: create dir: %w", err)
	}
	fi, err := os.Lstat(s.dir)
	if err != nil {
		return fmt.Errorf("spool: stat dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("spool: %s is not a directory", s.dir)
	}
	if fi.Mode().Perm() != dirMode {
		if err := os.Chmod(s.dir, dirMode); err != nil {
			return fmt.Errorf("spool: chmod dir: %w", err)
		}
	}
	return nil
}

func (s *Spool) acquireLock() error {
	f, err := openFile(filepath.Join(s.dir, lockFile), os.O_RDWR|os.O_CREATE)
	if err != nil {
		return fmt.Errorf("spool: open lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { //nolint:gosec // fd fits in int
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return ErrLocked
		}
		return fmt.Errorf("spool: flock: %w", err)
	}
	s.lock = f
	return nil
}

func (s *Spool) releaseLock() {
	if s.lock != nil {
		_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN) //nolint:gosec // fd fits in int
		_ = s.lock.Close()
		s.lock = nil
	}
}

// openFile opens a spool file without following symlinks, mode 0600.
func openFile(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, fileMode)
	if err != nil {
		return nil, err //nolint:wrapcheck // callers wrap
	}
	return f, nil
}

// load scans existing segments and restores the drain cursor.
func (s *Spool) load() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("spool: read dir: %w", err)
	}
	s.nextSeq = 1
	for _, e := range entries {
		seq, ok := parseSegName(e.Name())
		if !ok {
			continue
		}
		s.nextSeq = max(s.nextSeq, seq+1)
		path := filepath.Join(s.dir, e.Name())
		if !e.Type().IsRegular() {
			// Symlinks or other planted entries are removed, never followed.
			s.log.Warn("removing non-regular spool entry", "path", path)
			_ = os.Remove(path)
			continue
		}
		s.segs = append(s.segs, &segment{seq: seq, path: path})
	}
	sort.Slice(s.segs, func(i, j int) bool { return s.segs[i].seq < s.segs[j].seq })
	kept := s.segs[:0]
	for i, seg := range s.segs {
		if err := s.scanSegment(seg, i == len(s.segs)-1); err != nil {
			s.log.Warn("dropping unreadable spool segment", "path", seg.path, "error", err)
			_ = os.Remove(seg.path)
			continue
		}
		if len(seg.recs) == 0 {
			_ = os.Remove(seg.path)
			continue
		}
		kept = append(kept, seg)
	}
	s.segs = kept
	for _, seg := range s.segs {
		s.total += seg.size
		s.count += len(seg.recs)
	}
	cur, haveCursor := s.readCursor()
	if haveCursor {
		s.nextSeq = max(s.nextSeq, cur.seq+1)
		s.restoreCursor(cur)
	}
	s.enforceLimits()
	return s.openActive()
}

func parseSegName(name string) (uint64, bool) {
	if !strings.HasPrefix(name, segPrefix) || !strings.HasSuffix(name, segSuffix) {
		return 0, false
	}
	seq, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(name, segPrefix), segSuffix), 10, 64)
	return seq, err == nil
}

func segName(seq uint64) string {
	return fmt.Sprintf("%s%020d%s", segPrefix, seq, segSuffix)
}

// scanSegment indexes the valid records of a segment. For the newest
// segment a corrupt or torn tail is truncated.
func (s *Spool) scanSegment(seg *segment, last bool) error {
	f, err := openFile(seg.path, os.O_RDWR)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	if fi.Size() > maxSegmentSize+maxRecordSize+headerSize {
		return fmt.Errorf("segment too large (%d bytes)", fi.Size())
	}
	data := make([]byte, fi.Size())
	if _, err := io.ReadFull(f, data); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	recs, validEnd, skipped := scanRecords(data)
	seg.recs = recs
	seg.size = int64(len(data))
	if skipped > 0 {
		s.dropped += uint64(skipped) //nolint:gosec // non-negative
		s.log.Warn("skipped corrupt spool records", "path", seg.path, "count", skipped)
	}
	if last && validEnd < int64(len(data)) {
		if err := f.Truncate(validEnd); err != nil {
			return fmt.Errorf("truncate torn tail: %w", err)
		}
		seg.size = validEnd
	}
	return nil
}

// scanRecords returns the valid records in data, the end offset of the last
// valid record, and the number of corrupt regions skipped.
func scanRecords(data []byte) ([]recMeta, int64, int) {
	var recs []recMeta
	var validEnd int64
	skipped := 0
	inGarbage := false
	for off := 0; off+headerSize <= len(data); {
		if r, ok := parseRecord(data, off); ok {
			recs = append(recs, r)
			off += headerSize + int(r.n)
			validEnd = int64(off)
			inGarbage = false
			continue
		}
		if !inGarbage {
			skipped++
			inGarbage = true
		}
		// Resynchronize on the next magic.
		next := indexMagic(data, off+1)
		if next < 0 {
			break
		}
		off = next
	}
	if !inGarbage && validEnd < int64(len(data)) {
		skipped++ // short trailing fragment (torn write)
	}
	return recs, validEnd, skipped
}

func parseRecord(data []byte, off int) (recMeta, bool) {
	h := data[off : off+headerSize]
	if binary.LittleEndian.Uint32(h[0:4]) != recordMagic {
		return recMeta{}, false
	}
	n := binary.LittleEndian.Uint32(h[4:8])
	if n > maxRecordSize || off+headerSize+int(n) > len(data) {
		return recMeta{}, false
	}
	crc := crc32.Update(crc32.Checksum(h[12:20], castagnoli), castagnoli, data[off+headerSize:off+headerSize+int(n)])
	if crc != binary.LittleEndian.Uint32(h[8:12]) {
		return recMeta{}, false
	}
	return recMeta{off: int64(off), n: n, ts: int64(binary.LittleEndian.Uint64(h[12:20]))}, true //nolint:gosec // timestamp bits
}

func indexMagic(data []byte, from int) int {
	var m [4]byte
	binary.LittleEndian.PutUint32(m[:], recordMagic)
	for i := from; i+4 <= len(data); i++ {
		if data[i] == m[0] && data[i+1] == m[1] && data[i+2] == m[2] && data[i+3] == m[3] {
			return i
		}
	}
	return -1
}

type cursor struct {
	seq uint64
	off int64
}

// readCursor reads the drain position: seq uint64 | offset int64 | crc32c.
func (s *Spool) readCursor() (cursor, bool) {
	data, err := os.ReadFile(filepath.Join(s.dir, cursorFile))
	if err != nil || len(data) != cursorSize {
		return cursor{}, false
	}
	if crc32.Checksum(data[:16], castagnoli) != binary.LittleEndian.Uint32(data[16:20]) {
		s.log.Warn("ignoring corrupt spool cursor")
		return cursor{}, false
	}
	return cursor{
		seq: binary.LittleEndian.Uint64(data[0:8]),
		off: int64(binary.LittleEndian.Uint64(data[8:16])), //nolint:gosec // offset bits
	}, true
}

// restoreCursor applies a saved drain position.
func (s *Spool) restoreCursor(cur cursor) {
	// Segments before the cursor's were fully drained; a crash may have kept
	// them on disk.
	for len(s.segs) > 0 && s.segs[0].seq < cur.seq {
		s.removeSegment(0, false)
	}
	if len(s.segs) == 0 || s.segs[0].seq != cur.seq {
		return
	}
	for s.head < len(s.segs[0].recs) && s.segs[0].recs[s.head].off < cur.off {
		s.head++
	}
	s.count -= s.head
}

func (s *Spool) saveCursor() {
	s.unsaved = 0
	var buf [cursorSize]byte
	if len(s.segs) > 0 {
		seg := s.segs[0]
		binary.LittleEndian.PutUint64(buf[0:8], seg.seq)
		off := seg.size
		if s.head < len(seg.recs) {
			off = seg.recs[s.head].off
		}
		binary.LittleEndian.PutUint64(buf[8:16], uint64(off)) //nolint:gosec // non-negative
	}
	binary.LittleEndian.PutUint32(buf[16:20], crc32.Checksum(buf[:16], castagnoli))
	tmp := filepath.Join(s.dir, cursorFile+".tmp")
	f, err := openFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		s.log.Warn("cannot save spool cursor", "error", err)
		return
	}
	_, werr := f.Write(buf[:])
	cerr := f.Close()
	if werr != nil || cerr != nil {
		s.log.Warn("cannot save spool cursor", "error", errors.Join(werr, cerr))
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, cursorFile)); err != nil {
		s.log.Warn("cannot save spool cursor", "error", err)
	}
}

// openActive opens the newest segment for appending, or creates one.
func (s *Spool) openActive() error {
	if n := len(s.segs); n > 0 && s.segs[n-1].size < s.segMax {
		f, err := openFile(s.segs[n-1].path, os.O_WRONLY|os.O_APPEND)
		if err == nil {
			s.active = f
			return nil
		}
		s.log.Warn("cannot reopen spool segment; starting a new one", "error", err)
	}
	return s.newSegment()
}

func (s *Spool) newSegment() error {
	seq := s.nextSeq
	s.nextSeq++
	path := filepath.Join(s.dir, segName(seq))
	f, err := openFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND)
	if err != nil {
		return fmt.Errorf("spool: create segment: %w", err)
	}
	s.active = f
	s.segs = append(s.segs, &segment{seq: seq, path: path})
	return nil
}

// sealActive fsyncs and closes the active segment.
func (s *Spool) sealActive() {
	if s.active == nil {
		return
	}
	_ = s.active.Sync()
	_ = s.active.Close()
	s.active = nil
}

// Append adds a self-contained batch (replay = true is set if missing).
func (s *Spool) Append(b *agentv1.MetricsBatch) error {
	if b == nil {
		return errors.New("spool: nil batch")
	}
	if !b.GetReplay() {
		b = proto.CloneOf(b)
		b.Replay = true
	}
	payload, err := proto.Marshal(b)
	if err != nil {
		return fmt.Errorf("spool: marshal: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if len(payload) > maxRecordSize || int64(len(payload)+headerSize) > s.maxBytes/4 {
		return fmt.Errorf("%w (%d bytes)", ErrTooLarge, len(payload))
	}
	ts := b.GetTimestampMs()
	if ts == 0 {
		ts = s.now().UnixMilli()
	}
	rec := encodeRecord(ts, payload)

	if s.active == nil || len(s.segs) == 0 {
		// An earlier segment creation failed; retry.
		if err := s.newSegment(); err != nil {
			return err
		}
	}
	activeSeg := s.segs[len(s.segs)-1]
	if len(activeSeg.recs) > 0 && activeSeg.size+int64(len(rec)) > s.segMax {
		s.sealActive()
		if err := s.newSegment(); err != nil {
			return err
		}
		activeSeg = s.segs[len(s.segs)-1]
	}
	if n, err := s.active.Write(rec); err != nil {
		// Roll back a partial write so the segment stays well-formed.
		if n > 0 {
			_ = s.active.Truncate(activeSeg.size)
		}
		return fmt.Errorf("spool: write: %w", err)
	}
	activeSeg.recs = append(activeSeg.recs, recMeta{off: activeSeg.size, n: uint32(len(payload)), ts: ts}) //nolint:gosec // bounded
	activeSeg.size += int64(len(rec))
	s.total += int64(len(rec))
	s.count++
	s.enforceLimits()
	return nil
}

func encodeRecord(ts int64, payload []byte) []byte {
	rec := make([]byte, headerSize+len(payload))
	binary.LittleEndian.PutUint32(rec[0:4], recordMagic)
	binary.LittleEndian.PutUint32(rec[4:8], uint32(len(payload))) //nolint:gosec // bounded by maxRecordSize
	binary.LittleEndian.PutUint64(rec[12:20], uint64(ts))         //nolint:gosec // timestamp bits
	copy(rec[headerSize:], payload)
	crc := crc32.Update(crc32.Checksum(rec[12:20], castagnoli), castagnoli, payload)
	binary.LittleEndian.PutUint32(rec[8:12], crc)
	return rec
}

// enforceLimits drops expired segments and the oldest segments beyond
// maxBytes. The active segment is never dropped here.
func (s *Spool) enforceLimits() {
	cutoff := s.now().Add(-s.maxAge).UnixMilli()
	for len(s.segs) > 1 {
		seg := s.segs[0]
		expired := len(seg.recs) == 0 || seg.recs[len(seg.recs)-1].ts < cutoff
		if !expired && s.total <= s.maxBytes {
			break
		}
		s.removeSegment(0, true)
	}
}

// removeSegment deletes segs[i] (only i == 0 is used), adjusting counters.
func (s *Spool) removeSegment(i int, countDropped bool) {
	seg := s.segs[i]
	remaining := len(seg.recs)
	if i == 0 {
		remaining -= s.head
		s.head = 0
	}
	if countDropped && remaining > 0 {
		s.dropped += uint64(remaining) //nolint:gosec // non-negative
	}
	s.count -= remaining
	s.total -= seg.size
	if err := os.Remove(seg.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("cannot remove spool segment", "path", seg.path, "error", err)
	}
	s.segs = append(s.segs[:i], s.segs[i+1:]...)
}

// Drain sends spooled batches oldest-first. A record is removed only after
// send returned nil; on the first error Drain stops, keeps the remaining
// records, and returns the error. Expired and corrupt records are skipped.
// Only one Drain may run at a time; Append may be called concurrently.
func (s *Spool) Drain(ctx context.Context, send func(*agentv1.MetricsBatch) error) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if s.draining {
		s.mu.Unlock()
		return ErrBusy
	}
	s.draining = true
	defer func() {
		if !s.closed {
			s.saveCursor()
		}
		s.draining = false
		s.mu.Unlock()
	}()

	var reader *os.File
	var readerSeq uint64
	defer func() {
		if reader != nil {
			_ = reader.Close()
		}
	}()
	for {
		if s.closed {
			return ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("spool: drain: %w", err)
		}
		if !s.advanceHead() {
			return nil
		}
		seg := s.segs[0]
		rec := seg.recs[s.head]
		if rec.ts < s.now().Add(-s.maxAge).UnixMilli() {
			s.consume(seg.seq, s.head, true)
			continue
		}
		if reader == nil || readerSeq != seg.seq {
			if reader != nil {
				_ = reader.Close()
			}
			f, err := openFile(seg.path, os.O_RDONLY)
			if err != nil {
				return fmt.Errorf("spool: open segment: %w", err)
			}
			reader, readerSeq = f, seg.seq
		}
		batch, err := readRecord(reader, rec)
		if err != nil {
			s.log.Warn("skipping unreadable spool record", "segment", seg.path, "offset", rec.off, "error", err)
			s.consume(seg.seq, s.head, true)
			continue
		}
		seq, idx := seg.seq, s.head
		s.mu.Unlock()
		err = send(batch)
		s.mu.Lock()
		if err != nil {
			return fmt.Errorf("spool: send: %w", err)
		}
		s.consume(seq, idx, false)
	}
}

// advanceHead skips fully drained segments. It reports whether a record is
// available at segs[0].recs[head].
func (s *Spool) advanceHead() bool {
	for len(s.segs) > 0 {
		seg := s.segs[0]
		if s.head < len(seg.recs) {
			return true
		}
		if len(s.segs) == 1 {
			// The active segment is fully drained: reset it in place.
			s.resetActive()
			return false
		}
		s.removeSegment(0, false)
		s.saveCursor()
	}
	return false
}

// resetActive replaces the single, fully drained active segment with a new,
// empty one. A fresh sequence number (instead of truncating in place) means
// a stale cursor can never point into new data.
func (s *Spool) resetActive() {
	if len(s.segs[0].recs) == 0 {
		return
	}
	s.sealActive()
	s.removeSegment(0, false)
	if err := s.newSegment(); err != nil {
		s.log.Warn("cannot create spool segment", "error", err)
	}
	s.saveCursor()
}

// consume marks record idx of segment seq as done if it is still the head
// (Append may have dropped the segment for space while send was running).
func (s *Spool) consume(seq uint64, idx int, dropped bool) {
	if len(s.segs) == 0 || s.segs[0].seq != seq || s.head != idx {
		return
	}
	s.head++
	s.count--
	if dropped {
		s.dropped++
	}
	s.unsaved++
	if s.unsaved >= cursorSaveEvery {
		s.saveCursor()
	}
}

func readRecord(f *os.File, rec recMeta) (*agentv1.MetricsBatch, error) {
	buf := make([]byte, headerSize+int(rec.n))
	if _, err := f.ReadAt(buf, rec.off); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	r, ok := parseRecord(buf, 0)
	if !ok || r.n != rec.n {
		return nil, errors.New("checksum mismatch")
	}
	var b agentv1.MetricsBatch
	if err := proto.Unmarshal(buf[headerSize:], &b); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &b, nil
}

// Len returns the number of batches waiting to be drained.
func (s *Spool) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// Stats returns size and drop counters.
func (s *Spool) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Records: s.count, Bytes: s.total, Segments: len(s.segs), Dropped: s.dropped}
}

// Close flushes and closes the spool. A running Drain returns ErrClosed
// after its current send.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.saveCursor()
	s.closed = true
	var err error
	if s.active != nil {
		err = errors.Join(s.active.Sync(), s.active.Close())
		s.active = nil
	}
	s.releaseLock()
	if err != nil {
		return fmt.Errorf("spool: close: %w", err)
	}
	return nil
}
