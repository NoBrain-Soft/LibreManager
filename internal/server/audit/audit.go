// Package audit writes and verifies the hash-chained audit log
// (CLAUDE.md rule 9, ARCHITECTURE.md T9).
//
// hash_n = SHA-256(hash_{n-1} || canonical(entry_n)), with hash_0 = 32 zero
// bytes. Inserts are serialized with a transaction-scoped advisory lock.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// Genesis is the prev_hash of the first entry.
var Genesis = make([]byte, sha256.Size)

// Entry is one audit record.
type Entry struct {
	Actor   string
	ActorIP string
	Action  string
	Target  string
	Details map[string]any
}

// Logger appends entries.
type Logger struct {
	st  *store.Store
	now func() time.Time
}

// New returns a Logger.
func New(st *store.Store) *Logger { return &Logger{st: st, now: time.Now} }

// Log appends e in its own transaction.
func (l *Logger) Log(ctx context.Context, e Entry) error {
	return l.st.InTx(ctx, func(q *db.Queries, _ pgx.Tx) error {
		_, err := l.LogTx(ctx, q, e)
		return err
	})
}

// LogBestEffort logs and only reports failures to slog (for paths where the
// primary action already happened and must not be reported as failed).
func (l *Logger) LogBestEffort(ctx context.Context, e Entry) {
	if err := l.Log(ctx, e); err != nil {
		slog.ErrorContext(ctx, "audit log write failed", "action", e.Action, "err", err)
	}
}

// LogTx appends e inside an existing transaction (so the audit entry
// commits atomically with the change it describes).
func (l *Logger) LogTx(ctx context.Context, q *db.Queries, e Entry) (int64, error) {
	if e.Actor == "" || e.Action == "" {
		return 0, errors.New("audit: actor and action are required")
	}
	if err := q.LockAudit(ctx); err != nil {
		return 0, fmt.Errorf("audit: lock: %w", err)
	}
	prev, err := q.LastAuditHash(ctx)
	if store.IsNotFound(err) {
		prev = Genesis
	} else if err != nil {
		return 0, fmt.Errorf("audit: last hash: %w", err)
	}
	ts := l.now().UTC().Truncate(time.Microsecond)
	details, err := canonicalDetails(e.Details)
	if err != nil {
		return 0, err
	}
	h, err := Hash(prev, ts, e.Actor, e.ActorIP, e.Action, e.Target, details)
	if err != nil {
		return 0, err
	}
	id, err := q.InsertAudit(ctx, db.InsertAuditParams{
		Ts: ts, Actor: e.Actor, ActorIp: e.ActorIP, Action: e.Action, Target: e.Target,
		Details: details, PrevHash: prev, Hash: h,
	})
	if err != nil {
		return 0, fmt.Errorf("audit: insert: %w", err)
	}
	return id, nil
}

type hashed struct {
	Action  string          `json:"action"`
	Actor   string          `json:"actor"`
	ActorIP string          `json:"actor_ip"`
	Details json.RawMessage `json:"details"`
	Target  string          `json:"target"`
	Ts      string          `json:"ts"`
}

// Hash computes the chain hash of one entry. details must be canonical.
func Hash(prev []byte, ts time.Time, actor, actorIP, action, target string, details []byte) ([]byte, error) {
	b, err := json.Marshal(hashed{
		Action: action, Actor: actor, ActorIP: actorIP, Details: details, Target: target,
		Ts: ts.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, fmt.Errorf("audit: hash: %w", err)
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(b)
	return h.Sum(nil), nil
}

func canonicalDetails(d map[string]any) ([]byte, error) {
	if d == nil {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("audit: details: %w", err)
	}
	return Canonicalize(b)
}

// Canonicalize re-encodes JSON with sorted keys, no insignificant
// whitespace and normalized numbers, so that a value read back from jsonb
// hashes identically to the value written.
func Canonicalize(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("audit: canonicalize: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case json.Number:
		if i, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			buf.WriteString(strconv.FormatInt(i, 10))
			return nil
		}
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return fmt.Errorf("audit: number %q: %w", x, err)
		}
		buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Errorf("audit: canonicalize: %w", err)
		}
		buf.Write(b)
	}
	return nil
}

// VerifyResult describes a chain verification.
type VerifyResult struct {
	OK         bool
	Checked    int64
	FirstBadID int64
	Message    string
}

// Verify walks the whole chain. The oldest remaining entry anchors the
// chain (older entries may have been removed by retention).
func Verify(ctx context.Context, q *db.Queries) (VerifyResult, error) {
	var res VerifyResult
	var prev []byte
	var last int64
	first := true
	for {
		rows, err := q.AuditAfter(ctx, last)
		if err != nil {
			return res, fmt.Errorf("audit: verify: %w", err)
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			if first {
				prev = r.PrevHash
				if !bytes.Equal(prev, Genesis) {
					res.Message = fmt.Sprintf("chain anchored at entry %d (older entries removed by retention)", r.ID)
				}
				first = false
			}
			if !bytes.Equal(r.PrevHash, prev) {
				return fail(res, r.ID, "prev_hash does not match previous entry"), nil
			}
			details, err := Canonicalize(r.Details)
			if err != nil {
				return fail(res, r.ID, "details not canonicalizable"), nil
			}
			h, err := Hash(prev, r.Ts, r.Actor, r.ActorIp, r.Action, r.Target, details)
			if err != nil {
				return res, err
			}
			if !bytes.Equal(h, r.Hash) {
				return fail(res, r.ID, "hash mismatch (entry modified)"), nil
			}
			prev = r.Hash
			last = r.ID
			res.Checked++
		}
	}
	res.OK = true
	return res, nil
}

func fail(res VerifyResult, id int64, msg string) VerifyResult {
	res.OK = false
	res.FirstBadID = id
	res.Message = fmt.Sprintf("entry %d: %s", id, msg)
	return res
}

// HexHash formats a hash for display.
func HexHash(h []byte) string { return hex.EncodeToString(h) }
