// Package events carries live events (host status, job progress, alerts)
// from any central component to the API's WebSocket clients via
// PostgreSQL NOTIFY, so it works across separate containers.
package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/nobrain-soft/libremanager/internal/server/store"
)

// Event types (mirrors the OpenAPI Event schema).
const (
	HostConnected    = "host.connected"
	HostDisconnected = "host.disconnected"
	HostEnrolled     = "host.enrolled"
	HostUpdated      = "host.updated"
	JobCreated       = "job.created"
	JobTarget        = "job.target"
	JobFinished      = "job.finished"
	Alert            = "alert"
)

// Event is one notification.
type Event struct {
	Type    string    `json:"type"`
	Ts      time.Time `json:"ts"`
	HostID  string    `json:"host_id,omitempty"`
	JobID   string    `json:"job_id,omitempty"`
	Status  string    `json:"status,omitempty"`
	Message string    `json:"message,omitempty"`
}

// Publish sends e best-effort (events are hints; state lives in the DB).
func Publish(ctx context.Context, st *store.Store, e Event) {
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}
	if len(e.Message) > 512 {
		e.Message = e.Message[:512]
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	if err := st.Notify(ctx, store.ChanEvents, string(b)); err != nil {
		slog.DebugContext(ctx, "publish event", "err", err)
	}
}

// Hub fans events out to in-process subscribers.
type Hub struct {
	mu   sync.RWMutex
	subs map[chan Event]struct{}
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[chan Event]struct{}{}} }

// Subscribe returns a channel of events and an unsubscribe function.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

// Broadcast delivers e to all subscribers, dropping for slow ones.
func (h *Hub) Broadcast(e Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Run listens on the events channel and broadcasts until ctx is done.
func (h *Hub) Run(ctx context.Context, st *store.Store) {
	st.Listen(ctx, []string{store.ChanEvents}, func(_, payload string) {
		var e Event
		if err := json.Unmarshal([]byte(payload), &e); err == nil {
			h.Broadcast(e)
		}
	}, nil)
}
