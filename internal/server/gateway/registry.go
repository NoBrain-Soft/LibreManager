package gateway

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// agentConn is one connected agent's control stream.
type agentConn struct {
	hostID      uuid.UUID
	out         chan outMsg
	ctx         context.Context
	cancel      context.CancelCauseFunc
	connectedAt time.Time
	remote      string
	version     string
}

type outMsg struct {
	msg  *agentv1.ConnectResponse
	done chan error
}

// errConnClosed is returned when sending to a closed connection.
var errConnClosed = errors.New("gateway: agent connection closed")

// send enqueues msg and waits until it was written to the stream.
func (c *agentConn) send(ctx context.Context, msg *agentv1.ConnectResponse) error {
	done := make(chan error, 1)
	select {
	case c.out <- outMsg{msg: msg, done: done}:
	case <-c.ctx.Done():
		return errConnClosed
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return errors.New("gateway: agent send queue full")
	}
	select {
	case err := <-done:
		return err
	case <-c.ctx.Done():
		return errConnClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Registry tracks connected agents (host id -> stream).
type Registry struct {
	mu    sync.RWMutex
	conns map[uuid.UUID]*agentConn
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{conns: map[uuid.UUID]*agentConn{}} }

// add registers c, replacing (and closing) an older connection for the host.
func (r *Registry) add(c *agentConn) {
	r.mu.Lock()
	old := r.conns[c.hostID]
	r.conns[c.hostID] = c
	r.mu.Unlock()
	if old != nil {
		old.cancel(errors.New("replaced by a newer connection"))
	}
}

// remove unregisters c if it is still the current connection.
func (r *Registry) remove(c *agentConn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns[c.hostID] == c {
		delete(r.conns, c.hostID)
		return true
	}
	return false
}

func (r *Registry) get(id uuid.UUID) *agentConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conns[id]
}

// Connected reports whether the host has a live stream.
func (r *Registry) Connected(id uuid.UUID) bool { return r.get(id) != nil }

// HostIDs lists connected hosts.
func (r *Registry) HostIDs() []uuid.UUID {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]uuid.UUID, 0, len(r.conns))
	for id := range r.conns {
		out = append(out, id)
	}
	return out
}

// Disconnect closes the host's stream, if any.
func (r *Registry) Disconnect(id uuid.UUID, cause error) {
	if c := r.get(id); c != nil {
		c.cancel(cause)
	}
}

// Send delivers msg to a connected host.
func (r *Registry) Send(ctx context.Context, id uuid.UUID, msg *agentv1.ConnectResponse) error {
	c := r.get(id)
	if c == nil {
		return errConnClosed
	}
	return c.send(ctx, msg)
}

// ConnInfo describes a connection.
type ConnInfo struct {
	HostID      uuid.UUID
	ConnectedAt time.Time
	Remote      string
	Version     string
}

// List returns all connections.
func (r *Registry) List() []ConnInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ConnInfo, 0, len(r.conns))
	for _, c := range r.conns {
		out = append(out, ConnInfo{HostID: c.hostID, ConnectedAt: c.connectedAt, Remote: c.remote, Version: c.version})
	}
	return out
}

// Denylist holds revoked certificate serials (instant revocation: the
// gateway is the only relying party).
type Denylist struct {
	mu      sync.RWMutex
	serials map[string]struct{}
}

// NewDenylist returns an empty denylist.
func NewDenylist() *Denylist { return &Denylist{serials: map[string]struct{}{}} }

// Replace swaps the set.
func (d *Denylist) Replace(serials []string) {
	m := make(map[string]struct{}, len(serials))
	for _, s := range serials {
		m[s] = struct{}{}
	}
	d.mu.Lock()
	d.serials = m
	d.mu.Unlock()
}

// Add inserts one serial.
func (d *Denylist) Add(serial string) {
	d.mu.Lock()
	d.serials[serial] = struct{}{}
	d.mu.Unlock()
}

// Revoked reports whether serial is denied.
func (d *Denylist) Revoked(serial string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.serials[serial]
	return ok
}
