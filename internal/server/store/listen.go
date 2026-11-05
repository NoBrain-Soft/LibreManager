package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

// Notification channels.
const (
	ChanEvents      = "stellwerk_events"
	ChanDispatch    = "stellwerk_dispatch"
	ChanRevocations = "stellwerk_revocations"
)

// Listen subscribes to channels and calls fn for every notification until
// ctx is done. It reconnects with backoff on errors. onReconnect (optional)
// is called after each (re)connect so callers can resync missed state.
func (s *Store) Listen(ctx context.Context, channels []string, fn func(channel, payload string), onReconnect func()) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := s.listenOnce(ctx, channels, fn, onReconnect)
		if ctx.Err() != nil {
			return
		}
		slog.WarnContext(ctx, "listen connection lost", "err", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (s *Store) listenOnce(ctx context.Context, channels []string, fn func(channel, payload string), onReconnect func()) error {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire: %w", err)
	}
	defer conn.Release()
	for _, ch := range channels {
		if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{ch}.Sanitize()); err != nil {
			return fmt.Errorf("listen %s: %w", ch, err)
		}
	}
	if onReconnect != nil {
		onReconnect()
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return fmt.Errorf("wait: %w", err)
		}
		fn(n.Channel, n.Payload)
	}
}
