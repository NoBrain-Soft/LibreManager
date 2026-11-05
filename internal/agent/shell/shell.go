// Package shell relays a PTY spawned by the helper over a dedicated
// ShellSession gRPC stream (ARCHITECTURE.md §6.5, separate from the control
// stream to avoid head-of-line blocking).
package shell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Opener opens the ShellSession stream.
type Opener func(ctx context.Context) (agentv1.GatewayService_ShellSessionClient, error)

// Banner is shown at the start of every session.
func Banner(requestedBy, unixUser string) string {
	return fmt.Sprintf("\r\n\x1b[1;33m*** Stellwerk remote session for %s as %s. This session is recorded. ***\x1b[0m\r\n\r\n", requestedBy, unixUser)
}

// Relay pumps PTY master <-> stream until either side ends, the idle
// timeout passes or ctx is done. Closing the master hangs up the shell.
func Relay(ctx context.Context, open Opener, grant *agentv1.ShellGrant, requestedBy string, master *os.File) error {
	defer master.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := open(ctx)
	if err != nil {
		return fmt.Errorf("shell: open stream: %w", err)
	}
	if err := stream.Send(&agentv1.ShellSessionRequest{Payload: &agentv1.ShellSessionRequest_Attach{
		Attach: &agentv1.ShellAttach{SessionId: grant.GetSessionId()}}}); err != nil {
		return fmt.Errorf("shell: attach: %w", err)
	}
	_ = setSize(master, grant.GetCols(), grant.GetRows())
	if err := stream.Send(&agentv1.ShellSessionRequest{Payload: &agentv1.ShellSessionRequest_Output{
		Output: []byte(Banner(requestedBy, grant.GetUnixUser()))}}); err != nil {
		return fmt.Errorf("shell: banner: %w", err)
	}

	idle := time.Duration(grant.GetIdleTimeoutS()) * time.Second
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	errc := make(chan error, 3)

	// PTY -> gateway. Only this goroutine sends after the banner.
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				if serr := stream.Send(&agentv1.ShellSessionRequest{Payload: &agentv1.ShellSessionRequest_Output{
					Output: append([]byte(nil), buf[:n]...)}}); serr != nil {
					errc <- serr
					return
				}
			}
			if err != nil {
				// EIO when the shell exits.
				_ = stream.Send(&agentv1.ShellSessionRequest{Payload: &agentv1.ShellSessionRequest_Exit{
					Exit: &agentv1.ShellExit{Reason: "shell exited"}}})
				_ = stream.CloseSend()
				errc <- nil
				return
			}
		}
	}()
	// gateway -> PTY
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				errc <- err
				return
			}
			switch p := m.GetPayload().(type) {
			case *agentv1.ShellSessionResponse_Input:
				last.Store(time.Now().UnixNano())
				if _, err := master.Write(p.Input); err != nil {
					errc <- err
					return
				}
			case *agentv1.ShellSessionResponse_Resize:
				_ = setSize(master, p.Resize.GetCols(), p.Resize.GetRows())
			case *agentv1.ShellSessionResponse_Close:
				errc <- nil
				return
			}
		}
	}()
	if idle > 0 {
		go func() {
			t := time.NewTicker(5 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if time.Since(time.Unix(0, last.Load())) > idle {
						errc <- errors.New("idle timeout")
						return
					}
				}
			}
		}()
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func setSize(f *os.File, cols, rows uint32) error {
	if cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
		return nil
	}
	ws := &unix.Winsize{Col: uint16(cols), Row: uint16(rows)}     //nolint:gosec // bounded above
	return unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ, ws) //nolint:gosec // fd fits in int
}
