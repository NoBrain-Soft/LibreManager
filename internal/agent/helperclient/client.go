// Package helperclient is the agent core's client for the root helper
// (proto/stellwerk/helper/v1). Each call uses one connection; the helper
// treats the connection closing as cancellation, so cancelling ctx (which
// closes the connection) stops the job on the helper side.
package helperclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	helperv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/helper/v1"
)

// DefaultTimeout bounds calls other than ExecuteJob.
const DefaultTimeout = 10 * time.Minute

// ErrHelper wraps a HelperError returned by the helper.
var ErrHelper = errors.New("helper error")

// ErrProtocol is returned for unexpected responses.
var ErrProtocol = errors.New("helperclient: protocol violation")

// Client talks to the helper socket.
type Client struct {
	// SocketPath defaults to policy.DefaultHelperSocket.
	SocketPath string
	// Timeout bounds ListUpgrades, ReadPrivileged and Ping (default
	// DefaultTimeout) and the dial of every call. ExecuteJob runs until it
	// finishes or ctx ends (shells can last hours).
	Timeout time.Duration
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// call dials, sends req and returns the connection plus a stop func that
// must be called to release it.
func (c *Client) call(ctx context.Context, req *helperv1.HelperRequest) (*conn, func(), error) {
	path := c.SocketPath
	if path == "" {
		path = policy.DefaultHelperSocket
	}
	dctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	var d net.Dialer
	nc, err := d.DialContext(dctx, "unix", path)
	if err != nil {
		return nil, nil, fmt.Errorf("helperclient: dial: %w", err)
	}
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		_ = nc.Close()
		return nil, nil, errors.New("helperclient: not a unix connection")
	}
	cn := &conn{uc: uc}
	// Closing the raw socket is goroutine-safe and unblocks a pending read;
	// cn.close (which also drops queued fds) runs in stop, on the reader's
	// goroutine.
	stopClose := context.AfterFunc(ctx, func() { _ = uc.Close() })
	stop := func() {
		stopClose()
		cn.close()
	}
	if err := cn.write(req); err != nil {
		stop()
		return nil, nil, c.wrap(ctx, fmt.Errorf("helperclient: send: %w", err))
	}
	return cn, stop, nil
}

func (c *Client) wrap(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("helperclient: %w", ctx.Err())
	}
	return err
}

// single performs a request that has exactly one response frame.
func (c *Client) single(ctx context.Context, req *helperv1.HelperRequest) (*helperv1.HelperResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	cn, stop, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}
	defer stop()
	var resp helperv1.HelperResponse
	if err := cn.read(&resp); err != nil {
		return nil, c.wrap(ctx, fmt.Errorf("helperclient: read: %w", err))
	}
	if e := resp.GetError(); e != nil {
		return nil, fmt.Errorf("%w: %s", ErrHelper, e.GetMessage())
	}
	return &resp, nil
}

// Ping returns the helper version and host id.
func (c *Client) Ping(ctx context.Context) (*helperv1.PingResponse, error) {
	resp, err := c.single(ctx, &helperv1.HelperRequest{Call: &helperv1.HelperRequest_Ping{Ping: &helperv1.PingRequest{}}})
	if err != nil {
		return nil, err
	}
	if p := resp.GetPong(); p != nil {
		return p, nil
	}
	return nil, ErrProtocol
}

// ListUpgrades returns pending updates (no metadata refresh).
func (c *Client) ListUpgrades(ctx context.Context) (*agentv1.UpdatesReport, error) {
	resp, err := c.single(ctx, &helperv1.HelperRequest{Call: &helperv1.HelperRequest_ListUpgrades{ListUpgrades: &helperv1.ListUpgradesRequest{}}})
	if err != nil {
		return nil, err
	}
	if u := resp.GetUpgrades(); u != nil {
		return u, nil
	}
	return nil, ErrProtocol
}

// ReadPrivileged returns privileged facts for security checks/inventory.
func (c *Client) ReadPrivileged(ctx context.Context, kind helperv1.PrivilegedKind) (*helperv1.PrivilegedData, error) {
	resp, err := c.single(ctx, &helperv1.HelperRequest{Call: &helperv1.HelperRequest_ReadPrivileged{ReadPrivileged: &helperv1.ReadPrivilegedRequest{Kind: kind}}})
	if err != nil {
		return nil, err
	}
	if d := resp.GetPrivileged(); d != nil && d.GetKind() == kind {
		return d, nil
	}
	return nil, ErrProtocol
}

// ExecuteJob forwards a SignedJob (which the helper verifies again) and
// streams its output to onOutput. For shell jobs, onShell receives the PTY
// master and the shell pid and owns the file from then on (nil closes it);
// ExecuteJob keeps waiting until the shell exits or ctx is cancelled, which
// makes the helper hang up the shell. A rejected job is a JobFinished with
// status REJECTED, not an error.
func (c *Client) ExecuteJob(ctx context.Context, sj *agentv1.SignedJob, onOutput func(*agentv1.JobOutput), onShell func(master *os.File, pid int32)) (*agentv1.JobFinished, error) {
	cn, stop, err := c.call(ctx, &helperv1.HelperRequest{Call: &helperv1.HelperRequest_ExecuteJob{ExecuteJob: &helperv1.ExecuteJobRequest{Job: sj}}})
	if err != nil {
		return nil, err
	}
	defer stop()
	shellSeen := false
	for {
		var resp helperv1.HelperResponse
		if err := cn.read(&resp); err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, c.wrap(ctx, fmt.Errorf("helperclient: read: %w", err))
		}
		switch r := resp.GetResult().(type) {
		case *helperv1.HelperResponse_Output:
			if onOutput != nil {
				onOutput(r.Output)
			}
		case *helperv1.HelperResponse_ShellStarted:
			f := cn.takeFile("pty-master")
			if f == nil || shellSeen {
				if f != nil {
					_ = f.Close()
				}
				return nil, fmt.Errorf("%w: ShellStarted without exactly one fd", ErrProtocol)
			}
			shellSeen = true
			if onShell != nil {
				onShell(f, r.ShellStarted.GetPid())
			} else {
				_ = f.Close()
			}
		case *helperv1.HelperResponse_Finished:
			return r.Finished, nil
		case *helperv1.HelperResponse_Error:
			return nil, fmt.Errorf("%w: %s", ErrHelper, r.Error.GetMessage())
		default:
			return nil, fmt.Errorf("%w: unexpected response", ErrProtocol)
		}
	}
}
