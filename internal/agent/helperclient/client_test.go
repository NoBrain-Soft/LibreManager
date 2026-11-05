package helperclient

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nobrain-soft/libremanager/internal/common/framing"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	helperv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/helper/v1"
)

// fakeHelper accepts one connection and runs script on it.
func fakeHelper(t *testing.T, script func(c *net.UnixConn)) *Client {
	t.Helper()
	p := filepath.Join(t.TempDir(), "h.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		defer c.Close()
		script(c)
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
	return &Client{SocketPath: p, Timeout: 5 * time.Second}
}

func readReq(t *testing.T, c *net.UnixConn) *helperv1.HelperRequest {
	t.Helper()
	var req helperv1.HelperRequest
	if err := framing.Read(c, &req); err != nil {
		t.Errorf("read request: %v", err)
	}
	return &req
}

func send(t *testing.T, c *net.UnixConn, r *helperv1.HelperResponse) {
	t.Helper()
	if err := framing.Write(c, r); err != nil {
		t.Errorf("write: %v", err)
	}
}

func finished(st agentv1.JobStatus) *helperv1.HelperResponse {
	return &helperv1.HelperResponse{Result: &helperv1.HelperResponse_Finished{Finished: &agentv1.JobFinished{Status: st}}}
}

func TestExecuteJobStreamsAndPassesPTY(t *testing.T) {
	cl := fakeHelper(t, func(c *net.UnixConn) {
		if readReq(t, c).GetExecuteJob() == nil {
			t.Error("expected ExecuteJob")
		}
		send(t, c, &helperv1.HelperResponse{Result: &helperv1.HelperResponse_Output{Output: &agentv1.JobOutput{Data: []byte("out")}}})
		f, err := os.CreateTemp(t.TempDir(), "pty")
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = f.WriteString("master")
		defer f.Close()
		if err := framing.NewConn(c).WriteWithFile(&helperv1.HelperResponse{Result: &helperv1.HelperResponse_ShellStarted{ShellStarted: &helperv1.ShellStarted{Pid: 7}}}, f); err != nil {
			t.Error(err)
		}
		send(t, c, finished(agentv1.JobStatus_JOB_STATUS_SUCCEEDED))
	})
	var out string
	var gotPID int32
	var content []byte
	fin, err := cl.ExecuteJob(context.Background(), &agentv1.SignedJob{}, func(o *agentv1.JobOutput) { out += string(o.GetData()) },
		func(m *os.File, pid int32) {
			defer m.Close()
			gotPID = pid
			_, _ = m.Seek(0, io.SeekStart)
			content, _ = io.ReadAll(m)
		})
	if err != nil || fin.GetStatus() != agentv1.JobStatus_JOB_STATUS_SUCCEEDED {
		t.Fatalf("fin %v err %v", fin, err)
	}
	if out != "out" || gotPID != 7 || string(content) != "master" {
		t.Fatalf("out %q pid %d content %q", out, gotPID, content)
	}
}

func TestProtocolViolations(t *testing.T) {
	tests := []struct {
		name   string
		script func(t *testing.T, c *net.UnixConn)
		want   error
	}{
		{"shell started without fd", func(t *testing.T, c *net.UnixConn) {
			readReq(t, c)
			send(t, c, &helperv1.HelperResponse{Result: &helperv1.HelperResponse_ShellStarted{ShellStarted: &helperv1.ShellStarted{Pid: 1}}})
		}, ErrProtocol},
		{"unexpected response", func(t *testing.T, c *net.UnixConn) {
			readReq(t, c)
			send(t, c, &helperv1.HelperResponse{Result: &helperv1.HelperResponse_Pong{Pong: &helperv1.PingResponse{}}})
		}, ErrProtocol},
		{"helper error", func(t *testing.T, c *net.UnixConn) {
			readReq(t, c)
			send(t, c, &helperv1.HelperResponse{Result: &helperv1.HelperResponse_Error{Error: &helperv1.HelperError{Message: "nope"}}})
		}, ErrHelper},
		{"oversize frame", func(t *testing.T, c *net.UnixConn) {
			readReq(t, c)
			_, _ = c.Write([]byte{0xff, 0xff, 0xff, 0xff})
		}, framing.ErrFrameTooLarge},
		{"eof before finished", func(t *testing.T, c *net.UnixConn) {
			readReq(t, c)
		}, io.ErrUnexpectedEOF},
		{"closed without reading (ECONNRESET)", func(t *testing.T, c *net.UnixConn) {
			time.Sleep(50 * time.Millisecond) // let the request arrive unread
		}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cl := fakeHelper(t, func(c *net.UnixConn) { tc.script(t, c) })
			_, err := cl.ExecuteJob(context.Background(), &agentv1.SignedJob{}, nil, nil)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCancelClosesConnection(t *testing.T) {
	sawEOF := make(chan bool, 1)
	cl := fakeHelper(t, func(c *net.UnixConn) {
		readReq(t, c)
		var b [1]byte
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := c.Read(b[:])
		sawEOF <- errors.Is(err, io.EOF)
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	if _, err := cl.ExecuteJob(ctx, &agentv1.SignedJob{}, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if !<-sawEOF {
		t.Fatal("helper did not observe the connection closing")
	}
}

func TestSimpleCalls(t *testing.T) {
	cl := fakeHelper(t, func(c *net.UnixConn) {
		readReq(t, c)
		send(t, c, &helperv1.HelperResponse{Result: &helperv1.HelperResponse_Pong{Pong: &helperv1.PingResponse{Version: "v1", HostId: "h"}}})
	})
	if p, err := cl.Ping(context.Background()); err != nil || p.GetVersion() != "v1" {
		t.Fatalf("ping %v %v", p, err)
	}
	cl = fakeHelper(t, func(c *net.UnixConn) {
		readReq(t, c)
		send(t, c, &helperv1.HelperResponse{Result: &helperv1.HelperResponse_Privileged{Privileged: &helperv1.PrivilegedData{Kind: helperv1.PrivilegedKind_PRIVILEGED_KIND_SUDOERS}}})
	})
	if _, err := cl.ReadPrivileged(context.Background(), helperv1.PrivilegedKind_PRIVILEGED_KIND_SHADOW_FLAGS); !errors.Is(err, ErrProtocol) {
		t.Fatalf("kind mismatch: err = %v", err)
	}
	cl = fakeHelper(t, func(c *net.UnixConn) {
		readReq(t, c)
		_, _ = io.Copy(io.Discard, c) // never answers; returns when the client gives up
	})
	cl.Timeout = 100 * time.Millisecond
	if _, err := cl.ListUpgrades(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: err = %v", err)
	}
	if _, err := (&Client{SocketPath: filepath.Join(t.TempDir(), "absent")}).Ping(context.Background()); err == nil {
		t.Fatal("dial to absent socket succeeded")
	}
}
