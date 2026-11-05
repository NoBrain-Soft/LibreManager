package framing

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	helperv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/helper/v1"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := &helperv1.HelperResponse{Result: &helperv1.HelperResponse_Error{Error: &helperv1.HelperError{Message: "x"}}}
	if err := Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	var out helperv1.HelperResponse
	if err := Read(&buf, &out); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(in, &out) {
		t.Fatal("mismatch")
	}
	if err := Read(&buf, &out); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want EOF", err)
	}
}

func TestRejectsOversizeHeader(t *testing.T) {
	r := bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})
	var out helperv1.HelperResponse
	if err := Read(r, &out); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func socketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan *net.UnixConn, 1)
	go func() {
		c, _ := ln.AcceptUnix()
		ch <- c
	}()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	s := <-ch
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

func TestFDPassingAndPeerCred(t *testing.T) {
	a, b := socketPair(t)
	ca, cb := NewConn(a), NewConn(b)
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("hello-fd"); err != nil {
		t.Fatal(err)
	}
	msg := &helperv1.HelperResponse{Result: &helperv1.HelperResponse_ShellStarted{ShellStarted: &helperv1.ShellStarted{Pid: 42}}}
	if err := ca.WriteWithFile(msg, f); err != nil {
		t.Fatal(err)
	}
	if err := ca.Write(&helperv1.HelperResponse{Result: &helperv1.HelperResponse_Pong{Pong: &helperv1.PingResponse{Version: "v"}}}); err != nil {
		t.Fatal(err)
	}
	var got helperv1.HelperResponse
	if err := cb.Read(&got); err != nil {
		t.Fatal(err)
	}
	if got.GetShellStarted().GetPid() != 42 {
		t.Fatalf("got %v", &got)
	}
	rf := cb.TakeFile("passed")
	if rf == nil {
		t.Fatal("no fd received")
	}
	defer rf.Close()
	if _, err := rf.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rf)
	if string(data) != "hello-fd" {
		t.Fatalf("fd content %q", data)
	}
	if err := cb.Read(&got); err != nil || got.GetPong().GetVersion() != "v" {
		t.Fatalf("second frame: %v %v", err, &got)
	}
	cred, err := PeerCred(b)
	if err != nil {
		t.Fatal(err)
	}
	if int(cred.Uid) != os.Getuid() {
		t.Fatalf("peer uid %d", cred.Uid)
	}
}

func TestReadErrorDoesNotPanic(t *testing.T) {
	a, b := socketPair(t)
	cb := NewConn(b)
	_ = b.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, _ = a.Write([]byte{0, 0, 0, 10}) // header promising 10 bytes, never sent
	var m helperv1.HelperResponse
	if err := cb.Read(&m); err == nil {
		t.Fatal("expected error on deadline")
	}
}
