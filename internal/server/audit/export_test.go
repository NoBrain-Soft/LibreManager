package audit_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"strings"
	"testing"

	"github.com/nobrain-soft/libremanager/internal/pki/testpki"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/store/storetest"
)

func TestSyslogExport(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	l := audit.New(st)
	for _, a := range []string{"auth.login", `host."weird"]`} {
		if err := l.Log(ctx, audit.Entry{Actor: "user:alice", Action: a, Target: "x", Details: map[string]any{"k": "v"}}); err != nil {
			t.Fatal(err)
		}
	}
	p := testpki.New(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", p.ServerTLS())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		var msgs []string
		for range 2 {
			m, err := audit.ParseOctetFrame(r)
			if err != nil {
				break
			}
			msgs = append(msgs, m)
		}
		got <- msgs
		for { // later connections: complete handshakes so failures are fast
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	_, port, _ := strings.Cut(ln.Addr().String(), ":")
	e := &audit.Exporter{Store: st, Addr: "localhost:" + port, RootCAs: p.Roots, Hostname: "central"}
	n, err := e.ExportOnce(ctx)
	if err != nil || n != 2 {
		t.Fatalf("export: %d %v", n, err)
	}
	msgs := <-got
	if len(msgs) != 2 || !strings.HasPrefix(msgs[0], "<85>1 ") || !strings.Contains(msgs[0], `action="auth.login"`) ||
		!strings.Contains(msgs[1], `action="host.\"weird\"\]"`) || !strings.Contains(msgs[0], `hash="`) {
		t.Fatalf("messages: %q", msgs)
	}
	// Cursor advanced: nothing more to send.
	if n, err := e.ExportOnce(ctx); err != nil || n != 0 {
		t.Fatalf("second export: %d %v", n, err)
	}
	// Untrusted receiver certificate is refused.
	other := testpki.New(t)
	_ = l.Log(ctx, audit.Entry{Actor: "system", Action: "x"})
	bad := &audit.Exporter{Store: st, Addr: "localhost:" + port, RootCAs: other.Roots}
	if _, err := bad.ExportOnce(ctx); err == nil {
		t.Fatal("exported to an unverified receiver")
	}
}
