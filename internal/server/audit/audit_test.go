package audit_test

import (
	"context"
	"testing"

	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/store/storetest"
)

func TestChainAndTamperDetection(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	l := audit.New(st)
	for i, a := range []string{"auth.login", "host.enroll", "job.create"} {
		if err := l.Log(ctx, audit.Entry{Actor: "user:alice", ActorIP: "10.0.0.1", Action: a, Target: "x",
			Details: map[string]any{"n": i, "nested": map[string]any{"z": 1.5, "a": []any{"b", true}}}}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := audit.Verify(ctx, st.Q)
	if err != nil || !res.OK || res.Checked != 3 {
		t.Fatalf("verify = %+v, %v", res, err)
	}

	// Tamper with an entry, bypassing the guard trigger as a DB superuser would.
	if _, err := st.Pool.Exec(ctx, `ALTER TABLE audit_log DISABLE TRIGGER audit_log_guard_trg`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE audit_log SET details = '{"n": 99}' WHERE action = 'host.enroll'`); err != nil {
		t.Fatal(err)
	}
	res, err = audit.Verify(ctx, st.Q)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.FirstBadID == 0 {
		t.Fatalf("tampering not detected: %+v", res)
	}

	// Deleting a middle entry is detected too.
	if _, err := st.Pool.Exec(ctx, `UPDATE audit_log SET details = '{"n": 1, "nested": {"a": ["b", true], "z": 1.5}}' WHERE action = 'host.enroll'`); err != nil {
		t.Fatal(err)
	}
	if res, _ := audit.Verify(ctx, st.Q); !res.OK {
		t.Fatalf("restored chain should verify: %+v", res)
	}
	if _, err := st.Pool.Exec(ctx, `DELETE FROM audit_log WHERE action = 'host.enroll'`); err != nil {
		t.Fatal(err)
	}
	if res, _ := audit.Verify(ctx, st.Q); res.OK {
		t.Fatal("deleted entry not detected")
	}
}

func TestCanonicalizeStable(t *testing.T) {
	a, err := audit.Canonicalize([]byte(`{"b": 1, "a": {"d": [1, 2.50, "x"], "c": null}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := audit.Canonicalize([]byte(`{"a":{"c":null,"d":[1,2.5,"x"]},"b":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("%s != %s", a, b)
	}
}

func TestRejectsMissingActor(t *testing.T) {
	st := storetest.New(t)
	if err := audit.New(st).Log(context.Background(), audit.Entry{Action: "x"}); err == nil {
		t.Fatal("entry without actor accepted")
	}
}
