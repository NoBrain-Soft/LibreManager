package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/nobrain-soft/libremanager/internal/server/store/storetest"
)

func TestMigrationsApplyAndAuditIsAppendOnly(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	roles, err := st.Q.ListRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 5 {
		t.Fatalf("got %d builtin roles", len(roles))
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO audit_log (ts, actor, action, prev_hash, hash) VALUES ($1, 'x', 'test', '\x00', '\x01')`, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE audit_log SET actor = 'y'`); err == nil {
		t.Fatal("audit_log UPDATE allowed")
	}
	if _, err := st.Pool.Exec(ctx, `DELETE FROM audit_log`); err == nil {
		t.Fatal("audit_log DELETE allowed outside retention mode")
	}
}
