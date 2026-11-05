// Package storetest provides a migrated, isolated PostgreSQL database per
// test. Tests are skipped unless STELLWERK_TEST_DATABASE_URL points at a
// server where the user may create databases.
package storetest

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/server/store"
)

// EnvVar holds the admin DSN for tests.
const EnvVar = "STELLWERK_TEST_DATABASE_URL"

var (
	templateOnce sync.Once
	templateErr  error
)

const templateName = "stellwerk_test_template"

// New returns a Store backed by a fresh database cloned from a migrated
// template. The database is dropped when the test ends.
func New(t testing.TB) *store.Store {
	t.Helper()
	admin := os.Getenv(EnvVar)
	if admin == "" {
		t.Skipf("%s not set; skipping database test", EnvVar)
	}
	ctx := context.Background()
	templateOnce.Do(func() { templateErr = buildTemplate(ctx, admin) })
	if templateErr != nil {
		t.Fatalf("template db: %v", templateErr)
	}
	name := "stellwerk_test_" + strings.ReplaceAll(ids.New(), "-", "")[:20]
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s", name, templateName)); err != nil {
		t.Fatalf("create db: %v", err)
	}
	st, err := store.Open(ctx, withDB(t, admin, name))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		st.Close()
		c, err := pgx.Connect(ctx, admin)
		if err != nil {
			return
		}
		defer c.Close(ctx)
		_, _ = c.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", name))
	})
	return st
}

func withDB(t testing.TB, dsn, name string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

func buildTemplate(ctx context.Context, admin string) error {
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+templateName+" WITH (FORCE)")
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+templateName); err != nil {
		return err
	}
	u, err := url.Parse(admin)
	if err != nil {
		return err
	}
	u.Path = "/" + templateName
	st, err := store.Open(ctx, u.String())
	if err != nil {
		return err
	}
	defer st.Close()
	return store.Migrate(ctx, st.Pool)
}
