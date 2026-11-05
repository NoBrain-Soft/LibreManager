// Package storetest provides a migrated, isolated PostgreSQL database per
// test. Tests are skipped unless STELLWERK_TEST_DATABASE_URL points at a
// server where the user may create databases.
//
// A template database named after a hash of the migrations is built once
// (guarded by an advisory lock, so parallel `go test` package processes
// share it safely) and cloned for every test.
package storetest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"sort"
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
	templateName string
	templateErr  error
)

// New returns a Store backed by a fresh database cloned from a migrated
// template. The database is dropped when the test ends.
func New(t testing.TB) *store.Store {
	t.Helper()
	admin := os.Getenv(EnvVar)
	if admin == "" {
		t.Skipf("%s not set; skipping database test", EnvVar)
	}
	ctx := context.Background()
	templateOnce.Do(func() { templateName, templateErr = ensureTemplate(ctx, admin) })
	if templateErr != nil {
		t.Fatalf("template db: %v", templateErr)
	}
	name := "stellwerk_test_" + strings.ReplaceAll(ids.New(), "-", "")[:20]
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
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
		defer func() { _ = c.Close(ctx) }()
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

func migrationsHash() (string, error) {
	h := sha256.New()
	var names []string
	err := fs.WalkDir(store.Migrations(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			names = append(names, p)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(names)
	for _, n := range names {
		b, err := fs.ReadFile(store.Migrations(), n)
		if err != nil {
			return "", err
		}
		h.Write([]byte(n))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12], nil
}

func ensureTemplate(ctx context.Context, admin string) (string, error) {
	sum, err := migrationsHash()
	if err != nil {
		return "", err
	}
	name := "stellwerk_tpl_" + sum
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(4242999)"); err != nil {
		return "", err
	}
	defer func() { _, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock(4242999)") }()
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", name).Scan(&exists); err != nil {
		return "", err
	}
	if exists {
		return name, nil
	}
	build := name + "_build"
	_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+build+" WITH (FORCE)")
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+build); err != nil {
		return "", err
	}
	u, err := url.Parse(admin)
	if err != nil {
		return "", err
	}
	u.Path = "/" + build
	st, err := store.Open(ctx, u.String())
	if err != nil {
		return "", err
	}
	err = store.Migrate(ctx, st.Pool)
	st.Close()
	if err != nil {
		return "", err
	}
	if _, err := conn.Exec(ctx, "ALTER DATABASE "+build+" RENAME TO "+name); err != nil {
		return "", err
	}
	return name, nil
}
