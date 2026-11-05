package rbac_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/server/rbac"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
	"github.com/nobrain-soft/libremanager/internal/server/store/storetest"
)

func TestMatches(t *testing.T) {
	cases := []struct {
		g, p string
		want bool
	}{
		{"*", "admin.users", true},
		{"admin.*", "admin.users", true},
		{"admin.*", "administrator.x", false},
		{"host.view", "host.view", true},
		{"host.view", "host.manage", false},
	}
	for _, c := range cases {
		if rbac.Matches(c.g, c.p) != c.want {
			t.Errorf("Matches(%q,%q) != %v", c.g, c.p, c.want)
		}
	}
}

// TestScopedMatrix: a shell-user bound to group "web" (child "web-eu") can open
// shells on hosts in web and web-eu but not in "db"; nothing global.
func TestScopedMatrix(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q
	mkGroup := func(name string, parent *uuid.UUID) uuid.UUID {
		g, err := q.CreateHostGroup(ctx, db.CreateHostGroupParams{ID: ids.NewUUID(), Name: name, ParentID: parent, Settings: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		return g.ID
	}
	mkHost := func(name string, g uuid.UUID) uuid.UUID {
		h, err := q.CreateHost(ctx, db.CreateHostParams{ID: ids.NewUUID(), Hostname: name, Labels: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		if err := q.AddHostToGroup(ctx, db.AddHostToGroupParams{HostID: h.ID, HostGroupID: g}); err != nil {
			t.Fatal(err)
		}
		return h.ID
	}
	web := mkGroup("web", nil)
	webEU := mkGroup("web-eu", &web)
	dbg := mkGroup("db", nil)
	hWeb := mkHost("web1", web)
	hWebEU := mkHost("web-eu1", webEU)
	hDB := mkHost("db1", dbg)

	u, err := q.CreateUser(ctx, db.CreateUserParams{ID: ids.NewUUID(), Username: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	role, err := q.GetRoleByName(ctx, "shell-user")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.CreateRoleBinding(ctx, db.CreateRoleBindingParams{ID: ids.NewUUID(), UserID: u.ID, RoleID: role.ID, HostGroupID: &web}); err != nil {
		t.Fatal(err)
	}
	p, err := rbac.Load(ctx, q, u.ID, "bob")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host uuid.UUID
		perm string
		want bool
	}{
		{hWeb, rbac.ShellOpen, true},
		{hWebEU, rbac.ShellOpen, true},
		{hDB, rbac.ShellOpen, false},
		{hWeb, rbac.PkgUpgrade, false},
		{hWeb, rbac.ShellRoot, false},
	} {
		got, err := p.CanOnHost(ctx, q, tc.perm, tc.host)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("CanOnHost(%s, %v) = %v, want %v", tc.perm, tc.host, got, tc.want)
		}
	}
	if p.HasGlobal(rbac.ShellOpen) || p.HasGlobal(rbac.AdminUsers) {
		t.Error("scoped binding leaked into global")
	}
	f, err := p.HostsWith(ctx, q, rbac.HostView)
	if err != nil {
		t.Fatal(err)
	}
	if f.All || !f.Allows(hWeb) || !f.Allows(hWebEU) || f.Allows(hDB) {
		t.Errorf("host filter wrong: %+v", f)
	}
}
