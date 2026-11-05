package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/validate"
	"github.com/nobrain-soft/libremanager/internal/server/api/apigen"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/rbac"
	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// ListUsers implements apigen.ServerInterface.
func (s *Server) ListUsers(w http.ResponseWriter, r *http.Request) {
	if !requireGlobal(w, r, rbac.AdminUsers) {
		return
	}
	rows, err := s.d.Store.Q.ListUsers(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apigen.User, 0, len(rows))
	for i := range rows {
		out = append(out, s.userJSON(r.Context(), &rows[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// GetUser implements apigen.ServerInterface.
func (s *Server) GetUser(w http.ResponseWriter, r *http.Request, id apigen.UserId) {
	if !requireGlobal(w, r, rbac.AdminUsers) {
		return
	}
	u, err := s.d.Store.Q.GetUser(r.Context(), id)
	if store.IsNotFound(err) {
		notFound(w)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.userJSON(r.Context(), &u))
}

func (s *Server) validateBindings(r *http.Request, in []apigen.RoleBindingInput) error {
	if len(in) > 100 {
		return errors.New("too many role bindings")
	}
	roles, err := s.d.Store.Q.ListRoles(r.Context())
	if err != nil {
		return err
	}
	for _, b := range in {
		if !slices.ContainsFunc(roles, func(x db.Role) bool { return x.ID == b.RoleId }) {
			return errors.New("unknown role")
		}
		if b.HostGroupId != nil {
			if _, err := s.d.Store.Q.GetHostGroup(r.Context(), *b.HostGroupId); err != nil {
				return errors.New("unknown host group")
			}
		}
	}
	return nil
}

// CreateUser implements apigen.ServerInterface.
func (s *Server) CreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.adminWithStepup(w, r) {
		return
	}
	ctx := r.Context()
	var in apigen.UserCreate
	if !decode(w, r, &in) {
		return
	}
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	if !validUsername(in.Username) {
		invalid(w, "username must match ^[a-z0-9][a-z0-9._-]{0,63}$")
		return
	}
	var bindings []apigen.RoleBindingInput
	if in.RoleBindings != nil {
		bindings = *in.RoleBindings
	}
	if err := s.validateBindings(r, bindings); err != nil {
		invalid(w, err.Error())
		return
	}
	otp, err := auth.GeneratePassword()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	hash, err := auth.HashPassword(otp)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	mfa := true
	if in.MfaRequired != nil {
		mfa = *in.MfaRequired
	}
	var created db.User
	err = s.d.Store.InTx(ctx, func(q *db.Queries, _ pgxTx) error {
		u, err := q.CreateUser(ctx, db.CreateUserParams{
			ID: ids.NewUUID(), Username: in.Username, DisplayName: validate.Text(deref(in.DisplayName), 128),
			Email: validate.Text(deref(in.Email), 255), PasswordHash: &hash, PasswordChangeRequired: true, MfaRequired: mfa,
		})
		if err != nil {
			return err
		}
		created = u
		for _, b := range bindings {
			if err := q.CreateRoleBinding(ctx, db.CreateRoleBindingParams{ID: ids.NewUUID(), UserID: u.ID, RoleID: b.RoleId, HostGroupID: b.HostGroupId}); err != nil {
				return err
			}
		}
		_, err = s.d.Audit.LogTx(ctx, q, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "user.create", Target: "user:" + u.Username,
			Details: map[string]any{"bindings": len(bindings), "mfa_required": mfa}})
		return err
	})
	if isUniqueViolation(err) {
		writeError(w, http.StatusConflict, "conflict", "username already exists")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, apigen.UserCreated{User: s.userJSON(ctx, &created), OneTimePassword: otp})
}

func validUsername(u string) bool {
	if len(u) == 0 || len(u) > 64 {
		return false
	}
	for i, c := range u {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (i > 0 && (c == '.' || c == '_' || c == '-'))
		if !ok {
			return false
		}
	}
	return true
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// UpdateUser implements apigen.ServerInterface.
func (s *Server) UpdateUser(w http.ResponseWriter, r *http.Request, id apigen.UserId) {
	if !s.adminWithStepup(w, r) {
		return
	}
	ctx := r.Context()
	var in apigen.UserUpdate
	if !decode(w, r, &in) {
		return
	}
	if in.Disabled != nil && *in.Disabled {
		if id == userFrom(ctx).ID {
			invalid(w, "you cannot disable your own account")
			return
		}
		if err := s.ensureNotLastAdmin(r, id); err != nil {
			writeError(w, http.StatusConflict, "conflict", err.Error())
			return
		}
	}
	params := db.UpdateUserProfileParams{ID: id, Disabled: in.Disabled, MfaRequired: in.MfaRequired}
	if in.DisplayName != nil {
		params.DisplayName = ptr(validate.Text(*in.DisplayName, 128))
	}
	if in.Email != nil {
		params.Email = ptr(validate.Text(*in.Email, 255))
	}
	u, err := s.d.Store.Q.UpdateUserProfile(ctx, params)
	if store.IsNotFound(err) {
		notFound(w)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if u.Disabled {
		_ = s.d.Store.Q.DeleteUserSessions(ctx, u.ID)
	}
	details, _ := json.Marshal(in)
	var d map[string]any
	_ = json.Unmarshal(details, &d)
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "user.update", Target: "user:" + u.Username, Details: d})
	writeJSON(w, http.StatusOK, s.userJSON(ctx, &u))
}

func (s *Server) ensureNotLastAdmin(r *http.Request, id uuid.UUID) error {
	ctx := r.Context()
	n, err := s.d.Store.Q.CountAdmins(ctx)
	if err != nil {
		return err
	}
	p, err := rbac.Load(ctx, s.d.Store.Q, id, "")
	if err != nil {
		return err
	}
	if p.HasGlobal("*") && n <= 1 {
		return errors.New("cannot remove the last active administrator")
	}
	return nil
}

// DeleteUser implements apigen.ServerInterface.
func (s *Server) DeleteUser(w http.ResponseWriter, r *http.Request, id apigen.UserId) {
	if !s.adminWithStepup(w, r) {
		return
	}
	ctx := r.Context()
	if id == userFrom(ctx).ID {
		invalid(w, "you cannot delete your own account")
		return
	}
	if err := s.ensureNotLastAdmin(r, id); err != nil {
		writeError(w, http.StatusConflict, "conflict", err.Error())
		return
	}
	u, err := s.d.Store.Q.GetUser(ctx, id)
	if store.IsNotFound(err) {
		notFound(w)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.d.Store.Q.DeleteUser(ctx, id); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "user.delete", Target: "user:" + u.Username})
	w.WriteHeader(http.StatusNoContent)
}

// ResetUserPassword implements apigen.ServerInterface.
func (s *Server) ResetUserPassword(w http.ResponseWriter, r *http.Request, id apigen.UserId) {
	if !s.adminWithStepup(w, r) {
		return
	}
	ctx := r.Context()
	u, err := s.d.Store.Q.GetUser(ctx, id)
	if store.IsNotFound(err) {
		notFound(w)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	otp, err := auth.GeneratePassword()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	hash, err := auth.HashPassword(otp)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.d.Store.Q.SetUserPassword(ctx, db.SetUserPasswordParams{ID: id, PasswordHash: &hash, PasswordChangeRequired: true}); err != nil {
		s.internalError(w, r, err)
		return
	}
	_ = s.d.Store.Q.DeleteUserSessions(ctx, id)
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "user.password_reset", Target: "user:" + u.Username})
	writeJSON(w, http.StatusOK, apigen.OneTimePassword{OneTimePassword: otp})
}

// ResetUserMfa implements apigen.ServerInterface.
func (s *Server) ResetUserMfa(w http.ResponseWriter, r *http.Request, id apigen.UserId) {
	if !s.adminWithStepup(w, r) {
		return
	}
	ctx := r.Context()
	u, err := s.d.Store.Q.GetUser(ctx, id)
	if store.IsNotFound(err) {
		notFound(w)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	err = s.d.Store.InTx(ctx, func(q *db.Queries, _ pgxTx) error {
		if err := q.ClearTotp(ctx, id); err != nil {
			return err
		}
		if err := q.DeleteUserWebauthnCredentials(ctx, id); err != nil {
			return err
		}
		if err := q.DeleteUserSessions(ctx, id); err != nil {
			return err
		}
		_, err := s.d.Audit.LogTx(ctx, q, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "user.mfa_reset", Target: "user:" + u.Username})
		return err
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func bindingsJSON(rows []db.ListUserBindingsRow) []apigen.RoleBinding {
	out := make([]apigen.RoleBinding, 0, len(rows))
	for _, b := range rows {
		out = append(out, apigen.RoleBinding{Id: b.ID, RoleId: b.RoleID, RoleName: b.RoleName, HostGroupId: b.HostGroupID, HostGroupName: b.HostGroupName})
	}
	return out
}

// GetUserRoleBindings implements apigen.ServerInterface.
func (s *Server) GetUserRoleBindings(w http.ResponseWriter, r *http.Request, id apigen.UserId) {
	if !requireGlobal(w, r, rbac.AdminUsers) {
		return
	}
	rows, err := s.d.Store.Q.ListUserBindings(r.Context(), id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, bindingsJSON(rows))
}

// SetUserRoleBindings implements apigen.ServerInterface.
func (s *Server) SetUserRoleBindings(w http.ResponseWriter, r *http.Request, id apigen.UserId) {
	if !s.adminWithStepup(w, r) {
		return
	}
	ctx := r.Context()
	var in []apigen.RoleBindingInput
	if !decode(w, r, &in) {
		return
	}
	if err := s.validateBindings(r, in); err != nil {
		invalid(w, err.Error())
		return
	}
	u, err := s.d.Store.Q.GetUser(ctx, id)
	if store.IsNotFound(err) {
		notFound(w)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	err = s.d.Store.InTx(ctx, func(q *db.Queries, _ pgxTx) error {
		if err := q.DeleteUserBindings(ctx, id); err != nil {
			return err
		}
		for _, b := range in {
			if err := q.CreateRoleBinding(ctx, db.CreateRoleBindingParams{ID: ids.NewUUID(), UserID: id, RoleID: b.RoleId, HostGroupID: b.HostGroupId}); err != nil {
				return err
			}
		}
		if n, err := q.CountAdmins(ctx); err != nil || n == 0 {
			return errors.New("last administrator")
		}
		_, err := s.d.Audit.LogTx(ctx, q, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "user.roles_set", Target: "user:" + u.Username,
			Details: map[string]any{"bindings": len(in)}})
		return err
	})
	if err != nil && err.Error() == "last administrator" {
		writeError(w, http.StatusConflict, "conflict", "cannot remove the last active administrator")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	rows, err := s.d.Store.Q.ListUserBindings(ctx, id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, bindingsJSON(rows))
}

// ListRoles implements apigen.ServerInterface.
func (s *Server) ListRoles(w http.ResponseWriter, r *http.Request) {
	rows, err := s.d.Store.Q.ListRoles(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apigen.Role, 0, len(rows))
	for _, x := range rows {
		out = append(out, apigen.Role{Id: x.ID, Name: x.Name, Description: x.Description, Permissions: x.Permissions, Builtin: x.Builtin})
	}
	writeJSON(w, http.StatusOK, out)
}

// --- host groups

type groupSettings struct {
	Shell apigen.GroupShellSettings `json:"shell"`
}

func groupJSON(g db.HostGroup, count int) apigen.HostGroup {
	var gs groupSettings
	_ = json.Unmarshal(g.Settings, &gs)
	return apigen.HostGroup{Id: g.ID, Name: g.Name, ParentId: g.ParentID, Description: g.Description, HostCount: count, Shell: gs.Shell}
}

// ListHostGroups implements apigen.ServerInterface.
func (s *Server) ListHostGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := s.d.Store.Q.ListHostGroups(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apigen.HostGroup, 0, len(rows))
	for _, g := range rows {
		out = append(out, groupJSON(db.HostGroup{ID: g.ID, Name: g.Name, ParentID: g.ParentID, Description: g.Description, Settings: g.Settings}, int(g.HostCount)))
	}
	writeJSON(w, http.StatusOK, out)
}

func validGroupInput(in apigen.HostGroupInput) error {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, ",\n\r\t\"'<>") {
		return errors.New("invalid group name")
	}
	if in.Description != nil && len(*in.Description) > 512 {
		return errors.New("description too long")
	}
	if sh := in.Shell; sh != nil {
		if sh.SharedAccount != nil && *sh.SharedAccount != "" && !validate.AccountName(*sh.SharedAccount) {
			return errors.New("invalid shared account")
		}
		if sh.Identity != nil {
			switch *sh.Identity {
			case apigen.Shared, apigen.PerUser, apigen.Choose:
			default:
				return errors.New("invalid identity mode")
			}
		}
	}
	return nil
}

// CreateHostGroup implements apigen.ServerInterface.
func (s *Server) CreateHostGroup(w http.ResponseWriter, r *http.Request) {
	if !requireGlobal(w, r, rbac.AdminGroups) {
		return
	}
	ctx := r.Context()
	var in apigen.HostGroupInput
	if !decode(w, r, &in) {
		return
	}
	if err := validGroupInput(in); err != nil {
		invalid(w, err.Error())
		return
	}
	if in.ParentId != nil {
		if _, err := s.d.Store.Q.GetHostGroup(ctx, *in.ParentId); err != nil {
			invalid(w, "unknown parent group")
			return
		}
	}
	settings, _ := json.Marshal(groupSettings{Shell: deref(in.Shell)})
	g, err := s.d.Store.Q.CreateHostGroup(ctx, db.CreateHostGroupParams{
		ID: ids.NewUUID(), Name: strings.TrimSpace(in.Name), ParentID: in.ParentId, Description: deref(in.Description), Settings: settings,
	})
	if isUniqueViolation(err) {
		writeError(w, http.StatusConflict, "conflict", "group name already exists")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "group.create", Target: "group:" + g.Name})
	writeJSON(w, http.StatusCreated, groupJSON(g, 0))
}

// UpdateHostGroup implements apigen.ServerInterface.
func (s *Server) UpdateHostGroup(w http.ResponseWriter, r *http.Request, id apigen.GroupId) {
	if !requireGlobal(w, r, rbac.AdminGroups) {
		return
	}
	ctx := r.Context()
	var in apigen.HostGroupInput
	if !decode(w, r, &in) {
		return
	}
	if err := validGroupInput(in); err != nil {
		invalid(w, err.Error())
		return
	}
	if in.ParentId != nil {
		// Prevent cycles: the new parent must not be the group or a descendant.
		sub, err := s.d.Store.Q.GroupSubtree(ctx, id)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if slices.Contains(sub, *in.ParentId) {
			invalid(w, "a group cannot be its own ancestor")
			return
		}
	}
	settings, _ := json.Marshal(groupSettings{Shell: deref(in.Shell)})
	g, err := s.d.Store.Q.UpdateHostGroup(ctx, db.UpdateHostGroupParams{ID: id, Name: strings.TrimSpace(in.Name), ParentID: in.ParentId,
		Description: deref(in.Description), Settings: settings})
	if store.IsNotFound(err) {
		notFound(w)
		return
	}
	if isUniqueViolation(err) {
		writeError(w, http.StatusConflict, "conflict", "group name already exists")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "group.update", Target: "group:" + g.Name})
	writeJSON(w, http.StatusOK, groupJSON(g, 0))
}

// DeleteHostGroup implements apigen.ServerInterface.
func (s *Server) DeleteHostGroup(w http.ResponseWriter, r *http.Request, id apigen.GroupId) {
	if !requireGlobal(w, r, rbac.AdminGroups) {
		return
	}
	ctx := r.Context()
	if n, err := s.d.Store.Q.CountChildGroups(ctx, &id); err == nil && n > 0 {
		writeError(w, http.StatusConflict, "conflict", "group has child groups")
		return
	}
	n, err := s.d.Store.Q.DeleteHostGroup(ctx, id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if n == 0 {
		notFound(w)
		return
	}
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "group.delete", Target: "group:" + id.String()})
	w.WriteHeader(http.StatusNoContent)
}
