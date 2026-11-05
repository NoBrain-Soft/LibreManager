package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/validate"
	"github.com/nobrain-soft/libremanager/internal/server/api/apigen"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/install"
	"github.com/nobrain-soft/libremanager/internal/server/rbac"
	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// canHost checks perm on a host, writing 404 (not 403, to avoid leaking
// existence) when the host is invisible and 403 when only perm is missing.
func (s *Server) canHost(w http.ResponseWriter, r *http.Request, hostID uuid.UUID, perm string) bool {
	ctx := r.Context()
	p := principalFrom(ctx)
	if p == nil {
		forbidden(w)
		return false
	}
	view, err := p.CanOnHost(ctx, s.d.Store.Q, rbac.HostView, hostID)
	if err != nil {
		s.internalError(w, r, err)
		return false
	}
	if !view {
		notFound(w)
		return false
	}
	if perm == rbac.HostView {
		return true
	}
	ok, err := p.CanOnHost(ctx, s.d.Store.Q, perm, hostID)
	if err != nil {
		s.internalError(w, r, err)
		return false
	}
	if !ok {
		forbidden(w)
		return false
	}
	return true
}

func (s *Server) hostsJSON(ctx context.Context, rows []db.Host) ([]apigen.Host, error) {
	idsList := make([]uuid.UUID, 0, len(rows))
	for _, h := range rows {
		idsList = append(idsList, h.ID)
	}
	refs, err := s.d.Store.Q.ListHostGroupRefs(ctx, idsList)
	if err != nil {
		return nil, err
	}
	groups := map[uuid.UUID][]apigen.GroupRef{}
	for _, r := range refs {
		groups[r.HostID] = append(groups[r.HostID], apigen.GroupRef{Id: r.ID, Name: r.Name})
	}
	upd, err := s.d.Store.Q.ListUpdateStatuses(ctx, idsList)
	if err != nil {
		return nil, err
	}
	updates := map[uuid.UUID]db.HostUpdateStatus{}
	for _, u := range upd {
		updates[u.HostID] = u
	}
	out := make([]apigen.Host, 0, len(rows))
	for _, h := range rows {
		out = append(out, hostJSON(h, groups[h.ID], updates))
	}
	return out, nil
}

func hostJSON(h db.Host, groups []apigen.GroupRef, updates map[uuid.UUID]db.HostUpdateStatus) apigen.Host {
	labels := map[string]string{}
	_ = json.Unmarshal(h.Labels, &labels)
	var pol apigen.PolicySummary
	_ = json.Unmarshal(h.Policy, &pol)
	if groups == nil {
		groups = []apigen.GroupRef{}
	}
	out := apigen.Host{
		Id: h.ID, Hostname: h.Hostname, Fqdn: &h.Fqdn, Status: apigen.HostStatus(h.Status), Connected: h.Connected,
		OsFamily: &h.OsFamily, OsId: &h.OsID, OsVersion: &h.OsVersion, OsPrettyName: &h.OsPrettyName, Kernel: &h.Kernel,
		Arch: &h.Arch, AgentVersion: &h.AgentVersion, LastSeenAt: h.LastSeenAt, EnrolledAt: &h.EnrolledAt,
		CertNotAfter: h.CertNotAfter, Labels: labels, Groups: groups, Policy: &pol, PrimaryIp: &h.PrimaryIp,
	}
	if u, ok := updates[h.ID]; ok {
		t, sec, rr := int(u.Total), int(u.Security), u.RebootRequired
		out.Updates = &struct {
			RebootRequired *bool `json:"reboot_required,omitempty"`
			Security       *int  `json:"security,omitempty"`
			Total          *int  `json:"total,omitempty"`
		}{RebootRequired: &rr, Security: &sec, Total: &t}
	}
	return out
}

// ListHosts implements apigen.ServerInterface.
func (s *Server) ListHosts(w http.ResponseWriter, r *http.Request, params apigen.ListHostsParams) {
	ctx := r.Context()
	p := principalFrom(ctx)
	filter, err := p.HostsWith(ctx, s.d.Store.Q, rbac.HostView)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	lp := db.ListHostsParams{Q: params.Q, GroupID: params.GroupId}
	if params.Status != nil {
		lp.Status = ptr(string(*params.Status))
	}
	rows, err := s.d.Store.Q.ListHosts(ctx, lp)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	visible := rows[:0]
	for _, h := range rows {
		if filter.Allows(h.ID) {
			visible = append(visible, h)
		}
	}
	out, err := s.hostsJSON(ctx, visible)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// GetHost implements apigen.ServerInterface.
func (s *Server) GetHost(w http.ResponseWriter, r *http.Request, id apigen.HostId) {
	if !s.canHost(w, r, id, rbac.HostView) {
		return
	}
	h, err := s.d.Store.Q.GetHost(r.Context(), id)
	if store.IsNotFound(err) {
		notFound(w)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out, err := s.hostsJSON(r.Context(), []db.Host{h})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out[0])
}

// UpdateHost implements apigen.ServerInterface.
func (s *Server) UpdateHost(w http.ResponseWriter, r *http.Request, id apigen.HostId) {
	if !s.canHost(w, r, id, rbac.HostManage) {
		return
	}
	ctx := r.Context()
	var in apigen.HostUpdate
	if !decode(w, r, &in) {
		return
	}
	if in.GroupIds != nil && !principalFrom(ctx).HasGlobal(rbac.AdminGroups) {
		forbidden(w)
		return
	}
	if in.Labels != nil {
		if len(*in.Labels) > 64 {
			invalid(w, "too many labels")
			return
		}
		for k, v := range *in.Labels {
			if !validate.LabelKey(k) || len(v) > 256 {
				invalid(w, fmt.Sprintf("invalid label %q", k))
				return
			}
		}
	}
	err := s.d.Store.InTx(ctx, func(q *db.Queries, _ pgxTx) error {
		if in.Labels != nil {
			b, _ := json.Marshal(*in.Labels)
			if err := q.UpdateHostLabels(ctx, db.UpdateHostLabelsParams{ID: id, Labels: b}); err != nil {
				return err
			}
		}
		if in.Status != nil {
			if err := q.SetHostStatus(ctx, db.SetHostStatusParams{ID: id, Status: string(*in.Status)}); err != nil {
				return err
			}
		}
		if in.GroupIds != nil {
			if err := q.SetHostGroupsClear(ctx, id); err != nil {
				return err
			}
			for _, g := range *in.GroupIds {
				if err := q.AddHostToGroup(ctx, db.AddHostToGroupParams{HostID: id, HostGroupID: g}); err != nil {
					return err
				}
			}
		}
		b, _ := json.Marshal(in)
		var d map[string]any
		_ = json.Unmarshal(b, &d)
		_, err := s.d.Audit.LogTx(ctx, q, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "host.update", Target: "host:" + id.String(), Details: d})
		return err
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if in.Status != nil && *in.Status == apigen.HostUpdateStatusDisabled {
		_ = s.d.Store.Notify(ctx, store.ChanRevocations, id.String()) // disconnect it now
	}
	s.GetHost(w, r, id)
}

// DecommissionHost implements apigen.ServerInterface.
func (s *Server) DecommissionHost(w http.ResponseWriter, r *http.Request, id apigen.HostId) {
	if !s.canHost(w, r, id, rbac.HostManage) || !s.requireStepup(w, r) {
		return
	}
	ctx := r.Context()
	err := s.d.Store.InTx(ctx, func(q *db.Queries, _ pgxTx) error {
		if err := q.SetHostStatus(ctx, db.SetHostStatusParams{ID: id, Status: "decommissioned"}); err != nil {
			return err
		}
		serials, err := q.RevokeHostCerts(ctx, db.RevokeHostCertsParams{HostID: id, RevokeReason: "decommissioned"})
		if err != nil {
			return err
		}
		_, err = s.d.Audit.LogTx(ctx, q, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "host.decommission", Target: "host:" + id.String(),
			Details: map[string]any{"revoked_serials": serials}})
		return err
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	_ = s.d.Store.Notify(ctx, store.ChanRevocations, id.String())
	w.WriteHeader(http.StatusNoContent)
}

// GetHostInventory implements apigen.ServerInterface.
func (s *Server) GetHostInventory(w http.ResponseWriter, r *http.Request, id apigen.HostId) {
	if !s.canHost(w, r, id, rbac.HostView) {
		return
	}
	rows, err := s.d.Store.Q.ListInventory(r.Context(), id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	inv := apigen.Inventory{Sections: map[string]apigen.InventorySection{}}
	for _, row := range rows {
		var data map[string]any
		if json.Unmarshal(row.Data, &data) != nil {
			continue
		}
		inv.Sections[row.Kind] = apigen.InventorySection{CollectedAt: row.CollectedAt, Data: data}
	}
	writeJSON(w, http.StatusOK, inv)
}

// ListHostPackages implements apigen.ServerInterface.
func (s *Server) ListHostPackages(w http.ResponseWriter, r *http.Request, id apigen.HostId, params apigen.ListHostPackagesParams) {
	if !s.canHost(w, r, id, rbac.HostView) {
		return
	}
	rows, err := s.d.Store.Q.ListHostPackages(r.Context(), db.ListHostPackagesParams{HostID: id, Q: params.Q})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apigen.Package, 0, len(rows))
	for _, p := range rows {
		out = append(out, apigen.Package{Name: p.Name, Version: p.Version, Arch: p.Arch, Source: &p.Source, Purl: &p.Purl})
	}
	writeJSON(w, http.StatusOK, out)
}

// GetHostUpdates implements apigen.ServerInterface.
func (s *Server) GetHostUpdates(w http.ResponseWriter, r *http.Request, id apigen.HostId) {
	if !s.canHost(w, r, id, rbac.HostView) {
		return
	}
	ctx := r.Context()
	out := apigen.HostUpdates{Updates: []apigen.PendingUpdate{}}
	if st, err := s.d.Store.Q.GetUpdateStatus(ctx, id); err == nil {
		out.Manager = &st.Manager
		out.CheckedAt = &st.CheckedAt
		out.RebootRequired = st.RebootRequired
		out.RebootReasons = &st.RebootReasons
		out.Error = &st.Error
	}
	rows, err := s.d.Store.Q.ListPendingUpdates(ctx, id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	for _, u := range rows {
		out.Updates = append(out.Updates, apigen.PendingUpdate{Name: u.Name, Arch: &u.Arch, CurrentVersion: u.CurrentVersion,
			CandidateVersion: u.CandidateVersion, Source: &u.Source, IsSecurity: u.IsSecurity, Advisories: &u.Advisories})
	}
	writeJSON(w, http.StatusOK, out)
}

// GetHostProcesses implements apigen.ServerInterface.
func (s *Server) GetHostProcesses(w http.ResponseWriter, r *http.Request, id apigen.HostId) {
	if !s.canHost(w, r, id, rbac.HostView) {
		return
	}
	out := apigen.ProcessSnapshot{Processes: []struct {
		Cmdline    *string  `json:"cmdline,omitempty"`
		CpuPercent *float64 `json:"cpu_percent,omitempty"`
		Name       string   `json:"name"`
		Pid        int      `json:"pid"`
		RssBytes   *int64   `json:"rss_bytes,omitempty"`
		State      *string  `json:"state,omitempty"`
		User       *string  `json:"user,omitempty"`
	}{}}
	if rt, err := s.d.Store.Q.GetProcesses(r.Context(), id); err == nil {
		_ = json.Unmarshal(rt.Processes, &out)
		out.CollectedAt = rt.ProcessesAt
	}
	writeJSON(w, http.StatusOK, out)
}

// GetHostChecks implements apigen.ServerInterface.
func (s *Server) GetHostChecks(w http.ResponseWriter, r *http.Request, id apigen.HostId) {
	if !s.canHost(w, r, id, rbac.SecurityView) {
		return
	}
	rows, err := s.d.Store.Q.ListCheckResults(r.Context(), id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apigen.CheckResult, 0, len(rows))
	for _, c := range rows {
		ev := map[string]string{}
		_ = json.Unmarshal(c.Evidence, &ev)
		out = append(out, apigen.CheckResult{CheckId: c.CheckID, Status: apigen.CheckResultStatus(c.Status), Severity: apigen.CheckResultSeverity(c.Severity),
			Title: c.Title, Summary: &c.Summary, Evidence: &ev, CollectedAt: &c.CollectedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// --- enrollment tokens

func tokenJSON(t db.ListEnrollmentTokensRow) apigen.EnrollmentToken {
	labels := map[string]string{}
	_ = json.Unmarshal(t.Labels, &labels)
	return apigen.EnrollmentToken{Id: t.ID, Description: t.Description, HostGroupId: t.HostGroupID, Labels: labels,
		MaxUses: int(t.MaxUses), Uses: int(t.Uses), ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt, CreatedBy: &t.CreatedByName, CreatedAt: t.CreatedAt}
}

// ListEnrollmentTokens implements apigen.ServerInterface.
func (s *Server) ListEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	if !requireGlobal(w, r, rbac.EnrollManage) {
		return
	}
	rows, err := s.d.Store.Q.ListEnrollmentTokens(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apigen.EnrollmentToken, 0, len(rows))
	for _, t := range rows {
		out = append(out, tokenJSON(t))
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateEnrollmentToken implements apigen.ServerInterface.
func (s *Server) CreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	if !requireGlobal(w, r, rbac.EnrollManage) {
		return
	}
	ctx := r.Context()
	var in apigen.EnrollmentTokenCreate
	if !decode(w, r, &in) {
		return
	}
	maxUses, ttl := 1, 24
	if in.MaxUses != nil {
		maxUses = *in.MaxUses
	}
	if in.TtlHours != nil {
		ttl = *in.TtlHours
	}
	if maxUses < 1 || maxUses > 1000 || ttl < 1 || ttl > 720 {
		invalid(w, "max_uses must be 1-1000 and ttl_hours 1-720")
		return
	}
	labels := map[string]string{}
	if in.Labels != nil {
		labels = *in.Labels
	}
	if len(labels) > 32 {
		invalid(w, "too many labels")
		return
	}
	for k, v := range labels {
		if !validate.LabelKey(k) || len(v) > 256 {
			invalid(w, fmt.Sprintf("invalid label %q", k))
			return
		}
	}
	if in.HostGroupId != nil {
		if _, err := s.d.Store.Q.GetHostGroup(ctx, *in.HostGroupId); err != nil {
			invalid(w, "unknown host group")
			return
		}
	}
	secret, err := auth.RandomToken(auth.PrefixEnrollment)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	lb, _ := json.Marshal(labels)
	u := userFrom(ctx)
	t, err := s.d.Store.Q.CreateEnrollmentToken(ctx, db.CreateEnrollmentTokenParams{
		ID: ids.NewUUID(), TokenHash: s.d.Pepper.HashToken(secret), Description: validate.Text(deref(in.Description), 256),
		HostGroupID: in.HostGroupId, Labels: lb, MaxUses: int32(maxUses), //nolint:gosec // bounded above
		ExpiresAt: s.d.Now().Add(time.Duration(ttl) * time.Hour), CreatedBy: &u.ID,
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "enrollment_token.create", Target: "token:" + t.ID.String(),
		Details: map[string]any{"max_uses": maxUses, "ttl_hours": ttl}})
	p := s.installParams()
	script, err := install.Script(p)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, apigen.EnrollmentTokenCreated{
		Token: tokenJSON(db.ListEnrollmentTokensRow{ID: t.ID, Description: t.Description, HostGroupID: t.HostGroupID, Labels: t.Labels,
			MaxUses: t.MaxUses, Uses: t.Uses, ExpiresAt: t.ExpiresAt, CreatedAt: t.CreatedAt, CreatedByName: u.Username}),
		Secret:         secret,
		InstallCommand: install.Command(p, script, secret),
	})
}

// RevokeEnrollmentToken implements apigen.ServerInterface.
func (s *Server) RevokeEnrollmentToken(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	if !requireGlobal(w, r, rbac.EnrollManage) {
		return
	}
	ctx := r.Context()
	n, err := s.d.Store.Q.RevokeEnrollmentToken(ctx, id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if n == 0 {
		notFound(w)
		return
	}
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "enrollment_token.revoke", Target: "token:" + id.String()})
	w.WriteHeader(http.StatusNoContent)
}

// --- dashboard, fleet updates, security summary

// GetDashboard implements apigen.ServerInterface.
func (s *Server) GetDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := s.d.Store.Q
	c, err := q.DashboardCounts(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	u, err := q.UpdatesTotals(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	alerts, _ := q.CountFiringAlerts(ctx)
	certs, _ := q.CountExpiringCerts(ctx)
	out := apigen.Dashboard{
		HostsTotal: int(c.Total), HostsConnected: int(c.Connected), HostsOffline: int(c.Offline),
		UpdatesPendingHosts: int(u.HostsWithUpdates), SecurityUpdates: int(u.SecurityUpdates), RebootRequired: int(u.RebootRequired),
		AlertsFiring: int(alerts), ExpiringCerts: int(certs),
	}
	if principalFrom(ctx).HasAnywhere(rbac.JobView) {
		jobs, err := s.jobsJSON(ctx, 10, nil)
		if err == nil {
			out.RecentJobs = &jobs
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ListFleetUpdates implements apigen.ServerInterface.
func (s *Server) ListFleetUpdates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filter, err := principalFrom(ctx).HostsWith(ctx, s.d.Store.Q, rbac.HostView)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	hosts, err := s.d.Store.Q.ListHosts(ctx, db.ListHostsParams{Status: ptr("active")})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var idsList []uuid.UUID
	for _, h := range hosts {
		if filter.Allows(h.ID) {
			idsList = append(idsList, h.ID)
		}
	}
	st, err := s.d.Store.Q.ListUpdateStatuses(ctx, idsList)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	byID := map[uuid.UUID]db.HostUpdateStatus{}
	for _, x := range st {
		byID[x.HostID] = x
	}
	out := []apigen.HostUpdatesSummary{}
	for _, h := range hosts {
		if !filter.Allows(h.ID) {
			continue
		}
		sum := apigen.HostUpdatesSummary{HostId: h.ID, Hostname: h.Hostname, Connected: h.Connected, OsPrettyName: &h.OsPrettyName}
		if x, ok := byID[h.ID]; ok {
			sum.Total, sum.Security, sum.RebootRequired, sum.CheckedAt = int(x.Total), int(x.Security), x.RebootRequired, &x.CheckedAt
		}
		out = append(out, sum)
	}
	writeJSON(w, http.StatusOK, out)
}

// GetSecuritySummary implements apigen.ServerInterface.
func (s *Server) GetSecuritySummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filter, err := principalFrom(ctx).HostsWith(ctx, s.d.Store.Q, rbac.SecurityView)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	hosts, err := s.d.Store.Q.ListHosts(ctx, db.ListHostsParams{Status: ptr("active")})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var idsList []uuid.UUID
	for _, h := range hosts {
		if filter.Allows(h.ID) {
			idsList = append(idsList, h.ID)
		}
	}
	out := apigen.SecuritySummary{Hosts: len(idsList), FailingChecks: []struct {
		CheckId   string `json:"check_id"`
		HostCount int    `json:"host_count"`
		Severity  string `json:"severity"`
		Title     string `json:"title"`
	}{}}
	fails, err := s.d.Store.Q.FailingChecks(ctx, idsList)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	for _, f := range fails {
		out.FailingChecks = append(out.FailingChecks, struct {
			CheckId   string `json:"check_id"`
			HostCount int    `json:"host_count"`
			Severity  string `json:"severity"`
			Title     string `json:"title"`
		}{CheckId: f.CheckID, HostCount: int(f.HostCount), Severity: f.Severity, Title: f.Title})
	}
	if rate, err := s.d.Store.Q.CheckPassRate(ctx, idsList); err == nil && rate.Evaluated > 0 {
		out.CompliancePercent = ptr(100 * float64(rate.Passed) / float64(rate.Evaluated))
	}
	writeJSON(w, http.StatusOK, out)
}

// --- metrics proxy

type panelDef struct {
	unit    string
	queries []panelQuery
}

type panelQuery struct {
	// expr uses %[1]s for the host selector and %[2]s for the rate window.
	expr string
	// label is a template: "{mode}" style placeholders resolved from series labels, or a fixed string.
	label string
}

// Queries are built server-side with a validated host id; the caller only
// picks a panel name, so no user-controlled MetricsQL reaches VictoriaMetrics.
var panels = map[apigen.MetricsPanel]panelDef{
	apigen.Cpu: {unit: "percent", queries: []panelQuery{{
		expr:  `100 * sum by (mode) (rate(stellwerk_cpu_seconds_total{%[1]s,mode!="idle"}[%[2]s])) / scalar(sum(rate(stellwerk_cpu_seconds_total{%[1]s}[%[2]s])))`,
		label: "{mode}"}}},
	apigen.Load: {unit: "count", queries: []panelQuery{
		{expr: `stellwerk_load1{%[1]s}`, label: "load1"}, {expr: `stellwerk_load5{%[1]s}`, label: "load5"}, {expr: `stellwerk_load15{%[1]s}`, label: "load15"}}},
	apigen.Memory: {unit: "bytes", queries: []panelQuery{
		{expr: `stellwerk_memory_total_bytes{%[1]s} - stellwerk_memory_available_bytes{%[1]s}`, label: "used"},
		{expr: `stellwerk_memory_cached_bytes{%[1]s}`, label: "cached"},
		{expr: `stellwerk_memory_buffers_bytes{%[1]s}`, label: "buffers"},
		{expr: `stellwerk_memory_total_bytes{%[1]s}`, label: "total"}}},
	apigen.Swap: {unit: "bytes", queries: []panelQuery{
		{expr: `stellwerk_swap_total_bytes{%[1]s} - stellwerk_swap_free_bytes{%[1]s}`, label: "used"},
		{expr: `stellwerk_swap_total_bytes{%[1]s}`, label: "total"}}},
	apigen.DiskUsage: {unit: "percent", queries: []panelQuery{{
		expr:  `100 * (1 - stellwerk_filesystem_avail_bytes{%[1]s} / stellwerk_filesystem_size_bytes{%[1]s})`,
		label: "{mountpoint}"}}},
	apigen.DiskIo: {unit: "bytes_per_second", queries: []panelQuery{
		{expr: `sum by (device) (rate(stellwerk_disk_read_bytes_total{%[1]s}[%[2]s]))`, label: "{device} read"},
		{expr: `sum by (device) (rate(stellwerk_disk_written_bytes_total{%[1]s}[%[2]s]))`, label: "{device} write"}}},
	apigen.Network: {unit: "bytes_per_second", queries: []panelQuery{
		{expr: `sum by (device) (rate(stellwerk_network_receive_bytes_total{%[1]s}[%[2]s]))`, label: "{device} rx"},
		{expr: `sum by (device) (rate(stellwerk_network_transmit_bytes_total{%[1]s}[%[2]s]))`, label: "{device} tx"}}},
	apigen.Tcp: {unit: "count", queries: []panelQuery{{expr: `sum by (state) (stellwerk_tcp_connections{%[1]s})`, label: "{state}"}}},
	apigen.Pressure: {unit: "percent", queries: []panelQuery{{
		expr: `100 * rate(stellwerk_pressure_seconds_total{%[1]s}[%[2]s])`, label: "{resource} {kind}"}}},
}

type vmResponse struct {
	Status string `json:"status"`
	Data   struct {
		Result []struct {
			Metric map[string]string `json:"metric"`
			Values [][2]any          `json:"values"`
		} `json:"result"`
	} `json:"data"`
	Error string `json:"error"`
}

func resolveLabel(tmpl string, m map[string]string) string {
	out := []byte{}
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] == '{' {
			if j := indexByte(tmpl[i:], '}'); j > 0 {
				out = append(out, m[tmpl[i+1:i+j]]...)
				i += j
				continue
			}
		}
		out = append(out, tmpl[i])
	}
	return string(out)
}

func indexByte(s string, c byte) int {
	for i := range len(s) {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// GetHostMetrics implements apigen.ServerInterface.
func (s *Server) GetHostMetrics(w http.ResponseWriter, r *http.Request, id apigen.HostId, panel apigen.MetricsPanel, params apigen.GetHostMetricsParams) {
	if !s.canHost(w, r, id, rbac.HostView) {
		return
	}
	def, ok := panels[panel]
	if !ok {
		invalid(w, "unknown panel")
		return
	}
	start, end := params.Start, params.End
	if end <= start || end-start > 400*86400 {
		invalid(w, "invalid time range")
		return
	}
	step := int64(15)
	if params.Step != nil {
		step = int64(*params.Step)
	}
	step = max(step, (end-start)/600, 15)
	window := fmt.Sprintf("%ds", max(2*step, 60))
	selector := fmt.Sprintf(`host_id=%q`, id.String()) // id is a parsed UUID
	out := apigen.MetricsResponse{Panel: panel, Unit: def.unit}
	out.Series = []struct {
		Label  string      `json:"label"`
		Points [][]float64 `json:"points"`
	}{}
	for _, pq := range def.queries {
		expr := fmt.Sprintf(pq.expr, selector, window)
		v := url.Values{}
		v.Set("query", expr)
		v.Set("start", strconv.FormatInt(start, 10))
		v.Set("end", strconv.FormatInt(end, 10))
		v.Set("step", strconv.FormatInt(step, 10))
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.d.Cfg.VictoriaMetricsURL+"/api/v1/query_range?"+v.Encode(), nil)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		resp, err := s.d.VMClient.Do(req)
		if err != nil {
			writeError(w, http.StatusBadGateway, "unavailable", "metrics backend unavailable")
			return
		}
		var vr vmResponse
		err = json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 16<<20)).Decode(&vr)
		resp.Body.Close()
		if err != nil || vr.Status != "success" {
			writeError(w, http.StatusBadGateway, "unavailable", "metrics query failed")
			return
		}
		for _, res := range vr.Data.Result {
			pts := make([][]float64, 0, len(res.Values))
			for _, val := range res.Values {
				ts, ok1 := val[0].(float64)
				sv, ok2 := val[1].(string)
				f, err := strconv.ParseFloat(sv, 64)
				if !ok1 || !ok2 || err != nil {
					continue
				}
				pts = append(pts, []float64{ts, f})
			}
			out.Series = append(out.Series, struct {
				Label  string      `json:"label"`
				Points [][]float64 `json:"points"`
			}{Label: resolveLabel(pq.label, res.Metric), Points: pts})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
