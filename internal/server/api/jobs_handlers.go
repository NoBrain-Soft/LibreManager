package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/validate"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	centralv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/central/v1"
	"github.com/nobrain-soft/libremanager/internal/server/api/apigen"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/events"
	"github.com/nobrain-soft/libremanager/internal/server/rbac"
	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// Risk tiers (ARCHITECTURE.md §6.3).
type risk int

const (
	riskLow risk = iota
	riskMedium
	riskHigh
)

// JobTTL is how long a queued envelope stays valid (offline hosts miss it).
const JobTTL = 10 * time.Minute

type jobSpec struct {
	template *agentv1.Job
	perm     string
	risk     risk
}

func buildJob(in apigen.JobCreate) (jobSpec, error) {
	p := deref(in.Params)
	j := &agentv1.Job{}
	spec := jobSpec{template: j}
	pkgs := func(required bool) ([]string, error) {
		list := deref(p.Packages)
		if required && len(list) == 0 {
			return nil, errors.New("packages required")
		}
		for _, n := range list {
			if !validate.PackageName(n) {
				return nil, fmt.Errorf("invalid package name %q", n)
			}
		}
		return list, nil
	}
	switch in.Type {
	case apigen.PkgRefresh:
		j.Action = &agentv1.Job_PkgRefresh{PkgRefresh: &agentv1.PkgRefresh{}}
		spec.perm, spec.risk = rbac.PkgRefresh, riskLow
	case apigen.PkgUpgrade:
		u := &agentv1.PkgUpgrade{}
		switch deref(p.Scope) {
		case apigen.All, "":
			u.Scope = agentv1.UpgradeScope_UPGRADE_SCOPE_ALL
		case apigen.Security:
			u.Scope = agentv1.UpgradeScope_UPGRADE_SCOPE_SECURITY
		case apigen.Named:
			u.Scope = agentv1.UpgradeScope_UPGRADE_SCOPE_NAMED
			list, err := pkgs(true)
			if err != nil {
				return spec, err
			}
			u.Packages = list
		default:
			return spec, errors.New("invalid scope")
		}
		j.Action = &agentv1.Job_PkgUpgrade{PkgUpgrade: u}
		spec.perm, spec.risk = rbac.PkgUpgrade, riskMedium
	case apigen.PkgInstall, apigen.PkgRemove:
		list, err := pkgs(true)
		if err != nil {
			return spec, err
		}
		if in.Type == apigen.PkgInstall {
			j.Action = &agentv1.Job_PkgInstall{PkgInstall: &agentv1.PkgInstall{Packages: list}}
		} else {
			j.Action = &agentv1.Job_PkgRemove{PkgRemove: &agentv1.PkgRemove{Packages: list}}
		}
		spec.perm, spec.risk = rbac.PkgInstall, riskHigh
	case apigen.Service:
		unit := deref(p.Unit)
		if !validate.UnitName(unit) {
			return spec, errors.New("invalid unit name")
		}
		ops := map[apigen.JobParamsOp]agentv1.ServiceOp{
			apigen.Start: agentv1.ServiceOp_SERVICE_OP_START, apigen.Stop: agentv1.ServiceOp_SERVICE_OP_STOP,
			apigen.Restart: agentv1.ServiceOp_SERVICE_OP_RESTART, apigen.Reload: agentv1.ServiceOp_SERVICE_OP_RELOAD,
			apigen.Enable: agentv1.ServiceOp_SERVICE_OP_ENABLE, apigen.Disable: agentv1.ServiceOp_SERVICE_OP_DISABLE,
		}
		op, ok := ops[deref(p.Op)]
		if !ok {
			return spec, errors.New("invalid op")
		}
		j.Action = &agentv1.Job_Service{Service: &agentv1.ServiceAction{Unit: unit, Op: op}}
		spec.perm, spec.risk = rbac.ServiceControl, riskMedium
	case apigen.Reboot:
		d := deref(p.DelayS)
		if d < 0 || d > 3600 {
			return spec, errors.New("delay_s must be 0-3600")
		}
		msg := validate.Text(deref(p.Message), 256)
		j.Action = &agentv1.Job_Reboot{Reboot: &agentv1.Reboot{DelayS: uint32(d), Message: msg}} //nolint:gosec // bounded above
		spec.perm, spec.risk = rbac.HostReboot, riskMedium
	case apigen.RunCheck:
		checks := deref(p.CheckIds)
		for _, c := range checks {
			if !validate.CheckID(c) {
				return spec, fmt.Errorf("invalid check id %q", c)
			}
		}
		j.Action = &agentv1.Job_RunCheck{RunCheck: &agentv1.RunCheck{CheckIds: checks}}
		spec.perm, spec.risk = rbac.SecurityManage, riskLow
	case apigen.CollectInventory:
		j.Action = &agentv1.Job_CollectInventory{CollectInventory: &agentv1.CollectInventory{}}
		spec.perm, spec.risk = rbac.HostView, riskLow
	default:
		return spec, errors.New("unknown job type")
	}
	return spec, nil
}

func (s *Server) resolveTargets(ctx context.Context, t apigen.JobTargets) ([]uuid.UUID, error) {
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	add := func(id uuid.UUID) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range deref(t.HostIds) {
		h, err := s.d.Store.Q.GetHost(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("unknown host %s", id)
		}
		if h.Status != "active" {
			return nil, fmt.Errorf("host %s is %s", h.Hostname, h.Status)
		}
		add(id)
	}
	if groups := deref(t.HostGroupIds); len(groups) > 0 {
		var all []uuid.UUID
		for _, g := range groups {
			sub, err := s.d.Store.Q.GroupSubtree(ctx, g)
			if err != nil {
				return nil, err
			}
			all = append(all, sub...)
		}
		hosts, err := s.d.Store.Q.HostsInGroups(ctx, all)
		if err != nil {
			return nil, err
		}
		for _, h := range hosts {
			add(h)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no target hosts")
	}
	if len(out) > 1000 {
		return nil, errors.New("too many target hosts")
	}
	return out, nil
}

// CreateJob implements apigen.ServerInterface.
func (s *Server) CreateJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in apigen.JobCreate
	if !decode(w, r, &in) {
		return
	}
	spec, err := buildJob(in)
	if err != nil {
		invalid(w, err.Error())
		return
	}
	targets, err := s.resolveTargets(ctx, in.Targets)
	if err != nil {
		invalid(w, err.Error())
		return
	}
	p := principalFrom(ctx)
	for _, h := range targets {
		ok, err := p.CanOnHost(ctx, s.d.Store.Q, spec.perm, h)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if !ok {
			forbidden(w)
			return
		}
	}
	if spec.risk >= riskMedium && !s.requireStepup(w, r) {
		return
	}
	if s.d.Signer == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "signer unavailable")
		return
	}
	u := userFrom(ctx)
	jobID := ids.NewUUID()
	spec.template.JobId = jobID.String()
	spec.template.RequestedBy = u.Username
	hostStrs := make([]string, len(targets))
	for i, h := range targets {
		hostStrs[i] = h.String()
	}
	signed, err := s.d.Signer.SignJobs(ctx, &centralv1.SignJobsRequest{Template: spec.template, HostIds: hostStrs, TtlS: uint32(JobTTL.Seconds())})
	if err != nil {
		slog.WarnContext(ctx, "signer refused job", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "signer refused or unavailable: "+err.Error())
		return
	}
	params, _ := json.Marshal(deref(in.Params))
	var job db.Job
	err = s.d.Store.InTx(ctx, func(q *db.Queries, _ pgxTx) error {
		var err error
		job, err = q.CreateJob(ctx, db.CreateJobParams{ID: jobID, Type: string(in.Type), Params: params, RequestedBy: &u.ID, RequestedByName: u.Username})
		if err != nil {
			return err
		}
		for _, e := range signed.GetEnvelopes() {
			raw, err := proto.Marshal(e.GetSigned())
			if err != nil {
				return err
			}
			var parsed agentv1.Job
			if err := proto.Unmarshal(e.GetSigned().GetJob(), &parsed); err != nil {
				return err
			}
			if err := q.InsertJobTarget(ctx, db.InsertJobTargetParams{JobID: jobID, HostID: uuid.MustParse(e.GetHostId()),
				SignedEnvelope: raw, ExpiresAt: time.Unix(parsed.GetExpiresAt(), 0)}); err != nil {
				return err
			}
		}
		_, err = s.d.Audit.LogTx(ctx, q, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "job.create", Target: "job:" + jobID.String(),
			Details: map[string]any{"type": string(in.Type), "params": json.RawMessage(params), "targets": hostStrs}})
		return err
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	for _, h := range hostStrs {
		_ = s.d.Store.Notify(ctx, store.ChanDispatch, h)
	}
	events.Publish(ctx, s.d.Store, events.Event{Type: events.JobCreated, JobID: jobID.String()})
	out, err := s.jobJSON(ctx, job)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) jobJSON(ctx context.Context, j db.Job) (apigen.Job, error) {
	list, err := s.jobsToJSON(ctx, []db.Job{j})
	if err != nil {
		return apigen.Job{}, err
	}
	return list[0], nil
}

func (s *Server) jobsToJSON(ctx context.Context, jobs []db.Job) ([]apigen.Job, error) {
	jobIDs := make([]uuid.UUID, len(jobs))
	for i, j := range jobs {
		jobIDs[i] = j.ID
	}
	counts, err := s.d.Store.Q.JobTargetCounts(ctx, jobIDs)
	if err != nil {
		return nil, err
	}
	out := make([]apigen.Job, 0, len(jobs))
	for _, j := range jobs {
		var params apigen.JobParams
		_ = json.Unmarshal(j.Params, &params)
		aj := apigen.Job{Id: j.ID, Type: apigen.JobType(j.Type), Params: params, Status: apigen.JobStatus(j.Status),
			RequestedBy: j.RequestedByName, CreatedAt: j.CreatedAt, FinishedAt: j.FinishedAt}
		for _, c := range counts {
			if c.JobID != j.ID {
				continue
			}
			n := int(c.N)
			aj.Counts.Total += n
			switch c.Status {
			case "queued", "dispatched":
				aj.Counts.Queued += n
			case "running":
				aj.Counts.Running += n
			case "succeeded":
				aj.Counts.Succeeded += n
			default:
				aj.Counts.Failed += n
			}
		}
		out = append(out, aj)
	}
	return out, nil
}

// jobVisible reports whether the principal may see a job: global job.view,
// or job.view on at least one of its target hosts.
func (s *Server) jobVisible(ctx context.Context, p *rbac.Principal, jobID uuid.UUID) (bool, error) {
	if p.HasGlobal(rbac.JobView) {
		return true, nil
	}
	targets, err := s.d.Store.Q.ListJobTargets(ctx, jobID)
	if err != nil {
		return false, err
	}
	for _, t := range targets {
		if ok, err := p.CanOnHost(ctx, s.d.Store.Q, rbac.JobView, t.HostID); err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

func (s *Server) jobsJSON(ctx context.Context, limit int, hostID *uuid.UUID) ([]apigen.Job, error) {
	rows, err := s.d.Store.Q.ListJobs(ctx, db.ListJobsParams{HostID: hostID, Lim: int32(limit)}) //nolint:gosec // bounded by caller
	if err != nil {
		return nil, err
	}
	p := principalFrom(ctx)
	visible := rows[:0]
	for _, j := range rows {
		if ok, err := s.jobVisible(ctx, p, j.ID); err == nil && ok {
			visible = append(visible, j)
		}
	}
	return s.jobsToJSON(ctx, visible)
}

// ListJobs implements apigen.ServerInterface.
func (s *Server) ListJobs(w http.ResponseWriter, r *http.Request, params apigen.ListJobsParams) {
	limit := 100
	if params.Limit != nil && *params.Limit > 0 && *params.Limit <= 500 {
		limit = *params.Limit
	}
	out, err := s.jobsJSON(r.Context(), limit, params.HostId)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) loadVisibleJob(w http.ResponseWriter, r *http.Request, id uuid.UUID) (*db.Job, bool) {
	ctx := r.Context()
	j, err := s.d.Store.Q.GetJob(ctx, id)
	if store.IsNotFound(err) {
		notFound(w)
		return nil, false
	}
	if err != nil {
		s.internalError(w, r, err)
		return nil, false
	}
	ok, err := s.jobVisible(ctx, principalFrom(ctx), id)
	if err != nil {
		s.internalError(w, r, err)
		return nil, false
	}
	if !ok {
		notFound(w)
		return nil, false
	}
	return &j, true
}

// GetJob implements apigen.ServerInterface.
func (s *Server) GetJob(w http.ResponseWriter, r *http.Request, id apigen.JobId) {
	j, ok := s.loadVisibleJob(w, r, id)
	if !ok {
		return
	}
	out, err := s.jobJSON(r.Context(), *j)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ListJobTargets implements apigen.ServerInterface.
func (s *Server) ListJobTargets(w http.ResponseWriter, r *http.Request, id apigen.JobId) {
	if _, ok := s.loadVisibleJob(w, r, id); !ok {
		return
	}
	rows, err := s.d.Store.Q.ListJobTargets(r.Context(), id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apigen.JobTarget, 0, len(rows))
	for _, t := range rows {
		var code *int
		if t.ExitCode != nil {
			code = ptr(int(*t.ExitCode))
		}
		out = append(out, apigen.JobTarget{JobId: t.JobID, HostId: t.HostID, Hostname: t.Hostname, Status: apigen.JobTargetStatus(t.Status),
			ExitCode: code, Message: &t.Message, DispatchedAt: t.DispatchedAt, StartedAt: t.StartedAt, FinishedAt: t.FinishedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// GetJobOutput implements apigen.ServerInterface.
func (s *Server) GetJobOutput(w http.ResponseWriter, r *http.Request, jobID apigen.JobId, hostID apigen.HostId, params apigen.GetJobOutputParams) {
	ctx := r.Context()
	if ok, err := principalFrom(ctx).CanOnHost(ctx, s.d.Store.Q, rbac.JobView, hostID); err != nil || !ok {
		notFound(w)
		return
	}
	rows, err := s.d.Store.Q.ListJobOutput(ctx, db.ListJobOutputParams{JobID: jobID, HostID: hostID, ID: deref(params.After)})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apigen.JobOutputChunk, 0, len(rows))
	for _, c := range rows {
		out = append(out, apigen.JobOutputChunk{Id: c.ID, Ts: c.Ts, Stream: apigen.JobOutputChunkStream(c.Stream), Data: strings.ToValidUTF8(string(c.Data), string(utf8.RuneError))})
	}
	writeJSON(w, http.StatusOK, out)
}

// CancelJob implements apigen.ServerInterface.
func (s *Server) CancelJob(w http.ResponseWriter, r *http.Request, id apigen.JobId) {
	ctx := r.Context()
	j, ok := s.loadVisibleJob(w, r, id)
	if !ok {
		return
	}
	p := principalFrom(ctx)
	u := userFrom(ctx)
	if j.RequestedBy == nil || *j.RequestedBy != u.ID {
		targets, err := s.d.Store.Q.ListJobTargets(ctx, id)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		for _, t := range targets {
			if ok, err := p.CanOnHost(ctx, s.d.Store.Q, rbac.JobCancel, t.HostID); err != nil || !ok {
				forbidden(w)
				return
			}
		}
	}
	if _, err := s.d.Store.Q.CancelQueuedTargets(ctx, id); err != nil {
		s.internalError(w, r, err)
		return
	}
	open, err := s.d.Store.Q.OpenTargets(ctx, id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if s.d.Control != nil {
		for _, h := range open {
			if _, err := s.d.Control.CancelJob(ctx, &centralv1.CancelJobRequest{HostId: h.String(), JobId: id.String()}); err != nil {
				slog.WarnContext(ctx, "cancel delivery failed", "host_id", h, "err", err)
			}
		}
	}
	if st, err := s.d.Store.Q.FinalizeJobIfDone(ctx, id); err == nil {
		events.Publish(ctx, s.d.Store, events.Event{Type: events.JobFinished, JobID: id.String(), Status: st})
	}
	s.d.Audit.LogBestEffort(ctx, audit.Entry{Actor: actor(ctx), ActorIP: clientIP(ctx), Action: "job.cancel", Target: "job:" + id.String()})
	w.WriteHeader(http.StatusNoContent)
}

// --- audit

// ListAudit implements apigen.ServerInterface.
func (s *Server) ListAudit(w http.ResponseWriter, r *http.Request, params apigen.ListAuditParams) {
	if !requireGlobal(w, r, rbac.AuditView) {
		return
	}
	limit := int32(100)
	if params.Limit != nil && *params.Limit > 0 && *params.Limit <= 500 {
		limit = int32(*params.Limit) //nolint:gosec // bounded
	}
	rows, err := s.d.Store.Q.ListAudit(r.Context(), db.ListAuditParams{BeforeID: params.BeforeId, Actor: params.Actor, Action: params.Action, Lim: limit})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apigen.AuditEntry, 0, len(rows))
	for _, e := range rows {
		var d map[string]any
		_ = json.Unmarshal(e.Details, &d)
		out = append(out, apigen.AuditEntry{Id: e.ID, Ts: e.Ts, Actor: e.Actor, ActorIp: &e.ActorIp, Action: e.Action, Target: e.Target,
			Details: d, Hash: ptr(audit.HexHash(e.Hash))})
	}
	writeJSON(w, http.StatusOK, out)
}

// VerifyAudit implements apigen.ServerInterface.
func (s *Server) VerifyAudit(w http.ResponseWriter, r *http.Request) {
	if !requireGlobal(w, r, rbac.AuditView) {
		return
	}
	res, err := audit.Verify(r.Context(), s.d.Store.Q)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := apigen.AuditVerifyResult{Ok: res.OK, Checked: res.Checked, Message: &res.Message}
	if !res.OK {
		out.FirstBadId = &res.FirstBadID
	}
	writeJSON(w, http.StatusOK, out)
}

// --- alerts

// ListAlerts implements apigen.ServerInterface.
func (s *Server) ListAlerts(w http.ResponseWriter, r *http.Request, params apigen.ListAlertsParams) {
	ctx := r.Context()
	p := principalFrom(ctx)
	if !p.HasAnywhere(rbac.AlertsView) {
		forbidden(w)
		return
	}
	var st *string
	if params.Status != nil {
		st = ptr(string(*params.Status))
	}
	rows, err := s.d.Store.Q.ListAlerts(ctx, st)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	filter, err := p.HostsWith(ctx, s.d.Store.Q, rbac.AlertsView)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]apigen.Alert, 0, len(rows))
	for _, a := range rows {
		if a.HostID != nil && !filter.Allows(*a.HostID) || a.HostID == nil && !filter.All {
			continue
		}
		labels := map[string]string{}
		_ = json.Unmarshal(a.Labels, &labels)
		out = append(out, apigen.Alert{Id: a.ID, Name: a.Name, Severity: a.Severity, Status: apigen.AlertStatus(a.Status), HostId: a.HostID,
			Hostname: &a.Hostname, Summary: &a.Summary, StartsAt: a.StartsAt, EndsAt: a.EndsAt, Labels: labels})
	}
	writeJSON(w, http.StatusOK, out)
}

// AlertmanagerWebhook implements apigen.ServerInterface. Authenticated with
// a static bearer token shared only with Alertmanager.
func (s *Server) AlertmanagerWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || s.d.WebhookToken == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.d.WebhookToken)) != 1 {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "invalid webhook token")
		return
	}
	var in apigen.AlertmanagerPayload
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		invalid(w, "invalid payload")
		return
	}
	if len(in.Alerts) > 1000 {
		invalid(w, "too many alerts")
		return
	}
	for _, a := range in.Alerts {
		if a.Fingerprint == "" || len(a.Fingerprint) > 64 {
			continue
		}
		var hostID *uuid.UUID
		if hid, ok := a.Labels["host_id"]; ok && ids.Valid(hid) {
			id := uuid.MustParse(hid)
			if _, err := s.d.Store.Q.GetHost(ctx, id); err == nil {
				hostID = &id
			}
		}
		status := "firing"
		if a.Status == "resolved" {
			status = "resolved"
		}
		var ends *time.Time
		if a.EndsAt != nil && !a.EndsAt.IsZero() && status == "resolved" {
			ends = a.EndsAt
		}
		ann := deref(a.Annotations)
		labels, _ := json.Marshal(capMap(a.Labels))
		annotations, _ := json.Marshal(capMap(ann))
		sev := validate.Text(a.Labels["severity"], 16)
		if sev == "" {
			sev = "warning"
		}
		summary := ann["summary"]
		if summary == "" {
			summary = ann["description"]
		}
		row, err := s.d.Store.Q.UpsertAlert(ctx, db.UpsertAlertParams{
			ID: ids.NewUUID(), Fingerprint: "am:" + validate.Text(a.Fingerprint, 64), HostID: hostID,
			Name: validate.Text(a.Labels["alertname"], 128), Severity: sev, Status: status, Summary: validate.Text(summary, 512),
			Labels: labels, Annotations: annotations, StartsAt: a.StartsAt, EndsAt: ends,
		})
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		hid := ""
		if hostID != nil {
			hid = hostID.String()
		}
		events.Publish(ctx, s.d.Store, events.Event{Type: events.Alert, HostID: hid, Status: row.Status, Message: row.Name})
	}
	w.WriteHeader(http.StatusNoContent)
}

func capMap(m map[string]string) map[string]string {
	out := make(map[string]string, min(len(m), 32))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if len(out) >= 32 {
			break
		}
		out[validate.Text(k, 64)] = validate.Text(m[k], 1024)
	}
	return out
}
