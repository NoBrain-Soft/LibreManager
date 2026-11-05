package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/validate"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	"github.com/nobrain-soft/libremanager/internal/server/events"
	"github.com/nobrain-soft/libremanager/internal/server/gateway/remotewrite"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// Labels the gateway sets itself; agent-supplied labels with these names
// are dropped (agents cannot forge identity labels).
var reservedLabels = map[string]bool{"host_id": true, "hostname": true, "groups": true, "instance": true, "job": true}

// Inventory limits per section.
const (
	maxPackages      = 30000
	maxListItems     = 5000
	maxUpdates       = 10000
	maxCheckResults  = 500
	maxProcesses     = 200
	maxLabelsPerSer  = 16
	maxLabelValueLen = 256
)

type seriesMeta struct {
	labels []remotewrite.Label
}

type ingest struct {
	g        *Gateway
	hostID   uuid.UUID
	hostname string
	groups   string
	series   map[uint32]seriesMeta
	dropped  int
	// counters for observability
	droppedSeries int
}

func (in *ingest) loadGroups(ctx context.Context) error {
	refs, err := in.g.cfg.Store.Q.ListHostGroupRefs(ctx, []uuid.UUID{in.hostID})
	if err != nil {
		return err
	}
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	if len(names) > 0 {
		in.groups = "," + strings.Join(names, ",") + ","
	}
	return nil
}

func (in *ingest) handle(ctx context.Context, conn *agentConn, msg *agentv1.ConnectRequest) error {
	switch p := msg.GetPayload().(type) {
	case *agentv1.ConnectRequest_Heartbeat:
		return conn.send(ctx, &agentv1.ConnectResponse{Payload: &agentv1.ConnectResponse_HeartbeatAck{
			HeartbeatAck: &agentv1.HeartbeatAck{ServerTimeMs: in.g.cfg.Now().UnixMilli()}}})
	case *agentv1.ConnectRequest_Metrics:
		in.metrics(p.Metrics)
	case *agentv1.ConnectRequest_Inventory:
		if err := in.inventory(ctx, p.Inventory); err != nil {
			slog.WarnContext(ctx, "inventory ingest", "host_id", in.hostID, "err", err)
		}
	case *agentv1.ConnectRequest_JobEvent:
		if err := in.jobEvent(ctx, p.JobEvent); err != nil {
			slog.WarnContext(ctx, "job event", "host_id", in.hostID, "err", err)
		}
	case *agentv1.ConnectRequest_Processes:
		in.processes(ctx, p.Processes)
	case *agentv1.ConnectRequest_Updates:
		if err := in.updates(ctx, p.Updates); err != nil {
			slog.WarnContext(ctx, "updates ingest", "host_id", in.hostID, "err", err)
		}
	case *agentv1.ConnectRequest_Checks:
		if err := in.checks(ctx, p.Checks); err != nil {
			slog.WarnContext(ctx, "checks ingest", "host_id", in.hostID, "err", err)
		}
	case *agentv1.ConnectRequest_Hello:
		return status.Error(codes.InvalidArgument, "duplicate Hello")
	default:
		// Unknown payload from a newer agent: ignore.
	}
	return nil
}

// --- metrics

func (in *ingest) metrics(b *agentv1.MetricsBatch) {
	if in.g.cfg.RemoteWrite == nil || len(b.GetPoints()) > MaxPointsPerBatch {
		return
	}
	dict := in.series
	if b.GetReplay() {
		dict = map[uint32]seriesMeta{}
	}
	for _, d := range b.GetDefs() {
		if _, exists := dict[d.GetId()]; !exists && len(dict) >= MaxSeriesPerStream {
			in.droppedSeries++
			continue
		}
		if m, ok := in.seriesFromDef(d); ok {
			dict[d.GetId()] = m
		}
	}
	now := in.g.cfg.Now()
	out := rebuild(b, dict, now.Add(-25*time.Hour).UnixMilli(), now.Add(5*time.Minute).UnixMilli())
	in.g.cfg.RemoteWrite.Enqueue(out)
}

// rebuild groups points by series, dropping out-of-range samples.
func rebuild(b *agentv1.MetricsBatch, dict map[uint32]seriesMeta, minTs, maxTs int64) []remotewrite.Series {
	idx := map[uint32]int{}
	var out []remotewrite.Series
	for _, p := range b.GetPoints() {
		m, ok := dict[p.GetSeriesId()]
		if !ok {
			continue
		}
		ts := p.GetTimestampMs()
		if ts == 0 {
			ts = b.GetTimestampMs()
		}
		if ts < minTs || ts > maxTs || math.IsInf(p.GetValue(), 0) {
			continue
		}
		i, ok := idx[p.GetSeriesId()]
		if !ok {
			out = append(out, remotewrite.Series{Labels: m.labels})
			i = len(out) - 1
			idx[p.GetSeriesId()] = i
		}
		out[i].Samples = append(out[i].Samples, remotewrite.Sample{Value: p.GetValue(), TsMs: ts})
	}
	return out
}

func (in *ingest) seriesFromDef(d *agentv1.SeriesDef) (seriesMeta, bool) {
	if !validate.MetricName(d.GetName()) || len(d.GetLabels()) > maxLabelsPerSer {
		in.droppedSeries++
		return seriesMeta{}, false
	}
	labels := make([]remotewrite.Label, 0, len(d.GetLabels())+4)
	labels = append(labels, remotewrite.Label{Name: "__name__", Value: d.GetName()})
	seen := map[string]bool{}
	for _, l := range d.GetLabels() {
		n, v := l.GetName(), l.GetValue()
		if reservedLabels[n] || !validate.LabelName(n) || seen[n] || len(v) > maxLabelValueLen || !utf8.ValidString(v) {
			continue
		}
		seen[n] = true
		labels = append(labels, remotewrite.Label{Name: n, Value: v})
	}
	labels = append(labels,
		remotewrite.Label{Name: "host_id", Value: in.hostID.String()},
		remotewrite.Label{Name: "hostname", Value: in.hostname},
	)
	if in.groups != "" {
		labels = append(labels, remotewrite.Label{Name: "groups", Value: in.groups})
	}
	return seriesMeta{labels: labels}, true
}

// --- inventory

func sectionKind(s *agentv1.InventorySection) (string, proto.Message) {
	switch d := s.GetData().(type) {
	case *agentv1.InventorySection_Os:
		return "os", d.Os
	case *agentv1.InventorySection_Hardware:
		return "hardware", d.Hardware
	case *agentv1.InventorySection_Network:
		return "network", d.Network
	case *agentv1.InventorySection_Packages:
		return "packages", d.Packages
	case *agentv1.InventorySection_Services:
		return "services", d.Services
	case *agentv1.InventorySection_Ports:
		return "ports", d.Ports
	case *agentv1.InventorySection_Users:
		return "users", d.Users
	case *agentv1.InventorySection_Scheduled:
		return "scheduled", d.Scheduled
	case *agentv1.InventorySection_Containers:
		return "containers", d.Containers
	case *agentv1.InventorySection_SshHostKeys:
		return "ssh_host_keys", d.SshHostKeys
	case *agentv1.InventorySection_Certificates:
		return "certificates", d.Certificates
	case *agentv1.InventorySection_Agent:
		return "agent", d.Agent
	}
	return "", nil
}

func listTooLong(m proto.Message) bool {
	switch v := m.(type) {
	case *agentv1.PackageList:
		return len(v.GetPackages()) > maxPackages
	case *agentv1.ServiceList:
		return len(v.GetUnits()) > maxListItems
	case *agentv1.ListeningPorts:
		return len(v.GetPorts()) > maxListItems
	case *agentv1.UserAccounts:
		return len(v.GetUsers()) > maxListItems || len(v.GetGroups()) > maxListItems || len(v.GetSudoRules()) > maxListItems
	case *agentv1.ScheduledTasks:
		return len(v.GetTasks()) > maxListItems
	case *agentv1.Containers:
		return len(v.GetContainers()) > maxListItems
	case *agentv1.Certificates:
		return len(v.GetCertificates()) > 1000
	case *agentv1.NetworkInfo:
		return len(v.GetInterfaces()) > 1000 || len(v.GetRoutes()) > maxListItems
	case *agentv1.Hardware:
		return len(v.GetBlockDevices()) > 1000 || len(v.GetFilesystems()) > 1000
	}
	return false
}

func (in *ingest) inventory(ctx context.Context, rep *agentv1.InventoryReport) error {
	q := in.g.cfg.Store.Q
	collected := time.UnixMilli(rep.GetCollectedAtMs())
	now := in.g.cfg.Now()
	if collected.After(now.Add(5*time.Minute)) || collected.Before(now.Add(-48*time.Hour)) {
		collected = now
	}
	seen := map[string]bool{}
	for _, sec := range rep.GetSections() {
		kind, msg := sectionKind(sec)
		if kind == "" || seen[kind] {
			continue
		}
		seen[kind] = true
		if listTooLong(msg) {
			slog.WarnContext(ctx, "inventory section too large, dropped", "host_id", in.hostID, "kind", kind)
			continue
		}
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(raw)
		if old, err := q.GetInventoryHash(ctx, db.GetInventoryHashParams{HostID: in.hostID, Kind: kind}); err == nil && string(old) == string(sum[:]) {
			continue
		}
		var data []byte
		switch v := msg.(type) {
		case *agentv1.PackageList:
			if err := in.replacePackages(ctx, v); err != nil {
				return err
			}
			data, _ = json.Marshal(map[string]any{"manager": validate.Text(v.GetManager(), 16), "count": len(v.GetPackages())})
		case *agentv1.OsInfo:
			if err := q.UpdateHostOS(ctx, db.UpdateHostOSParams{ID: in.hostID, OsPrettyName: validate.Text(v.GetPrettyName(), 128)}); err != nil {
				return err
			}
		case *agentv1.NetworkInfo:
			if ip := primaryIP(v); ip != "" {
				if err := q.UpdateHostOS(ctx, db.UpdateHostOSParams{ID: in.hostID, OsPrettyName: "", PrimaryIp: ip}); err != nil {
					return err
				}
			}
		}
		if data == nil {
			data, err = jsonOpts.Marshal(msg)
			if err != nil {
				continue
			}
		}
		if err := q.UpsertInventory(ctx, db.UpsertInventoryParams{HostID: in.hostID, Kind: kind, Data: data, Hash: sum[:], CollectedAt: collected}); err != nil {
			return err
		}
	}
	events.Publish(ctx, in.g.cfg.Store, events.Event{Type: events.HostUpdated, HostID: in.hostID.String(), Message: "inventory"})
	return nil
}

func primaryIP(n *agentv1.NetworkInfo) string {
	for _, i := range n.GetInterfaces() {
		if i.GetName() == "lo" || !i.GetUp() {
			continue
		}
		for _, a := range i.GetAddresses() {
			ip := a
			if k := strings.IndexByte(a, '/'); k > 0 {
				ip = a[:k]
			}
			if strings.Contains(ip, ".") && !strings.HasPrefix(ip, "127.") && !strings.HasPrefix(ip, "169.254.") {
				return validate.Text(ip, 64)
			}
		}
	}
	return ""
}

func (in *ingest) replacePackages(ctx context.Context, pl *agentv1.PackageList) error {
	rows := make([][]any, 0, len(pl.GetPackages()))
	seen := map[string]bool{}
	for _, p := range pl.GetPackages() {
		name := validate.Text(p.GetName(), 256)
		arch := validate.Text(p.GetArch(), 32)
		if name == "" || seen[name+"\x00"+arch] {
			continue
		}
		seen[name+"\x00"+arch] = true
		rows = append(rows, []any{in.hostID, name, arch, validate.Text(p.GetVersion(), 256), validate.Text(p.GetSource(), 256),
			validate.Text(p.GetSourceName(), 256), validate.Text(p.GetPurl(), 1024)})
	}
	return in.g.cfg.Store.InTx(ctx, func(q *db.Queries, tx pgx.Tx) error {
		if err := q.DeleteHostPackages(ctx, in.hostID); err != nil {
			return err
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"host_packages"},
			[]string{"host_id", "name", "arch", "version", "source", "source_name", "purl"}, pgx.CopyFromRows(rows))
		return err
	})
}

// --- updates, checks, processes

func (in *ingest) updates(ctx context.Context, u *agentv1.UpdatesReport) error {
	if len(u.GetUpdates()) > maxUpdates {
		return fmt.Errorf("too many updates (%d)", len(u.GetUpdates()))
	}
	checked := time.UnixMilli(u.GetCheckedAtMs())
	if now := in.g.cfg.Now(); checked.After(now.Add(5*time.Minute)) || checked.Before(now.Add(-48*time.Hour)) {
		checked = now
	}
	sec := 0
	rows := make([][]any, 0, len(u.GetUpdates()))
	seen := map[string]bool{}
	for _, p := range u.GetUpdates() {
		name, arch := validate.Text(p.GetName(), 256), validate.Text(p.GetArch(), 32)
		if name == "" || seen[name+"\x00"+arch] {
			continue
		}
		seen[name+"\x00"+arch] = true
		if p.GetIsSecurity() {
			sec++
		}
		adv := make([]string, 0, len(p.GetAdvisories()))
		for i, a := range p.GetAdvisories() {
			if i >= 20 {
				break
			}
			adv = append(adv, validate.Text(a, 64))
		}
		rows = append(rows, []any{in.hostID, name, arch, validate.Text(p.GetCurrentVersion(), 256),
			validate.Text(p.GetCandidateVersion(), 256), validate.Text(p.GetSource(), 256), p.GetIsSecurity(), adv})
	}
	reasons := make([]string, 0, len(u.GetRebootReasons()))
	for i, r := range u.GetRebootReasons() {
		if i >= 50 {
			break
		}
		reasons = append(reasons, validate.Text(r, 256))
	}
	err := in.g.cfg.Store.InTx(ctx, func(q *db.Queries, tx pgx.Tx) error {
		if err := q.DeletePendingUpdates(ctx, in.hostID); err != nil {
			return err
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"pending_updates"},
			[]string{"host_id", "name", "arch", "current_version", "candidate_version", "source", "is_security", "advisories"},
			pgx.CopyFromRows(rows)); err != nil {
			return err
		}
		return q.UpsertUpdateStatus(ctx, db.UpsertUpdateStatusParams{
			HostID: in.hostID, Manager: validate.Text(u.GetManager(), 16), CheckedAt: checked,
			RebootRequired: u.GetRebootRequired(), RebootReasons: reasons, Error: validate.Text(u.GetError(), 1024),
			Total: int32(len(rows)), Security: int32(sec), //nolint:gosec // bounded by maxUpdates
		})
	})
	if err == nil {
		events.Publish(ctx, in.g.cfg.Store, events.Event{Type: events.HostUpdated, HostID: in.hostID.String(), Message: "updates"})
	}
	return err
}

var checkStatus = map[agentv1.CheckStatus]string{
	agentv1.CheckStatus_CHECK_STATUS_PASS: "pass", agentv1.CheckStatus_CHECK_STATUS_FAIL: "fail",
	agentv1.CheckStatus_CHECK_STATUS_WARN: "warn", agentv1.CheckStatus_CHECK_STATUS_NA: "na",
	agentv1.CheckStatus_CHECK_STATUS_ERROR: "error",
}

var severityName = map[agentv1.Severity]string{
	agentv1.Severity_SEVERITY_INFO: "info", agentv1.Severity_SEVERITY_LOW: "low", agentv1.Severity_SEVERITY_MEDIUM: "medium",
	agentv1.Severity_SEVERITY_HIGH: "high", agentv1.Severity_SEVERITY_CRITICAL: "critical",
}

func (in *ingest) checks(ctx context.Context, c *agentv1.CheckReport) error {
	if len(c.GetResults()) > maxCheckResults {
		return fmt.Errorf("too many check results")
	}
	collected := in.g.cfg.Now()
	return in.g.cfg.Store.InTx(ctx, func(q *db.Queries, _ pgx.Tx) error {
		if err := q.DeleteCheckResults(ctx, in.hostID); err != nil {
			return err
		}
		for _, r := range c.GetResults() {
			st, ok := checkStatus[r.GetStatus()]
			if !ok || !validate.CheckID(r.GetCheckId()) {
				continue
			}
			sev, ok := severityName[r.GetSeverity()]
			if !ok {
				sev = "info"
			}
			ev := map[string]string{}
			for k, v := range r.GetEvidence() {
				if len(ev) >= 32 {
					break
				}
				ev[validate.Text(k, 64)] = validate.Text(v, 512)
			}
			evJSON, _ := json.Marshal(ev)
			if err := q.InsertCheckResult(ctx, db.InsertCheckResultParams{
				HostID: in.hostID, CheckID: r.GetCheckId(), Status: st, Severity: sev,
				Title: validate.Text(r.GetTitle(), 256), Summary: validate.Text(r.GetSummary(), 1024),
				Evidence: evJSON, CollectedAt: collected,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (in *ingest) processes(ctx context.Context, p *agentv1.ProcessSnapshot) {
	if len(p.GetTop()) > maxProcesses {
		return
	}
	type proc struct {
		Pid        int32   `json:"pid"`
		Name       string  `json:"name"`
		User       string  `json:"user"`
		CPUPercent float64 `json:"cpu_percent"`
		RSSBytes   uint64  `json:"rss_bytes"`
		Cmdline    string  `json:"cmdline"`
		State      string  `json:"state"`
	}
	list := make([]proc, 0, len(p.GetTop()))
	for _, t := range p.GetTop() {
		list = append(list, proc{Pid: t.GetPid(), Name: validate.Text(t.GetName(), 64), User: validate.Text(t.GetUser(), 64),
			CPUPercent: t.GetCpuPercent(), RSSBytes: t.GetRssBytes(), Cmdline: validate.Text(t.GetCmdline(), 256), State: validate.Text(t.GetState(), 8)})
	}
	b, err := json.Marshal(map[string]any{"total": p.GetTotal(), "processes": list})
	if err != nil {
		return
	}
	ts := in.g.cfg.Now()
	if err := in.g.cfg.Store.Q.UpsertProcesses(ctx, db.UpsertProcessesParams{HostID: in.hostID, Processes: b, ProcessesAt: &ts}); err != nil {
		slog.DebugContext(ctx, "store processes", "err", err)
	}
}

// --- job events

var finishedStatus = map[agentv1.JobStatus]string{
	agentv1.JobStatus_JOB_STATUS_SUCCEEDED: "succeeded",
	agentv1.JobStatus_JOB_STATUS_FAILED:    "failed",
	agentv1.JobStatus_JOB_STATUS_REJECTED:  "rejected",
	agentv1.JobStatus_JOB_STATUS_CANCELED:  "canceled",
	agentv1.JobStatus_JOB_STATUS_TIMED_OUT: "timed_out",
}

var streamName = map[agentv1.OutputStream]string{
	agentv1.OutputStream_OUTPUT_STREAM_STDOUT: "stdout",
	agentv1.OutputStream_OUTPUT_STREAM_STDERR: "stderr",
	agentv1.OutputStream_OUTPUT_STREAM_INFO:   "info",
}

func (in *ingest) jobEvent(ctx context.Context, ev *agentv1.JobEvent) error {
	if !ids.Valid(ev.GetJobId()) {
		return fmt.Errorf("invalid job id")
	}
	jobID := uuid.MustParse(ev.GetJobId())
	q := in.g.cfg.Store.Q
	key := db.GetJobTargetParams{JobID: jobID, HostID: in.hostID}
	// Every query below is scoped to (job, this host): a host can only
	// report on its own targets.
	switch e := ev.GetEvent().(type) {
	case *agentv1.JobEvent_Started:
		n, err := q.MarkTargetRunning(ctx, db.MarkTargetRunningParams(key))
		if err != nil {
			return err
		}
		if n > 0 {
			events.Publish(ctx, in.g.cfg.Store, events.Event{Type: events.JobTarget, JobID: jobID.String(), HostID: in.hostID.String(), Status: "running"})
		}
	case *agentv1.JobEvent_Output:
		data := e.Output.GetData()
		if len(data) == 0 {
			return nil
		}
		if len(data) > 64<<10 {
			data = data[:64<<10]
		}
		total, err := q.AddTargetOutputBytes(ctx, db.AddTargetOutputBytesParams{JobID: jobID, HostID: in.hostID, OutputBytes: int64(len(data))})
		if err != nil {
			return err // unknown target -> ignore
		}
		if total-int64(len(data)) >= MaxOutputPerTarget {
			return nil
		}
		if total > MaxOutputPerTarget {
			data = append(data[:MaxOutputPerTarget-(total-int64(len(data)))], []byte("\n[output truncated by gateway]\n")...)
		}
		stream, ok := streamName[e.Output.GetStream()]
		if !ok {
			stream = "stdout"
		}
		return q.InsertJobOutput(ctx, db.InsertJobOutputParams{JobID: jobID, HostID: in.hostID, Stream: stream, Data: data})
	case *agentv1.JobEvent_Finished:
		st, ok := finishedStatus[e.Finished.GetStatus()]
		if !ok {
			st = "failed"
		}
		code := e.Finished.GetExitCode()
		n, err := q.FinishTarget(ctx, db.FinishTargetParams{JobID: jobID, HostID: in.hostID, Status: st, ExitCode: &code,
			Message: validate.Text(e.Finished.GetMessage(), 1024)})
		if err != nil {
			return err
		}
		if n > 0 {
			events.Publish(ctx, in.g.cfg.Store, events.Event{Type: events.JobTarget, JobID: jobID.String(), HostID: in.hostID.String(), Status: st})
			in.g.finalizeJob(ctx, jobID)
		}
	}
	return nil
}

func (g *Gateway) finalizeJob(ctx context.Context, jobID uuid.UUID) {
	st, err := g.cfg.Store.Q.FinalizeJobIfDone(ctx, jobID)
	if err != nil {
		return // still open, or already final
	}
	events.Publish(ctx, g.cfg.Store, events.Event{Type: events.JobFinished, JobID: jobID.String(), Status: st})
}
