package helper

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/common/envelope"
	"github.com/nobrain-soft/libremanager/internal/common/journal"
	"github.com/nobrain-soft/libremanager/internal/helper/pkgmgr"
	"github.com/nobrain-soft/libremanager/internal/helper/runner"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Rejection reasons besides envelope and policy errors.
var (
	errNotHelperAction = errors.New("not a helper action")
	errNotImplemented  = errors.New("not implemented")
	errRateLimited     = errors.New("helper rate limit exceeded")
	errTimeNotSynced   = errors.New("clock not synchronized")
	errTooManyShells   = errors.New("too many concurrent shells")
)

// Per-action execution timeouts.
const (
	pkgTimeout     = 2 * time.Hour
	serviceTimeout = 5 * time.Minute
	rebootTimeout  = time.Minute
)

func (s *Server) executeJob(ctx context.Context, w *responder, sj *agentv1.SignedJob) {
	job, pol, release, err := s.admit(sj)
	if err != nil {
		_ = s.audit(journal.PriWarning, "job rejected: "+err.Error(), sj, job,
			map[string]string{"STELLWERK_DECISION": "rejected", "STELLWERK_REASON": err.Error()})
		w.finish(&agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_REJECTED, Message: err.Error()})
		return
	}
	msg := fmt.Sprintf("executing %s job %s requested by %q", envelope.ActionName(job), job.GetJobId(), job.GetRequestedBy())
	if err := s.audit(journal.PriNotice, msg, sj, job, map[string]string{"STELLWERK_DECISION": "accepted"}); err != nil {
		release()
		s.log.Error("journal unavailable, refusing job", "job_id", job.GetJobId(), "err", err)
		w.finish(&agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_REJECTED, Message: "audit log unavailable"})
		return
	}
	fin := s.run(ctx, w, job, pol)
	release()
	pri := journal.PriNotice
	if fin.GetStatus() != agentv1.JobStatus_JOB_STATUS_SUCCEEDED {
		pri = journal.PriWarning
	}
	_ = s.audit(pri, fmt.Sprintf("job %s finished: %s", job.GetJobId(), fin.GetStatus()), sj, job, map[string]string{
		"STELLWERK_DECISION":  "finished",
		"STELLWERK_STATUS":    fin.GetStatus().String(),
		"STELLWERK_EXIT_CODE": strconv.Itoa(int(fin.GetExitCode())),
	})
	w.finish(fin)
}

// admit performs every check before execution. job is returned (also on
// rejection) once the envelope verified, for logging. release must be
// called once execution ended.
func (s *Server) admit(sj *agentv1.SignedJob) (job *agentv1.Job, pol *policy.Policy, release func(), err error) {
	pol, err = s.policy()
	if err != nil {
		return nil, nil, nil, err
	}
	hostID, err := s.hostID()
	if err != nil {
		return nil, nil, nil, err
	}
	keys, err := s.keyRing()
	if err != nil {
		return nil, nil, nil, err
	}
	// Checked before verification: the validity window is meaningless on
	// an unsynchronized clock, and the nonce is not consumed.
	if pol.TimeSyncRequired() {
		if s.cfg.TimeSynced == nil {
			return nil, nil, nil, fmt.Errorf("%w (status unknown)", errTimeNotSynced)
		}
		if ok, err := s.cfg.TimeSynced(); err != nil || !ok {
			return nil, nil, nil, errTimeNotSynced
		}
	}
	v := envelope.Verifier{Keys: keys, HostID: hostID, Nonces: s.nonces, Now: s.cfg.Now}
	job, err = v.Verify(sj)
	if err != nil {
		return nil, nil, nil, err //nolint:wrapcheck // envelope errors are descriptive
	}
	switch job.GetAction().(type) {
	case *agentv1.Job_PkgRefresh, *agentv1.Job_PkgUpgrade, *agentv1.Job_PkgInstall, *agentv1.Job_PkgRemove,
		*agentv1.Job_Service, *agentv1.Job_Reboot, *agentv1.Job_Shell, *agentv1.Job_FileRead:
	case *agentv1.Job_Script, *agentv1.Job_AgentUpdate:
		return job, nil, nil, errNotImplemented
	default:
		return job, nil, nil, errNotHelperAction
	}
	ev := policy.Evaluator{P: pol, Users: s.cfg.Users}
	if err := ev.Check(job); err != nil {
		return job, nil, nil, err //nolint:wrapcheck
	}
	if !s.allowRate(pol.Limits.MaxJobsPerMinute) {
		return job, nil, nil, errRateLimited
	}
	release = func() {}
	if _, ok := job.GetAction().(*agentv1.Job_Shell); ok {
		if !s.acquireShell(pol.Limits.MaxConcurrentShells) {
			return job, nil, nil, errTooManyShells
		}
		release = s.releaseShell
	}
	return job, pol, release, nil
}

func (s *Server) allowRate(limit int) bool {
	s.mu.Lock()
	if s.limiter == nil || s.limit != limit {
		s.limiter, s.limit = policy.NewRateLimiter(limit, s.cfg.Now), limit
	}
	l := s.limiter
	s.mu.Unlock()
	return l.Allow()
}

func (s *Server) acquireShell(max int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shells >= max {
		return false
	}
	s.shells++
	return true
}

func (s *Server) releaseShell() {
	s.mu.Lock()
	s.shells--
	s.mu.Unlock()
}

// audit writes a journald entry. Before verification only the (untrusted,
// clipped) key id is logged; afterwards the signed job fields.
func (s *Server) audit(pri int, msg string, sj *agentv1.SignedJob, job *agentv1.Job, extra map[string]string) error {
	f := map[string]string{"STELLWERK_COMPONENT": "helper", "STELLWERK_KEY_ID": clean(sj.GetKeyId(), 64)}
	if job != nil {
		f["STELLWERK_JOB_ID"] = job.GetJobId()
		f["STELLWERK_ACTION"] = envelope.ActionName(job)
		f["STELLWERK_REQUESTED_BY"] = job.GetRequestedBy()
		if a := job.GetApprovedBy(); len(a) > 0 {
			f["STELLWERK_APPROVED_BY"] = strings.Join(a, ",")
		}
	}
	maps.Copy(f, extra)
	if err := s.cfg.Journal.Send(pri, msg, f); err != nil {
		return fmt.Errorf("helper: journal: %w", err)
	}
	return nil
}

func (s *Server) run(ctx context.Context, w *responder, job *agentv1.Job, pol *policy.Policy) *agentv1.JobFinished {
	out := &jobOutput{w: w, max: maxJobOutput}
	switch a := job.GetAction().(type) {
	case *agentv1.Job_PkgRefresh:
		return s.pkg(ctx, out, func(ctx context.Context, pm pkgmgr.Manager, o pkgmgr.Output) (pkgmgr.Result, error) {
			return pm.Refresh(ctx, o)
		})
	case *agentv1.Job_PkgUpgrade:
		spec := pkgmgr.UpgradeSpec{Scope: a.PkgUpgrade.GetScope(), Packages: a.PkgUpgrade.GetPackages()}
		return s.pkg(ctx, out, func(ctx context.Context, pm pkgmgr.Manager, o pkgmgr.Output) (pkgmgr.Result, error) {
			return pm.Upgrade(ctx, spec, o)
		})
	case *agentv1.Job_PkgInstall:
		return s.pkg(ctx, out, func(ctx context.Context, pm pkgmgr.Manager, o pkgmgr.Output) (pkgmgr.Result, error) {
			return pm.Install(ctx, a.PkgInstall.GetPackages(), o)
		})
	case *agentv1.Job_PkgRemove:
		return s.pkg(ctx, out, func(ctx context.Context, pm pkgmgr.Manager, o pkgmgr.Output) (pkgmgr.Result, error) {
			return pm.Remove(ctx, a.PkgRemove.GetPackages(), o)
		})
	case *agentv1.Job_Service:
		return s.service(ctx, out, a.Service)
	case *agentv1.Job_Reboot:
		return s.reboot(ctx, out, job, a.Reboot)
	case *agentv1.Job_Shell:
		return s.shell(ctx, w, job, a.Shell)
	case *agentv1.Job_FileRead:
		return s.fileRead(out, pol, a.FileRead)
	}
	return failed("unsupported action")
}

type pkgOp func(context.Context, pkgmgr.Manager, pkgmgr.Output) (pkgmgr.Result, error)

func (s *Server) pkg(ctx context.Context, out *jobOutput, op pkgOp) *agentv1.JobFinished {
	pm, err := s.pkgManager()
	if err != nil {
		return failed(err.Error())
	}
	ctx, cancel := context.WithTimeout(ctx, pkgTimeout)
	defer cancel()
	res, err := op(ctx, pm, pkgmgr.Output{Stdout: out.stream(agentv1.OutputStream_OUTPUT_STREAM_STDOUT), Stderr: out.stream(agentv1.OutputStream_OUTPUT_STREAM_STDERR)})
	return result(ctx, res.ExitCode, err)
}

func serviceVerb(op agentv1.ServiceOp) string {
	switch op {
	case agentv1.ServiceOp_SERVICE_OP_START:
		return "start"
	case agentv1.ServiceOp_SERVICE_OP_STOP:
		return "stop"
	case agentv1.ServiceOp_SERVICE_OP_RESTART:
		return "restart"
	case agentv1.ServiceOp_SERVICE_OP_RELOAD:
		return "reload"
	case agentv1.ServiceOp_SERVICE_OP_ENABLE:
		return "enable"
	case agentv1.ServiceOp_SERVICE_OP_DISABLE:
		return "disable"
	}
	return ""
}

func (s *Server) service(ctx context.Context, out *jobOutput, a *agentv1.ServiceAction) *agentv1.JobFinished {
	verb := serviceVerb(a.GetOp())
	if verb == "" || !policy.ValidUnitName(a.GetUnit()) {
		return failed("invalid service action")
	}
	ctx, cancel := context.WithTimeout(ctx, serviceTimeout)
	defer cancel()
	return s.exec(ctx, out, "systemctl", "--no-ask-password", verb, "--", a.GetUnit())
}

func (s *Server) reboot(ctx context.Context, out *jobOutput, job *agentv1.Job, r *agentv1.Reboot) *agentv1.JobFinished {
	if r.GetDelayS() > 3600 {
		return failed("reboot delay exceeds 3600 s")
	}
	when := "now"
	if d := r.GetDelayS(); d > 0 {
		when = "+" + strconv.Itoa(int((d+59)/60)) // shutdown takes minutes
	}
	wall := "Stellwerk: reboot requested by " + clean(job.GetRequestedBy(), 64)
	if m := clean(r.GetMessage(), 256); m != "" {
		wall += ": " + m
	}
	ctx, cancel := context.WithTimeout(ctx, rebootTimeout)
	defer cancel()
	// "--" keeps a wall message starting with '-' from being parsed as an option.
	return s.exec(ctx, out, "shutdown", "-r", "--", when, wall)
}

func (s *Server) exec(ctx context.Context, out *jobOutput, name string, args ...string) *agentv1.JobFinished {
	code, err := s.cfg.Runner.Run(ctx, runner.Cmd{
		Name: name, Args: args,
		Stdout: out.stream(agentv1.OutputStream_OUTPUT_STREAM_STDOUT),
		Stderr: out.stream(agentv1.OutputStream_OUTPUT_STREAM_STDERR),
	})
	return result(ctx, code, err)
}

func result(ctx context.Context, code int, err error) *agentv1.JobFinished {
	f := &agentv1.JobFinished{ExitCode: int32(code)} //nolint:gosec // exit codes are small
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		f.Status, f.Message = agentv1.JobStatus_JOB_STATUS_TIMED_OUT, "timed out"
	case ctx.Err() != nil:
		f.Status, f.Message = agentv1.JobStatus_JOB_STATUS_CANCELED, "canceled"
	case err != nil:
		f.Status, f.Message = agentv1.JobStatus_JOB_STATUS_FAILED, err.Error()
	case code != 0:
		f.Status, f.Message = agentv1.JobStatus_JOB_STATUS_FAILED, fmt.Sprintf("exited with status %d", code)
	default:
		f.Status = agentv1.JobStatus_JOB_STATUS_SUCCEEDED
	}
	return f
}

func failed(msg string) *agentv1.JobFinished {
	return &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_FAILED, ExitCode: -1, Message: msg}
}

func rejected(err error) *agentv1.JobFinished {
	return &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_REJECTED, ExitCode: -1, Message: err.Error()}
}

// clean keeps printable characters only (no newlines or terminal escapes)
// and caps the length.
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

// jobOutput streams JobOutput frames in chunks of at most maxChunk bytes
// and truncates after max bytes with a single notice.
type jobOutput struct {
	w     *responder
	max   int
	mu    sync.Mutex
	total int
	cut   bool
}

func (o *jobOutput) write(stream agentv1.OutputStream, p []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for len(p) > 0 && !o.cut {
		if o.total >= o.max {
			o.cut = true
			o.w.output(agentv1.OutputStream_OUTPUT_STREAM_INFO, fmt.Appendf(nil, "[stellwerk] output truncated after %d bytes\n", o.max))
			return
		}
		n := min(len(p), maxChunk, o.max-o.total)
		o.w.output(stream, p[:n])
		o.total += n
		p = p[n:]
	}
}

func (o *jobOutput) info(msg string) {
	o.write(agentv1.OutputStream_OUTPUT_STREAM_INFO, []byte(msg+"\n"))
}

func (o *jobOutput) stream(s agentv1.OutputStream) streamWriter { return streamWriter{o: o, s: s} }

type streamWriter struct {
	o *jobOutput
	s agentv1.OutputStream
}

// Write never fails, so a vanished client does not SIGPIPE the child; the
// request context is cancelled instead.
func (sw streamWriter) Write(p []byte) (int, error) {
	sw.o.write(sw.s, p)
	return len(p), nil
}
