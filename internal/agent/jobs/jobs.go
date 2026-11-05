// Package jobs verifies and dispatches SignedJob envelopes in the agent
// core (ARCHITECTURE.md §6.3). The core checks signature, host, window,
// nonce, local policy and rate limit; privileged actions are then passed
// to the helper as the *original* envelope, which the helper verifies
// again on its own. There is no unsigned path.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/common/envelope"
	"github.com/nobrain-soft/libremanager/internal/common/journal"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Helper is the subset of helperclient.Client used here.
type Helper interface {
	ExecuteJob(ctx context.Context, sj *agentv1.SignedJob, onOutput func(*agentv1.JobOutput), onShell func(master *os.File, pid int32)) (*agentv1.JobFinished, error)
}

// Local runs actions handled by the unprivileged core.
type Local interface {
	RunChecks(ctx context.Context, ids []string) error
	CollectInventory(ctx context.Context) error
	SetProbes(probes []*agentv1.Probe)
}

// ShellRelay connects a spawned PTY to the gateway.
type ShellRelay func(ctx context.Context, grant *agentv1.ShellGrant, requestedBy string, master *os.File) error

// Runner executes verified jobs.
type Runner struct {
	Verifier   *envelope.Verifier
	Policy     *policy.Evaluator
	Limiter    *policy.RateLimiter
	Helper     Helper
	Local      Local
	Shell      ShellRelay
	Journal    journal.Writer
	TimeSynced func() (bool, error)
	// Emit sends a job event to central (buffered by the caller).
	Emit func(*agentv1.JobEvent)
	Now  func() time.Time
	// MaxConcurrent bounds parallel jobs (default 4).
	MaxConcurrent int

	mu      sync.Mutex
	running map[string]context.CancelFunc
	sem     chan struct{}
	once    sync.Once
}

func (r *Runner) init() {
	r.once.Do(func() {
		r.running = map[string]context.CancelFunc{}
		n := r.MaxConcurrent
		if n <= 0 {
			n = 4
		}
		r.sem = make(chan struct{}, n)
		if r.Now == nil {
			r.Now = time.Now
		}
	})
}

// Running returns the number of running jobs.
func (r *Runner) Running() int {
	r.init()
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.running)
}

func (r *Runner) emit(jobID string, ev any) {
	e := &agentv1.JobEvent{JobId: jobID, TimestampMs: r.Now().UnixMilli()}
	switch v := ev.(type) {
	case *agentv1.JobStarted:
		e.Event = &agentv1.JobEvent_Started{Started: v}
	case *agentv1.JobOutput:
		e.Event = &agentv1.JobEvent_Output{Output: v}
	case *agentv1.JobFinished:
		e.Event = &agentv1.JobEvent_Finished{Finished: v}
	}
	if r.Emit != nil {
		r.Emit(e)
	}
}

func (r *Runner) journal(prio int, msg string, job *agentv1.Job, decision string) {
	if r.Journal == nil {
		return
	}
	fields := map[string]string{"STELLWERK_DECISION": decision}
	if job != nil {
		fields["STELLWERK_JOB_ID"] = job.GetJobId()
		fields["STELLWERK_ACTION"] = envelope.ActionName(job)
		fields["STELLWERK_REQUESTED_BY"] = job.GetRequestedBy()
	}
	if err := r.Journal.Send(prio, msg, fields); err != nil {
		slog.Warn("journald write failed", "err", err)
	}
}

// unverifiedJobID extracts the job id from an envelope for error reporting
// only (never acted upon).
func unverifiedJobID(sj *agentv1.SignedJob) string {
	var j agentv1.Job
	if proto.Unmarshal(sj.GetJob(), &j) != nil {
		return ""
	}
	return j.GetJobId()
}

// Verify performs all core-side checks and returns the job.
func (r *Runner) Verify(sj *agentv1.SignedJob) (*agentv1.Job, error) {
	if r.TimeSynced != nil && r.Policy.P.TimeSyncRequired() {
		ok, err := r.TimeSynced()
		if err != nil || !ok {
			return nil, errors.New("clock not synchronized; refusing signed jobs")
		}
	}
	job, err := r.Verifier.Verify(sj)
	if err != nil {
		return nil, err
	}
	if err := r.Policy.Check(job); err != nil {
		return job, err
	}
	if r.Limiter != nil && !r.Limiter.Allow() {
		return job, errors.New("local job rate limit exceeded")
	}
	return job, nil
}

// Handle verifies and runs sj asynchronously.
func (r *Runner) Handle(ctx context.Context, sj *agentv1.SignedJob) {
	r.init()
	job, err := r.Verify(sj)
	if err != nil {
		if errors.Is(err, envelope.ErrReplay) {
			// A duplicate delivery of something we already accepted: do not
			// report, the original run owns the status.
			slog.Info("ignoring replayed job envelope")
			return
		}
		id := job.GetJobId()
		if id == "" {
			id = unverifiedJobID(sj)
		}
		r.journal(journal.PriWarning, "Stellwerk job rejected: "+err.Error(), job, "rejected")
		slog.Warn("job rejected", "job_id", id, "err", err)
		if id != "" {
			r.emit(id, &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_REJECTED, ExitCode: -1, Message: err.Error()})
		}
		return
	}
	r.journal(journal.PriNotice, fmt.Sprintf("Stellwerk job %s (%s) accepted, requested by %s", job.GetJobId(), envelope.ActionName(job), job.GetRequestedBy()), job, "accepted")

	jctx, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	r.running[job.GetJobId()] = cancel
	r.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			r.mu.Lock()
			delete(r.running, job.GetJobId())
			r.mu.Unlock()
		}()
		select {
		case r.sem <- struct{}{}:
		case <-jctx.Done():
			r.emit(job.GetJobId(), &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_CANCELED, ExitCode: -1, Message: "canceled before start"})
			return
		}
		defer func() { <-r.sem }()
		r.emit(job.GetJobId(), &agentv1.JobStarted{})
		fin := r.run(jctx, sj, job)
		if jctx.Err() != nil && fin.GetStatus() != agentv1.JobStatus_JOB_STATUS_SUCCEEDED {
			fin = &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_CANCELED, ExitCode: -1, Message: "canceled"}
		}
		r.journal(journal.PriInfo, fmt.Sprintf("Stellwerk job %s finished: %s", job.GetJobId(), fin.GetStatus()), job, "finished")
		r.emit(job.GetJobId(), fin)
	}()
}

func failed(msg string) *agentv1.JobFinished {
	return &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_FAILED, ExitCode: -1, Message: msg}
}

func (r *Runner) run(ctx context.Context, sj *agentv1.SignedJob, job *agentv1.Job) *agentv1.JobFinished {
	switch a := job.GetAction().(type) {
	case *agentv1.Job_RunCheck:
		if r.Local == nil {
			return failed("checks not available")
		}
		if err := r.Local.RunChecks(ctx, a.RunCheck.GetCheckIds()); err != nil {
			return failed(err.Error())
		}
		return &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_SUCCEEDED, Message: "checks reported"}
	case *agentv1.Job_CollectInventory:
		if r.Local == nil {
			return failed("inventory not available")
		}
		if err := r.Local.CollectInventory(ctx); err != nil {
			return failed(err.Error())
		}
		return &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_SUCCEEDED, Message: "inventory reported"}
	case *agentv1.Job_ProbeConfig:
		if r.Local == nil {
			return failed("probes not available")
		}
		r.Local.SetProbes(a.ProbeConfig.GetProbes())
		return &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_SUCCEEDED, Message: "probes updated"}
	case *agentv1.Job_Script, *agentv1.Job_AgentUpdate:
		return &agentv1.JobFinished{Status: agentv1.JobStatus_JOB_STATUS_REJECTED, ExitCode: -1, Message: "action not enabled in this release"}
	}
	if r.Helper == nil {
		return failed("helper unavailable")
	}
	var onShell func(*os.File, int32)
	shellDone := make(chan struct{})
	if g := job.GetShell(); g != nil {
		if r.Shell == nil {
			return failed("shell relay unavailable")
		}
		onShell = func(master *os.File, _ int32) {
			go func() {
				defer close(shellDone)
				if err := r.Shell(ctx, g, job.GetRequestedBy(), master); err != nil {
					slog.Warn("shell relay ended", "session_id", g.GetSessionId(), "err", err)
				}
			}()
		}
	} else {
		close(shellDone)
	}
	fin, err := r.Helper.ExecuteJob(ctx, sj, func(o *agentv1.JobOutput) { r.emit(job.GetJobId(), o) }, onShell)
	if job.GetShell() != nil {
		// Without ShellStarted (helper refused) the relay never started.
		select {
		case <-shellDone:
		case <-time.After(5 * time.Second):
		}
	}
	if err != nil {
		return failed("helper: " + err.Error())
	}
	return fin
}

// Cancel cancels a running job.
func (r *Runner) Cancel(jobID string) bool {
	r.init()
	r.mu.Lock()
	cancel, ok := r.running[jobID]
	r.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}
