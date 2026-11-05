package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nobrain-soft/libremanager/internal/agent/policy"
	"github.com/nobrain-soft/libremanager/internal/common/journal"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
	helperv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/helper/v1"
)

// shellKillGrace is the time between SIGHUP and SIGKILL when a shell is
// terminated (max duration, cancellation, client gone).
const shellKillGrace = 5 * time.Second

// shell spawns the user's login shell on a new PTY, hands the master fd to
// the core and waits for the shell to exit. The core owns the I/O (and the
// idle timeout); the helper enforces max_duration_s and kills the shell
// when the core disconnects.
func (s *Server) shell(ctx context.Context, w *responder, job *agentv1.Job, g *agentv1.ShellGrant) *agentv1.JobFinished {
	u, err := s.cfg.Users.Lookup(g.GetUnixUser())
	if err != nil {
		return failed("unknown unix user")
	}
	cred, err := s.credential(u)
	if err != nil {
		return failed(err.Error())
	}
	sh, err := s.cfg.LoginShell(u)
	if err != nil {
		return failed(err.Error())
	}
	master, slave, err := openPTY()
	if err != nil {
		return failed(err.Error())
	}
	defer func() { _ = master.Close() }()
	defer func() { _ = slave.Close() }()
	rows, cols := uint16(24), uint16(80)
	if g.GetRows() > 0 && g.GetCols() > 0 {
		rows, cols = uint16(g.GetRows()), uint16(g.GetCols()) //nolint:gosec // policy caps at 1000
	}
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols}); err != nil { //nolint:gosec // fd fits int
		return failed("pty: set window size")
	}
	if cred != nil {
		// Like login/sshd: the terminal belongs to the user, group tty.
		ttyGID := int(cred.Gid)
		if grp, err := user.LookupGroup("tty"); err == nil {
			if n, err := strconv.Atoi(grp.Gid); err == nil {
				ttyGID = n
			}
		}
		if err := slave.Chown(int(cred.Uid), ttyGID); err != nil {
			return failed("pty: chown")
		}
		if err := slave.Chmod(0o620); err != nil {
			return failed("pty: chmod")
		}
	}
	home := u.HomeDir
	if st, err := os.Stat(home); err != nil || !st.IsDir() {
		home = "/"
	}
	cmd := &exec.Cmd{
		Path:   sh,
		Args:   []string{"-" + filepath.Base(sh)},
		Env:    shellEnv(u, sh, home),
		Dir:    home,
		Stdin:  slave,
		Stdout: slave,
		Stderr: slave,
		SysProcAttr: &syscall.SysProcAttr{
			Setsid: true, Setctty: true, Ctty: 0, Credential: cred,
		},
	}
	if err := cmd.Start(); err != nil {
		return failed("cannot start shell: " + err.Error())
	}
	_ = slave.Close()
	pid := cmd.Process.Pid
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait() // status is read from cmd.ProcessState
		close(done)
	}()
	start := time.Now()
	fields := map[string]string{
		"STELLWERK_SESSION_ID": g.GetSessionId(), "STELLWERK_UNIX_USER": u.Username, "STELLWERK_PID": strconv.Itoa(pid),
	}
	_ = s.audit(journal.PriNotice, fmt.Sprintf("shell opened for %q as %s (pid %d)", job.GetRequestedBy(), u.Username, pid), nil, job, fields)

	var status agentv1.JobStatus
	if err := w.write(&helperv1.HelperResponse{Result: &helperv1.HelperResponse_ShellStarted{ShellStarted: &helperv1.ShellStarted{Pid: int32(pid)}}}, master); err != nil { //nolint:gosec // pid fits int32
		status = agentv1.JobStatus_JOB_STATUS_FAILED
		terminate(pid, done)
	} else {
		_ = master.Close()
		timer := time.NewTimer(time.Duration(g.GetMaxDurationS()) * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-ctx.Done():
			status = agentv1.JobStatus_JOB_STATUS_CANCELED
			terminate(pid, done)
		case <-timer.C:
			status = agentv1.JobStatus_JOB_STATUS_TIMED_OUT
			terminate(pid, done)
		}
	}
	fin := shellResult(cmd.ProcessState, status)
	fields["STELLWERK_STATUS"] = fin.GetStatus().String()
	_ = s.audit(journal.PriNotice, fmt.Sprintf("shell closed for %q as %s after %s: %s", job.GetRequestedBy(), u.Username,
		time.Since(start).Round(time.Second), fin.GetStatus()), nil, job, fields)
	return fin
}

func shellResult(ps *os.ProcessState, status agentv1.JobStatus) *agentv1.JobFinished {
	fin := &agentv1.JobFinished{Status: status, ExitCode: -1}
	if ps != nil {
		fin.ExitCode = int32(ps.ExitCode()) //nolint:gosec // small
		if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			fin.ExitCode = 128 + int32(ws.Signal()) //nolint:gosec // signal numbers are small
		}
	}
	if fin.Status == agentv1.JobStatus_JOB_STATUS_UNSPECIFIED {
		fin.Status = agentv1.JobStatus_JOB_STATUS_SUCCEEDED
		if fin.ExitCode != 0 {
			fin.Status = agentv1.JobStatus_JOB_STATUS_FAILED
		}
	}
	fin.Message = "shell exited with status " + strconv.Itoa(int(fin.ExitCode))
	return fin
}

// terminate hangs up the shell's process group (the shell is its session
// leader), escalating to SIGKILL, and waits for the shell to be reaped.
// The group id cannot be reallocated while the shell is unreaped or any
// group member is alive, so the signals cannot hit an unrelated process.
func terminate(pid int, done <-chan struct{}) {
	_ = unix.Kill(-pid, unix.SIGHUP)
	_ = unix.Kill(-pid, unix.SIGCONT)
	select {
	case <-done:
		return
	case <-time.After(shellKillGrace):
	}
	_ = unix.Kill(-pid, unix.SIGKILL)
	<-done
}

// credential returns the uid/gid/groups to switch to. When the helper is
// not root (development), it can only spawn shells as itself.
func (s *Server) credential(u *user.User) (*syscall.Credential, error) {
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil {
		return nil, errors.New("invalid uid/gid")
	}
	if os.Geteuid() != 0 {
		if int(uid) != os.Geteuid() { //nolint:gosec // uid fits
			return nil, errors.New("helper is not running as root")
		}
		return nil, nil //nolint:nilnil // no switch needed
	}
	gids, err := s.cfg.Users.GroupIDs(u)
	if err != nil {
		return nil, errors.New("cannot resolve groups")
	}
	c := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	for _, g := range gids {
		if n, err := strconv.ParseUint(g, 10, 32); err == nil {
			c.Groups = append(c.Groups, uint32(n))
		}
	}
	return c, nil
}

func shellEnv(u *user.User, sh, home string) []string {
	path := "/usr/local/bin:/usr/bin:/bin"
	if u.Uid == "0" {
		path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	env := []string{
		"HOME=" + home, "USER=" + u.Username, "LOGNAME=" + u.Username, "SHELL=" + sh,
		"PATH=" + path, "TERM=xterm-256color",
	}
	if lang := os.Getenv("LANG"); lang != "" && clean(lang, 64) == lang && !strings.ContainsAny(lang, " /") {
		env = append(env, "LANG="+lang)
	}
	return env
}

// defaultLoginShell returns the account's shell from /etc/passwd.
func defaultLoginShell(u *user.User) (string, error) {
	sh := policy.LoginShell(u.Username)
	if sh == "" || !filepath.IsAbs(sh) || filepath.Clean(sh) != sh ||
		strings.HasSuffix(sh, "/nologin") || strings.HasSuffix(sh, "/false") {
		return "", errors.New("account has no login shell")
	}
	st, err := os.Stat(sh)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
		return "", errors.New("login shell is not executable")
	}
	return sh, nil
}

// openPTY allocates a pseudo terminal pair without cgo or extra deps.
func openPTY() (master, slave *os.File, err error) {
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("pty: open /dev/ptmx: %w", err)
	}
	master = os.NewFile(uintptr(mfd), "/dev/ptmx")
	if err := unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		_ = master.Close()
		return nil, nil, fmt.Errorf("pty: unlock: %w", err)
	}
	// TIOCGPTPEER (Linux 4.13+) opens the peer without a path lookup.
	sfd, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(mfd), unix.TIOCGPTPEER, uintptr(unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC))
	if errno != 0 {
		n, err := unix.IoctlGetUint32(mfd, unix.TIOCGPTN)
		if err != nil {
			_ = master.Close()
			return nil, nil, fmt.Errorf("pty: TIOCGPTN: %w", err)
		}
		fd, err := unix.Open("/dev/pts/"+strconv.FormatUint(uint64(n), 10), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if err != nil {
			_ = master.Close()
			return nil, nil, fmt.Errorf("pty: open slave: %w", err)
		}
		sfd = uintptr(fd)
	}
	return master, os.NewFile(sfd, "pts"), nil
}
