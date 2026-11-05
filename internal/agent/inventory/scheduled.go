package inventory

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

var (
	cronEnvLine = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)
	timerName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@\\-]{0,250}\.timer$`)
)

// cronIgnoredSuffixes are package-manager leftovers cron does not run.
var cronIgnoredSuffixes = []string{"~", ".dpkg-old", ".dpkg-dist", ".dpkg-new", ".dpkg-tmp", ".rpmsave", ".rpmnew", ".rpmorig", ".swp", ".bak"}

// ScheduledTasks returns cron entries from /etc/crontab and /etc/cron.d/*
// plus systemd timers. Per-user crontabs (/var/spool/cron) are root-only and
// not included.
func (c *Collector) ScheduledTasks(ctx context.Context) (*agentv1.InventorySection, error) {
	var tasks []*agentv1.ScheduledTask
	tasks = append(tasks, c.cronFile(c.path("etc", "crontab"), "/etc/crontab")...)
	dir := c.path("etc", "cron.d")
	if entries, err := os.ReadDir(dir); err == nil {
		n := 0
		for _, e := range entries {
			if n >= maxCronFiles {
				break
			}
			if !cronFileName(e.Name()) || e.IsDir() {
				continue
			}
			n++
			tasks = append(tasks, c.cronFile(filepath.Join(dir, e.Name()), "/etc/cron.d/"+e.Name())...)
		}
	}
	if c.systemdBooted() {
		tasks = append(tasks, c.timers(ctx)...)
	}
	if len(tasks) > maxTasks {
		tasks = tasks[:maxTasks]
	}
	slices.SortStableFunc(tasks, func(a, b *agentv1.ScheduledTask) int {
		return cmp.Or(strings.Compare(a.GetKind(), b.GetKind()), strings.Compare(a.GetName(), b.GetName()))
	})
	st := &agentv1.ScheduledTasks{}
	st.Tasks, _ = capBySize(tasks, budgetScheduled)
	return newSection(st)
}

func cronFileName(name string) bool {
	if name == "" || name[0] == '.' {
		return false
	}
	for _, s := range cronIgnoredSuffixes {
		if strings.HasSuffix(name, s) {
			return false
		}
	}
	return true
}

func (c *Collector) cronFile(path, display string) []*agentv1.ScheduledTask {
	data, err := osutil.ReadFileLimit(path, maxConfigFile)
	if err != nil {
		return nil
	}
	return parseSystemCrontab(data, display)
}

// parseSystemCrontab parses a system crontab (with a user column):
// "m h dom mon dow user command" or "@reboot user command".
func parseSystemCrontab(data []byte, display string) []*agentv1.ScheduledTask {
	var out []*agentv1.ScheduledTask
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || cronEnvLine.MatchString(line) {
			continue
		}
		f := strings.Fields(line)
		var schedule string
		var rest []string
		if strings.HasPrefix(f[0], "@") {
			if len(f) < 3 {
				continue
			}
			schedule, rest = f[0], f[1:]
		} else {
			if len(f) < 7 {
				continue
			}
			schedule, rest = strings.Join(f[:5], " "), f[5:]
		}
		out = append(out, &agentv1.ScheduledTask{
			Kind:     "cron",
			Name:     osutil.Clean(display+":"+strconv.Itoa(lineNo), maxPath),
			Schedule: osutil.Clean(schedule, maxShort),
			User:     osutil.Clean(rest[0], maxShort),
			Command:  osutil.Clean(strings.Join(rest[1:], " "), maxText),
		})
		if len(out) >= maxTasks {
			break
		}
	}
	return out
}

// timers lists systemd timers with `systemctl list-timers --all` and reads
// their schedules with one `systemctl show` call.
func (c *Collector) timers(ctx context.Context) []*agentv1.ScheduledTask {
	run := c.exec()
	out, err := run.Run(ctx, "systemctl", "list-timers", "--all", "--plain", "--no-legend", "--no-pager", "--full")
	if err != nil {
		c.log().Debug("systemctl list-timers failed", "error", err)
		return nil
	}
	activates := parseListTimers(out)
	if len(activates) == 0 {
		return nil
	}
	names := make([]string, 0, len(activates))
	for n := range activates {
		names = append(names, n)
	}
	slices.Sort(names)
	args := append([]string{"show", "--property=Id,TimersCalendar,TimersMonotonic", "--"}, names...)
	schedules := map[string]string{}
	if show, err := run.Run(ctx, "systemctl", args...); err == nil {
		schedules = parseTimerShow(show)
	} else {
		c.log().Debug("systemctl show timers failed", "error", err)
	}
	tasks := make([]*agentv1.ScheduledTask, 0, len(names))
	for _, n := range names {
		tasks = append(tasks, &agentv1.ScheduledTask{
			Kind:     "systemd-timer",
			Name:     osutil.Clean(n, maxName),
			Schedule: osutil.Clean(schedules[n], maxText),
			Command:  osutil.Clean(activates[n], maxName),
			User:     "root",
		})
	}
	return tasks
}

// parseListTimers maps timer unit -> activated unit. Columns are
// NEXT LEFT LAST PASSED UNIT ACTIVATES where the time columns contain
// spaces, so the unit names are taken from the end of the line.
func parseListTimers(out []byte) map[string]string {
	res := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		unit, act := f[len(f)-2], f[len(f)-1]
		if !timerName.MatchString(unit) {
			continue
		}
		res[unit] = act
		if len(res) >= maxTimers {
			break
		}
	}
	return res
}

// parseTimerShow parses `systemctl show -p Id,TimersCalendar,TimersMonotonic`
// output for several units (blocks separated by blank lines), e.g.
// "TimersCalendar={ OnCalendar=*-*-* 06:00:00 ; next_elapse=... }".
func parseTimerShow(out []byte) map[string]string {
	res := make(map[string]string)
	var id string
	var specs []string
	flush := func() {
		if id != "" {
			res[id] = strings.Join(specs, "; ")
		}
		id, specs = "", nil
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "Id":
			id = v
		case "TimersCalendar", "TimersMonotonic":
			// Several entries may be on one line: "{ A ; next... } { B ; ... }".
			for part := range strings.SplitSeq(v, "}") {
				part = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), "{"))
				spec, _, _ := strings.Cut(part, " ;")
				if spec = strings.TrimSpace(spec); spec != "" {
					specs = append(specs, spec)
				}
			}
		}
	}
	flush()
	return res
}
