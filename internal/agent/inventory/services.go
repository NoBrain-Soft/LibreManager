package inventory

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// Services returns the ServiceList section from
// `systemctl list-units --type=service --all` merged with
// `systemctl list-unit-files --type=service` (for the enablement state).
func (c *Collector) Services(ctx context.Context) (*agentv1.InventorySection, error) {
	if !c.systemdBooted() {
		return nil, fmt.Errorf("services: host not booted with systemd: %w", ErrUnsupported)
	}
	run := c.exec()
	units, err := run.Run(ctx, "systemctl", "list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager", "--full")
	if err != nil {
		return nil, fmt.Errorf("services: %w", err)
	}
	files, err := run.Run(ctx, "systemctl", "list-unit-files", "--type=service", "--plain", "--no-legend", "--no-pager", "--full")
	if err != nil {
		c.log().Warn("systemctl list-unit-files failed", "error", err)
		files = nil
	}
	list := &agentv1.ServiceList{Units: mergeUnits(parseListUnits(units), parseUnitFiles(files))}
	var truncated bool
	list.Units, truncated = capBySize(list.Units, budgetServices)
	if truncated {
		c.log().Warn("service list truncated to size budget", "kept", len(list.Units))
	}
	return newSection(list)
}

func (c *Collector) systemdBooted() bool {
	_, err := os.Stat(c.path("run", "systemd", "system"))
	return err == nil
}

// parseListUnits parses `list-units --plain --no-legend` output:
// UNIT LOAD ACTIVE SUB DESCRIPTION... Some systemd versions prefix units in
// a bad state with "●" even with --plain.
func parseListUnits(out []byte) []*agentv1.Unit {
	var units []*agentv1.Unit
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) > 0 && (f[0] == "●" || f[0] == "*" || f[0] == "×") {
			f = f[1:]
		}
		if len(f) < 4 || !strings.Contains(f[0], ".") {
			continue
		}
		units = append(units, &agentv1.Unit{
			Name:        osutil.Clean(f[0], maxName),
			LoadState:   osutil.Clean(f[1], maxShort),
			ActiveState: osutil.Clean(f[2], maxShort),
			SubState:    osutil.Clean(f[3], maxShort),
			Description: osutil.Clean(strings.Join(f[4:], " "), maxName),
		})
		if len(units) >= maxUnits {
			break
		}
	}
	return units
}

// parseUnitFiles parses `list-unit-files --plain --no-legend` output:
// UNIT FILE STATE [VENDOR PRESET].
func parseUnitFiles(out []byte) map[string]string {
	states := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || !strings.Contains(f[0], ".") {
			continue
		}
		states[osutil.Clean(f[0], maxName)] = osutil.Clean(f[1], maxShort)
		if len(states) >= maxUnits {
			break
		}
	}
	return states
}

// mergeUnits adds unit file states and lists installed but unloaded unit
// files (e.g. disabled services) as inactive. Templates ("foo@.service")
// are skipped since they are not runnable units themselves.
func mergeUnits(units []*agentv1.Unit, fileStates map[string]string) []*agentv1.Unit {
	seen := make(map[string]bool, len(units))
	for _, u := range units {
		seen[u.GetName()] = true
		if st, ok := fileStates[u.GetName()]; ok {
			u.UnitFileState = st
		}
	}
	for name, st := range fileStates {
		if seen[name] || strings.Contains(name, "@.") || len(units) >= maxUnits {
			continue
		}
		units = append(units, &agentv1.Unit{Name: name, ActiveState: "inactive", SubState: "dead", UnitFileState: st})
	}
	sort.Slice(units, func(i, j int) bool { return units[i].GetName() < units[j].GetName() })
	return units
}
