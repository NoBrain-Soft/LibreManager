package inventory

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

// cpuInfo is the parsed /proc/cpuinfo summary.
type cpuInfo struct {
	model   string
	threads int
	cores   int
	flags   map[string]bool
}

// armParts names common ARM CPU parts (implementer 0x41) like lscpu does.
var armParts = map[string]string{
	"0xd03": "Cortex-A53", "0xd04": "Cortex-A35", "0xd05": "Cortex-A55", "0xd07": "Cortex-A57",
	"0xd08": "Cortex-A72", "0xd09": "Cortex-A73", "0xd0a": "Cortex-A75", "0xd0b": "Cortex-A76",
	"0xd0c": "Neoverse-N1", "0xd0d": "Cortex-A77", "0xd40": "Neoverse-V1", "0xd41": "Cortex-A78",
	"0xd49": "Neoverse-N2", "0xd4f": "Neoverse-V2", "0xd8e": "Neoverse-N3", "0xd84": "Neoverse-V3",
}

var armImplementers = map[string]string{
	"0x41": "ARM", "0x42": "Broadcom", "0x43": "Cavium", "0x46": "Fujitsu", "0x48": "HiSilicon",
	"0x4e": "NVIDIA", "0x50": "APM", "0x51": "Qualcomm", "0x61": "Apple", "0xc0": "Ampere",
}

func parseCPUInfo(data []byte) cpuInfo {
	info := cpuInfo{flags: map[string]bool{}}
	cores := map[string]bool{}
	var implementer, part, boardModel string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	physID := ""
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "processor":
			info.threads++
			physID = ""
		case "model name":
			if info.model == "" {
				info.model = v
			}
		case "physical id":
			physID = v
		case "core id":
			cores[physID+"/"+v] = true
		case "CPU implementer":
			if implementer == "" {
				implementer = strings.ToLower(v)
			}
		case "CPU part":
			if part == "" {
				part = strings.ToLower(v)
			}
		case "Model", "Hardware":
			if boardModel == "" {
				boardModel = v
			}
		case "flags", "Features":
			if len(info.flags) == 0 {
				for _, f := range strings.Fields(v) {
					info.flags[f] = true
				}
			}
		}
	}
	if info.model == "" && implementer != "" {
		vendor := armImplementers[implementer]
		if vendor == "" {
			vendor = "ARM implementer " + implementer
		}
		name := part
		if implementer == "0x41" && armParts[part] != "" {
			name = armParts[part]
		}
		info.model = strings.TrimSpace(vendor + " " + name)
	}
	if info.model == "" {
		info.model = boardModel
	}
	info.model = osutil.Clean(info.model, maxName)
	info.cores = len(cores)
	if info.cores == 0 {
		info.cores = info.threads
	}
	return info
}

func (c *Collector) cpuinfo() cpuInfo {
	data, err := osutil.ReadFileLimit(c.proc("cpuinfo"), 8<<20)
	if err != nil {
		return cpuInfo{}
	}
	return parseCPUInfo(data)
}

func cpuHasFlag(info cpuInfo, flag string) bool { return info.flags[flag] }

// Hardware returns the Hardware section.
func (c *Collector) Hardware(ctx context.Context) (*agentv1.InventorySection, error) {
	cpu := c.cpuinfo()
	mem, swap := c.memInfo()
	hw := &agentv1.Hardware{
		CpuModel:    cpu.model,
		CpuCores:    uint32(min(cpu.cores, 1<<20)),   //nolint:gosec // bounded
		CpuThreads:  uint32(min(cpu.threads, 1<<20)), //nolint:gosec // bounded
		MemoryBytes: mem,
		SwapBytes:   swap,
	}
	hw.BlockDevices, _ = capBySize(c.blockDevices(), budgetBlockDevs)
	hw.Filesystems, _ = capBySize(c.filesystems(ctx), budgetFS)
	dmi := func(name string) string {
		s, _ := osutil.ReadString(c.sys("class", "dmi", "id", name), 256)
		return osutil.Clean(s, maxName)
	}
	hw.Vendor, hw.Product = dmi("sys_vendor"), dmi("product_name")
	if hw.Product == "" {
		// Boards without DMI (Raspberry Pi, many ARM servers) expose a
		// device-tree model string.
		if data, err := osutil.ReadFileLimit(c.sys("firmware", "devicetree", "base", "model"), 1024); err == nil {
			hw.Product = osutil.Clean(string(bytes.TrimRight(data, "\x00\n")), maxName)
		}
	}
	return newSection(hw)
}

func (c *Collector) memInfo() (total, swap uint64) {
	data, err := osutil.ReadFileLimit(c.proc("meminfo"), maxSmallFile)
	if err != nil {
		return 0, 0
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = v * 1024
		case "SwapTotal:":
			swap = v * 1024
		}
	}
	return total, swap
}

// blockDevices lists /sys/block devices and their partitions.
func (c *Collector) blockDevices() []*agentv1.BlockDevice {
	dir := c.sys("block")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []*agentv1.BlockDevice
	for _, e := range entries {
		if len(out) >= maxBlockDevices {
			break
		}
		name := e.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "zram") {
			continue
		}
		devDir := filepath.Join(dir, name)
		size, err := osutil.ReadUint(filepath.Join(devDir, "size"))
		if err != nil || size == 0 {
			continue
		}
		dev := &agentv1.BlockDevice{
			Name:      osutil.Clean(strings.ReplaceAll(name, "!", "/"), maxShort),
			SizeBytes: size * 512,
			Type:      "disk",
		}
		if rot, err := osutil.ReadUint(filepath.Join(devDir, "queue", "rotational")); err == nil {
			dev.Rotational = rot == 1
		}
		if m, err := osutil.ReadString(filepath.Join(devDir, "device", "model"), 256); err == nil {
			dev.Model = osutil.Clean(m, maxShort)
		}
		switch {
		case strings.HasPrefix(name, "dm-"):
			dev.Type = "dm"
			uuid, _ := osutil.ReadString(filepath.Join(devDir, "dm", "uuid"), 256)
			switch {
			case strings.HasPrefix(uuid, "LVM-"):
				dev.Type = "lvm"
			case strings.HasPrefix(uuid, "CRYPT-"):
				dev.Type = "crypt"
			case strings.HasPrefix(uuid, "mpath-"):
				dev.Type = "mpath"
			}
			// Device-mapper devices have no hardware model; report the
			// mapper name (e.g. vg0-root) there instead.
			if dmName, err := osutil.ReadString(filepath.Join(devDir, "dm", "name"), 256); err == nil {
				dev.Model = osutil.Clean(dmName, maxShort)
			}
		case strings.HasPrefix(name, "md"):
			dev.Type = "md"
		case strings.HasPrefix(name, "sr"):
			dev.Type = "rom"
		}
		out = append(out, dev)
		out = append(out, c.partitions(devDir, dev.GetRotational())...)
	}
	return out
}

func (c *Collector) partitions(devDir string, rotational bool) []*agentv1.BlockDevice {
	entries, err := os.ReadDir(devDir)
	if err != nil {
		return nil
	}
	var out []*agentv1.BlockDevice
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(devDir, e.Name())
		if _, err := os.Stat(filepath.Join(p, "partition")); err != nil {
			continue
		}
		size, err := osutil.ReadUint(filepath.Join(p, "size"))
		if err != nil {
			continue
		}
		out = append(out, &agentv1.BlockDevice{Name: osutil.Clean(e.Name(), maxShort), SizeBytes: size * 512, Type: "part", Rotational: rotational})
	}
	return out
}

func (c *Collector) filesystems(ctx context.Context) []*agentv1.Filesystem {
	mounts, err := osutil.ReadMountInfo(c.proc())
	if err != nil {
		return nil
	}
	guard := &osutil.GuardedStatfs{Fn: c.Statfs, Timeout: 5 * time.Second}
	var out []*agentv1.Filesystem
	for _, m := range osutil.SelectFilesystems(mounts, maxFilesystems) {
		fs := &agentv1.Filesystem{
			Device:     osutil.Clean(m.Source, maxName),
			Mountpoint: osutil.Clean(m.MountPoint, maxPath),
			Fstype:     osutil.Clean(m.FSType, maxShort),
			Options:    cleanList(m.Options, 32, maxShort),
		}
		// Skip sizes of mounts shadowed by a tmpfs in our namespace
		// (ProtectHome=yes).
		if st, err := guard.Statfs(ctx, c.path(m.MountPoint)); err == nil &&
			(st.Type != osutil.TmpfsMagic || m.FSType == "tmpfs") {
			fs.SizeBytes = st.Blocks * st.BlockSize
		}
		out = append(out, fs)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].GetMountpoint() < out[j].GetMountpoint() })
	return out
}
