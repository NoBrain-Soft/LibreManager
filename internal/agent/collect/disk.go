package collect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
)

// Disk collector limits.
const (
	maxDisks         = 128
	diskListCacheTTL = 60 * time.Second
	sectorSize       = 512 // /proc/diskstats always counts 512-byte sectors
)

// virtualDisk matches block devices that are never interesting: loop and
// RAM disks, floppies.
var virtualDisk = regexp.MustCompile(`^(loop|ram|zram|fd)\d+$`)

// partitionFallback matches partitions when /sys/block is unavailable.
var partitionFallback = regexp.MustCompile(`^((h|s|v|xv)d[a-z]+\d+|nvme\d+n\d+p\d+|mmcblk\d+p\d+)$`)

// diskstatsCollector reads /proc/diskstats for whole block devices (as
// listed in /sys/block, which excludes partitions), skipping loop/ram/zram
// devices and devices with zero size (empty nbd, ejected CD-ROM, inactive
// md). Label: device (kernel name, e.g. sda, nvme0n1, dm-0).
//
//	stellwerk_disk_reads_completed_total, _writes_completed_total  counter
//	stellwerk_disk_read_bytes_total, _written_bytes_total          counter
//	stellwerk_disk_read_time_seconds_total, _write_time_seconds_total, _io_time_seconds_total  counter
type diskstatsCollector struct {
	procRoot, sysRoot string
	now               func() time.Time

	mu       sync.Mutex
	devices  map[string]bool // nil: /sys/block unavailable, use regexes
	listedAt time.Time
}

func newDiskstatsCollector(o Options) *diskstatsCollector {
	return &diskstatsCollector{procRoot: o.ProcRoot, sysRoot: o.SysRoot, now: o.Now}
}

func (c *diskstatsCollector) Name() string { return "diskstats" }

func (c *diskstatsCollector) Collect(_ context.Context, emit func(Sample)) error {
	data, err := readProc(c.procRoot, "diskstats")
	if err != nil {
		return fmt.Errorf("read /proc/diskstats: %w", err)
	}
	devices := c.deviceSet()
	n := 0
	var f [][]byte
	eachLine(data, func(line []byte) {
		f = fieldsN(f, line)
		// major minor name + at least 11 stat fields
		if len(f) < 14 || n >= maxDisks {
			return
		}
		name := string(f[2])
		if !c.include(devices, name) {
			return
		}
		n++
		dev := osutil.Clean(name, 64)
		val := func(i int) float64 {
			v, _ := parseUint(f[i])
			return float64(v)
		}
		emit(sample("stellwerk_disk_reads_completed_total", val(3), "device", dev))
		emit(sample("stellwerk_disk_read_bytes_total", val(5)*sectorSize, "device", dev))
		emit(sample("stellwerk_disk_read_time_seconds_total", val(6)/1000, "device", dev))
		emit(sample("stellwerk_disk_writes_completed_total", val(7), "device", dev))
		emit(sample("stellwerk_disk_written_bytes_total", val(9)*sectorSize, "device", dev))
		emit(sample("stellwerk_disk_write_time_seconds_total", val(10)/1000, "device", dev))
		emit(sample("stellwerk_disk_io_time_seconds_total", val(12)/1000, "device", dev))
	})
	return nil
}

func (c *diskstatsCollector) include(devices map[string]bool, name string) bool {
	if virtualDisk.MatchString(name) {
		return false
	}
	if devices != nil {
		// /sys/block uses '!' where the kernel name has '/' (cciss/c0d0).
		return devices[strings.ReplaceAll(name, "/", "!")]
	}
	return !partitionFallback.MatchString(name)
}

// deviceSet returns the whole-disk devices with non-zero size, cached.
func (c *diskstatsCollector) deviceSet() map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !c.listedAt.IsZero() && now.Sub(c.listedAt) < diskListCacheTTL {
		return c.devices
	}
	c.listedAt = now
	dir := filepath.Join(c.sysRoot, "block")
	entries, err := os.ReadDir(dir)
	if err != nil {
		c.devices = nil
		return nil
	}
	set := make(map[string]bool, len(entries))
	for _, e := range entries {
		name := e.Name()
		if virtualDisk.MatchString(name) {
			continue
		}
		size, err := osutil.ReadUint(filepath.Join(dir, name, "size"))
		if err != nil || size == 0 {
			continue
		}
		set[name] = true
	}
	c.devices = set
	return set
}
