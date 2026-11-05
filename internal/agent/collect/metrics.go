package collect

// MetricNames lists every metric name the agent emits. It is the contract
// with the server's chart queries and alert rules (ARCHITECTURE.md §7.3);
// tests fail when a collector emits a name that is not listed here.
//
// Units follow Prometheus conventions: *_seconds_total and *_bytes_total are
// counters, *_bytes and plain names are gauges.
var MetricNames = []string{
	// CPU / scheduler (/proc/stat, /proc/loadavg, /proc/pressure).
	"stellwerk_cpu_seconds_total", // {mode[,cpu]}
	"stellwerk_cpu_count",
	"stellwerk_load1",
	"stellwerk_load5",
	"stellwerk_load15",
	"stellwerk_context_switches_total",
	"stellwerk_forks_total",
	"stellwerk_procs_running",
	"stellwerk_procs_blocked",
	"stellwerk_processes_total",        // gauge: current number of processes
	"stellwerk_pressure_seconds_total", // {resource,kind}

	// Memory (/proc/meminfo, /proc/vmstat).
	"stellwerk_memory_total_bytes",
	"stellwerk_memory_available_bytes",
	"stellwerk_memory_free_bytes",
	"stellwerk_memory_cached_bytes",
	"stellwerk_memory_buffers_bytes",
	"stellwerk_memory_shared_bytes",
	"stellwerk_memory_slab_bytes",
	"stellwerk_swap_total_bytes",
	"stellwerk_swap_free_bytes",
	"stellwerk_oom_kills_total",

	// Filesystems {mountpoint,device,fstype}.
	"stellwerk_filesystem_size_bytes",
	"stellwerk_filesystem_avail_bytes",
	"stellwerk_filesystem_free_bytes",
	"stellwerk_filesystem_files",
	"stellwerk_filesystem_files_free",
	"stellwerk_filesystem_readonly",

	// Block devices {device}.
	"stellwerk_disk_reads_completed_total",
	"stellwerk_disk_writes_completed_total",
	"stellwerk_disk_read_bytes_total",
	"stellwerk_disk_written_bytes_total",
	"stellwerk_disk_read_time_seconds_total",
	"stellwerk_disk_write_time_seconds_total",
	"stellwerk_disk_io_time_seconds_total",

	// Network {device}.
	"stellwerk_network_receive_bytes_total",
	"stellwerk_network_receive_packets_total",
	"stellwerk_network_receive_errs_total",
	"stellwerk_network_receive_drop_total",
	"stellwerk_network_transmit_bytes_total",
	"stellwerk_network_transmit_packets_total",
	"stellwerk_network_transmit_errs_total",
	"stellwerk_network_transmit_drop_total",
	"stellwerk_tcp_connections", // {state}
	"stellwerk_listening_sockets",
	"stellwerk_conntrack_entries",
	"stellwerk_conntrack_entries_limit",

	// System.
	"stellwerk_uptime_seconds",
	"stellwerk_boot_time_seconds",
	"stellwerk_filefd_allocated",
	"stellwerk_filefd_maximum",
	"stellwerk_time_sync_status",
	"stellwerk_time_offset_seconds",
	"stellwerk_systemd_units_failed",

	// Probes.
	"stellwerk_probe_success",             // {probe,kind}
	"stellwerk_probe_duration_seconds",    // {probe,kind}
	"stellwerk_probe_cert_expiry_seconds", // {probe}, unix time of earliest NotAfter

	// Agent self-monitoring.
	"stellwerk_agent_rss_bytes",
	"stellwerk_agent_cpu_seconds_total",
	"stellwerk_agent_goroutines",
	"stellwerk_agent_series_dropped_total", // only after drops
}
