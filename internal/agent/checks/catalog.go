package checks

import agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"

const (
	sevLow      = agentv1.Severity_SEVERITY_LOW
	sevMedium   = agentv1.Severity_SEVERITY_MEDIUM
	sevHigh     = agentv1.Severity_SEVERITY_HIGH
	sevCritical = agentv1.Severity_SEVERITY_CRITICAL
)

// catalog is the fixed, ordered check table (ARCHITECTURE.md §7.1). It is
// never modified at run time.
var catalog = []check{
	// --- SSH (effective sshd configuration via the helper) ---
	{Definition{
		ID: "SSH-001", Title: "SSH root login disabled", Severity: sevHigh,
		Rationale:   "Direct root logins bypass individual accountability and make root the target of password guessing.",
		Remediation: "Set \"PermitRootLogin no\" in /etc/ssh/sshd_config (or a drop-in) and reload sshd; log in as a named user and escalate with sudo.",
	}, sshCheck(evalPermitRootLogin)},
	{Definition{
		ID: "SSH-002", Title: "SSH password authentication disabled", Severity: sevHigh,
		Rationale:   "Passwords can be guessed, phished or reused; public-key authentication is not exposed to online brute force.",
		Remediation: "Deploy SSH keys for all users, then set \"PasswordAuthentication no\" and reload sshd.",
	}, sshCheck(sshNo("password authentication", "passwordauthentication"))},
	{Definition{
		ID: "SSH-003", Title: "SSH keyboard-interactive authentication disabled", Severity: sevMedium,
		Rationale:   "With PAM, keyboard-interactive authentication accepts passwords even when PasswordAuthentication is off.",
		Remediation: "Set \"KbdInteractiveAuthentication no\" (\"ChallengeResponseAuthentication no\" on OpenSSH < 8.7) unless it is required for a second factor.",
	}, sshCheck(sshNo("keyboard-interactive authentication", "kbdinteractiveauthentication", "challengeresponseauthentication"))},
	{Definition{
		ID: "SSH-004", Title: "SSH MaxAuthTries at most 4", Severity: sevLow,
		Rationale:   "Limiting authentication attempts per connection slows down online guessing.",
		Remediation: "Set \"MaxAuthTries 4\" (or lower) in sshd_config and reload sshd.",
	}, sshCheck(evalMaxAuthTries)},
	{Definition{
		ID: "SSH-005", Title: "SSH X11 forwarding disabled", Severity: sevLow,
		Rationale:   "X11 forwarding exposes the client's display to the server and is rarely needed on servers.",
		Remediation: "Set \"X11Forwarding no\" in sshd_config and reload sshd.",
	}, sshCheck(sshNo("X11 forwarding", "x11forwarding"))},
	{Definition{
		ID: "SSH-006", Title: "SSH ciphers exclude weak algorithms", Severity: sevMedium,
		Rationale:   "CBC-mode, RC4 (arcfour), 3DES, Blowfish and CAST ciphers have known weaknesses.",
		Remediation: "Restrict \"Ciphers\" to chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com and aes*-ctr, or use the distribution's crypto policy.",
	}, sshCheck(sshAlgorithms("ciphers", "cipher", weakCipher))},
	{Definition{
		ID: "SSH-007", Title: "SSH MACs exclude weak algorithms", Severity: sevMedium,
		Rationale:   "MD5, RIPEMD-160, truncated (-96) and non-ETM SHA-1 MACs provide insufficient integrity protection.",
		Remediation: "Restrict \"MACs\" to hmac-sha2-512-etm@openssh.com, hmac-sha2-256-etm@openssh.com and umac-128-etm@openssh.com.",
	}, sshCheck(sshAlgorithms("macs", "MAC", weakMAC))},
	{Definition{
		ID: "SSH-008", Title: "SSH key exchange excludes weak algorithms", Severity: sevMedium,
		Rationale:   "SHA-1 based and 1024-bit Diffie-Hellman key exchanges (diffie-hellman-group1-sha1, diffie-hellman-group14-sha1, diffie-hellman-group-exchange-sha1) are deprecated.",
		Remediation: "Restrict \"KexAlgorithms\" to sntrup761x25519-sha512@openssh.com, mlkem768x25519-sha256, curve25519-sha256 and diffie-hellman-group16/18 with SHA-512.",
	}, sshCheck(sshAlgorithms("kexalgorithms", "key exchange algorithm", weakKex))},
	{Definition{
		ID: "SSH-009", Title: "SSH LoginGraceTime at most 60 seconds", Severity: sevLow,
		Rationale:   "A long grace time lets unauthenticated connections tie up sshd slots (MaxStartups) and eases denial of service.",
		Remediation: "Set \"LoginGraceTime 60\" (or lower) in sshd_config and reload sshd.",
	}, sshCheck(evalLoginGraceTime)},
	{Definition{
		ID: "SSH-010", Title: "SSH empty passwords not permitted", Severity: sevHigh,
		Rationale:   "Accounts with an empty password would be reachable over the network without any credential.",
		Remediation: "Set \"PermitEmptyPasswords no\" in sshd_config and reload sshd.",
	}, sshCheck(sshNo("login with empty passwords", "permitemptypasswords"))},

	// --- Accounts ---
	{Definition{
		ID: "ACC-001", Title: "No UID 0 accounts other than root", Severity: sevCritical,
		Rationale:   "Additional UID 0 accounts have full root privileges and are a common persistence technique.",
		Remediation: "Remove the extra accounts or assign them a unique non-zero UID; use sudo for delegated administration.",
	}, checkUID0},
	{Definition{
		ID: "ACC-002", Title: "No accounts with an empty password", Severity: sevCritical,
		Rationale:   "An empty password hash allows login (su, console, PAM services with nullok) without any credential.",
		Remediation: "Set a password or lock the account (\"passwd -l USER\" or \"usermod -L USER\").",
	}, checkEmptyPasswords},
	{Definition{
		ID: "ACC-003", Title: "No passwordless sudo for all commands", Severity: sevHigh,
		Rationale:   "\"NOPASSWD: ALL\" turns any compromise of the user (or its SSH key) into an immediate root compromise.",
		Remediation: "Require a password, or restrict NOPASSWD to the specific commands that automation needs.",
	}, checkSudoNopasswd},
	{Definition{
		ID: "ACC-004", Title: "No dormant interactive accounts", Severity: sevLow,
		Rationale:   "Accounts unused for more than 90 days are often forgotten, keep stale credentials and go unnoticed when abused.",
		Remediation: "Lock or remove accounts that are no longer needed (\"usermod -L -e 1 USER\").",
	}, checkDormantAccounts},

	// --- Packages ---
	{Definition{
		ID: "PKG-001", Title: "No pending security updates", Severity: sevHigh,
		Rationale:   "Unapplied security updates leave publicly known vulnerabilities exploitable.",
		Remediation: "Apply pending security updates (Stellwerk package upgrade job, apt upgrade or dnf upgrade --security).",
	}, checkSecurityUpdates},
	{Definition{
		ID: "PKG-002", Title: "No reboot pending", Severity: sevMedium,
		Rationale:   "Kernel and core library updates only take effect after a reboot; until then the vulnerable code keeps running.",
		Remediation: "Schedule a reboot in the next maintenance window.",
	}, checkRebootRequired},
	{Definition{
		ID: "PKG-003", Title: "Automatic security updates configured", Severity: sevMedium,
		Rationale:   "Automatic installation of security updates shortens the exposure window between disclosure and patching.",
		Remediation: "Debian/Ubuntu: install unattended-upgrades and set APT::Periodic::Unattended-Upgrade \"1\". RHEL family: install dnf-automatic, set apply_updates = yes (upgrade_type = security) and enable dnf-automatic.timer.",
	}, checkAutoUpdates},

	// --- Network ---
	{Definition{
		ID: "NET-001", Title: "No unexpected network listeners", Severity: sevMedium,
		Rationale:   "Every service reachable from the network is attack surface; unexpected listeners may indicate misconfiguration or compromise.",
		Remediation: "Stop or bind unneeded services to loopback, or add the expected ports to the host's listener allow-list.",
	}, checkListeners},
	{Definition{
		ID: "NET-002", Title: "Host firewall active", Severity: sevMedium,
		Rationale:   "A host firewall limits exposure when a service is accidentally bound to a public interface.",
		Remediation: "Enable firewalld, ufw or an nftables ruleset with a default-drop input policy.",
	}, checkFirewall},

	// --- Kernel ---
	{Definition{
		ID: "KRN-001", Title: "Kernel sysctl hardening", Severity: sevMedium,
		Rationale:   "Kernel settings such as kptr_restrict, dmesg_restrict, rp_filter, protected links and unprivileged BPF restrictions reduce the impact of local and network attacks.",
		Remediation: "Set the reported values in /etc/sysctl.d/90-hardening.conf and apply them with \"sysctl --system\".",
	}, checkSysctl},

	// --- File system ---
	{Definition{
		ID: "FS-001", Title: "No world-writable or unexpected set-uid files in system paths", Severity: sevHigh,
		Rationale:   "World-writable binaries allow trivial privilege escalation; unexpected set-uid/set-gid programs are a classic backdoor.",
		Remediation: "Remove world-write permission (chmod o-w) and verify unexpected set-uid/set-gid programs against the package database (dpkg -S / rpm -qf); remove the bits if not needed.",
	}, checkFilePermissions},
	{Definition{
		ID: "FS-002", Title: "/tmp and /var/tmp mounted nodev,nosuid", Severity: sevLow,
		Rationale:   "World-writable temporary directories should not allow device files or set-uid programs.",
		Remediation: "Mount /tmp (e.g. tmp.mount) and /var/tmp as separate file systems with nodev,nosuid (and noexec where feasible).",
	}, checkTmpMounts},

	// --- Services ---
	{Definition{
		ID: "SVC-001", Title: "Required services running", Severity: sevMedium,
		Rationale:   "Security-relevant services (time sync, audit, EDR sensors) only protect the host while they run.",
		Remediation: "Install, enable and start the missing services (\"systemctl enable --now UNIT\").",
	}, checkRequiredServices},
	{Definition{
		ID: "SVC-002", Title: "No failed systemd units", Severity: sevLow,
		Rationale:   "Failed units may mean that backups, security agents or other expected functions are not running.",
		Remediation: "Inspect with \"systemctl status UNIT\" and \"journalctl -u UNIT\", fix the cause and restart, or reset with \"systemctl reset-failed\".",
	}, checkFailedUnits},
	{Definition{
		ID: "TIME-001", Title: "System clock synchronized", Severity: sevMedium,
		Rationale:   "Accurate time is required for TLS, signed jobs, Kerberos and correlating logs across hosts.",
		Remediation: "Enable an NTP client (chronyd or systemd-timesyncd) with reachable time sources.",
	}, checkTimeSync},
	{Definition{
		ID: "LOG-001", Title: "Persistent logging and auditd active", Severity: sevMedium,
		Rationale:   "Logs kept only in memory are lost on reboot; auditd records security-relevant events for investigations.",
		Remediation: "Create /var/log/journal or set Storage=persistent in journald.conf; install and enable auditd.",
	}, checkLogging},

	// --- Certificates ---
	{Definition{
		ID: "CRT-001", Title: "No local TLS certificates expiring within 30 days", Severity: sevMedium,
		Rationale:   "Expired certificates break services and train users to ignore certificate warnings.",
		Remediation: "Renew the reported certificates (or fix the ACME renewal) and reload the services using them.",
	}, checkCertificates},

	// --- Mandatory access control ---
	{Definition{
		ID: "MAC-001", Title: "Mandatory access control enforcing", Severity: sevMedium,
		Rationale:   "SELinux or AppArmor confine compromised services beyond Unix permissions.",
		Remediation: "RHEL family: set SELINUX=enforcing in /etc/selinux/config and relabel if needed. Debian/Ubuntu: enable AppArmor (apparmor=1 security=apparmor) and load profiles.",
	}, checkMAC},

	// --- Agent ---
	{Definition{
		ID: "AGT-001", Title: "Stellwerk agent up to date", Severity: sevLow,
		Rationale:   "Agent releases contain security fixes and new checks.",
		Remediation: "Update the stellwerk-agent package (or let agent self-update run).",
	}, checkAgentVersion},
}
