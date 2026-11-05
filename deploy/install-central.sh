#!/usr/bin/env bash
# Stellwerk central installer (ARCHITECTURE.md §8.1).
#
#   sudo ./install-central.sh --fqdn stellwerk.example.internal [options]
#
# Idempotent: re-running keeps existing secrets, keys and data and only
# (re)writes generated configuration. Supported hosts: Debian 12/13,
# Ubuntu 24.04, RHEL/Alma/Rocky 9/10.
set -euo pipefail

PREFIX=/opt/stellwerk
FQDN=""
AGENT_ENDPOINT=""
TLS_MODE=internal
CERT=""
KEY=""
ACME_EMAIL=""
IMAGE="${STELLWERK_IMAGE:-}"
IMAGE_TAR=""
METRICS_RETENTION=30d
ADMIN_CIDRS=""
NON_INTERACTIVE=0
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
  cat <<USAGE
Usage: $0 --fqdn NAME [options]

  --fqdn NAME                 DNS name of the web UI (required)
  --agent-endpoint HOST:PORT  address agents dial (default: <fqdn>:8443)
  --tls internal|acme|custom  web TLS mode (default: internal)
  --cert FILE --key FILE      certificate + key for --tls custom
  --acme-email ADDR           contact for --tls acme
  --image REF@sha256:...      server image reference (pinned by digest)
  --image-tar FILE            load the server image from a tarball (offline)
  --metrics-retention 30d     VictoriaMetrics retention (default 30d)
  --admin-cidrs CIDR[,CIDR]   optionally restrict 443 to these networks (nftables)
  --prefix DIR                install directory (default /opt/stellwerk)
  --non-interactive           never prompt
USAGE
}

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --fqdn) FQDN=$2; shift 2 ;;
    --agent-endpoint) AGENT_ENDPOINT=$2; shift 2 ;;
    --tls) TLS_MODE=$2; shift 2 ;;
    --cert) CERT=$2; shift 2 ;;
    --key) KEY=$2; shift 2 ;;
    --acme-email) ACME_EMAIL=$2; shift 2 ;;
    --image) IMAGE=$2; shift 2 ;;
    --image-tar) IMAGE_TAR=$2; shift 2 ;;
    --metrics-retention) METRICS_RETENTION=$2; shift 2 ;;
    --admin-cidrs) ADMIN_CIDRS=$2; shift 2 ;;
    --prefix) PREFIX=$2; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

# ---------------------------------------------------------------- preflight
[ "$(id -u)" -eq 0 ] || die "run as root"
[ -n "$FQDN" ] || { usage; die "--fqdn is required"; }
[[ "$FQDN" =~ ^[A-Za-z0-9.-]+$ ]] || die "invalid --fqdn"
AGENT_ENDPOINT=${AGENT_ENDPOINT:-$FQDN:8443}
[[ "$AGENT_ENDPOINT" =~ ^[A-Za-z0-9.-]+:[0-9]{1,5}$ ]] || die "invalid --agent-endpoint"
AGENT_PORT=${AGENT_ENDPOINT##*:}
case "$TLS_MODE" in
  internal|acme) ;;
  custom) [ -r "$CERT" ] && [ -r "$KEY" ] || die "--tls custom needs readable --cert and --key" ;;
  *) die "--tls must be internal, acme or custom" ;;
esac
[[ "$METRICS_RETENTION" =~ ^[0-9]+[dwmy]?$ ]] || die "invalid --metrics-retention"

. /etc/os-release
case "$ID" in
  debian|ubuntu|rhel|rocky|almalinux|centos) ;;
  *) log "warning: $ID is not a tested central host OS" ;;
esac
ARCH=$(uname -m)
case "$ARCH" in x86_64|aarch64) ;; *) die "unsupported architecture $ARCH" ;; esac
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
[ "$MEM_MB" -ge 3500 ] || log "warning: ${MEM_MB} MiB RAM; 4 GiB recommended"
FREE_GB=$(df -Pk "$(dirname "$PREFIX")" | awk 'NR==2 {print int($4/1024/1024)}')
[ "$FREE_GB" -ge 20 ] || log "warning: only ${FREE_GB} GiB free disk; 50 GiB recommended"
for p in 443 "$AGENT_PORT"; do
  if ss -ltnH "sport = :$p" 2>/dev/null | grep -q .; then
    [ -f "$PREFIX/compose.yml" ] || die "port $p is already in use"
  fi
done
if command -v timedatectl >/dev/null && [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" != "yes" ]; then
  log "warning: system clock is not NTP-synchronized (agents reject jobs with skewed clocks)"
fi
getent hosts "$FQDN" >/dev/null || log "warning: $FQDN does not resolve on this host"

# ------------------------------------------------------------ container runtime
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
  ENGINE=docker
elif command -v podman >/dev/null 2>&1 && command -v podman-compose >/dev/null 2>&1; then
  COMPOSE=(podman-compose)
  ENGINE=podman
else
  log "installing Docker Engine + compose plugin from the distribution"
  case "$ID" in
    debian|ubuntu)
      DEBIAN_FRONTEND=noninteractive apt-get update -q
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io docker-compose-v2 || \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io docker-compose-plugin
      ;;
    rhel|rocky|almalinux|centos)
      dnf -y -q install podman podman-compose || die "install Docker or Podman + compose manually"
      ;;
  esac
  if command -v docker >/dev/null 2>&1; then
    systemctl enable --now docker
    COMPOSE=(docker compose); ENGINE=docker
  else
    COMPOSE=(podman-compose); ENGINE=podman
  fi
fi
log "using ${COMPOSE[*]}"

# ------------------------------------------------------------------ layout
umask 077
install -d -m 0750 "$PREFIX"
install -d -m 0700 "$PREFIX/secrets" "$PREFIX/secrets/db" "$PREFIX/backups"
install -d -m 0750 "$PREFIX/data" "$PREFIX/data/recordings" "$PREFIX/data/signer" "$PREFIX/data/packages" "$PREFIX/certs"
for f in compose.yml Caddyfile; do install -m 0644 "$SRC_DIR/compose/$f" "$PREFIX/$f"; done
for d in vmalert alertmanager grafana; do
  rm -rf "${PREFIX:?}/$d"; cp -r "$SRC_DIR/compose/$d" "$PREFIX/$d"
done
chmod -R go-w "$PREFIX/vmalert" "$PREFIX/alertmanager" "$PREFIX/grafana"
if [ "$TLS_MODE" = custom ]; then
  install -m 0644 "$CERT" "$PREFIX/certs/fullchain.pem"
  install -m 0640 "$KEY" "$PREFIX/certs/privkey.pem"
fi

rand() { openssl rand -base64 32 | tr -d '\n/+=' | cut -c1-40; }
if [ ! -s "$PREFIX/secrets/db/password" ]; then
  rand > "$PREFIX/secrets/db/password"
fi
DBPW=$(cat "$PREFIX/secrets/db/password")
printf 'postgres://stellwerk:%s@postgres:5432/stellwerk?sslmode=disable\n' "$DBPW" > "$PREFIX/secrets/db/dsn"
install -d -m 0700 "$PREFIX/secrets/grafana"
[ -s "$PREFIX/secrets/grafana/admin_password" ] || rand > "$PREFIX/secrets/grafana/admin_password"

# ------------------------------------------------------------------ image
if [ -n "$IMAGE_TAR" ]; then
  log "loading image from $IMAGE_TAR"
  if [[ "$IMAGE_TAR" == *.zst ]]; then zstd -dc "$IMAGE_TAR" | $ENGINE load; else $ENGINE load -i "$IMAGE_TAR"; fi
fi
if [ -z "$IMAGE" ] && [ -f "$PREFIX/.env" ]; then
  IMAGE=$(sed -n 's/^STELLWERK_IMAGE=//p' "$PREFIX/.env")
fi
[ -n "$IMAGE" ] || die "--image REF@sha256:<digest> is required (images are pinned by digest)"
[[ "$IMAGE" == *@sha256:* ]] || [ -n "$IMAGE_TAR" ] || die "--image must be pinned by digest (…@sha256:…)"
if command -v cosign >/dev/null 2>&1 && [ -n "${STELLWERK_COSIGN_KEY:-}" ]; then
  log "verifying image signature"
  cosign verify --key "$STELLWERK_COSIGN_KEY" "$IMAGE" >/dev/null
fi

cat > "$PREFIX/.env" <<ENV
# Generated by install-central.sh — re-run the installer to change.
STELLWERK_IMAGE=$IMAGE
STELLWERK_FQDN=$FQDN
STELLWERK_AGENT_ENDPOINT=$AGENT_ENDPOINT
STELLWERK_AGENT_PORT=$AGENT_PORT
STELLWERK_TLS=$TLS_MODE
STELLWERK_ACME_EMAIL=$ACME_EMAIL
STELLWERK_METRICS_RETENTION=$METRICS_RETENTION
ENV
chmod 0600 "$PREFIX/.env"

# Containers run as uid 65532; give them their directories.
chown -R 65532:65532 "$PREFIX/secrets" "$PREFIX/data"
chmod 0700 "$PREFIX/secrets"
# Postgres reads its password as uid 70 (alpine); keep the db dir group-readable for both.
chown -R 65532:70 "$PREFIX/secrets/db"; chmod 0750 "$PREFIX/secrets/db"; chmod 0640 "$PREFIX/secrets/db/"*

cd "$PREFIX"
log "pulling images"
"${COMPOSE[@]}" pull --quiet || [ -n "$IMAGE_TAR" ]

# ------------------------------------------------------------------ init
log "starting PostgreSQL"
"${COMPOSE[@]}" up -d postgres
for _ in $(seq 1 60); do
  "${COMPOSE[@]}" exec -T postgres pg_isready -U stellwerk -d stellwerk >/dev/null 2>&1 && break
  sleep 2
done
log "initializing (migrations, CA, job-signing key, break-glass admin)"
INIT_OUT=$("${COMPOSE[@]}" run --rm --no-deps \
  -v "$PREFIX/secrets:/var/lib/stellwerk/secrets" -v "$PREFIX/data:/var/lib/stellwerk/data" \
  api init)
echo "$INIT_OUT" | grep -v "One-time password" || true

log "starting the stack"
"${COMPOSE[@]}" up -d
sleep 5
"${COMPOSE[@]}" ps

# ------------------------------------------------------- backups & helpers
install -m 0755 /dev/stdin /usr/local/sbin/stellwerk-backup <<'BACKUP'
#!/bin/sh
# Encrypted backup of the database and secrets (age recipient in /opt/stellwerk/backup.recipient).
set -eu
cd /opt/stellwerk
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=backups/stellwerk-$TS.tar
docker compose exec -T postgres pg_dump -U stellwerk -d stellwerk -Fc > "backups/db-$TS.dump"
tar -cf "$OUT" "backups/db-$TS.dump" secrets .env
rm -f "backups/db-$TS.dump"
if command -v age >/dev/null 2>&1 && [ -s backup.recipient ]; then
  age -R backup.recipient -o "$OUT.age" "$OUT" && rm -f "$OUT"
else
  echo "warning: age or backup.recipient missing; backup is NOT encrypted" >&2
fi
find backups -name 'stellwerk-*' -mtime +30 -delete
BACKUP
cat > /etc/systemd/system/stellwerk-backup.service <<'UNIT'
[Unit]
Description=Stellwerk encrypted backup
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/stellwerk-backup
UNIT
cat > /etc/systemd/system/stellwerk-backup.timer <<'UNIT'
[Unit]
Description=Daily Stellwerk backup
[Timer]
OnCalendar=*-*-* 02:17:00
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now stellwerk-backup.timer >/dev/null

# -------------------------------------------------------- optional firewall
if [ -n "$ADMIN_CIDRS" ]; then
  command -v nft >/dev/null || die "nft not available for --admin-cidrs"
  log "restricting 443 to $ADMIN_CIDRS (nftables table inet stellwerk)"
  nft -f - <<NFT
table inet stellwerk
delete table inet stellwerk
table inet stellwerk {
  set admin_v4 { type ipv4_addr; flags interval; elements = { ${ADMIN_CIDRS} } }
  chain input {
    type filter hook input priority -10; policy accept;
    tcp dport 443 ip saddr != @admin_v4 drop
  }
}
NFT
fi

FP=$(echo "$INIT_OUT" | sed -n 's/.*CA fingerprint (SHA-256): //p')
OTP=$(echo "$INIT_OUT" | sed -n 's/.*One-time password: *//p')
cat <<DONE

Stellwerk is running.

  Web UI:            https://$FQDN
  Agent endpoint:    $AGENT_ENDPOINT   (servers must reach this port)
  CA fingerprint:    ${FP:-see 'docker compose logs'}
DONE
if [ -n "$OTP" ]; then
  cat <<DONE
  Break-glass admin: admin
  One-time password: $OTP
                     (shown once — change it at first login; MFA enrollment is enforced)
DONE
fi
cat <<DONE

Next steps:
  1. Log in, set a new password and register a security key (or TOTP).
  2. Copy agent packages into $PREFIX/data/packages (make packages).
  3. Admin → Enrollment tokens → create a token and run the shown command on each server.
  4. Optional: put an age public key into $PREFIX/backup.recipient for encrypted backups.
  5. Optional: move $PREFIX/secrets/ca/root.key.sealed and master.key offline.
DONE
