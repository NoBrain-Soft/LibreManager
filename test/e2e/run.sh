#!/usr/bin/env bash
# VM-based E2E harness (see README.md). Requires incus.
set -euo pipefail
command -v incus >/dev/null || { echo "incus is required for e2e tests" >&2; exit 1; }
PREFIX=${E2E_PREFIX:-swk-e2e}
IMAGES=("images:debian/13" "images:ubuntu/24.04" "images:rockylinux/9")
cleanup() { for n in central a0 a1 a2; do incus delete -f "$PREFIX-$n" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT
incus launch images:debian/13 "$PREFIX-central" --vm -c limits.memory=4GiB -c limits.cpu=2
for i in 0 1 2; do incus launch "${IMAGES[$i]}" "$PREFIX-a$i" --vm -c limits.memory=1GiB; done
echo "waiting for VMs"; sleep 60
incus file push -r deploy "$PREFIX-central/root/"
incus file push dist/stellwerk-agent* "$PREFIX-central/root/packages/" --create-dirs
incus exec "$PREFIX-central" -- bash -c "apt-get update -q && apt-get install -y -q curl openssl"
incus exec "$PREFIX-central" -- /root/deploy/install-central.sh --fqdn "$PREFIX-central.incus" \
  --image "${STELLWERK_IMAGE:?set STELLWERK_IMAGE}" --non-interactive
echo "central installed; enroll agents via the UI/API token flow (scripted checks: TODO)"
