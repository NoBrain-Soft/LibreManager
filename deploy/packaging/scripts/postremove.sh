#!/bin/sh
set -e
case "$1" in
  purge)
    rm -rf /var/lib/stellwerk-agent /var/lib/stellwerk-agent-helper /etc/stellwerk
    ;;
esac
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
