#!/bin/sh
set -e
# deb: $1 = remove|upgrade ; rpm: $1 = 0 (erase) | 1 (upgrade)
case "$1" in
  remove|0)
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
      systemctl disable --now stellwerk-agent.service stellwerk-agent-helper.socket stellwerk-agent-helper.service >/dev/null 2>&1 || true
    fi
    ;;
esac
