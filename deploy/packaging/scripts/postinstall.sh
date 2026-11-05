#!/bin/sh
set -e
install -d -m 0700 -o stellwerk-agent -g stellwerk-agent /var/lib/stellwerk-agent
install -d -m 0755 /etc/stellwerk /etc/stellwerk/jobkeys.d
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  systemctl enable stellwerk-agent-helper.socket stellwerk-agent.service >/dev/null 2>&1 || true
  # Only restart what is already running (first install: the installer
  # enrolls and then starts the units).
  systemctl try-restart stellwerk-agent-helper.service stellwerk-agent.service || true
fi
