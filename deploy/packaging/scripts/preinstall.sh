#!/bin/sh
set -e
if ! getent group stellwerk-agent >/dev/null; then
  groupadd --system stellwerk-agent
fi
if ! getent passwd stellwerk-agent >/dev/null; then
  useradd --system --gid stellwerk-agent --home-dir /var/lib/stellwerk-agent --no-create-home \
    --shell /usr/sbin/nologin --comment "Stellwerk agent" stellwerk-agent
fi
