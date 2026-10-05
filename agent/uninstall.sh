#!/usr/bin/env bash
# Removes the SentinelAI agent. Keeps configuration and state unless --purge is given.
# The host record stays in the dashboard until an admin deletes it there.
set -euo pipefail
PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1
[[ $EUID -eq 0 ]] || { echo "run as root (sudo ./uninstall.sh)"; exit 1; }

if command -v systemctl >/dev/null && [[ -f /etc/systemd/system/sentinel-agent.service ]]; then
  systemctl disable --now sentinel-agent || true
  rm -f /etc/systemd/system/sentinel-agent.service
  systemctl daemon-reload
fi
rm -rf /opt/sentinelai/agent
rmdir /opt/sentinelai 2>/dev/null || true

if [[ $PURGE -eq 1 ]]; then
  rm -rf /etc/sentinelai /var/lib/sentinelai
  id sentinelai >/dev/null 2>&1 && userdel sentinelai || true
  echo "SentinelAI agent removed, including configuration, credentials and the sentinelai user."
else
  echo "SentinelAI agent removed. Kept /etc/sentinelai and /var/lib/sentinelai (use --purge to delete them)."
fi
