#!/usr/bin/env bash

set -euo pipefail

SERVER_NAME="${1:-}"

if [[ -z "$SERVER_NAME" ]]; then
  echo "Usage: $0 servername"
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

echo "==== Server report: $SERVER_NAME ===="
echo "Timestamp: $(date -Is)"
echo

# Host / OS
echo "Hostname (actual): $(hostname -f 2>/dev/null || hostname)"
echo "OS: $(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2- | tr -d '"')"
echo "Kernel: $(uname -r)"
echo

# Uptime / load
echo "Uptime: $(uptime -p)"
echo "Load: $(uptime | awk -F'load average:' '{print $2}')"
echo

# Disk
echo "Disk usage:"
df -h --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs
echo

# Memory
echo "Memory usage:"
free -h
echo

# Updates
echo "Checking updates..."
apt-get update -qq

TOTAL_UPDATES=$(apt-get -s upgrade | grep -P '^\d+ upgraded' | awk '{print $1}')
TOTAL_UPDATES=${TOTAL_UPDATES:-0}

SECURITY_UPDATES="N/A"
if command -v unattended-upgrade >/dev/null 2>&1; then
  SECURITY_UPDATES=$(unattended-upgrade --dry-run -d 2>/dev/null | grep -c "^Inst ")
fi

echo "Pending updates: $TOTAL_UPDATES"
echo "Security updates: $SECURITY_UPDATES"
echo

# Reboot check
if [[ -f /var/run/reboot-required ]]; then
  echo "Reboot required: YES"
  cat /var/run/reboot-required.pkgs 2>/dev/null || true
else
  echo "Reboot required: NO"
fi

echo
echo "==== End of report ===="
