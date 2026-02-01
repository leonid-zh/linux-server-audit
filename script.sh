#!/usr/bin/env bash

# Lightweight VPS audit that runs without root, prints a colorized local log and writes a plain-text report.
# Usage: ./script.sh [optional-report-name-prefix]

set -o pipefail

PREFIX="${1:-vps}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${PREFIX}-audit-${TIMESTAMP}.txt"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
GRAY='\033[0;90m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Helpers
cmd_exists() { command -v "$1" >/dev/null 2>&1; }
write_report() { echo -e "$1" >> "$REPORT_FILE"; }
print_header() {
  local h="$1"
  echo -e "\n${BLUE}${BOLD}$h${NC}"
  write_report "\n$h"
  write_report "================================"
}
print_info() {
  local k="$1"; local v="$2"
  echo -e "${BOLD}$k:${NC} $v"
  write_report "$k: $v"
}
check_security() {
  local name="$1"; local status="$2"; local msg="$3"
  case "$status" in
    PASS) color="$GREEN" tag="[PASS]" ;;
    WARN) color="$YELLOW" tag="[WARN]" ;;
    FAIL) color="$RED" tag="[FAIL]" ;;
    *) color="$GRAY" tag="[INFO]" ;;
  esac
  echo -e "${color}${tag}${NC} $name ${GRAY}- $msg${NC}"
  write_report "${tag} $name - $msg"
}

# Start
echo -e "${BLUE}${BOLD}Local VPS Audit${NC}"
echo -e "${GRAY}Running locally; no root required${NC}"
write_report "Local VPS Audit"
write_report "Started: $(date)"
write_report "================================"

# System info
print_header "System Information"
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
OS_INFO=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'=' -f2- | tr -d '"' || uname -s)
KERNEL=$(uname -r 2>/dev/null || echo "unknown")
UPTIME_PRETTY=$(uptime -p 2>/dev/null || echo "unknown")
LOAD=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | xargs 2>/dev/null || echo "n/a")
CPU_MODEL=$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null | xargs || lscpu 2>/dev/null | awk -F: '/Model name/ {print $2; exit}' | xargs || echo "unknown")
CPU_CORES=$(nproc 2>/dev/null || echo "?")
TOTAL_MEM=$(free -h 2>/dev/null | awk '/^Mem:/ {print $2}' || echo "?")
DISK_TOTAL=$(df -h / 2>/dev/null | awk 'NR==2{print $2}' || echo "?")

print_info "Hostname" "$HOSTNAME"
print_info "OS" "$OS_INFO"
print_info "Kernel" "$KERNEL"
print_info "Uptime" "$UPTIME_PRETTY"
print_info "Load" "$LOAD"
print_info "CPU" "$CPU_MODEL ($CPU_CORES cores)"
print_info "Memory" "$TOTAL_MEM"
print_info "Root disk" "$DISK_TOTAL"

# Optional Public IP (if curl available)
if cmd_exists curl; then
  PUB_IP=$(curl -fsS --max-time 5 https://api.ipify.org || echo "unavailable")
  print_info "Public IP" "$PUB_IP"
fi

# Security checks
print_header "Security Summary"

# Check SSH configuration
SSHD_CONFIGS=(/etc/ssh/sshd_config)
# include support
if grep -q '^Include' /etc/ssh/sshd_config 2>/dev/null; then
  while read -r inc; do
    incpath=$(echo "$inc" | awk '{print $2}')
    [ -n "$incpath" ] && SSHD_CONFIGS+=("$incpath")
  done < <(grep '^Include' /etc/ssh/sshd_config 2>/dev/null || true)
fi
SSHD_ROOT=""
SSHD_PASS=""
SSHD_PORT=""
for f in "${SSHD_CONFIGS[@]}"; do
  [ -r "$f" ] || continue
  grep -E '^[[:space:]]*PermitRootLogin' "$f" 2>/dev/null | awk '{print $2; exit}' | grep -v '^$' >/dev/null 2>&1 && SSHD_ROOT=$(grep -E '^[[:space:]]*PermitRootLogin' "$f" 2>/dev/null | awk '{print $2; exit}')
  grep -E '^[[:space:]]*PasswordAuthentication' "$f" 2>/dev/null | awk '{print $2; exit}' | grep -v '^$' >/dev/null 2>&1 && SSHD_PASS=$(grep -E '^[[:space:]]*PasswordAuthentication' "$f" 2>/dev/null | awk '{print $2; exit}')
  grep -E '^[[:space:]]*Port' "$f" 2>/dev/null | awk '{print $2; exit}' | grep -v '^$' >/dev/null 2>&1 && SSHD_PORT=$(grep -E '^[[:space:]]*Port' "$f" 2>/dev/null | awk '{print $2; exit}')
done
SSHD_ROOT=${SSHD_ROOT:-prohibit-password}
SSHD_PASS=${SSHD_PASS:-yes}
SSHD_PORT=${SSHD_PORT:-22}
if [[ "$SSHD_ROOT" == "no" ]]; then
  check_security "SSH Root Login" "PASS" "Root login disabled"
else
  check_security "SSH Root Login" "WARN" "Root login allowed or not explicitly disabled (value: $SSHD_ROOT)"
fi
if [[ "$SSHD_PASS" == "no" ]]; then
  check_security "SSH Password Auth" "PASS" "Password auth disabled"
else
  check_security "SSH Password Auth" "WARN" "Password auth enabled (value: $SSHD_PASS)"
fi
if [[ "$SSHD_PORT" == "22" ]]; then
  check_security "SSH Port" "WARN" "Default port 22 in use"
else
  check_security "SSH Port" "PASS" "Non-default SSH port $SSHD_PORT"
fi

# Firewall
if cmd_exists ufw; then
  if ufw status | grep -qi active; then
    check_security "Firewall (ufw)" "PASS" "UFW active"
  else
    check_security "Firewall (ufw)" "WARN" "UFW installed but not active"
  fi
elif cmd_exists firewall-cmd; then
  if firewall-cmd --state 2>/dev/null | grep -qi running; then
    check_security "Firewall (firewalld)" "PASS" "Firewalld running"
  else
    check_security "Firewall (firewalld)" "WARN" "Firewalld present but not running"
  fi
elif cmd_exists nft; then
  if nft list ruleset 2>/dev/null | grep -q table; then
    check_security "Firewall (nftables)" "PASS" "nftables rules present"
  else
    check_security "Firewall (nftables)" "WARN" "nftables present but no rules detected"
  fi
elif cmd_exists iptables; then
  if iptables -L -n 2>/dev/null | grep -q "Chain INPUT"; then
    check_security "Firewall (iptables)" "PASS" "iptables rules detected"
  else
    check_security "Firewall (iptables)" "WARN" "iptables present but no rules detected or permission limited"
  fi
else
  check_security "Firewall" "WARN" "No firewall tool detected"
fi

# Intrusion Prevention (best-effort without root)
if cmd_exists fail2ban-client; then
  if fail2ban-client ping >/dev/null 2>&1; then
    check_security "Intrusion Prevention" "PASS" "Fail2ban running"
  else
    check_security "Intrusion Prevention" "WARN" "Fail2ban detected but not responding"
  fi
elif cmd_exists cscli; then
  check_security "Intrusion Prevention" "PASS" "CrowdSec tools detected"
else
  check_security "Intrusion Prevention" "FAIL" "No Fail2ban/CrowdSec detected"
fi

# Logs: failed auth attempts (best-effort; may be permission-limited)
AUTH_FAILED=0
if [ -r /var/log/auth.log ]; then
  AUTH_FAILED=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)
elif cmd_exists journalctl; then
  AUTH_FAILED=$(journalctl -u ssh -n 1000 --no-pager --since "24 hours ago" 2>/dev/null | grep -c "Failed password" || echo 0)
else
  AUTH_FAILED=0
fi
if (( AUTH_FAILED < 10 )); then
  check_security "Failed Logins" "PASS" "$AUTH_FAILED failed attempts in logs"
elif (( AUTH_FAILED < 50 )); then
  check_security "Failed Logins" "WARN" "$AUTH_FAILED failed attempts in logs"
else
  check_security "Failed Logins" "FAIL" "$AUTH_FAILED failed attempts in logs"
fi

# Updates (non-root, best-effort)
UPDATES_N=0
if cmd_exists apt; then
  UPDATES_N=$(apt list --upgradable 2>/dev/null | grep -v '^Listing' | wc -l || echo 0)
elif cmd_exists dnf; then
  UPDATES_N=$(dnf check-update --refresh 2>/dev/null | grep -E '^[A-Za-z0-9]' | wc -l || echo 0)
elif cmd_exists yum; then
  UPDATES_N=$(yum check-update 2>/dev/null | grep -E '^[A-Za-z0-9]' | wc -l || echo 0)
fi
if [ "$UPDATES_N" -eq 0 ]; then
  check_security "System Updates" "PASS" "No upgradable packages detected (or not checkable without root)"
else
  check_security "System Updates" "WARN" "$UPDATES_N packages upgradable"
fi

# Disk usage
ROOT_USAGE=$(df -h / 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%' || echo 0)
if [ -z "$ROOT_USAGE" ]; then ROOT_USAGE=0; fi
ROOT_USAGE_NUM=${ROOT_USAGE//[^0-9]/}
if [ "$ROOT_USAGE_NUM" -lt 50 ]; then
  check_security "Disk Usage" "PASS" "Root usage ${ROOT_USAGE}%"
elif [ "$ROOT_USAGE_NUM" -lt 80 ]; then
  check_security "Disk Usage" "WARN" "Root usage ${ROOT_USAGE}%"
else
  check_security "Disk Usage" "FAIL" "Root usage ${ROOT_USAGE}%"
fi

# Memory
MEM_USAGE=$(free -m 2>/dev/null | awk '/Mem:/ {printf "%d", $3/$2*100}')
if [ -z "$MEM_USAGE" ]; then MEM_USAGE=0; fi
if [ "$MEM_USAGE" -lt 50 ]; then
  check_security "Memory Usage" "PASS" "${MEM_USAGE}% used"
elif [ "$MEM_USAGE" -lt 80 ]; then
  check_security "Memory Usage" "WARN" "${MEM_USAGE}% used"
else
  check_security "Memory Usage" "FAIL" "${MEM_USAGE}% used"
fi

# CPU load
CPU_LOAD1=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | cut -d',' -f1 | xargs)
if [[ -n "$CPU_LOAD1" && $(echo "$CPU_LOAD1 < $CPU_CORES" | bc -l 2>/dev/null) -eq 1 2>/dev/null ]]; then
  check_security "CPU Load" "PASS" "1m load: $CPU_LOAD1"
else
  # best-effort judgement
  check_security "CPU Load" "WARN" "1m load: $CPU_LOAD1"
fi

# Ports (using ss or netstat)
LISTEN_PORTS=""
if cmd_exists ss; then
  LISTEN_PORTS=$(ss -tuln 2>/dev/null | awk '{print $5}' | grep -Eo '[0-9]+$' | sort -n | uniq | tr '\n' ',' | sed 's/,$//')
elif cmd_exists netstat; then
  LISTEN_PORTS=$(netstat -tuln 2>/dev/null | awk '{print $4}' | grep -Eo '[0-9]+$' | sort -n | uniq | tr '\n' ',' | sed 's/,$//')
fi
if [ -n "$LISTEN_PORTS" ]; then
  PORT_COUNT=$(echo "$LISTEN_PORTS" | tr ',' '\n' | wc -l)
  check_security "Open Ports" "WARN" "Ports: $LISTEN_PORTS (count: $PORT_COUNT)"
else
  check_security "Open Ports" "WARN" "Unable to determine listening ports"
fi

# SUID checks (limited by permissions)
SUID_COUNT=$(find /usr/bin /bin /sbin /usr/sbin -xdev -type f -perm -4000 2>/dev/null | wc -l || echo 0)
if [ "$SUID_COUNT" -eq 0 ]; then
  check_security "SUID Files" "PASS" "No unusual SUID files found in common paths"
elif [ "$SUID_COUNT" -lt 10 ]; then
  check_security "SUID Files" "WARN" "Found $SUID_COUNT SUID files in common paths"
else
  check_security "SUID Files" "FAIL" "Found $SUID_COUNT SUID files — review"
fi

# Summary
print_header "Summary"
echo "Report generated: $(date)"; write_report "Report generated: $(date)"
echo "Report saved to: $REPORT_FILE"; write_report "Report saved to: $REPORT_FILE"

echo -e "\n${GREEN}Audit complete.${NC} Review the report file for full details: ${BOLD}$REPORT_FILE${NC}"

exit 0
