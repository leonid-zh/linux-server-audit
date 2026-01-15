# linux-server-audit

A lightweight audit script for Debian and Ubuntu servers.

The script collects basic system information and reports:
- Operating system and kernel details
- Uptime and load average
- Disk and memory usage
- Pending system updates
- Pending security updates
- Whether a system reboot is required

## Usage

```bash
sudo ./script.sh servername
