#!/usr/bin/env bash
# Reverse bootstrap-target.sh. Untag the instance first: that alone cuts
# access at the IAM layer.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
rm -f /etc/ssh/sshd_config.d/50-ssh-mcp.conf /etc/ssh/ssh-mcp-ca.pub
rm -rf /etc/ssh/ssh-mcp-principals
sshd -t && { systemctl reload sshd 2>/dev/null || systemctl reload ssh; }
pkill -u agent-ro 2>/dev/null || true
pkill -u agent-sftp 2>/dev/null || true
userdel agent-ro 2>/dev/null || true
userdel agent-sftp 2>/dev/null || true
rm -f /usr/local/libexec/ssh-mcp-helper
echo "removed"
