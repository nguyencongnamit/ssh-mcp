#!/bin/sh
# Test bed stand-in for systemd's Delegate=: hand this container's cgroup
# subtree to the ssh-mcp user, then drop root for good.
set -e
if mount -o remount,rw /sys/fs/cgroup 2>/dev/null; then
  chown ssh-mcp:ssh-mcp /sys/fs/cgroup /sys/fs/cgroup/cgroup.procs /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
fi
# No --bounding-set: setuid fusermount3 must still gain CAP_SYS_ADMIN to mount.
exec setpriv --reuid ssh-mcp --regid ssh-mcp --init-groups \
  /usr/local/bin/ssh-mcp serve -config /etc/ssh-mcp/ssh-mcp.yaml
