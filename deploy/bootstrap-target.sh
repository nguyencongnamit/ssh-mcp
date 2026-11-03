#!/usr/bin/env bash
# One-time, idempotent setup of an ssh-mcp target. Run as root (for example
# through SSM Run Command by an admin). It does not open any port.
#
#   CA_PUBKEY="ssh-ed25519 AAAA... ssh-mcp user CA" HELPER_URL=... HELPER_SHA256=... ./bootstrap-target.sh
#
# Needs OpenSSH >= 8.2 (Include, ExposeAuthInfo). CI covers Amazon Linux 2023,
# Ubuntu 22.04/24.04/26.04 and Debian 12. Amazon Linux 2 (OpenSSH 7.4, EOL) is refused.
set -euo pipefail

: "${CA_PUBKEY:?set CA_PUBKEY to the ssh-mcp CA public key line}"
: "${HELPER_SRC:=}"          # local path to ssh-mcp-helper, or
: "${HELPER_URL:=}"          # URL to download it from
: "${HELPER_SHA256:?set HELPER_SHA256 to the expected helper checksum}"
HELPER=/usr/local/libexec/ssh-mcp-helper
DROPIN=/etc/ssh/sshd_config.d/50-ssh-mcp.conf

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

echo "==> users"
id agent-ro   >/dev/null 2>&1 || useradd --system --shell /bin/sh --no-create-home --home-dir / agent-ro
id agent-sftp >/dev/null 2>&1 || useradd --system --shell /bin/sh --no-create-home --home-dir / agent-sftp
# /bin/sh (not nologin) for both: sshd runs a ForceCommand through the login
# shell (only the built-in internal-sftp skips it), and nologin would print
# its banner instead of running the helper. ForceCommand below means no
# client command ever reaches that shell.
usermod -s /bin/sh agent-ro; usermod -s /bin/sh agent-sftp
# '*' = no usable password. Not 'passwd -l': sshd treats a '!' password as a
# locked account and refuses even certificate logins when PAM is off.
usermod -p '*' agent-ro; usermod -p '*' agent-sftp
for g in adm systemd-journal; do
  getent group "$g" >/dev/null && usermod -aG "$g" agent-ro && usermod -aG "$g" agent-sftp
done
# Neither account may have sudo rights.
if sudo -l -U agent-ro 2>/dev/null | grep -q "may run"; then echo "agent-ro has sudo rights; remove them" >&2; exit 1; fi

echo "==> helper"
tmp=$(mktemp)
if [ -n "$HELPER_SRC" ]; then cp "$HELPER_SRC" "$tmp"; else curl -fsSL "$HELPER_URL" -o "$tmp"; fi
echo "$HELPER_SHA256  $tmp" | sha256sum -c - >/dev/null || { echo "helper checksum mismatch" >&2; rm -f "$tmp"; exit 1; }
install -D -o root -g root -m 0755 "$tmp" "$HELPER"; rm -f "$tmp"

echo "==> sshd"
# Older sshd has no -V and exits non-zero, but prints its version in the
# usage text; "|| true" keeps pipefail from aborting silently.
ver=$( (sshd -V 2>&1 || true) | sed -n 's/^OpenSSH_\([0-9]*\)\.\([0-9]*\).*/\1 \2/p' | head -1)
read -r maj min <<<"${ver:-0 0}"
if [ "$maj" -lt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -lt 2 ]; }; then
  echo "OpenSSH $maj.$min is too old (need 8.2+ for Include and ExposeAuthInfo)" >&2; exit 1
fi
printf '%s\n' "$CA_PUBKEY" > /etc/ssh/ssh-mcp-ca.pub
chmod 0644 /etc/ssh/ssh-mcp-ca.pub
install -d -m 0755 /etc/ssh/ssh-mcp-principals
echo ssh-mcp-live > /etc/ssh/ssh-mcp-principals/agent-ro
echo ssh-mcp-sftp > /etc/ssh/ssh-mcp-principals/agent-sftp
chmod 0644 /etc/ssh/ssh-mcp-principals/*

backup=/etc/ssh/sshd_config.ssh-mcp-bak.$(date +%s)
cp -p /etc/ssh/sshd_config "$backup"
restore() { echo "sshd -t failed; restoring $backup" >&2; cp -p "$backup" /etc/ssh/sshd_config; rm -f "$DROPIN"; sshd -t; exit 1; }

if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config; then
  sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
fi
install -d -m 0755 /etc/ssh/sshd_config.d
# Everything is scoped to the two agent users, so an existing
# TrustedUserCAKeys / AuthorizedPrincipalsFile for other users is untouched.
cat > "$DROPIN" <<'CONF'
# Managed by ssh-mcp bootstrap. Remove with remove-target.sh.
Match User agent-ro
    TrustedUserCAKeys /etc/ssh/ssh-mcp-ca.pub
    AuthorizedPrincipalsFile /etc/ssh/ssh-mcp-principals/%u
    AuthorizedKeysFile none
    ExposeAuthInfo yes
    ForceCommand /usr/local/libexec/ssh-mcp-helper
    PermitTTY no
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    AllowAgentForwarding no
    PermitTunnel no
    PermitUserRC no

Match User agent-sftp
    TrustedUserCAKeys /etc/ssh/ssh-mcp-ca.pub
    AuthorizedPrincipalsFile /etc/ssh/ssh-mcp-principals/%u
    AuthorizedKeysFile none
    ExposeAuthInfo yes
    ForceCommand /usr/local/libexec/ssh-mcp-helper --sftp
    PermitTTY no
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    AllowAgentForwarding no
    PermitTunnel no
    PermitUserRC no
CONF
chmod 0644 "$DROPIN"
sshd -t || restore
if [ "${SKIP_RELOAD:-0}" != 1 ]; then
  systemctl reload sshd 2>/dev/null || systemctl reload ssh
fi

echo "==> done. Now tag the instance ssh-mcp=enabled and add its host key to the server's known_hosts:"
echo "    $(hostname)  -> $(awk '{print $1" "$2}' /etc/ssh/ssh_host_ed25519_key.pub)"
