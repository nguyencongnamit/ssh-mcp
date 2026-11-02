# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

First public preview.

### Added
- MCP server (streamable HTTP) with 11 tools: `list_hosts`, `host_overview`,
  `ps`, `listening_ports`, `journal`, `systemctl_status`, `failed_units`,
  `read_file`, `tail_file`, `list_dir`, `sandbox_exec`.
- `ssh-mcp-helper` target boundary: fixed argv per tool, no shell,
  symlink/FIFO-safe reads, refuses root, read-only SFTP mode for the mirror.
- Per-call Ed25519 SSH certificates with forced command, no extensions,
  pinned source address and the path policy embedded as a signed extension.
- Transports: SSH over AWS SSM `AWS-StartSSHSession`, and direct SSH.
- bubblewrap sandbox over an sshfs read-only mirror with per-call cgroup v2
  pids/memory limits and a concurrency cap.
- Policy: who (OIDC group/user, bot token) × host tags × tools, rate limits,
  path allow/deny with globs and a built-in deny list.
- Redaction filter (cloud keys, JWTs, PEM, passwords, DSNs, CLI secret flags,
  entropy) and untrusted-output fencing.
- Hash-chained, append-only, optionally HMAC-keyed audit log; kill switch;
  hashed, expiring bot tokens.
- Admin web console: overview, activity with call trails, hosts, identities,
  policy, audit integrity; ⌘K palette; light and dark themes.
- Target bootstrap and removal scripts, IAM policy, systemd unit.
- Docker test bed and an end-to-end suite that attacks the boundary.

### Security
- Build with Go 1.26.10 and current dependencies (govulncheck clean).
- Fixed 13 findings from a pre-release adversarial review (see
  `docs/threat-model.md`).

[Unreleased]: https://github.com/nguyencongnamit/ssh-mcp/commits/main
