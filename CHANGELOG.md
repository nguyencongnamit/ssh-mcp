# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0-rc.1] - 2026-11-03

Release candidate. Not yet run on a production fleet; v0.2.0 waits for a
staging pilot on real hosts (see ROADMAP.md).

### Added
- End-to-end attack suite now runs on every pull request against Ubuntu 22.04,
  24.04 and 26.04, Debian 12 and Amazon Linux 2023 targets (#7).
- Go fuzz tests for request decoding, the path policy and the certificate
  path-policy check, run in CI on every pull request (#10).
- Generic OIDC sign-in (`oidc.provider: generic`) for Okta, Keycloak, Google,
  Auth0 and other issuers, with configurable subject, groups and username
  claims (dotted names for nested claims); scopes read from `scp` or `scope`
  (#9).
- Provider-neutral `who: { group: ... }` in policy; `entra_group` remains an
  alias. User subjects other than Entra object IDs are accepted (case-sensitive).
- Policy hot reload: `systemctl reload ssh-mcp` (SIGHUP) re-reads
  `policy.yaml`; invalid files are refused and every attempt is audited.
- CA key in AWS KMS (`ca_kms`): an ECC_NIST_P256 key signs every
  certificate through `kms:Sign`; the private key never leaves KMS (#12).
- `docker_ps` and `docker_logs` tools through a read-only Docker proxy
  (`ssh-mcp-helper --docker-proxy`, opt-in per host with `DOCKER_PROXY=1`).
  The proxy answers only container list and non-following logs, rebuilds
  each upstream request from validated values, and never returns labels,
  commands, environment or mounts. agent-ro never gets the Docker socket (#8).
- Opt-in alerts to Slack and Microsoft Teams (same alerts to both): refusal
  bursts, calls the target refused after the server allowed them, and admin
  actions, each linking to the console call trail. Off by default.
- Jump-host transport (`transport: jump`) for fleets outside AWS or without
  SSM: one bastion connection per call, TCP forwarding only, certificates
  pinned to the bastion's address; sandbox mirrors use `ssh -W` through the
  same bastion. Covered end to end by a bastion container in the test bed.

### Changed
- `tools: ["*"]` in a policy now includes the two Docker tools; they return
  "not enabled" on hosts without the proxy.
- Architecture diagram is now a drawn SVG (light and dark) instead of Mermaid source.

### Fixed
- CLI `kill`, `unkill`, `token create` and `token revoke` now write audit
  records (`cli:<user>`), as the console already did.

### Documentation
- AppArmor profiles for Ubuntu servers (`deploy/apparmor/`), tested on real
  24.04 and 26.04 hosts in CI; deployment guide corrected (24.04 needs the
  user-namespace profile, 26.04 the fusermount3 override) (#11).
- OpenSSH 9.8+ `PerSourcePenalties`: how to exempt the ssh-mcp source address.

## [0.1.0] - 2026-11-03

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

[Unreleased]: https://github.com/nguyencongnamit/ssh-mcp/compare/v0.2.0-rc.1...HEAD
[0.2.0-rc.1]: https://github.com/nguyencongnamit/ssh-mcp/compare/v0.1.0...v0.2.0-rc.1
[0.1.0]: https://github.com/nguyencongnamit/ssh-mcp/releases/tag/v0.1.0
