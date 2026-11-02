# Security policy

ssh-mcp exists to give AI agents a safe, read-only path into servers, so we
treat any way around that boundary as a critical vulnerability.

## Reporting a vulnerability

Report privately through **GitHub Security Advisories**:
https://github.com/nguyencongnamit/ssh-mcp/security/advisories/new

Please include the version or commit, your setup (transport, distro, OpenSSH
and bubblewrap versions), reproduction steps and the impact you observed.
Do not open a public issue, pull request or discussion for security reports.

| Step | Target |
|---|---|
| Acknowledge the report | 3 business days |
| Initial assessment and severity | 7 days |
| Fix or mitigation for critical issues | 30 days |
| Coordinated public disclosure | after a fix ships, or 90 days, whichever is first |

We credit reporters in the advisory unless you prefer otherwise.

## In scope

- Any write, signal, process execution or shell on a target through ssh-mcp.
- Reading a path the policy denies (on the host or through the sandbox mirror).
- Escaping the sandbox, reaching the network from it, or exhausting the server.
- Certificate misuse: using an ssh-mcp certificate outside its principal,
  validity, source address or embedded path policy.
- Authentication or authorization bypass on the MCP endpoint or the console.
- Tampering with the audit chain without `ssh-mcp audit verify` detecting it.
- Secret-redaction bypasses for the built-in formats.

## Out of scope

- Secrets in formats the redaction filter does not claim to cover, inside files
  the operator's policy allows (a documented limit, see the threat model).
- Attacks that require root on the ssh-mcp server or on a target.
- Denial of service through volumetric traffic against the HTTP endpoint.

## Supported versions

Only the latest release receives security fixes during the 0.x series.

## Hardening reference

See [docs/threat-model.md](docs/threat-model.md) and
[docs/deployment.md](docs/deployment.md).
