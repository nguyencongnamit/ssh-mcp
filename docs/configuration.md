# Configuration

## `ssh-mcp.yaml`

| Key | Meaning |
|---|---|
| `listen` | MCP listener, e.g. `10.0.1.5:8443` |
| `public_url` | external URL (used for OAuth protected-resource metadata) |
| `tls.cert_file`, `tls.key_file` | serve HTTPS directly |
| `data_dir` | SQLite audit store |
| `audit_key` | HMAC key for the audit chain (`ssh-mcp audit keygen`); keep outside `data_dir` |
| `ca_key` | CA private key, `0600` |
| `source_address` | CIDR pinned into certificates for direct-transport hosts (SSM hosts get loopback) |
| `helper_path` | helper location on targets (default `/usr/local/libexec/ssh-mcp-helper`) |
| `known_hosts` | host keys; `<instance-id> ssh-ed25519 …` for SSM hosts |
| `policy` | path to `policy.yaml` |
| `oidc.issuer`, `oidc.audience`, `oidc.required_scope`, `oidc.tenant_id` | OIDC for people (Microsoft Entra ID today) |
| `inventory.static` | YAML host list (`id`, `name`, `transport`, `address`, `tags`) |
| `inventory.ec2[].region`, `.profile` | discover EC2 instances tagged `ssh-mcp=enabled` |
| `transport.ssm`, `transport.direct` | enable transports |
| `sandbox.enabled`, `.prefixes`, `.max_concurrent`, `.cgroups` | free-form sandbox; `prefixes` must sit inside `paths.allow`; `cgroups: auto\|required\|off` |
| `console.listen`, `.user`, `.password_hash`, `.timezone` | admin console (`ssh-mcp console passwd` prints the hash) |

Full example: [`deploy/ssh-mcp.example.yaml`](../deploy/ssh-mcp.example.yaml).

## `policy.yaml`

Deny by default. A call is allowed when one rule matches caller, host and tool.

```yaml
rules:
  - name: oncall-everything
    who: { entra_group: <group-object-id> }   # or user: <object-id>, or token: <bot-name>
    hosts: { tags: { env: [staging, prod] } } # or all: true
    tools: ["*"]
  - name: triage-bot
    who: { token: triage-bot }
    hosts: { tags: { env: [prod] } }
    tools: [journal, tail_file]
    rate: 60/min
paths:
  allow: [/var/log/, /etc/]
  deny: [/etc/app/private/]   # added to the built-in deny list, never replacing it
```

The effective `paths` policy is signed into every certificate and enforced on
the host, intersected with the host's own `/etc/ssh-mcp/helper-policy.json`
floor. The server can narrow what a host exposes, never widen it.

Built-in deny list (always applied) includes `/etc/shadow`, `/etc/gshadow`,
`/etc/sudoers*`, `/etc/ssh/`, `/etc/ssl/private/`, `/etc/letsencrypt/`,
`/var/log/audit/`, and globs such as `**/.env`, `**/*.pem`, `**/*.key`,
`**/id_rsa*`, `**/credentials`, `**/*secret*`, `**/*token*`. See
`internal/pathpolicy`.
