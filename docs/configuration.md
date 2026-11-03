# Configuration

## `ssh-mcp.yaml`

| Key | Meaning |
|---|---|
| `listen` | MCP listener, e.g. `10.0.1.5:8443` |
| `public_url` | external URL (used for OAuth protected-resource metadata) |
| `tls.cert_file`, `tls.key_file` | serve HTTPS directly |
| `data_dir` | SQLite audit store |
| `audit_key` | HMAC key for the audit chain (`ssh-mcp audit keygen`); keep outside `data_dir` |
| `ca_key` | CA private key file, `0600`. Or use `ca_kms` |
| `ca_kms.key_id`, `.region`, `.profile` | CA key held in AWS KMS (ECC_NIST_P256, SIGN_VERIFY); the private key never leaves KMS. See [deployment](deployment.md#ca-key-in-aws-kms) |
| `source_address` | CIDR pinned into certificates for direct-transport hosts (SSM hosts get loopback) |
| `helper_path` | helper location on targets (default `/usr/local/libexec/ssh-mcp-helper`) |
| `known_hosts` | host keys; `<instance-id> ssh-ed25519 …` for SSM hosts |
| `policy` | path to `policy.yaml` |
| `oidc.provider` | `entra` (default when `tenant_id` is set) or `generic` (Okta, Keycloak, Google, Auth0, ...). See [People sign-in](#people-sign-in-oidc) |
| `oidc.issuer`, `oidc.audience`, `oidc.required_scope` | issuer URL (discovery), required `aud` value, and an optional scope that must appear in `scp` or `scope` |
| `oidc.tenant_id` | Entra only: the token's `tid` must match |
| `oidc.subject_claim`, `.groups_claim`, `.username_claim` | generic only: claim names, dotted for nested claims (defaults `sub`, `groups`, `preferred_username` then `email`) |
| `inventory.static` | YAML host list (`id`, `name`, `transport`, `address`, `tags`) |
| `oidc.issuer`, `oidc.audience`, `oidc.required_scope`, `oidc.tenant_id` | OIDC for people (Microsoft Entra ID today) |
| `inventory.static` | YAML host list (`id`, `name`, `transport` = `ssm`\|`direct`\|`jump`, `address`, `tags`) |
| `inventory.ec2[].region`, `.profile` | discover EC2 instances tagged `ssh-mcp=enabled` |
| `transport.ssm`, `transport.direct` | enable transports |
| `transport.jump.address`, `.user`, `.key_file`, `.known_hosts`, `.source_address` | reach `transport: jump` hosts through an SSH bastion. See [deployment](deployment.md#targets-without-ssm-jump-host) |
| `sandbox.enabled`, `.prefixes`, `.max_concurrent`, `.cgroups` | free-form sandbox; `prefixes` must sit inside `paths.allow`; `cgroups: auto\|required\|off` |
| `alerts.enabled`, `.slack_webhook_file`, `.teams_webhook_file`, `.console_url`, `.refusals`, `.window`, `.cooldown` | opt-in alerts to Slack and Teams (off by default). See [Alerts](#alerts) |
| `console.listen`, `.user`, `.password_hash`, `.timezone` | admin console (`ssh-mcp console passwd` prints the hash) |

Full example: [`deploy/ssh-mcp.example.yaml`](../deploy/ssh-mcp.example.yaml).

## `policy.yaml`

Deny by default. A call is allowed when one rule matches caller, host and tool.

```yaml
rules:
  - name: oncall-everything
    who: { group: <group> }   # or user: <subject>, or token: <bot-name>
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

`who` takes exactly one of:

- `group`: a value in the caller's groups (Entra group object ID or app-role
  name; for generic OIDC, a value of `groups_claim`). `entra_group` is an
  accepted alias.
- `user`: the caller's immutable subject (Entra object ID, or the generic
  provider's subject claim; case-sensitive unless it is a GUID). Emails and
  usernames are rejected because they can change.
- `token`: a bot token name from `ssh-mcp token create`.
### Reloading the policy

`systemctl reload ssh-mcp` (SIGHUP) re-reads `policy.yaml` without dropping
connections. Run `ssh-mcp policy check` first. A file that does not parse, or
whose `paths.allow` no longer contains the sandbox prefixes, is refused and
the running policy stays in force. Every attempt, applied or refused, is an
audit record (`tool = policy_reload`, with the file's SHA-256). Rate-limit
budgets carry over. When `paths` changes, new certificates carry the new
paths at once and sandbox mirrors are remounted. Certificates already issued
keep the old paths until they expire (5 minutes for live calls). Other
settings in `ssh-mcp.yaml` need a restart.

The effective `paths` policy is signed into every certificate and enforced on
the host, intersected with the host's own `/etc/ssh-mcp/helper-policy.json`
floor. The server can narrow what a host exposes, never widen it.

Built-in deny list (always applied) includes `/etc/shadow`, `/etc/gshadow`,
`/etc/sudoers*`, `/etc/ssh/`, `/etc/ssl/private/`, `/etc/letsencrypt/`,
`/var/log/audit/`, and globs such as `**/.env`, `**/*.pem`, `**/*.key`,
`**/id_rsa*`, `**/credentials`, `**/*secret*`, `**/*token*`. See
`internal/pathpolicy`.

## People sign-in (OIDC)

ssh-mcp verifies each bearer JWT's signature against the issuer's published
keys and checks issuer, audience (`aud` must contain `audience`), expiry and,
if set, `required_scope`. Authorization keys only on an immutable subject;
display names and emails go to the audit log as labels and are never used to
decide access.

**Microsoft Entra ID**

```yaml
oidc:
  issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
  audience: api://<ssh-mcp-app-id>
  required_scope: ssh-mcp.read
  tenant_id: <tenant-id>      # selects provider entra; users keyed by oid
```

Groups are the `groups` claim (object IDs) plus `roles` (app roles). With more
than 200 groups Entra omits the claim; such users match no group rules (fails
closed), so prefer app roles.

**Okta** (custom authorization server)

```yaml
oidc:
  provider: generic
  issuer: https://<org>.okta.com/oauth2/<auth-server-id>
  audience: api://ssh-mcp
  required_scope: ssh-mcp.read
  # Add a "groups" claim to access tokens in the authorization server.
```

**Keycloak**

```yaml
oidc:
  provider: generic
  issuer: https://<host>/realms/<realm>
  audience: ssh-mcp            # add an audience mapper to the client
  groups_claim: realm_access.roles
```

**Google** (ID tokens; Google access tokens are opaque and cannot be verified
locally)

```yaml
oidc:
  provider: generic
  issuer: https://accounts.google.com
  audience: <oauth-client-id>.apps.googleusercontent.com
  # Google tokens carry no groups; write rules with user: <numeric sub>.
```

**Auth0**

```yaml
oidc:
  provider: generic
  issuer: https://<tenant>.auth0.com/
  audience: https://ssh-mcp.example
  groups_claim: https://ssh-mcp.example/groups   # set by an Auth0 Action
```

None of these providers, Entra included, has yet been tested with live
sign-ins. Each claim shape above is covered by unit tests that run a local
issuer and sign real JWTs.
## Alerts

Off by default. When enabled, ssh-mcp watches its own audit log and posts to
a Slack incoming webhook, a Microsoft Teams Workflows webhook, or both (same
alerts to each):

```yaml
alerts:
  enabled: true
  slack_webhook_file: /etc/ssh-mcp/slack-webhook   # 0600, one https:// URL
  teams_webhook_file: /etc/ssh-mcp/teams-webhook   # 0600, one https:// URL
  console_url: https://localhost:8444              # links to the call trail
  refusals: 5        # refusal burst threshold per identity ...
  window: 10m        # ... within this window
  cooldown: 30m      # at most one alert per rule and identity in this time
```

| Rule | Fires when |
|---|---|
| `refusal_burst` | one identity is refused `refusals` times within `window` |
| `host_refusal` | the server allowed a call but the target's helper refused it: the host floor and the server policy disagree, or someone is probing for a bypass |
| `admin_action` | kill switch, unkill, token create or revoke, from the console or the CLI |

Rules are fixed and deterministic; no model is involved. The watcher reads
the audit log after the fact, so a slow or failing webhook never delays a
call. It starts after the newest record, so a restart does not replay old
events.
