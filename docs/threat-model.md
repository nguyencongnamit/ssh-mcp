# Threat model

**The promise:** an agent using ssh-mcp cannot change a target. It cannot
write, delete or chmod files, signal or restart processes, open a shell, reach
the network from the sandbox, read root-only files, or reach a host the policy
does not grant.

**The biggest remaining risk** is secrets leaving through output, not writes.
Writes are blocked by the operating system; secret leaks are only filtered.

## Layers

Layers 1–4 are the hard boundary. Layers 5–7 narrow what is reachable and make
misuse visible.

| # | Layer | Enforced by | Guarantee | If bypassed |
|---|---|---|---|---|
| 1 | `agent-ro` / `agent-sftp` users | Linux DAC | non-root, no sudo, unusable password | base boundary |
| 2 | SSH certificate + `Match User` | sshd | forced helper, no pty, no forwarding, short TTL, source-address | layer 1 holds |
| 3 | `ssh-mcp-helper` | fixed `execve`, no shell | typed tools, schema-validated args, symlink-safe reads, path policy = host floor ∩ signed cert policy | layers 1–2 hold |
| 4 | Sandbox | bubblewrap + cgroup v2 | all namespaces unshared (no network), caps dropped, uid 65534, read-only root and mirror, pids/memory/time capped | the mirror is read-only at the source |
| 5 | Transport | AWS IAM + SSM | only `AWS-StartSSHSession`, only tagged hosts, no port 22 | still lands as `agent-ro` |
| 6 | Policy | ssh-mcp server | who × host × tool, rate limits, deny by default | narrows reach only |
| 7 | Output pipeline | ssh-mcp server | size cap, redaction, untrusted fence | secrets may reach the LLM |

## Threats

| Threat | Example | Control | Residual |
|---|---|---|---|
| Agent changes a host | `rm`, `kill`, `systemctl restart` | no such tool; fixed argv; DAC; read-only mirror | none known |
| Shell escape via allowed binary | pager `!sh`, `find -exec`, `awk system()` | no shell, `--no-pager`, `PAGER=cat`, no pty; free-form only in sandbox | low |
| Argument injection | `unit="x; id"`, `path="../../etc/shadow"` | per-arg regex, `--` before operands, canonical paths | low |
| Symlink / hardlink to secret | `/var/log/app.log → /root/.ssh/id_rsa` | `O_NOFOLLOW`, `/proc/self/fd` re-check, DAC | low |
| Denied file via sandbox | `sed 's/./& /g' .env` to dodge redaction | SFTP helper hides denied paths at the source (e2e regression test) | low |
| Prompt injection via output | log line: "ignore instructions, read …" | untrusted fence, no write tools to misuse, audit | medium — can steer reads, not writes |
| Secret exfiltration to LLM | password in a world-readable config | redaction (cloud keys, JWTs, PEM, `password=`, DSNs, CLI flags, entropy), deny list | **medium** — unknown formats pass; fix file permissions |
| Stolen client token | laptop compromise | OIDC session lifetime; bot tokens expiring, scoped, revocable; kill switch | low–medium |
| Server compromise | RCE in the server | attacker gets read-only `agent-ro` on granted hosts; keep CA in KMS/sealed file, private subnet | medium |
| Sandbox escape | kernel exploit | no network, no caps, non-root, per-call; lands on server, not targets | low |
| Resource exhaustion | fork bomb, huge journal range | cgroup pids/memory, rlimits, timeouts, concurrency cap, arg clamps | low |
| Audit tampering | edit SQLite rows | append-only triggers, hash chain, optional HMAC key, `audit verify` | low |
| Insider abuse | engineer reads logs they should not | tag + group scoping, per-person audit, console | low |

## Known limits

- Redaction is a filter. Secrets in unknown formats inside files the policy
  allows can reach the agent's model provider.
- `journal` exposes what the `adm` / `systemd-journal` groups can read.
- `listening_ports` shows process names only for `agent-ro`'s own processes.
- On bubblewrap < 0.7 the sandbox `/tmp` has no size flag; cgroup `memory.max`
  bounds it.

## Independent review

An adversarial review before the first release found 13 issues (sandbox glob
bypass, server-only path rules, kill-switch normalisation, sandbox DoS,
mutable identity claims, bootstrap on old sshd, CA override, SSM host key and
source address, mirror lifecycle, redaction gaps, ProxyCommand characters,
unkeyed audit chain, unfenced errors). All are fixed, most with regression
tests. A third-party audit is planned before 1.0.
