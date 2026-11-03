# Tools

Every tool takes a required `host` (ID or Name tag, from `list_hosts`) and
returns redacted text inside an untrusted-data fence.

| Tool | Path | Runs | Arguments and limits |
|---|---|---|---|
| `list_hosts` | server | inventory | hosts your policy grants; no target contact |
| `host_overview` | live | `uname`, `uptime`, `free`, `df`, `nproc` | none |
| `ps` | live | `ps -eo … --sort=-%cpu` | `limit` ≤ 200 (default 50) |
| `listening_ports` | live | `ss -tulnp` | none |
| `journal` | live | `journalctl --no-pager -o short-iso` | `unit`, `since_seconds` ≤ 7 d, `priority` 0–7, `lines` ≤ 2000 |
| `systemctl_status` | live | `systemctl status --no-pager` | `unit` (validated), `lines` ≤ 200 |
| `failed_units` | live | `systemctl list-units --failed` | none |
| `read_file` | live | `open(O_RDONLY\|O_NOFOLLOW)` in the helper | `path`, `offset`, `length` ≤ 256 KiB |
| `tail_file` | live | same | `path`, `lines` ≤ 2000 |
| `list_dir` | live | `readdir` in the helper | `path`, ≤ 1000 entries |
| `docker_ps` | live | read-only Docker proxy, `GET /containers` | `all`; returns id, names, image, state, status, created, ports only |
| `docker_logs` | live | read-only Docker proxy, `GET /containers/{id}/logs` (never follow) | `container` (validated), `lines` ≤ 2000, `since_seconds` ≤ 7 d |
| `sandbox_exec` | sandbox | `/bin/sh -c` inside bubblewrap | `command`; mirror at `/targets/<host-id>`, read-only; 30 s, 256 KiB output |

Adding a live tool means adding a schema in `internal/protocol`, a fixed argv
in `internal/helper`, and attack tests. No tool accepts a raw command for a
target.

## Docker tools

`docker_ps` and `docker_logs` work only on hosts bootstrapped with
`DOCKER_PROXY=1`; elsewhere they answer "not enabled on this host". The
helper never opens the Docker socket, which is root-equivalent. It asks a
separate proxy (`ssh-mcp-helper --docker-proxy`, run by systemd as
`ssh-mcp-docker` in the `docker` group) on `/run/ssh-mcp/docker.sock`, which
only `agent-ro` can open. The proxy:

- accepts `GET` only, on exactly two paths, with an allowlist of parameters;
- builds a new upstream request from the validated values instead of
  forwarding the incoming one (`follow` is always off);
- returns a reduced container view: labels, commands, environment and mounts
  never leave it;
- runs with no network, no capabilities and a system-call filter.

Log output passes through the same redaction and untrusted-data fence as
every other tool. CI installs the proxy with the real bootstrap and units on
a host with Docker and probes it (`.github/workflows/docker-proxy.yml`).
