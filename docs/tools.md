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
| `sandbox_exec` | sandbox | `/bin/sh -c` inside bubblewrap | `command`; mirror at `/targets/<host-id>`, read-only; 30 s, 256 KiB output |

Adding a live tool means adding a schema in `internal/protocol`, a fixed argv
in `internal/helper`, and attack tests. No tool accepts a raw command for a
target.
