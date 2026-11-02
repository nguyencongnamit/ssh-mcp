# Quick start (local, no cloud account)

The test bed runs a real Linux target (OpenSSH, built with the production
bootstrap script) and an ssh-mcp server in Docker, then attacks both.

**Needs:** Docker with Linux containers, Go (version from `go.mod`), ~2 GB RAM.

```sh
git clone https://github.com/nguyencongnamit/ssh-mcp && cd ssh-mcp
make test          # gofmt, vet, unit tests with -race
./testbed/up.sh    # builds target + server, generates CA, tokens, console password
make e2e           # end-to-end attack suite
```

| Endpoint (127.0.0.1) | What |
|---|---|
| `:18471/mcp` | MCP endpoint (bearer token from `testbed/state/*.token`) |
| `:18472` | target sshd (only ssh-mcp certificates work) |
| `:18473` | admin console, user `admin`, password in `testbed/state/console.password` |

## Connect an agent

```sh
claude mcp add --transport http ssh-mcp http://127.0.0.1:18471/mcp \
  --header "Authorization: Bearer $(cat testbed/state/ops-bot.token)"
```

Then ask: *"List the hosts you can inspect, then check why nginx failed on web-1."*

The test bed ships three bots: `ops-bot` (all tools on staging), `log-bot`
(`journal` and `tail_file` only) and `stranger` (no rules, so every call is
refused).

## Tear down

```sh
make down
```
