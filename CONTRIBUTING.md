# Contributing to ssh-mcp

Thanks for helping. ssh-mcp is a **security boundary**, so the bar for changes
is high and the process is predictable.

## Ground rules

- **Read-only is absolute.** No change may add a way to write, signal, execute
  arbitrary commands on, or open a shell on a target. Proposals that need write
  access belong in a different project.
- **No raw commands for targets.** New live tools are a schema plus a fixed
  `argv` in `internal/helper`, reviewed like code. Free-form commands run only
  in the sandbox over the read-only mirror.
- **Fail closed.** Unknown input, missing policy, unverifiable certificate:
  refuse.
- **Every boundary change ships with a test that attacks it.** Unit tests for
  the helper and policy, and an e2e case in `testbed/e2e` when the behaviour
  spans hosts.

## Development

```sh
make test          # gofmt check, go vet, unit tests with -race
./testbed/up.sh    # Docker target + server (Linux containers, no cloud account)
make e2e           # end-to-end suite that attacks the running test bed
make build         # bin/ssh-mcp and bin/ssh-mcp-helper
```

Go version: whatever `go.mod` pins. The test bed needs Docker with Linux
containers and roughly 2 GB of free memory.

## Pull requests

1. Open an issue first for anything bigger than a bug fix, so the design can be
   agreed before you write code.
2. One logical change per PR. Keep unrelated formatting out of the diff.
3. `make test` must pass; run `make e2e` when you touch `internal/helper`,
   `internal/sandbox`, `internal/transport`, `internal/ca`, `deploy/` or
   `testbed/`.
4. Update `docs/` and `CHANGELOG.md` (Unreleased) for user-visible changes.
5. Sign off your commits (`git commit -s`) and tick the CLA box — see
   [CLA.md](CLA.md). Contributions without the CLA cannot be merged because the
   project is dual-licensed.

## Reporting security issues

Never in a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
