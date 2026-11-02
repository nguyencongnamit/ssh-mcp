## What and why

<!-- One logical change. Link the issue: Fixes #123 -->

## Boundary impact

- [ ] Does not add any way to write, signal, execute or open a shell on a target
- [ ] Touches the security boundary (helper, cert, sandbox, transport, auth) — design agreed in an issue, attack test added

## Checklist

- [ ] `make test` passes
- [ ] `make e2e` passes (required when touching helper, sandbox, transport, ca, deploy or testbed)
- [ ] Docs and `CHANGELOG.md` (Unreleased) updated for user-visible changes
- [ ] Commits are signed off (`git commit -s`)
- [ ] I agree to the [Contributor License Agreement](../CLA.md)
