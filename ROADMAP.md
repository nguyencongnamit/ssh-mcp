# Roadmap

Direction, not promises. Each release has a gate it must pass.

| Version | Theme | Highlights | Gate |
|---|---|---|---|
| **v0.1.0** (released) | Public preview | read-only live tools, sandbox over read-only mirror, SSM + direct transports, OIDC + bot tokens, hash-chained audit, admin console | unit + e2e green, release pipeline with SBOM and provenance |
| v0.2.0 | Field-proven | real-cloud pilot findings, Ubuntu 24.04/26.04, Amazon Linux 2023 and Debian in the e2e matrix, e2e in CI | two weeks on real staging hosts |
| v0.3.0 | Containers and signals | `docker_ps` / `docker_logs` via GET-only socket proxy, async anomaly flagger (opt-in, Slack and Teams) | proxy attack tests |
| v0.4.0 | Beyond AWS | bastion / jump-host transport, generic OIDC (Okta, Google, Keycloak), Helm chart | |
| v0.5.0 | Enterprise | KMS-backed CA, policy hot reload, console SSO, OpenTelemetry | |
| v1.0.0 | Stable | frozen config and certificate format, third-party security audit | audit published |

Have a use case that is not here? Open a
[discussion](https://github.com/nguyencongnamit/ssh-mcp/discussions).

**Never on the roadmap:** write access, arbitrary command execution on
targets, or an LLM as the blocking gate.
