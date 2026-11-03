# Roadmap

Direction, not promises. Each release has a gate it must pass.

| Version | Theme | Highlights | Gate |
|---|---|---|---|
| **v0.1.0** (released) | Public preview | read-only live tools, sandbox over read-only mirror, SSM + direct transports, OIDC + bot tokens, hash-chained audit, admin console | unit + e2e green, release pipeline with SBOM and provenance |
| **v0.2.0-rc.1** (released) | Release candidate | everything marked ✓ below | CI green on every target |
| v0.2.0 | Field-proven | ✓ e2e on Ubuntu 22.04/24.04/26.04, Debian 12, Amazon Linux 2023 in CI · ✓ AppArmor profiles tested on real hosts · ✓ fuzzing · real-cloud pilot findings | two weeks on real staging hosts |
| v0.3.0 | Containers and signals | ✓ `docker_ps` / `docker_logs` via read-only Docker proxy · ✓ opt-in alerts (Slack and Teams) | ✓ proxy attack tests |
| v0.4.0 | Beyond AWS | ✓ SSH jump-host transport · ✓ generic OIDC (Okta, Google, Keycloak, Auth0) · Helm chart · Tailscale SSH, GCP IAP, Azure Bastion | live sign-in with each provider |
| v0.5.0 | Enterprise | ✓ KMS-backed CA · ✓ policy hot reload · console SSO · OpenTelemetry | |
| v1.0.0 | Stable | frozen config and certificate format, third-party security audit | audit published |

Have a use case that is not here? Open a
[discussion](https://github.com/nguyencongnamit/ssh-mcp/discussions).

**Never on the roadmap:** write access, arbitrary command execution on
targets, or an LLM as the blocking gate.
