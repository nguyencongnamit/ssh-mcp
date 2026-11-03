# Deployment

## Server

1. Run it in a private subnet with no inbound internet. Linux with cgroup v2.
2. Install: `ssh-mcp` binary, AWS CLI + `session-manager-plugin` (SSM
   transport), `bwrap`, `sshfs` / `fusermount3`, `prlimit`.
   **Ubuntu AppArmor.** The live tools need nothing. `sandbox_exec` does:

   | Release | Blocks | Fix |
   |---|---|---|
   | 24.04 | unprivileged user namespaces (bubblewrap) | load [`deploy/apparmor/ssh-mcp`](../deploy/apparmor/ssh-mcp) |
   | 26.04 | fusermount3 mount points (sshfs mirrors under `data_dir`) | add [`deploy/apparmor/fusermount3.local`](../deploy/apparmor/fusermount3.local) as `/etc/apparmor.d/local/fusermount3` |

   Both keep the system-wide restrictions on for everything else; each file
   has its install commands at the top. 26.04 already ships a bwrap profile,
   so the first file is not needed there. CI loads both on real 24.04 and
   26.04 hosts and checks that each is refused without its profile and works
   with it (`.github/workflows/apparmor.yml`). Avoid turning
   `kernel.apparmor_restrict_unprivileged_userns` off host-wide.
3. Keys:
   ```sh
   ssh-mcp ca init -key /etc/ssh-mcp/ca_key
   ssh-mcp audit keygen -out /etc/ssh-mcp/audit.key
   ssh-mcp ca pubkey -config /etc/ssh-mcp/ssh-mcp.yaml > ssh-mcp-ca.pub   # copy to targets
   ```
4. Write `/etc/ssh-mcp/ssh-mcp.yaml` and `policy.yaml` from
   [`deploy/`](../deploy) and validate with `ssh-mcp policy check`.
5. Install [`deploy/ssh-mcp.service`](../deploy/ssh-mcp.service).
   `Delegate=pids memory` gives each sandbox its own cgroup; with
   `sandbox.cgroups: required` the server refuses to start without it.

### CA key in AWS KMS

Instead of `ca_key`, the CA can be an asymmetric KMS key, so the signing key
never exists on the server's disk:

```sh
aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY \
  --description "ssh-mcp user CA"
aws kms create-alias --alias-name alias/ssh-mcp-ca --target-key-id <key-id>
```

```yaml
ca_kms:
  key_id: alias/ssh-mcp-ca
  region: <region>
```

Grant the server role `kms:GetPublicKey` and `kms:Sign` on that key only.
`ssh-mcp ca pubkey -config ...` prints the `ecdsa-sha2-nistp256` public key
for targets. Every certificate is one `kms:Sign` call through the AWS CLI, so
each tool call costs one KMS round trip plus the CLI's start-up time. KMS
signing quotas apply. It has not yet been measured against real KMS.

### AWS

Attach [`deploy/iam-server-role.json`](../deploy/iam-server-role.json) to the
server's instance role. It allows `ssm:StartSession` only with the
`AWS-StartSSHSession` document (`ssm:SessionDocumentAccessCheck`) and only on
instances tagged `ssh-mcp=enabled`. It grants no `ssm:SendCommand`. Without a
NAT route, add VPC endpoints for `ssm`, `ssmmessages` and `ec2messages`.

## Targets

Requirements: systemd Linux with OpenSSH 8.2+. Every pull request runs the
full end-to-end attack suite against these targets:

| Target | OpenSSH |
|---|---|
| Ubuntu 22.04 | 8.9 |
| Ubuntu 24.04 | 9.6 |
| Ubuntu 26.04 | 10.2 |
| Debian 12 | 9.2 |
| Amazon Linux 2023 | 9.9 |

Ubuntu 20.04 and Debian 11 also meet the requirements but are not in CI.
Amazon Linux 2 (OpenSSH 7.4) is refused. Run once, as root (for example
through SSM Run Command):

```sh
CA_PUBKEY="$(cat ssh-mcp-ca.pub)" \
HELPER_URL=https://github.com/nguyencongnamit/ssh-mcp/releases/download/v0.1.0/ssh-mcp-helper-linux-amd64 \
HELPER_SHA256=<sha256 from the release SHA256SUMS> \
  ./deploy/bootstrap-target.sh          # or HELPER_SRC=/path/to/ssh-mcp-helper
```

The script creates `agent-ro` and `agent-sftp` (no sudo, password `*`), adds a
`Match User`-scoped sshd drop-in (forced helper, `ExposeAuthInfo`,
`TrustedUserCAKeys`, principals file), validates with `sshd -t` and rolls back
on failure. Existing corporate SSH CA settings for other users are untouched.
Then tag the instance `ssh-mcp=enabled` and add `<instance-id> <host key>` to
the server's `known_hosts`.

Remove with `deploy/remove-target.sh`; untagging alone cuts access at the IAM
layer.

### OpenSSH 9.8+ source penalties

OpenSSH 9.8 and later (Amazon Linux 2023 ships 9.9, Ubuntu 26.04 ships 10.2) penalise a source address
after failed logins or crashes (`PerSourcePenalties`, on by default). Every
call from ssh-mcp comes from one address, so a burst of failures, such as a
rotated CA not yet rolled out to a host, can block all agents from that host
for a while. Over SSM the source is the host's own loopback. If you see
`drop connection ... penalty` in the target's sshd log, exempt the ssh-mcp
source rather than turning penalties off:

```
# /etc/ssh/sshd_config.d/40-ssh-mcp-penalties.conf
PerSourcePenaltyExemptList 127.0.0.1/32,::1/128   # SSM transport
# PerSourcePenaltyExemptList 10.0.1.10/32         # direct transport: the server's address
```

The exemption covers only that address; every other source is still
penalised.

## Console

Keep `console.listen` on `127.0.0.1` and reach it with SSM port forwarding:

```sh
aws ssm start-session --target <server-instance-id> \
  --document-name AWS-StartPortForwardingSession \
  --parameters portNumber=8444,localPortNumber=8444
```

## Rollout checklist

- [ ] Test bed green (`make test`, `make e2e`) on your build.
- [ ] One staging host, one bot token, staging tag only.
- [ ] Review console refusals and redaction counts for two weeks.
- [ ] Fix permissions on any world-readable secret the pilot surfaces.
- [ ] Widen to all staging, enable OIDC, then production for on-call groups.
