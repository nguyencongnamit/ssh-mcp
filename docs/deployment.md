# Deployment

## Server

1. Run it in a private subnet with no inbound internet. Linux with cgroup v2.
2. Install: `ssh-mcp` binary, AWS CLI + `session-manager-plugin` (SSM
   transport), `bwrap`, `sshfs` / `fusermount3`, `prlimit`.
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

### AWS

Attach [`deploy/iam-server-role.json`](../deploy/iam-server-role.json) to the
server's instance role. It allows `ssm:StartSession` only with the
`AWS-StartSSHSession` document (`ssm:SessionDocumentAccessCheck`) and only on
instances tagged `ssh-mcp=enabled`. It grants no `ssm:SendCommand`. Without a
NAT route, add VPC endpoints for `ssm`, `ssmmessages` and `ec2messages`.

## Targets

Requirements: systemd Linux with OpenSSH 8.2+ (for example Amazon Linux 2023,
Ubuntu 20.04+, Debian 11+). The test bed verifies Ubuntu 22.04; other
distributions are expected to work but are not yet covered by CI. Run once,
as root (for example through SSM Run Command):

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
