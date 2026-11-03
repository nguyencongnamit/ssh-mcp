#!/usr/bin/env bash
# Build and start the local test bed, then mint test tokens.
set -euo pipefail
cd "$(dirname "$0")"
ARCH=$(docker version -f '{{.Server.Arch}}')
echo "==> building linux/$ARCH binaries"
(cd .. && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -o testbed/target/ssh-mcp-helper ./cmd/ssh-mcp-helper \
       && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags "-X main.version=${VERSION:-dev}" -o testbed/server/ssh-mcp ./cmd/ssh-mcp)

rm -rf server/etc state && mkdir -p server/etc state
cp etc-template/* server/etc/
cp ../deploy/bootstrap-target.sh target/
go run ../cmd/ssh-mcp audit keygen -out server/etc/audit.key
CONSOLE_PW=$(openssl rand -base64 18)
echo "$CONSOLE_PW" > state/console.password
HASH=$(echo "$CONSOLE_PW" | go run ../cmd/ssh-mcp console passwd 2>/dev/null)
printf 'console:\n  listen: 0.0.0.0:8444\n  user: admin\n  timezone: UTC\n  password_hash: "%s"\n' "$HASH" >> server/etc/ssh-mcp.yaml
echo "==> creating test CA"
go run ../cmd/ssh-mcp ca init -key server/etc/ca_key > target/ssh-mcp-ca.pub

echo "==> creating jump-host key"
ssh-keygen -q -t ed25519 -N '' -C ssh-mcp-jump -f server/etc/jump_key
cp server/etc/jump_key.pub bastion/authorized_keys && rm server/etc/jump_key.pub

echo "==> resetting this project's containers and volume"
docker compose down -v --remove-orphans >/dev/null 2>&1 || true

echo "==> building target"
docker compose build target
HOSTKEY=$(docker compose run --rm --no-deps target cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1" "$2}')
{ echo "web-1 $HOSTKEY"; echo "db-1 $HOSTKEY"; echo "web-2 $HOSTKEY"; } > server/etc/known_hosts

echo "==> building bastion"
docker compose build bastion
JUMPKEY=$(docker compose run --rm --no-deps bastion cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1" "$2}')
echo "bastion $JUMPKEY" > server/etc/jump_known_hosts

echo "==> building server and starting"
docker compose build server
docker compose up -d --force-recreate
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:18471/healthz >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:18471/healthz

echo "==> minting test tokens"
for b in ops-bot log-bot stranger; do
  docker compose exec -T server ssh-mcp token create -config /etc/ssh-mcp/ssh-mcp.yaml -name "$b" -owner testbed -ttl 24h > "state/$b.token"
  [ -s "state/$b.token" ] || { echo "token $b not created" >&2; exit 1; }
done
echo "==> ready. Run: go test -tags e2e -count=1 ./testbed/e2e/"
echo "==> console: http://127.0.0.1:18473  user admin  password: $(cat state/console.password)"
