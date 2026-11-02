#!/usr/bin/env bash
# Rebuild only the ssh-mcp server image, keeping the data volume (audit log,
# tokens) and the existing CA/config.
set -euo pipefail
cd "$(dirname "$0")"
ARCH=$(docker version -f '{{.Server.Arch}}')
(cd .. && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags "-X main.version=${VERSION:-dev}" -o testbed/server/ssh-mcp ./cmd/ssh-mcp)
docker compose build server >/dev/null
docker compose up -d --no-deps --force-recreate server >/dev/null
for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:18471/healthz >/dev/null 2>&1 && break; sleep 1; done
echo "server redeployed"
