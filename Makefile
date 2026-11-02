.PHONY: build test e2e lint linux up down
VERSION ?= $(patsubst v%,%,$(shell git describe --tags --always --dirty 2>/dev/null || echo dev))
LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ssh-mcp ./cmd/ssh-mcp
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ssh-mcp-helper ./cmd/ssh-mcp-helper

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/linux-amd64/ssh-mcp ./cmd/ssh-mcp
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/linux-amd64/ssh-mcp-helper ./cmd/ssh-mcp-helper
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/linux-arm64/ssh-mcp ./cmd/ssh-mcp
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/linux-arm64/ssh-mcp-helper ./cmd/ssh-mcp-helper
	cd bin && shasum -a 256 linux-*/* > SHA256SUMS

test:
	gofmt -l . | (! grep .)
	go vet ./...
	go test -race -count=1 ./...

e2e:
	go test -tags e2e -count=1 -v ./testbed/e2e/

up:
	./testbed/up.sh

down:
	cd testbed && docker compose down -v
