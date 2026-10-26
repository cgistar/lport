VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all web build build-all test dev clean

all: web build

web:
	cd web && npm ci && npm run build

build:
	$(GOBUILD) -o bin/lport ./cmd/lport

build-all: web
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o bin/lport-linux-amd64 ./cmd/lport
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o bin/lport-linux-arm64 ./cmd/lport

test:
	go test ./...

# 开发模式：后端监听 8080，前端 vite dev server 代理 /api
dev:
	@echo "终端 1: sudo go run ./cmd/lport serve --config ./dev-config.yaml"
	@echo "终端 2: cd web && npm run dev"

clean:
	rm -rf bin web/dist
