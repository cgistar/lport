VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)

.PHONY: all web build build-all test lint dev clean

all: web build

web:
	cd web && npm ci && npm run build

# 本机编译（前端需先构建，否则面板显示占位页）
build:
	LPORT_VERSION=$(VERSION) cargo build --release
	@echo "产物: target/release/lport"

# 交叉编译全部架构到 release/（需 cargo-zigbuild 与 zig）
build-all:
	VERSION=$(VERSION) scripts/build.sh

test:
	cargo test

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

# 开发模式：后端监听 8080，前端 vite dev server 代理 /api
dev:
	@echo "终端 1: sudo cargo run -- serve --config ./dev-config.yaml"
	@echo "终端 2: cd web && npm run dev"

clean:
	cargo clean
	rm -rf web/dist release
