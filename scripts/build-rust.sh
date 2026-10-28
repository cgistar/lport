#!/usr/bin/env bash
# lport Rust 版编译脚本：交叉编译多架构 Linux musl 静态二进制（rust/ 目录）。
#
# 用法:
#   scripts/build-rust.sh                 # 编译全部目标
#   scripts/build-rust.sh amd64 arm64     # 只编译指定架构
#   VERSION=v1.0.0 scripts/build-rust.sh  # 指定版本号（默认取 git describe 或 dev）
#
# 依赖: rustup、cargo-zigbuild（cargo install cargo-zigbuild）与 zig
# 支持的架构: amd64 arm64 armv7 armv6 386
# 产物: release/lport-rs-<版本>-linux-<架构>.tar.gz 及 release/sha256sums-rs.txt
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ALL_ARCHES=(amd64 arm64 armv7 armv6 386)
ARCHES=("$@")
[[ ${#ARCHES[@]} -eq 0 ]] && ARCHES=("${ALL_ARCHES[@]}")

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT="$ROOT/release"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2; exit 1; }

command -v cargo >/dev/null || die "未找到 cargo（可通过 rustup 安装）"
cargo zigbuild --help >/dev/null 2>&1 || die "未找到 cargo-zigbuild（cargo install cargo-zigbuild，并安装 zig）"

# 架构名 → Rust target
target() {
  case "$1" in
    amd64) echo x86_64-unknown-linux-musl ;;
    arm64) echo aarch64-unknown-linux-musl ;;
    armv7) echo armv7-unknown-linux-musleabihf ;;
    armv6) echo arm-unknown-linux-musleabihf ;;
    386)   echo i686-unknown-linux-musl ;;
    *) die "不支持的架构: $1（可选: ${ALL_ARCHES[*]}）" ;;
  esac
}
for a in "${ARCHES[@]}"; do target "$a" >/dev/null; done

if [[ "$(uname -s)" == Linux ]]; then
  log "运行测试"
  (cd rust && cargo test --quiet >/dev/null)
else
  log "非 Linux 主机，跳过测试"
fi

mkdir -p "$OUT"
for a in "${ARCHES[@]}"; do
  t="$(target "$a")"
  name="lport-rs-${VERSION}-linux-${a}"
  stage="$OUT/$name"
  log "编译 linux/${a} (${t})"
  rustup target add "$t" >/dev/null
  (cd rust && LPORT_VERSION="$VERSION" cargo zigbuild --release --locked --target "$t")
  rm -rf "$stage" && mkdir -p "$stage"
  cp "rust/target/$t/release/lport" "$stage/lport"
  cp README.md README.zh-CN.md "$stage/"
  tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
  rm -rf "$stage"
done

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$OUT" && sha256 lport-rs-"${VERSION}"-linux-*.tar.gz > sha256sums-rs.txt)
log "完成，产物位于 $OUT:"
ls -lh "$OUT"/lport-rs-*
