#!/usr/bin/env bash
# lport 编译脚本：构建前端并交叉编译多架构 Linux 静态二进制（musl）。
#
# 用法:
#   scripts/build.sh                      # 编译全部目标
#   scripts/build.sh amd64 arm64          # 只编译指定架构
#   SKIP_WEB=1 scripts/build.sh arm64     # 跳过前端构建（复用 web/dist）
#   VERSION=v1.0.0 scripts/build.sh       # 指定版本号（默认取 git describe 或 dev）
#
# 依赖: rustup、cargo-zigbuild（cargo install cargo-zigbuild）与 zig；构建前端需要 Node.js
# 支持的架构: amd64 arm64 armv7 armv6 386
# 产物: release/lport-<版本>-linux-<架构>.tar.gz 及 release/sha256sums.txt
# 二进制为 musl 静态链接，可直接运行于 Alpine / Debian / Ubuntu / CentOS 等发行版。
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

if [[ "${SKIP_WEB:-0}" != "1" ]]; then
  command -v npm >/dev/null || die "未找到 npm（或设置 SKIP_WEB=1 复用已有 web/dist）"
  log "构建前端"
  # node_modules 含平台相关的原生二进制（typescript、esbuild 等）。共享目录被多台机器使用时，
  # 平台变化或 lockfile 更新后需要重新安装
  platform="$(uname -s)-$(uname -m)"
  stamp=web/node_modules/.lport-platform
  if [[ "$(cat "$stamp" 2>/dev/null)" != "$platform" || web/package-lock.json -nt "$stamp" ]]; then
    log "安装前端依赖（${platform}）"
    (cd web && npm ci)
    echo "$platform" > "$stamp"
  fi
  (cd web && npm run build)
fi
# Web 面板的前端文件在编译时嵌入二进制，发布包必须包含真实前端
[[ -f web/dist/index.html ]] || die "web/dist 不存在，请先构建前端（去掉 SKIP_WEB=1 重新运行）"

if [[ "$(uname -s)" == Linux ]]; then
  log "运行测试"
  cargo test --locked --quiet >/dev/null
else
  log "非 Linux 主机，跳过测试"
fi

mkdir -p "$OUT"
for a in "${ARCHES[@]}"; do
  t="$(target "$a")"
  name="lport-${VERSION}-linux-${a}"
  stage="$OUT/$name"
  log "编译 linux/${a} (${t})"
  rustup target add "$t" >/dev/null
  LPORT_VERSION="$VERSION" cargo zigbuild --release --locked --target "$t"
  rm -rf "$stage" && mkdir -p "$stage"
  cp "target/$t/release/lport" "$stage/lport"
  cp README.md README.zh-CN.md "$stage/"
  tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
  rm -rf "$stage"
done

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$OUT" && sha256 lport-"${VERSION}"-linux-*.tar.gz > sha256sums.txt)
log "完成，产物位于 $OUT:"
ls -lh "$OUT"/lport-"${VERSION}"-linux-*.tar.gz "$OUT/sha256sums.txt"
