#!/usr/bin/env bash
# lport 编译脚本：构建前端并交叉编译多架构 Linux 静态二进制。
#
# 用法:
#   scripts/build.sh                      # 编译全部目标
#   scripts/build.sh amd64 arm64          # 只编译指定架构
#   SKIP_WEB=1 scripts/build.sh arm64     # 跳过前端构建（复用 web/dist）
#   VERSION=v1.0.0 scripts/build.sh       # 指定版本号（默认取 git describe 或 dev）
#
# 支持的架构: amd64 arm64 armv7 armv6 386
# 产物: release/lport-<版本>-linux-<架构>.tar.gz 及 release/sha256sums.txt
# 二进制为 CGO_ENABLED=0 静态编译，可直接运行于 Alpine(musl) / Debian / Ubuntu / CentOS 等发行版。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ALL_ARCHES=(amd64 arm64 armv7 armv6 386)
ARCHES=("$@")
[[ ${#ARCHES[@]} -eq 0 ]] && ARCHES=("${ALL_ARCHES[@]}")

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT="$ROOT/release"
LDFLAGS="-s -w -X main.version=${VERSION}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2; exit 1; }

command -v go >/dev/null || die "未找到 go"

# 架构名 → GOARCH / GOARM
goenv() {
  case "$1" in
    amd64) echo "amd64 " ;;
    arm64) echo "arm64 " ;;
    armv7) echo "arm 7" ;;
    armv6) echo "arm 6" ;;
    386)   echo "386 " ;;
    *) die "不支持的架构: $1（可选: ${ALL_ARCHES[*]}）" ;;
  esac
}
for a in "${ARCHES[@]}"; do goenv "$a" >/dev/null; done

if [[ "${SKIP_WEB:-0}" != "1" ]]; then
  command -v npm >/dev/null || die "未找到 npm（或设置 SKIP_WEB=1 复用已有 web/dist）"
  log "构建前端"
  (cd web && { [[ -d node_modules ]] || npm ci; } && npm run build)
fi
[[ -f web/dist/index.html ]] || die "web/dist 不存在，请先构建前端"

log "运行测试"
go test ./... >/dev/null

mkdir -p "$OUT"
for a in "${ARCHES[@]}"; do
  read -r goarch goarm <<<"$(goenv "$a")"
  name="lport-${VERSION}-linux-${a}"
  stage="$OUT/$name"
  log "编译 linux/${a}"
  rm -rf "$stage" && mkdir -p "$stage"
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOARM="$goarm" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$stage/lport" ./cmd/lport
  cp README.md "$stage/"
  tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
  rm -rf "$stage"
done

(cd "$OUT" && sha256sum lport-"${VERSION}"-linux-*.tar.gz > sha256sums.txt)
log "完成，产物位于 $OUT:"
ls -lh "$OUT"
