#!/bin/sh
# lport 一键安装 / 升级脚本，在服务器上以 root 运行:
#
#   curl -fsSL https://raw.githubusercontent.com/cgistar/lport/main/scripts/install.sh | sh
#   wget -qO- https://raw.githubusercontent.com/cgistar/lport/main/scripts/install.sh | sh
#
# 首次安装：内置转发（builtin）、管理面板监听 0.0.0.0:8080、随机生成管理员密码，注册系统服务并开机自启。
# 已安装时：升级程序并重启服务，保留原有配置（后端、监听地址、密码与规则均不变）。
#
# 可用环境变量覆盖默认值（仅首次安装生效的项已注明）:
#   LPORT_VERSION=v0.2.0      指定版本（默认最新版）
#   LPORT_LISTEN=0.0.0.0:8080 管理面板监听地址（仅首次安装）
#   LPORT_BACKEND=builtin     转发后端 builtin | realm | nftables | iptables（仅首次安装）
#   LPORT_IMPL=go             go（默认）| rs：安装 Rust 版（内存占用更低，功能与配置均与 Go 版相同）
#
# 例: curl -fsSL .../install.sh | LPORT_LISTEN=127.0.0.1:8080 sh
#
# 只依赖 POSIX sh、tar、sha256sum 与 curl / wget 之一，可运行于 Alpine（busybox）/ Debian / Ubuntu / CentOS 等。
set -eu

REPO="cgistar/lport"
CONFIG="/etc/lport/config.yaml"
LISTEN="${LPORT_LISTEN:-0.0.0.0:8080}"
BACKEND="${LPORT_BACKEND:-builtin}"
VERSION="${LPORT_VERSION:-}"
IMPL="${LPORT_IMPL:-go}"

if [ -t 1 ]; then
  C_BLUE='\033[1;34m' C_GREEN='\033[1;32m' C_YELLOW='\033[1;33m' C_RED='\033[1;31m' C_OFF='\033[0m'
else
  C_BLUE='' C_GREEN='' C_YELLOW='' C_RED='' C_OFF=''
fi
log() { printf "${C_BLUE}==>${C_OFF} %s\n" "$*"; }
warn() { printf "${C_YELLOW}注意:${C_OFF} %s\n" "$*"; }
die() {
  printf "${C_RED}错误:${C_OFF} %s\n" "$*" >&2
  exit 1
}

[ "$(id -u)" = 0 ] || die "请以 root 运行（例如: curl -fsSL ... | sudo sh）"
[ "$(uname -s)" = Linux ] || die "仅支持 Linux"
case "$IMPL" in
  go) PREFIX=lport SUMS=sha256sums.txt ;;
  rs) PREFIX=lport-rs SUMS=sha256sums-rs.txt ;;
  *) die "LPORT_IMPL 必须是 go 或 rs" ;;
esac
for c in tar sha256sum; do
  command -v "$c" >/dev/null 2>&1 || die "缺少命令 $c"
done

# fetch URL DEST：下载到文件；DEST 为 - 时输出到标准输出
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1"; }
  # 短超时取一段文本，失败返回空
  peek() { curl -fsS --max-time 5 "$1" 2>/dev/null || true; }
  # 跟随跳转后的最终地址，用于从 releases/latest 解析出版本号
  final_url() { curl -fsSL --connect-timeout 15 -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
  peek() { wget -qO- -T 5 "$1" 2>/dev/null || true; }
  final_url() { wget -S --spider "$1" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1 | tr -d '\r'; }
else
  die "需要 curl 或 wget"
fi

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  armv7* | armv8l) ARCH=armv7 ;;
  armv6*) ARCH=armv6 ;;
  i386 | i686) ARCH=386 ;;
  *) die "不支持的架构: $(uname -m)" ;;
esac

if [ -z "$VERSION" ]; then
  log "查询最新版本"
  VERSION="$(final_url "https://github.com/$REPO/releases/latest" | sed -n 's#.*/tag/##p')"
  [ -n "$VERSION" ] || die "无法获取最新版本，可通过 LPORT_VERSION=v0.2.0 指定"
fi

PKG="${PREFIX}-${VERSION}-linux-${ARCH}"
BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

log "下载 $PREFIX $VERSION（linux/$ARCH）"
fetch "$BASE/$PKG.tar.gz" "$TMP/$PKG.tar.gz" || die "下载 $PKG.tar.gz 失败"
fetch "$BASE/$SUMS" "$TMP/$SUMS" || die "下载 $SUMS 失败"

log "校验文件完整性"
grep " $PKG.tar.gz\$" "$TMP/$SUMS" >"$TMP/sum.txt" || die "$SUMS 中没有 $PKG.tar.gz"
(cd "$TMP" && sha256sum -c sum.txt >/dev/null 2>&1) || die "sha256 校验失败，文件可能已损坏"

tar -xzf "$TMP/$PKG.tar.gz" -C "$TMP"
BIN="$TMP/$PKG/lport"
[ -x "$BIN" ] || die "安装包中缺少 lport"

# lport install 的输出先写入文件：失败时完整展示，成功时从中取出随机生成的密码放进最后的提示
if [ -f "$CONFIG" ]; then
  log "检测到已有配置 $CONFIG，升级并保留原有配置"
  FRESH=0
  set -- install -y
else
  log "首次安装（后端 $BACKEND，监听 $LISTEN）"
  FRESH=1
  set -- install -y --backend "$BACKEND" --listen "$LISTEN"
fi
if ! "$BIN" "$@" >"$TMP/install.log" 2>&1; then
  cat "$TMP/install.log" >&2
  die "lport install 失败"
fi
PASSWORD="$(sed -n 's/^ *密码: *\([^（ ]*\).*/\1/p' "$TMP/install.log" | head -n 1)"
USERNAME="$(sed -n 's/^ *用户名: *//p' "$TMP/install.log" | head -n 1)"
grep -E '未注册服务|警告|跳过' "$TMP/install.log" || true

# 面板访问地址：以配置中实际生效的监听地址为准（升级时沿用旧配置）
CUR="$(sed -n 's/^listen: *//p' "$CONFIG" | tr -d "\"'" | head -n 1)"
[ -n "$CUR" ] || CUR="$LISTEN"
PORT="${CUR##*:}"
HOST="${CUR%:*}"
PUBLIC=0
if [ "$HOST" = 0.0.0.0 ] || [ -z "$HOST" ]; then
  # 云服务器的出口 IP 往往是内网地址，优先查询公网 IP，查不到时用本机出口 IP
  HOST="$(peek https://api.ipify.org | grep -E '^[0-9]+(\.[0-9]+){3}$' || true)"
  [ -n "$HOST" ] || HOST="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
  [ -n "$HOST" ] || HOST="<服务器IP>"
  PUBLIC=1
fi

printf "\n${C_GREEN}%s %s 安装完成${C_OFF}\n\n" "$PREFIX" "$VERSION"
printf "  管理面板: http://%s:%s\n" "$HOST" "$PORT"
printf "  用户名:   %s\n" "${USERNAME:-admin}"
if [ -n "$PASSWORD" ]; then
  printf "  密码:     ${C_YELLOW}%s${C_OFF}（随机生成，请登录后修改，或执行 lport passwd 重置）\n" "$PASSWORD"
elif [ "$FRESH" = 0 ]; then
  echo "  密码:     沿用原密码（忘记可执行 lport passwd 重置）"
fi
printf "  转发后端: %s\n" "$(sed -n 's/^backend: *//p' "$CONFIG" | head -n 1)"
printf "  配置文件: %s\n\n" "$CONFIG"
if [ "$PUBLIC" = 1 ]; then
  if [ "$FRESH" = 1 ]; then
    warn "面板对外开放，请确认云服务器安全组 / 防火墙已放行 TCP $PORT，并尽快修改密码"
  else
    warn "面板对外开放，请确认云服务器安全组 / 防火墙已放行 TCP $PORT"
  fi
fi
echo "  常用命令: lport list | lport add 8443 10.0.0.2:443 | lport restart（不带参数运行 lport 查看全部命令）"
