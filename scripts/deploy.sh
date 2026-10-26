#!/usr/bin/env bash
# 编译并部署 lport 到远程服务器（自动识别远端架构，安装/升级为系统服务）。
#
# 用法:
#   scripts/deploy.sh root@host                         # 部署，沿用远端已有配置
#   scripts/deploy.sh root@host --listen 127.0.0.1:8080 # 其余参数传给 lport install
#   scripts/deploy.sh root@host -y --backend nftables   # 非交互安装
#   SKIP_WEB=1 scripts/deploy.sh root@host              # 跳过前端构建
#
# 首次安装且在终端中运行时，会在远端交互询问密码、转发工具、是否注册服务；升级时不询问。
#
# 远端需要: root 权限的 SSH 登录、tar；systemd 或 OpenRC。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${1:-}"
[[ -z "$HOST" || "$HOST" == -* ]] && { sed -n '2,12p' "$0"; exit 2; }
shift
INSTALL_ARGS=("$@")

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2; exit 1; }

SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST")

log "检测 $HOST 的架构"
machine="$("${SSH[@]}" uname -m)" || die "无法连接 $HOST"
case "$machine" in
  x86_64|amd64)   arch=amd64 ;;
  aarch64|arm64)  arch=arm64 ;;
  armv7*|armv8l)  arch=armv7 ;;
  armv6*)         arch=armv6 ;;
  i386|i686)      arch=386 ;;
  *) die "不支持的远端架构: $machine" ;;
esac
log "远端架构 $machine → linux/$arch"

export VERSION="${VERSION:-$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo "dev-$(date +%Y%m%d%H%M)")}"
"$ROOT/scripts/build.sh" "$arch"

pkg="lport-${VERSION}-linux-${arch}"
tarball="$ROOT/release/$pkg.tar.gz"
[[ -f "$tarball" ]] || die "未找到 $tarball"

log "上传 $pkg.tar.gz"
remote_dir="/tmp/lport-deploy"
"${SSH[@]}" "rm -rf $remote_dir && mkdir -p $remote_dir"
scp -q -o BatchMode=yes "$tarball" "$HOST:$remote_dir/"

log "安装 / 升级服务"
# 本地是终端时为远端分配 tty，使 lport install 可以交互提问
TTY=()
[[ -t 0 && -t 1 ]] && TTY=(-t)
# shellcheck disable=SC2029
ssh "${TTY[@]}" -o BatchMode=yes -o ConnectTimeout=10 "$HOST" "set -e; cd $remote_dir && tar -xzf $pkg.tar.gz && ./$pkg/lport install ${INSTALL_ARGS[*]:-} && rm -rf $remote_dir && lport version && lport detect"
log "部署完成"
