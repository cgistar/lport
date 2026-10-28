# lport

[English](README.md) | 简体中文

Linux 端口转发管理工具：通过 Web 界面把本机 TCP/UDP 端口转发到其它 `IP/域名:端口`。单个二进制文件，无其它依赖。

## 功能

- 支持 Alpine / Debian / Ubuntu / CentOS / Rocky / Alma / Fedora，amd64 / arm64 / armv7 / armv6 / 386
- 四种转发方式：**nftables**（推荐）、**iptables**、**realm**、**builtin**（lport 自身转发，无任何依赖）；缺少时可在界面一键安装（realm 从 GitHub Releases 下载到 `/usr/local/bin`）
- 目标支持 IP 或域名，域名每 60 秒重新解析，IP 变化自动更新
- 端口冲突检查：规则之间、管理面板、系统已占用端口（显示占用进程）
- 连通性检测：一键检测本机端口与目标端口是否可达，快速定位故障
- 兼容 Docker 等将 FORWARD 默认策略设为 DROP 的环境
- Web 界面支持中文与英文（顶栏切换）；命令行输出目前仅中文
- 配置为单个 YAML 文件，可手动编辑；注册为 systemd / OpenRC 服务，开机自动恢复

## 安装

### 一键安装（推荐）

在服务器上以 root 运行：

```sh
curl -fsSL https://raw.githubusercontent.com/cgistar/lport/main/scripts/install.sh | sh
# 没有 curl 时（如 Alpine）：
wget -qO- https://raw.githubusercontent.com/cgistar/lport/main/scripts/install.sh | sh
```

脚本会识别架构、下载最新版并校验 sha256，然后安装为系统服务。首次安装使用内置转发（builtin）、管理面板监听 `0.0.0.0:8080`、随机生成管理员密码，完成后会提示面板地址和密码。已安装时只升级程序，保留原有配置。

可用环境变量修改默认值（`LPORT_LISTEN`、`LPORT_BACKEND` 仅首次安装生效）：

```sh
curl -fsSL https://raw.githubusercontent.com/cgistar/lport/main/scripts/install.sh | LPORT_LISTEN=127.0.0.1:8080 LPORT_BACKEND=nftables sh
```

`LPORT_VERSION=v0.2.0` 可安装指定版本。

### 手动安装

从 [Releases](https://github.com/cgistar/lport/releases) 下载对应架构的压缩包，解压后以 root 运行：

```sh
tar -xzf lport-*-linux-amd64.tar.gz
cd lport-*-linux-amd64
./lport install
```

安装过程会询问：

1. 管理员密码（直接回车随机生成）
2. 默认转发工具 `nftables / iptables / realm / builtin [nftables]`，未安装时可自动安装
3. 是否注册为系统服务并开机自启

非交互安装：`./lport install -y --backend nftables --listen 0.0.0.0:8080`

安装完成后访问 `http://服务器IP:8080` 登录管理。

## 使用

### Web 界面

- **概览**：系统信息、依赖工具状态与一键安装
- **转发规则**：新增 / 编辑 / 启停 / 删除规则；输入端口时实时提示冲突；点击「连通性」图标检测，绿点成功、红点失败，再次点击重新检测
- **设置**：切换转发工具、修改密码、查看系统已占用端口

### 命令行

| 命令 | 说明 |
|---|---|
| `lport install` | 安装或升级（已安装时直接升级并重启服务） |
| `lport uninstall [--purge]` | 卸载服务，`--purge` 同时删除配置 |
| `lport start` / `stop` / `restart` | 启动 / 停止 / 重启已安装的系统服务 |
| `lport passwd [新密码]` | 重置管理员密码（不填则随机生成） |
| `lport list` | 列出转发规则及运行状态 |
| `lport add [--proto tcp\|udp\|both] [--name 名称] 端口 目标:端口` | 添加转发规则，如 `lport add 8443 10.0.0.2:443` |
| `lport edit [--port 端口] [--target 目标:端口] [--proto ...] [--name 名称] [--enable\|--disable] 规则名\|ID\|端口` | 修改转发规则，只改指定的项，如 `lport edit --port 9443 8443` |
| `lport remove 规则名\|ID\|端口 ...` | 删除转发规则 |
| `lport probe [规则名\|端口 ...]` | 命令行检测规则连通性，有失败时退出码为 1 |
| `lport detect` | 检测系统环境与依赖工具 |
| `lport serve` | 前台运行（调试用） |

所有命令都支持 `--config` 指定配置文件，默认 `/etc/lport/config.yaml`。

`add` / `remove` 与 Web 界面使用相同的校验（端口冲突、目标地址等）：服务运行中时立即生效，否则写入配置文件，服务启动后生效。

### 配置文件

```yaml
listen: 0.0.0.0:8080      # 管理面板地址
backend: nftables         # nftables | iptables | realm | builtin
admin:
  username: admin
  password: ""            # 可填明文，启动时自动转为 password_hash
rules:
  - name: web
    proto: tcp            # tcp | udp | both
    listen_port: 18080
    target: example.com:80
    enabled: true
```

手动修改后执行 `systemctl restart lport`（Alpine：`rc-service lport restart`）生效。

### 反向代理

面板可以部署在站点根路径或子路径下。以 nginx 挂在 `/lport/`、lport 监听 `127.0.0.1:8080` 为例：

```nginx
location = /lport { return 301 /lport/; }
location ^~ /lport/ {                       # ^~ 避免 .js/.css 等正则 location 抢先匹配
    proxy_pass http://127.0.0.1:8080/;      # 末尾的 / 会去掉 /lport 前缀
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 300s;                # 在概览页安装依赖可能耗时较长
}
```

lport 只信任来自回环地址（即同机代理）的 `X-Forwarded-For`（用于登录失败限制）与 `X-Forwarded-Proto`（用于给会话 Cookie 加 `Secure`）。建议面板只监听 `127.0.0.1`，仅通过代理访问。

### 转发工具对比

| | nftables | iptables | realm | builtin |
|---|---|---|---|---|
| 性能 | 最高（内核转发，map 查找） | 高（内核转发） | 中（用户态，Rust 异步） | 中（用户态，Rust 异步，splice 零拷贝） |
| 目标为本机 127.0.0.1 | 不支持 | 不支持 | 支持 | 支持 |
| 依赖 | nftables | iptables | realm（自动下载） | 无 |
| 适用 | 新系统首选 | 老系统（如 CentOS 7） | 本机端口，或无法使用内核 NAT 时 | 非 root 运行，或无法安装任何工具时 |

socat 后端已移除；配置为 `backend: socat` 时，启动后会自动改为 `builtin`。

## 从源码构建

需要 Rust（rustup）与 Node.js；交叉编译还需要 [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) 与 zig：

```sh
scripts/build.sh                # 构建前端并交叉编译全部架构到 release/
scripts/build.sh amd64 arm64    # 只编译指定架构
scripts/deploy.sh root@host     # 编译并部署到远程服务器
scripts/deploy.sh -p 2222 root@host  # 指定 SSH 端口

cd web && npm ci && npm run build  # 本机开发：先构建前端（编译时嵌入二进制，未构建时面板显示占位页）
cargo build --release              # 产物 target/release/lport
cargo test                         # 单元测试；集成测试需 root，见 src/integration.rs
```

推送 `v*` tag（如 `git tag v1.0.0 && git push origin v1.0.0`）会由 GitHub Actions 自动测试、编译并发布 Release。

### 版本说明

v0.3.0 起 lport 由 Go 改为 Rust 实现，功能、配置文件、命令行、Web 界面与 systemd / OpenRC 服务文件与之前完全相同，直接用一键安装脚本或 `lport install` 升级即可，已登录的会话也保持有效。v0.2.0 及以前的 Go 源码保留在 git 历史中。

- builtin 后端内存占用显著降低：5000 条 TCP 长连接约 15 MiB（Go 版约 87 MiB），4000 个 UDP 会话约 20 MiB（Go 版约 96 MiB），吞吐与延迟相当；nftables / iptables 为内核转发，性能不变
- 二进制约 3 MB（Go 版约 9 MB），服务空闲时内存约 2 MiB
- 下载 realm 时使用系统的 curl 或 wget（不内置 HTTPS 客户端，以保持二进制精简）
