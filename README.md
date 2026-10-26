# lport — 端口转发管理工具

单文件部署的 Linux 端口转发管理工具：通过 Web 界面把本机 TCP/UDP 端口转发到其它 `IP:端口`。

- 支持 Alpine / Debian / Ubuntu / CentOS / Rocky / Alma / Fedora
- 三种转发后端（全局选择一种）：**nftables**（推荐）、**iptables**、**socat**；首次启动自动选择可用的最优后端
- 自动检测依赖工具，缺失时显示对应发行版的安装命令，并可在界面一键安装
- 端口冲突检查：规则之间、管理面板端口、系统已占用端口（显示占用进程）
- 配置为单个 YAML 文件，可手动编辑，重启生效
- 用户名密码登录；systemd / OpenRC 服务注册，开机自动恢复规则

## 安装

```sh
# 构建（需要 Go 1.22+ 与 Node 20+）
scripts/build.sh                    # 前端 + 全部架构：amd64 arm64 armv7 armv6 386
scripts/build.sh amd64 arm64        # 只编译指定架构；SKIP_WEB=1 跳过前端，VERSION=v1.0 指定版本
                                    # 产物: release/lport-<版本>-linux-<架构>.tar.gz + sha256sums.txt

# 一键部署到远程服务器（自动识别远端架构，安装或升级为系统服务）
scripts/deploy.sh root@host [--listen 127.0.0.1:8080]

# 在服务器上（root）
./lport detect                              # 查看系统与依赖工具状态
./lport install --listen 0.0.0.0:8080       # 安装到 /usr/local/bin 并注册为服务
```

`lport install` 首次运行时会交互询问：

1. 管理员密码（配置中没有密码时；直接回车随机生成）
2. 默认转发工具 `nftables / iptables / socat [nftables]`（配置中未指定时；所选工具未安装会询问是否安装）
3. 是否注册为系统服务并开机自启（已安装过服务则直接升级并重启，不再询问）

问答完成前不会写入配置，中途 Ctrl-C / Ctrl-D 不留下任何改动。加 `-y` 或在无终端环境（如脚本、管道）中运行时不提问，全部取默认值：随机密码（打印在输出中）、自动选择已安装的最优工具（都没有则安装 nftables）、注册服务。也可用 `--backend` 直接指定工具。

## 命令

| 命令 | 说明 |
|---|---|
| `lport serve [--config PATH] [--listen ADDR]` | 前台运行 Web 服务 |
| `lport install [--config PATH] [--listen ADDR] [--backend NAME] [-y]` | 安装程序并（可选）注册 systemd / OpenRC 服务，交互式询问密码、转发工具 |
| `lport uninstall [--purge]` | 卸载服务，`--purge` 同时删除配置目录 |
| `lport passwd [新密码]` | 重置密码（不填则随机生成），自动重启服务 |
| `lport probe [规则名\|ID\|端口 ...]` | 检测规则连通性（与 Web「连通性」相同），有失败项时退出码为 1 |
| `lport detect` | 检测系统、包管理器、依赖工具 |

## 配置文件

默认 `/etc/lport/config.yaml`：

```yaml
listen: 0.0.0.0:8080
backend: nftables         # nftables | iptables | socat；省略则首次启动自动选择
admin:
  username: admin
  password: ""            # 可填明文密码，启动时自动转为 password_hash 并清空
  password_hash: $2a$10$...
session_secret: ...
rules:
  - id: web01             # 可省略，启动时自动生成
    name: web
    proto: tcp            # tcp | udp | both
    listen_port: 8080
    target: 10.0.0.5:80
    enabled: true
    remark: ""
```

- 手动编辑后执行 `systemctl restart lport`（或 `rc-service lport restart`）生效。
- 启动时会完整校验配置，有错误（端口冲突、协议错误等）会拒绝启动并指出具体规则。
- 服务运行期间在界面中修改会整体写回该文件，**手写的注释会丢失**；建议手动编辑后立即重启。

## 转发后端

| 后端 | 原理 | 说明 |
|---|---|---|
| socat | 每条规则一个 socat 子进程（`both` 为两个），崩溃自动重启 | 可转发到域名与 `127.0.0.1`；用户态转发，性能较低 |
| iptables | nat 表 DNAT + MASQUERADE | 只操作自有链 `LPORT_PRE/OUT/POST/FWD`，不影响已有规则 |
| nftables | 独立表 `table ip lport`，`nft -f` 原子替换；DNAT 通过 map 哈希查找 | 不影响其它表；规则数量增加不影响匹配性能 |

- 首次启动（配置中未写 `backend`）时：以 root 运行则依次选择已安装的 nftables、iptables，否则使用 socat；若已有规则不适用于内核后端（如目标为 127.0.0.1）则跳过该后端。
- nftables 默认使用 map 模式（每个协议一条 `dnat ip addr . port to tcp dport map @fwd_tcp`），需要 nft ≥ 0.9.4、内核 ≥ 5.6；不支持时（如 CentOS 7、Debian 10）自动降级为逐条规则的兼容模式，概览页会显示当前模式。
- 内核后端（iptables/nftables）要求目标为非回环 IPv4 地址，并会自动开启 `net.ipv4.ip_forward`（写入 `/etc/sysctl.d/99-lport.conf`）。
- 服务停止时会清除所有转发；启动时先清理残留再重新应用。
- 如果系统中有其它 nftables 表的 forward 链默认策略为 drop（如 firewalld、Docker），被转发的流量可能仍被拦截，需要在对应防火墙中放行。iptables 后端会把 `LPORT_FWD` 插入 `FORWARD` 链首。

## 开发

```sh
# 终端 1：后端（非 root 时仅 socat 后端与 1024 以上端口可用）
go run ./cmd/lport serve --config ./dev-config.yaml

# 终端 2：前端热更新，/api 代理到 127.0.0.1:8080
cd web && npm install && npm run dev

make test
```

目录结构：`cmd/lport` 入口；`internal/config` YAML 配置；`internal/backend` 三种转发实现；`internal/portcheck` 端口占用检测；`internal/manager` 规则编排；`internal/api` HTTP 接口；`internal/service` 服务注册；`web/` Vite + React + Ant Design 前端（构建后通过 `go:embed` 嵌入）。
