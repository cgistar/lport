# lport

[English](README.md) | 简体中文

Linux 端口转发管理工具：通过 Web 界面把本机 TCP/UDP 端口转发到其它 `IP/域名:端口`。单个二进制文件，无其它依赖。

## 功能

- 支持 Alpine / Debian / Ubuntu / CentOS / Rocky / Alma / Fedora，amd64 / arm64 / armv7 / armv6 / 386
- 三种转发方式：**nftables**（推荐）、**iptables**、**socat**；缺少时可在界面一键安装
- 目标支持 IP 或域名，域名每 60 秒重新解析，IP 变化自动更新
- 端口冲突检查：规则之间、管理面板、系统已占用端口（显示占用进程）
- 连通性检测：一键检测本机端口与目标端口是否可达，快速定位故障
- 兼容 Docker 等将 FORWARD 默认策略设为 DROP 的环境
- Web 界面支持中文与英文（顶栏切换）；命令行输出目前仅中文
- 配置为单个 YAML 文件，可手动编辑；注册为 systemd / OpenRC 服务，开机自动恢复

## 安装

从 [Releases](https://github.com/cgistar/lport/releases) 下载对应架构的压缩包，解压后以 root 运行：

```sh
tar -xzf lport-*-linux-amd64.tar.gz
cd lport-*-linux-amd64
./lport install
```

安装过程会询问：

1. 管理员密码（直接回车随机生成）
2. 默认转发工具 `nftables / iptables / socat [nftables]`，未安装时可自动安装
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
backend: nftables         # nftables | iptables | socat
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

| | nftables | iptables | socat |
|---|---|---|---|
| 性能 | 最高（内核转发，map 查找） | 高（内核转发） | 较低（用户态） |
| 目标为本机 127.0.0.1 | 不支持 | 不支持 | 支持 |
| 适用 | 新系统首选 | 老系统（如 CentOS 7） | 转发到本机端口 |

## 从源码构建

需要 Go 与 Node.js：

```sh
scripts/build.sh                # 编译全部架构到 release/
scripts/build.sh amd64 arm64    # 只编译指定架构
scripts/deploy.sh root@host     # 编译并部署到远程服务器
scripts/deploy.sh -p 2222 root@host  # 指定 SSH 端口
```

推送 `v*` tag（如 `git tag v1.0.0 && git push origin v1.0.0`）会由 GitHub Actions 自动测试、编译并发布 Release。
