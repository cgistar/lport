# lport

English | [简体中文](README.zh-CN.md)

Port forwarding manager for Linux: forward local TCP/UDP ports to any `IP/domain:port` through a web UI or the command line. Ships as a single binary with no other dependencies.

> The web UI and command output are currently in Chinese only.

## Features

- Runs on Alpine / Debian / Ubuntu / CentOS / Rocky / Alma / Fedora, amd64 / arm64 / armv7 / armv6 / 386
- Three forwarding backends: **nftables** (recommended), **iptables**, **socat**; a missing tool can be installed from the UI with one click
- Targets can be IPs or domain names; domains are re-resolved every 60 seconds and rules follow IP changes automatically
- Port conflict checks against other rules, the admin panel, and ports already in use on the system (with the owning process shown)
- Connectivity probe: check in one click whether the local port and the target are reachable, to pinpoint failures quickly
- Works in environments such as Docker hosts that set the FORWARD chain's default policy to DROP
- Configuration is a single, hand-editable YAML file; registers as a systemd / OpenRC service and restores rules on boot

## Installation

Download the archive for your architecture from [Releases](https://github.com/cgistar/lport/releases), extract it, and run as root:

```sh
tar -xzf lport-*-linux-amd64.tar.gz
cd lport-*-linux-amd64
./lport install
```

The installer asks for:

1. The admin password (press Enter to generate a random one)
2. The default forwarding backend `nftables / iptables / socat [nftables]`; it can install the tool if it is missing
3. Whether to register a system service that starts on boot

Non-interactive install: `./lport install -y --backend nftables --listen 0.0.0.0:8080`

When it finishes, open `http://<server-ip>:8080` and log in.

## Usage

### Web UI

- **Overview**: system information, dependency status, and one-click install
- **Rules**: add / edit / enable / disable / delete rules; conflicts are flagged as you type a port; click the connectivity icon to probe (green dot = OK, red dot = failed, click again to re-run)
- **Settings**: switch backend, change password, view ports in use on the system

### Command line

| Command | Description |
|---|---|
| `lport install` | Install or upgrade (an existing install is upgraded and its service restarted) |
| `lport uninstall [--purge]` | Remove the service; `--purge` also deletes the configuration |
| `lport passwd [new-password]` | Reset the admin password (random if omitted) |
| `lport list` | List rules and their status |
| `lport add [--proto tcp\|udp\|both] [--name NAME] PORT TARGET:PORT` | Add a rule, e.g. `lport add 8443 10.0.0.2:443` |
| `lport remove NAME\|ID\|PORT ...` | Delete rules |
| `lport probe [NAME\|PORT ...]` | Probe rule connectivity; exits with status 1 if any check fails |
| `lport detect` | Inspect the system environment and dependencies |
| `lport serve` | Run in the foreground (for debugging) |

Every command accepts `--config` to choose the configuration file (default `/etc/lport/config.yaml`).

`add` / `remove` run the same validation as the web UI (port conflicts, target address, and so on). If the service is running, changes take effect immediately; otherwise they are written to the configuration file and applied when the service starts.

### Configuration file

```yaml
listen: 0.0.0.0:8080      # admin panel address
backend: nftables         # nftables | iptables | socat
admin:
  username: admin
  password: ""            # plain text allowed; converted to password_hash on startup
rules:
  - name: web
    proto: tcp            # tcp | udp | both
    listen_port: 18080
    target: example.com:80
    enabled: true
```

After editing by hand, run `systemctl restart lport` (Alpine: `rc-service lport restart`) to apply.

### Backend comparison

| | nftables | iptables | socat |
|---|---|---|---|
| Performance | Highest (in-kernel, map lookup) | High (in-kernel) | Lower (user space) |
| Target on local 127.0.0.1 | Not supported | Not supported | Supported |
| Best for | Modern systems | Older systems (e.g. CentOS 7) | Forwarding to local ports |

## Building from source

Requires Go and Node.js:

```sh
scripts/build.sh                     # build all architectures into release/
scripts/build.sh amd64 arm64         # build selected architectures only
scripts/deploy.sh root@host          # build and deploy to a remote server
scripts/deploy.sh -p 2222 root@host  # use a custom SSH port
```

Pushing a `v*` tag (e.g. `git tag v1.0.0 && git push origin v1.0.0`) makes GitHub Actions test, build, and publish a release.
