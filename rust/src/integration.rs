//! 真实内核上的集成测试，移植自 Go 版 internal/testnet、internal/backend/integration_test.go 与
//! internal/manager/integration_test.go。需要 root、ip、python3，以及 nft / iptables / realm：
//!
//! ```sh
//! cargo test --no-run && sudo target/debug/deps/lport-<hash> --ignored integration --test-threads=1
//! ```
//!
//! 拓扑（网络命名空间）：
//!
//! ```text
//! lpit-client (10.201.0.2) ── veth ── 本机 (10.201.0.1 | 10.200.0.1) ── veth ── lpit-target (10.200.0.2, 10.200.0.3)
//! ```
//!
//! client 模拟外部客户端，流量经本机 PREROUTING → FORWARD → POSTROUTING 到达 target，与真实转发路径一致。
//! target 命名空间不设默认路由，回包只能依赖 MASQUERADE，可以验证 SNAT 是否生效。
//! 缺少工具时打印 `--- SKIP:` 并跳过，CI 中以此判断测试是否真正执行。

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::net::Ipv4Addr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::backend::Backend;
use crate::builtin::Builtin;
use crate::config::Store;
use crate::kernel::{self, CHAIN_FWD, Iptables, Nftables};
use crate::manager::Manager;
use crate::model::Rule;
use crate::probe;
use crate::realm::Realm;
use crate::sysinfo;

const CLIENT_NS: &str = "lpit-client";
const TARGET_NS: &str = "lpit-target";
/// 客户端访问的本机地址
const HOST_CLIENT_SIDE: &str = "10.201.0.1";
const CLIENT_IP: &str = "10.201.0.2";
/// MASQUERADE 后目标看到的源地址
const HOST_TARGET_SIDE: &str = "10.200.0.1";
const TARGET_IP: &str = "10.200.0.2";
/// 用于模拟域名解析结果变化
const TARGET_IP2: &str = "10.200.0.3";
const DOMAIN: &str = "target.lport.test";

fn sh(args: &[&str]) {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("{}: {e}", args.join(" ")));
    assert!(
        out.status.success(),
        "{}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn quiet(args: &[&str]) {
    let _ = Command::new(args[0]).args(&args[1..]).output();
}

fn output(args: &[&str]) -> String {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)
        })
        .unwrap_or_default()
}

/// 缺少 root 或工具时打印跳过原因并返回 false。
fn require(name: &str, bins: &[&str]) -> bool {
    if !sysinfo::is_root() {
        println!("--- SKIP: {name}: 集成测试需要 root");
        return false;
    }
    if let Some(b) = bins.iter().find(|b| sysinfo::look_path(b).is_none()) {
        println!("--- SKIP: {name}: 未安装 {b}");
        return false;
    }
    true
}

const SERVER_SCRIPT: &str = r#"
import socket, threading
def tcp():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 9000)); s.listen(64)
    while True:
        c, a = s.accept()
        try: c.sendall(("lport-it %s %s\n" % (c.getsockname()[0], a[0])).encode())
        finally: c.close()
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, 8, 1)  # IP_PKTINFO：取得报文实际的目的地址
    s.bind(("0.0.0.0", 9001))
    while True:
        d, anc, _, a = s.recvmsg(2048, 256)
        dst = "?"
        for lvl, typ, data in anc:
            if lvl == socket.IPPROTO_IP and typ == 8: dst = socket.inet_ntoa(data[8:12])
        s.sendto(("lport-it %s %s\n" % (dst, a[0])).encode(), a)
threading.Thread(target=udp, daemon=True).start()
print("ready", flush=True)
tcp()
"#;

const CLIENT_SCRIPT: &str = r#"
import socket, sys
proto, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
if proto == "tcp":
    s = socket.create_connection((host, port), timeout=3)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(b"ping", (host, port))
print(s.recv(256).decode().strip())
"#;

/// 测试拓扑，离开作用域时清理。
struct Net {
    server: Child,
    forward_policy: Option<String>,
}

fn teardown() {
    quiet(&["ip", "netns", "del", CLIENT_NS]);
    quiet(&["ip", "netns", "del", TARGET_NS]);
    quiet(&["ip", "link", "del", "lpit-h0"]);
    quiet(&["ip", "link", "del", "lpit-h1"]);
}

impl Net {
    /// 创建拓扑并在 target 中启动 TCP/UDP 服务；forward_drop 时把 filter FORWARD 默认策略设为 DROP（模拟 Docker）。
    fn setup(forward_drop: bool) -> Net {
        teardown();
        sh(&["ip", "netns", "add", TARGET_NS]);
        sh(&["ip", "netns", "add", CLIENT_NS]);
        sh(&[
            "ip", "link", "add", "lpit-h0", "type", "veth", "peer", "name", "lpit-t0",
        ]);
        sh(&["ip", "link", "set", "lpit-t0", "netns", TARGET_NS]);
        sh(&[
            "ip",
            "addr",
            "add",
            &format!("{HOST_TARGET_SIDE}/24"),
            "dev",
            "lpit-h0",
        ]);
        sh(&["ip", "link", "set", "lpit-h0", "up"]);
        sh(&[
            "ip",
            "-n",
            TARGET_NS,
            "addr",
            "add",
            &format!("{TARGET_IP}/24"),
            "dev",
            "lpit-t0",
        ]);
        sh(&[
            "ip",
            "-n",
            TARGET_NS,
            "addr",
            "add",
            &format!("{TARGET_IP2}/24"),
            "dev",
            "lpit-t0",
        ]);
        sh(&["ip", "-n", TARGET_NS, "link", "set", "lpit-t0", "up"]);
        sh(&["ip", "-n", TARGET_NS, "link", "set", "lo", "up"]);
        sh(&[
            "ip", "link", "add", "lpit-h1", "type", "veth", "peer", "name", "lpit-c0",
        ]);
        sh(&["ip", "link", "set", "lpit-c0", "netns", CLIENT_NS]);
        sh(&[
            "ip",
            "addr",
            "add",
            &format!("{HOST_CLIENT_SIDE}/24"),
            "dev",
            "lpit-h1",
        ]);
        sh(&["ip", "link", "set", "lpit-h1", "up"]);
        sh(&[
            "ip",
            "-n",
            CLIENT_NS,
            "addr",
            "add",
            &format!("{CLIENT_IP}/24"),
            "dev",
            "lpit-c0",
        ]);
        sh(&["ip", "-n", CLIENT_NS, "link", "set", "lpit-c0", "up"]);
        sh(&["ip", "-n", CLIENT_NS, "link", "set", "lo", "up"]);
        sh(&[
            "ip",
            "-n",
            CLIENT_NS,
            "route",
            "add",
            "default",
            "via",
            HOST_CLIENT_SIDE,
        ]);

        let mut server = Command::new("ip")
            .args([
                "netns",
                "exec",
                TARGET_NS,
                "python3",
                "-u",
                "-c",
                SERVER_SCRIPT,
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(server.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(line.starts_with("ready"), "target 服务启动失败: {line:?}");

        let mut net = Net {
            server,
            forward_policy: None,
        };
        if forward_drop {
            let old = if output(&["iptables", "-w", "-S", "FORWARD"]).contains("-P FORWARD DROP") {
                "DROP"
            } else {
                "ACCEPT"
            };
            sh(&["iptables", "-w", "-P", "FORWARD", "DROP"]);
            net.forward_policy = Some(old.into());
        }
        net
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        if let Some(p) = &self.forward_policy {
            quiet(&["iptables", "-w", "-P", "FORWARD", p]);
        }
        let _ = self.server.kill();
        let _ = self.server.wait();
        teardown();
    }
}

/// 在 client 命名空间中连接 host:port；host 不是本机地址时流量途经本机转发（本机作为网关）。
fn from_client_to(proto: &str, host: &str, port: u16) -> Result<String, String> {
    let mut child = Command::new("ip")
        .args([
            "netns",
            "exec",
            CLIENT_NS,
            "python3",
            "-c",
            CLIENT_SCRIPT,
            proto,
            host,
            &port.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(6);
    while child.try_wait().map_err(|e| e.to_string())?.is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("超时".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    if child.wait().unwrap().success() {
        Ok(out.trim().into())
    } else {
        Err(err.trim().lines().last().unwrap_or("").into())
    }
}

/// 在 client 命名空间中连接本机:port，返回 target 的应答（"lport-it <目标地址> <源地址>"）。
fn from_client(proto: &str, port: u16) -> Result<String, String> {
    from_client_to(proto, HOST_CLIENT_SIDE, port)
}

/// 在本机连接 addr（经 OUTPUT 链），返回 TCP 应答。
fn from_host(addr: &str) -> Result<String, String> {
    let mut c =
        std::net::TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(3))
            .map_err(|e| e.to_string())?;
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut b = [0u8; 256];
    let n = c.read(&mut b).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&b[..n]).trim().into())
}

fn reply(target: &str, source: &str) -> String {
    format!("lport-it {target} {source}")
}

/// 收集失败项，测试结束时统一报告（与 Go 的 t.Errorf 一样不在第一处失败就中止）。
#[derive(Default)]
struct Errors(Vec<String>);

impl Errors {
    fn reply(&mut self, what: &str, got: Result<String, String>, want: &str) {
        match got {
            Err(e) => self.0.push(format!("{what}: 连接失败: {e}")),
            Ok(g) if g != want => self.0.push(format!("{what}: 应答 {g:?}，期望 {want:?}")),
            _ => {}
        }
    }

    fn fail(&mut self, what: &str, got: Result<String, String>) {
        if let Ok(g) = got {
            self.0.push(format!("{what}: 期望失败，实际收到 {g:?}"));
        }
    }

    fn check(self, name: &str) {
        assert!(self.0.is_empty(), "{name}:\n  {}", self.0.join("\n  "));
    }
}

fn stub_dns(ip: &str) {
    let ip: Ipv4Addr = ip.parse().unwrap();
    *kernel::DNS_STUB.lock().unwrap() = Some(HashMap::from([(DOMAIN.to_string(), vec![ip])]));
}

fn it_rules() -> Vec<Rule> {
    let r = |id: &str, proto: &str, port, target: String, enabled| Rule {
        id: id.into(),
        name: id.into(),
        proto: proto.into(),
        listen_port: port,
        target,
        enabled,
        ..Default::default()
    };
    vec![
        r("tcp", "tcp", 18080, format!("{TARGET_IP}:9000"), true),
        r("udp", "udp", 18081, format!("{TARGET_IP}:9001"), true),
        r("dns", "tcp", 18082, format!("{DOMAIN}:9000"), true),
        r("both", "both", 18083, format!("{TARGET_IP}:9000"), true),
        r("off", "tcp", 18084, format!("{TARGET_IP}:9000"), false),
    ]
}

/// 等待 realm 进程开始监听测试端口（内置转发在 sync 返回时已在监听）。
fn wait_listen(b: &Backend) {
    if !matches!(b, Backend::Realm(_)) {
        return;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if output(&["ss", "-lnt"]).contains(":18080 ")
            && output(&["ss", "-lnu"]).contains(":18081 ")
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{} 未能启动监听", b.name());
}

/// 在真实内核上验证各后端：外部客户端经 PREROUTING/FORWARD（FORWARD 默认 DROP，模拟 Docker）访问、
/// 本机经 OUTPUT 访问、UDP、双协议、域名目标、途经转发的流量不被劫持、DNS 变化后自动更新、
/// 规则（FORWARD 放行、NAT 表 / 链）被外部清除后自动修复与清理。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "需要 root，见模块说明"]
async fn integration_backends() {
    if !require("integration_backends", &["ip", "python3", "iptables", "ss"]) {
        return;
    }
    let _net = Net::setup(true);
    type Case = (&'static str, &'static str, fn() -> Backend);
    let cases: Vec<Case> = vec![
        ("nftables-map", "nft", || {
            Backend::Nftables(Nftables::default())
        }),
        ("nftables-linear", "nft", || {
            Backend::Nftables(Nftables::linear())
        }),
        ("iptables", "iptables", || {
            Backend::Iptables(Iptables::default())
        }),
        ("builtin", "", || Backend::Builtin(Builtin::new())),
        ("realm", "realm", || Backend::Realm(Realm::new())),
    ];
    for (name, tool, new) in cases {
        if !tool.is_empty() && !require(name, &[tool]) {
            continue;
        }
        println!("=== RUN {name}");
        stub_dns(TARGET_IP);
        let mut b = new();
        let kernel = b.is_kernel();
        let mut rules = it_rules();
        if !kernel {
            rules.truncate(2); // 用户态后端自行解析域名，不受 stub_dns 影响；其余场景已由内核后端覆盖
        }
        let mut e = Errors::default();
        if let Err(err) = b.sync(&rules).await {
            let _ = b.cleanup().await;
            panic!("{name}: sync: {err}");
        }
        if let Backend::Nftables(_) = b {
            println!("    nftables 模式: {}", b.mode());
        }
        wait_listen(&b);

        let via_host = reply(TARGET_IP, HOST_TARGET_SIDE);
        e.reply("外部客户端 TCP", from_client("tcp", 18080), &via_host);
        e.reply("外部客户端 UDP", from_client("udp", 18081), &via_host);
        e.reply(
            "本机经 OUTPUT",
            from_host(&format!("{HOST_CLIENT_SIDE}:18080")),
            &via_host,
        );
        if kernel {
            e.reply("域名目标", from_client("tcp", 18082), &via_host);
            e.reply("both 规则 TCP", from_client("tcp", 18083), &via_host);
            e.fail("停用规则", from_client("tcp", 18084));
            // 本机兼作网关时，途经本机发往其它主机同端口的流量不能被 DNAT 劫持
            e.fail("途经转发的流量", from_client_to("tcp", TARGET_IP, 18080));
            let st = b.status().remove("dns").unwrap_or_default();
            if st.state != "applied" || !st.message.contains(TARGET_IP) {
                e.0.push(format!("域名规则状态: {st:?}"));
            }

            // 域名解析结果变化 → maintain 重新应用
            stub_dns(TARGET_IP2);
            b.maintain().await.unwrap().unwrap();
            e.reply(
                "DNS 变化后",
                from_client("tcp", 18082),
                &reply(TARGET_IP2, HOST_TARGET_SIDE),
            );

            // FORWARD 放行规则被外部清除（如防火墙重载）→ 转发失败 → maintain 自动修复
            match b {
                Backend::Nftables(_) => kernel::remove_forward_accept().await.unwrap(),
                _ => quiet(&["iptables", "-w", "-D", "FORWARD", "-j", CHAIN_FWD]),
            }
            e.fail("FORWARD 放行被清除后", from_client("tcp", 18080));
            b.maintain().await.unwrap().unwrap();
            e.reply("maintain 修复后", from_client("tcp", 18080), &via_host);

            // NAT 表 / 自有链被外部删除或清空（如 nft flush ruleset、防火墙重载）→ maintain 全量重建
            match b {
                Backend::Nftables(_) => quiet(&["nft", "delete", "table", "ip", "lport"]),
                _ => quiet(&["iptables", "-w", "-t", "nat", "-F", "LPORT_PRE"]),
            }
            e.fail("NAT 规则被清除后", from_client("tcp", 18080));
            b.maintain().await.unwrap().unwrap();
            e.reply("NAT 重建后", from_client("tcp", 18080), &via_host);
        }

        // 清理后不再转发，且不留残余
        if let Err(err) = b.cleanup().await {
            e.0.push(format!("cleanup: {err}"));
        }
        e.fail("cleanup 后", from_client("tcp", 18080));
        if output(&["nft", "list", "tables"]).contains("table ip lport") {
            e.0.push("cleanup 后仍有 lport 表".into());
        }
        let fwd = output(&["iptables", "-w", "-S", "FORWARD"]);
        if fwd.contains("lport") || fwd.contains(CHAIN_FWD) {
            e.0.push(format!("cleanup 后 FORWARD 仍有残留: {fwd}"));
        }
        *kernel::DNS_STUB.lock().unwrap() = None;
        e.check(name);
        println!("--- PASS: {name}");
    }
}

/// 在真实转发上验证连通性检测：本机检测经转发路径，目标检测直连；
/// 用户态后端下目标不可达时，本机检测须识别出「接受后立即关闭」而不是误报成功。
/// 同时验证 serve 启动时会清理上次残留的内核规则。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "需要 root，见模块说明"]
async fn integration_probe() {
    if !require("integration_probe", &["ip", "python3", "iptables"]) {
        return;
    }
    let _net = Net::setup(true);
    for (backend, tool) in [
        ("nftables", "nft"),
        ("iptables", "iptables"),
        ("builtin", ""),
        ("realm", "realm"),
    ] {
        if !tool.is_empty() && !require(backend, &[tool]) {
            continue;
        }
        println!("=== RUN probe/{backend}");
        let dir = std::env::temp_dir().join(format!("lport-it-{}", crate::config::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        std::fs::write(
            &path,
            format!(
                "listen: 127.0.0.1:18999
backend: {backend}
admin: {{password: it-password}}
rules:
  - {{id: ok, proto: tcp, listen_port: 18090, target: \"{TARGET_IP}:9000\", enabled: true}}
  - {{id: dead, proto: tcp, listen_port: 18091, target: \"{TARGET_IP}:9999\", enabled: true}}
  - {{id: udp, proto: udp, listen_port: 18092, target: \"{TARGET_IP}:9001\", enabled: true}}
  - {{id: off, proto: tcp, listen_port: 18093, target: \"{TARGET_IP}:9000\", enabled: false}}
"
            ),
        )
        .unwrap();
        // 模拟上次异常退出留下的内核规则：start 时必须先清除
        let mut stale = Backend::new(if backend == "iptables" {
            "nftables"
        } else {
            "iptables"
        })
        .unwrap();
        if stale.available().is_ok() {
            let leftover = vec![Rule {
                id: "stale".into(),
                proto: "tcp".into(),
                listen_port: 18094,
                target: format!("{TARGET_IP}:9000"),
                enabled: true,
                ..Default::default()
            }];
            stale.sync(&leftover).await.unwrap();
        }

        let (store, _) = Store::load(&path).unwrap();
        let m = Arc::new(Manager::new(Arc::new(store)));
        m.start().await;
        let sync_err = m.sync_error().await;
        let mut e = Errors::default();
        if !sync_err.is_empty() {
            m.stop().await;
            panic!("{backend}: 应用规则失败: {sync_err}");
        }
        e.fail("残留规则应在启动时被清除", from_client("tcp", 18094));

        for (id, local, target) in [
            ("ok", probe::STATE_OK, probe::STATE_OK),
            ("dead", probe::STATE_FAIL, probe::STATE_FAIL),
            ("udp", probe::STATE_OK, probe::STATE_OK),
            ("off", probe::STATE_SKIPPED, probe::STATE_OK),
        ] {
            // realm 进程启动需要一点时间，最多等待 5 秒
            let deadline = Instant::now() + Duration::from_secs(5);
            let res = loop {
                let res = m.probe(id).await.unwrap();
                if res.local[0].state == local || Instant::now() > deadline {
                    break res;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            };
            let (l, t) = (&res.local[0], &res.target[0]);
            if l.state != local || t.state != target {
                e.0.push(format!(
                    "规则 {id}: 本机={}({}) 目标={}({})，期望 本机={local} 目标={target}",
                    l.state, l.message, t.state, t.message
                ));
            }
        }
        m.stop().await;
        let _ = std::fs::remove_dir_all(&dir);
        e.check(&format!("probe/{backend}"));
        println!("--- PASS: probe/{backend}");
    }
}
