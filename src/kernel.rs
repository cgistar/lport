//! 内核转发后端（nftables / iptables）与域名解析。生成的规则脚本与 Go 版（v0.2.0 及以前）
//! 逐字节一致（testdata/*.golden），升级前后内核规则不变。

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::backend::{RuleStatus, check_tool, enabled, ok, run};
use crate::model::{self, Rule};
use crate::sysinfo;

#[cfg(test)]
pub static DNS_STUB: std::sync::Mutex<Option<HashMap<String, Vec<Ipv4Addr>>>> =
    std::sync::Mutex::new(None);

async fn lookup_ipv4(host: &str) -> std::io::Result<Vec<Ipv4Addr>> {
    #[cfg(test)]
    if let Some(m) = DNS_STUB.lock().unwrap().as_ref() {
        return m
            .get(host)
            .cloned()
            .ok_or_else(|| std::io::Error::other("no such host"));
    }
    let addrs = tokio::net::lookup_host((host, 0)).await?;
    Ok(addrs
        .filter_map(|a| match a.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect())
}

/// 将域名解析为 IPv4；prefer 仍在解析结果中时优先保留，避免 DNS 轮询导致规则反复变化。
pub async fn resolve_host(host: &str, prefer: &str) -> Result<String, String> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(host.to_string());
    }
    let ips = tokio::time::timeout(Duration::from_secs(5), lookup_ipv4(host))
        .await
        .map_err(|_| format!("解析 {host} 失败: 超时"))?
        .map_err(|e| format!("解析 {host} 失败: {e}"))?;
    let usable: Vec<String> = ips
        .iter()
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .map(Ipv4Addr::to_string)
        .collect();
    if let Some(p) = usable.iter().find(|s| *s == prefer) {
        return Ok(p.clone());
    }
    usable
        .into_iter()
        .next()
        .ok_or_else(|| format!("{host} 没有可用的 IPv4 地址（不能是回环地址）"))
}

/// 内核后端的公共状态：域名解析结果与最近一次应用的规则。
#[derive(Default)]
pub struct KernelState {
    /// 最近一次应用的原始规则
    rules: Vec<Rule>,
    /// rule id → 域名解析出的 IPv4
    ips: HashMap<String, String>,
    /// rule id → 解析错误
    errs: HashMap<String, String>,
}

/// 把启用规则中的域名目标替换为 IP；解析失败的规则被跳过并记录错误。
async fn resolve_rules(rules: &[Rule], prev: &HashMap<String, String>) -> (Vec<Rule>, KernelState) {
    // 同一域名只解析一次，不同域名并发解析
    let mut set = tokio::task::JoinSet::new();
    let mut seen = HashSet::new();
    for r in enabled(rules) {
        let Ok((host, _)) = r.target_host_port() else {
            continue;
        };
        if host.parse::<IpAddr>().is_ok() || !seen.insert(host.clone()) {
            continue;
        }
        let prefer = prev.get(&r.id).cloned().unwrap_or_default();
        set.spawn(async move {
            let res = resolve_host(&host, &prefer).await;
            (host, res)
        });
    }
    let hosts: HashMap<String, Result<String, String>> = set.join_all().await.into_iter().collect();
    let mut st = KernelState {
        rules: rules.to_vec(),
        ..Default::default()
    };
    let mut out = Vec::new();
    for r in enabled(rules) {
        let mut r = r.clone();
        let Ok((host, port)) = r.target_host_port() else {
            continue;
        };
        match hosts.get(&host) {
            Some(Err(e)) => {
                st.errs.insert(r.id.clone(), e.clone());
                continue;
            }
            Some(Ok(ip)) => {
                st.ips.insert(r.id.clone(), ip.clone());
                r.target = format!("{ip}:{port}");
            }
            None => {}
        }
        out.push(r);
    }
    (out, st)
}

impl KernelState {
    fn status(&self) -> HashMap<String, RuleStatus> {
        self.rules
            .iter()
            .map(|r| {
                let st = if !r.enabled {
                    RuleStatus::new("stopped", "")
                } else if let Some(e) = self.errs.get(&r.id) {
                    RuleStatus::new("error", e.clone())
                } else if let Some(ip) = self.ips.get(&r.id) {
                    let host = r.target_host_port().map(|(h, _)| h).unwrap_or_default();
                    RuleStatus::new("applied", format!("{host} → {ip}"))
                } else {
                    RuleStatus::new("applied", "")
                };
                (r.id.clone(), st)
            })
            .collect()
    }
}

// ---------------------------------------------------------------- nftables

const NFT_TABLE: &str = "lport";

/// 标记 lport 做了 DNAT 的连接，供 filter FORWARD 链放行（Docker 等会把 FORWARD 默认策略设为 DROP，
/// 而独立 nft 表中的 accept 无法覆盖其它表的 drop）。只占用 ct mark 的一个比特位。
pub const CONN_MARK: u32 = 0x0100_0000;

#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub enum NftMode {
    #[default]
    Unknown,
    /// map 查找，规则数量不影响匹配开销（nft >= 0.9.4，内核 >= 5.6）
    Map,
    /// 每条转发一条规则，兼容老版本 nft / 内核
    Linear,
}

/// 一条展开后的转发（both 已拆分）。
struct NftForward {
    proto: &'static str,
    listen_port: i64,
    host: String,
    port: u16,
}

fn nft_forwards(rules: &[Rule]) -> Vec<NftForward> {
    let mut out = Vec::new();
    for r in enabled(rules) {
        let Ok((host, port)) = r.target_host_port() else {
            continue;
        };
        for proto in r.protos() {
            out.push(NftForward {
                proto,
                listen_port: r.listen_port,
                host: host.clone(),
                port,
            });
        }
    }
    out
}

fn nft_script(body: &str) -> String {
    // 先建后删再建：保证表存在时可被删除，整个脚本在一个事务内原子生效
    format!(
        "table ip {NFT_TABLE} {{}}\ndelete table ip {NFT_TABLE}\ntable ip {NFT_TABLE} {{\n{body}}}\n"
    )
}

/// 基于 map 的规则：每个协议一条 DNAT 规则，通过哈希查找目标。
pub fn nft_map_script(rules: &[Rule]) -> String {
    let protos = [model::PROTO_TCP, model::PROTO_UDP];
    let mut dnat: HashMap<&str, Vec<String>> = HashMap::new();
    let mut lports: HashMap<&str, Vec<String>> = HashMap::new();
    let mut targets: HashMap<&str, Vec<String>> = HashMap::new();
    let mut seen = HashSet::new();
    for f in nft_forwards(rules) {
        dnat.entry(f.proto)
            .or_default()
            .push(format!("{} : {} . {}", f.listen_port, f.host, f.port));
        lports
            .entry(f.proto)
            .or_default()
            .push(f.listen_port.to_string());
        let t = format!("{} . {}", f.host, f.port);
        if seen.insert(format!("{}{t}", f.proto)) {
            targets.entry(f.proto).or_default().push(t);
        }
    }
    let elements = |m: &HashMap<&str, Vec<String>>, p: &str| match m.get(p) {
        Some(items) if !items.is_empty() => format!("\t\telements = {{ {} }}\n", items.join(", ")),
        _ => String::new(),
    };
    let mut b = String::new();
    for p in protos {
        let _ = write!(
            b,
            "\tset lports_{p} {{\n\t\ttype inet_service\n{}\t}}\n",
            elements(&lports, p)
        );
        let _ = write!(
            b,
            "\tmap fwd_{p} {{\n\t\ttype inet_service : ipv4_addr . inet_service\n{}\t}}\n",
            elements(&dnat, p)
        );
        let _ = write!(
            b,
            "\tset dst_{p} {{\n\t\ttype ipv4_addr . inet_service\n{}\t}}\n",
            elements(&targets, p)
        );
    }
    // prerouting 只处理目的地址为本机的流量：本机兼作网关 / VPN / 容器宿主时，途经转发的流量不受影响
    b.push_str(
        "\tchain prerouting {\n\t\ttype nat hook prerouting priority -100; policy accept;\n",
    );
    for p in protos {
        let _ = writeln!(
            b,
            "\t\tfib daddr type local {p} dport @lports_{p} counter ct mark set ct mark or 0x{CONN_MARK:08x}"
        );
        let _ = writeln!(
            b,
            "\t\tfib daddr type local dnat ip addr . port to {p} dport map @fwd_{p}"
        );
    }
    b.push_str("\t}\n\tchain output {\n\t\ttype nat hook output priority -100; policy accept;\n");
    for p in protos {
        let _ = writeln!(
            b,
            "\t\tfib daddr type local dnat ip addr . port to {p} dport map @fwd_{p}"
        );
    }
    b.push_str(
        "\t}\n\tchain postrouting {\n\t\ttype nat hook postrouting priority 100; policy accept;\n",
    );
    for p in protos {
        let _ = writeln!(
            b,
            "\t\tct status dnat ip daddr . {p} dport @dst_{p} masquerade"
        );
    }
    b.push_str("\t}\n");
    nft_script(&b)
}

/// 每条转发一条规则，兼容老版本 nft；使用数值优先级以兼容较老版本的 nft。
pub fn nft_linear_script(rules: &[Rule]) -> String {
    let (mut pre, mut out, mut post) = (String::new(), String::new(), String::new());
    for f in nft_forwards(rules) {
        let dst = format!("{}:{}", f.host, f.port);
        let _ = writeln!(
            pre,
            "\t\tfib daddr type local {} dport {} counter ct mark set ct mark or 0x{CONN_MARK:08x} dnat to {dst}",
            f.proto, f.listen_port
        );
        let _ = writeln!(
            out,
            "\t\tfib daddr type local {} dport {} dnat to {dst}",
            f.proto, f.listen_port
        );
        let _ = writeln!(
            post,
            "\t\tct status dnat ip daddr {} {} dport {} masquerade",
            f.host, f.proto, f.port
        );
    }
    nft_script(&format!(
        "\tchain prerouting {{\n\t\ttype nat hook prerouting priority -100; policy accept;\n{pre}\t}}\n\
         \tchain output {{\n\t\ttype nat hook output priority -100; policy accept;\n{out}\t}}\n\
         \tchain postrouting {{\n\t\ttype nat hook postrouting priority 100; policy accept;\n{post}\t}}\n"
    ))
}

/// 插入 filter FORWARD 链的放行规则（通过 iptables 命令维护，兼容 iptables-nft / legacy）。
fn fwd_accept_args(op: &str) -> Vec<String> {
    let mut a: Vec<String> = ["-w", "-t", "filter", op, "FORWARD"]
        .map(String::from)
        .to_vec();
    if op == "-I" {
        a.push("1".into());
    }
    let mark = format!("0x{CONN_MARK:x}/0x{CONN_MARK:x}");
    a.extend(
        [
            "-m",
            "connmark",
            "--mark",
            &mark,
            "-m",
            "comment",
            "--comment",
            "lport",
            "-j",
            "ACCEPT",
        ]
        .map(String::from),
    );
    a
}

async fn iptables(args: &[String]) -> Result<(), String> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    run("", "iptables", &a).await
}

/// 在 filter FORWARD 链首放行带 lport 标记的连接。系统没有 iptables 时跳过
/// （此时通常也没有其它会 drop 转发流量的 iptables 规则）。
async fn ensure_forward_accept() -> Result<(), String> {
    if !sysinfo::tool_installed("iptables") || iptables(&fwd_accept_args("-C")).await.is_ok() {
        return Ok(());
    }
    iptables(&fwd_accept_args("-I")).await
}

pub async fn remove_forward_accept() -> Result<(), String> {
    if !sysinfo::tool_installed("iptables") {
        return Ok(());
    }
    for _ in 0..10 {
        if iptables(&fwd_accept_args("-D")).await.is_err() {
            break;
        }
    }
    if iptables(&fwd_accept_args("-C")).await.is_ok() {
        return Err("删除 FORWARD 放行规则失败".into());
    }
    Ok(())
}

/// 使用独立的 ip lport 表实现转发。
#[derive(Default)]
pub struct Nftables {
    mode: NftMode,
    state: KernelState,
}

impl Nftables {
    #[cfg(test)]
    pub fn linear() -> Self {
        Nftables {
            mode: NftMode::Linear,
            ..Default::default()
        }
    }

    /// 当前使用的规则模式（map / linear），未应用过时为空。
    pub fn mode(&self) -> &'static str {
        match self.mode {
            NftMode::Unknown => "",
            NftMode::Map => "map",
            NftMode::Linear => "linear",
        }
    }

    pub async fn sync(&mut self, rules: &[Rule]) -> Result<(), String> {
        check_tool(model::BACKEND_NFTABLES)?;
        if enabled(rules).next().is_some() {
            sysinfo::enable_ip_forward()?;
        }
        let (resolved, st) = resolve_rules(rules, &self.state.ips).await;
        self.apply(&resolved).await?;
        ensure_forward_accept()
            .await
            .map_err(|e| format!("添加 FORWARD 放行规则失败: {e}"))?;
        self.state = st;
        Ok(())
    }

    async fn apply(&mut self, rules: &[Rule]) -> Result<(), String> {
        if self.mode == NftMode::Linear {
            return run(&nft_linear_script(rules), "nft", &["-f", "-"]).await;
        }
        let map_err = match run(&nft_map_script(rules), "nft", &["-f", "-"]).await {
            Ok(()) => {
                if self.mode == NftMode::Unknown {
                    crate::logln!("nftables: 使用 map 查找模式");
                }
                self.mode = NftMode::Map;
                return Ok(());
            }
            Err(e) if self.mode == NftMode::Map => return Err(e),
            Err(e) => e,
        };
        // 首次失败时尝试兼容模式；nft -f 为事务，失败不会留下部分规则
        run(&nft_linear_script(rules), "nft", &["-f", "-"]).await?;
        crate::logln!("nftables: 当前 nft/内核不支持 map 方式 DNAT，已改用兼容模式: {map_err}");
        self.mode = NftMode::Linear;
        Ok(())
    }

    /// 定期全量重新应用：重新解析域名，并修复被外部清除（如防火墙重载、nft flush ruleset）的
    /// lport 表与 FORWARD 放行规则。nft -f 在一个事务内替换整张表，不影响已建立的连接。
    pub async fn maintain(&mut self) -> Result<(), String> {
        let rules = self.state.rules.clone();
        self.sync(&rules).await
    }

    pub fn status(&self) -> HashMap<String, RuleStatus> {
        self.state.status()
    }

    pub async fn cleanup(&mut self) -> Result<(), String> {
        self.state = KernelState::default();
        let fwd = remove_forward_accept().await;
        if !sysinfo::tool_installed(model::BACKEND_NFTABLES) {
            return fwd;
        }
        // 先建后删，表不存在时也不会报错，因此这里的错误都是真实的删除失败
        let script = format!("table ip {NFT_TABLE} {{}}\ndelete table ip {NFT_TABLE}\n");
        run(&script, "nft", &["-f", "-"])
            .await
            .map_err(|e| format!("删除 nftables 表失败: {e}"))?;
        fwd
    }
}

// ---------------------------------------------------------------- iptables

const CHAIN_PRE: &str = "LPORT_PRE";
const CHAIN_OUT: &str = "LPORT_OUT";
const CHAIN_POST: &str = "LPORT_POST";
pub const CHAIN_FWD: &str = "LPORT_FWD";

/// 把自有链挂到内置链上的规则。
struct Jump {
    table: &'static str,
    chain: &'static str,
    /// 目的地址为本机的流量才做 DNAT：本机兼作网关 / VPN / 容器宿主时，途经本机转发到其它主机同端口的流量不受影响
    local_dst: bool,
    target: &'static str,
}

const IPT_JUMPS: [Jump; 4] = [
    Jump {
        table: "nat",
        chain: "PREROUTING",
        local_dst: true,
        target: CHAIN_PRE,
    },
    Jump {
        table: "nat",
        chain: "OUTPUT",
        local_dst: true,
        target: CHAIN_OUT,
    },
    Jump {
        table: "nat",
        chain: "POSTROUTING",
        local_dst: false,
        target: CHAIN_POST,
    },
    Jump {
        table: "filter",
        chain: "FORWARD",
        local_dst: false,
        target: CHAIN_FWD,
    },
];

/// 旧版本创建、已不再使用的挂接规则，清理时一并删除。
const LEGACY_JUMPS: [Jump; 1] = [Jump {
    table: "nat",
    chain: "PREROUTING",
    local_dst: false,
    target: CHAIN_PRE,
}];

const IPT_CHAINS: [(&str, &str); 4] = [
    ("nat", CHAIN_PRE),
    ("nat", CHAIN_OUT),
    ("nat", CHAIN_POST),
    ("filter", CHAIN_FWD),
];

impl Jump {
    fn args(&self, op: &str) -> Vec<String> {
        let mut a: Vec<String> = ["-w", "-t", self.table, op, self.chain]
            .map(String::from)
            .to_vec();
        if op == "-I" {
            a.push("1".into());
        }
        if self.local_dst {
            a.extend(["-m", "addrtype", "--dst-type", "LOCAL"].map(String::from));
        }
        a.extend(["-j", self.target].map(String::from));
        a
    }
}

/// iptables-restore --noflush 的输入；声明自有链会将其清空，因此整份脚本以原子方式替换自有链内容。
pub fn iptables_restore_script(rules: &[Rule]) -> String {
    let (mut nat, mut filter) = (String::new(), String::new());
    for r in enabled(rules) {
        let Ok((host, port)) = r.target_host_port() else {
            continue;
        };
        let dst = format!("{host}:{port}");
        let lp = r.listen_port;
        let comment = format!("-m comment --comment \"lport:{}\"", r.id);
        for proto in r.protos() {
            let _ = writeln!(
                nat,
                "-A {CHAIN_PRE} -p {proto} --dport {lp} {comment} -j DNAT --to-destination {dst}"
            );
            let _ = writeln!(
                nat,
                "-A {CHAIN_OUT} -p {proto} --dport {lp} {comment} -j DNAT --to-destination {dst}"
            );
            let _ = writeln!(
                nat,
                "-A {CHAIN_POST} -p {proto} -d {host} --dport {port} -m conntrack --ctstate DNAT {comment} -j MASQUERADE"
            );
            let _ = writeln!(
                filter,
                "-A {CHAIN_FWD} -p {proto} -d {host} --dport {port} -m conntrack --ctstate DNAT {comment} -j ACCEPT"
            );
            let _ = writeln!(
                filter,
                "-A {CHAIN_FWD} -p {proto} -s {host} --sport {port} -m conntrack --ctstate DNAT {comment} -j ACCEPT"
            );
        }
    }
    format!(
        "*nat\n:{CHAIN_PRE} - [0:0]\n:{CHAIN_OUT} - [0:0]\n:{CHAIN_POST} - [0:0]\n{nat}COMMIT\n*filter\n:{CHAIN_FWD} - [0:0]\n{filter}COMMIT\n"
    )
}

/// 使用自有链实现转发，不改动用户已有规则。
#[derive(Default)]
pub struct Iptables {
    state: KernelState,
}

impl Iptables {
    pub async fn sync(&mut self, rules: &[Rule]) -> Result<(), String> {
        check_tool(model::BACKEND_IPTABLES)?;
        if enabled(rules).next().is_some() {
            sysinfo::enable_ip_forward()?;
        }
        let (resolved, st) = resolve_rules(rules, &self.state.ips).await;
        run(
            &iptables_restore_script(&resolved),
            "iptables-restore",
            &["-w", "--noflush"],
        )
        .await?;
        for j in &IPT_JUMPS {
            if iptables(&j.args("-C")).await.is_err() {
                iptables(&j.args("-I")).await?;
            }
        }
        self.state = st;
        Ok(())
    }

    /// 定期全量重新应用：重新解析域名，并修复被外部清除（如防火墙重载）的自有链、规则与挂接。
    /// iptables-restore 按表原子替换自有链内容，不影响已建立的连接。
    pub async fn maintain(&mut self) -> Result<(), String> {
        let rules = self.state.rules.clone();
        self.sync(&rules).await
    }

    pub fn status(&self) -> HashMap<String, RuleStatus> {
        self.state.status()
    }

    /// 删除挂接与自有链。规则或链本不存在时删除命令会失败，属于正常情况，
    /// 因此最后逐项核查，仍有残留才返回错误。
    pub async fn cleanup(&mut self) -> Result<(), String> {
        self.state = KernelState::default();
        if !sysinfo::tool_installed(model::BACKEND_IPTABLES) {
            return Ok(());
        }
        let jumps = || IPT_JUMPS.iter().chain(LEGACY_JUMPS.iter());
        for j in jumps() {
            for _ in 0..10 {
                if iptables(&j.args("-D")).await.is_err() {
                    break;
                }
            }
        }
        for (table, chain) in IPT_CHAINS {
            let _ = run("", "iptables", &["-w", "-t", table, "-F", chain]).await;
            let _ = run("", "iptables", &["-w", "-t", table, "-X", chain]).await;
        }
        let mut left = Vec::new();
        for j in jumps() {
            if iptables(&j.args("-C")).await.is_ok() {
                left.push(format!("{} → {}", j.chain, j.target));
            }
        }
        for (table, chain) in IPT_CHAINS {
            if ok("iptables", &["-w", "-t", table, "-S", chain]).await {
                left.push(format!("{table}/{chain}"));
            }
        }
        if left.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "清理 iptables 规则失败，仍残留: {}",
                left.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// golden 文件取自 Go 版（v0.2.0），保证升级前后生成的规则逐字节一致。
    fn golden(name: &str) -> String {
        let path = format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("读取 {path}: {e}"))
    }

    pub fn test_rules() -> Vec<Rule> {
        let r = |id: &str, name: &str, proto: &str, port, target: &str, enabled| Rule {
            id: id.into(),
            name: name.into(),
            proto: proto.into(),
            listen_port: port,
            target: target.into(),
            enabled,
            ..Default::default()
        };
        vec![
            r("a1", "web", "tcp", 8080, "10.0.0.5:80", true),
            r("b2", "dns", "both", 5353, "10.0.0.6:53", true),
            r("c3", "off", "udp", 9999, "10.0.0.7:99", false),
        ]
    }

    #[test]
    fn iptables_script_matches_go() {
        assert_eq!(
            iptables_restore_script(&test_rules()),
            golden("iptables.golden")
        );
    }

    #[test]
    fn nft_linear_script_matches_go() {
        assert_eq!(
            nft_linear_script(&test_rules()),
            golden("nft_linear.golden")
        );
    }

    #[test]
    fn nft_map_script_matches_go() {
        let mut rules = test_rules();
        rules.push(Rule {
            id: "d4".into(),
            proto: "tcp".into(),
            listen_port: 8081,
            target: "10.0.0.5:80".into(),
            enabled: true,
            ..Default::default()
        });
        assert_eq!(nft_map_script(&rules), golden("nft_map.golden"));
        // 无规则时 map/set 不能带空 elements（nft 语法错误）
        assert!(!nft_map_script(&[]).contains("elements"));
    }

    #[test]
    fn jump_args() {
        assert_eq!(
            IPT_JUMPS[0].args("-I").join(" "),
            "-w -t nat -I PREROUTING 1 -m addrtype --dst-type LOCAL -j LPORT_PRE"
        );
        assert_eq!(
            fwd_accept_args("-C").join(" "),
            "-w -t filter -C FORWARD -m connmark --mark 0x1000000/0x1000000 -m comment --comment lport -j ACCEPT"
        );
    }

    #[tokio::test]
    async fn resolve_prefers_previous_ip() {
        let ips = |v: &[[u8; 4]]| v.iter().map(|o| Ipv4Addr::from(*o)).collect::<Vec<_>>();
        *DNS_STUB.lock().unwrap() = Some(HashMap::from([
            ("rr.test".to_string(), ips(&[[10, 0, 0, 1], [10, 0, 0, 2]])),
            ("lo.test".to_string(), ips(&[[127, 0, 0, 1]])),
        ]));
        assert_eq!(resolve_host("rr.test", "").await.unwrap(), "10.0.0.1");
        assert_eq!(
            resolve_host("rr.test", "10.0.0.2").await.unwrap(),
            "10.0.0.2",
            "仍在结果中时保留原 IP"
        );
        assert_eq!(resolve_host("1.2.3.4", "").await.unwrap(), "1.2.3.4");
        assert!(
            resolve_host("lo.test", "")
                .await
                .unwrap_err()
                .contains("回环")
        );
        assert!(resolve_host("none.test", "").await.is_err());

        let mut rules = test_rules();
        rules[0].target = "rr.test:80".into();
        rules[1].target = "none.test:53".into();
        let (out, st) = resolve_rules(&rules, &HashMap::new()).await;
        *DNS_STUB.lock().unwrap() = None;
        assert_eq!(out.len(), 1, "解析失败与停用的规则不应用");
        assert_eq!(out[0].target, "10.0.0.1:80");
        let status = st.status();
        assert_eq!(
            status["a1"],
            RuleStatus::new("applied", "rr.test → 10.0.0.1")
        );
        assert_eq!(status["b2"].state, "error");
        assert_eq!(status["c3"].state, "stopped");
    }
}
