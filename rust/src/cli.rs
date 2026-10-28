//! 规则相关命令（list / add / edit / remove），对应 Go 版 cmd/lport/rules.go。

use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;

use crate::config::{self, Store};
use crate::ctl::{self, CtlError};
use crate::manager::{Manager, ProbeResult, RuleView};
use crate::model::{self, Rule};
use crate::{probe, service};

/// 命令行选项，语义同 Go flag 包：-x 与 --x 等价，值可用 `-x v` 或 `-x=v`，
/// 选项可出现在位置参数之后（如 lport add 8080 1.2.3.4:80 --proto udp），`--` 之后全部为位置参数。
pub struct Flags {
    values: HashMap<&'static str, String>,
    pub pos: Vec<String>,
}

impl Flags {
    /// spec 为 (选项名, 是否为布尔开关)。
    pub fn parse(args: &[String], spec: &[(&'static str, bool)]) -> Result<Flags, String> {
        let mut f = Flags {
            values: HashMap::new(),
            pos: Vec::new(),
        };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if a == "--" {
                f.pos.extend(it.by_ref().cloned());
                break;
            }
            let Some(body) = a
                .strip_prefix("--")
                .or_else(|| a.strip_prefix('-'))
                .filter(|b| !b.is_empty())
            else {
                f.pos.push(a.clone());
                continue;
            };
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (body, None),
            };
            let Some(&(key, is_bool)) = spec.iter().find(|(n, _)| *n == name) else {
                return Err(format!("未知选项: {a}"));
            };
            let v = match (inline, is_bool) {
                (Some(v), _) => v,
                (None, true) => "true".into(),
                (None, false) => it
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("选项 {a} 需要参数"))?,
            };
            if is_bool && !["true", "false", "1", "0"].contains(&v.as_str()) {
                return Err(format!("选项 {a} 的值无效: {v}"));
            }
            f.values.insert(key, v);
        }
        Ok(f)
    }

    pub fn has(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    pub fn str(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    pub fn bool(&self, name: &str) -> bool {
        matches!(self.str(name), Some("true" | "1"))
    }

    pub fn config(&self) -> &str {
        self.str("config").unwrap_or(config::DEFAULT_PATH)
    }
}

/// 规则增删查：服务运行中时经控制套接字由服务执行（立即生效），否则直接修改配置文件。
pub enum RuleOps {
    Online(ctl::Client),
    Offline(Box<Manager>),
}

impl RuleOps {
    /// 优先连接运行中的服务；连接不上且服务确实未运行时退回离线模式。
    pub async fn open(cfg_path: &str) -> Result<RuleOps, String> {
        let sock = ctl::socket_path(Path::new(cfg_path));
        let c = ctl::Client::new(sock.clone());
        let res = match std::fs::metadata(&sock) {
            Ok(_) => c.list().await.map(drop),
            Err(e) => Err(CtlError::Connect(e)),
        };
        match res {
            Ok(()) => return Ok(RuleOps::Online(c)),
            Err(CtlError::Connect(e))
                if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {}
            Err(CtlError::Connect(e)) if e.kind() == ErrorKind::PermissionDenied => {
                return Err("需要 root 权限运行".into());
            }
            Err(e) => return Err(e.into()),
        }
        if service::running() {
            return Err(format!(
                "服务正在运行，但无法连接控制套接字 {}，请重启服务（systemctl restart lport）后重试",
                sock.display()
            ));
        }
        let store = load_config(cfg_path, "")?;
        Ok(RuleOps::Offline(Box::new(Manager::offline(Arc::new(
            store,
        )))))
    }

    pub fn online(&self) -> bool {
        matches!(self, RuleOps::Online(_))
    }

    pub async fn list(&self) -> Result<Vec<RuleView>, String> {
        match self {
            RuleOps::Online(c) => Ok(c.list().await?),
            RuleOps::Offline(m) => Ok(m
                .store()
                .get()
                .rules
                .into_iter()
                .map(|rule| RuleView {
                    rule,
                    ..Default::default()
                })
                .collect()),
        }
    }

    pub async fn create(&self, r: Rule) -> Result<Rule, String> {
        match self {
            RuleOps::Online(c) => Ok(c.create(&r).await?),
            RuleOps::Offline(m) => m.create(r).await,
        }
    }

    pub async fn update(&self, id: &str, r: Rule) -> Result<Rule, String> {
        match self {
            RuleOps::Online(c) => Ok(c.update(id, &r).await?),
            RuleOps::Offline(m) => m.update(id, r).await,
        }
    }

    pub async fn delete(&self, id: &str) -> Result<(), String> {
        match self {
            RuleOps::Online(c) => Ok(c.delete(id).await?),
            RuleOps::Offline(m) => m.delete(id).await,
        }
    }
}

/// 加载配置，并在 listen 参数非空时写入配置；首次生成密码时打印出来。
pub fn load_config(path: &str, listen: &str) -> Result<Store, String> {
    let (store, res) = Store::load(path)?;
    if !listen.is_empty() && listen != store.get().listen {
        store.update(|c| {
            c.listen = listen.to_string();
            Ok(())
        })?;
    }
    if !res.generated_password.is_empty() {
        println!(
            "\n========================================\n 已生成管理员账号\n 用户名: {}\n 密码:   {}\n 请登录后尽快修改密码\n========================================\n",
            store.get().admin.username,
            res.generated_password
        );
    }
    Ok(store)
}

/// 按显示宽度补齐空格（中日韩字符按 2 列计）。
fn pad_width(s: &str, w: usize) -> String {
    let n: usize = s
        .chars()
        .map(|c| if c as u32 > 0x2E80 { 2 } else { 1 })
        .sum();
    format!("{s}{}", " ".repeat(w.saturating_sub(n)))
}

/// 按名称、ID 或监听端口筛选规则；未指定时返回全部。
fn select_rules(rules: &[Rule], keys: &[String]) -> Result<Vec<Rule>, String> {
    if keys.is_empty() {
        return Ok(rules.to_vec());
    }
    let mut out = Vec::new();
    for k in keys {
        let found: Vec<&Rule> = rules
            .iter()
            .filter(|r| &r.name == k || &r.id == k || r.listen_port.to_string() == *k)
            .collect();
        if found.is_empty() {
            return Err(format!("未找到规则: {k}（可用名称、ID 或监听端口）"));
        }
        out.extend(found.into_iter().cloned());
    }
    Ok(out)
}

fn state_text(s: &str) -> &str {
    match s {
        "running" => "运行中",
        "applied" => "已生效",
        "stopped" => "已停用",
        "error" => "错误",
        s => s,
    }
}

fn summary(r: &Rule) -> String {
    format!(
        "{} ({}): {} :{} → {}",
        r.name, r.id, r.proto, r.listen_port, r.target
    )
}

pub async fn cmd_list(args: &[String]) -> Result<(), String> {
    let fs = Flags::parse(args, &[("config", false)])?;
    let ops = RuleOps::open(fs.config()).await?;
    let rules = ops.list().await?;
    if rules.is_empty() {
        println!("没有转发规则");
        return Ok(());
    }
    println!(
        "{:<8}  {}  {} {} {} 状态",
        "ID",
        pad_width("名称", 16),
        pad_width("协议", 5),
        pad_width("端口", 6),
        pad_width("目标", 26)
    );
    for v in &rules {
        let r = &v.rule;
        let mut state = if r.enabled { "已启用" } else { "未启用" }.to_string();
        if ops.online() {
            state = state_text(&v.status.state).to_string();
            if !v.status.message.is_empty() {
                state = format!("{state}: {}", v.status.message);
            }
        }
        println!(
            "{:<8}  {}  {:<5} {:<6} {:<26} {state}",
            r.id,
            pad_width(&r.name, 16),
            r.proto,
            r.listen_port,
            r.target
        );
    }
    if !ops.online() {
        println!("\n服务未运行，以上为配置文件中的规则");
    }
    Ok(())
}

pub async fn cmd_add(args: &[String]) -> Result<(), String> {
    let fs = Flags::parse(
        args,
        &[
            ("config", false),
            ("proto", false),
            ("name", false),
            ("remark", false),
            ("disabled", true),
        ],
    )?;
    let [port, target] = fs.pos.as_slice() else {
        return Err(
            "用法: lport add [--proto tcp|udp|both] [--name NAME] 监听端口 目标地址:端口".into(),
        );
    };
    let port: i64 = port.parse().map_err(|_| format!("监听端口无效: {port}"))?;
    let ops = RuleOps::open(fs.config()).await?;
    let r = ops
        .create(Rule {
            name: fs.str("name").unwrap_or_default().into(),
            proto: fs.str("proto").unwrap_or(model::PROTO_TCP).into(),
            listen_port: port,
            target: target.clone(),
            remark: fs.str("remark").unwrap_or_default().into(),
            enabled: !fs.bool("disabled"),
            ..Default::default()
        })
        .await?;
    println!("已添加规则 {}", summary(&r));
    if !ops.online() {
        println!("服务未运行，规则已写入配置，启动服务后生效");
    }
    Ok(())
}

async fn current_rules(ops: &RuleOps) -> Result<Vec<Rule>, String> {
    Ok(ops.list().await?.into_iter().map(|v| v.rule).collect())
}

pub async fn cmd_edit(args: &[String]) -> Result<(), String> {
    const USAGE: &str = "用法: lport edit [--port PORT] [--target HOST:PORT] [--proto tcp|udp|both] [--name NAME] [--remark TEXT] [--enable|--disable] 规则名|ID|端口";
    let fs = Flags::parse(
        args,
        &[
            ("config", false),
            ("port", false),
            ("target", false),
            ("proto", false),
            ("name", false),
            ("remark", false),
            ("enable", true),
            ("disable", true),
        ],
    )?;
    let edits: HashSet<&str> = [
        "port", "target", "proto", "name", "remark", "enable", "disable",
    ]
    .into_iter()
    .filter(|n| fs.has(n))
    .collect();
    if fs.pos.len() != 1 || edits.is_empty() {
        return Err(USAGE.into());
    }
    if fs.bool("enable") && fs.bool("disable") {
        return Err("--enable 与 --disable 不能同时使用".into());
    }
    let port = fs
        .str("port")
        .map(|p| p.parse::<i64>().map_err(|_| format!("监听端口无效: {p}")))
        .transpose()?;
    let ops = RuleOps::open(fs.config()).await?;
    let selected = select_rules(&current_rules(&ops).await?, &fs.pos)?;
    if selected.len() > 1 {
        return Err(format!(
            "{} 匹配到 {} 条规则，请改用 ID 指定（lport list 查看）",
            fs.pos[0],
            selected.len()
        ));
    }
    let mut r = selected.into_iter().next().unwrap();
    if let Some(port) = port {
        // 沿用默认名称的规则随端口一起改名
        if !fs.has("name") && r.name == Rule::default_name(r.listen_port) {
            r.name = Rule::default_name(port);
        }
        r.listen_port = port;
    }
    for (key, field) in [
        ("target", &mut r.target),
        ("proto", &mut r.proto),
        ("name", &mut r.name),
        ("remark", &mut r.remark),
    ] {
        if let Some(v) = fs.str(key) {
            *field = v.to_string();
        }
    }
    if fs.bool("enable") {
        r.enabled = true;
    }
    if fs.bool("disable") {
        r.enabled = false;
    }
    let id = r.id.clone();
    let r = ops.update(&id, r).await?;
    println!("已修改规则 {}", summary(&r));
    if !ops.online() {
        println!("服务未运行，已写入配置，启动服务后生效");
    }
    Ok(())
}

pub async fn cmd_remove(args: &[String]) -> Result<(), String> {
    let fs = Flags::parse(args, &[("config", false)])?;
    if fs.pos.is_empty() {
        return Err("用法: lport remove 规则名|ID|端口 ...".into());
    }
    let ops = RuleOps::open(fs.config()).await?;
    let selected = select_rules(&current_rules(&ops).await?, &fs.pos)?;
    let mut removed = HashSet::new();
    for r in selected {
        if !removed.insert(r.id.clone()) {
            continue;
        }
        ops.delete(&r.id)
            .await
            .map_err(|e| format!("删除规则 {} 失败: {e}", r.name))?;
        println!("已删除规则 {}", summary(&r));
    }
    if !ops.online() {
        println!("服务未运行，已从配置中删除");
    }
    Ok(())
}

fn probe_label(state: &str) -> (&'static str, &'static str) {
    match state {
        probe::STATE_OK => ("32", "成功"),
        probe::STATE_FAIL => ("31", "失败"),
        probe::STATE_UNKNOWN => ("33", "无法确定"),
        _ => ("90", "跳过"),
    }
}

fn worst(items: &[probe::Check]) -> &'static str {
    let mut s = probe::STATE_OK;
    for it in items {
        if it.state == probe::STATE_FAIL {
            return probe::STATE_FAIL;
        }
        if it.state != probe::STATE_OK {
            s = it.state;
        }
    }
    s
}

fn probe_hint(res: &ProbeResult) -> &'static str {
    match (worst(&res.local), worst(&res.target)) {
        (probe::STATE_FAIL, probe::STATE_OK) => {
            "目标可达但经本机转发失败：请检查规则状态、转发后端与防火墙"
        }
        (_, probe::STATE_FAIL) => "本机无法直连目标：目标服务未启动、地址错误或目标防火墙拦截",
        (probe::STATE_OK, probe::STATE_OK) => {
            "本机检测不经过 FORWARD 链；若外部仍无法访问，请检查云安全组与 FORWARD 防火墙规则"
        }
        _ => "",
    }
}

/// 在命令行检测规则连通性；只读配置，不影响运行中的服务。
pub async fn cmd_probe(args: &[String]) -> Result<(), String> {
    let fs = Flags::parse(args, &[("config", false)])?;
    let (store, _) = Store::load_no_save(fs.config())?;
    let cfg = store.get();
    let rules = select_rules(&cfg.rules, &fs.pos)?;
    if rules.is_empty() {
        println!("没有转发规则");
        return Ok(());
    }
    let mgr = Manager::offline(Arc::new(store));
    let results = futures_util::future::join_all(rules.iter().map(|r| mgr.probe(&r.id))).await;

    // SAFETY: isatty 只查询描述符
    let color = unsafe { libc::isatty(1) == 1 };
    let paint = |code: &str, s: &str| {
        if color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let mut failed = false;
    for (r, res) in rules.iter().zip(results) {
        let state = if r.enabled { "启用" } else { "停用" };
        println!(
            "{}  {} :{} → {}  [{}, {state}]",
            paint("1", &r.name),
            r.proto,
            r.listen_port,
            r.target,
            cfg.backend
        );
        let res = match res {
            Ok(res) => res,
            Err(e) => {
                println!("  {} {e}", paint("31", "●"));
                failed = true;
                continue;
            }
        };
        for (label, items) in [("本机", &res.local), ("目标", &res.target)] {
            for it in items {
                let (code, text) = probe_label(it.state);
                let latency = if it.state == probe::STATE_OK || it.state == probe::STATE_FAIL {
                    format!("{}ms", it.latency_ms)
                } else {
                    String::new()
                };
                println!(
                    "  {label}  {} {} {:<3} {:<22} {latency:>6}  {}",
                    paint(code, "●"),
                    pad_width(text, 8),
                    it.proto,
                    it.addr,
                    it.message
                );
                failed |= it.state == probe::STATE_FAIL;
            }
        }
        let hint = probe_hint(&res);
        if !hint.is_empty() {
            println!("  {}", paint("90", &format!("提示: {hint}")));
        }
        println!();
    }
    if failed {
        Err("存在检测失败的项".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn flags_interspersed() {
        let spec = [("config", false), ("proto", false), ("disabled", true)];
        let f = Flags::parse(
            &args("8080 1.2.3.4:80 --proto udp -disabled --config=/x.yaml"),
            &spec,
        )
        .unwrap();
        assert_eq!(f.pos, ["8080", "1.2.3.4:80"]);
        assert_eq!(
            (f.str("proto"), f.bool("disabled"), f.config()),
            (Some("udp"), true, "/x.yaml")
        );
        let f = Flags::parse(&args("-- --proto"), &spec).unwrap();
        assert_eq!(f.pos, ["--proto"]);
        assert!(Flags::parse(&args("--bogus"), &spec).is_err());
        assert!(Flags::parse(&args("--proto"), &spec).is_err());
        assert!(
            !Flags::parse(&args("--disabled=false"), &spec)
                .unwrap()
                .bool("disabled")
        );
    }

    #[test]
    fn select_and_pad() {
        let r = |id: &str, name: &str, port| Rule {
            id: id.into(),
            name: name.into(),
            listen_port: port,
            ..Default::default()
        };
        let rules = [r("a1", "web", 80), r("b2", "dns", 53)];
        assert_eq!(select_rules(&rules, &args("53 a1")).unwrap().len(), 2);
        assert!(select_rules(&rules, &args("nope")).is_err());
        assert_eq!(pad_width("名称", 6), "名称  ");
    }
}
