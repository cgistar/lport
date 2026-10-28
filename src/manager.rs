//! 编排配置存储与转发后端。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::backend::{Backend, RuleStatus};
use crate::config::{self, Config, Store};
use crate::model::{self, Rule};
use crate::{kernel, portcheck, probe, sysinfo};

/// 内核后端重新解析域名、修复规则的间隔。
const MAINTAIN_INTERVAL: Duration = Duration::from_secs(60);
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// 端口冲突信息，JSON 格式与 Go 版一致。
#[derive(Debug, Clone, Serialize)]
pub struct Conflict {
    /// rule | panel | system
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub proto: String,
    pub message: String,
}

/// 规则及其运行状态；JSON 中规则字段展平，与 Go 版的 RuleView 一致。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuleView {
    #[serde(flatten)]
    pub rule: Rule,
    #[serde(default)]
    pub status: RuleStatus,
}

impl Serialize for RuleView {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut v = rule_json(&self.rule);
        v["status"] = serde_json::to_value(&self.status).map_err(serde::ser::Error::custom)?;
        v.serialize(s)
    }
}

/// 规则的 JSON 形式：与 Go encoding/json 一致，remark、created_at 总是输出（配置文件中为空时省略）。
pub fn rule_json(r: &Rule) -> Value {
    let mut v = serde_json::to_value(r).unwrap_or_else(|_| json!({}));
    v["remark"] = json!(r.remark);
    v["created_at"] = json!(
        r.created_at
            .as_ref()
            .map_or("0001-01-01T00:00:00Z".into(), model::go_time::format)
    );
    v
}

struct Inner {
    /// None 表示离线模式：只修改配置、不应用转发
    backend: Option<Backend>,
    sync_err: String,
    /// 启动时与系统已占用端口冲突的规则（rule id → 冲突说明），暂不应用；编辑该规则时重新校验
    blocked: HashMap<String, String>,
}

impl Inner {
    /// 实际交给后端的规则：启动时检测到端口冲突的规则按停用处理。
    fn effective(&self, rules: &[Rule]) -> Vec<Rule> {
        let mut out = rules.to_vec();
        for r in &mut out {
            if self.blocked.get(&r.id).is_some_and(|m| !m.is_empty()) {
                r.enabled = false;
            }
        }
        out
    }

    async fn sync(&mut self, rules: &[Rule]) -> Result<(), String> {
        let eff = self.effective(rules);
        match &mut self.backend {
            Some(b) => b.sync(&eff).await,
            None => Ok(()),
        }
    }

    async fn apply(&mut self, rules: &[Rule]) {
        match self.sync(rules).await {
            Ok(()) => self.sync_err.clear(),
            Err(e) => {
                crate::logln!("应用转发规则失败: {e}");
                self.sync_err = e;
            }
        }
    }

    /// 本工具的转发进程 pid，其占用的端口不算系统占用（规则间冲突另行检查）。
    fn own_pids(&self) -> Vec<i32> {
        self.backend.as_ref().map(Backend::pids).unwrap_or_default()
    }
}

pub struct Manager {
    store: Arc<Store>,
    inner: Mutex<Inner>,
    stop: CancellationToken,
}

/// 规则连通性检测结果。
#[derive(Debug, Serialize)]
pub struct ProbeResult {
    /// 经本机监听端口（走转发路径）
    pub local: Vec<probe::Check>,
    /// 直连目标
    pub target: Vec<probe::Check>,
}

impl Manager {
    /// 按配置中的后端创建；start 时才清理残留并应用规则。
    pub fn new(store: Arc<Store>) -> Self {
        let backend = Backend::new(&store.get().backend)
            .unwrap_or_else(|| Backend::new(model::BACKEND_BUILTIN).unwrap());
        Self::with_backend(store, Some(backend))
    }

    /// 只修改配置、不应用转发的 Manager，用于服务未运行时在命令行增删规则，
    /// 校验逻辑与运行时一致，规则在服务启动后生效。
    pub fn offline(store: Arc<Store>) -> Self {
        Self::with_backend(store, None)
    }

    fn with_backend(store: Arc<Store>, backend: Option<Backend>) -> Self {
        Manager {
            stop: CancellationToken::new(),
            store,
            inner: Mutex::new(Inner {
                backend,
                sync_err: String::new(),
                blocked: HashMap::new(),
            }),
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub async fn backend_name(&self) -> &'static str {
        self.inner
            .lock()
            .await
            .backend
            .as_ref()
            .map_or("offline", Backend::name)
    }

    pub async fn sync_error(&self) -> String {
        self.inner.lock().await.sync_err.clone()
    }

    /// 清理残留并按配置应用规则，之后定期维护。后端不可用时记录错误但不阻止启动，安装依赖后自动重试。
    /// 停机期间端口可能已被其它服务占用；内核后端不绑定端口，直接应用会把发往该服务的流量转走，
    /// 因此与在线启用规则一样检查系统占用，冲突的规则暂不应用。
    pub async fn start(self: &Arc<Self>) {
        let mut inner = self.inner.lock().await;
        let cfg = self.store.get();
        // 上次异常退出（如被 kill -9）时内核规则不会被清除，先清掉再按当前配置重建
        if sysinfo::is_root() {
            for name in [model::BACKEND_IPTABLES, model::BACKEND_NFTABLES] {
                if let Err(e) = Backend::new(name).unwrap().cleanup().await {
                    crate::logln!("清理残留的 {name} 转发规则失败: {e}");
                }
            }
        }
        inner.blocked.clear();
        for r in cfg.rules.iter().filter(|r| r.enabled) {
            let sys: Vec<Conflict> = check_port(&cfg, &r.proto, r.listen_port, &r.id, true, &[])
                .into_iter()
                .filter(|c| c.kind == "system")
                .collect();
            if let Err(e) = conflict_err(&sys) {
                crate::logln!("规则「{}」未应用: {e}", r.name);
                inner.blocked.insert(r.id.clone(), e);
            }
        }
        inner.apply(&cfg.rules).await;
        drop(inner);
        let m = self.clone();
        tokio::spawn(async move { m.maintain_loop().await });
    }

    async fn maintain_loop(&self) {
        loop {
            tokio::select! {
                _ = self.stop.cancelled() => return,
                _ = tokio::time::sleep(MAINTAIN_INTERVAL) => {}
            }
            let mut inner = self.inner.lock().await;
            if !inner.backend.as_ref().is_some_and(Backend::is_kernel) {
                continue;
            }
            if !inner.sync_err.is_empty() {
                // 上次应用失败（如依赖刚装好、网络刚恢复），整体重试
                inner.apply(&self.store.get().rules).await;
            } else if let Some(Err(e)) = inner.backend.as_mut().unwrap().maintain().await {
                crate::logln!("维护转发规则失败: {e}");
            }
        }
    }

    /// 停止维护并清除所有转发。
    pub async fn stop(&self) {
        self.stop.cancel();
        if let Some(b) = &mut self.inner.lock().await.backend
            && let Err(e) = b.cleanup().await
        {
            crate::logln!("清除转发规则失败: {e}");
        }
    }

    pub async fn rules(&self) -> Vec<RuleView> {
        let inner = self.inner.lock().await;
        let st = inner
            .backend
            .as_ref()
            .map(Backend::status)
            .unwrap_or_default();
        self.store
            .get()
            .rules
            .into_iter()
            .map(|r| {
                let status = match (inner.blocked.get(&r.id), st.get(&r.id)) {
                    (Some(msg), _) if r.enabled => RuleStatus::new("error", msg.clone()),
                    (_, Some(s)) => s.clone(),
                    _ if r.enabled => RuleStatus::new("error", inner.sync_err.clone()),
                    _ => RuleStatus::new("stopped", ""),
                };
                RuleView { rule: r, status }
            })
            .collect()
    }

    /// 在锁内修改规则（id 为被修改的规则，新建时为空）、校验、同步后端并保存。
    /// 同步失败或同步后保存失败时都恢复为旧规则，保证运行状态与配置一致。
    async fn mutate(
        &self,
        id: &str,
        f: impl FnOnce(&mut Config, &[i32]) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut inner = self.inner.lock().await;
        let old = self.store.get();
        // 被修改的规则会经 validate_rule 重新校验系统端口占用，不再沿用启动时的冲突标记
        let blocked = inner.blocked.remove(id);
        let restore = |inner: &mut Inner| {
            if let Some(m) = blocked.clone() {
                inner.blocked.insert(id.to_string(), m);
            }
        };
        let mut c = old.clone();
        if let Err(e) = f(&mut c, &inner.own_pids()) {
            restore(&mut inner);
            return Err(e);
        }
        let res = match inner.sync(&c.rules).await {
            Err(e) => Err(format!("应用规则失败: {e}")),
            Ok(()) => self.store.replace(c),
        };
        if let Err(e) = res {
            restore(&mut inner);
            inner.apply(&old.rules).await;
            return Err(e);
        }
        inner.sync_err.clear();
        Ok(())
    }

    /// 内核后端需要把域名解析为非回环的 IPv4，在加锁前异步检查，避免 DNS 查询阻塞其它操作。
    async fn check_resolvable(&self, r: &Rule) -> Result<(), String> {
        let backend = self.store.get().backend;
        let mut r = r.clone();
        if model::user_space(&backend) || !r.enabled || r.validate(&backend).is_err() {
            return Ok(());
        }
        let (host, _) = r.target_host_port()?;
        kernel::resolve_host(&host, "").await.map(drop)
    }

    pub async fn create(&self, mut r: Rule) -> Result<Rule, String> {
        self.check_resolvable(&r).await?;
        r.id = config::new_id();
        r.created_at = Some(config::now());
        if r.name.trim().is_empty() {
            r.name = Rule::default_name(r.listen_port);
        }
        self.mutate("", |c, own| {
            validate_rule(c, &mut r, own)?;
            c.rules.push(r.clone());
            Ok(())
        })
        .await?;
        Ok(r)
    }

    pub async fn update(&self, id: &str, mut r: Rule) -> Result<Rule, String> {
        self.check_resolvable(&r).await?;
        self.mutate(id, |c, own| {
            let i = find_rule(c, id)?;
            r.id = id.to_string();
            r.created_at = c.rules[i].created_at;
            if r.name.trim().is_empty() {
                r.name = Rule::default_name(r.listen_port);
            }
            validate_rule(c, &mut r, own)?;
            c.rules[i] = r.clone();
            Ok(())
        })
        .await?;
        Ok(r)
    }

    pub async fn delete(&self, id: &str) -> Result<(), String> {
        self.mutate(id, |c, _| {
            let i = find_rule(c, id)?;
            c.rules.remove(i);
            Ok(())
        })
        .await
    }

    pub async fn toggle(&self, id: &str, enabled: bool) -> Result<(), String> {
        if enabled && let Some(r) = self.store.get().rules.iter().find(|r| r.id == id) {
            let mut r = r.clone();
            r.enabled = true;
            self.check_resolvable(&r).await?;
        }
        self.mutate(id, |c, own| {
            let i = find_rule(c, id)?;
            let mut r = c.rules[i].clone();
            r.enabled = enabled;
            if enabled {
                validate_rule(c, &mut r, own)?;
            }
            c.rules[i] = r;
            Ok(())
        })
        .await
    }

    /// 重新应用规则（例如安装依赖后）。
    pub async fn reapply(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().await;
        inner.apply(&self.store.get().rules).await;
        if inner.sync_err.is_empty() {
            Ok(())
        } else {
            Err(inner.sync_err.clone())
        }
    }

    /// 后端的运行模式（目前仅 nftables 有 map / linear 之分）。
    pub async fn backend_mode(&self) -> &'static str {
        self.inner
            .lock()
            .await
            .backend
            .as_ref()
            .map_or("", Backend::mode)
    }

    /// 检查监听端口冲突。check_system 为 false 时只检查规则与面板端口。
    pub async fn check_port(
        &self,
        proto: &str,
        port: i64,
        exclude_id: &str,
        check_system: bool,
    ) -> Vec<Conflict> {
        let own = self.inner.lock().await.own_pids();
        check_port(
            &self.store.get(),
            proto,
            port,
            exclude_id,
            check_system,
            &own,
        )
    }

    /// 切换转发后端，失败时回滚到原后端。
    pub async fn set_backend(&self, name: &str) -> Result<(), String> {
        if !model::valid_backend(name) {
            return Err(format!("未知后端: {name}"));
        }
        let mut inner = self.inner.lock().await;
        if inner.backend.as_ref().is_some_and(|b| b.name() == name) {
            return Ok(());
        }
        let mut nb = Backend::new(name).unwrap();
        nb.available()?;
        let cfg = self.store.get();
        for r in &cfg.rules {
            r.clone()
                .validate(name)
                .map_err(|e| format!("规则「{}」不适用于 {name} 后端: {e}", r.name))?;
        }
        // 旧后端清理失败时不能继续：残留的旧转发会与新后端同时生效。恢复旧后端的完整规则后返回错误
        if let Some(Err(e)) = match inner.backend.as_mut() {
            Some(b) => Some(b.cleanup().await),
            None => None,
        } {
            inner.apply(&cfg.rules).await;
            return Err(format!("切换到 {name} 失败: {e}"));
        }
        let eff = inner.effective(&cfg.rules);
        let res = match nb.sync(&eff).await {
            Err(e) => Err(format!("切换到 {name} 失败: {e}")),
            Ok(()) => self.store.update(|c| {
                c.backend = name.to_string();
                Ok(())
            }),
        };
        if let Err(e) = res {
            if let Err(ce) = nb.cleanup().await {
                crate::logln!("回滚时清除 {name} 转发规则失败: {ce}");
            }
            inner.apply(&cfg.rules).await;
            return Err(e);
        }
        inner.backend = Some(nb);
        inner.sync_err.clear();
        Ok(())
    }
}

impl Manager {
    /// 检测规则的本机监听端口与目标端口。本机检测连接本机出口 IP 而非 127.0.0.1，
    /// 使流量经过与外部客户端相同的用户态进程 / DNAT 规则（DNAT 后源地址为回环会被内核丢弃）。
    pub async fn probe(&self, id: &str) -> Result<ProbeResult, String> {
        let cfg = self.store.get();
        let r = cfg.rules[find_rule(&cfg, id)?].clone();
        let (host, port) = r.target_host_port()?;
        let user_space = model::user_space(&cfg.backend);
        let target_ip = match kernel::resolve_host(&host, "").await {
            Ok(ip) => Ok(ip),
            // 用户态后端可转发到回环地址/域名，回环地址被 resolve_host 排除，这里直接使用原始主机名
            Err(_) if user_space => Ok(host.clone()),
            Err(e) => Err(e),
        };
        let mut local_ip = probe::local_ip(target_ip.as_deref().unwrap_or_default());
        if local_ip.is_empty() {
            local_ip = "127.0.0.1".into();
        }
        let local_addr = format!("{local_ip}:{}", r.listen_port);
        let run = |proto: &'static str, addr: String, hold: bool| async move {
            if proto == model::PROTO_UDP {
                probe::udp(&addr, PROBE_TIMEOUT).await
            } else if hold {
                probe::tcp(&addr, PROBE_TIMEOUT, Duration::from_millis(1500)).await
            } else {
                probe::tcp(&addr, PROBE_TIMEOUT, Duration::ZERO).await
            }
        };
        let mut local = Vec::new();
        let mut target = Vec::new();
        for proto in r.protos() {
            local.push(async {
                if r.enabled {
                    run(proto, local_addr.clone(), user_space).await
                } else {
                    probe::Check::skipped(proto, &local_addr, "规则未启用")
                }
            });
            let t = target_ip.clone();
            let rt = r.target.clone();
            target.push(async move {
                match t {
                    Ok(ip) => run(proto, format!("{ip}:{port}"), false).await,
                    Err(e) => probe::Check::fail(proto, &rt, e),
                }
            });
        }
        let (local, target) = tokio::join!(
            futures_util::future::join_all(local),
            futures_util::future::join_all(target)
        );
        Ok(ProbeResult { local, target })
    }
}

fn find_rule(c: &Config, id: &str) -> Result<usize, String> {
    c.rules
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| "规则不存在".to_string())
}

/// 校验规则与端口冲突；停用的规则不检查系统占用。
fn validate_rule(c: &Config, r: &mut Rule, own: &[i32]) -> Result<(), String> {
    r.validate(&c.backend)?;
    conflict_err(&check_port(
        c,
        &r.proto,
        r.listen_port,
        &r.id,
        r.enabled,
        own,
    ))
}

/// 检查监听端口冲突。check_system 为 false 时只检查规则与面板端口。
pub fn check_port(
    cfg: &Config,
    proto: &str,
    port: i64,
    exclude_id: &str,
    check_system: bool,
    own: &[i32],
) -> Vec<Conflict> {
    let mut out = Vec::new();
    for r in &cfg.rules {
        if r.id != exclude_id && r.listen_port == port && model::proto_overlap(&r.proto, proto) {
            out.push(Conflict {
                kind: "rule",
                proto: r.proto.clone(),
                message: format!("与规则「{}」({}/{}) 冲突", r.name, r.proto, r.listen_port),
            });
        }
    }
    if port == config::panel_port(&cfg.listen) && model::proto_overlap(proto, model::PROTO_TCP) {
        out.push(Conflict {
            kind: "panel",
            proto: model::PROTO_TCP.into(),
            message: "与管理面板端口冲突".into(),
        });
    }
    if !check_system {
        return out;
    }
    let listeners = portcheck::listeners(true);
    let probe = Rule {
        proto: proto.into(),
        ..Default::default()
    };
    for p in probe.protos() {
        let mut found = false;
        for l in listeners
            .iter()
            .filter(|l| l.proto == p && l.port == port && l.blocks_ipv4())
        {
            found = true;
            if l.pid > 0 && (own.contains(&l.pid) || own.contains(&portcheck::parent_pid(l.pid))) {
                continue;
            }
            let who = if l.process.is_empty() {
                "未知进程".to_string()
            } else {
                format!("{} (pid {})", l.process, l.pid)
            };
            out.push(Conflict {
                kind: "system",
                proto: p.into(),
                message: format!("{p} 端口 {port} 已被 {who} 占用 ({})", l.addr),
            });
            break;
        }
        if !found && let Err(e) = portcheck::bind_test(p, port) {
            out.push(Conflict {
                kind: "system",
                proto: p.into(),
                message: format!("{p} 端口 {port} 无法绑定: {e}"),
            });
        }
    }
    out
}

fn conflict_err(cs: &[Conflict]) -> Result<(), String> {
    if cs.is_empty() {
        return Ok(());
    }
    let msgs: Vec<&str> = cs.iter().map(|c| c.message.as_str()).collect();
    Err(format!("端口冲突: {}", msgs.join("；")))
}
