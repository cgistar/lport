//! 编排配置存储与转发后端，对应 Go 版 internal/manager 的规则管理部分。

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::builtin::{Builtin, RuleStatus};
use crate::config::{self, Config, Store};
use crate::model::{self, Rule};
use crate::portcheck;

/// 端口冲突信息。
#[derive(Debug, Clone)]
pub struct Conflict {
    /// rule | panel | system
    pub kind: &'static str,
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
    backend: Option<Builtin>,
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
        self.backend.as_ref().map(Builtin::pids).unwrap_or_default()
    }
}

pub struct Manager {
    store: Arc<Store>,
    inner: Mutex<Inner>,
}

impl Manager {
    pub fn new(store: Arc<Store>) -> Self {
        Self::with_backend(store, Some(Builtin::new()))
    }

    /// 只修改配置、不应用转发的 Manager，用于服务未运行时在命令行增删规则，
    /// 校验逻辑与运行时一致，规则在服务启动后生效。
    pub fn offline(store: Arc<Store>) -> Self {
        Self::with_backend(store, None)
    }

    fn with_backend(store: Arc<Store>, backend: Option<Builtin>) -> Self {
        Manager {
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

    /// 按配置应用规则。停机期间端口可能已被其它服务占用，与在线启用规则一样检查系统占用，冲突的规则暂不应用。
    pub async fn start(&self) {
        let mut inner = self.inner.lock().await;
        let cfg = self.store.get();
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
    }

    /// 清除所有转发。
    pub async fn stop(&self) {
        if let Some(b) = &mut self.inner.lock().await.backend {
            b.cleanup().await;
        }
    }

    pub async fn rules(&self) -> Vec<RuleView> {
        let inner = self.inner.lock().await;
        let st = inner
            .backend
            .as_ref()
            .map(Builtin::status)
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

    pub async fn create(&self, mut r: Rule) -> Result<Rule, String> {
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
    if !model::user_space(&c.backend) && r.enabled {
        let (host, port) = r.target_host_port()?;
        resolve_host(&host, port)?;
    }
    conflict_err(&check_port(
        c,
        &r.proto,
        r.listen_port,
        &r.id,
        r.enabled,
        own,
    ))
}

/// 内核后端需要把域名解析为非回环的 IPv4。
fn resolve_host(host: &str, port: u16) -> Result<(), String> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("解析 {host} 失败: {e}"))?;
    let ok = addrs
        .into_iter()
        .any(|a| matches!(a.ip(), IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified()));
    if ok {
        Ok(())
    } else {
        Err(format!("{host} 没有可用的 IPv4 地址（不能是回环地址）"))
    }
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
                message: format!("与规则「{}」({}/{}) 冲突", r.name, r.proto, r.listen_port),
            });
        }
    }
    if port == config::panel_port(&cfg.listen) && model::proto_overlap(proto, model::PROTO_TCP) {
        out.push(Conflict {
            kind: "panel",
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
                message: format!("{p} 端口 {port} 已被 {who} 占用 ({})", l.addr),
            });
            break;
        }
        if !found && let Err(e) = portcheck::bind_test(p, port) {
            out.push(Conflict {
                kind: "system",
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
