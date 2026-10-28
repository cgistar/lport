//! 转发后端：内置转发、realm 子进程、iptables、nftables，对应 Go 版 internal/backend。

use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::builtin::Builtin;
use crate::kernel::{Iptables, Nftables};
use crate::model::{self, Rule};
use crate::realm::Realm;
use crate::sysinfo;

/// 规则运行状态，JSON 格式与 Go 版一致。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleStatus {
    /// running | stopped | error | applied
    pub state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pids: Vec<i32>,
    #[serde(skip_serializing_if = "is_zero")]
    pub restarts: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

impl RuleStatus {
    pub fn new(state: &str, message: impl Into<String>) -> Self {
        RuleStatus {
            state: state.into(),
            message: message.into(),
            ..Default::default()
        }
    }
}

pub enum Backend {
    Builtin(Builtin),
    Realm(Realm),
    Iptables(Iptables),
    Nftables(Nftables),
}

impl Backend {
    pub fn new(name: &str) -> Option<Backend> {
        Some(match name {
            model::BACKEND_BUILTIN => Backend::Builtin(Builtin::new()),
            model::BACKEND_REALM => Backend::Realm(Realm::new()),
            model::BACKEND_IPTABLES => Backend::Iptables(Iptables::default()),
            model::BACKEND_NFTABLES => Backend::Nftables(Nftables::default()),
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Backend::Builtin(_) => model::BACKEND_BUILTIN,
            Backend::Realm(_) => model::BACKEND_REALM,
            Backend::Iptables(_) => model::BACKEND_IPTABLES,
            Backend::Nftables(_) => model::BACKEND_NFTABLES,
        }
    }

    /// 后端依赖的工具是否可用。
    #[cfg(test)]
    pub fn available(&self) -> Result<(), String> {
        match self {
            Backend::Builtin(_) => Ok(()),
            b => check_tool(b.name()),
        }
    }

    /// 按启用的规则全量同步（幂等）。
    pub async fn sync(&mut self, rules: &[Rule]) -> Result<(), String> {
        match self {
            Backend::Builtin(b) => b.sync(rules).await,
            Backend::Realm(b) => b.sync(rules).await,
            Backend::Iptables(b) => b.sync(rules).await,
            Backend::Nftables(b) => b.sync(rules).await,
        }
    }

    pub fn status(&self) -> HashMap<String, RuleStatus> {
        match self {
            Backend::Builtin(b) => b.status(),
            Backend::Realm(b) => b.status(),
            Backend::Iptables(b) => b.status(),
            Backend::Nftables(b) => b.status(),
        }
    }

    /// 清除本工具创建的所有转发。
    pub async fn cleanup(&mut self) -> Result<(), String> {
        match self {
            Backend::Builtin(b) => {
                b.cleanup().await;
                Ok(())
            }
            Backend::Realm(b) => {
                b.cleanup().await;
                Ok(())
            }
            Backend::Iptables(b) => b.cleanup().await,
            Backend::Nftables(b) => b.cleanup().await,
        }
    }

    /// 内核后端定期调用：域名解析结果变化时重新应用规则，并修复被外部清除的规则。
    /// 用户态后端自行解析域名、进程退出时自动重启，不需要维护，返回 None。
    pub async fn maintain(&mut self) -> Option<Result<(), String>> {
        match self {
            Backend::Iptables(b) => Some(b.maintain().await),
            Backend::Nftables(b) => Some(b.maintain().await),
            _ => None,
        }
    }

    pub fn is_kernel(&self) -> bool {
        matches!(self, Backend::Iptables(_) | Backend::Nftables(_))
    }

    /// 本工具的转发进程 pid，其占用的端口不算系统占用。
    pub fn pids(&self) -> Vec<i32> {
        match self {
            Backend::Builtin(b) => b.pids(),
            Backend::Realm(b) => b.pids(),
            _ => Vec::new(),
        }
    }

    /// 后端的运行模式（目前仅 nftables 有 map / linear 之分）。
    #[allow(dead_code)]
    pub fn mode(&self) -> &'static str {
        match self {
            Backend::Nftables(b) => b.mode(),
            _ => "",
        }
    }
}

pub fn check_tool(tool: &str) -> Result<(), String> {
    if sysinfo::tool_installed(tool) {
        Ok(())
    } else {
        Err(format!(
            "{tool} 未安装，请先安装（lport detect 查看安装命令）"
        ))
    }
}

pub fn enabled(rules: &[Rule]) -> impl Iterator<Item = &Rule> {
    rules.iter().filter(|r| r.enabled)
}

/// 防火墙命令的执行上限。iptables 的 -w 在 xtables 锁被长期占用时会无限等待
/// （CentOS 7 的 iptables 不支持 -w 秒数），而调用方持有 manager 锁，不能被无限阻塞。
const CMD_TIMEOUT: Duration = Duration::from_secs(30);

/// 执行命令，stdin 非空时作为标准输入；失败时错误中带上命令输出。
pub async fn run(stdin: &str, name: &str, args: &[&str]) -> Result<(), String> {
    let cmdline = format!("{name} {}", args.join(" "));
    let mut cmd = tokio::process::Command::new(name);
    cmd.args(args)
        .stdin(if stdin.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let fut = async {
        let mut child = cmd.spawn().map_err(|e| e.to_string())?;
        if let Some(mut w) = child.stdin.take() {
            w.write_all(stdin.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
        }
        child.wait_with_output().await.map_err(|e| e.to_string())
    };
    let out = match tokio::time::timeout(CMD_TIMEOUT, fut).await {
        Err(_) => return Err(format!("{cmdline}: 执行超时（{}s）", CMD_TIMEOUT.as_secs())),
        Ok(Err(e)) => return Err(format!("{cmdline}: {e}")),
        Ok(Ok(out)) => out,
    };
    if out.status.success() {
        return Ok(());
    }
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Err(format!(
        "{cmdline}: {}: {}",
        exit_text(out.status),
        text.trim()
    ))
}

/// 与 Go 的 exec.ExitError 文案一致：exit status N / signal: N。
pub fn exit_text(st: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (st.code(), st.signal()) {
        (Some(c), _) => format!("exit status {c}"),
        (None, Some(s)) => format!("signal: {s}"),
        _ => st.to_string(),
    }
}

/// 命令是否执行成功（忽略输出），用于 iptables -C 之类的检查。
pub async fn ok(name: &str, args: &[&str]) -> bool {
    run("", name, args).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_reports_output() {
        assert!(run("", "true", &[]).await.is_ok());
        let e = run("", "sh", &["-c", "echo boom >&2; exit 3"])
            .await
            .unwrap_err();
        assert_eq!(e, "sh -c echo boom >&2; exit 3: exit status 3: boom");
        assert!(run("hello", "grep", &["-q", "hello"]).await.is_ok());
        assert!(run("", "/nonexistent-lport-tool", &[]).await.is_err());
    }
}
