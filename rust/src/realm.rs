//! 通过监管 realm 子进程实现转发，每条规则每个协议一个进程，对应 Go 版 internal/backend 的
//! realm.go 与 process.go。realm 单进程虽可同时转发 tcp/udp，但某个协议绑定失败时只会结束对应任务、
//! 进程继续运行，拆开后任一协议失败都能被监管发现。

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

use crate::backend::{RuleStatus, check_tool, enabled, exit_text};
use crate::model::{self, Rule};
use crate::sysinfo;

const TOOL: &str = model::BACKEND_REALM;

/// 新启动的进程存活这么久即视为启动成功；端口被占用、权限不足等错误会在此之前退出。
const STARTUP_GRACE: Duration = Duration::from_millis(500);

/// 某条规则某个协议的 realm 参数。
pub fn realm_args(r: &Rule, proto: &str) -> Vec<String> {
    let (host, port) = r.target_host_port().unwrap_or_default();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let mut a = vec![
        "-l".into(),
        format!("0.0.0.0:{}", r.listen_port),
        "-r".into(),
        format!("{host}:{port}"),
    ];
    if proto == model::PROTO_UDP {
        // UDP 会话超时与内置后端保持一致
        a.extend(["-u", "-t", "--udp-timeout", "120"].map(String::from));
    }
    a
}

/// 保留子进程 stderr 的最后一部分。
#[derive(Default)]
struct TailBuffer(Vec<u8>);

impl TailBuffer {
    fn write(&mut self, p: &[u8]) {
        self.0.extend_from_slice(p);
        if self.0.len() > 2048 {
            self.0.drain(..self.0.len() - 2048);
        }
    }

    /// 最后一行有效输出，跳过 Rust panic 附带的 "note: run with RUST_BACKTRACE=1" 提示。
    fn last_line(&self) -> String {
        let s = String::from_utf8_lossy(&self.0);
        let lines: Vec<&str> = s.trim().split('\n').collect();
        for l in lines.iter().skip(1).rev() {
            let l = l.trim();
            if !l.is_empty() && !l.starts_with("note:") {
                return l.to_string();
            }
        }
        lines[0].trim().to_string()
    }
}

#[derive(Default)]
struct ProcState {
    label: String,
    pid: i32,
    restarts: i64,
    last_err: String,
}

struct Proc {
    proto: &'static str,
    rule: Rule,
    state: Arc<Mutex<ProcState>>,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

impl Proc {
    fn spawn(
        bin: PathBuf,
        r: &Rule,
        proto: &'static str,
    ) -> (Proc, oneshot::Receiver<Result<(), String>>) {
        let (tx, rx) = oneshot::channel();
        let state = Arc::new(Mutex::new(ProcState {
            label: format!("{}/{proto}", r.name),
            ..Default::default()
        }));
        let stop = CancellationToken::new();
        let task = tokio::spawn(supervise(
            bin,
            realm_args(r, proto),
            state.clone(),
            stop.clone(),
            tx,
        ));
        (
            Proc {
                proto,
                rule: r.clone(),
                state,
                stop,
                task,
            },
            rx,
        )
    }

    async fn stop(self) {
        self.stop.cancel();
        let _ = self.task.await;
    }
}

fn kill_group(pid: i32, sig: i32) {
    // SAFETY: 向以 pid 为组长的进程组发信号，pid > 0
    unsafe { libc::kill(-pid, sig) };
}

/// 运行并监管一个 realm 进程：退出后按 1s 起指数退避（最长 30s）重启，运行超过 30s 后退避复位。
/// 首次启动的结果（存活过 STARTUP_GRACE 或提前退出）经 ready 报告一次。
async fn supervise(
    bin: PathBuf,
    args: Vec<String>,
    st: Arc<Mutex<ProcState>>,
    stop: CancellationToken,
    ready: oneshot::Sender<Result<(), String>>,
) {
    let mut ready = Some(ready);
    let mut report = |res: Result<(), String>| {
        if let Some(tx) = ready.take() {
            let _ = tx.send(res);
        }
    };
    let mut backoff = Duration::from_secs(1);
    loop {
        let mut cmd = tokio::process::Command::new(&bin);
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // 独立进程组便于整组终止；lport 意外退出时子进程随之结束
        cmd.process_group(0);
        let parent = std::process::id() as libc::pid_t;
        // SAFETY: pre_exec 闭包在 fork 后的子进程中执行，只调用异步信号安全的系统调用，不分配内存
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // 与 Go 的 SysProcAttr.Pdeathsig 一致：fork 之后、prctl 之前 lport 已退出时，
                // 死亡信号不会补发，子进程已被重新托管，需自行结束
                if libc::getppid() != parent {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                }
                Ok(())
            });
        }
        let started = Instant::now();
        let msg = match cmd.spawn() {
            Err(e) => e.to_string(),
            Ok(mut child) => {
                let pid = child.id().unwrap_or(0) as i32;
                st.lock().unwrap().pid = pid;
                let tail = Arc::new(Mutex::new(TailBuffer::default()));
                let mut reader = child.stderr.take().map(|mut e| {
                    let tail = tail.clone();
                    tokio::spawn(async move {
                        let mut b = [0u8; 1024];
                        while let Ok(n) = e.read(&mut b).await {
                            if n == 0 {
                                break;
                            }
                            tail.lock().unwrap().write(&b[..n]);
                        }
                    })
                });
                let grace = sleep(STARTUP_GRACE);
                tokio::pin!(grace);
                let mut graced = false;
                let status = loop {
                    tokio::select! {
                        s = child.wait() => break s,
                        _ = &mut grace, if !graced => {
                            graced = true;
                            report(Ok(()));
                        }
                        _ = stop.cancelled() => {
                            kill_group(pid, libc::SIGTERM);
                            if timeout(Duration::from_secs(3), child.wait()).await.is_err() {
                                kill_group(pid, libc::SIGKILL);
                                let _ = child.wait().await;
                            }
                            if let Some(r) = reader {
                                r.abort();
                            }
                            report(Err("stopped".into()));
                            return;
                        }
                    }
                };
                // 监听进程退出后，fork 出的子进程可能仍持有 stderr 管道，最多等 2 秒读取剩余输出；
                // 超时须中止读取任务，否则丢弃句柄只会让它在后台继续持有管道，每次重启泄漏一个描述符
                if let Some(r) = reader.as_mut()
                    && timeout(Duration::from_secs(2), &mut *r).await.is_err()
                {
                    r.abort();
                    let _ = r.await;
                }
                let line = tail.lock().unwrap().last_line();
                match (line.is_empty(), status) {
                    (false, _) => line,
                    (true, Ok(s)) if !s.success() => exit_text(s),
                    (true, Err(e)) => e.to_string(),
                    _ => "进程已退出".into(),
                }
            }
        };
        let label = {
            let mut s = st.lock().unwrap();
            s.pid = 0;
            s.restarts += 1;
            s.last_err = msg.clone();
            s.label.clone()
        };
        crate::logln!("{TOOL} {label} 退出: {msg}");
        report(Err(msg));
        if started.elapsed() > Duration::from_secs(30) {
            backoff = Duration::from_secs(1);
        }
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

#[derive(Default)]
pub struct Realm {
    /// rule id → 每个协议一个进程
    procs: HashMap<String, Vec<Proc>>,
    /// 测试时替换 realm 可执行文件
    bin: Option<PathBuf>,
}

impl Realm {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn sync(&mut self, rules: &[Rule]) -> Result<(), String> {
        let bin = match &self.bin {
            Some(b) => b.clone(),
            None => {
                check_tool(TOOL)?;
                // 每次启动时查找，工具升级或安装位置变化后无需重启 lport
                sysinfo::tool_path(TOOL).unwrap_or_else(|| TOOL.into())
            }
        };
        let want: Vec<&Rule> = enabled(rules).collect();
        // 先停掉删除或变更的规则，释放端口
        let stale: Vec<String> = self
            .procs
            .iter()
            .filter(|(id, ps)| {
                !want
                    .iter()
                    .any(|r| &r.id == *id && ps.first().is_some_and(|p| p.rule.same_forward(r)))
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            for p in self.procs.remove(&id).unwrap_or_default() {
                p.stop().await;
            }
        }
        let mut started = Vec::new();
        for r in want {
            if let Some(ps) = self.procs.get_mut(&r.id) {
                for p in ps {
                    // 名称等非转发字段更新
                    p.state.lock().unwrap().label = format!("{}/{}", r.name, p.proto);
                    p.rule = r.clone();
                }
                continue;
            }
            let (ps, readies): (Vec<Proc>, Vec<_>) = r
                .protos()
                .into_iter()
                .map(|proto| Proc::spawn(bin.clone(), r, proto))
                .unzip();
            self.procs.insert(r.id.clone(), ps);
            started.push((r.id.clone(), readies));
        }
        // 等待新进程的首次启动结果：启动即失败的规则整体停止并返回错误，由调用方回滚
        let mut errs = Vec::new();
        for (id, readies) in started {
            let mut failed = false;
            for (p, rx) in self.procs[&id].iter().zip(readies) {
                if let Err(e) = rx.await.unwrap_or_else(|_| Err("进程已退出".into())) {
                    failed = true;
                    errs.push(format!(
                        "{TOOL} 启动失败（{}/{}）: {e}",
                        p.proto, p.rule.listen_port
                    ));
                }
            }
            if failed {
                for p in self.procs.remove(&id).unwrap_or_default() {
                    p.stop().await;
                }
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("；"))
        }
    }

    pub fn status(&self) -> HashMap<String, RuleStatus> {
        self.procs
            .iter()
            .map(|(id, ps)| {
                let mut st = RuleStatus::new("running", "");
                let mut errs = Vec::new();
                for p in ps {
                    let s = p.state.lock().unwrap();
                    if s.pid > 0 {
                        st.pids.push(s.pid);
                    } else {
                        st.state = "error".into();
                    }
                    st.restarts += s.restarts;
                    if !s.last_err.is_empty() {
                        errs.push(format!("{}: {}", p.proto, s.last_err));
                    }
                }
                if st.state == "error" {
                    st.message = errs.join("; ");
                }
                (id.clone(), st)
            })
            .collect()
    }

    /// 所有转发主进程 pid，用于端口占用检查时排除自身。
    pub fn pids(&self) -> Vec<i32> {
        self.procs
            .values()
            .flatten()
            .map(|p| p.state.lock().unwrap().pid)
            .filter(|&p| p > 0)
            .collect()
    }

    pub async fn cleanup(&mut self) {
        let all: Vec<Proc> = self.procs.drain().flat_map(|(_, ps)| ps).collect();
        let mut set = tokio::task::JoinSet::new();
        for p in all {
            set.spawn(p.stop());
        }
        set.join_all().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// 写一个假的 realm 脚本，返回 (Realm, 临时目录)。
    fn fake(script: &str) -> (Realm, PathBuf) {
        let dir = std::env::temp_dir().join(format!("lport-test-{}", crate::config::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("realm");
        std::fs::write(&bin, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        (
            Realm {
                bin: Some(bin),
                ..Default::default()
            },
            dir,
        )
    }

    fn rule(proto: &str) -> Rule {
        Rule {
            id: "r".into(),
            name: "r".into(),
            proto: proto.into(),
            listen_port: 18000,
            target: "127.0.0.1:9".into(),
            enabled: true,
            ..Default::default()
        }
    }

    /// 读取脚本记录的后台子进程 pid；进程刚启动时脚本可能还没写入，稍等片刻。
    async fn read_child(dir: &std::path::Path, pid: i32) -> i32 {
        let path = dir.join(format!("child.{pid}"));
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(n) = std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| s.trim().parse().ok())
            {
                return n;
            }
            assert!(Instant::now() < deadline, "脚本未写入 {}", path.display());
            sleep(Duration::from_millis(20)).await;
        }
    }

    fn alive(pid: i32) -> bool {
        // SAFETY: 信号 0 只检查进程是否存在
        unsafe { libc::kill(pid, 0) == 0 }
    }

    // 启动即失败时 Sync 返回 stderr 最后一行且不保留该规则
    #[tokio::test]
    async fn startup_failure() {
        let (mut b, dir) = fake(
            "echo 'thread panicked at x' >&2; echo '[tcp]failed to bind 0.0.0.0:18000: Address already in use' >&2; exit 101",
        );
        let err = b.sync(&[rule("both")]).await.unwrap_err();
        assert!(
            err.contains("realm 启动失败（tcp/18000）: [tcp]failed to bind"),
            "{err}"
        );
        assert!(b.status().is_empty(), "失败的规则不应保留");
        std::fs::remove_dir_all(dir).unwrap();
    }

    // 正常运行、崩溃后自动重启、停止时整个进程组（含 fork 出的子进程）被终止
    #[tokio::test]
    async fn supervise_restart_and_stop() {
        let (mut b, dir) =
            fake("sleep 300 & echo $! > \"$(dirname \"$0\")/child.$$\"; exec sleep 300");
        b.sync(&[rule("tcp")]).await.unwrap();
        let st = &b.status()["r"];
        assert_eq!((st.state.as_str(), st.pids.len()), ("running", 1), "{st:?}");
        let pid = st.pids[0];
        let child = read_child(&dir, pid).await;
        assert!(alive(child));

        // 主进程被杀后自动重启：fork 出的子进程仍持有 stderr，最多等 2 秒，再退避 1 秒
        // SAFETY: 测试启动的进程
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            let st = &b.status()["r"];
            if st.restarts == 1 && st.state == "running" {
                assert_ne!(st.pids[0], pid);
                break;
            }
            assert!(Instant::now() < deadline, "未自动重启: {st:?}");
            sleep(Duration::from_millis(50)).await;
        }
        let pid2 = b.pids()[0];
        let child2 = read_child(&dir, pid2).await;

        b.cleanup().await;
        sleep(Duration::from_millis(100)).await;
        assert!(!alive(pid2) && !alive(child2), "停止后进程组应全部退出");
        assert!(b.status().is_empty());
        // SAFETY: 清理第一轮被杀主进程留下的子进程
        unsafe { libc::kill(child, libc::SIGKILL) };
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn args() {
        let r = |proto: &str, port, target: &str| Rule {
            proto: proto.into(),
            listen_port: port,
            target: target.into(),
            ..Default::default()
        };
        assert_eq!(
            realm_args(&r("tcp", 8080, "10.0.0.5:80"), "tcp").join(" "),
            "-l 0.0.0.0:8080 -r 10.0.0.5:80"
        );
        assert_eq!(
            realm_args(&r("both", 5353, "10.0.0.6:53"), "udp").join(" "),
            "-l 0.0.0.0:5353 -r 10.0.0.6:53 -u -t --udp-timeout 120"
        );
    }

    fn pipe_fds() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter(|e| {
                std::fs::read_link(e.path()).is_ok_and(|l| l.to_string_lossy().starts_with("pipe:"))
            })
            .count()
    }

    // 后台子进程一直持有 stderr 时，反复重启不能累积读取任务与管道描述符
    #[tokio::test]
    async fn restart_does_not_leak_stderr_reader() {
        let (mut b, dir) =
            fake("sleep 30 & echo $! >> \"$(dirname \"$0\")/kids\"; sleep 0.6; exit 1");
        b.sync(&[rule("tcp")]).await.unwrap();
        let mut counts = Vec::new();
        for _ in 0..3 {
            let r = b.status()["r"].restarts;
            while b.status()["r"].restarts == r {
                sleep(Duration::from_millis(50)).await;
            }
            counts.push(pipe_fds());
        }
        b.cleanup().await;
        for pid in std::fs::read_to_string(dir.join("kids"))
            .unwrap()
            .split_whitespace()
        {
            // SAFETY: 测试脚本启动的后台进程
            unsafe { libc::kill(pid.parse().unwrap(), libc::SIGKILL) };
        }
        std::fs::remove_dir_all(dir).unwrap();
        // 其它并发测试也会打开管道，只要求不随重启次数单调增长
        assert!(
            !(counts[0] < counts[1] && counts[1] < counts[2]),
            "每次重启后管道 fd 持续增长: {counts:?}"
        );
    }

    // realm 绑定失败时以 Rust panic 退出，需取 panic 消息而不是末尾的 RUST_BACKTRACE 提示
    #[test]
    fn tail_last_line() {
        let mut b = TailBuffer::default();
        b.write(
            b"thread 'tokio-runtime-worker' panicked at realm_core/src/tcp/mod.rs:37:58:\n\
              [tcp]failed to bind 0.0.0.0:80: Address already in use (os error 98)\n\
              note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n",
        );
        assert_eq!(
            b.last_line(),
            "[tcp]failed to bind 0.0.0.0:80: Address already in use (os error 98)"
        );
        let mut c = TailBuffer::default();
        c.write(b"bind: Address in use\n");
        assert_eq!(c.last_line(), "bind: Address in use");
    }
}
