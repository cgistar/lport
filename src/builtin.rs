//! 在 lport 进程内实现 TCP/UDP 转发，不依赖外部工具。

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::backend::RuleStatus;
use crate::model::{self, Rule};
use crate::splice;

/// 连接目标的超时；域名目标每个新连接 / UDP 会话都会重新解析。
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// UDP 会话空闲超时，与 realm 后端保持一致。
const UDP_IDLE: Duration = Duration::from_secs(120);
/// 每条规则的 UDP 会话上限，防止大量源地址耗尽文件描述符。
const MAX_UDP_SESSIONS: usize = 4096;
const BUF_SIZE: usize = 64 * 1024;
const BACKLOG: u32 = 4096;

#[derive(Default)]
pub struct Builtin {
    /// rule id → 每个协议一个转发器
    fwds: HashMap<String, Vec<Forwarder>>,
}

impl Builtin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name(&self) -> &'static str {
        model::BACKEND_BUILTIN
    }

    /// 按启用的规则全量同步（幂等）。
    pub async fn sync(&mut self, rules: &[Rule]) -> Result<(), String> {
        let want: Vec<&Rule> = rules.iter().filter(|r| r.enabled).collect();
        // 先停掉删除或变更的规则，释放端口
        let stale: Vec<String> = self
            .fwds
            .iter()
            .filter(|(id, fs)| {
                !want
                    .iter()
                    .any(|r| &r.id == *id && fs.first().is_some_and(|f| f.rule.same_forward(r)))
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            for f in self.fwds.remove(&id).unwrap_or_default() {
                f.stop().await;
            }
        }
        let mut errs = Vec::new();
        for r in want {
            if let Some(fs) = self.fwds.get_mut(&r.id) {
                for f in fs {
                    f.set_rule(r); // 名称等非转发字段更新
                }
                continue;
            }
            let mut fs = Vec::new();
            for proto in r.protos() {
                match Forwarder::start(r, proto).await {
                    Ok(f) => fs.push(f),
                    Err(e) => {
                        errs.push(format!(
                            "{} 启动失败（{proto}/{}）: {e}",
                            self.name(),
                            r.listen_port
                        ));
                        break;
                    }
                }
            }
            // 某个协议失败时整条规则不启动，由调用方回滚
            if fs.len() != r.protos().len() {
                for f in fs {
                    f.stop().await;
                }
                continue;
            }
            self.fwds.insert(r.id.clone(), fs);
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("；"))
        }
    }

    pub fn status(&self) -> HashMap<String, RuleStatus> {
        self.fwds
            .iter()
            .map(|(id, fs)| {
                let errs: Vec<String> = fs
                    .iter()
                    .filter_map(|f| {
                        let e = f.shared.err.lock().unwrap();
                        (!e.is_empty()).then(|| format!("{}: {e}", f.proto))
                    })
                    .collect();
                let state = if errs.is_empty() { "running" } else { "error" };
                (id.clone(), RuleStatus::new(state, errs.join("; ")))
            })
            .collect()
    }

    /// lport 自身 pid：转发端口由本进程监听，端口占用检查时排除。
    pub fn pids(&self) -> Vec<i32> {
        vec![std::process::id() as i32]
    }

    /// 停止全部转发。
    pub async fn cleanup(&mut self) {
        for (_, fs) in self.fwds.drain() {
            for f in fs {
                f.stop().await;
            }
        }
    }

    /// 某条规则的活动连接数（TCP 每个客户端连接计 1，UDP 每个会话计 1），供测试使用。
    #[cfg(test)]
    fn active(&self, id: &str) -> usize {
        self.fwds[id]
            .iter()
            .map(|f| f.shared.active.load(Ordering::SeqCst))
            .sum()
    }
}

/// 转发器与其上各任务共享的状态。
struct Shared {
    label: Mutex<String>,
    /// 最近一次 accept / 读取错误，恢复后清空
    err: Mutex<String>,
    active: AtomicUsize,
    sessions: Mutex<HashMap<SocketAddr, Arc<UdpSession>>>,
}

impl Shared {
    fn set_err(&self, e: String) {
        let mut cur = self.err.lock().unwrap();
        if *cur != e && !e.is_empty() {
            crate::logln!("builtin {}: {e}", self.label.lock().unwrap());
        }
        *cur = e;
    }

    fn track(self: &Arc<Self>) -> ActiveGuard {
        self.active.fetch_add(1, Ordering::SeqCst);
        ActiveGuard(self.clone())
    }
}

struct ActiveGuard(Arc<Shared>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 一条规则一个协议的监听及其上的全部连接。
struct Forwarder {
    proto: &'static str,
    rule: Rule,
    shared: Arc<Shared>,
    token: CancellationToken,
    tracker: TaskTracker,
}

impl Forwarder {
    async fn start(r: &Rule, proto: &'static str) -> io::Result<Forwarder> {
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, r.listen_port as u16));
        let f = Forwarder {
            proto,
            rule: r.clone(),
            shared: Arc::new(Shared {
                label: Mutex::new(format!("{}/{proto}", r.name)),
                err: Mutex::default(),
                active: AtomicUsize::new(0),
                sessions: Mutex::default(),
            }),
            token: CancellationToken::new(),
            tracker: TaskTracker::new(),
        };
        let ctx = Ctx {
            target: Arc::from(r.target.as_str()),
            shared: f.shared.clone(),
            token: f.token.clone(),
            tracker: f.tracker.clone(),
        };
        if proto == model::PROTO_UDP {
            let sock = Arc::new(UdpSocket::bind(addr).await?);
            f.tracker.spawn(serve_udp(sock, ctx));
        } else {
            let sock = TcpSocket::new_v4()?;
            sock.set_reuseaddr(true)?;
            sock.bind(addr)?;
            f.tracker.spawn(serve_tcp(sock.listen(BACKLOG)?, ctx));
        }
        Ok(f)
    }

    fn set_rule(&mut self, r: &Rule) {
        *self.shared.label.lock().unwrap() = format!("{}/{}", r.name, self.proto);
        self.rule = r.clone();
    }

    /// 关闭监听与全部连接，并等待所有任务退出（端口随即可重新绑定）。
    async fn stop(self) {
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }
}

#[derive(Clone)]
struct Ctx {
    target: Arc<str>,
    shared: Arc<Shared>,
    token: CancellationToken,
    tracker: TaskTracker,
}

/// 读取 / accept 出现非关闭错误（如文件描述符耗尽）时的退避，最长 1 秒。
fn retry_delay(d: Duration) -> Duration {
    if d.is_zero() {
        Duration::from_millis(5)
    } else {
        (d * 2).min(Duration::from_secs(1))
    }
}

/// 出错后退避；返回 false 表示转发器已停止。
async fn backoff(ctx: &Ctx, delay: &mut Duration, e: io::Error) -> bool {
    ctx.shared.set_err(e.to_string());
    *delay = retry_delay(*delay);
    tokio::select! {
        _ = ctx.token.cancelled() => false,
        _ = sleep(*delay) => true,
    }
}

fn recovered(ctx: &Ctx, delay: &mut Duration) {
    if !delay.is_zero() {
        *delay = Duration::ZERO;
        ctx.shared.set_err(String::new());
    }
}

/// 解析目标的 IPv4 地址（与 Go 版的 tcp4 / udp4 一致）。
async fn resolve4(target: &str) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target)
        .await?
        .filter(SocketAddr::is_ipv4)
        .collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{target} 没有 IPv4 地址"),
        ));
    }
    Ok(addrs)
}

async fn dial_tcp(target: &str) -> io::Result<TcpStream> {
    timeout(DIAL_TIMEOUT, async {
        let mut last = None;
        for a in resolve4(target).await? {
            match TcpStream::connect(a).await {
                Ok(c) => return Ok(c),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "连接目标超时"))?
}

async fn serve_tcp(ln: TcpListener, ctx: Ctx) {
    let mut delay = Duration::ZERO;
    loop {
        let res = tokio::select! {
            _ = ctx.token.cancelled() => return,
            r = ln.accept() => r,
        };
        match res {
            Ok((c, _)) => {
                recovered(&ctx, &mut delay);
                ctx.tracker.spawn(handle_tcp(c, ctx.clone()));
            }
            Err(e) => {
                if !backoff(&ctx, &mut delay, e).await {
                    return;
                }
            }
        }
    }
}

async fn handle_tcp(c: TcpStream, ctx: Ctx) {
    let _guard = ctx.shared.track();
    tokio::select! {
        _ = ctx.token.cancelled() => {}
        _ = async {
            // 与 realm 等用户态代理一致：连不上目标时直接关闭客户端连接
            let Ok(up) = dial_tcp(&ctx.target).await else { return };
            let _ = c.set_nodelay(true);
            let _ = up.set_nodelay(true);
            pipe(c, up).await;
        } => {}
    }
}

/// 双向转发；返回时两端连接随之关闭。
async fn pipe(c: TcpStream, up: TcpStream) {
    let _ = splice::forward(&c, &up).await;
}

struct UdpSession {
    sock: UdpSocket,
    /// 最近一次收到客户端数据的时间（相对进程内基准的毫秒数）
    last: AtomicU64,
}

fn mono_ms() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_millis() as u64
}

async fn serve_udp(ln: Arc<UdpSocket>, ctx: Ctx) {
    let mut buf = vec![0u8; BUF_SIZE];
    let mut delay = Duration::ZERO;
    loop {
        let res = tokio::select! {
            _ = ctx.token.cancelled() => return,
            r = ln.recv_from(&mut buf) => r,
        };
        let (n, addr) = match res {
            Ok(v) => v,
            Err(e) => {
                if !backoff(&ctx, &mut delay, e).await {
                    return;
                }
                continue;
            }
        };
        recovered(&ctx, &mut delay);
        let s = tokio::select! {
            _ = ctx.token.cancelled() => return,
            s = udp_session(&ln, addr, &ctx) => s,
        };
        if let Some(s) = s {
            // 发送缓冲区满时会等待可写，须响应停止，否则 stop 等不到任务退出、端口无法释放
            tokio::select! {
                _ = ctx.token.cancelled() => return,
                _ = s.sock.send(&buf[..n]) => {}
            }
        }
    }
}

/// 返回客户端对应的会话并续期，不存在时连接目标新建；失败或超过上限时返回 None（丢弃该包）。
/// 续期与 expire 的过期判断在同一把锁下进行：会话要么已续期不会被回收，要么已从表中删除而新建。
async fn udp_session(ln: &Arc<UdpSocket>, addr: SocketAddr, ctx: &Ctx) -> Option<Arc<UdpSession>> {
    {
        let sessions = ctx.shared.sessions.lock().unwrap();
        if let Some(s) = sessions.get(&addr) {
            s.last.store(mono_ms(), Ordering::SeqCst);
            return Some(s.clone());
        }
        if sessions.len() >= MAX_UDP_SESSIONS {
            return None;
        }
    }
    let sock = timeout(DIAL_TIMEOUT, async {
        let target = *resolve4(&ctx.target).await?.first().unwrap();
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        sock.connect(target).await?;
        io::Result::Ok(sock)
    })
    .await
    .ok()?
    .ok()?;
    let s = Arc::new(UdpSession {
        sock,
        last: AtomicU64::new(mono_ms()),
    });
    ctx.shared.sessions.lock().unwrap().insert(addr, s.clone());
    ctx.tracker
        .spawn(udp_reply(ln.clone(), addr, s.clone(), ctx.clone()));
    Some(s)
}

thread_local! {
    /// 各会话共用的接收缓冲区：就绪后在当前线程内同步收包，空闲会话不占用 64KiB 缓冲区。
    static RECV_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; BUF_SIZE]);
}

/// 把目标的回包发回客户端，会话空闲超时或目标不可达（ICMP 拒绝）时结束。
async fn udp_reply(ln: Arc<UdpSocket>, addr: SocketAddr, s: Arc<UdpSession>, ctx: Ctx) {
    let _guard = ctx.shared.track();
    loop {
        let res = tokio::select! {
            _ = ctx.token.cancelled() => break,
            r = timeout(UDP_IDLE, s.sock.readable()) => r,
        };
        match res {
            Ok(Ok(())) => {}
            Ok(Err(_)) => break,
            // 客户端仍在发送，只是目标暂时没有回包
            Err(_) if !expire(&ctx, addr, &s) => continue,
            Err(_) => break,
        }
        // 能直接发出时不复制；监听 socket 发送缓冲区满时复制一份再异步等待
        let pending = RECV_BUF.with_borrow_mut(|buf| match s.sock.try_recv(buf) {
            Ok(n) => match ln.try_send_to(&buf[..n], addr) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Some(buf[..n].to_vec())),
                _ => Ok(None),
            },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        });
        match pending {
            Ok(Some(data)) => {
                tokio::select! {
                    _ = ctx.token.cancelled() => break,
                    _ = ln.send_to(&data, addr) => {}
                }
            }
            Ok(None) => {}
            Err(_) => break,
        }
    }
    let mut sessions = ctx.shared.sessions.lock().unwrap();
    if sessions.get(&addr).is_some_and(|x| Arc::ptr_eq(x, &s)) {
        sessions.remove(&addr);
    }
}

/// 在锁内检查会话是否空闲超时，超时则从表中删除并返回 true。
fn expire(ctx: &Ctx, addr: SocketAddr, s: &Arc<UdpSession>) -> bool {
    let mut sessions = ctx.shared.sessions.lock().unwrap();
    if mono_ms().saturating_sub(s.last.load(Ordering::SeqCst)) < UDP_IDLE.as_millis() as u64 {
        return false;
    }
    if sessions.get(&addr).is_some_and(|x| Arc::ptr_eq(x, s)) {
        sessions.remove(&addr);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn free_port() -> i64 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
            .into()
    }

    /// TCP/UDP 回显服务，回包加上协议前缀。
    async fn echo_server() -> i64 {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let udp = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            loop {
                let (mut c, _) = tcp.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = Vec::new();
                    let _ = c.read_to_end(&mut b).await;
                    let _ = c.write_all(&[b"tcp:".as_slice(), &b].concat()).await;
                });
            }
        });
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            loop {
                let (n, a) = udp.recv_from(&mut b).await.unwrap();
                let _ = udp
                    .send_to(&[b"udp:".as_slice(), &b[..n]].concat(), a)
                    .await;
            }
        });
        port.into()
    }

    async fn tcp_echo(port: i64, msg: &str) -> String {
        let r = timeout(Duration::from_secs(2), async {
            let mut c = TcpStream::connect(("127.0.0.1", port as u16)).await?;
            c.write_all(msg.as_bytes()).await?;
            c.shutdown().await?;
            let mut s = String::new();
            c.read_to_string(&mut s).await?;
            io::Result::Ok(s)
        })
        .await;
        r.ok().and_then(Result::ok).unwrap_or_default()
    }

    async fn udp_echo(port: i64, msg: &str) -> String {
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.connect(("127.0.0.1", port as u16)).await.unwrap();
        c.send(msg.as_bytes()).await.unwrap();
        let mut b = [0u8; 1500];
        match timeout(Duration::from_secs(2), c.recv(&mut b)).await {
            Ok(Ok(n)) => String::from_utf8_lossy(&b[..n]).into(),
            _ => String::new(),
        }
    }

    fn rule(id: &str, proto: &str, port: i64, target: String) -> Rule {
        Rule {
            id: id.into(),
            name: id.into(),
            proto: proto.into(),
            listen_port: port,
            target,
            enabled: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn forward() {
        let echo = echo_server().await;
        let (lp, lp2) = (free_port(), free_port());
        let mut b = Builtin::new();
        let mut rules = vec![
            rule("ip", "both", lp, format!("127.0.0.1:{echo}")),
            rule("dn", "tcp", lp2, format!("localhost:{echo}")),
        ];
        b.sync(&rules).await.unwrap();
        assert_eq!(tcp_echo(lp, "hi").await, "tcp:hi");
        assert_eq!(udp_echo(lp, "hi").await, "udp:hi");
        assert_eq!(tcp_echo(lp2, "dn").await, "tcp:dn", "域名目标");
        assert_eq!(b.status()["ip"].state, "running");

        // 目标不可达：接受后立即关闭客户端连接
        rules[1].target = format!("127.0.0.1:{}", free_port());
        b.sync(&rules).await.unwrap();
        assert_eq!(tcp_echo(lp2, "x").await, "", "目标不可达时应无回包");

        // 名称变化不重启转发器，已有连接不受影响
        let mut held = TcpStream::connect(("127.0.0.1", lp as u16)).await.unwrap();
        rules[0].name = "renamed".into();
        b.sync(&rules).await.unwrap();
        held.write_all(b"still").await.unwrap();
        held.shutdown().await.unwrap();
        let mut s = String::new();
        held.read_to_string(&mut s).await.unwrap();
        assert_eq!(s, "tcp:still", "未变更的规则不应中断连接");

        // 停用规则后端口释放，已建立的连接被关闭
        let mut c = TcpStream::connect(("127.0.0.1", lp as u16)).await.unwrap();
        sleep(Duration::from_millis(50)).await;
        rules[0].enabled = false;
        b.sync(&rules).await.unwrap();
        let r = timeout(Duration::from_secs(2), c.read(&mut [0u8; 1])).await;
        assert!(
            matches!(r, Ok(Ok(0)) | Ok(Err(_))),
            "停用后连接应被关闭: {r:?}"
        );
        std::net::TcpListener::bind(("0.0.0.0", lp as u16)).expect("停用后端口应释放");
        std::net::UdpSocket::bind(("0.0.0.0", lp as u16)).expect("停用后 UDP 端口应释放");
        assert!(!b.status().contains_key("ip"), "停用的规则不应有状态");
        b.cleanup().await;
    }

    // 某个协议启动失败时整条规则不启动，已启动的协议释放端口
    #[tokio::test]
    async fn partial_start_failure() {
        let lp = free_port();
        let _busy = std::net::UdpSocket::bind(("0.0.0.0", lp as u16)).unwrap();
        let mut b = Builtin::new();
        let err = b
            .sync(&[rule("r", "both", lp, "127.0.0.1:1".into())])
            .await
            .unwrap_err();
        assert!(err.contains("udp"), "{err}");
        assert!(b.status().is_empty());
        std::net::TcpListener::bind(("0.0.0.0", lp as u16)).expect("TCP 端口应已释放");
    }

    // 大量数据经 splice 完整转发
    #[tokio::test]
    async fn large_transfer() {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = up.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut c, _) = up.accept().await.unwrap();
            let (mut r, mut w) = c.split();
            tokio::io::copy(&mut r, &mut w).await.unwrap();
            w.shutdown().await.unwrap();
        });
        let lp = free_port();
        let mut b = Builtin::new();
        b.sync(&[rule("r", "tcp", lp, target)]).await.unwrap();
        let data: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let c = TcpStream::connect(("127.0.0.1", lp as u16)).await.unwrap();
        let (mut r, mut w) = c.into_split();
        let d = data.clone();
        let writer = tokio::spawn(async move {
            w.write_all(&d).await.unwrap();
            w.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        timeout(Duration::from_secs(10), r.read_to_end(&mut got))
            .await
            .unwrap()
            .unwrap();
        writer.await.unwrap();
        assert!(
            got == data,
            "数据不一致: {} / {} 字节",
            got.len(),
            data.len()
        );
        b.cleanup().await;
    }

    // 客户端 RST 断开而上游保持连接时，代理须关闭两端，不能留下滞留的连接
    #[tokio::test]
    async fn client_reset_releases_upstream() {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = up.local_addr().unwrap().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut c, _) = up.accept().await.unwrap();
            // 上游只读不写也不主动关闭，模拟忽略半关闭的服务；读到 EOF 或错误即说明代理已关闭上游
            let mut b = [0u8; 64];
            loop {
                match c.read(&mut b).await {
                    Ok(n) if n > 0 => continue,
                    _ => break,
                }
            }
            let _ = tx.send(());
        });
        let lp = free_port();
        let mut b = Builtin::new();
        b.sync(&[rule("r", "tcp", lp, target)]).await.unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", lp as u16)).await.unwrap();
        c.write_all(b"hi").await.unwrap();
        sleep(Duration::from_millis(100)).await;
        c.set_zero_linger().unwrap(); // 关闭时发送 RST
        drop(c);
        timeout(Duration::from_secs(3), rx)
            .await
            .expect("上游连接未被关闭")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while b.active("r") > 0 {
            assert!(
                Instant::now() < deadline,
                "客户端 RST 后仍有 {} 个连接未释放",
                b.active("r")
            );
            sleep(Duration::from_millis(20)).await;
        }
        b.cleanup().await;
    }
}
