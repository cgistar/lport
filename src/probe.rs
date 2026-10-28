//! TCP/UDP 端口连通性检测，用于排查转发故障。

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdp};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

pub const STATE_OK: &str = "ok";
pub const STATE_FAIL: &str = "fail";
/// UDP 无响应，无法判断
pub const STATE_UNKNOWN: &str = "unknown";
pub const STATE_SKIPPED: &str = "skipped";

#[derive(Debug, Clone, Default, Serialize)]
pub struct Check {
    pub proto: String,
    pub addr: String,
    pub state: &'static str,
    pub latency_ms: i64,
    pub message: String,
}

impl Check {
    fn new(proto: &str, addr: &str) -> Self {
        Check {
            proto: proto.into(),
            addr: addr.into(),
            ..Default::default()
        }
    }

    pub fn skipped(proto: &str, addr: &str, msg: &str) -> Self {
        Check {
            state: STATE_SKIPPED,
            message: msg.into(),
            ..Self::new(proto, addr)
        }
    }

    pub fn fail(proto: &str, addr: &str, msg: String) -> Self {
        Check {
            state: STATE_FAIL,
            message: msg,
            ..Self::new(proto, addr)
        }
    }
}

const TIMEOUT_MSG: &str = "连接超时（可能被防火墙丢弃或主机不可达）";

fn describe(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::ECONNREFUSED) => return "连接被拒绝（端口未监听）".into(),
        Some(libc::EHOSTUNREACH) => return "主机不可达".into(),
        Some(libc::ENETUNREACH) => return "网络不可达".into(),
        _ => {}
    }
    if e.kind() == io::ErrorKind::TimedOut {
        return TIMEOUT_MSG.into();
    }
    e.to_string()
}

fn elapsed_ms(start: Instant) -> i64 {
    start.elapsed().as_millis() as i64
}

/// 尝试建立 TCP 连接。hold 非零时建立连接后再观察 hold 时长：用户态代理（内置转发 / realm）会先接受连接
/// 再连目标，目标不可达时会立即关闭连接，仅看握手会误判为成功。
pub async fn tcp(addr: &str, limit: Duration, hold: Duration) -> Check {
    let mut r = Check::new("tcp", addr);
    let start = Instant::now();
    let conn = timeout(limit, TcpStream::connect(addr)).await;
    r.latency_ms = elapsed_ms(start);
    let mut c = match conn {
        Err(_) => return Check::fail("tcp", addr, TIMEOUT_MSG.into()).with_latency(r.latency_ms),
        Ok(Err(e)) => return Check::fail("tcp", addr, describe(&e)).with_latency(r.latency_ms),
        Ok(Ok(c)) => c,
    };
    (r.state, r.message) = (STATE_OK, "连接成功".into());
    if hold.is_zero() {
        return r;
    }
    match timeout(hold, c.read(&mut [0u8; 1])).await {
        Ok(Ok(n)) if n > 0 => r.message = "连接成功，收到数据".into(),
        // 连接保持中，视为成功
        Err(_) => {}
        _ => {
            (r.state, r.message) = (
                STATE_FAIL,
                "连接建立后立即被关闭（转发进程无法连接目标）".into(),
            )
        }
    }
    r
}

impl Check {
    fn with_latency(mut self, ms: i64) -> Self {
        self.latency_ms = ms;
        self
    }
}

/// 发送一个探测包：收到回复为成功，收到 ICMP 端口不可达为失败，超时无响应则无法判断。
pub async fn udp(addr: &str, limit: Duration) -> Check {
    let mut r = Check::new("udp", addr);
    let start = Instant::now();
    let sock = async {
        let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        s.connect(addr).await?;
        s.send(b"lport-probe\n").await?;
        io::Result::Ok(s)
    };
    let s = match timeout(limit, sock).await {
        Err(_) => return Check::fail("udp", addr, TIMEOUT_MSG.into()),
        Ok(Err(e)) => return Check::fail("udp", addr, describe(&e)),
        Ok(Ok(s)) => s,
    };
    let res = timeout(limit, s.recv(&mut [0u8; 512])).await;
    r.latency_ms = elapsed_ms(start);
    match res {
        Ok(Ok(_)) => (r.state, r.message) = (STATE_OK, "收到响应".into()),
        Err(_) => {
            (r.state, r.message) = (
                STATE_UNKNOWN,
                "无响应（UDP 无法确认端口是否开放，服务可能只响应特定协议数据）".into(),
            )
        }
        Ok(Err(e)) => (r.state, r.message) = (STATE_FAIL, describe(&e)),
    }
    r
}

/// 访问目标时使用的本机出口 IPv4；通过 UDP "连接"（不发送数据）让内核选路得到。
pub fn local_ip(target_ip: &str) -> String {
    let via_route = || -> Option<IpAddr> {
        let ip: IpAddr = target_ip.parse().ok()?;
        let s = StdUdp::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        s.connect(SocketAddr::new(ip, 9)).ok()?;
        Some(s.local_addr().ok()?.ip()).filter(|ip| !ip.is_loopback())
    };
    if let Some(ip) = via_route() {
        return ip.to_string();
    }
    interface_ipv4()
        .into_iter()
        .find(|ip| !ip.is_loopback())
        .map(|ip| ip.to_string())
        .unwrap_or_default()
}

/// 所有网卡上的 IPv4 地址。
fn interface_ipv4() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs 成功时返回链表，遍历后由 freeifaddrs 释放；只读取 AF_INET 的 sockaddr_in
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut p = ifap;
        while !p.is_null() {
            let a = (*p).ifa_addr;
            if !a.is_null() && (*a).sa_family as i32 == libc::AF_INET {
                let sin = &*(a as *const libc::sockaddr_in);
                out.push(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
            }
            p = (*p).ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    const T: Duration = Duration::from_secs(2);

    #[tokio::test]
    async fn tcp_states() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            // 第一个连接保持，第二个发数据，第三个立即关闭
            let (keep, _) = l.accept().await.unwrap();
            let (mut talk, _) = l.accept().await.unwrap();
            talk.write_all(b"x").await.unwrap();
            let (close, _) = l.accept().await.unwrap();
            drop(close);
            tokio::time::sleep(Duration::from_secs(3)).await;
            drop((keep, talk));
        });
        let hold = Duration::from_millis(300);
        assert_eq!(tcp(&addr, T, hold).await.state, STATE_OK);
        assert_eq!(tcp(&addr, T, hold).await.message, "连接成功，收到数据");
        let r = tcp(&addr, T, hold).await;
        assert_eq!(
            (r.state, r.message.as_str()),
            (STATE_FAIL, "连接建立后立即被关闭（转发进程无法连接目标）")
        );

        let free = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();
        let r = tcp(&free, T, Duration::ZERO).await;
        assert_eq!(
            (r.state, r.message.as_str()),
            (STATE_FAIL, "连接被拒绝（端口未监听）")
        );
    }

    #[tokio::test]
    async fn udp_states() {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut b = [0u8; 64];
            let (_, a) = s.recv_from(&mut b).await.unwrap();
            s.send_to(b"pong", a).await.unwrap();
            // 之后不再回复
            let _ = s.recv_from(&mut b).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        assert_eq!(udp(&addr, T).await.state, STATE_OK);
        assert_eq!(
            udp(&addr, Duration::from_millis(300)).await.state,
            STATE_UNKNOWN
        );
        let free = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();
        let r = udp(&free, T).await;
        assert_eq!(
            (r.state, r.message.as_str()),
            (STATE_FAIL, "连接被拒绝（端口未监听）"),
            "ICMP 端口不可达"
        );
    }

    #[test]
    fn local_ip_not_loopback() {
        let ip = local_ip("1.1.1.1");
        assert!(ip.is_empty() || !ip.starts_with("127."), "{ip}");
    }
}
