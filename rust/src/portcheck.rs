use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 系统中一个被占用的端口。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Listener {
    pub proto: &'static str,
    pub addr: String,
    pub port: i64,
    pub inode: u64,
    pub pid: i32,
    pub process: String,
}

impl Listener {
    /// 该监听是否占用 IPv4 端口。转发只监听 IPv4，绑定在具体 IPv6 地址（如 ::1）上的
    /// 监听互不影响；[::] 通常为双栈（net.ipv6.bindv6only=0），按占用处理。
    pub fn blocks_ipv4(&self) -> bool {
        match self.addr.parse::<IpAddr>() {
            Ok(IpAddr::V6(v6)) => v6.is_unspecified() || v6.to_ipv4_mapped().is_some(),
            _ => true,
        }
    }
}

/// 解析 /proc/net/{tcp,tcp6,udp,udp6} 的内容。TCP 只返回 LISTEN(0A) 状态；UDP 返回全部已绑定端口。
pub fn parse_proc_net(content: &str, proto: &'static str, v6: bool) -> Vec<Listener> {
    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || (proto == "tcp" && f[3] != "0A") {
            continue;
        }
        let Some((hex_addr, hex_port)) = f[1].split_once(':') else {
            continue;
        };
        let port = match u16::from_str_radix(hex_port, 16) {
            Ok(p) if p != 0 => p,
            _ => continue,
        };
        out.push(Listener {
            proto,
            addr: decode_addr(hex_addr, v6),
            port: port.into(),
            inode: f[9].parse().unwrap_or(0),
            ..Default::default()
        });
    }
    out
}

/// 将 /proc/net 中小端序的十六进制地址转为可读形式。
fn decode_addr(h: &str, v6: bool) -> String {
    let Some(mut b) = (0..h.len() / 2)
        .map(|i| {
            h.get(2 * i..2 * i + 2)
                .and_then(|x| u8::from_str_radix(x, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
    else {
        return h.to_string();
    };
    // 每 4 字节为一个小端序的 32 位整数
    for c in b.as_chunks_mut::<4>().0 {
        c.reverse();
    }
    match (v6, b.len()) {
        (false, 4) => Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        (_, 16) => {
            let a: [u8; 16] = b.try_into().unwrap();
            let ip = Ipv6Addr::from(a);
            // 与 Go 一致：IPv4 映射地址显示为点分十进制
            ip.to_ipv4_mapped()
                .map_or(ip.to_string(), |v4| v4.to_string())
        }
        _ => h.to_string(),
    }
}

/// 扫描 /proc/*/fd 建立 socket inode → pid 映射。
fn socket_owners() -> HashMap<u64, i32> {
    let mut m = HashMap::new();
    let Ok(procs) = fs::read_dir("/proc") else {
        return m;
    };
    for p in procs.flatten() {
        let Ok(pid) = p.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(fds) = fs::read_dir(p.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };
            let link = link.to_string_lossy();
            if let Some(ino) = link
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse().ok())
            {
                m.insert(ino, pid);
            }
        }
    }
    m
}

fn proc_name(pid: i32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// 读取进程的父进程 pid。
pub fn parent_pid(pid: i32) -> i32 {
    let Ok(s) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0;
    };
    // comm 字段可能含空格，从最后一个 ')' 之后开始解析
    let Some(i) = s.rfind(')') else { return 0 };
    s[i + 1..]
        .split_whitespace()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(0)
}

/// 返回系统所有监听/绑定端口（附带进程信息）。
pub fn listeners(with_process: bool) -> Vec<Listener> {
    let mut all = Vec::new();
    for (file, proto, v6) in [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp", true),
    ] {
        if let Ok(content) = fs::read_to_string(file) {
            all.extend(parse_proc_net(&content, proto, v6));
        }
    }
    if with_process {
        let owners = socket_owners();
        for l in &mut all {
            if let Some(&pid) = owners.get(&l.inode) {
                l.pid = pid;
                l.process = proc_name(pid);
            }
        }
    }
    all.sort_by(|a, b| (a.port, a.proto, &a.addr).cmp(&(b.port, b.proto, &b.addr)));
    all
}

/// 尝试绑定 IPv4 端口，作为 /proc 解析之外的兜底检测。
pub fn bind_test(proto: &str, port: i64) -> std::io::Result<()> {
    let addr = (Ipv4Addr::UNSPECIFIED, port as u16);
    if proto == "udp" {
        std::net::UdpSocket::bind(addr).map(drop)
    } else {
        std::net::TcpListener::bind(addr).map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proc_net_tcp() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F91 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
";
        let ls = parse_proc_net(tcp, "tcp", false);
        assert_eq!(ls.len(), 1, "只保留 LISTEN");
        assert_eq!(
            (ls[0].addr.as_str(), ls[0].port, ls[0].inode),
            ("127.0.0.1", 8080, 12345)
        );

        let tcp6 = "header
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1
   1: 00000000000000000000000001000000:0051 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 223 1
";
        let ls = parse_proc_net(tcp6, "tcp", true);
        assert_eq!((ls[0].addr.as_str(), ls[0].port), ("::", 80));
        assert!(ls[0].blocks_ipv4());
        assert_eq!(ls[1].addr, "::1");
        assert!(!ls[1].blocks_ipv4());
    }
}
