//! TCP 双向转发。优先用 Linux splice 零拷贝：socket → pipe → socket，数据不经过用户态
//! （Go 的 io.Copy 在 TCP 之间也走 splice）；无法创建管道时退回用户态缓冲区拷贝。

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use tokio::io::Interest;
use tokio::net::TcpStream;

/// 每次 splice 的最大字节数，与默认管道容量一致。
const CHUNK: usize = 64 * 1024;

struct Pipe {
    r: OwnedFd,
    w: OwnedFd,
}

impl Pipe {
    fn new() -> io::Result<Pipe> {
        let mut fds = [0; 2];
        // SAFETY: fds 为两个元素的数组，成功时内核写入两个新的文件描述符
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pipe2 成功返回的描述符归本结构独占
        Ok(unsafe {
            Pipe {
                r: OwnedFd::from_raw_fd(fds[0]),
                w: OwnedFd::from_raw_fd(fds[1]),
            }
        })
    }
}

fn splice(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
    // SAFETY: 两个描述符在调用期间有效，偏移量为空表示使用并推进文件当前位置
    let n = unsafe {
        libc::splice(
            from,
            std::ptr::null_mut(),
            to,
            std::ptr::null_mut(),
            len,
            libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// 把 src 的数据经管道搬到 dst，直到 src 读到 EOF。
async fn splice_one_way(src: &TcpStream, dst: &TcpStream, pipe: &Pipe) -> io::Result<()> {
    loop {
        let n = src
            .async_io(Interest::READABLE, || {
                splice(src.as_raw_fd(), pipe.w.as_raw_fd(), CHUNK)
            })
            .await?;
        if n == 0 {
            return Ok(());
        }
        let mut left = n;
        while left > 0 {
            left -= dst
                .async_io(Interest::WRITABLE, || {
                    splice(pipe.r.as_raw_fd(), dst.as_raw_fd(), left)
                })
                .await?;
        }
    }
}

/// 经用户态缓冲区把 src 的数据拷贝到 dst，直到 src 读到 EOF。
async fn copy_one_way(src: &TcpStream, dst: &TcpStream) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK];
    loop {
        src.readable().await?;
        let n = match src.try_read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        };
        let mut off = 0;
        while off < n {
            dst.writable().await?;
            match dst.try_write(&buf[off..n]) {
                Ok(m) => off += m,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// 一个方向：读到 EOF 后半关闭对端写方向。
async fn one_way(src: &TcpStream, dst: &TcpStream, pipe: Option<&Pipe>) -> io::Result<()> {
    match pipe {
        Some(p) => splice_one_way(src, dst, p).await?,
        None => copy_one_way(src, dst).await?,
    }
    shutdown_write(dst);
    Ok(())
}

fn shutdown_write(s: &TcpStream) {
    // SAFETY: 描述符在 s 存活期间有效
    unsafe { libc::shutdown(s.as_raw_fd(), libc::SHUT_WR) };
}

/// 等待已读到 EOF 的一端出错（如对端在 FIN 之后又发来 RST）。该方向已没有读操作，
/// 不额外监听的话错误要等另一方向有数据可写时才会发现，上游一直沉默时连接会滞留。
async fn wait_error(s: &TcpStream) -> io::Error {
    loop {
        if let Err(e) = s.ready(Interest::ERROR).await {
            return e;
        }
        match s.take_error() {
            Ok(Some(e)) | Err(e) => return e,
            // 没有待处理的错误：清除本次就绪状态后继续等待
            Ok(None) => {
                let _ = s.try_io(Interest::ERROR, || {
                    Err::<(), _>(io::ErrorKind::WouldBlock.into())
                });
            }
        }
    }
}

/// 双向转发，两个方向都读到 EOF 时正常结束。一个方向读到 EOF 时半关闭对端写方向，另一方向继续传输，
/// 同时继续监听已结束一端的错误；任一方向出错（如对端 RST）时立即返回，由调用方关闭两端，
/// 否则上游不关闭时连接会一直滞留。
pub async fn forward(a: &TcpStream, b: &TcpStream) -> io::Result<()> {
    run(a, b, Pipe::new().and_then(|p1| Ok((p1, Pipe::new()?))).ok()).await
}

/// pipes 为 None 时使用用户态拷贝（如文件描述符耗尽、无法创建管道）。
async fn run(a: &TcpStream, b: &TcpStream, pipes: Option<(Pipe, Pipe)>) -> io::Result<()> {
    let (p1, p2) = match &pipes {
        Some((p1, p2)) => (Some(p1), Some(p2)),
        None => (None, None),
    };
    let ab = one_way(a, b, p1);
    let ba = one_way(b, a, p2);
    tokio::pin!(ab, ba);
    let (mut ab_done, mut ba_done) = (false, false);
    while !(ab_done && ba_done) {
        tokio::select! {
            r = &mut ab, if !ab_done => { r?; ab_done = true; }
            r = &mut ba, if !ba_done => { r?; ba_done = true; }
            e = wait_error(a), if ab_done => return Err(e),
            e = wait_error(b), if ba_done => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{sleep, timeout};

    /// 返回 (客户端, 代理的客户端侧, 代理的上游侧, 上游)。
    async fn quad() -> (TcpStream, TcpStream, TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (pc, _) = l.accept().await.unwrap();
        let pu = TcpStream::connect(addr).await.unwrap();
        let (up, _) = l.accept().await.unwrap();
        (client, pc, pu, up)
    }

    fn modes() -> [Option<(Pipe, Pipe)>; 2] {
        [Some((Pipe::new().unwrap(), Pipe::new().unwrap())), None]
    }

    // 客户端半关闭后上游仍可回包，两端都读完后正常结束
    #[tokio::test]
    async fn half_close() {
        for pipes in modes() {
            let splice = pipes.is_some();
            let (mut client, pc, pu, mut up) = quad().await;
            let fwd = tokio::spawn(async move { run(&pc, &pu, pipes).await });
            client.write_all(b"req").await.unwrap();
            client.shutdown().await.unwrap();
            let mut got = Vec::new();
            up.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"req", "splice={splice}");
            up.write_all(b"resp").await.unwrap();
            up.shutdown().await.unwrap();
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"resp", "splice={splice}");
            let r = timeout(Duration::from_secs(2), fwd)
                .await
                .expect("两端 EOF 后应结束");
            assert!(r.unwrap().is_ok(), "splice={splice}");
        }
    }

    // 客户端先 FIN 后 RST、上游保持沉默时须立即结束，不能等上游有数据才发现
    #[tokio::test]
    async fn reset_after_fin() {
        for pipes in modes() {
            let splice = pipes.is_some();
            let (mut client, pc, pu, mut up) = quad().await;
            let fwd = tokio::spawn(async move { run(&pc, &pu, pipes).await });
            client.write_all(b"hi").await.unwrap();
            client.shutdown().await.unwrap();
            let mut got = Vec::new();
            up.read_to_end(&mut got).await.unwrap(); // 上游收到 FIN，之后不再发送
            sleep(Duration::from_millis(50)).await;
            client.set_zero_linger().unwrap();
            drop(client); // RST
            let r = timeout(Duration::from_secs(2), fwd)
                .await
                .expect("RST 后应立即结束");
            assert!(r.unwrap().is_err(), "splice={splice}");
            drop(up);
        }
    }
}
