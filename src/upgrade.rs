//! 从 GitHub Releases 下载新版本替换本程序（upgrade）。

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::cli::Flags;
use crate::install::{Prompter, require_root};
use crate::sysinfo::{self, Fetch};
use crate::{VERSION, service};

const REPO: &str = "cgistar/lport";

/// 校验和文件的大小上限。
const MAX_SUMS_SIZE: u64 = 64 << 10;

/// 当前机器对应的发布包架构名，与 scripts/install.sh 的判断一致。
fn release_arch() -> Result<&'static str, String> {
    // SAFETY: utsname 为纯数据结构，uname 成功时完整填充
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    // SAFETY: machine 为 NUL 结尾的字符串
    let m = unsafe { std::ffi::CStr::from_ptr(u.machine.as_ptr()) }.to_string_lossy();
    arch_name(&m).ok_or_else(|| format!("不支持的架构: {m}"))
}

fn arch_name(machine: &str) -> Option<&'static str> {
    Some(match machine {
        "x86_64" | "amd64" => "amd64",
        "aarch64" | "arm64" => "arm64",
        "armv8l" => "armv7",
        "i386" | "i686" => "386",
        m if m.starts_with("armv7") => "armv7",
        m if m.starts_with("armv6") => "armv6",
        _ => return None,
    })
}

/// 在 sha256sums.txt 中查找本架构的发布包，返回 (版本号, sha256)。
fn find_package<'a>(sums: &'a str, arch: &str) -> Option<(&'a str, &'a str)> {
    let suffix = format!("-linux-{arch}.tar.gz");
    sums.lines().find_map(|l| {
        let (sum, file) = l.split_once(char::is_whitespace)?;
        // sha256sum 二进制模式会在文件名前加 *
        let file = file.trim_start().trim_start_matches('*');
        let ver = file.strip_prefix("lport-")?.strip_suffix(suffix.as_str())?;
        (!ver.is_empty() && sum.len() == 64).then_some((ver, sum))
    })
}

/// 解析 vX.Y.Z 形式的正式版本号；预发布、开发版返回 None。
fn semver(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.strip_prefix('v')?.split('.').map(|n| n.parse().ok());
    let r = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(r)
}

/// 下载一个小文本文件。
fn fetch_text(url: &str) -> Result<String, String> {
    let mut f = Fetch::start(url).ok_or("下载需要 curl 或 wget")??;
    let mut s = String::new();
    let res = f.stdout().take(MAX_SUMS_SIZE).read_to_string(&mut s);
    f.finish()?;
    res.map_err(|e| format!("下载失败: {e}"))?;
    Ok(s)
}

/// 读取时同时计算 sha256。
struct HashReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// 下载发布包并解压出 lport 到 dir 中的临时文件，校验 sha256 后返回其路径。
fn download(url: &str, sum: &str, dir: &Path) -> Result<PathBuf, String> {
    let mut f = Fetch::start(url).ok_or("下载需要 curl 或 wget")??;
    let mut r = HashReader {
        inner: f.stdout(),
        hasher: Sha256::new(),
    };
    let staged = sysinfo::extract_staged(&mut r, "lport", dir).and_then(|tmp| {
        // 读完 gzip 流之后可能剩余的数据，校验和针对整个文件
        match io::copy(&mut r, &mut io::sink()) {
            Ok(_) => Ok(tmp),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(format!("下载失败: {e}"))
            }
        }
    });
    let done = f.finish();
    let tmp = staged?;
    let fail = |e: String| {
        let _ = fs::remove_file(&tmp);
        e
    };
    done.map_err(fail)?;
    let got = hex(&r.hasher.finalize());
    if !got.eq_ignore_ascii_case(sum) {
        return Err(fail("sha256 校验失败，文件可能已损坏".into()));
    }
    Ok(tmp)
}

/// 运行新程序确认其可以执行（架构匹配）且版本号符合预期。
fn check_binary(path: &Path, want: &str) -> Result<(), String> {
    let out = Command::new(path)
        .arg("version")
        .output()
        .map_err(|e| format!("新版本无法运行: {e}"))?;
    let got = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || got != want {
        return Err(format!("新版本自检失败: 期望 {want}，实际输出 {got:?}"));
    }
    Ok(())
}

pub fn cmd_upgrade(args: &[String]) -> Result<(), String> {
    let fs = Flags::parse(args, &[("version", false), ("force", true), ("y", true)])?;
    require_root()?;
    let arch = release_arch()?;
    // 已安装时升级 BIN_PATH（即服务运行的程序），否则替换当前程序
    let target = if Path::new(service::BIN_PATH).exists() {
        PathBuf::from(service::BIN_PATH)
    } else {
        std::env::current_exe()
            .and_then(fs::canonicalize)
            .map_err(|e| e.to_string())?
    };
    let dir = target.parent().unwrap_or(Path::new("/"));

    // 发布包的文件名含版本号，最新版的 sha256sums.txt 同时给出版本号与校验和
    let requested = fs.str("version").filter(|v| !v.is_empty());
    let base = format!("https://github.com/{REPO}/releases");
    let sums_url = match requested {
        Some(v) => format!("{base}/download/{v}/sha256sums.txt"),
        None => format!("{base}/latest/download/sha256sums.txt"),
    };
    println!(
        "查询{}版本 ...",
        if requested.is_some() {
            "指定"
        } else {
            "最新"
        }
    );
    let sums = fetch_text(&sums_url).map_err(|e| match requested {
        Some(v) => format!("{e}\n请确认版本 {v} 存在: {base}"),
        None => e,
    })?;
    let (ver, sum) = find_package(&sums, arch)
        .ok_or_else(|| format!("发布页中没有 linux/{arch} 架构的安装包"))?;
    if let Some(v) = requested
        && v != ver
    {
        return Err(format!("发布页中的版本 {ver} 与指定的 {v} 不符"));
    }

    let force = fs.bool("force");
    if ver == VERSION && !force {
        println!("已是最新版本 {VERSION}（--force 重新安装）");
        return Ok(());
    }
    if requested.is_none()
        && !force
        && let (Some(new), Some(cur)) = (semver(ver), semver(VERSION))
        && new < cur
    {
        println!(
            "当前版本 {VERSION} 比最新发布版 {ver} 更新，无需升级（--version 指定版本可降级）"
        );
        return Ok(());
    }

    let p = Prompter::new(!fs.bool("y"));
    if !p.confirm(
        &format!(
            "将 {} 从 {VERSION} 升级到 {ver}，是否继续?",
            target.display()
        ),
        true,
    ) {
        println!("已取消");
        return Ok(());
    }

    let pkg = format!("lport-{ver}-linux-{arch}.tar.gz");
    println!("下载 {pkg} ...");
    let tmp = download(&format!("{base}/download/{ver}/{pkg}"), sum, dir)?;
    let res = check_binary(&tmp, ver).and_then(|()| {
        // 改名替换，运行中的服务不受影响，重启后使用新版本
        fs::rename(&tmp, &target).map_err(|e| format!("替换 {} 失败: {e}", target.display()))
    });
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    println!("已升级到 {ver}: {}", target.display());

    if target == Path::new(service::BIN_PATH) && service::installed() {
        if service::running() {
            println!("正在重启服务 ...");
            service::restart()?;
            println!("服务已重启");
        } else {
            println!("服务未运行，执行 lport start 启动");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_names() {
        for (m, a) in [
            ("x86_64", "amd64"),
            ("aarch64", "arm64"),
            ("armv7l", "armv7"),
            ("armv8l", "armv7"),
            ("armv6l", "armv6"),
            ("i686", "386"),
        ] {
            assert_eq!(arch_name(m), Some(a), "{m}");
        }
        assert_eq!(arch_name("riscv64"), None);
    }

    #[test]
    fn find_in_sums() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let sums = format!(
            "{a}  lport-v1.2.0-rc1-linux-amd64.tar.gz\n{b} *lport-v1.2.0-rc1-linux-arm64.tar.gz\n"
        );
        assert_eq!(
            find_package(&sums, "amd64"),
            Some(("v1.2.0-rc1", a.as_str()))
        );
        assert_eq!(
            find_package(&sums, "arm64"),
            Some(("v1.2.0-rc1", b.as_str()))
        );
        assert_eq!(find_package(&sums, "armv7"), None);
        assert_eq!(
            find_package("short  lport-v1-linux-amd64.tar.gz", "amd64"),
            None
        );
    }

    #[test]
    fn semver_parse() {
        assert_eq!(semver("v0.3.0"), Some((0, 3, 0)));
        assert!(semver("v0.10.0") > semver("v0.9.1"));
        for v in ["0.3.0", "v0.3.0-rc1", "v0.3.0-2-gabc1234", "dev", "v1.2"] {
            assert_eq!(semver(v), None, "{v}");
        }
    }
}
