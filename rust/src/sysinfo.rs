//! 系统环境检测与依赖工具安装，对应 Go 版 internal/sysinfo。

use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

/// 下载安装的工具（如 realm）所在目录。
const DOWNLOAD_DIR: &str = "/usr/local/bin";

/// 一个转发依赖工具。
#[derive(Debug, Clone, Default)]
pub struct Tool {
    /// realm | iptables | nftables
    pub name: &'static str,
    /// 可执行文件名
    pub binary: &'static str,
    /// 包名；为空表示不走包管理器，从发布页下载
    pub package: &'static str,
    pub installed: bool,
    pub path: String,
    pub version: String,
}

static TOOLS: [Tool; 3] = [
    Tool {
        name: "realm",
        binary: "realm",
        package: "",
        installed: false,
        path: String::new(),
        version: String::new(),
    },
    Tool {
        name: "iptables",
        binary: "iptables",
        package: "iptables",
        installed: false,
        path: String::new(),
        version: String::new(),
    },
    Tool {
        name: "nftables",
        binary: "nft",
        package: "nftables",
        installed: false,
        path: String::new(),
        version: String::new(),
    },
];

fn tool_def(name: &str) -> Option<&'static Tool> {
    TOOLS.iter().find(|t| t.name == name)
}

pub fn is_root() -> bool {
    // SAFETY: geteuid 无副作用，总是成功
    unsafe { libc::geteuid() == 0 }
}

/// 工具对应的可执行文件名。
pub fn tool_binary(name: &str) -> &str {
    tool_def(name).map_or(name, |t| t.binary)
}

fn is_executable(p: &Path) -> bool {
    p.metadata()
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// 在 PATH 中查找可执行文件。
pub fn look_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| is_executable(p))
}

/// 查找工具的可执行文件。除 PATH 外还查找下载安装目录，服务管理器提供的 PATH 可能不含 /usr/local/bin。
pub fn tool_path(name: &str) -> Option<PathBuf> {
    let bin = tool_binary(name);
    look_path(bin).or_else(|| Some(Path::new(DOWNLOAD_DIR).join(bin)).filter(|p| is_executable(p)))
}

pub fn tool_installed(name: &str) -> bool {
    tool_path(name).is_some()
}

/// 解析 /etc/os-release 内容。
pub fn parse_os_release(content: &str) -> std::collections::HashMap<String, String> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| {
            (
                k.to_string(),
                v.trim_matches(|c| c == '"' || c == '\'').to_string(),
            )
        })
        .collect()
}

/// 根据 ID / ID_LIKE 判断发行版家族。
pub fn family(id: &str, like: &str) -> &'static str {
    for f in std::iter::once(id).chain(like.split_whitespace()) {
        match f {
            "alpine" => return "alpine",
            "debian" | "ubuntu" | "linuxmint" | "raspbian" | "kali" => return "debian",
            "centos" | "rhel" | "fedora" | "rocky" | "almalinux" | "ol" | "amzn" | "anolis"
            | "openEuler" | "opencloudos" => return "rhel",
            _ => {}
        }
    }
    "unknown"
}

/// 包管理器名称；look 便于测试注入。
pub fn package_manager(family: &str, look: impl Fn(&str) -> bool) -> &'static str {
    match family {
        "alpine" => return "apk",
        "debian" => return "apt",
        "rhel" => return if look("dnf") { "dnf" } else { "yum" },
        _ => {}
    }
    for (bin, pm) in [
        ("apk", "apk"),
        ("apt-get", "apt"),
        ("dnf", "dnf"),
        ("yum", "yum"),
    ] {
        if look(bin) {
            return pm;
        }
    }
    ""
}

/// 安装命令（shell 字符串）。
pub fn install_command(pm: &str, pkgs: &[&str]) -> String {
    if pkgs.is_empty() {
        return String::new();
    }
    let p = pkgs.join(" ");
    match pm {
        "apk" => format!("apk add --no-cache {p}"),
        "apt" => format!("apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y {p}"),
        "dnf" => format!("dnf install -y {p}"),
        "yum" => format!("yum install -y {p}"),
        _ => String::new(),
    }
}

/// 运行命令并在超时后杀掉，返回合并的输出。
fn output_with_timeout(cmd: &mut Command, secs: u64) -> io::Result<(bool, String)> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let t_out = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = so.read_to_string(&mut s);
        s
    });
    let t_err = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = se.read_to_string(&mut s);
        s
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut out = t_out.join().unwrap_or_default();
    out.push_str(&t_err.join().unwrap_or_default());
    match status {
        Some(st) => Ok((st.success(), out)),
        None => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("执行超时（{secs}s）"),
        )),
    }
}

fn tool_version(path: &Path, name: &str) -> String {
    let arg = if name == "realm" { "-v" } else { "--version" };
    match output_with_timeout(Command::new(path).arg(arg), 3) {
        Ok((_, out)) => out
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or_default()
            .to_string(),
        Err(_) => String::new(),
    }
}

fn detect_init() -> &'static str {
    if Path::new("/run/systemd/system").is_dir() {
        "systemd"
    } else if look_path("openrc-run").is_some() || Path::new("/sbin/openrc-run").exists() {
        "openrc"
    } else {
        "unknown"
    }
}

/// 读取 net.ipv4.ip_forward。
pub fn ip_forward_enabled() -> bool {
    fs::read_to_string("/proc/sys/net/ipv4/ip_forward").is_ok_and(|s| s.trim() == "1")
}

const SYSCTL_CONF: &str = "/etc/sysctl.d/99-lport.conf";

/// 开启并持久化 ip_forward。运行值与持久化分别处理：运行值已是 1 时也补写持久化配置；
/// 持久化失败只记录日志，不影响本次转发（lport 启动时会重新开启运行值）。
pub fn enable_ip_forward() -> Result<(), String> {
    if !ip_forward_enabled() {
        fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|e| format!("开启 ip_forward 失败: {e}"))?;
    }
    const WANT: &str = "net.ipv4.ip_forward = 1\n";
    if fs::read_to_string(SYSCTL_CONF).is_ok_and(|s| s == WANT)
        || !Path::new("/etc/sysctl.d").is_dir()
    {
        return Ok(());
    }
    if let Err(e) = fs::write(SYSCTL_CONF, WANT) {
        crate::logln!("持久化 ip_forward 失败（重启后需由 lport 重新开启）: {e}");
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct Info {
    pub os_id: String,
    pub os_like: String,
    pub os_name: String,
    /// alpine | debian | rhel | unknown
    pub family: &'static str,
    pub package_manager: &'static str,
    pub kernel: String,
    pub is_root: bool,
    pub ip_forward: bool,
    pub init_system: &'static str,
    pub tools: Vec<Tool>,
    /// 安装缺失工具的命令，全部已装时为空
    pub install_command: String,
}

/// 采集系统信息。
pub fn detect() -> Info {
    let mut info = Info {
        is_root: is_root(),
        ip_forward: ip_forward_enabled(),
        init_system: detect_init(),
        ..Default::default()
    };
    if let Ok(s) = fs::read_to_string("/etc/os-release") {
        let m = parse_os_release(&s);
        let get = |k: &str| m.get(k).cloned().unwrap_or_default();
        (info.os_id, info.os_like, info.os_name) = (get("ID"), get("ID_LIKE"), get("PRETTY_NAME"));
    }
    info.kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    info.family = family(&info.os_id, &info.os_like);
    info.package_manager = package_manager(info.family, |b| look_path(b).is_some());
    let mut missing = Vec::new();
    for t in &TOOLS {
        let mut t = t.clone();
        match tool_path(t.name) {
            Some(p) => {
                t.installed = true;
                t.version = tool_version(&p, t.name);
                t.path = p.display().to_string();
            }
            None => missing.push(t.name),
        }
        info.tools.push(t);
    }
    info.install_command = tools_install_command(info.package_manager, &missing);
    info
}

/// 安装若干工具的完整命令：包管理器安装的合并为一条，需下载的各自追加。包管理器未知时只返回下载部分。
pub fn tools_install_command(pm: &str, tools: &[&str]) -> String {
    let defs: Vec<&Tool> = tools.iter().filter_map(|n| tool_def(n)).collect();
    let pkgs: Vec<&str> = defs
        .iter()
        .filter(|t| !t.package.is_empty())
        .map(|t| t.package)
        .collect();
    let mut parts = Vec::new();
    let c = install_command(pm, &pkgs);
    if !c.is_empty() {
        parts.push(c);
    }
    for t in defs.iter().filter(|t| t.package.is_empty()) {
        if let Ok(url) = download_url(t.name, std::env::consts::ARCH) {
            parts.push(format!(
                "curl -fsSL {url} | tar -xz -C {DOWNLOAD_DIR} {}",
                t.binary
            ));
        }
    }
    parts.join(" && ")
}

static INSTALL_LOCK: Mutex<()> = Mutex::new(());

/// 安装指定工具，返回 (执行的命令, 命令输出, 结果)。同一时间只允许一个安装任务。
pub fn install(tools: &[&str]) -> (String, String, Result<(), String>) {
    let Ok(_guard) = INSTALL_LOCK.try_lock() else {
        return (
            String::new(),
            String::new(),
            Err("已有安装任务正在进行，请稍后再试".into()),
        );
    };
    if !is_root() {
        return (
            String::new(),
            String::new(),
            Err("需要 root 权限才能安装软件包".into()),
        );
    }
    let mut pkgs = Vec::new();
    let mut downloads = Vec::new();
    for name in tools {
        match tool_def(name) {
            None => {
                return (
                    String::new(),
                    String::new(),
                    Err(format!("未知工具: {name}")),
                );
            }
            Some(t) if t.package.is_empty() => downloads.push(t),
            Some(t) => pkgs.push(t.package),
        }
    }
    let mut cmds = Vec::new();
    let mut out = String::new();
    if !pkgs.is_empty() {
        let cmdline = install_command(detect().package_manager, &pkgs);
        if cmdline.is_empty() {
            return (
                String::new(),
                String::new(),
                Err("无法识别当前系统的包管理器，请手动安装".into()),
            );
        }
        cmds.push(cmdline.clone());
        let res = output_with_timeout(
            Command::new("/bin/sh")
                .arg("-c")
                .arg(&cmdline)
                .env("DEBIAN_FRONTEND", "noninteractive"),
            300,
        );
        match res {
            Ok((true, o)) => out.push_str(&o),
            Ok((false, o)) => {
                out.push_str(&o);
                return (cmdline, out, Err("安装失败: 命令执行失败".into()));
            }
            Err(e) => return (cmdline, out, Err(format!("安装失败: {e}"))),
        }
    }
    for t in downloads {
        let url = match download_url(t.name, std::env::consts::ARCH) {
            Ok(u) => u,
            Err(e) => return (cmds.join(" && "), out, Err(e)),
        };
        cmds.push(format!("download {url}"));
        out.push_str(&format!("downloading {url}\n"));
        match download(&url, t.binary, Path::new(DOWNLOAD_DIR)) {
            Ok(dst) => out.push_str(&format!("installed to {}\n", dst.display())),
            Err(e) => return (cmds.join(" && "), out, Err(format!("安装失败: {e}"))),
        }
    }
    (cmds.join(" && "), out, Ok(()))
}

/// 架构（std::env::consts::ARCH）→ realm 发布包的 Rust target。均为静态链接的 musl 版本，
/// glibc 与 Alpine 通用；arm 统一使用 armv6 硬浮点版本，armv7 也可运行。
fn realm_target(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("x86_64-unknown-linux-musl"),
        "aarch64" => Some("aarch64-unknown-linux-musl"),
        "arm" => Some("arm-unknown-linux-musleabihf"),
        _ => None,
    }
}

/// 当前架构下工具发布包的下载地址。
pub fn download_url(name: &str, arch: &str) -> Result<String, String> {
    if name != "realm" {
        return Err(format!("{name} 不支持下载安装"));
    }
    let target = realm_target(arch)
        .ok_or_else(|| format!("realm 未提供 {arch} 架构的预编译版本，请手动安装"))?;
    Ok(format!(
        "https://github.com/zhboner/realm/releases/latest/download/realm-{target}.tar.gz"
    ))
}

/// 解压出的可执行文件大小上限。
const MAX_BINARY_SIZE: u64 = 64 << 20;

/// 用系统的 curl 或 wget 下载 tar.gz 发布包，把其中名为 binary 的文件安装到 dir。
/// 不内置 HTTPS 客户端以保持二进制精简；解压与校验在进程内完成。
fn download(url: &str, binary: &str, dir: &Path) -> Result<PathBuf, String> {
    let mut cmd = if look_path("curl").is_some() {
        let mut c = Command::new("curl");
        c.args([
            "-fsSL",
            "--retry",
            "3",
            "--connect-timeout",
            "15",
            "--max-time",
            "300",
            url,
        ]);
        c
    } else if look_path("wget").is_some() {
        let mut c = Command::new("wget");
        c.args(["-qO-", "-T", "60", url]);
        c
    } else {
        return Err("下载 realm 需要 curl 或 wget".into());
    };
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("下载失败: {e}"))?;
    let stdout = child.stdout.take().unwrap();
    // 先解压到临时文件；下载命令成功退出后才改名替换，被中断或报错的下载不会覆盖已有版本
    let staged = extract_staged(stdout, binary, dir);
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    let status = child.wait().map_err(|e| format!("下载失败: {e}"))?;
    let tmp = staged?;
    if !status.success() {
        let _ = fs::remove_file(&tmp);
        return Err(format!(
            "下载失败: {} {}",
            crate::backend::exit_text(status),
            err.trim()
        ));
    }
    let dst = dir.join(binary);
    fs::rename(&tmp, &dst).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        e.to_string()
    })?;
    Ok(dst)
}

/// 从 tar.gz 流中取出名为 binary 的文件安装到 dir。先写临时文件，读完整个 gzip 流
/// （完成 CRC 与长度校验）后才改名替换，损坏或截断的发布包不会覆盖已有版本。
#[cfg(test)]
fn extract(r: impl Read, binary: &str, dir: &Path) -> Result<PathBuf, String> {
    let tmp = extract_staged(r, binary, dir)?;
    let dst = dir.join(binary);
    fs::rename(&tmp, &dst).map_err(|e| e.to_string())?;
    Ok(dst)
}

/// extract 的前半部分：校验通过后返回 dir 中的临时文件路径，由调用方改名。
fn extract_staged(r: impl Read, binary: &str, dir: &Path) -> Result<PathBuf, String> {
    let mut gz = flate2::read::GzDecoder::new(r);
    let found = {
        let mut ar = tar::Archive::new(&mut gz);
        let entries = ar.entries().map_err(|e| format!("解压失败: {e}"))?;
        let mut found = None;
        for entry in entries {
            let mut entry = entry.map_err(|e| format!("解压失败: {e}"))?;
            let is_bin = entry.header().entry_type().is_file()
                && entry
                    .path()
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n == binary))
                    .unwrap_or(false);
            if !is_bin {
                continue;
            }
            if entry.size() > MAX_BINARY_SIZE {
                return Err(format!("{binary} 超过大小上限"));
            }
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            let tmp = dir.join(format!(".{binary}-{}", crate::config::new_id()));
            let res = (|| {
                let mut f = fs::File::create(&tmp)?;
                io::copy(&mut (&mut entry).take(MAX_BINARY_SIZE), &mut f)?;
                f.sync_all()
            })();
            if let Err(e) = res {
                let _ = fs::remove_file(&tmp);
                return Err(format!("写入失败: {e}"));
            }
            found = Some(tmp);
            break;
        }
        found
    };
    let Some(tmp) = found else {
        return Err(format!("发布包中没有 {binary}"));
    };
    // 读完剩余数据，GzDecoder 在流末尾校验 CRC 与长度
    let fail = |e: String| {
        let _ = fs::remove_file(&tmp);
        e
    };
    io::copy(&mut gz, &mut io::sink()).map_err(|e| fail(format!("解压失败: {e}")))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))
        .map_err(|e| fail(e.to_string()))?;
    Ok(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_family_and_pm() {
        let m =
            parse_os_release("ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n# x\n");
        assert_eq!(
            (m["ID"].as_str(), m["PRETTY_NAME"].as_str()),
            ("ubuntu", "Ubuntu 24.04 LTS")
        );
        assert_eq!(family("ubuntu", "debian"), "debian");
        assert_eq!(family("rocky", "rhel centos fedora"), "rhel");
        assert_eq!(family("alpine", ""), "alpine");
        assert_eq!(family("arch", ""), "unknown");
        assert_eq!(package_manager("rhel", |b| b == "dnf"), "dnf");
        assert_eq!(package_manager("rhel", |_| false), "yum");
        assert_eq!(package_manager("unknown", |b| b == "apt-get"), "apt");
        assert_eq!(
            install_command("apk", &["nftables"]),
            "apk add --no-cache nftables"
        );
        assert_eq!(install_command("", &["nftables"]), "");
        assert_eq!(
            tools_install_command("apt", &["nftables", "iptables"]),
            "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y nftables iptables"
        );
    }

    #[test]
    fn realm_urls() {
        assert!(
            download_url("realm", "x86_64")
                .unwrap()
                .ends_with("realm-x86_64-unknown-linux-musl.tar.gz")
        );
        assert!(download_url("realm", "riscv64").is_err());
        assert!(download_url("iptables", "x86_64").is_err());
    }

    fn tar_gz(files: &[(&str, &str)]) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tw = tar::Builder::new(&mut gz);
            for (name, body) in files {
                let mut h = tar::Header::new_gnu();
                h.set_size(body.len() as u64);
                h.set_mode(0o755);
                h.set_entry_type(tar::EntryType::Regular);
                tw.append_data(&mut h, name, body.as_bytes()).unwrap();
            }
            tw.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tmpdir() -> TempDir {
        let d = std::env::temp_dir().join(format!("lport-test-{}", crate::config::new_id()));
        fs::create_dir_all(&d).unwrap();
        TempDir(d)
    }

    #[test]
    fn extract_binary() {
        let dir = tmpdir();
        let dst = extract(
            &tar_gz(&[("README", "x"), ("realm", "new")])[..],
            "realm",
            &dir.0,
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&dst).unwrap(), "new");
        assert!(
            fs::metadata(&dst).unwrap().permissions().mode() & 0o111 != 0,
            "应可执行"
        );
        assert!(
            extract(&tar_gz(&[("README", "x")])[..], "realm", &dir.0).is_err(),
            "缺少文件时应失败"
        );
    }

    // gzip 尾部（CRC）损坏时，即使 realm 已完整解出也不能覆盖已有版本，且不留下临时文件
    #[test]
    fn extract_corrupt_trailer() {
        let dir = tmpdir();
        let old = dir.0.join("realm");
        fs::write(&old, "old").unwrap();
        let mut data = tar_gz(&[("realm", "new")]);
        let n = data.len();
        data[n - 8] ^= 0xff; // 破坏 CRC32
        assert!(
            extract(&data[..], "realm", &dir.0).is_err(),
            "CRC 错误时应失败"
        );
        assert_eq!(fs::read_to_string(&old).unwrap(), "old", "已有版本被覆盖");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1, "残留临时文件");
    }
}
