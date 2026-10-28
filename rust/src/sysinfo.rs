use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// 下载安装的工具（如 realm）所在目录。
const DOWNLOAD_DIR: &str = "/usr/local/bin";

pub fn is_root() -> bool {
    // SAFETY: geteuid 无副作用，总是成功
    unsafe { libc::geteuid() == 0 }
}

/// 工具对应的可执行文件名。
pub fn tool_binary(name: &str) -> &str {
    match name {
        "nftables" => "nft",
        n => n,
    }
}

fn is_executable(p: &Path) -> bool {
    p.metadata()
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// 查找工具的可执行文件。除 PATH 外还查找下载安装目录，服务管理器提供的 PATH 可能不含 /usr/local/bin。
pub fn tool_path(name: &str) -> Option<PathBuf> {
    let bin = tool_binary(name);
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain([PathBuf::from(DOWNLOAD_DIR)])
        .map(|d| d.join(bin))
        .find(|p| is_executable(p))
}

pub fn tool_installed(name: &str) -> bool {
    tool_path(name).is_some()
}
