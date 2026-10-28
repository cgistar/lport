//! 注册与管理系统服务（systemd / OpenRC），对应 Go 版 internal/service。
//! 服务文件与 Go 版相同，两个版本可以互相升级替换。

use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

pub const BIN_PATH: &str = "/usr/local/bin/lport";
const SYSTEMD_UNIT: &str = "/etc/systemd/system/lport.service";
const OPENRC_INIT: &str = "/etc/init.d/lport";

fn systemd_file(config_path: &str) -> String {
    format!(
        "[Unit]
Description=lport port forwarding manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={BIN_PATH} serve --config {config_path}
Restart=on-failure
RestartSec=3
KillMode=mixed

[Install]
WantedBy=multi-user.target
"
    )
}

fn openrc_file(config_path: &str) -> String {
    format!(
        "#!/sbin/openrc-run
name=\"lport\"
description=\"lport port forwarding manager\"
command=\"{BIN_PATH}\"
command_args=\"serve --config {config_path}\"
supervisor=supervise-daemon
output_log=\"/var/log/lport.log\"
error_log=\"/var/log/lport.log\"

depend() {{
\tneed net
\tafter firewall
}}
"
    )
}

/// systemd / openrc / 空字符串。
pub fn init_system() -> &'static str {
    if Path::new("/run/systemd/system").is_dir() {
        "systemd"
    } else if Path::new("/sbin/openrc-run").exists() {
        "openrc"
    } else {
        ""
    }
}

/// 执行命令，输出直接显示给用户。
fn run(name: &str, args: &[&str]) -> Result<(), String> {
    let st = Command::new(name)
        .args(args)
        .status()
        .map_err(|e| format!("{name} {}: {e}", args.join(" ")))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!(
            "{name} {}: {}",
            args.join(" "),
            crate::backend::exit_text(st)
        ))
    }
}

fn quiet(name: &str, args: &[&str]) -> bool {
    Command::new(name)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// 将当前程序复制到 BIN_PATH（先写临时文件再改名，运行中的服务不受影响）。
pub fn copy_self() -> Result<(), String> {
    let exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| e.to_string())?;
    if exe == Path::new(BIN_PATH) {
        return Ok(());
    }
    let tmp = format!("{BIN_PATH}.tmp");
    let res = (|| -> io::Result<()> {
        let mut src = fs::File::open(&exe)?;
        let mut dst = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o755)
            .open(&tmp)?;
        io::copy(&mut src, &mut dst)?;
        dst.sync_all()?;
        fs::rename(&tmp, BIN_PATH)
    })();
    res.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        e.to_string()
    })
}

/// 复制二进制并注册、启动系统服务。
pub fn install(config_path: &str) -> Result<(), String> {
    let init = init_system();
    if init.is_empty() {
        return Err("未检测到 systemd 或 OpenRC，请手动运行: lport serve".into());
    }
    // 若服务已在运行，先停止以便覆盖二进制
    if installed() {
        let _ = stop();
    }
    copy_self().map_err(|e| format!("复制程序到 {BIN_PATH} 失败: {e}"))?;
    if init == "systemd" {
        fs::write(SYSTEMD_UNIT, systemd_file(config_path)).map_err(|e| e.to_string())?;
        run("systemctl", &["daemon-reload"])?;
        return run("systemctl", &["enable", "--now", "lport"]);
    }
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(OPENRC_INIT)
        .and_then(|mut f| io::Write::write_all(&mut f, openrc_file(config_path).as_bytes()))
        .map_err(|e| e.to_string())?;
    run("rc-update", &["add", "lport", "default"])?;
    run("rc-service", &["lport", "start"])
}

/// 是否已注册为系统服务。
pub fn installed() -> bool {
    Path::new(SYSTEMD_UNIT).exists() || Path::new(OPENRC_INIT).exists()
}

/// 已安装的服务是否正在运行。
pub fn running() -> bool {
    match init_system() {
        "systemd" => quiet("systemctl", &["is-active", "--quiet", "lport"]),
        "openrc" => quiet("rc-service", &["lport", "status"]),
        _ => false,
    }
}

pub fn start() -> Result<(), String> {
    match init_system() {
        "systemd" => run("systemctl", &["start", "lport"]),
        "openrc" => run("rc-service", &["lport", "start"]),
        _ => Ok(()),
    }
}

pub fn stop() -> Result<(), String> {
    match init_system() {
        "systemd" => run("systemctl", &["stop", "lport"]),
        "openrc" => run("rc-service", &["lport", "stop"]),
        _ => Ok(()),
    }
}

/// 重启已安装的服务（用于命令行修改配置后生效）。
pub fn restart() -> Result<(), String> {
    if !installed() {
        return Ok(());
    }
    match init_system() {
        "systemd" => run("systemctl", &["restart", "lport"]),
        "openrc" => run("rc-service", &["lport", "restart"]),
        _ => Ok(()),
    }
}

/// 停止并移除服务；purge 时同时删除配置目录。
pub fn uninstall(config_path: &str, purge: bool) -> Result<(), String> {
    match init_system() {
        "systemd" => {
            let _ = run("systemctl", &["disable", "--now", "lport"]);
            let _ = fs::remove_file(SYSTEMD_UNIT);
            let _ = run("systemctl", &["daemon-reload"]);
        }
        "openrc" => {
            let _ = run("rc-service", &["lport", "stop"]);
            let _ = run("rc-update", &["del", "lport", "default"]);
            let _ = fs::remove_file(OPENRC_INIT);
        }
        _ => {}
    }
    let _ = fs::remove_file(BIN_PATH);
    if purge {
        let dir = Path::new(config_path)
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if let Err(e) = fs::remove_dir_all(dir)
            && e.kind() != io::ErrorKind::NotFound
        {
            return Err(e.to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // 服务文件与 Go 版逐字一致，两个版本可以互相升级替换
    #[test]
    fn files_match_go() {
        let go = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../internal/service/service.go"
        ))
        .unwrap();
        let unit = systemd_file("/etc/lport/config.yaml")
            .replace("/etc/lport/config.yaml", "%s")
            .replacen(BIN_PATH, "%s", 1);
        assert!(go.contains(&unit), "systemd unit 与 Go 版不一致:\n{unit}");
        let rc = openrc_file("/etc/lport/config.yaml")
            .replace("/etc/lport/config.yaml", "%s")
            .replacen(BIN_PATH, "%s", 1);
        assert!(go.contains(&rc), "OpenRC 脚本与 Go 版不一致:\n{rc}");
    }
}
