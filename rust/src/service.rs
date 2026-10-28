use std::path::Path;
use std::process::Command;

const SYSTEMD_UNIT: &str = "/etc/systemd/system/lport.service";
const OPENRC_INIT: &str = "/etc/init.d/lport";

pub fn init_system() -> &'static str {
    if Path::new("/run/systemd/system").is_dir() {
        "systemd"
    } else if Path::new("/sbin/openrc-run").exists() {
        "openrc"
    } else {
        ""
    }
}

/// 是否已注册为系统服务。
pub fn installed() -> bool {
    Path::new(SYSTEMD_UNIT).exists() || Path::new(OPENRC_INIT).exists()
}

fn quiet(name: &str, args: &[&str]) -> bool {
    Command::new(name)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// 已安装的服务是否正在运行。
pub fn running() -> bool {
    match init_system() {
        "systemd" => quiet("systemctl", &["is-active", "--quiet", "lport"]),
        "openrc" => quiet("rc-service", &["lport", "status"]),
        _ => false,
    }
}

pub fn restart() -> Result<(), String> {
    let (name, args): (&str, &[&str]) = match init_system() {
        "systemd" => ("systemctl", &["restart", "lport"]),
        "openrc" => ("rc-service", &["lport", "restart"]),
        _ => return Ok(()),
    };
    let st = Command::new(name)
        .args(args)
        .status()
        .map_err(|e| format!("{name}: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("{name} {}: {st}", args.join(" ")))
    }
}
