mod builtin;
mod cli;
mod config;
mod ctl;
mod manager;
mod model;
mod portcheck;
mod service;
mod splice;
mod sysinfo;

use std::sync::Arc;

use tokio::signal::unix::{SignalKind, signal};

use cli::Flags;
use manager::Manager;

pub const VERSION: &str = env!("LPORT_VERSION");

/// 带时间前缀的日志，格式同 Go log 包默认输出。
#[macro_export]
macro_rules! logln {
    ($($arg:tt)*) => {
        eprintln!("{} {}", chrono::Local::now().format("%Y/%m/%d %H:%M:%S"), format_args!($($arg)*))
    };
}

const USAGE: &str = "lport - 端口转发管理工具 Rust 版 ({version})

用法:
  lport serve     [--config PATH] [--listen ADDR]   前台运行转发服务（目前仅 builtin 后端，暂无 Web 面板）
  lport passwd    [--config PATH] [新密码]          重置管理员密码（不填则随机生成）
  lport list      [--config PATH]                   列出转发规则
  lport add       [--config PATH] [--proto tcp|udp|both] [--name NAME] [--remark TEXT] [--disabled]
                  监听端口 目标地址:端口             添加转发规则（服务运行中时立即生效）
  lport edit      [--config PATH] [--port PORT] [--target HOST:PORT] [--proto tcp|udp|both]
                  [--name NAME] [--remark TEXT] [--enable|--disable]
                  规则名|ID|端口                     修改转发规则（只改指定的项）
  lport remove    [--config PATH] 规则名|ID|端口 ...  删除转发规则
  lport version

install / uninstall / start / stop / restart / probe / detect 及 Web 面板尚未移植，请使用 Go 版。

默认配置文件: {config}
";

fn usage() -> String {
    USAGE
        .replace("{version}", VERSION)
        .replace("{config}", config::DEFAULT_PATH)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((cmd, rest)) = args.split_first() else {
        eprint!("{}", usage());
        std::process::exit(2);
    };
    let res = match cmd.as_str() {
        "serve" => cmd_serve(rest).await,
        "passwd" => cmd_passwd(rest),
        "list" | "ls" => cli::cmd_list(rest).await,
        "add" => cli::cmd_add(rest).await,
        "edit" => cli::cmd_edit(rest).await,
        "remove" | "rm" => cli::cmd_remove(rest).await,
        "install" | "uninstall" | "start" | "stop" | "restart" | "probe" | "detect" => {
            Err(format!("Rust 版暂未实现 {cmd}，请使用 Go 版 lport"))
        }
        "version" | "-v" | "--version" => {
            println!("{VERSION}");
            Ok(())
        }
        "help" | "-h" | "--help" => {
            print!("{}", usage());
            Ok(())
        }
        _ => {
            eprint!("{}", usage());
            std::process::exit(2);
        }
    };
    if let Err(e) = res {
        eprintln!("错误: {e}");
        std::process::exit(1);
    }
}

async fn cmd_serve(args: &[String]) -> Result<(), String> {
    let fs = Flags::parse(args, &[("config", false), ("listen", false)])?;
    if !sysinfo::is_root() {
        logln!("警告: 当前不是 root，低端口将不可用");
    }
    let store = cli::load_config(fs.config(), fs.str("listen").unwrap_or_default())?;
    let backend = store.get().backend;
    if backend != model::BACKEND_BUILTIN {
        return Err(format!(
            "Rust 版目前只支持 builtin 后端，配置中为 {backend}；请改为 backend: builtin，或使用 Go 版 lport"
        ));
    }
    let mgr = Arc::new(Manager::new(Arc::new(store)));
    mgr.start().await;

    let sock = ctl::socket_path(mgr.store().path());
    match ctl::listen(&sock) {
        Ok(l) => {
            let app = ctl::router(mgr.clone());
            tokio::spawn(async move {
                let _ = axum::serve(l, app).await;
            });
        }
        Err(e) => logln!("警告: 控制套接字启动失败，lport add/remove 将无法连接运行中的服务: {e}"),
    }
    logln!(
        "lport {VERSION} (Rust) 已启动，转发规则 {} 条（配置: {}, 后端: builtin）；Web 面板尚未移植",
        mgr.store().get().rules.iter().filter(|r| r.enabled).count(),
        mgr.store().path().display()
    );

    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let name = tokio::select! {
        _ = tokio::signal::ctrl_c() => "SIGINT",
        _ = term.recv() => "SIGTERM",
    };
    logln!("收到信号 {name}，正在停止转发");
    mgr.stop().await;
    let _ = std::fs::remove_file(&sock);
    Ok(())
}

fn cmd_passwd(args: &[String]) -> Result<(), String> {
    let fs = Flags::parse(args, &[("config", false)])?;
    let pw = fs
        .pos
        .first()
        .cloned()
        .unwrap_or_else(config::random_password);
    if pw.len() < 6 {
        return Err("密码至少 6 位".into());
    }
    let store = cli::load_config(fs.config(), "")?;
    let h = config::hash_password(&pw)?;
    store.update(|c| {
        c.admin.password_hash = h;
        Ok(())
    })?;
    println!("用户名: {}\n新密码: {pw}", store.get().admin.username);
    if service::installed() {
        println!("正在重启服务使密码生效...");
        return service::restart();
    }
    Ok(())
}
