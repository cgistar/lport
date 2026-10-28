mod api;
mod auth;
mod backend;
mod builtin;
mod cli;
mod config;
mod ctl;
mod i18n;
mod install;
#[cfg(test)]
mod integration;
mod kernel;
mod manager;
mod model;
mod portcheck;
mod probe;
mod realm;
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
  lport serve     [--config PATH] [--listen ADDR]   启动 Web 管理服务
  lport install   [--config PATH] [--listen ADDR] [--backend NAME] [-y]
                                                    安装程序与系统服务（交互式；-y 或无终端时使用默认值）
  lport uninstall [--config PATH] [--purge]         卸载系统服务，--purge 同时删除配置
  lport start | stop | restart                      启动 / 停止 / 重启系统服务
  lport passwd    [--config PATH] [新密码]          重置管理员密码（不填则随机生成）
  lport list      [--config PATH]                   列出转发规则
  lport add       [--config PATH] [--proto tcp|udp|both] [--name NAME] [--remark TEXT] [--disabled]
                  监听端口 目标地址:端口             添加转发规则（服务运行中时立即生效）
  lport edit      [--config PATH] [--port PORT] [--target HOST:PORT] [--proto tcp|udp|both]
                  [--name NAME] [--remark TEXT] [--enable|--disable]
                  规则名|ID|端口                     修改转发规则（只改指定的项）
  lport remove    [--config PATH] 规则名|ID|端口 ...  删除转发规则
  lport probe     [--config PATH] [规则名|ID|端口 ...] 检测规则连通性（本机经转发 / 直连目标）
  lport detect                                      检测系统环境与依赖工具
  lport version

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
        "install" => install::cmd_install(rest),
        "uninstall" => install::cmd_uninstall(rest),
        "start" | "stop" | "restart" => install::cmd_service(cmd),
        "probe" => cli::cmd_probe(rest).await,
        "detect" => {
            install::cmd_detect();
            Ok(())
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
        logln!("警告: 当前不是 root，iptables/nftables 后端、低端口和软件安装将不可用");
    }
    let store = Arc::new(cli::load_config(
        fs.config(),
        fs.str("listen").unwrap_or_default(),
    )?);
    let mgr = Arc::new(Manager::new(store.clone()));
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

    let listen = mgr.store().get().listen;
    // 与 Go 一致：省略主机（如 :8080）时监听所有地址
    let bind = if listen.starts_with(':') {
        format!("0.0.0.0{listen}")
    } else {
        listen.clone()
    };
    let web = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            mgr.stop().await;
            let _ = std::fs::remove_file(&sock);
            return Err(format!("Web 服务启动失败: listen tcp {listen}: {e}"));
        }
    };
    let app = api::router(store, mgr.clone())
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    let server = tokio::spawn(async move { axum::serve(web, app).await });
    logln!(
        "lport {VERSION} (Rust) 已启动: http://{listen}  (配置: {}, 后端: {})",
        mgr.store().path().display(),
        mgr.backend_name().await
    );

    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let name = tokio::select! {
        _ = tokio::signal::ctrl_c() => "SIGINT",
        _ = term.recv() => "SIGTERM",
        r = server => {
            mgr.stop().await;
            let _ = std::fs::remove_file(&sock);
            let e = match r {
                Ok(Err(e)) => e.to_string(),
                Ok(Ok(())) => "服务已退出".into(),
                Err(e) => e.to_string(),
            };
            return Err(format!("Web 服务异常退出: {e}"));
        }
    };
    logln!("收到信号 {name}，正在停止并清理转发规则");
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
