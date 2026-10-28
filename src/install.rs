//! 安装、卸载与服务管理命令（install / uninstall / start / stop / restart / detect）及安装时的交互问答。

use std::io::{self, BufRead, Write};

use crate::cli::Flags;
use crate::config::{self, Store};
use crate::model::{self, Rule};
use crate::{portcheck, service, sysinfo};

fn require_root() -> Result<(), String> {
    if sysinfo::is_root() {
        Ok(())
    } else {
        Err("需要 root 权限运行".into())
    }
}

fn isatty(fd: i32) -> bool {
    // SAFETY: isatty 只查询描述符
    unsafe { libc::isatty(fd) == 1 }
}

/// 安装时的交互问答；非交互模式下所有问题直接取默认值。
struct Prompter {
    interactive: bool,
}

impl Prompter {
    fn new(allow: bool) -> Self {
        Prompter {
            interactive: allow && isatty(0),
        }
    }

    /// 读取一行；输入结束（如 Ctrl-D）时取消安装，此时配置尚未写入。
    fn line(&self, prompt: &str) -> String {
        print!("{prompt}");
        let _ = io::stdout().flush();
        let mut s = String::new();
        if io::stdin().lock().read_line(&mut s).unwrap_or(0) == 0 && s.trim().is_empty() {
            println!("\n输入已结束，安装已取消");
            std::process::exit(1);
        }
        s.trim().to_string()
    }

    /// 询问是否，def 为直接回车时的默认值。
    fn confirm(&self, question: &str, def: bool) -> bool {
        if !self.interactive {
            return def;
        }
        let hint = if def { "[Y/n]" } else { "[y/N]" };
        loop {
            match self
                .line(&format!("{question} {hint}: "))
                .to_lowercase()
                .as_str()
            {
                "" => return def,
                "y" | "yes" => return true,
                "n" | "no" => return false,
                _ => {}
            }
        }
    }

    /// 读取并确认新密码；直接回车返回空字符串，表示使用随机密码。
    fn password(&self) -> Result<String, String> {
        loop {
            let a = read_password("设置管理员密码（至少 6 位，直接回车随机生成）: ")?;
            if a.is_empty() {
                return Ok(a);
            }
            if a.len() < 6 {
                println!("  密码至少 6 位，请重新输入");
                continue;
            }
            if read_password("再次输入密码: ")? != a {
                println!("  两次输入不一致，请重新输入");
                continue;
            }
            return Ok(a);
        }
    }

    /// 让用户选择转发工具，默认 nftables；会拒绝与已有规则不兼容的后端。
    fn choose_backend(&self, rules: &[Rule]) -> String {
        const DEF: &str = model::BACKEND_NFTABLES;
        let order = [
            model::BACKEND_NFTABLES,
            model::BACKEND_IPTABLES,
            model::BACKEND_REALM,
            model::BACKEND_BUILTIN,
        ];
        println!("选择默认转发工具:");
        for (i, b) in order.iter().enumerate() {
            let state = if *b == model::BACKEND_BUILTIN {
                "内置，无需安装"
            } else if sysinfo::tool_installed(b) {
                "已安装"
            } else {
                "未安装，选择后可自动安装"
            };
            println!("  {}) {b:<9} {state}", i + 1);
        }
        loop {
            let ans = self
                .line(&format!(
                    "请选择 nftables / iptables / realm / builtin [{DEF}]: "
                ))
                .to_lowercase();
            let b = match ans.parse::<usize>() {
                _ if ans.is_empty() => DEF.to_string(),
                Ok(n) if (1..=order.len()).contains(&n) => order[n - 1].to_string(),
                _ => ans,
            };
            if !model::valid_backend(&b) {
                println!("  无效的选择");
                continue;
            }
            if let Err(e) = rules_compatible(rules, &b) {
                println!("  {e}");
                continue;
            }
            return b;
        }
    }
}

/// 关闭回显读取一行密码。
fn read_password(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    let _ = io::stdout().flush();
    // SAFETY: termios 为纯数据结构，tcgetattr 成功时完整填充
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let tty = unsafe { libc::tcgetattr(0, &mut old) } == 0;
    if tty {
        let mut t = old;
        t.c_lflag &= !libc::ECHO;
        t.c_lflag |= libc::ECHONL;
        // SAFETY: 修改标准输入的终端属性，读取后恢复
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) };
    }
    let mut s = String::new();
    let res = io::stdin().lock().read_line(&mut s);
    if tty {
        // SAFETY: 恢复原终端属性
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &old) };
    } else {
        println!();
    }
    match res {
        Ok(0) => {
            println!("\n输入已结束，安装已取消");
            std::process::exit(1);
        }
        Ok(_) => Ok(s.trim_end_matches(['\r', '\n']).to_string()),
        Err(e) => Err(e.to_string()),
    }
}

fn rules_compatible(rules: &[Rule], backend: &str) -> Result<(), String> {
    for r in rules {
        r.clone()
            .validate(backend)
            .map_err(|e| format!("规则「{}」不适用于 {backend}: {e}", r.name))?;
    }
    Ok(())
}

pub fn cmd_install(args: &[String]) -> Result<(), String> {
    let fs = Flags::parse(
        args,
        &[
            ("config", false),
            ("listen", false),
            ("backend", false),
            ("y", true),
        ],
    )?;
    require_root()?;
    let cfg_path = fs.config().to_string();
    let p = Prompter::new(!fs.bool("y"));

    // 问答结束前不写文件，中途退出不会留下用户不知道的随机密码
    let (store, res) = Store::load_no_save(&cfg_path)?;

    // 1. 管理员密码：配置中没有密码时询问
    let mut generated = res.generated_password.clone();
    let mut pw_hash = String::new();
    if !generated.is_empty() && p.interactive {
        let pw = p.password()?;
        if !pw.is_empty() {
            pw_hash = config::hash_password(&pw)?;
            generated.clear();
        }
    }

    // 2. 转发工具：命令行指定 > 交互选择（仅配置中未指定时）> 自动选择
    let rules = store.get().rules;
    let mut backend = store.get().backend;
    if let Some(b) = fs.str("backend") {
        if !model::valid_backend(b) {
            return Err("--backend 必须是 nftables / iptables / realm / builtin".into());
        }
        backend = b.to_string();
    } else if res.backend_auto && p.interactive {
        backend = p.choose_backend(&rules);
    } else if res.backend_auto
        && !sysinfo::tool_installed(&backend)
        && rules_compatible(&rules, model::BACKEND_NFTABLES).is_ok()
    {
        // 非交互且没有任何可用工具时，使用默认的 nftables 并自动安装
        backend = model::BACKEND_NFTABLES.into();
    }
    rules_compatible(&rules, &backend)?;
    let listen = fs.str("listen").unwrap_or_default().to_string();
    store.update(|c| {
        c.backend = backend.clone();
        if !pw_hash.is_empty() {
            c.admin.password_hash = pw_hash.clone();
        }
        if !listen.is_empty() {
            c.listen = listen.clone();
        }
        Ok(())
    })?;
    ensure_tool(&p, &backend);

    // 3. 系统服务：首次安装时询问；已安装则直接升级并重启
    let init = service::init_system();
    let install_svc = if init.is_empty() {
        println!("未检测到 systemd 或 OpenRC，跳过服务注册");
        false
    } else if !service::installed() {
        p.confirm(&format!("是否安装为系统服务（{init}）并开机自启?"), true)
    } else {
        true
    };
    if install_svc {
        service::install(&cfg_path)?;
    } else {
        service::copy_self().map_err(|e| format!("复制程序到 {} 失败: {e}", service::BIN_PATH))?;
    }

    let c = store.get();
    println!(
        "\n安装完成\n  程序:     {}\n  配置:     {cfg_path}\n  管理地址: http://{}\n  转发工具: {}\n  用户名:   {}",
        service::BIN_PATH,
        c.listen,
        c.backend,
        c.admin.username
    );
    if !generated.is_empty() {
        println!("  密码:     {generated}（随机生成，请登录后修改，或执行 lport passwd 重置）");
    }
    if !install_svc {
        println!(
            "  未注册服务，手动启动: {} serve --config {cfg_path}",
            service::BIN_PATH
        );
    }
    Ok(())
}

/// 检查后端依赖的工具，缺失时询问（非交互模式直接）安装。
fn ensure_tool(p: &Prompter, backend: &str) {
    if backend == model::BACKEND_BUILTIN || sysinfo::tool_installed(backend) {
        return;
    }
    let info = sysinfo::detect();
    let cmdline = sysinfo::tools_install_command(info.package_manager, &[backend]);
    if cmdline.is_empty() {
        println!("警告: {backend} 未安装且无法识别包管理器，请手动安装后执行 lport restart");
        return;
    }
    if !p.confirm(
        &format!("{backend} 未安装，是否现在安装（{cmdline}）?"),
        true,
    ) {
        println!("警告: {backend} 未安装，转发规则不会生效。可稍后执行: {cmdline}");
        return;
    }
    println!("正在安装 {backend} ...");
    let (_, out, res) = sysinfo::install(&[backend]);
    if let Err(e) = res {
        print!("{out}");
        println!("警告: {e}，可稍后手动安装: {cmdline}");
    }
}

pub fn cmd_uninstall(args: &[String]) -> Result<(), String> {
    let fs = Flags::parse(args, &[("config", false), ("purge", true)])?;
    require_root()?;
    service::uninstall(fs.config(), fs.bool("purge"))?;
    println!("已卸载");
    Ok(())
}

/// 通过 systemd / OpenRC 启动、停止或重启已安装的服务。
pub fn cmd_service(action: &str) -> Result<(), String> {
    require_root()?;
    if service::init_system().is_empty() {
        return Err("未检测到 systemd 或 OpenRC".into());
    }
    if !service::installed() {
        return Err("服务未安装，请先执行 lport install".into());
    }
    match action {
        "start" => service::start()?,
        "stop" => service::stop()?,
        _ => service::restart()?,
    }
    println!(
        "{}",
        if service::running() {
            "服务运行中"
        } else {
            "服务已停止"
        }
    );
    Ok(())
}

pub fn cmd_detect() {
    let info = sysinfo::detect();
    println!(
        "系统:       {} ({}, 家族: {})",
        info.os_name, info.os_id, info.family
    );
    println!("内核:       {}", info.kernel);
    println!("包管理器:   {}", info.package_manager);
    println!("init 系统:  {}", info.init_system);
    println!("root:       {}", info.is_root);
    println!("ip_forward: {}", info.ip_forward);
    println!("工具:");
    for t in &info.tools {
        if t.installed {
            println!("  [✓] {:<9} {}  {}", t.name, t.path, t.version);
        } else {
            println!("  [✗] {:<9} 未安装", t.name);
        }
    }
    if !info.install_command.is_empty() {
        println!("安装缺失工具: {}", info.install_command);
    }
    println!("系统已占用端口: {} 个", portcheck::listeners(false).len());
}
