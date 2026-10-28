//! 后端消息的中文格式串 → 英文格式串，参数动词（%s %d %v %w %q）的数量与顺序必须一致。
//! 新增返回给 Web 界面的中文消息时需在这里补充译文，i18n::tests::catalog_covers_source 会检查遗漏。
//! 格式串沿用 Go 版（v0.2.0 及以前）的写法，%s 等动词对应 Rust 格式串中的 {} 占位符。

pub const CATALOG: &[(&str, &str)] = &[
    // api
    ("未登录", "Not logged in"),
    ("登录已过期", "Session expired"),
    (
        "Content-Type 必须为 application/json",
        "Content-Type must be application/json",
    ),
    ("请求格式错误", "Malformed request"),
    ("请指定要安装的工具", "Specify the tools to install"),
    (
        "端口必须在 1-65535 之间",
        "Port must be between 1 and 65535",
    ),
    // auth
    (
        "登录失败次数过多，请一分钟后再试",
        "Too many failed login attempts; try again in a minute",
    ),
    ("用户名或密码错误", "Incorrect username or password"),
    (
        "新密码至少 6 位",
        "New password must be at least 6 characters",
    ),
    ("原密码错误", "Current password is incorrect"),
    // model
    (
        "目标地址格式应为 host:port",
        "Target must be in host:port format",
    ),
    ("目标端口无效: %s", "Invalid target port: %s"),
    ("目标主机不能为空", "Target host must not be empty"),
    (
        "协议必须是 tcp / udp / both",
        "Protocol must be tcp / udp / both",
    ),
    (
        "监听端口必须在 1-65535 之间",
        "Listen port must be between 1 and 65535",
    ),
    (
        "目标主机既不是 IP 也不是合法域名: %s",
        "Target host is neither an IP address nor a valid domain name: %s",
    ),
    (
        "目前仅支持 IPv4 目标地址",
        "Only IPv4 targets are supported",
    ),
    (
        "%s 后端不能转发到回环地址 %s，请改用 builtin 或 realm 后端",
        "The %s backend cannot forward to loopback address %s; use the builtin or realm backend instead",
    ),
    ("目标地址不能是 0.0.0.0", "Target address cannot be 0.0.0.0"),
    // manager
    (
        "与规则「%s」(%s/%d) 冲突",
        r#"Conflicts with rule "%s" (%s/%d)"#,
    ),
    ("与管理面板端口冲突", "Conflicts with the admin panel port"),
    ("未知进程", "an unknown process"),
    (
        "%s 端口 %d 已被 %s 占用 (%s)",
        "%s port %d is in use by %s (%s)",
    ),
    ("%s 端口 %d 无法绑定: %v", "%s port %d cannot be bound: %v"),
    ("端口冲突: %s", "Port conflict: %s"),
    ("应用规则失败: %w", "Failed to apply rules: %w"),
    ("规则不存在", "Rule not found"),
    ("未知后端: %s", "Unknown backend: %s"),
    (
        "规则「%s」不适用于 %s 后端: %w",
        r#"Rule "%s" is not compatible with the %s backend: %w"#,
    ),
    ("切换到 %s 失败: %w", "Failed to switch to %s: %w"),
    ("规则未启用", "Rule is disabled"),
    // probe
    ("连接成功", "Connected"),
    ("连接成功，收到数据", "Connected, data received"),
    (
        "连接建立后立即被关闭（转发进程无法连接目标）",
        "Connection was closed right after it opened (the forwarding process could not reach the target)",
    ),
    ("收到响应", "Response received"),
    (
        "无响应（UDP 无法确认端口是否开放，服务可能只响应特定协议数据）",
        "No response (UDP cannot confirm whether the port is open; the service may only reply to protocol-specific data)",
    ),
    (
        "连接被拒绝（端口未监听）",
        "Connection refused (port is not listening)",
    ),
    (
        "连接超时（可能被防火墙丢弃或主机不可达）",
        "Connection timed out (possibly dropped by a firewall, or the host is unreachable)",
    ),
    ("主机不可达", "Host unreachable"),
    ("网络不可达", "Network unreachable"),
    // backend
    ("%s %s: 执行超时（%s）", "%s %s: timed out (%s)"),
    (
        "清理 iptables 规则失败，仍残留: %s",
        "Failed to clean up iptables rules; still present: %s",
    ),
    (
        "删除 FORWARD 放行规则失败",
        "Failed to remove the FORWARD accept rule",
    ),
    (
        "删除 nftables 表失败: %w",
        "Failed to delete the nftables table: %w",
    ),
    ("进程已退出", "Process exited"),
    ("%s 启动失败（%s/%d）: %s", "%s failed to start (%s/%d): %s"),
    (
        "%s 未安装，请先在概览页安装",
        "%s is not installed; install it from the Overview page first",
    ),
    (
        "添加 FORWARD 放行规则失败: %w",
        "Failed to add the FORWARD accept rule: %w",
    ),
    ("解析 %s 失败: %v", "Failed to resolve %s: %v"),
    (
        "%s 没有可用的 IPv4 地址（不能是回环地址）",
        "%s has no usable IPv4 address (loopback addresses are not allowed)",
    ),
    // sysinfo
    (
        "开启 ip_forward 失败: %w",
        "Failed to enable ip_forward: %w",
    ),
    (
        "已有安装任务正在进行，请稍后再试",
        "Another installation is in progress; try again later",
    ),
    (
        "需要 root 权限才能安装软件包",
        "Root privileges are required to install packages",
    ),
    ("未知工具: %s", "Unknown tool: %s"),
    (
        "无法识别当前系统的包管理器，请手动安装",
        "Could not detect the system package manager; install manually",
    ),
    ("安装失败: %w", "Installation failed: %w"),
    ("%s 不支持下载安装", "%s cannot be installed by download"),
    (
        "realm 未提供 %s 架构的预编译版本，请手动安装",
        "realm has no prebuilt release for %s; install it manually",
    ),
    ("下载失败: %w", "Download failed: %w"),
    ("下载失败: HTTP %d", "Download failed: HTTP %d"),
    ("解压失败: %w", "Failed to extract: %w"),
    ("发布包中没有 %s", "The release archive does not contain %s"),
    ("写入失败: %w", "Write failed: %w"),
    ("%s 超过大小上限", "%s exceeds the size limit"),
    // config
    (
        "解析配置文件 %s 失败: %w",
        "Failed to parse config file %s: %w",
    ),
    ("配置文件 %s 校验失败: %w", "Invalid config file %s: %w"),
    (
        "listen 格式错误 %q，应为 ip:port",
        "Invalid listen address %q; expected ip:port",
    ),
    (
        "backend 必须是 builtin / realm / iptables / nftables，当前为 %q",
        "backend must be builtin / realm / iptables / nftables, got %q",
    ),
    ("第 %d 条规则 (%s): %w", "Rule %d (%s): %w"),
    (
        "规则 %s 的监听端口 %d 与管理面板端口冲突",
        "Rule %s: listen port %d conflicts with the admin panel port",
    ),
    (
        "规则 %s 与 %s 的监听端口 %d 冲突",
        "Rules %s and %s both listen on port %d",
    ),
    ("保存配置失败: %w", "Failed to save configuration: %w"),
    // service
    (
        "未检测到 systemd 或 OpenRC，请手动运行: lport serve",
        "Neither systemd nor OpenRC was detected; run lport serve manually",
    ),
    (
        "复制程序到 %s 失败: %w",
        "Failed to copy the binary to %s: %w",
    ),
    // Rust 版新增
    (
        "读取配置文件 %s 失败: %v",
        "Failed to read config file %s: %v",
    ),
    ("无法解析时间: %s", "Cannot parse time: %s"),
    (
        "下载 realm 需要 curl 或 wget",
        "Downloading realm requires curl or wget",
    ),
    ("命令执行失败", "the command failed"),
    ("执行超时（%s）", "timed out (%s)"),
    ("%s 不完整（%d/%d 字节）", "%s is incomplete (%d/%d bytes)"),
    ("%s 没有 IPv4 地址", "%s has no IPv4 address"),
    ("连接目标超时", "Timed out connecting to the target"),
    ("超时", "timed out"),
];
