//! 把后端返回给 Web 界面的中文消息翻译为英文，对应 Go 版 internal/i18n。
//!
//! 译文表直接取自 Go 版的 internal/i18n/catalog.go（编译时嵌入），两个版本共用一份；
//! Rust 版特有的消息在 RUST_CATALOG 中补充。匹配算法与 Go 版相同：用中文格式串匹配已生成的消息、
//! 提取参数（参数中的嵌套消息递归翻译），再套用译文格式重新生成。

use std::sync::OnceLock;

pub const ZH: &str = "zh";
pub const EN: &str = "en";

/// 拼接多条消息时使用的分隔符（如多个端口冲突），翻译时先按它拆分。
const LIST_SEP: &str = "；";

const GO_CATALOG: &str = include_str!("../../internal/i18n/catalog.go");

/// Rust 版特有的消息（Go 版没有对应的中文原文）。
const RUST_CATALOG: &[(&str, &str)] = &[
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

/// 格式串中的一段：字面量或参数。
#[derive(Debug, Clone, PartialEq)]
enum Part {
    Lit(String),
    /// 参数动词：s d v w q
    Verb(char),
}

struct Entry {
    parts: Vec<Part>,
    /// 译文按动词拆开的字面量片段，len = 动词数 + 1
    en: Vec<String>,
    verbs: Vec<char>,
    /// 原文开头字面量的长度（字节）
    prefix: usize,
    /// 原文字面量总长度（字节）
    literal: usize,
    /// 与 Go 版 regexp.String() 相同的排序键，相同优先级时保证匹配顺序一致
    key: String,
}

/// 按 %s %d %v %w %q 拆分格式串。
fn split_verbs(s: &str) -> (Vec<String>, Vec<char>) {
    let (mut lits, mut verbs, mut cur) = (Vec::new(), Vec::new(), String::new());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '%'
            && let Some(&v) = it.peek()
            && "sdvwq".contains(v)
        {
            it.next();
            lits.push(std::mem::take(&mut cur));
            verbs.push(v);
            continue;
        }
        cur.push(c);
    }
    lits.push(cur);
    (lits, verbs)
}

/// regexp.QuoteMeta
fn quote_meta(s: &str) -> String {
    s.chars().fold(String::new(), |mut o, c| {
        if r"\.+*?()|[]{}^$".contains(c) {
            o.push('\\');
        }
        o.push(c);
        o
    })
}

fn compile(zh: &str, en: &str) -> Entry {
    let (lits, verbs) = split_verbs(zh);
    let (en, _) = split_verbs(en);
    let mut parts = Vec::new();
    let mut key = String::from("^");
    for (i, lit) in lits.iter().enumerate() {
        key.push_str(&quote_meta(lit));
        if !lit.is_empty() {
            parts.push(Part::Lit(lit.clone()));
        }
        if let Some(&v) = verbs.get(i) {
            key.push_str(match v {
                'd' => r"(-?\d+)",
                'q' => r#"("(?:[^"\\]|\\.)*")"#,
                _ => "(.*?)",
            });
            parts.push(Part::Verb(v));
        }
    }
    key.push('$');
    Entry {
        prefix: lits[0].len(),
        literal: lits.iter().map(String::len).sum(),
        parts,
        en,
        verbs,
        key,
    }
}

/// 解析 Go 源码中 map[string]string 字面量的条目（"..." 或 `...` 字符串）。
fn parse_go_catalog(src: &str) -> Vec<(String, String)> {
    fn string_lit(s: &str) -> Option<(String, &str)> {
        let s = s.trim_start();
        if let Some(rest) = s.strip_prefix('`') {
            let end = rest.find('`')?;
            return Some((rest[..end].to_string(), &rest[end + 1..]));
        }
        let rest = s.strip_prefix('"')?;
        let mut out = String::new();
        let mut chars = rest.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => return Some((out, &rest[i + 1..])),
                '\\' => match chars.next()?.1 {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    c => out.push(c),
                },
                c => out.push(c),
            }
        }
        None
    }
    let body = src.split_once("map[string]string{").map_or("", |(_, b)| b);
    let mut out = Vec::new();
    for line in body.lines() {
        let Some((zh, rest)) = string_lit(line) else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix(':') else {
            continue;
        };
        if let Some((en, _)) = string_lit(rest) {
            out.push((zh, en));
        }
    }
    out
}

fn catalog() -> &'static [(String, String)] {
    static C: OnceLock<Vec<(String, String)>> = OnceLock::new();
    C.get_or_init(|| {
        let mut c = parse_go_catalog(GO_CATALOG);
        c.extend(
            RUST_CATALOG
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string())),
        );
        c
    })
}

fn entries() -> &'static [Entry] {
    static E: OnceLock<Vec<Entry>> = OnceLock::new();
    E.get_or_init(|| {
        let mut out: Vec<Entry> = catalog().iter().map(|(zh, en)| compile(zh, en)).collect();
        // 匹配顺序：开头字面量越长越优先（外层包装消息以固定文字开头、内层错误在末尾，
        // 先试外层才能正确拆分嵌套消息），其次字面量越长越具体
        out.sort_by(|a, b| {
            b.prefix
                .cmp(&a.prefix)
                .then(b.literal.cmp(&a.literal))
                .then(a.key.cmp(&b.key))
        });
        out
    })
}

/// 参数 %d 可匹配的前缀长度候选（由短到长）。
fn match_int(s: &str) -> Vec<usize> {
    let b = s.as_bytes();
    let start = usize::from(b.first() == Some(&b'-'));
    let digits = b[start..].iter().take_while(|c| c.is_ascii_digit()).count();
    (1..=digits).map(|n| start + n).collect()
}

/// 参数 %q：一个带转义的双引号字符串。
fn match_quoted(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            b'\\' if i + 1 < b.len() => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// 整串匹配 parts，返回各参数；与 `^...(.*?)...$` 的正则语义相同（非贪婪参数先试最短）。
fn match_parts(parts: &[Part], s: &str, args: &mut Vec<String>) -> bool {
    let Some((first, rest)) = parts.split_first() else {
        return s.is_empty();
    };
    match first {
        Part::Lit(l) => s
            .strip_prefix(l.as_str())
            .is_some_and(|r| match_parts(rest, r, args)),
        Part::Verb(v) => {
            let candidates: Vec<usize> = match v {
                'd' => match_int(s),
                'q' => match_quoted(s).into_iter().collect(),
                _ => s
                    .char_indices()
                    .map(|(i, _)| i)
                    .chain(std::iter::once(s.len()))
                    .collect(),
            };
            for n in candidates {
                args.push(s[..n].to_string());
                if match_parts(rest, &s[n..], args) {
                    return true;
                }
                args.pop();
            }
            false
        }
    }
}

fn cjk_count(s: &str) -> usize {
    s.chars()
        .filter(|&c| {
            matches!(c as u32,
                0x2E80..=0x2E99 | 0x2E9B..=0x2EF3 | 0x2F00..=0x2FD5 | 0x3005 | 0x3007 | 0x3021..=0x3029
                | 0x3038..=0x303B | 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x20000..=0x3134F)
        })
        .count()
}

/// 把后端生成的中文消息翻译为 lang；无对应译文的部分保持原样。
pub fn translate(s: &str, lang: &str) -> String {
    if lang != EN {
        s.to_string()
    } else {
        translate_inner(s).0
    }
}

/// 译文及其中残留的中文字符数。一条消息可能被多个格式匹配，按 entries 顺序逐个尝试，
/// 取残留中文最少的拆法（相同时取先试到的）；拆错时参数通常无法完整翻译，残留会更多。
fn translate_inner(s: &str) -> (String, usize) {
    let mut residual = cjk_count(s);
    if residual == 0 {
        return (s.to_string(), 0);
    }
    if s.contains(LIST_SEP) {
        let mut total = 0;
        let parts: Vec<String> = s
            .split(LIST_SEP)
            .map(|p| {
                let (t, n) = translate_inner(p);
                total += n;
                t
            })
            .collect();
        return (parts.join("; "), total);
    }
    let mut best = s.to_string();
    for e in entries() {
        let mut args = Vec::new();
        if !match_parts(&e.parts, s, &mut args) {
            continue;
        }
        let mut out = String::new();
        let mut left = 0;
        for (i, lit) in e.en.iter().enumerate() {
            out.push_str(lit);
            if let (Some(&v), Some(arg)) = (e.verbs.get(i), args.get(i)) {
                if v == 'd' || v == 'q' {
                    left += cjk_count(arg);
                    out.push_str(arg);
                } else {
                    let (t, n) = translate_inner(arg);
                    left += n;
                    out.push_str(&t);
                }
            }
        }
        if left < residual {
            (best, residual) = (out, left);
            if left == 0 {
                break;
            }
        }
    }
    (best, residual)
}

/// 请求使用的语言：优先 Web 界面发送的 X-Lport-Lang，其次 Accept-Language；都没有时为中文。
pub fn from_headers(lport_lang: Option<&str>, accept_language: Option<&str>) -> &'static str {
    match lport_lang.map(str::to_lowercase).as_deref() {
        Some(EN) => return EN,
        Some(ZH) => return ZH,
        _ => {}
    }
    let al = accept_language.unwrap_or("").trim().to_lowercase();
    if al.is_empty() || al.starts_with("zh") {
        ZH
    } else {
        EN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 与 Go 版 TestTranslate 的用例相同
    #[test]
    fn translate_like_go() {
        for (input, want) in [
            ("规则不存在", "Rule not found"),
            ("目标端口无效: abc", "Invalid target port: abc"),
            (
                "与规则「web」(tcp/8080) 冲突",
                r#"Conflicts with rule "web" (tcp/8080)"#,
            ),
            (
                "tcp 端口 22 已被 sshd (pid 1) 占用 (0.0.0.0:22)",
                "tcp port 22 is in use by sshd (pid 1) (0.0.0.0:22)",
            ),
            (
                "udp 端口 53 已被 未知进程 占用 (0.0.0.0:53)",
                "udp port 53 is in use by an unknown process (0.0.0.0:53)",
            ),
            (
                "端口冲突: 与规则「a」(tcp/80) 冲突；与规则「b」(udp/80) 冲突；与管理面板端口冲突",
                r#"Port conflict: Conflicts with rule "a" (tcp/80); Conflicts with rule "b" (udp/80); Conflicts with the admin panel port"#,
            ),
            (
                "应用规则失败: nftables 未安装，请先在概览页安装",
                "Failed to apply rules: nftables is not installed; install it from the Overview page first",
            ),
            (
                "规则「x」不适用于 nftables 后端: nftables 后端不能转发到回环地址 127.0.0.1，请改用 builtin 或 realm 后端",
                r#"Rule "x" is not compatible with the nftables backend: The nftables backend cannot forward to loopback address 127.0.0.1; use the builtin or realm backend instead"#,
            ),
            (
                "解析 foo.example 失败: lookup foo.example: no such host",
                "Failed to resolve foo.example: lookup foo.example: no such host",
            ),
            (
                r#"listen 格式错误 "abc"，应为 ip:port"#,
                r#"Invalid listen address "abc"; expected ip:port"#,
            ),
            ("tcp: connection reset", "tcp: connection reset"),
            ("某条未收录的消息", "某条未收录的消息"),
        ] {
            assert_eq!(translate(input, EN), want, "{input}");
            assert_eq!(translate(input, ZH), input);
        }
    }

    #[test]
    fn catalog_parsed() {
        let c = catalog();
        assert!(c.len() > 80, "解析出的条目太少: {}", c.len());
        assert!(c.iter().any(|(zh, en)| zh == "与规则「%s」(%s/%d) 冲突"
            && en == r#"Conflicts with rule "%s" (%s/%d)"#));
        for (zh, en) in c {
            assert_eq!(
                split_verbs(zh).1,
                split_verbs(en).1,
                "{zh:?} 与译文 {en:?} 的参数不一致"
            );
            assert!(!zh.contains(LIST_SEP), "{zh:?} 含列表分隔符");
        }
    }

    #[test]
    fn lang_from_headers() {
        for (h, al, want) in [
            (Some("en"), Some("zh-CN,zh"), EN),
            (Some("zh"), Some("en-US"), ZH),
            (None, Some("en-US,en;q=0.9"), EN),
            (None, Some("zh-CN,zh;q=0.9"), ZH),
            (None, None, ZH),
        ] {
            assert_eq!(from_headers(h, al), want, "{h:?} {al:?}");
        }
    }

    /// 可能返回给 Web 界面的源码文件（日志、命令行输出与测试除外）。
    const USER_FACING: &[&str] = &[
        "auth.rs",
        "api.rs",
        "backend.rs",
        "builtin.rs",
        "config.rs",
        "kernel.rs",
        "manager.rs",
        "model.rs",
        "portcheck.rs",
        "probe.rs",
        "realm.rs",
        "sysinfo.rs",
    ];

    /// 只用于日志或配置文件、不会返回给 Web 界面的中文字面量。
    const NOT_USER_FACING: &[&str] = &[
        "# lport 配置文件，可手动编辑，重启服务后生效。\n# admin.password 可填写明文密码，启动时会自动转换为 password_hash。\n",
        "HMAC 接受任意长度的密钥",
    ];

    /// 去掉日志宏调用与测试模块，返回剩余源码中的字符串字面量。
    fn literals(src: &str) -> Vec<String> {
        let src = src.split("#[cfg(test)]\nmod tests").next().unwrap();
        let mut out = Vec::new();
        let b = src.as_bytes();
        let mut i = 0;
        let mut depth_skip: Option<i32> = None;
        while i < b.len() {
            if depth_skip.is_none() {
                for m in [
                    "logln!(",
                    "println!(",
                    "eprintln!(",
                    "panic!(",
                    "assert!(",
                    "assert_eq!(",
                    ".expect(",
                ] {
                    if src[i..].starts_with(m) {
                        depth_skip = Some(0);
                        break;
                    }
                }
            }
            match b[i] {
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    i += src[i..].find('\n').unwrap_or(src.len() - i);
                    continue;
                }
                b'\'' if b.get(i + 2) == Some(&b'\'') || b.get(i + 1) == Some(&b'\\') => {
                    // 字符字面量
                    i += src[i + 1..].find('\'').map_or(1, |n| n + 2);
                    continue;
                }
                b'(' => {
                    if let Some(d) = depth_skip.as_mut() {
                        *d += 1;
                    }
                }
                b')' => {
                    if let Some(d) = depth_skip.as_mut() {
                        *d -= 1;
                        if *d == 0 {
                            depth_skip = None;
                        }
                    }
                }
                b'"' => {
                    let start = i + 1;
                    let mut j = start;
                    while j < b.len() && b[j] != b'"' {
                        j += if b[j] == b'\\' { 2 } else { 1 };
                    }
                    if depth_skip.is_none() {
                        out.push(src[start..j].replace("\\n", "\n").replace("\\\"", "\""));
                    }
                    i = j + 1;
                    continue;
                }
                _ => {}
            }
            i += 1;
        }
        out
    }

    /// Rust 格式串中的 {..} 占位符替换为示例参数，{:?}（对应 Go 的 %q）替换为带引号的值。
    fn sample(lit: &str) -> String {
        let mut out = String::new();
        let mut it = lit.chars().peekable();
        while let Some(c) = it.next() {
            if c == '{' && it.peek() != Some(&'{') {
                let mut spec = String::new();
                for c in it.by_ref() {
                    if c == '}' {
                        break;
                    }
                    spec.push(c);
                }
                out.push_str(if spec.ends_with(":?") { "\"1\"" } else { "1" });
                continue;
            }
            out.push(c);
        }
        out
    }

    // 检查可能返回给 Web 界面的中文字符串都有译文（对应 Go 版 TestCatalogCoversSource）
    #[test]
    fn catalog_covers_source() {
        let mut missing = Vec::new();
        for f in USER_FACING {
            let path = format!("{}/src/{f}", env!("CARGO_MANIFEST_DIR"));
            let src = std::fs::read_to_string(&path).unwrap();
            for lit in literals(&src) {
                if cjk_count(&lit) == 0 || NOT_USER_FACING.contains(&lit.as_str()) {
                    continue;
                }
                let s = sample(&lit);
                let (t, left) = translate_inner(&s);
                if left > 0 {
                    missing.push(format!("{f}: {lit:?} → {t:?}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "以下消息缺少英文译文:\n  {}",
            missing.join("\n  ")
        );
    }
}
