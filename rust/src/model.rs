use std::net::IpAddr;

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, SecondsFormat};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const PROTO_TCP: &str = "tcp";
pub const PROTO_UDP: &str = "udp";
pub const PROTO_BOTH: &str = "both";

pub const BACKEND_BUILTIN: &str = "builtin";
pub const BACKEND_REALM: &str = "realm";
pub const BACKEND_IPTABLES: &str = "iptables";
pub const BACKEND_NFTABLES: &str = "nftables";

/// 已移除的 socat 后端，加载旧配置时迁移为 builtin。
pub const LEGACY_BACKEND_SOCAT: &str = "socat";

pub const BACKENDS: [&str; 4] = [
    BACKEND_BUILTIN,
    BACKEND_REALM,
    BACKEND_IPTABLES,
    BACKEND_NFTABLES,
];

/// 是否为用户态后端（内置转发 / realm）：自行解析域名，可转发到回环地址。
pub fn user_space(backend: &str) -> bool {
    backend == BACKEND_BUILTIN || backend == BACKEND_REALM
}

pub fn valid_backend(b: &str) -> bool {
    BACKENDS.contains(&b)
}

/// 一条端口转发规则：本机 listen_port → target(host:port)。字段与 Go 版的 yaml / json 格式一致。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rule {
    #[serde(deserialize_with = "nullable_string")]
    pub id: String,
    #[serde(deserialize_with = "nullable_string")]
    pub name: String,
    #[serde(deserialize_with = "nullable_string")]
    pub proto: String,
    pub listen_port: i64,
    #[serde(deserialize_with = "nullable_string")]
    pub target: String,
    pub enabled: bool,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable_string"
    )]
    pub remark: String,
    #[serde(skip_serializing_if = "Option::is_none", with = "go_time")]
    pub created_at: Option<DateTime<FixedOffset>>,
}

/// 字符串字段，与 Go yaml.v3 / encoding/json 一致：YAML 中的数字、布尔等无引号标量保留原文
/// （如 `password: 1e3` 仍是 "1e3"，不会按数字改写），null 视为空串。
pub fn nullable_string<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

/// 时间格式与 Go time.Time 一致（RFC3339，UTC 时用 Z）；Go 的零值时间按未设置处理。
pub mod go_time {
    use super::*;

    pub fn format(t: &DateTime<FixedOffset>) -> String {
        t.to_rfc3339_opts(SecondsFormat::AutoSi, true)
    }

    pub fn serialize<S: Serializer>(
        t: &Option<DateTime<FixedOffset>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => s.serialize_str(&format(t)),
            None => s.serialize_str("0001-01-01T00:00:00Z"),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<DateTime<FixedOffset>>, D::Error> {
        let s = Option::<String>::deserialize(d)?.unwrap_or_default();
        if s.is_empty() || s.starts_with("0001-01-01") {
            return Ok(None);
        }
        parse(&s)
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom(format!("无法解析时间: {s}")))
    }

    /// 除 RFC3339 外，与 Go yaml.v3 一样接受 `2006-01-02 15:04:05`、`2006-01-02T15:04:05`
    /// （无时区按 UTC）与只有日期的 `2006-01-02`。
    pub fn parse(s: &str) -> Option<DateTime<FixedOffset>> {
        if let Ok(t) = DateTime::parse_from_rfc3339(s) {
            return Some(t);
        }
        let utc = |t: NaiveDateTime| t.and_utc().fixed_offset();
        [
            "%Y-%m-%d %H:%M:%S%.f",
            "%Y-%m-%dT%H:%M:%S%.f",
            "%Y-%m-%dt%H:%M:%S%.f",
        ]
        .iter()
        .find_map(|f| NaiveDateTime::parse_from_str(s, f).ok())
        .or_else(|| {
            NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .ok()
                .map(|d| d.and_time(NaiveTime::MIN))
        })
        .map(utc)
    }
}

/// 拆分 host:port，规则同 Go net.SplitHostPort（IPv6 需加方括号）。
pub fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?;
        return (!port.contains(':')).then_some((host, port));
    }
    let (host, port) = s.rsplit_once(':')?;
    (!host.contains(':') && !host.contains('[') && !host.contains(']')).then_some((host, port))
}

/// 解析 IP，IPv4 映射的 IPv6 地址（::ffff:1.2.3.4）视为 IPv4。
fn parse_ip(host: &str) -> Option<IpAddr> {
    match host.parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => Some(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)),
        ip => Some(ip),
    }
}

/// 与 Go 版的主机名正则一致：点分的若干标签，每个标签 1-63 位字母数字或中间的连字符。
fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.split('.').all(|l| {
            let b = l.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b[0].is_ascii_alphanumeric()
                && b[b.len() - 1].is_ascii_alphanumeric()
                && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        })
}

pub fn proto_overlap(a: &str, b: &str) -> bool {
    a == b || a == PROTO_BOTH || b == PROTO_BOTH
}

impl Rule {
    /// 把 both 展开成 tcp/udp。
    pub fn protos(&self) -> Vec<&'static str> {
        match self.proto.as_str() {
            PROTO_BOTH => vec![PROTO_TCP, PROTO_UDP],
            PROTO_UDP => vec![PROTO_UDP],
            _ => vec![PROTO_TCP],
        }
    }

    /// 拆分目标地址。
    pub fn target_host_port(&self) -> Result<(String, u16), String> {
        let t = self.target.trim();
        let (host, ps) = split_host_port(t).ok_or("目标地址格式应为 host:port")?;
        let port = match ps.parse::<i64>() {
            Ok(p @ 1..=65535) => p as u16,
            _ => return Err(format!("目标端口无效: {ps}")),
        };
        if host.is_empty() {
            return Err("目标主机不能为空".into());
        }
        Ok((host.to_string(), port))
    }

    /// 校验规则本身的合法性（不含端口冲突检查），同时规范化各字段。
    pub fn validate(&mut self, backend: &str) -> Result<(), String> {
        self.name = self.name.trim().to_string();
        self.target = self.target.trim().to_string();
        self.proto = self.proto.trim().to_lowercase();
        if ![PROTO_TCP, PROTO_UDP, PROTO_BOTH].contains(&self.proto.as_str()) {
            return Err("协议必须是 tcp / udp / both".into());
        }
        if !(1..=65535).contains(&self.listen_port) {
            return Err("监听端口必须在 1-65535 之间".into());
        }
        let (host, port) = self.target_host_port()?;
        let ip = match parse_ip(&host) {
            Some(ip) => ip,
            None => {
                // 域名：用户态后端直接使用；内核后端解析为 IPv4 后应用，并定期重新解析
                if !valid_hostname(&host) {
                    return Err(format!("目标主机既不是 IP 也不是合法域名: {host}"));
                }
                return Ok(());
            }
        };
        let IpAddr::V4(v4) = ip else {
            return Err("目前仅支持 IPv4 目标地址".into());
        };
        // 统一为点分十进制，避免 ::ffff:1.2.3.4 这类 IPv4 映射地址原样进入转发参数
        self.target = format!("{v4}:{port}");
        if user_space(backend) {
            return Ok(());
        }
        if v4.is_loopback() {
            return Err(format!(
                "{backend} 后端不能转发到回环地址 {v4}，请改用 builtin 或 realm 后端"
            ));
        }
        if v4.is_unspecified() {
            return Err("目标地址不能是 0.0.0.0".into());
        }
        Ok(())
    }

    /// 两条规则的实际转发配置是否一致（用于用户态后端 diff）。
    pub fn same_forward(&self, o: &Rule) -> bool {
        self.proto == o.proto && self.listen_port == o.listen_port && self.target == o.target
    }

    pub fn default_name(port: i64) -> String {
        format!("rule-{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(target: &str) -> Rule {
        Rule {
            proto: "tcp".into(),
            listen_port: 8080,
            target: target.into(),
            ..Default::default()
        }
    }

    #[test]
    fn validate_normalizes_target() {
        for (input, want) in [
            ("[::ffff:192.0.2.1]:443", "192.0.2.1:443"), // IPv4 映射地址统一为点分十进制
            (" 10.0.0.5:80 ", "10.0.0.5:80"),
            ("example.com:80", "example.com:80"),
        ] {
            let mut r = rule(input);
            r.validate(BACKEND_NFTABLES)
                .unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(r.target, want, "{input}");
        }
        assert!(
            rule("[2001:db8::1]:80").validate(BACKEND_NFTABLES).is_err(),
            "IPv6 目标应被拒绝"
        );
    }

    #[test]
    fn validate_errors() {
        for (target, backend) in [
            ("127.0.0.1:80", BACKEND_IPTABLES),
            ("0.0.0.0:80", BACKEND_NFTABLES),
            ("1.2.3.4", BACKEND_BUILTIN),
            ("1.2.3.4:0", BACKEND_BUILTIN),
            ("1.2.3.4:70000", BACKEND_BUILTIN),
            (":80", BACKEND_BUILTIN),
            ("bad_host:80", BACKEND_BUILTIN),
            ("-a.com:80", BACKEND_BUILTIN),
            ("a..com:80", BACKEND_BUILTIN),
        ] {
            assert!(
                rule(target).validate(backend).is_err(),
                "{target} / {backend} 应校验失败"
            );
        }
        assert!(rule("127.0.0.1:80").validate(BACKEND_BUILTIN).is_ok());
        let mut r = rule("1.2.3.4:80");
        r.proto = " UDP ".into();
        assert!(r.validate(BACKEND_BUILTIN).is_ok());
        assert_eq!(r.proto, "udp");
        r.listen_port = 0;
        assert!(r.validate(BACKEND_BUILTIN).is_err());
    }

    #[test]
    fn json_matches_go() {
        let r: Rule = serde_json::from_str(
            r#"{"id":"a","name":"n","proto":"tcp","listen_port":80,"target":"1.2.3.4:80","enabled":true,"remark":"","created_at":"0001-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(r.created_at, None);
        let r: Rule =
            serde_json::from_str(r#"{"created_at":"2026-10-27T10:00:00+08:00","name":null}"#)
                .unwrap();
        assert_eq!(r.name, "");
        assert_eq!(
            go_time::format(&r.created_at.unwrap()),
            "2026-10-27T10:00:00+08:00"
        );
        // 与 Go encoding/json 一致：字符串字段不接受数字
        assert!(serde_json::from_str::<Rule>(r#"{"name":123}"#).is_err());
    }

    // 与 Go yaml.v3 一致：无引号标量按原文读入字符串字段，null 为空串
    #[test]
    fn yaml_scalars_keep_text() {
        for (raw, want) in [
            ("0x123456", "0x123456"),
            ("0123", "0123"),
            ("1e3", "1e3"),
            ("1.10", "1.10"),
            ("true", "true"),
            ("yes", "yes"),
            ("123456", "123456"),
            ("~", ""),
            ("", ""),
        ] {
            let r: Rule = serde_yaml_ng::from_str(&format!("name: {raw}\nlisten_port: 1")).unwrap();
            assert_eq!(r.name, want, "name: {raw}");
        }
    }

    // 与 Go yaml.v3 接受的时间格式一致，无时区按 UTC
    #[test]
    fn yaml_timestamps() {
        for (raw, want) in [
            ("2026-10-27T10:00:00+08:00", "2026-10-27T10:00:00+08:00"),
            ("2026-10-27T02:00:00.5Z", "2026-10-27T02:00:00.500Z"),
            ("2026-10-27 10:00:00", "2026-10-27T10:00:00Z"),
            ("2026-10-27T10:00:00", "2026-10-27T10:00:00Z"),
            ("2026-10-27", "2026-10-27T00:00:00Z"),
        ] {
            let r: Rule = serde_yaml_ng::from_str(&format!("created_at: {raw}")).unwrap();
            assert_eq!(go_time::format(&r.created_at.unwrap()), want, "{raw}");
        }
        assert!(serde_yaml_ng::from_str::<Rule>("created_at: yesterday").is_err());
    }
}
