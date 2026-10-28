use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use chrono::{Local, Timelike};
use serde::{Deserialize, Serialize};

use crate::model::{self, Rule, nullable_string};
use crate::sysinfo;

pub const DEFAULT_PATH: &str = "/etc/lport/config.yaml";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Admin {
    #[serde(deserialize_with = "nullable_string")]
    pub username: String,
    /// 手动填写明文，启动时自动转为 hash 并清空
    #[serde(deserialize_with = "nullable_string")]
    pub password: String,
    /// bcrypt
    #[serde(deserialize_with = "nullable_string")]
    pub password_hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    #[serde(deserialize_with = "nullable_string")]
    pub listen: String,
    #[serde(deserialize_with = "nullable_string")]
    pub backend: String,
    pub admin: Admin,
    #[serde(deserialize_with = "nullable_string")]
    pub session_secret: String,
    #[serde(deserialize_with = "null_as_empty")]
    pub rules: Vec<Rule>,
}

/// Go yaml 中 `rules:`（空值）等同于空列表。
fn null_as_empty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Rule>, D::Error> {
    Ok(Option::<Vec<Rule>>::deserialize(d)?.unwrap_or_default())
}

/// 记录加载时自动做的修正，便于调用方打印提示。
#[derive(Debug, Default)]
pub struct LoadResult {
    /// 非空表示首次启动生成了随机密码
    pub generated_password: String,
    /// 配置未指定 backend，已自动选择
    pub backend_auto: bool,
    /// 是否需要写回文件
    pub changed: bool,
}

/// 负责配置文件的加载、校验与写回。
pub struct Store {
    path: PathBuf,
    cfg: RwLock<Config>,
}

fn valid_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub fn new_id() -> String {
    rand::random::<[u8; 4]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn random_string(n: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    (0..n)
        .map(|_| CHARS[rand::random_range(0..CHARS.len())] as char)
        .collect()
}

/// 生成随机密码。
pub fn random_password() -> String {
    random_string(12)
}

/// 生成 bcrypt hash，与 Go 版相同的 $2a$ 前缀与默认 cost 10。
pub fn hash_password(pw: &str) -> Result<String, String> {
    bcrypt::hash_with_result(pw, 10)
        .map(|h| h.format_for_version(bcrypt::Version::TwoA))
        .map_err(|e| e.to_string())
}

/// 当前时间（截断到秒），用作规则创建时间。
pub fn now() -> chrono::DateTime<chrono::FixedOffset> {
    let t = Local::now().fixed_offset();
    t.with_nanosecond(0).unwrap_or(t)
}

pub fn panel_port(listen: &str) -> i64 {
    model::split_host_port(listen)
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(0)
}

/// 检查规则之间是否存在同协议同端口。
pub fn check_rule_conflicts(rules: &[Rule]) -> Result<(), String> {
    for (i, a) in rules.iter().enumerate() {
        for b in &rules[i + 1..] {
            if a.listen_port == b.listen_port && model::proto_overlap(&a.proto, &b.proto) {
                return Err(format!(
                    "规则 {} 与 {} 的监听端口 {} 冲突",
                    a.name, b.name, a.listen_port
                ));
            }
        }
    }
    Ok(())
}

/// 运行环境，便于测试替换。
pub struct Env {
    pub is_root: fn() -> bool,
    pub tool_installed: fn(&str) -> bool,
}

pub const REAL_ENV: Env = Env {
    is_root: sysinfo::is_root,
    tool_installed: sysinfo::tool_installed,
};

/// 为未指定后端的配置选择默认值：root 下优先 nftables，其次 iptables，
/// 且需所有已有规则都适用于该后端；否则使用内置转发。
fn auto_backend(rules: &[Rule], env: &Env) -> String {
    if !(env.is_root)() {
        return model::BACKEND_BUILTIN.into();
    }
    for b in [model::BACKEND_NFTABLES, model::BACKEND_IPTABLES] {
        if (env.tool_installed)(b) && rules.iter().all(|r| r.clone().validate(b).is_ok()) {
            return b.into();
        }
    }
    model::BACKEND_BUILTIN.into()
}

fn normalize(c: &mut Config, res: &mut LoadResult, env: &Env) -> Result<(), String> {
    if c.listen.is_empty() {
        c.listen = "0.0.0.0:8080".into();
        res.changed = true;
    }
    if model::split_host_port(&c.listen).is_none() {
        return Err(format!("listen 格式错误 {:?}，应为 ip:port", c.listen));
    }
    if c.backend.is_empty() {
        c.backend = auto_backend(&c.rules, env);
        res.backend_auto = true;
        res.changed = true;
    }
    if c.backend == model::LEGACY_BACKEND_SOCAT {
        crate::logln!("socat 后端已移除，改用内置转发（builtin）");
        c.backend = model::BACKEND_BUILTIN.into();
        res.changed = true;
    }
    if !model::valid_backend(&c.backend) {
        return Err(format!(
            "backend 必须是 builtin / realm / iptables / nftables，当前为 {:?}",
            c.backend
        ));
    }
    if c.admin.username.is_empty() {
        c.admin.username = "admin".into();
        res.changed = true;
    }
    if !c.admin.password.is_empty() {
        c.admin.password_hash = hash_password(&c.admin.password)?;
        c.admin.password.clear();
        res.changed = true;
    }
    if c.admin.password_hash.is_empty() {
        let pw = random_password();
        c.admin.password_hash = hash_password(&pw)?;
        res.generated_password = pw;
        res.changed = true;
    }
    if c.session_secret.len() < 16 {
        c.session_secret = random_string(32);
        res.changed = true;
    }
    let mut ids = HashSet::new();
    let backend = c.backend.clone();
    for (i, r) in c.rules.iter_mut().enumerate() {
        // ID 会写入 iptables 规则注释，只允许安全字符，手工编辑出的非法 ID 重新生成
        if !valid_id(&r.id) || ids.contains(&r.id) {
            r.id = new_id();
            res.changed = true;
        }
        ids.insert(r.id.clone());
        if r.created_at.is_none() {
            r.created_at = Some(now());
            res.changed = true;
        }
        if r.name.is_empty() {
            r.name = Rule::default_name(r.listen_port);
            res.changed = true;
        }
        r.validate(&backend)
            .map_err(|e| format!("第 {} 条规则 ({}): {e}", i + 1, r.name))?;
    }
    check_rule_conflicts(&c.rules)?;
    let lp = panel_port(&c.listen);
    for r in &c.rules {
        if r.listen_port == lp && model::proto_overlap(&r.proto, model::PROTO_TCP) {
            return Err(format!(
                "规则 {} 的监听端口 {lp} 与管理面板端口冲突",
                r.name
            ));
        }
    }
    Ok(())
}

impl Store {
    /// 读取配置；文件不存在时使用默认配置。会补全缺省值并校验，校验失败返回错误；有补全时写回文件。
    pub fn load(path: impl AsRef<Path>) -> Result<(Store, LoadResult), String> {
        Self::load_with(path, true, &REAL_ENV)
    }

    /// 同 load，但不写回文件，由调用方在合适时机调用 save。
    #[allow(dead_code)]
    pub fn load_no_save(path: impl AsRef<Path>) -> Result<(Store, LoadResult), String> {
        Self::load_with(path, false, &REAL_ENV)
    }

    pub fn load_with(
        path: impl AsRef<Path>,
        save: bool,
        env: &Env,
    ) -> Result<(Store, LoadResult), String> {
        let path = path.as_ref().to_path_buf();
        let mut res = LoadResult::default();
        let mut cfg = Config::default();
        match fs::read_to_string(&path) {
            Err(e) if e.kind() == ErrorKind::NotFound => res.changed = true,
            Err(e) => return Err(format!("读取配置文件 {} 失败: {e}", path.display())),
            Ok(data) if data.trim().is_empty() => {}
            Ok(data) => {
                cfg = serde_yaml_ng::from_str(&data)
                    .map_err(|e| format!("解析配置文件 {} 失败: {e}", path.display()))?;
            }
        }
        normalize(&mut cfg, &mut res, env)
            .map_err(|e| format!("配置文件 {} 校验失败: {e}", path.display()))?;
        let store = Store {
            path,
            cfg: RwLock::new(cfg),
        };
        if res.changed && save {
            store.save()?;
        }
        Ok((store, res))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 返回配置副本。
    pub fn get(&self) -> Config {
        self.cfg.read().unwrap().clone()
    }

    /// 写回当前配置。
    pub fn save(&self) -> Result<(), String> {
        write_file(&self.path, &self.cfg.read().unwrap())
    }

    /// 在锁内修改配置并写回；fn 返回错误则不保存并回滚。
    pub fn update(&self, f: impl FnOnce(&mut Config) -> Result<(), String>) -> Result<(), String> {
        let mut guard = self.cfg.write().unwrap();
        let mut c = guard.clone();
        f(&mut c)?;
        write_file(&self.path, &c).map_err(|e| format!("保存配置失败: {e}"))?;
        *guard = c;
        Ok(())
    }

    /// 用新配置整体替换并写回，失败时保持原配置。
    pub fn replace(&self, c: Config) -> Result<(), String> {
        self.update(|cur| {
            *cur = c;
            Ok(())
        })
    }
}

fn write_file(path: &Path, c: &Config) -> Result<(), String> {
    let mut buf = String::from(
        "# lport 配置文件，可手动编辑，重启服务后生效。\n# admin.password 可填写明文密码，启动时会自动转换为 password_hash。\n",
    );
    buf.push_str(&serde_yaml_ng::to_string(c).map_err(|e| e.to_string())?);
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| e.to_string())?;
    }
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        f.write_all(buf.as_bytes()).map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NON_ROOT: Env = Env {
        is_root: || false,
        tool_installed: |_| false,
    };
    const ROOT_NFT: Env = Env {
        is_root: || true,
        tool_installed: |t| t == "nftables",
    };

    /// 测试用临时目录，离开作用域时删除。
    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tmpdir() -> TempDir {
        let d = std::env::temp_dir().join(format!("lport-test-{}", new_id()));
        fs::create_dir_all(&d).unwrap();
        TempDir(d)
    }

    /// 临时目录中的配置文件路径，离开作用域时连同目录删除。
    struct TempCfg {
        path: PathBuf,
        _dir: TempDir,
    }

    impl std::ops::Deref for TempCfg {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.path
        }
    }

    impl AsRef<Path> for TempCfg {
        fn as_ref(&self) -> &Path {
            &self.path
        }
    }

    fn write_cfg(content: &str) -> TempCfg {
        let dir = tmpdir();
        let path = dir.0.join("config.yaml");
        fs::write(&path, content).unwrap();
        TempCfg { path, _dir: dir }
    }

    fn load(p: &Path) -> Result<(Store, LoadResult), String> {
        Store::load_with(p, true, &NON_ROOT)
    }

    #[test]
    fn auto_backend_choice() {
        let lo = Rule {
            proto: "tcp".into(),
            listen_port: 1,
            target: "127.0.0.1:80".into(),
            ..Default::default()
        };
        assert_eq!(auto_backend(&[], &NON_ROOT), "builtin");
        assert_eq!(auto_backend(&[], &ROOT_NFT), "nftables");
        assert_eq!(
            auto_backend(&[lo], &ROOT_NFT),
            "builtin",
            "回环目标不适用内核后端"
        );
    }

    #[test]
    fn load_defaults() {
        let dir = tmpdir();
        let p = dir.0.join("sub").join("config.yaml");
        let (s, res) = load(&p).unwrap();
        assert!(!res.generated_password.is_empty());
        let c = s.get();
        assert_eq!(
            (
                c.listen.as_str(),
                c.backend.as_str(),
                c.admin.username.as_str()
            ),
            ("0.0.0.0:8080", "builtin", "admin")
        );
        assert!(bcrypt::verify(&res.generated_password, &c.admin.password_hash).unwrap());
        assert!(c.admin.password_hash.starts_with("$2a$10$"));
        assert!(p.exists());
        // 再次加载不应重新生成密码
        let (_, res2) = load(&p).unwrap();
        assert!(
            res2.generated_password.is_empty() && !res2.changed,
            "{res2:?}"
        );
    }

    #[test]
    fn plain_password_and_id_fill() {
        let p = write_cfg(
            "
backend: builtin
admin:
  username: root
  password: secret123
rules:
  - proto: tcp
    listen_port: 18080
    target: 127.0.0.1:80
    enabled: true
",
        );
        let (s, res) = load(&p).unwrap();
        assert!(res.generated_password.is_empty());
        let c = s.get();
        assert!(
            c.admin.password.is_empty()
                && bcrypt::verify("secret123", &c.admin.password_hash).unwrap()
        );
        assert!(!c.rules[0].id.is_empty() && c.rules[0].name == "rule-18080");
        assert!(!fs::read_to_string(&p).unwrap().contains("secret123"));
    }

    #[test]
    fn invalid_configs() {
        for (name, content) in [
            ("backend", "backend: foo\n"),
            (
                "proto",
                "rules:\n  - {proto: icmp, listen_port: 1000, target: 1.2.3.4:80}",
            ),
            (
                "conflict",
                "rules:\n  - {proto: tcp, listen_port: 1000, target: 1.2.3.4:80}\n  - {proto: both, listen_port: 1000, target: 1.2.3.4:81}",
            ),
            (
                "loopback-kernel",
                "backend: iptables\nrules:\n  - {proto: tcp, listen_port: 1000, target: 127.0.0.1:80}",
            ),
            (
                "panel-port",
                "listen: 0.0.0.0:9000\nrules:\n  - {proto: tcp, listen_port: 9000, target: 1.2.3.4:80}",
            ),
        ] {
            assert!(load(&write_cfg(content)).is_err(), "{name}: expected error");
        }
        let ok = "rules:\n  - {proto: tcp, listen_port: 1000, target: 1.2.3.4:80}\n  - {proto: udp, listen_port: 1000, target: 1.2.3.4:81}";
        load(&write_cfg(ok)).expect("tcp+udp same port should be allowed");
    }

    // ID 会写入 iptables 规则注释，含引号、换行等字符的 ID 须在加载时重新生成
    #[test]
    fn invalid_rule_id_regenerated() {
        let p = write_cfg(
            r#"backend: builtin
rules:
  - {id: "x\" -j ACCEPT\n-A", proto: tcp, listen_port: 18080, target: "10.0.0.5:80"}
  - {id: ok_id-1, proto: tcp, listen_port: 18081, target: "10.0.0.5:80"}
"#,
        );
        let rules = load(&p).unwrap().0.get().rules;
        assert!(
            valid_id(&rules[0].id),
            "非法 ID 未重新生成: {:?}",
            rules[0].id
        );
        assert_eq!(rules[1].id, "ok_id-1");
    }

    // 形如数字的明文密码按原文哈希，不能被改写成数字的十进制形式（如 1e3 → 1000）
    #[test]
    fn numeric_looking_password_kept() {
        for pw in ["1e3", "0x123456", "1.10"] {
            let p = write_cfg(&format!("admin:\n  password: {pw}\n"));
            let c = load(&p).unwrap().0.get();
            assert!(
                bcrypt::verify(pw, &c.admin.password_hash).unwrap(),
                "password: {pw}"
            );
        }
    }

    // 已移除的 socat 后端在加载时迁移为内置转发并写回配置
    #[test]
    fn legacy_socat_migrated() {
        let p = write_cfg("backend: socat\nadmin: {password: secret123}\n");
        let (s, res) = load(&p).unwrap();
        assert!(s.get().backend == "builtin" && res.changed);
        assert!(fs::read_to_string(&p).unwrap().contains("backend: builtin"));
    }

    // Go 版写出的配置（yaml.v3，2 空格缩进、time.Time）可被读取，写回后字段保持不变
    #[test]
    fn reads_go_config() {
        let p = write_cfg(
            r#"# lport 配置文件，可手动编辑，重启服务后生效。
listen: 0.0.0.0:8080
backend: builtin
admin:
  username: admin
  password: ""
  password_hash: $2a$10$Bj8yT4qO6xQnD6G0n5bS7eS0fVvB3yqY1jJ0p8b4m7e3kQ2Q2a9mK
session_secret: abcdefghijklmnopqrstuvwxyz123456
rules:
  - id: 3f2a9c01
    name: web
    proto: tcp
    listen_port: 18080
    target: example.com:80
    enabled: true
    remark: 备注
    created_at: 2026-10-27T10:00:00+08:00
  - id: 3f2a9c02
    name: dns
    proto: udp
    listen_port: 5353
    target: 1.1.1.1:53
    enabled: false
    created_at: 2026-10-27T02:00:00Z
"#,
        );
        let (s, res) = load(&p).unwrap();
        assert!(!res.changed, "{res:?}");
        let c = s.get();
        assert_eq!(c.rules.len(), 2);
        assert_eq!(c.rules[0].remark, "备注");
        assert_eq!(
            model::go_time::format(&c.rules[0].created_at.unwrap()),
            "2026-10-27T10:00:00+08:00"
        );
        assert_eq!(
            model::go_time::format(&c.rules[1].created_at.unwrap()),
            "2026-10-27T02:00:00Z"
        );
        s.save().unwrap();
        let (s2, res2) = load(&p).unwrap();
        assert!(!res2.changed);
        assert_eq!(s2.get().rules, c.rules);
    }
}
