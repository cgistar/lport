//! 管理面板登录与会话，对应 Go 版 internal/auth。token 格式与签名密钥与 Go 版一致，
//! 两个版本互相替换后已登录的会话仍然有效。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::config::{self, Store};

pub const COOKIE_NAME: &str = "lport_session";
pub const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);

pub const ERR_TOO_MANY: &str = "登录失败次数过多，请一分钟后再试";
const ERR_BAD_CREDENTIAL: &str = "用户名或密码错误";

pub struct Auth {
    store: Arc<Store>,
    failures: Mutex<HashMap<String, Vec<Instant>>>,
}

/// 常量时间比较，避免通过响应时间猜测用户名或签名。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

impl Auth {
    pub fn new(store: Arc<Store>) -> Self {
        Auth {
            store,
            failures: Mutex::default(),
        }
    }

    /// 签名密钥绑定密码 hash，修改密码后旧会话自动失效。
    fn sign(&self, payload: &str) -> String {
        let c = self.store.get();
        let key = format!("{}|{}", c.session_secret, c.admin.password_hash);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_bytes())
            .expect("HMAC 接受任意长度的密钥");
        mac.update(payload.as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// IP 是否因失败过多被限制（每分钟 5 次）。
    fn limited(&self, ip: &str) -> bool {
        let mut f = self.failures.lock().unwrap();
        let cutoff = Instant::now().checked_sub(Duration::from_secs(60));
        let kept: Vec<Instant> = f
            .get(ip)
            .into_iter()
            .flatten()
            .copied()
            .filter(|t| cutoff.is_none_or(|c| *t > c))
            .collect();
        let n = kept.len();
        if kept.is_empty() {
            f.remove(ip);
        } else {
            f.insert(ip.to_string(), kept);
        }
        n >= 5
    }

    fn fail(&self, ip: &str) {
        self.failures
            .lock()
            .unwrap()
            .entry(ip.to_string())
            .or_default()
            .push(Instant::now());
    }

    /// 校验用户名密码，成功返回会话 token；Err 为 (是否因失败过多被限制, 错误消息)。
    pub fn login(&self, ip: &str, user: &str, pass: &str) -> Result<String, (bool, &'static str)> {
        if self.limited(ip) {
            return Err((true, ERR_TOO_MANY));
        }
        let c = self.store.get();
        let ok_user = ct_eq(user.as_bytes(), c.admin.username.as_bytes());
        let ok_pass = bcrypt::verify(pass, &c.admin.password_hash).unwrap_or(false);
        if !ok_user || !ok_pass {
            self.fail(ip);
            return Err((false, ERR_BAD_CREDENTIAL));
        }
        let exp = now_unix() + SESSION_TTL.as_secs() as i64;
        let payload = URL_SAFE_NO_PAD.encode(format!("{user}|{exp}"));
        let sig = self.sign(&payload);
        Ok(format!("{payload}.{sig}"))
    }

    /// 校验 token，返回用户名。
    pub fn verify(&self, token: &str) -> Option<String> {
        let (payload, sig) = token.split_once('.')?;
        if !ct_eq(sig.as_bytes(), self.sign(payload).as_bytes()) {
            return None;
        }
        let raw = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        let (user, exp) = raw.split_once('|')?;
        if now_unix() > exp.parse::<i64>().ok()? || user != self.store.get().admin.username {
            return None;
        }
        Some(user.to_string())
    }

    /// 校验旧密码后设置新密码。
    pub fn change_password(&self, old: &str, new: &str) -> Result<(), String> {
        if new.len() < 6 {
            return Err("新密码至少 6 位".into());
        }
        if !bcrypt::verify(old, &self.store.get().admin.password_hash).unwrap_or(false) {
            return Err("原密码错误".into());
        }
        let h = config::hash_password(new)?;
        self.store.update(|c| {
            c.admin.password_hash = h;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> (Auth, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("lport-test-{}", config::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.yaml");
        std::fs::write(&p, "backend: builtin\nadmin: {username: admin, password: secret123}\nsession_secret: 0123456789abcdef0123456789abcdef\n").unwrap();
        let (store, _) = Store::load(&p).unwrap();
        (Auth::new(Arc::new(store)), dir)
    }

    #[test]
    fn login_verify_and_rate_limit() {
        let (a, dir) = auth();
        let t = a.login("1.1.1.1", "admin", "secret123").unwrap();
        assert_eq!(a.verify(&t).as_deref(), Some("admin"));
        assert_eq!(a.verify(&format!("{t}x")), None, "签名被篡改");
        assert_eq!(a.verify("garbage"), None);
        for _ in 0..5 {
            assert_eq!(
                a.login("2.2.2.2", "admin", "bad"),
                Err((false, ERR_BAD_CREDENTIAL))
            );
        }
        assert_eq!(
            a.login("2.2.2.2", "admin", "secret123"),
            Err((true, ERR_TOO_MANY)),
            "失败 5 次后限制"
        );
        assert!(
            a.login("3.3.3.3", "admin", "secret123").is_ok(),
            "按 IP 分别计数"
        );

        // 修改密码后旧会话失效
        assert_eq!(
            a.change_password("bad", "newpass1"),
            Err("原密码错误".into())
        );
        assert_eq!(
            a.change_password("secret123", "short"),
            Err("新密码至少 6 位".into())
        );
        a.change_password("secret123", "newpass1").unwrap();
        assert_eq!(a.verify(&t), None);
        assert!(a.login("1.1.1.1", "admin", "newpass1").is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    // 与 Go 版的 token 格式互通：payload 为 base64url(user|exp)，签名为 HMAC-SHA256 的十六进制
    #[test]
    fn token_format_matches_go() {
        let (a, dir) = auth();
        let t = a.login("1.1.1.1", "admin", "secret123").unwrap();
        let (payload, sig) = t.split_once('.').unwrap();
        let raw = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert!(
            raw.starts_with("admin|") && raw[6..].parse::<i64>().is_ok(),
            "{raw}"
        );
        assert_eq!(sig.len(), 64);
        // 已过期的 token
        let old = URL_SAFE_NO_PAD.encode("admin|1000");
        assert_eq!(a.verify(&format!("{old}.{}", a.sign(&old))), None);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
