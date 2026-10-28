//! Web 管理面板的 HTTP API 与前端静态文件，对应 Go 版 internal/api。路由、JSON 格式、
//! 会话 Cookie 与错误文案均与 Go 版一致，web/ 下的前端无需修改即可同时用于两个版本。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post, put};
use http_body_util::{BodyExt, Limited};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::auth::{self, Auth};
use crate::config::Store;
use crate::i18n;
use crate::manager::{Manager, rule_json};
use crate::model::{self, Rule};
use crate::{portcheck, sysinfo};

mod assets {
    include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));
}

#[derive(Clone)]
pub struct AppState {
    store: Arc<Store>,
    mgr: Arc<Manager>,
    auth: Arc<Auth>,
}

pub fn router(store: Arc<Store>, mgr: Arc<Manager>) -> Router {
    let auth = Arc::new(Auth::new(store.clone()));
    let st = AppState { store, mgr, auth };
    let api = Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(me))
        .route("/system", get(system))
        .route("/system/install", post(install))
        .route("/settings", get(get_settings).put(put_settings))
        .route("/settings/password", put(change_password))
        .route("/rules", get(list_rules).post(create_rule))
        .route("/rules/{id}", put(update_rule).delete(delete_rule))
        .route("/rules/{id}/toggle", post(toggle_rule))
        .route("/rules/{id}/probe", post(probe_rule))
        .route("/ports/check", get(check_port))
        .route("/ports/listening", get(listening))
        .fallback(|| async { (StatusCode::NOT_FOUND, "404 page not found\n") })
        .layer(middleware::from_fn_with_state(st.clone(), require_auth));
    Router::new()
        .nest("/api", api)
        .fallback(spa)
        .layer(middleware::from_fn(localize))
        .with_state(st)
}

// ---------------------------------------------------------------- 工具函数

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

fn bad(msg: impl Into<String>) -> Response {
    err(StatusCode::BAD_REQUEST, msg)
}

/// 读取 JSON 请求体，上限 1 MiB；任何解析失败都返回同一条错误。
async fn read_json<T: DeserializeOwned>(body: Body) -> Result<T, &'static str> {
    let bytes = Limited::new(body, 1 << 20)
        .collect()
        .await
        .map_err(|_| "请求格式错误")?
        .to_bytes();
    serde_json::from_slice(&bytes).map_err(|_| "请求格式错误")
}

/// 请求是否来自本机反向代理（如同机部署的 nginx）。只信任回环地址发来的
/// X-Forwarded-* 头，其它来源可以任意伪造这些头。
fn from_trusted_proxy(peer: &SocketAddr) -> bool {
    match peer.ip() {
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        ip => ip.is_loopback(),
    }
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// 客户端 IP，用于登录失败限制。经本机反向代理时取 X-Forwarded-For 的最后一项
/// （代理追加的、实际连接它的地址，前面的项可由客户端伪造），其次 X-Real-IP。
fn client_ip(h: &HeaderMap, peer: &SocketAddr) -> String {
    let host = peer.ip().to_string();
    if !from_trusted_proxy(peer) {
        return host;
    }
    if let Some(last) = h
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
    {
        let ip = last.rsplit(',').next().unwrap_or("").trim();
        if ip.parse::<IpAddr>().is_ok() {
            return ip.to_string();
        }
    }
    match header_str(h, "x-real-ip").map(str::trim) {
        Some(ip) if ip.parse::<IpAddr>().is_ok() => ip.to_string(),
        _ => host,
    }
}

/// 浏览器到面板的连接是否为 HTTPS（由本机反向代理终止 TLS）；本服务自身只提供 HTTP。
fn is_https(h: &HeaderMap, peer: &SocketAddr) -> bool {
    from_trusted_proxy(peer)
        && header_str(h, "x-forwarded-proto").is_some_and(|p| p.eq_ignore_ascii_case("https"))
}

fn session_cookie(h: &HeaderMap) -> Option<String> {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == auth::COOKIE_NAME)
        .map(|(_, v)| v.to_string())
}

// ---------------------------------------------------------------- 中间件

async fn require_auth(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path == "/login" || path == "/logout" {
        return next.run(req).await;
    }
    let Some(token) = session_cookie(req.headers()) else {
        return err(StatusCode::UNAUTHORIZED, "未登录");
    };
    if st.auth.verify(&token).is_none() {
        return err(StatusCode::UNAUTHORIZED, "登录已过期");
    }
    // 变更请求要求 JSON，配合 SameSite=Strict 防御 CSRF
    let has_body = header_str(req.headers(), "content-length")
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > 0);
    let is_json = header_str(req.headers(), "content-type")
        .is_some_and(|v| v.starts_with("application/json"));
    if req.method() != Method::GET && has_body && !is_json {
        return err(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type 必须为 application/json",
        );
    }
    next.run(req).await
}

/// 响应 JSON 中需要翻译的字段：错误、端口冲突 / 连通性检测 / 规则状态的消息、规则应用错误。
const MESSAGE_KEYS: [&str; 3] = ["error", "message", "sync_error"];

fn translate_json(v: &mut Value, lang: &str) {
    match v {
        Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                match val {
                    Value::String(s) if MESSAGE_KEYS.contains(&k.as_str()) => {
                        *s = i18n::translate(s, lang)
                    }
                    _ => translate_json(val, lang),
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| translate_json(x, lang)),
        _ => {}
    }
}

/// 按请求语言翻译 /api/ 响应中的消息字段；中文请求直接透传。
async fn localize(req: Request, next: Next) -> Response {
    let lang = i18n::from_headers(
        header_str(req.headers(), "x-lport-lang"),
        header_str(req.headers(), "accept-language"),
    );
    if lang == i18n::ZH || !req.uri().path().starts_with("/api/") {
        return next.run(req).await;
    }
    let resp = next.run(req).await;
    let is_json = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !is_json {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let Ok(bytes) = body.collect().await.map(|b| b.to_bytes()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let out = match serde_json::from_slice::<Value>(&bytes) {
        Ok(mut v) => {
            translate_json(&mut v, lang);
            Bytes::from(serde_json::to_vec(&v).unwrap_or_else(|_| bytes.to_vec()))
        }
        Err(_) => bytes,
    };
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(out))
}

// ---------------------------------------------------------------- 处理函数

#[derive(Deserialize)]
struct LoginReq {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

async fn login(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let req: LoginReq = match read_json(body).await {
        Ok(r) => r,
        Err(e) => return bad(e),
    };
    let ip = client_ip(&headers, &peer);
    let auth = st.auth.clone();
    let (user, pass) = (req.username.clone(), req.password);
    // bcrypt 校验约需几十毫秒 CPU，放到阻塞线程池
    let res = tokio::task::spawn_blocking(move || auth.login(&ip, &user, &pass))
        .await
        .unwrap();
    let token = match res {
        Ok(t) => t,
        Err((too_many, msg)) => {
            let code = if too_many {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::UNAUTHORIZED
            };
            return err(code, msg);
        }
    };
    let secure = if is_https(&headers, &peer) {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{}={token}; Path=/; Max-Age={}; HttpOnly{secure}; SameSite=Strict",
        auth::COOKIE_NAME,
        auth::SESSION_TTL.as_secs()
    );
    let mut resp = Json(json!({ "username": req.username })).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

async fn logout(ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap) -> Response {
    let secure = if is_https(&headers, &peer) {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{}=; Path=/; Max-Age=0; HttpOnly{secure}",
        auth::COOKIE_NAME
    );
    let mut resp = Json(json!({ "ok": true })).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

async fn me(State(st): State<AppState>) -> Response {
    Json(json!({ "username": st.store.get().admin.username })).into_response()
}

async fn system(State(st): State<AppState>) -> Response {
    // 检测会执行各工具的 --version，放到阻塞线程池
    let info = tokio::task::spawn_blocking(sysinfo::detect).await.unwrap();
    Json(json!({
        "info": info,
        "backend": st.mgr.backend_name().await,
        "backend_mode": st.mgr.backend_mode().await,
        "sync_error": st.mgr.sync_error().await,
        "config_path": st.store.path().display().to_string(),
        "listen": st.store.get().listen,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct InstallReq {
    #[serde(default)]
    tools: Vec<String>,
}

async fn install(State(st): State<AppState>, body: Body) -> Response {
    let tools = match read_json::<InstallReq>(body).await {
        Ok(r) if !r.tools.is_empty() => r.tools,
        _ => return bad("请指定要安装的工具"),
    };
    let (cmd, out, res) = tokio::task::spawn_blocking(move || {
        let names: Vec<&str> = tools.iter().map(String::as_str).collect();
        sysinfo::install(&names)
    })
    .await
    .unwrap();
    let mut resp = json!({ "command": cmd, "output": out, "ok": res.is_ok() });
    match res {
        Err(e) => resp["error"] = json!(e),
        // 依赖装好后自动重新应用规则
        Ok(()) if !st.mgr.sync_error().await.is_empty() => {
            let _ = st.mgr.reapply().await;
        }
        Ok(()) => {}
    }
    Json(resp).into_response()
}

async fn settings_json(st: &AppState) -> Value {
    let c = st.store.get();
    json!({
        "backend": st.mgr.backend_name().await,
        "backends": model::BACKENDS,
        "listen": c.listen,
        "username": c.admin.username,
    })
}

async fn get_settings(State(st): State<AppState>) -> Response {
    Json(settings_json(&st).await).into_response()
}

#[derive(Deserialize)]
struct BackendReq {
    #[serde(default)]
    backend: String,
}

async fn put_settings(State(st): State<AppState>, body: Body) -> Response {
    let req: BackendReq = match read_json(body).await {
        Ok(r) => r,
        Err(e) => return bad(e),
    };
    if let Err(e) = st.mgr.set_backend(&req.backend).await {
        return bad(e);
    }
    Json(settings_json(&st).await).into_response()
}

#[derive(Deserialize)]
struct PasswordReq {
    #[serde(default)]
    old_password: String,
    #[serde(default)]
    new_password: String,
}

async fn change_password(State(st): State<AppState>, body: Body) -> Response {
    let req: PasswordReq = match read_json(body).await {
        Ok(r) => r,
        Err(e) => return bad(e),
    };
    let auth = st.auth.clone();
    match tokio::task::spawn_blocking(move || {
        auth.change_password(&req.old_password, &req.new_password)
    })
    .await
    .unwrap()
    {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => bad(e),
    }
}

async fn list_rules(State(st): State<AppState>) -> Response {
    Json(st.mgr.rules().await).into_response()
}

async fn create_rule(State(st): State<AppState>, body: Body) -> Response {
    let rule: Rule = match read_json(body).await {
        Ok(r) => r,
        Err(e) => return bad(e),
    };
    match st.mgr.create(rule).await {
        Ok(r) => Json(rule_json(&r)).into_response(),
        Err(e) => bad(e),
    }
}

async fn update_rule(State(st): State<AppState>, Path(id): Path<String>, body: Body) -> Response {
    let rule: Rule = match read_json(body).await {
        Ok(r) => r,
        Err(e) => return bad(e),
    };
    match st.mgr.update(&id, rule).await {
        Ok(r) => Json(rule_json(&r)).into_response(),
        Err(e) => bad(e),
    }
}

async fn delete_rule(State(st): State<AppState>, Path(id): Path<String>) -> Response {
    match st.mgr.delete(&id).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => bad(e),
    }
}

#[derive(Deserialize)]
struct ToggleReq {
    #[serde(default)]
    enabled: bool,
}

async fn toggle_rule(State(st): State<AppState>, Path(id): Path<String>, body: Body) -> Response {
    let req: ToggleReq = match read_json(body).await {
        Ok(r) => r,
        Err(e) => return bad(e),
    };
    match st.mgr.toggle(&id, req.enabled).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => bad(e),
    }
}

async fn probe_rule(State(st): State<AppState>, Path(id): Path<String>) -> Response {
    match st.mgr.probe(&id).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => bad(e),
    }
}

#[derive(Deserialize)]
struct PortQuery {
    #[serde(default)]
    port: String,
    #[serde(default)]
    proto: String,
    #[serde(default)]
    exclude: String,
}

async fn check_port(State(st): State<AppState>, Query(q): Query<PortQuery>) -> Response {
    let port = match q.port.parse::<i64>() {
        Ok(p @ 1..=65535) => p,
        _ => return bad("端口必须在 1-65535 之间"),
    };
    if ![model::PROTO_TCP, model::PROTO_UDP, model::PROTO_BOTH].contains(&q.proto.as_str()) {
        return bad("协议必须是 tcp / udp / both");
    }
    let cs = st.mgr.check_port(&q.proto, port, &q.exclude, true).await;
    Json(json!({ "available": cs.is_empty(), "conflicts": cs })).into_response()
}

async fn listening() -> Response {
    // 扫描 /proc/*/fd 建立 socket → 进程映射，放到阻塞线程池
    Json(
        tokio::task::spawn_blocking(|| portcheck::listeners(true))
            .await
            .unwrap(),
    )
    .into_response()
}

// ---------------------------------------------------------------- 前端静态文件

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn asset(path: &str) -> Option<&'static [u8]> {
    assets::ASSETS
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, b)| *b)
}

/// 提供嵌入的前端文件，未知路径回落到 index.html。
async fn spa(uri: Uri) -> Response {
    // 规范化路径（等同 path.Clean）：去掉空段与 .，.. 回退一级
    let mut segs: Vec<&str> = Vec::new();
    for s in uri.path().split('/') {
        match s {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let p = segs.join("/");
    let (name, body) = match asset(&p) {
        Some(b) if !p.is_empty() => (p.as_str(), b),
        _ => ("index.html", asset("index.html").unwrap_or_default()),
    };
    let cache = if p.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    (
        [
            (header::CONTENT_TYPE, content_type(name)),
            (header::CACHE_CONTROL, cache),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    fn peer(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn headers(kv: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in kv {
            h.append(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    // 与 Go 版 TestClientIP 的用例相同
    #[test]
    fn client_ip_cases() {
        for (name, remote, h, want) in [
            ("直连", "203.0.113.5:4000", vec![], "203.0.113.5"),
            (
                "直连伪造 XFF 无效",
                "203.0.113.5:4000",
                vec![("X-Forwarded-For", "1.2.3.4")],
                "203.0.113.5",
            ),
            (
                "本机代理取 XFF 最后一项",
                "127.0.0.1:5000",
                vec![("X-Forwarded-For", "6.6.6.6, 198.51.100.7")],
                "198.51.100.7",
            ),
            (
                "本机代理 IPv6 回环",
                "[::1]:5000",
                vec![("X-Forwarded-For", "198.51.100.7")],
                "198.51.100.7",
            ),
            (
                "本机代理 X-Real-IP",
                "127.0.0.1:5000",
                vec![("X-Real-IP", "198.51.100.8")],
                "198.51.100.8",
            ),
            ("本机代理无头", "127.0.0.1:5000", vec![], "127.0.0.1"),
            (
                "本机代理非法值",
                "127.0.0.1:5000",
                vec![("X-Forwarded-For", "garbage")],
                "127.0.0.1",
            ),
        ] {
            assert_eq!(client_ip(&headers(&h), &peer(remote)), want, "{name}");
        }
    }

    #[test]
    fn https_detection() {
        let proto = headers(&[("X-Forwarded-Proto", "https")]);
        assert!(
            is_https(&proto, &peer("127.0.0.1:5000")),
            "本机代理声明 https 时应视为 HTTPS"
        );
        assert!(
            !is_https(&proto, &peer("203.0.113.5:4000")),
            "非本机来源的 X-Forwarded-Proto 不可信"
        );
        assert!(!is_https(&HeaderMap::new(), &peer("127.0.0.1:5000")));
    }

    struct Env {
        app: Router,
        dir: std::path::PathBuf,
        mgr: Arc<Manager>,
    }

    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    async fn env() -> Env {
        let dir = std::env::temp_dir().join(format!("lport-test-{}", crate::config::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.yaml");
        std::fs::write(&p, "listen: 127.0.0.1:18999\nbackend: builtin\nadmin: {username: admin, password: secret123}\n").unwrap();
        let (store, _) = Store::load(&p).unwrap();
        let store = Arc::new(store);
        let mgr = Arc::new(Manager::new(store.clone()));
        mgr.start().await;
        Env {
            app: router(store, mgr.clone()),
            dir,
            mgr,
        }
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> (StatusCode, HeaderMap, Value) {
        let mut b = HttpRequest::builder().method(method).uri(uri);
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        let body = match body {
            Some(v) => {
                b = b.header("content-type", "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        let mut req = b.body(body).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(peer("203.0.113.9:1234")));
        let resp = app.clone().oneshot(req).await.unwrap();
        let (st, h) = (resp.status(), resp.headers().clone());
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (st, h, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn login(app: &Router) -> String {
        let (st, h, v) = call(
            app,
            "POST",
            "/api/login",
            Some(json!({"username": "admin", "password": "secret123"})),
            &[],
        )
        .await;
        assert_eq!(
            (st, v["username"].as_str()),
            (StatusCode::OK, Some("admin"))
        );
        let c = h[header::SET_COOKIE].to_str().unwrap();
        assert!(
            c.contains("HttpOnly") && c.contains("SameSite=Strict") && !c.contains("Secure"),
            "{c}"
        );
        c.split(';').next().unwrap().to_string()
    }

    #[tokio::test]
    async fn auth_flow() {
        let e = env().await;
        let (st, _, v) = call(&e.app, "GET", "/api/rules", None, &[]).await;
        assert_eq!(
            (st, v["error"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("未登录"))
        );
        let (st, _, v) = call(
            &e.app,
            "GET",
            "/api/rules",
            None,
            &[("cookie", "lport_session=bogus")],
        )
        .await;
        assert_eq!(
            (st, v["error"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("登录已过期"))
        );
        let (st, _, v) = call(
            &e.app,
            "POST",
            "/api/login",
            Some(json!({"username": "admin", "password": "x"})),
            &[],
        )
        .await;
        assert_eq!(
            (st, v["error"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("用户名或密码错误"))
        );
        let cookie = login(&e.app).await;
        let (st, _, v) = call(&e.app, "GET", "/api/me", None, &[("cookie", &cookie)]).await;
        assert_eq!(
            (st, v["username"].as_str()),
            (StatusCode::OK, Some("admin"))
        );
        // 变更请求必须是 JSON
        let (st, _, _) = call(
            &e.app,
            "POST",
            "/api/rules",
            None,
            &[
                ("cookie", &cookie),
                ("content-type", "text/plain"),
                ("content-length", "2"),
            ],
        )
        .await;
        assert_eq!(st, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let (st, _, _) = call(&e.app, "GET", "/api/nope", None, &[("cookie", &cookie)]).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        e.mgr.stop().await;
    }

    #[tokio::test]
    async fn rules_crud_and_localize() {
        let e = env().await;
        let ck = login(&e.app).await;
        let c = [("cookie", ck.as_str())];
        let rule =
            json!({"proto": "tcp", "listen_port": 18998, "target": "127.0.0.1:9", "enabled": true});
        let (st, _, r) = call(&e.app, "POST", "/api/rules", Some(rule), &c).await;
        assert_eq!(st, StatusCode::OK, "{r}");
        let id = r["id"].as_str().unwrap().to_string();
        assert_eq!(
            (r["name"].as_str(), r["remark"].as_str()),
            (Some("rule-18998"), Some(""))
        );

        let (_, _, list) = call(&e.app, "GET", "/api/rules", None, &c).await;
        assert_eq!(list[0]["status"]["state"], "running");

        // 冲突检查：中文与英文
        let (_, _, v) = call(
            &e.app,
            "GET",
            "/api/ports/check?proto=both&port=18998",
            None,
            &c,
        )
        .await;
        assert_eq!(v["available"], false);
        assert_eq!(v["conflicts"][0]["type"], "rule");
        assert_eq!(
            v["conflicts"][0]["message"],
            "与规则「rule-18998」(tcp/18998) 冲突"
        );
        let en = [("cookie", ck.as_str()), ("x-lport-lang", "en")];
        let (_, _, v) = call(
            &e.app,
            "GET",
            "/api/ports/check?proto=both&port=18998",
            None,
            &en,
        )
        .await;
        assert_eq!(
            v["conflicts"][0]["message"],
            r#"Conflicts with rule "rule-18998" (tcp/18998)"#
        );
        let (_, _, v) = call(
            &e.app,
            "GET",
            &format!("/api/ports/check?proto=tcp&port=18998&exclude={id}"),
            None,
            &c,
        )
        .await;
        assert_eq!(
            v,
            json!({"available": true, "conflicts": []}),
            "排除自身后无冲突，conflicts 为 [] 而不是 null"
        );
        let (st, _, v) = call(
            &e.app,
            "GET",
            "/api/ports/check?proto=tcp&port=0",
            None,
            &en,
        )
        .await;
        assert_eq!(
            (st, v["error"].as_str()),
            (
                StatusCode::BAD_REQUEST,
                Some("Port must be between 1 and 65535")
            )
        );

        let (st, _, _) = call(
            &e.app,
            "POST",
            &format!("/api/rules/{id}/toggle"),
            Some(json!({"enabled": false})),
            &c,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let (_, _, list) = call(&e.app, "GET", "/api/rules", None, &c).await;
        assert_eq!(
            (
                list[0]["enabled"].as_bool(),
                list[0]["status"]["state"].as_str()
            ),
            (Some(false), Some("stopped"))
        );

        let (_, _, p) = call(&e.app, "POST", &format!("/api/rules/{id}/probe"), None, &c).await;
        assert_eq!(p["local"][0]["state"], "skipped");

        let (st, _, v) = call(
            &e.app,
            "PUT",
            &format!("/api/rules/{id}"),
            Some(json!({"proto": "icmp", "listen_port": 1, "target": "1.1.1.1:1"})),
            &en,
        )
        .await;
        assert_eq!(
            (st, v["error"].as_str()),
            (
                StatusCode::BAD_REQUEST,
                Some("Protocol must be tcp / udp / both")
            )
        );
        let (st, _, _) = call(&e.app, "DELETE", &format!("/api/rules/{id}"), None, &c).await;
        assert_eq!(st, StatusCode::OK);
        let (st, _, v) = call(&e.app, "DELETE", &format!("/api/rules/{id}"), None, &c).await;
        assert_eq!(
            (st, v["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("规则不存在"))
        );

        let (st, _, s) = call(&e.app, "GET", "/api/settings", None, &c).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(
            s["backends"],
            json!(["builtin", "realm", "iptables", "nftables"])
        );
        let (st, _, v) = call(
            &e.app,
            "PUT",
            "/api/settings",
            Some(json!({"backend": "bogus"})),
            &c,
        )
        .await;
        assert_eq!(
            (st, v["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("未知后端: bogus"))
        );
        e.mgr.stop().await;
    }

    #[tokio::test]
    async fn spa_fallback() {
        let e = env().await;
        let get = |uri: &'static str| {
            let app = e.app.clone();
            async move {
                let resp = app
                    .oneshot(HttpRequest::get(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let h = resp.headers().clone();
                (resp.status(), h)
            }
        };
        let (st, h) = get("/").await;
        assert_eq!(
            (st, &h[header::CONTENT_TYPE]),
            (
                StatusCode::OK,
                &HeaderValue::from_static("text/html; charset=utf-8")
            )
        );
        assert_eq!(h[header::CACHE_CONTROL], "no-cache");
        let (st, h) = get("/rules/some/client/route").await;
        assert_eq!(
            (st, &h[header::CONTENT_TYPE]),
            (
                StatusCode::OK,
                &HeaderValue::from_static("text/html; charset=utf-8")
            )
        );
        if let Some((name, _)) = assets::ASSETS
            .iter()
            .find(|(p, _)| p.starts_with("assets/"))
        {
            let uri: &'static str = Box::leak(format!("/{name}").into_boxed_str());
            let (_, h) = get(uri).await;
            assert_eq!(
                h[header::CACHE_CONTROL],
                "public, max-age=31536000, immutable"
            );
        }
        let (_, h) = get("/../../etc/passwd").await;
        assert_eq!(
            h[header::CONTENT_TYPE],
            "text/html; charset=utf-8",
            "路径穿越回落到 index.html"
        );
        e.mgr.stop().await;
    }
}
