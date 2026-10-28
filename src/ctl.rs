//! 本机控制套接字：服务运行时 lport add/edit/remove/list 经此由服务执行（立即生效）。
//! 路由与 JSON 格式与 Go 版（v0.2.0 及以前）一致，新旧版本的命令行与服务可以互通。

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path as UrlPath, State};
use axum::http::{Method, Request, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, put};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::net::{UnixListener, UnixStream};

use crate::manager::{Manager, RuleView, rule_json};
use crate::model::Rule;

/// 控制套接字放在配置目录下（0700），仅 root 可访问。
pub fn socket_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("lport.sock")
}

/// 监听控制套接字，先移除上次异常退出遗留的文件。
pub fn listen(path: &Path) -> Result<UnixListener, String> {
    if path.as_os_str().len() > 100 {
        return Err(format!(
            "路径过长（Unix 套接字路径上限约 100 字节）: {}",
            path.display()
        ));
    }
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    Ok(l)
}

pub fn router(mgr: Arc<Manager>) -> Router {
    Router::new()
        .route("/rules", get(list_rules).post(create_rule))
        .route("/rules/{id}", put(update_rule).delete(delete_rule))
        .with_state(mgr)
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

fn read_json<T: DeserializeOwned>(body: &Bytes) -> Result<T, &'static str> {
    if body.len() > 1 << 20 {
        return Err("请求格式错误");
    }
    serde_json::from_slice(body).map_err(|_| "请求格式错误")
}

async fn list_rules(State(m): State<Arc<Manager>>) -> Response {
    Json(m.rules().await).into_response()
}

async fn create_rule(State(m): State<Arc<Manager>>, body: Bytes) -> Response {
    let rule: Rule = match read_json(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    match m.create(rule).await {
        Ok(r) => Json(rule_json(&r)).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

async fn update_rule(
    State(m): State<Arc<Manager>>,
    UrlPath(id): UrlPath<String>,
    body: Bytes,
) -> Response {
    let rule: Rule = match read_json(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    match m.update(&id, rule).await {
        Ok(r) => Json(rule_json(&r)).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

async fn delete_rule(State(m): State<Arc<Manager>>, UrlPath(id): UrlPath<String>) -> Response {
    match m.delete(&id).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

/// 请求失败的原因：连接失败（服务可能未运行）或服务返回的错误。
#[derive(Debug)]
pub enum CtlError {
    Connect(io::Error),
    Other(String),
}

impl From<CtlError> for String {
    fn from(e: CtlError) -> String {
        match e {
            CtlError::Connect(e) => e.to_string(),
            CtlError::Other(s) => s,
        }
    }
}

pub struct Client {
    sock: PathBuf,
}

impl Client {
    pub fn new(sock: PathBuf) -> Self {
        Client { sock }
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T, CtlError> {
        let stream = UnixStream::connect(&self.sock)
            .await
            .map_err(CtlError::Connect)?;
        let other = |e: &dyn std::fmt::Display| CtlError::Other(e.to_string());
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| other(&e))?;
        tokio::spawn(conn);
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "lport")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| other(&e))?;
        let resp = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let resp = tx.send_request(req).await.map_err(|e| other(&e))?;
            let status = resp.status();
            let bytes = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| other(&e))?
                .to_bytes();
            Ok::<_, CtlError>((status, bytes))
        })
        .await
        .map_err(|_| CtlError::Other("请求服务超时".into()))??;
        let (status, bytes) = resp;
        if status != StatusCode::OK {
            let msg = serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| v["error"].as_str().map(String::from))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("服务返回 {status}"));
            return Err(CtlError::Other(msg));
        }
        serde_json::from_slice(&bytes).map_err(|e| other(&e))
    }

    pub async fn list(&self) -> Result<Vec<RuleView>, CtlError> {
        // Go 版在没有规则时返回 null
        Ok(self
            .call::<Option<Vec<RuleView>>>(Method::GET, "/rules", None)
            .await?
            .unwrap_or_default())
    }

    pub async fn create(&self, r: &Rule) -> Result<Rule, CtlError> {
        self.call(Method::POST, "/rules", Some(rule_json(r))).await
    }

    pub async fn update(&self, id: &str, r: &Rule) -> Result<Rule, CtlError> {
        self.call(
            Method::PUT,
            &format!("/rules/{}", escape(id)),
            Some(rule_json(r)),
        )
        .await
    }

    pub async fn delete(&self, id: &str) -> Result<(), CtlError> {
        self.call::<Value>(Method::DELETE, &format!("/rules/{}", escape(id)), None)
            .await
            .map(drop)
    }
}

/// 规则 ID 只含 [A-Za-z0-9_-]，其它字符按百分号编码以防万一。
fn escape(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
