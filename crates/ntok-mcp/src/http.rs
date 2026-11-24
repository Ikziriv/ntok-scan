//! Optional Streamable HTTP transport (`--http ADDR`) — the remote half
//! of ntok-mcp. rmcp's `StreamableHttpService` serves the protocol on
//! `/mcp`; we sit in front of it doing Bearer auth, reusing the same
//! `ntok_…` API tokens ntok-web mints (settings → "API access") — the
//! `api_tokens` table in `reports/ntok.db` — plus an `NTOK_MCP_TOKEN`
//! shared secret for installs with no web users.

use crate::{Opts, server::NtokMcp};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// The path MCP clients POST to — anything else 404s.
const MCP_PATH: &str = "/mcp";

fn boxed(s: &str) -> BoxBody<Bytes, Infallible> {
    Full::new(Bytes::from(s.to_string())).boxed()
}

fn unauthorized() -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("www-authenticate", "Bearer realm=\"ntok-mcp\"")
        .header("content-type", "application/json")
        .body(boxed(
            "{\"error\":\"unauthorized — send Authorization: Bearer ntok_… \
             (mint one in ntok-web settings → API access) or NTOK_MCP_TOKEN\"}",
        ))
        .expect("static 401 response")
}

fn not_found() -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("content-type", "application/json")
        .body(boxed(&format!(
            "{{\"error\":\"MCP endpoint is POST {MCP_PATH}\"}}"
        )))
        .expect("static 404 response")
}

/// Constant-time equality over byte slices so `NTOK_MCP_TOKEN` isn't a
/// timing oracle.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Bearer check: `NTOK_MCP_TOKEN` shared secret, or a `ntok_…` API token
/// from the index DB — the same lookup ntok-web's `/api` routes do.
/// Runs the SQLite lookup on a blocking thread over a shared connection
/// instead of reopening the DB on every request.
async fn authorized(
    req: &Request<Incoming>,
    auth_db: &Arc<Mutex<Option<ntok_store::Store>>>,
    db_path: &Arc<std::path::PathBuf>,
    env_token: Option<&str>,
) -> bool {
    let Some(tok) = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        return false;
    };
    if let Some(t) = env_token
        && !t.is_empty()
        && ct_eq(t.as_bytes(), tok.as_bytes())
    {
        return true;
    }
    let tok = tok.to_string();
    let db = Arc::clone(auth_db);
    let path = Arc::clone(db_path);
    tokio::task::spawn_blocking(move || {
        let mut guard = db.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = ntok_store::Store::open(&path).ok();
        }
        guard
            .as_ref()
            .and_then(|s| s.user_for_api_token(&tok).ok().flatten())
            .is_some()
    })
    .await
    .unwrap_or(false)
}

/// Serve MCP over HTTP/1.1 on `addr`. Runs until the process dies —
/// `config.cancellation_token` stays unused (Ctrl-C kills it anyway).
pub async fn serve(opts: Opts, addr: SocketAddr, extra_hosts: Vec<String>) -> anyhow::Result<()> {
    let env_token = std::env::var("NTOK_MCP_TOKEN").ok();
    if env_token.as_deref().unwrap_or("").is_empty() {
        tracing::warn!(
            "NTOK_MCP_TOKEN unset — only existing ntok-web API tokens authorize; \
             with none minted every request will 401"
        );
    }

    let db_path = Arc::new(opts.db.clone().unwrap_or_else(ntok_store::db_path));
    let auth_db = Arc::new(Mutex::new(ntok_store::Store::open(&db_path).ok()));

    let mut config = StreamableHttpServerConfig::default();
    config.allowed_hosts.extend(extra_hosts);
    config.json_response = true;

    let opts = Arc::new(opts);
    let svc = StreamableHttpService::new(
        {
            let opts = opts.clone();
            move || Ok(NtokMcp::new((*opts).clone()))
        },
        Arc::new(LocalSessionManager::default()),
        config,
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, path = MCP_PATH, "ntok-mcp http listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let svc = svc.clone();
        let auth_db = Arc::clone(&auth_db);
        let db_path = Arc::clone(&db_path);
        let env_token = env_token.clone();
        tokio::spawn(async move {
            let f = service_fn(move |req: Request<Incoming>| {
                let svc = svc.clone();
                let auth_db = Arc::clone(&auth_db);
                let db_path = Arc::clone(&db_path);
                let env_token = env_token.clone();
                async move {
                    if !authorized(&req, &auth_db, &db_path, env_token.as_deref()).await {
                        return Ok::<_, Infallible>(unauthorized());
                    }
                    if req.uri().path() != MCP_PATH {
                        return Ok::<_, Infallible>(not_found());
                    }
                    Ok::<_, Infallible>(svc.handle(req).await)
                }
            });
            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), f)
                .await
            {
                tracing::debug!(%peer, "http connection closed: {e}");
            }
        });
    }
}
