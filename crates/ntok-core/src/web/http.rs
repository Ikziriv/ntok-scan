//! HTTP(S) fetch for reconnaissance: reqwest pinned to the scanned IP
//! (Host/SNI stay the real site's), a manual redirect chain so hops are
//! recorded, and byte-capped bodies. Bad certificates don't block the
//! fetch — the TLS pass reports them separately.

use crate::model::{RedirectHop, SecurityHeaders};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Cap on the saved response body — enough for head + main bundle refs.
const BODY_CAP: usize = 1_500_000;
const MAX_REDIRECTS: usize = 8;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub struct HttpPage {
    pub final_url: String,
    pub status: u16,
    pub version: String,
    pub ttfb_ms: u64,
    pub redirects: Vec<RedirectHop>,
    /// All response headers on the final response (lowercased names).
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// First value of `name` (headers are stored lowercased).
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
}

/// All values of `name` joined — for `set-cookie`.
pub fn header_all(headers: &[(String, String)], name: &str) -> String {
    headers
        .iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

/// A pinned origin: one reqwest client shared by every fetch a profile
/// makes. Page, JS bundles, robots.txt, favicon and crawl links all hit
/// the same `host:port` — keepalive reuses the TLS session instead of
/// re-handshaking ~15× per site.
pub struct Site {
    client: Option<reqwest::Client>,
    ip: IpAddr,
    port: u16,
}

fn client_builder(host: &str, ip: IpAddr, port: u16) -> reqwest::ClientBuilder {
    let mut builder = reqwest::Client::builder()
        .user_agent("ntok/0.1 (recon)")
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        // Recon reads certs in the TLS pass — a bad/expired cert is data,
        // not a reason to give up on the headers.
        .danger_accept_invalid_certs(true);
    if host.parse::<IpAddr>().is_err() {
        builder = builder.resolve(host, SocketAddr::new(ip, port));
    }
    builder
}

impl Site {
    /// Infallible: a `None` client falls back to a per-request build —
    /// a builder failure never blocks the profile.
    pub fn new(ip: IpAddr, url: &url::Url) -> Self {
        let host = url.host_str().unwrap_or_default().to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let client = client_builder(&host, ip, port).build().ok();
        Self { client, ip, port }
    }

    /// GET `url` through the shared connection pool.
    pub async fn fetch(
        &self,
        url: &url::Url,
        cancel: CancellationToken,
    ) -> crate::Result<HttpPage> {
        let tmp;
        let client = match &self.client {
            Some(c) => c,
            None => {
                let host = url.host_str().unwrap_or_default();
                let port = url.port_or_known_default().unwrap_or(self.port);
                tmp = client_builder(host, self.ip, port)
                    .build()
                    .map_err(|e| crate::Error::Tool(format!("http client: {e}")))?;
                &tmp
            }
        };
        Self::fetch_with(client, url, cancel).await
    }

    /// GET `url` via `ip`, following redirects manually to record the chain.
    async fn fetch_with(
        client: &reqwest::Client,
        url: &url::Url,
        cancel: CancellationToken,
    ) -> crate::Result<HttpPage> {
        let mut current = url.clone();
        let mut redirects = Vec::new();
        for _ in 0..=MAX_REDIRECTS {
            if cancel.is_cancelled() {
                return Err(crate::Error::Cancelled);
            }
            let t = Instant::now();
            let mut res = tokio::select! {
                r = client.get(current.clone()).send() => r,
                _ = cancel.cancelled() => return Err(crate::Error::Cancelled),
            }
            .map_err(|e| crate::Error::Tool(format!("{current}: {e}")))?;
            let ttfb_ms = t.elapsed().as_millis() as u64;

            let status = res.status().as_u16();
            if res.status().is_redirection()
                && let Some(loc) = res
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                && let Ok(next) = current.join(loc)
            {
                redirects.push(RedirectHop {
                    status,
                    location: loc.to_string(),
                });
                current = next;
                continue;
            }

            let headers: Vec<(String, String)> = res
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|s| (k.as_str().to_ascii_lowercase(), s.to_string()))
                })
                .collect();
            let version = format!("{:?}", res.version());

            let mut body = Vec::new();
            loop {
                let next = tokio::select! {
                    c = res.chunk() => c,
                    _ = cancel.cancelled() => return Err(crate::Error::Cancelled),
                };
                match next {
                    Ok(Some(chunk)) => {
                        body.extend_from_slice(&chunk);
                        if body.len() >= BODY_CAP {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
            body.truncate(BODY_CAP);

            let body = String::from_utf8(body)
                .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());

            return Ok(HttpPage {
                final_url: current.to_string(),
                status,
                version,
                ttfb_ms,
                redirects,
                headers,
                body,
            });
        }
        Err(crate::Error::Tool(format!(
            "{url}: too many redirects ({MAX_REDIRECTS})"
        )))
    }

    /// Fetch raw bytes (e.g. `/favicon.ico`) without UTF-8 decoding or
    /// duplicating the buffer. Follows redirects up to `MAX_REDIRECTS`.
    pub async fn fetch_bytes(
        &self,
        url: &url::Url,
        cancel: CancellationToken,
    ) -> crate::Result<(u16, Vec<u8>)> {
        let tmp;
        let client = match &self.client {
            Some(c) => c,
            None => {
                let host = url.host_str().unwrap_or_default();
                let port = url.port_or_known_default().unwrap_or(self.port);
                tmp = client_builder(host, self.ip, port)
                    .build()
                    .map_err(|e| crate::Error::Tool(format!("http client: {e}")))?;
                &tmp
            }
        };
        let mut current = url.clone();
        for _ in 0..=MAX_REDIRECTS {
            if cancel.is_cancelled() {
                return Err(crate::Error::Cancelled);
            }
            let mut res = tokio::select! {
                r = client.get(current.clone()).send() => r,
                _ = cancel.cancelled() => return Err(crate::Error::Cancelled),
            }
            .map_err(|e| crate::Error::Tool(format!("{current}: {e}")))?;
            let status = res.status().as_u16();
            if res.status().is_redirection()
                && let Some(loc) = res
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                && let Ok(next) = current.join(loc)
            {
                current = next;
                continue;
            }
            let mut body = Vec::new();
            loop {
                let next = tokio::select! {
                    c = res.chunk() => c,
                    _ = cancel.cancelled() => return Err(crate::Error::Cancelled),
                };
                match next {
                    Ok(Some(chunk)) => {
                        body.extend_from_slice(&chunk);
                        if body.len() >= BODY_CAP {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            body.truncate(BODY_CAP);
            return Ok((status, body));
        }
        Err(crate::Error::Tool(format!(
            "{url}: too many redirects ({MAX_REDIRECTS})"
        )))
    }
}

/// One-off fetch with its own client — for callers that make a single
/// request per site. Profile paths should share a [`Site`] instead.
pub async fn fetch(
    ip: IpAddr,
    url: &url::Url,
    _port: u16,
    cancel: CancellationToken,
) -> crate::Result<HttpPage> {
    Site::new(ip, url).fetch(url, cancel).await
}

/// Pull the hardening headers out of a header list; `score` counts the
/// six main ones present (hsts, csp, xfo, xcto, referrer, permissions).
pub fn security_headers(headers: &[(String, String)]) -> SecurityHeaders {
    let h = |n: &str| header(headers, n).map(str::to_string);
    let mut s = SecurityHeaders {
        hsts: h("strict-transport-security"),
        csp: h("content-security-policy"),
        x_frame_options: h("x-frame-options"),
        x_content_type_options: h("x-content-type-options"),
        referrer_policy: h("referrer-policy"),
        cors_origin: h("access-control-allow-origin"),
        score: 0,
    };
    s.score = [
        &s.hsts,
        &s.csp,
        &s.x_frame_options,
        &s.x_content_type_options,
        &s.referrer_policy,
        &h("permissions-policy"),
    ]
    .iter()
    .filter(|v| v.is_some())
    .count() as u8;
    s
}
