//! Website reconnaissance: per HTTP(S) endpoint, profile the server
//! headers, TLS certificate, company/ownership intel (RDAP + DNS),
//! Wappalyzer-style technologies, and the page's asset inventory.
//!
//! Follows the tools/advisor rule: every step is bounded (timeouts, byte
//! caps, item caps) and every failure degrades to a partial profile or a
//! `Note` — a scan never fails because reconnaissance did.

pub mod assets;
pub mod company;
pub mod dns;
pub mod favicon;
pub mod http;
pub mod tech;
pub mod tls;

use crate::event::ScanEvent;
use crate::model::{HostState, ScanReport, WebProfile};
use crate::target::ResolvedUrl;
use futures::stream::{self, StreamExt};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Ports treated as HTTP-ish even when service detection didn't run.
const WEB_PORTS: &[u16] = &[
    80, 81, 443, 3000, 3001, 5000, 5001, 5601, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
];

/// Wall-clock cap for one endpoint profile — the scan moves on past it.
pub const PROFILE_TIMEOUT: Duration = Duration::from_secs(30);
/// How many endpoints profile at once.
const PROFILE_CONCURRENCY: usize = 8;

/// Post-scan web enrichment: profile every `(ip, url)` pair — the
/// explicit URL targets plus, when `all_http` is set, every open
/// HTTP-ish port on up hosts — and attach profiles to their hosts.
pub async fn enrich(
    report: &mut ScanReport,
    urls: &[ResolvedUrl],
    all_http: bool,
    events: &broadcast::Sender<ScanEvent>,
    cancel: &CancellationToken,
    advisor: &std::sync::Arc<dyn crate::advisor::ScanAdvisor>,
    crawl: usize,
) {
    let mut targets: Vec<(IpAddr, String)> = urls
        .iter()
        .map(|r| (r.ip, r.target.origin.clone()))
        .collect();
    if all_http {
        for h in &report.hosts {
            if h.state != HostState::Up {
                continue;
            }
            let name = h.hostname.clone().unwrap_or_else(|| h.ip.to_string());
            for p in &h.ports {
                if !p.state.is_open() || !is_http_port(p) {
                    continue;
                }
                let scheme = if is_https(p.port, p.service.as_deref()) {
                    "https"
                } else {
                    "http"
                };
                let default =
                    (scheme == "https" && p.port == 443) || (scheme == "http" && p.port == 80);
                let origin = if default {
                    format!("{scheme}://{name}")
                } else {
                    format!("{scheme}://{name}:{}", p.port)
                };
                targets.push((h.ip, origin));
            }
        }
    }
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return;
    }
    note(
        events,
        format!("web: profiling {} endpoint(s)", targets.len()),
    );

    let mut profiles = stream::iter(targets)
        .map(|(ip, url)| {
            let cancel = cancel.clone();
            async move {
                if cancel.is_cancelled() {
                    return None;
                }
                let advisor = advisor.clone();
                let p = tokio::time::timeout(
                    PROFILE_TIMEOUT,
                    profile(ip, &url, cancel.clone(), advisor, crawl),
                )
                .await
                .ok()
                .flatten();
                Some((ip, p))
            }
        })
        .buffer_unordered(PROFILE_CONCURRENCY);

    while let Some(item) = profiles.next().await {
        let Some((ip, Some(p))) = item else { continue };
        note(events, summarize(&p));
        if let Some(h) = report.hosts.iter_mut().find(|h| h.ip == ip) {
            h.web_profiles.push(p);
        }
    }
}

fn is_http_port(p: &crate::model::PortResult) -> bool {
    if p.banner.as_deref().is_some_and(|b| b.starts_with("HTTP/")) {
        return true;
    }
    if let Some(s) = &p.service {
        let s = s.to_ascii_lowercase();
        if s.contains("http") {
            return true;
        }
    }
    WEB_PORTS.contains(&p.port)
}

fn is_https(port: u16, service: Option<&str>) -> bool {
    matches!(port, 443 | 8443)
        || service.is_some_and(|s| {
            let s = s.to_ascii_lowercase();
            s.contains("https") || s.contains("ssl") || s.contains("tls")
        })
}

/// Full profile for one origin URL pinned to `ip` (the address the scan
/// found it on — DNS pinning keeps Host/SNI identical to the real site).
pub async fn profile(
    ip: IpAddr,
    origin: &str,
    cancel: CancellationToken,
    advisor: std::sync::Arc<dyn crate::advisor::ScanAdvisor>,
    crawl: usize,
) -> Option<WebProfile> {
    crate::ensure_crypto_provider();
    let u = url::Url::parse(origin).ok()?;
    let host = u.host_str()?.to_string();
    let port = u.port_or_known_default()?;
    let https = u.scheme() == "https";

    let mut prof = WebProfile {
        url: origin.to_string(),
        final_url: origin.to_string(),
        status: 0,
        http_version: String::new(),
        ttfb_ms: 0,
        redirects: Vec::new(),
        server: None,
        powered_by: None,
        headers: Vec::new(),
        security: Default::default(),
        tls: None,
        company: Default::default(),
        technologies: Vec::new(),
        assets: Vec::new(),
        external_domains: Vec::new(),
        api_hints: Vec::new(),
        robots: None,
        favicon_mmh3: None,
        error: None,
        ai_note: None,
    };

    // TLS and HTTP run together — independent round trips, and the
    // certificate feeds company + SAN intel even when HTTP is filtered.
    let site = http::Site::new(ip, &u);
    let (tls_res, http_res) = tokio::join!(
        async {
            if https {
                tls::fetch(ip, &host, port, Duration::from_secs(6)).await
            } else {
                None
            }
        },
        site.fetch(&u, cancel.clone())
    );
    prof.tls = tls_res;

    let resp = match http_res {
        Ok(r) => Some(r),
        Err(e) => {
            prof.error = Some(e.to_string());
            None
        }
    };

    let body = if let Some(r) = resp {
        prof.final_url = r.final_url;
        prof.status = r.status;
        prof.http_version = r.version;
        prof.ttfb_ms = r.ttfb_ms;
        prof.redirects = r.redirects;
        prof.server = http::header(&r.headers, "server").map(str::to_string);
        prof.powered_by = http::header(&r.headers, "x-powered-by").map(str::to_string);
        prof.security = http::security_headers(&r.headers);
        prof.headers = r.headers;
        Some(r.body)
    } else {
        None
    };

    let final_url = url::Url::parse(&prof.final_url).unwrap_or_else(|_| u.clone());
    let page = body.as_deref().map(|b| assets::parse_page(&final_url, b));
    let body = body.unwrap_or_default();

    // Independent lookups run together; each is individually bounded.
    let (company, (assets, external, api_hints, js_bundles), robots, fav) = tokio::join!(
        company::gather(
            &host,
            ip,
            &site,
            prof.tls.as_ref(),
            page.as_ref(),
            &final_url,
            cancel.clone()
        ),
        assets::collect(&site, &final_url, page.as_ref(), &body, cancel.clone()),
        assets::robots(&site, &final_url, cancel.clone()),
        favicon::fetch_hash(&site, &final_url, cancel.clone()),
    );
    prof.company = company;
    prof.assets = assets;
    prof.external_domains = external;
    prof.api_hints = api_hints;
    prof.favicon_mmh3 = fav;
    let robots_body = robots.as_ref().map(|(_, b)| b.clone());
    prof.robots = robots.map(|(info, _)| info);

    // Shallow same-origin crawl — inner pages often carry tech the
    // homepage doesn't. Bodies/inline-js/meta/script-srcs merge into
    // the detection signals. `crawl == 0` is polite mode.
    let mut crawl_bodies: Vec<String> = Vec::new();
    let mut extra_meta: Vec<(String, String)> = Vec::new();
    let mut extra_inline: Vec<String> = Vec::new();
    let mut extra_scripts: Vec<String> = Vec::new();
    if crawl > 0 && page.is_some() {
        let links: Vec<url::Url> = prof
            .assets
            .iter()
            .filter(|a| a.kind == "link")
            .filter_map(|a| url::Url::parse(&a.url).ok())
            .take(crawl)
            .collect();
        let pages: Vec<http::HttpPage> = stream::iter(links)
            .map(|u| {
                let site = &site;
                let cancel = cancel.clone();
                async move { site.fetch(&u, cancel).await.ok() }
            })
            .buffer_unordered(crawl.min(4))
            .filter_map(|r| async { r })
            .collect()
            .await;
        for r in pages {
            if cancel.is_cancelled() {
                break;
            }
            let Ok(u) = url::Url::parse(&r.final_url) else {
                continue;
            };
            let inner = assets::parse_page(&u, &r.body);
            extra_meta.extend(inner.meta);
            extra_inline.extend(inner.inline_js);
            extra_scripts.extend(
                inner
                    .asset_urls
                    .into_iter()
                    .filter(|(k, _)| k == "script")
                    .map(|(_, u)| u),
            );
            crawl_bodies.push(r.body);
        }
    }
    let (mut meta_all, mut inline_all) = match page {
        Some(p) => (p.meta, p.inline_js),
        None => (Vec::new(), Vec::new()),
    };
    meta_all.extend(extra_meta);
    inline_all.extend(extra_inline);
    let mut script_srcs: Vec<String> = prof
        .assets
        .iter()
        .filter(|a| a.kind == "script")
        .map(|a| a.url.clone())
        .collect();
    script_srcs.extend(extra_scripts);

    prof.technologies = tech::detect(&tech::Signals {
        headers: &prof.headers,
        cookies: http::header(&prof.headers, "set-cookie")
            .unwrap_or_default()
            .to_string(),
        meta: &meta_all,
        scripts: script_srcs.iter().map(String::as_str).collect(),
        inline_js: &inline_all,
        js_bundles: &js_bundles,
        crawl: &crawl_bodies,
        body: &body,
        final_url: &prof.final_url,
        server: prof.server.as_deref(),
        powered_by: prof.powered_by.as_deref(),
        dns: &prof.company.dns,
        tls_issuer: prof.tls.as_ref().and_then(|t| t.issuer_org.as_deref()),
        robots_body: robots_body.as_deref(),
        favicon_mmh3: prof.favicon_mmh3,
    });

    // Optional AI stack commentary — after fingerprinting so it sees the
    // full picture. Failures degrade to silence like every advisor hook.
    if let Some(text) = advisor.analyze_web(&prof).await {
        prof.ai_note = Some(text);
    }

    Some(prof)
}

fn summarize(p: &WebProfile) -> String {
    use std::fmt::Write;
    let status: std::borrow::Cow<'_, str> = if p.status == 0 {
        "no response".into()
    } else {
        p.status.to_string().into()
    };
    let mut s = format!("web: {} — {status}", p.url);
    if let Some(srv) = &p.server {
        let _ = write!(s, " · {srv}");
    }
    if !p.technologies.is_empty() {
        let _ = write!(s, " · {} tech", p.technologies.len());
    }
    if !p.assets.is_empty() {
        let _ = write!(s, " · {} assets", p.assets.len());
    }
    if let Some(e) = &p.error {
        let _ = write!(s, " · {e}");
    }
    s
}

fn note(events: &broadcast::Sender<ScanEvent>, text: impl Into<String>) {
    let _ = events.send(ScanEvent::Note { text: text.into() });
}
