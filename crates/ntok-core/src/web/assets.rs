//! Asset inventory: every resource the page references — scripts,
//! styles, media, fonts, docs, forms — plus internal links, robots.txt,
//! and API-path hints pulled out of first-party JS bundles.

use super::http;
use crate::model::{RobotsInfo, WebAsset};
use futures::stream::{self, StreamExt};
use regex::Regex;
use std::collections::BTreeSet;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// First-party JS bundles scanned for API paths.
const MAX_JS_BUNDLES: usize = 12;
/// Per-bundle byte cap.
const JS_CAP: usize = 256 * 1024;
/// Caps that keep the inventory legible.
const MAX_LINKS: usize = 100;
const MAX_DISALLOWS: usize = 60;
const MAX_API_HINTS: usize = 40;

/// What `parse_page` pulled out of the HTML — meta, JSON-LD and the raw
/// asset references (resolved later against the final URL).
pub struct Page {
    /// (name-or-property, content) from `<meta>`.
    pub meta: Vec<(String, String)>,
    /// `<script type="application/ld+json">` bodies.
    pub jsonld: Vec<String>,
    /// (kind, raw attribute value) before URL resolution.
    pub asset_urls: Vec<(String, String)>,
    /// Inline script bodies, bounded — API paths hide here too.
    pub inline_js: Vec<String>,
}

/// Parse the HTML head+body into a [`Page`].
pub fn parse_page(_base: &url::Url, html: &str) -> Page {
    let dom = tl::parse(html, tl::ParserOptions::default());
    let Ok(dom) = dom else {
        return Page {
            meta: Vec::new(),
            jsonld: Vec::new(),
            asset_urls: Vec::new(),
            inline_js: Vec::new(),
        };
    };
    let parser = dom.parser();
    let mut page = Page {
        meta: Vec::new(),
        jsonld: Vec::new(),
        asset_urls: Vec::new(),
        inline_js: Vec::new(),
    };

    let attr = |h: &tl::NodeHandle, key: &str| -> Option<String> {
        h.get(parser)?
            .as_tag()?
            .attributes()
            .get(key)
            .flatten()
            .map(|b| b.as_utf8_str().into_owned())
    };

    if let Some(nodes) = dom.query_selector("meta") {
        for h in nodes {
            let name = attr(&h, "name")
                .or_else(|| attr(&h, "property"))
                .or_else(|| attr(&h, "http-equiv"));
            if let (Some(k), Some(v)) = (name, attr(&h, "content")) {
                page.meta.push((k.to_ascii_lowercase(), v));
            }
        }
    }

    for (sel, kind) in [
        ("script[src]", "script"),
        ("img[src]", "image"),
        ("img[srcset]", "image"),
        ("source[src]", "media"),
        ("source[srcset]", "media"),
        ("video[src]", "media"),
        ("video[poster]", "image"),
        ("audio[src]", "media"),
        ("iframe[src]", "frame"),
        ("embed[src]", "embed"),
        ("object[data]", "embed"),
        ("form[action]", "form"),
    ] {
        let key = sel
            .split('[')
            .nth(1)
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or("src");
        let Some(nodes) = dom.query_selector(sel) else {
            continue;
        };
        for h in nodes {
            if let Some(v) = attr(&h, key) {
                let v = v.trim();
                if !v.is_empty() && !v.starts_with("data:") && !v.starts_with('#') {
                    page.asset_urls
                        .push((kind.to_string(), first_url(v).to_string()));
                }
            }
        }
    }

    // <link href>: classify by rel/as — stylesheets and preloads are real
    // assets; preconnects are third-party origin hints; canonicals skip.
    if let Some(nodes) = dom.query_selector("link[href]") {
        for h in nodes {
            let Some(href) = attr(&h, "href") else {
                continue;
            };
            let rel = attr(&h, "rel").unwrap_or_default().to_ascii_lowercase();
            let as_ = attr(&h, "as").unwrap_or_default().to_ascii_lowercase();
            let kind = if rel.contains("stylesheet") {
                "style"
            } else if rel.contains("icon") {
                "icon"
            } else if rel.contains("manifest") {
                "doc"
            } else if rel.contains("preload") || rel.contains("prefetch") {
                match as_.as_str() {
                    "font" => "font",
                    "script" => "script",
                    "style" => "style",
                    "image" => "image",
                    _ => "hint",
                }
            } else if rel.contains("preconnect") || rel.contains("dns-prefetch") {
                "hint"
            } else if rel.contains("canonical") || rel.contains("alternate") {
                continue;
            } else {
                "link"
            };
            let v = href.trim();
            if !v.is_empty() && !v.starts_with("data:") && !v.starts_with('#') {
                page.asset_urls
                    .push((kind.to_string(), first_url(v).to_string()));
            }
        }
    }

    // Page links — internal navigation surface.
    if let Some(nodes) = dom.query_selector("a[href]") {
        for h in nodes {
            if let Some(v) = attr(&h, "href") {
                let v = v.trim();
                if !v.is_empty()
                    && !v.starts_with("data:")
                    && !v.starts_with('#')
                    && !v.starts_with("mailto:")
                    && !v.starts_with("tel:")
                {
                    page.asset_urls
                        .push(("link".to_string(), first_url(v).to_string()));
                }
            }
        }
    }

    if let Some(scripts) = dom.query_selector("script") {
        for h in scripts {
            let ty = attr(&h, "type").unwrap_or_default();
            let text = || {
                h.get(parser)
                    .map(|n| n.inner_text(parser).trim().to_string())
                    .unwrap_or_default()
            };
            if ty.contains("ld+json") {
                page.jsonld.push(text());
            } else if attr(&h, "src").is_none() {
                let body = text();
                if !body.is_empty() {
                    page.inline_js.push(body.chars().take(64 * 1024).collect());
                }
            }
        }
    }
    page
}

/// srcset first candidate: `a.png 1x, b.png 2x` → `a.png`.
fn first_url(v: &str) -> &str {
    v.split(',')
        .next()
        .unwrap_or(v)
        .split_whitespace()
        .next()
        .unwrap_or(v)
}

/// Resolve raw references against the final URL into [`WebAsset`]s,
/// collect third-party hosts, and grep first-party JS for API paths.
/// Returns `(assets, external_domains, api_hints, js_bundles)` — the
/// bundle texts feed tech detection too.
pub async fn collect(
    site: &http::Site,
    final_url: &url::Url,
    page: Option<&Page>,
    body: &str,
    cancel: CancellationToken,
) -> (Vec<WebAsset>, Vec<String>, Vec<String>, Vec<String>) {
    let Some(page) = page else {
        return (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    };
    let page_host = final_url.host_str().unwrap_or_default().to_string();
    let mut external = BTreeSet::new();
    let mut assets = Vec::new();
    let mut links = Vec::new();
    let mut script_urls: Vec<url::Url> = Vec::new();

    for (kind, raw) in &page.asset_urls {
        let Ok(u) = final_url.join(raw) else {
            continue;
        };
        if !matches!(u.scheme(), "http" | "https") {
            continue;
        }
        let host = u.host_str().map(str::to_string);
        let third_party = host
            .as_deref()
            .is_some_and(|h| !h.eq_ignore_ascii_case(&page_host));
        if third_party && let Some(h) = &host {
            external.insert(h.clone());
        }
        let url_s = u.to_string();
        match kind.as_str() {
            "link" if !third_party => {
                // a[href] internal page links — kept separately, bounded.
                if links.len() < MAX_LINKS {
                    links.push(url_s.clone());
                }
                continue;
            }
            "script" if script_urls.len() < MAX_JS_BUNDLES && !third_party => {
                script_urls.push(u.clone());
            }
            _ => {}
        }
        assets.push(WebAsset {
            kind: kind.clone(),
            url: url_s,
            host: third_party.then(|| host.clone()).flatten(),
            content_type: None,
            bytes: None,
        });
    }

    // Internal links ride in the asset list with kind "link" — they are
    // site surface, the first thing a deeper crawl would hit.
    for l in links {
        assets.push(WebAsset {
            kind: "link".into(),
            url: l,
            host: None,
            content_type: None,
            bytes: None,
        });
    }

    let (api_hints, bundles) = js_scan(site, &script_urls, page, body, cancel).await;
    (assets, external.into_iter().collect(), api_hints, bundles)
}

/// Fetch first-party JS bundles once and reuse them twice: grep for
/// API-ish absolute paths, and hand the text to tech detection —
/// `scripts`/`js` fingerprints live in bundles, not the HTML.
/// Returns `(api_hints, bundle_texts)`.
async fn js_scan(
    site: &http::Site,
    script_urls: &[url::Url],
    page: &Page,
    body: &str,
    cancel: CancellationToken,
) -> (Vec<String>, Vec<String>) {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r#"["'](/(?:api|graphql|oauth2?|auth|v[0-9])[a-zA-Z0-9/._~?&=-]*)"#).unwrap()
    });
    let mut seen = BTreeSet::new();
    for js in page.inline_js.iter() {
        for m in re.captures_iter(js) {
            seen.insert(m[1].to_string());
        }
    }
    for cap in re.captures_iter(body) {
        seen.insert(cap[1].to_string());
    }

    // Bundles fetch in parallel (bounded) — sequential fetches made a
    // script-heavy page the slowest stage of the profile.
    let pages: Vec<http::HttpPage> = stream::iter(script_urls.iter().cloned())
        .map(|u| {
            let cancel = cancel.clone();
            async move { site.fetch(&u, cancel).await.ok() }
        })
        .buffer_unordered(4)
        .filter_map(|r| async { r })
        .collect()
        .await;
    let mut bundles = Vec::new();
    for r in pages {
        if cancel.is_cancelled() {
            break;
        }
        let text: String = r.body.chars().take(JS_CAP).collect();
        if seen.len() < MAX_API_HINTS {
            for m in re.captures_iter(&text) {
                seen.insert(m[1].to_string());
            }
        }
        bundles.push(text);
    }
    (seen.into_iter().take(MAX_API_HINTS).collect(), bundles)
}

/// robots.txt: presence, sitemaps, disallowed paths (bounded). Returns
/// the parsed info plus the raw body — tech fingerprints match on it.
pub async fn robots(
    site: &http::Site,
    final_url: &url::Url,
    cancel: CancellationToken,
) -> Option<(RobotsInfo, String)> {
    let host = final_url.host_str()?;
    let port_part = final_url
        .port()
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    let u = url::Url::parse(&format!(
        "{}://{host}{port_part}/robots.txt",
        final_url.scheme()
    ))
    .ok()?;
    // robots.txt is small — reuse the site fetch, it's already capped.
    let r = tokio::time::timeout(Duration::from_secs(8), site.fetch(&u, cancel))
        .await
        .ok()?
        .ok()?;
    if r.status != 200 {
        return None;
    }
    let mut info = RobotsInfo {
        present: true,
        sitemaps: Vec::new(),
        disallows: Vec::new(),
    };
    for line in r.body.lines() {
        let line = line.trim();
        if let Some(v) = line
            .strip_prefix("Sitemap:")
            .or_else(|| line.strip_prefix("sitemap:"))
        {
            info.sitemaps.push(v.trim().to_string());
        } else if let Some(v) = line
            .strip_prefix("Disallow:")
            .or_else(|| line.strip_prefix("disallow:"))
        {
            let v = v.trim();
            if !v.is_empty() && info.disallows.len() < MAX_DISALLOWS {
                info.disallows.push(v.to_string());
            }
        }
    }
    Some((info, r.body))
}
