//! `web::tech::detect` hot-path bench — one realistic page through the
//! whole fingerprint DB (AC gates + gated regex eval + DOM).
use criterion::{Criterion, criterion_group, criterion_main};
use ntok_core::web::tech::{Signals, detect};
use std::hint::black_box;
use std::time::Duration;

fn wordpress_page() -> String {
    let mut b = String::with_capacity(60_000);
    b.push_str("<!DOCTYPE html><html><head>");
    b.push_str(r#"<meta name="generator" content="WordPress 6.4.1">"#);
    b.push_str(r#"<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">"#);
    b.push_str(r#"<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>"#);
    for i in 0..400 {
        b.push_str(&format!(
            r#"<div class="entry-content wp-block-paragraph" id="p{i}"><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit {i}.</p><a href="/wp-content/uploads/2024/img{i}.png"><img src="/wp-content/uploads/2024/img{i}.png"></a></div>"#
        ));
    }
    b.push_str(
        r#"<script>var wpEmojiSettings={"baseUrl":"https://s.w.org/images/core/emoji/"};jQuery(function($){$(".x").click(function(){})});</script>"#,
    );
    b.push_str("</body></html>");
    b
}

fn detect_wp(c: &mut Criterion) {
    let body = wordpress_page();
    let headers = vec![
        ("server".to_string(), "nginx/1.25.4".to_string()),
        (
            "x-pingback".to_string(),
            "https://example.com/xmlrpc.php".to_string(),
        ),
        (
            "set-cookie".to_string(),
            "wp-settings-1=x; path=/".to_string(),
        ),
    ];
    let meta = vec![("generator".to_string(), "WordPress 6.4.1".to_string())];
    let scripts = vec![
        "/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
        "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js",
    ];
    let inline =
        vec!["var wpEmojiSettings = {}; jQuery(document).ready(function($){});".to_string()];
    let cookies = "wp-settings-1=x; comment_author_hash=abc".to_string();
    detect(&Signals {
        headers: &headers,
        cookies: cookies.clone(),
        meta: &meta,
        scripts: scripts.clone(),
        inline_js: &inline,
        js_bundles: &[],
        crawl: &[],
        body: "",
        final_url: "https://example.com/",
        server: Some("nginx/1.25.4"),
        powered_by: None,
        dns: &[],
        tls_issuer: None,
        robots_body: None,
        favicon_mmh3: None,
    }); // warm the lazy regex/AC tables outside the measured loop
    let mut g = c.benchmark_group("tech_detect");
    g.measurement_time(Duration::from_secs(6));
    g.bench_function("empty_page", |ben| {
        ben.iter(|| {
            black_box(detect(&Signals {
                headers: &headers,
                cookies: cookies.clone(),
                meta: &[],
                scripts: vec![],
                inline_js: &[],
                js_bundles: &[],
                crawl: &[],
                body: "",
                final_url: "https://example.com/",
                server: Some("nginx/1.25.4"),
                powered_by: None,
                dns: &[],
                tls_issuer: None,
                robots_body: None,
                favicon_mmh3: None,
            }))
        })
    });
    g.bench_function("wordpress_60k", |ben| {
        ben.iter(|| {
            black_box(detect(&Signals {
                headers: &headers,
                cookies: cookies.clone(),
                meta: &meta,
                scripts: scripts.clone(),
                inline_js: &inline,
                js_bundles: &[],
                crawl: &[],
                body: black_box(&body),
                final_url: "https://example.com/",
                server: Some("nginx/1.25.4"),
                powered_by: None,
                dns: &[],
                tls_issuer: None,
                robots_body: None,
                favicon_mmh3: None,
            }))
        })
    });
    g.finish();
}

criterion_group!(benches, detect_wp);
criterion_main!(benches);
