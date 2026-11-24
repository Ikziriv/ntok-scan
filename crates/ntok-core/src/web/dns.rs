//! DNS + registration intel via public JSON APIs — DNS-over-HTTPS for
//! MX/NS/TXT and RDAP for domain/IP ownership. Every call is bounded and
//! optional: private IPs skip the external lookups entirely, and any
//! failure just yields less intel.

use serde_json::Value;
use std::net::IpAddr;
use std::time::Duration;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(6);

fn client() -> &'static reqwest::Client {
    static C: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent("ntok/0.1 (recon)")
            .timeout(LOOKUP_TIMEOUT)
            .build()
            .expect("reqwest client")
    })
}

/// Common two-level public suffixes — take three labels for these.
/// shortcut: a curated list, not the full PSL; upgrade to a suffix list
/// if ccTLD intel needs to be exact.
const TWO_LEVEL_TLDS: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "or.jp", "ne.jp",
    "com.br", "com.cn", "com.tw", "co.kr", "co.in", "com.sg", "com.hk", "co.nz", "com.mx",
    "com.tr", "com.ar", "com.co", "com.sa", "co.za", "com.pl", "com.ua",
];

/// Registered domain for `host` — the level ownership attaches to
/// (`www.example.co.uk` → `example.co.uk`). IP literals return `None`.
pub fn registered_domain(host: &str) -> Option<std::borrow::Cow<'_, str>> {
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let host = host.trim_end_matches('.');
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return Some(host.into());
    }
    let last2 = labels[labels.len() - 2..].join(".");
    if labels.len() >= 3 && TWO_LEVEL_TLDS.contains(&last2.as_str()) {
        return Some(labels[labels.len() - 3..].join(".").into());
    }
    Some(last2.into())
}

/// Certificate-transparency subdomain discovery via crt.sh — passive:
/// one HTTPS GET to the CT log aggregator, zero packets toward the
/// target. Sorted, deduped, wildcard markers stripped, capped.
pub async fn ct_subdomains(domain: &str) -> Vec<String> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    if domain.is_empty() || domain.parse::<IpAddr>().is_ok() {
        return Vec::new();
    }
    let res = client()
        .get("https://crt.sh/")
        .query(&[("q", format!("%.{domain}")), ("output", "json".into())])
        .send()
        .await;
    let Ok(res) = res else { return Vec::new() };
    let Ok(v) = res.json::<Value>().await else {
        return Vec::new();
    };
    parse_ct_names(&v, &domain)
}

/// crt.sh rows carry newline-separated `name_value` lists. Under
/// `domain` only, `*.` stripped, capped at 2000 — CT answers can be
/// unreasonably large for popular zones.
fn parse_ct_names(v: &Value, domain: &str) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    let Some(rows) = v.as_array() else {
        return Vec::new();
    };
    // crt.sh substring-matches — `testexample.com` hits `%.example.com`.
    // Require an exact match or a real label boundary.
    let suffix = format!(".{domain}");
    for names in rows
        .iter()
        .filter_map(|r| r.get("name_value").and_then(Value::as_str))
    {
        for n in names.split('\n') {
            let n = n
                .trim()
                .trim_start_matches("*.")
                .trim_end_matches('.')
                .to_lowercase();
            if (n == domain || n.ends_with(&suffix)) && !n.contains([' ', '@']) && !n.is_empty() {
                out.insert(n);
            }
        }
    }
    out.into_iter().take(2000).collect()
}

/// One DoH JSON answer set: `doh("example.com", "TXT")` → raw `data`
/// strings (quotes stripped).
pub async fn doh(name: &str, kind: &str) -> Vec<String> {
    for base in [
        "https://cloudflare-dns.com/dns-query",
        "https://1.1.1.1/dns-query",
    ] {
        let res = client()
            .get(base)
            .query(&[("name", name), ("type", kind)])
            .header("accept", "application/dns-json")
            .send()
            .await;
        let Ok(res) = res else { continue };
        let Ok(v) = res.json::<Value>().await else {
            continue;
        };
        let Some(rows) = v.get("Answer").and_then(Value::as_array) else {
            return Vec::new();
        };
        return rows
            .iter()
            .filter_map(|r| r.get("data").and_then(Value::as_str))
            .map(|d| d.replace('"', "").trim().to_string())
            .collect();
    }
    Vec::new()
}

/// Domain registration intel: registrant org and registrar, parsed
/// loosely — RDAP vcard shapes vary between registries.
pub async fn rdap_domain(domain: &str) -> (Option<String>, Option<String>) {
    let Some(v) = rdap(&format!("https://rdap.org/domain/{domain}")).await else {
        return (None, None);
    };
    let mut registrant = None;
    let mut registrar = None;
    for ent in v
        .get("entities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let roles = ent
            .get("roles")
            .and_then(Value::as_array)
            .map(|r| r.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let name = vcard_name(ent);
        if roles.contains(&"registrar") && registrar.is_none() {
            registrar = name;
        } else if roles.contains(&"registrant") && registrant.is_none() {
            registrant = name;
        }
    }
    (registrant, registrar)
}

/// IP block owner for a public IP — the network name RDAP reports.
pub async fn rdap_ip(ip: IpAddr) -> Option<String> {
    if !is_public(ip) {
        return None;
    }
    let v = rdap(&format!("https://rdap.org/ip/{ip}")).await?;
    v.get("name")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            v.get("entities")
                .and_then(Value::as_array)?
                .iter()
                .find_map(vcard_name)
        })
}

/// "AS13335 Cloudflare, Inc." style string for a public IP, via
/// ipinfo.io's free endpoint. Best-effort — degrades silently.
pub async fn asn_org(ip: IpAddr) -> Option<String> {
    if !is_public(ip) {
        return None;
    }
    let v: Value = client()
        .get(format!("https://ipinfo.io/{ip}/json"))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    v.get("org")
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

fn is_public(ip: IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v) => v,
        IpAddr::V6(_) => return true,
    };
    !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        || v4.is_broadcast() || v4.is_multicast() || v4.is_documentation()
        // CGNAT 100.64/10 — stable Rust has no is_shared; check the range.
        || (u32::from(v4) >= 0x6440_0000 && u32::from(v4) < 0x6480_0000))
}

/// `fn`/`org` from an RDAP entity's vcardArray.
fn vcard_name(ent: &Value) -> Option<String> {
    let arr = ent.get("vcardArray")?.as_array()?.get(1)?.as_array()?;
    // Prefer "org" (companies), then "fn" (names), each first row.
    for key in ["org", "fn"] {
        for prop in arr {
            if prop.as_array()?.first().and_then(Value::as_str) == Some(key)
                && let Some(v) = prop.as_array()?.get(3).and_then(Value::as_str)
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

async fn rdap(url: &str) -> Option<Value> {
    client()
        .get(url)
        .send()
        .await
        .ok()?
        .json::<Value>()
        .await
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_names_filtered_sorted() {
        let v = serde_json::json!([
            {"name_value":"www.example.com\n*.example.com"},
            {"name_value":"EXAMPLE.com."},
            {"name_value":"other.org\n a.example.com\ntestexample.com\nm.testexample.com"},
            {"name_value":"dup.example.com"},
            {"name_value":"dup.example.com"}
        ]);
        let got = parse_ct_names(&v, "example.com");
        assert_eq!(
            got,
            vec![
                "a.example.com",
                "dup.example.com",
                "example.com",
                "www.example.com"
            ]
        );
    }
}
