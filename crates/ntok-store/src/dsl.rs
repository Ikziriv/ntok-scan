//! The `ntok search` query language — Shodan-shaped:
//!
//! ```text
//! ip:1.2.3.4        net:10.0.          port:443 | 1-1024
//! service:nginx     product:apache     hostname:example
//! os:linux          asn:13335          org:cloudflare
//! server:nginx      tech:wordpress     banner:"openssh_8.9"
//! status:200        state:open         protocol:tcp
//! risk:high|medium|low|<n>  (≥70 / ≥40 / ≥1 / ≥n)
//! has:banner|tls|web|tech|hostname|os|org
//! expired:true      selfsigned:true    after:2025-01-01 | 1700000000
//! before:…          (bare words) → full-text over banners/certs/tech
//! ```

use crate::Error;

/// A parsed query: field filters AND'd with optional full-text terms.
#[derive(Debug, Default)]
pub struct Query {
    pub conds: Vec<Cond>,
    /// Free-text terms — each becomes a phrase in one FTS5 MATCH.
    pub free: Vec<String>,
}

#[derive(Debug)]
pub enum Cond {
    /// `col = 'v'` (protocol, state).
    Eq(&'static str, String),
    /// `col LIKE '%v%'` (service, hostname, os, asn, org, server, tech, banner).
    Like(&'static str, String),
    /// `col LIKE 'v%'` — net: prefix.
    Prefix(&'static str, String),
    /// `port BETWEEN lo AND hi` (lo == hi → `port = lo`).
    Port(u16, u16),
    /// `col >= n` — risk threshold (`risk:high|medium|low|<n>`).
    Min(&'static str, i64),
    /// `http_status = n`.
    Status(u16),
    /// `col IS NOT NULL AND col != ''` — has:*.
    NotNull(&'static str),
    /// `col = 1` / `= 0` — expired:, selfsigned:.
    Bool(&'static str, bool),
    /// `last_seen >= ts` / `<= ts`.
    Seen(bool, u64),
}

/// Tokenize on whitespace, honoring `"..."` phrases, then classify.
pub fn parse(q: &str) -> Result<Query, Error> {
    let mut out = Query::default();
    for tok in tokens(q) {
        match classify(&tok) {
            Kind::Cond(c) => out.conds.push(c),
            Kind::Free(t) if !t.is_empty() => out.free.push(t),
            Kind::Free(_) => {}
        }
    }
    Ok(out)
}

enum Kind {
    Cond(Cond),
    Free(String),
}

fn tokens(q: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in q.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn classify(tok: &str) -> Kind {
    let Some((field, val)) = tok.split_once(':') else {
        return Kind::Free(unquote(tok));
    };
    let v = unquote(val);
    let cond = match field.to_ascii_lowercase().as_str() {
        "ip" => Cond::Eq("s.ip", v),
        "net" => Cond::Prefix("s.ip", v),
        "port" => {
            return port(&v)
                .map(Kind::Cond)
                .unwrap_or(Kind::Free(tok.to_string()));
        }
        "protocol" => Cond::Eq("s.protocol", v),
        "state" => Cond::Eq("s.state", v),
        "service" => Cond::Like("s.service", v),
        "product" | "banner" => Cond::Like("s.banner", v),
        "hostname" => Cond::Like("s.hostname", v),
        "os" => Cond::Like("s.os", v),
        "asn" => Cond::Like("s.asn", v),
        "org" => Cond::Like("s.org", v),
        "server" => Cond::Like("s.server", v),
        "tech" => Cond::Like("s.tech", v),
        // finding:cve-2021 · sev:critical — tool findings text.
        "finding" | "sev" => Cond::Like("s.findings", v),
        "status" => {
            return v
                .parse::<u16>()
                .map(|n| Kind::Cond(Cond::Status(n)))
                .unwrap_or(Kind::Free(tok.to_string()));
        }
        "has" => {
            return match has_col(&v) {
                Some(c) => Kind::Cond(Cond::NotNull(c)),
                None => Kind::Free(tok.to_string()),
            };
        }
        "expired" => Cond::Bool("s.tls_expired", truthy(&v)),
        "favicon" => Cond::Eq("s.favicon_mmh3", v),
        "risk" | "anomaly" | "rare" => {
            let col = if field.eq_ignore_ascii_case("risk") {
                "s.risk"
            } else {
                "s.anomaly"
            };
            let n = match v.as_str() {
                "high" | "critical" => Some(70),
                "medium" | "med" => Some(40),
                "low" => Some(1),
                _ => v.parse::<i64>().ok(),
            };
            return n
                .map(|n| Kind::Cond(Cond::Min(col, n)))
                .unwrap_or(Kind::Free(tok.to_string()));
        }
        "selfsigned" => Cond::Bool("s.tls_self_signed", truthy(&v)),
        "after" => {
            return date(&v)
                .map(|t| Kind::Cond(Cond::Seen(true, t)))
                .unwrap_or(Kind::Free(tok.to_string()));
        }
        "before" => {
            return date(&v)
                .map(|t| Kind::Cond(Cond::Seen(false, t)))
                .unwrap_or(Kind::Free(tok.to_string()));
        }
        _ => return Kind::Free(tok.to_string()),
    };
    Kind::Cond(cond)
}

fn port(v: &str) -> Option<Cond> {
    if let Some((lo, hi)) = v.split_once('-') {
        Some(Cond::Port(lo.parse().ok()?, hi.parse().ok()?))
    } else {
        let n: u16 = v.parse().ok()?;
        Some(Cond::Port(n, n))
    }
}

fn has_col(v: &str) -> Option<&'static str> {
    Some(match v {
        "banner" => "s.banner",
        "tls" => "s.tls_subject",
        "web" | "http" => "s.url",
        "tech" => "s.tech",
        "hostname" => "s.hostname",
        "os" => "s.os",
        "org" => "s.org",
        "asn" => "s.asn",
        "findings" | "finding" | "vuln" => "s.findings",
        _ => return None,
    })
}

fn truthy(v: &str) -> bool {
    matches!(v, "true" | "yes" | "1" | "on")
}

/// Unix seconds or `YYYY-MM-DD` (UTC midnight). Bad input degrades to
/// free text rather than a confusing SQL error.
fn date(v: &str) -> Option<u64> {
    if let Ok(t) = v.parse::<u64>() {
        return Some(t);
    }
    let mut it = v.split('-');
    let (y, m, d): (i64, i64, i64) = (
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    );
    if it.next().is_some()
        || !(1970..=9999).contains(&y)
        || !(1..=12).contains(&m)
        || !(1..=31).contains(&d)
    {
        return None;
    }
    // days-from-civil (Howard Hinnant) — 86400s per civil day in UTC.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(((era * 146097 + doe - 719468) * 86400) as u64)
}

fn unquote(s: &str) -> String {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
        .to_string()
}

/// `(WHERE-fragment, params)` for `SELECT … FROM services s {frag}`.
/// FTS terms ride in as the first param against `services_fts MATCH ?`.
pub fn to_sql(q: &Query) -> Result<(String, Vec<String>), Error> {
    let mut wh: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();

    let mut join = String::new();
    if !q.free.is_empty() {
        join = "JOIN services_fts ON services_fts.rowid = s.rowid".into();
        let fts = q
            .free
            .iter()
            .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" AND ");
        wh.push("services_fts MATCH ?".into());
        params.push(fts);
    }

    for c in &q.conds {
        match c {
            Cond::Eq(col, v) => {
                wh.push(format!("{col} = ?"));
                params.push(v.clone());
            }
            Cond::Like(col, v) => {
                wh.push(format!("{col} LIKE ? ESCAPE '\\'"));
                params.push(format!("%{}%", crate::escape_like(v)));
            }
            Cond::Prefix(col, v) => {
                wh.push(format!("{col} LIKE ? ESCAPE '\\'"));
                params.push(format!("{}%", crate::escape_like(v)));
            }
            Cond::Port(lo, hi) if lo == hi => {
                wh.push("s.port = ?".into());
                params.push(lo.to_string());
            }
            Cond::Port(lo, hi) => {
                wh.push("s.port BETWEEN ? AND ?".into());
                params.extend([lo.to_string(), hi.to_string()]);
            }
            Cond::Min(col, n) => {
                wh.push(format!("{col} >= ?"));
                params.push(n.to_string());
            }
            Cond::Status(n) => {
                wh.push("s.http_status = ?".into());
                params.push(n.to_string());
            }
            Cond::NotNull(col) => wh.push(format!("{col} IS NOT NULL AND {col} != ''")),
            Cond::Bool(col, b) => wh.push(format!("{col} = {}", i32::from(*b))),
            Cond::Seen(after, t) => {
                wh.push(format!(
                    "s.last_seen {} ?",
                    if *after { ">=" } else { "<=" }
                ));
                params.push(t.to_string());
            }
        }
    }

    let frag = match (join.is_empty(), wh.is_empty()) {
        (true, true) => String::new(),
        (false, true) => join,
        (true, false) => format!("WHERE {}", wh.join(" AND ")),
        (false, false) => format!("{join} WHERE {}", wh.join(" AND ")),
    };
    Ok((frag, params))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields_and_freetext() {
        let q = parse("service:nginx port:443 \"expired cert\"").unwrap();
        assert_eq!(q.conds.len(), 2);
        assert_eq!(q.free, vec!["expired cert"]);
        let (sql, params) = to_sql(&q).unwrap();
        assert!(sql.contains("services_fts MATCH ?"));
        assert!(sql.contains("s.service LIKE ?"));
        assert!(sql.contains("s.port = ?"));
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn empty_query_is_no_where() {
        let (sql, params) = to_sql(&parse("").unwrap()).unwrap();
        assert_eq!(sql, "");
        assert!(params.is_empty());
    }

    #[test]
    fn port_range_and_flags() {
        let q = parse("port:1-1024 has:tls expired:true after:2025-01-01").unwrap();
        let (sql, _) = to_sql(&q).unwrap();
        assert!(sql.contains("s.port BETWEEN ? AND ?"));
        assert!(sql.contains("s.tls_subject IS NOT NULL"));
        assert!(sql.contains("s.tls_expired = 1"));
        assert!(sql.contains("s.last_seen >= ?"));
    }
}
