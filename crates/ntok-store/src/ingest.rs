//! `ScanReport` → `services`/`scans` rows, in one transaction.
//!
//! Indexing rules: only open (incl. `open|filtered`) ports become rows —
//! the index answers "what services exist", not "what was probed". A
//! host's `WebProfile` joins onto the port it was fetched from (the
//! profile URL's effective port), contributing server/TLS/tech/company
//! columns. `first_seen` survives upserts; everything else tracks the
//! newest observation.

use crate::Result;
use ntok_core::{ScanReport, WebProfile};
use rusqlite::Connection;

pub fn ingest_report(conn: &Connection, r: &ScanReport) -> Result<usize> {
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT OR REPLACE INTO scans
         (start_unix, end_unix, args, technique, hosts_up, hosts_down, open)
         VALUES (?,?,?,?,?,?,?)",
        rusqlite::params![
            r.start_unix as i64,
            r.end_unix as i64,
            r.args,
            r.technique,
            r.summary.hosts_up as i64,
            r.summary.hosts_down as i64,
            r.summary.open as i64,
        ],
    )?;

    let mut n = 0;
    {
        let mut up_svc = tx.prepare_cached(
            "INSERT INTO services
             (ip, port, protocol, state, service, banner, hostname, os, asn, org,
              server, url, http_status, sec_score,
              tls_subject, tls_org, tls_sans, tls_expired, tls_self_signed, tech,
              risk, favicon_mmh3, findings, first_seen, last_seen, last_scan)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(ip, port, protocol) DO UPDATE SET
              state=excluded.state, service=excluded.service, banner=excluded.banner,
              hostname=excluded.hostname, os=excluded.os, asn=excluded.asn,
              org=excluded.org, server=excluded.server, url=excluded.url,
              http_status=excluded.http_status, sec_score=excluded.sec_score,
              tls_subject=excluded.tls_subject, tls_org=excluded.tls_org,
              tls_sans=excluded.tls_sans, tls_expired=excluded.tls_expired,
              tls_self_signed=excluded.tls_self_signed, tech=excluded.tech,
              risk=excluded.risk, favicon_mmh3=excluded.favicon_mmh3,
              findings=excluded.findings,
              last_seen=excluded.last_seen, last_scan=excluded.last_scan
             RETURNING rowid",
        )?;
        let mut del_fts = tx.prepare_cached("DELETE FROM services_fts WHERE rowid = ?")?;
        let mut ins_fts = tx.prepare_cached(
            "INSERT INTO services_fts
             (rowid, banner, hostname, service, server, url, tls_subject, org, tech)
             VALUES (?,?,?,?,?,?,?,?,?)",
        )?;
        let mut up_edge = tx.prepare_cached(
            "INSERT INTO edges (src, dst, kind, first_seen, last_seen)
             VALUES (?,?,?,?,?)
             ON CONFLICT(src, dst, kind) DO UPDATE SET
              last_seen=excluded.last_seen",
        )?;

        for host in &r.hosts {
            let ip_str = host.ip.to_string();
            let profiles_by_port: std::collections::HashMap<u16, &WebProfile> = host
                .web_profiles
                .iter()
                .filter_map(|w| {
                    let port = url::Url::parse(&w.url)
                        .ok()
                        .and_then(|u| u.port_or_known_default())?;
                    Some((port, w))
                })
                .collect();

            for p in &host.ports {
                if !p.state.is_open() {
                    continue;
                }
                let web = profiles_by_port.get(&p.port).copied();
                let risk = risk(p, web);
                let (
                    tls_sub,
                    tls_org,
                    tls_sans,
                    tls_exp,
                    tls_self,
                    tech,
                    org,
                    asn,
                    server,
                    url,
                    status,
                    score,
                ) = match web {
                    Some(w) => {
                        let tls = w.tls.as_ref();
                        (
                            tls.and_then(|t| t.subject_cn.as_deref()),
                            tls.and_then(|t| t.org.as_deref()),
                            tls.map(|t| t.san.join(",")),
                            tls.map(|t| i32::from(t.expired)).unwrap_or(0),
                            tls.map(|t| i32::from(t.self_signed)).unwrap_or(0),
                            tech_list(w),
                            w.company
                                .ip_org
                                .as_deref()
                                .or_else(|| w.company.names.first().map(String::as_str)),
                            w.company.asn.as_deref(),
                            w.server.as_deref(),
                            Some(w.final_url.as_str()),
                            (w.status > 0).then_some(w.status as i64),
                            Some(w.security.score as i64),
                        )
                    }
                    None => (
                        None, None, None, 0, 0, None, None, None, None, None, None, None,
                    ),
                };
                // Tool findings scoped to this port, plus host-level ones —
                // `tool:severity:detail` lines joined for `finding:`/`sev:`.
                let findings_text = {
                    let fs: Vec<String> = host
                        .findings
                        .iter()
                        .filter(|f| f.port.is_none() || f.port == Some(p.port))
                        .map(|f| format!("{}:{}:{}", f.tool, f.severity, f.detail))
                        .collect();
                    (!fs.is_empty()).then(|| fs.join(" | "))
                };
                let proto = p.protocol.as_str();
                let rowid: i64 = up_svc.query_row(
                    rusqlite::params![
                        &ip_str,
                        p.port as i64,
                        proto,
                        p.state.as_str(),
                        p.service,
                        p.banner,
                        host.hostname,
                        host.os_guess,
                        asn,
                        org,
                        server,
                        url,
                        status,
                        score,
                        tls_sub,
                        tls_org,
                        tls_sans,
                        tls_exp,
                        tls_self,
                        tech,
                        risk,
                        web.and_then(|w| w.favicon_mmh3.map(|h| h as i64)),
                        findings_text,
                        r.start_unix as i64,
                        r.end_unix as i64,
                        r.start_unix as i64,
                    ],
                    |r| r.get(0),
                )?;

                // Sync the FTS row (standalone table keyed by services.rowid).
                del_fts.execute(rusqlite::params![rowid])?;
                ins_fts.execute(rusqlite::params![
                    rowid,
                    format!(
                        "{} {}",
                        p.banner.as_deref().unwrap_or(""),
                        findings_text.as_deref().unwrap_or("")
                    ),
                    host.hostname.as_deref().unwrap_or(""),
                    p.service.as_deref().unwrap_or(""),
                    server.unwrap_or(""),
                    url.unwrap_or(""),
                    tls_sub.unwrap_or(""),
                    org.unwrap_or(""),
                    tech.as_deref().unwrap_or(""),
                ])?;
                n += 1;
            }
            // Relationship graph (host-level): cert SANs, redirect targets,
            // third-party asset hosts, the DNS name — Censys's "internet
            // map" pivots, drawn from data the scan already collected.
            for (kind, dst) in edges_for(host, &ip_str) {
                up_edge.execute(rusqlite::params![
                    &ip_str,
                    dst,
                    kind,
                    r.start_unix as i64,
                    r.end_unix as i64,
                ])?;
            }
        }
    }
    // Rarity score: % of indexed hosts this port is open on, inverted —
    // "seen on almost nothing" surfaces the outliers. Single O(N) pass
    // via CTE; only rewrites rows whose score actually changed.
    tx.execute(
        "WITH c AS (SELECT port, COUNT(DISTINCT ip) AS n FROM services GROUP BY port),
              t AS (SELECT MAX(1, COUNT(DISTINCT ip)) AS tot FROM services)
         UPDATE services
         SET anomaly = 100 - (100 * c.n) / t.tot
         FROM c, t
         WHERE c.port = services.port
           AND anomaly != 100 - (100 * c.n) / t.tot",
        [],
    )?;
    tx.commit()?;
    Ok(n)
}

/// Deduped `(kind, dst)` pairs a host's report data implies. `dst` is
/// a bare hostname — schemes/paths stripped, lowercased, trailing dot
/// dropped; self-references and non-hostnames skipped.
fn edges_for(host: &ntok_core::HostResult, src: &str) -> Vec<(&'static str, String)> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut push = |kind: &'static str, dst: String| {
        let dst = dst.trim_end_matches('.').to_lowercase();
        if !dst.is_empty() && dst != src && seen.insert((kind, dst.clone())) {
            out.push((kind, dst));
        }
    };
    if let Some(h) = &host.hostname {
        push("dns", h.clone());
    }
    for w in &host.web_profiles {
        if let Some(t) = &w.tls {
            for san in &t.san {
                push("san", san.clone());
            }
        }
        for hop in &w.redirects {
            if let Some(h) = url_host(&hop.location, &w.url) {
                push("redirect", h);
            }
        }
        if let Some(h) = url_host(&w.final_url, &w.url)
            && url_host(&w.url, &w.url) != Some(h.clone())
        {
            push("redirect", h);
        }
        for d in &w.external_domains {
            push("asset", d.clone());
        }
    }
    out
}

/// Host part of `url_s`, resolved against `base` for relative
/// locations (`Location: /login`).
fn url_host(url_s: &str, base: &str) -> Option<String> {
    let u = url::Url::parse(url_s)
        .ok()
        .or_else(|| url::Url::parse(base).ok()?.join(url_s).ok())?;
    u.host_str().map(str::to_string)
}

/// Exposure score 0–100 — deterministic and explainable, not ML. Inputs
/// are only facts the scan produced: risky-port table (remote admin,
/// cleartext, DB, IPC surface), cert validity, and the header score.
/// Findings/CVE context joins later via the tools enrichment path.
fn risk(p: &ntok_core::PortResult, web: Option<&WebProfile>) -> i64 {
    /// (port, points) — services that should not be reachable at all.
    const RISKY_PORTS: &[(u16, i64)] = &[
        (23, 35),   // telnet — cleartext
        (21, 25),   // ftp — cleartext
        (111, 25),  // rpcbind
        (135, 25),  // msrpc
        (139, 30),  // netbios
        (445, 30),  // smb
        (3389, 30), // rdp
        (5900, 30), // vnc
        (2375, 40), // docker daemon — unauthenticated by default
        (2376, 10), // docker tls — exposed but authenticated
    ];
    /// (port-range start, points) — database/queue/kv surface.
    const DB_PORTS: &[u16] = &[
        1433, 1521, 3306, 5432, 5984, 6379, 7000, 7001, 7474, 8000, 8086, 8888, 9042, 9200, 9300,
        11211, 27017, 27018, 28015, 28017, 50000,
    ];
    let mut score = 0i64;
    if let Some((_, pts)) = RISKY_PORTS.iter().find(|(port, _)| *port == p.port) {
        score = score.max(*pts);
    }
    if DB_PORTS.contains(&p.port) {
        score = score.max(20);
    }
    if let Some(w) = web {
        if w.tls.as_ref().map(|t| t.expired).unwrap_or(false) {
            score += 20;
        }
        if w.tls.as_ref().map(|t| t.self_signed).unwrap_or(false) {
            score += 10;
        }
        score += match w.security.score {
            0 => 10,
            1 | 2 => 5,
            _ => 0,
        };
    }
    score.min(100)
}

/// `nginx/1.25, WordPress` — searchable tech summary.
fn tech_list(w: &WebProfile) -> Option<String> {
    if w.technologies.is_empty() {
        return None;
    }
    Some(
        w.technologies
            .iter()
            .map(|t| match &t.version {
                Some(v) => format!("{}/{v}", t.name),
                None => t.name.clone(),
            })
            .collect::<Vec<_>>()
            .join(", "),
    )
}
