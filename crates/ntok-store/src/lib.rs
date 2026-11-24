//! Local searchable index of scan results — the "Shodan half" of ntok.
//! Every report (scans from the CLI or web UI, imported nmap XML) is
//! upserted into a SQLite database holding one row per open
//! `(ip, port, protocol)` service, plus an FTS5 table over the free-text
//! surface (banners, certs, tech). `ntok search "service:nginx port:443"`
//! then answers across the union of all past scans.
//!
//! The database lives next to the reports it indexes: `reports/ntok.db`
//! by default, overridable with `NTOK_DB` or `--db`.

pub mod agent;
mod auth;
mod dsl;
mod ingest;

use rusqlite::Connection;
use serde::Serialize;
use std::path::{Path, PathBuf};

pub use auth::{ApiToken, AuthEvent, SessionInfo, User, new_totp_secret, totp_check, totp_code};
pub use dsl::{Query, to_sql};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("store: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("query: {0}")]
    Query(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// One indexed service — a row of `services` joined to its FTS entry.
#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub ip: String,
    pub hostname: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub server: Option<String>,
    pub url: Option<String>,
    pub http_status: Option<u16>,
    pub os: Option<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
    pub tls_subject: Option<String>,
    pub tls_expired: bool,
    pub tech: Option<String>,
    /// Deterministic exposure score 0–100 (risky port + cert + header
    /// signals) — no model, fully explainable.
    pub risk: i64,
    /// Shodan-style mmh3 favicon hash (`ntok_core::web::favicon::lookup`
    /// resolves it to a product when known).
    pub favicon_mmh3: Option<i64>,
    /// 100 - % of indexed hosts this port is open on. 0 = ubiquitous,
    /// ~99 = seen on almost nothing — the "what's weird here" score.
    pub anomaly: i64,
    /// External-tool findings (`tool:severity:detail` joined by ` | `)
    /// — nuclei/nmap output, searchable via `finding:` and `sev:`.
    pub findings: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// One observed relationship a scan surfaced — a cert's SAN, a
/// redirect target, a third-party asset host, or a DNS name. `kind`
/// is `san | redirect | asset | dns`.
#[derive(Debug, Clone, Serialize)]
pub struct Edge {
    /// Host the edge was observed on (scanned IP).
    pub src: String,
    /// Domain or host it points at.
    pub dst: String,
    pub kind: String,
    pub last_seen: u64,
    /// `dst` already appears in the index (as an IP or hostname) —
    /// i.e. the related asset has been scanned too.
    pub indexed: bool,
}

/// Counts for `stats()` / `ntok search` footers.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Stats {
    pub services: u64,
    pub hosts: u64,
    pub scans: u64,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS scans (
    start_unix  INTEGER PRIMARY KEY,
    end_unix    INTEGER NOT NULL,
    args        TEXT NOT NULL,
    technique   TEXT NOT NULL,
    hosts_up    INTEGER NOT NULL,
    hosts_down  INTEGER NOT NULL,
    open        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS services (
    ip              TEXT NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT NOT NULL DEFAULT 'tcp',
    state           TEXT NOT NULL,
    service         TEXT,
    banner          TEXT,
    hostname        TEXT,
    os              TEXT,
    asn             TEXT,
    org             TEXT,
    server          TEXT,
    url             TEXT,
    http_status     INTEGER,
    sec_score       INTEGER,
    tls_subject     TEXT,
    tls_org         TEXT,
    tls_sans        TEXT,
    tls_expired     INTEGER NOT NULL DEFAULT 0,
    tls_self_signed INTEGER NOT NULL DEFAULT 0,
    tech            TEXT,
    risk            INTEGER NOT NULL DEFAULT 0,
    favicon_mmh3    INTEGER,
    anomaly         INTEGER NOT NULL DEFAULT 0,
    findings        TEXT,
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    last_scan       INTEGER NOT NULL,
    PRIMARY KEY (ip, port, protocol)
);
CREATE VIRTUAL TABLE IF NOT EXISTS services_fts USING fts5(
    banner, hostname, service, server, url, tls_subject, org, tech
);
CREATE TABLE IF NOT EXISTS edges (
    src         TEXT NOT NULL,
    dst         TEXT NOT NULL,
    kind        TEXT NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    PRIMARY KEY (src, dst, kind)
);
CREATE INDEX IF NOT EXISTS services_port_ip ON services(port, ip);
CREATE INDEX IF NOT EXISTS services_last_seen ON services(last_seen);
CREATE INDEX IF NOT EXISTS services_hostname ON services(hostname);
CREATE INDEX IF NOT EXISTS edges_dst ON edges(dst);
";

/// The index database — one file next to `reports/`.
pub struct Store {
    conn: Connection,
}

/// Columns added after v1, applied to pre-existing DBs (SQLite has no
/// `ADD COLUMN IF NOT EXISTS`, so check `table_info` first).
fn migrate(conn: &Connection) -> Result<()> {
    let mut st = conn.prepare("PRAGMA table_info(services)")?;
    let cols: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<std::result::Result<_, _>>()?;
    for (col, ddl) in [
        (
            "risk",
            "ALTER TABLE services ADD COLUMN risk INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "favicon_mmh3",
            "ALTER TABLE services ADD COLUMN favicon_mmh3 INTEGER",
        ),
        (
            "anomaly",
            "ALTER TABLE services ADD COLUMN anomaly INTEGER NOT NULL DEFAULT 0",
        ),
        ("findings", "ALTER TABLE services ADD COLUMN findings TEXT"),
    ] {
        if !cols.iter().any(|c| c == col) {
            conn.execute(ddl, [])?;
        }
    }
    let mut st = conn.prepare("PRAGMA table_info(users)")?;
    let cols: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<std::result::Result<_, _>>()?;
    for (col, ddl) in [
        ("email", "ALTER TABLE users ADD COLUMN email TEXT"),
        ("full_name", "ALTER TABLE users ADD COLUMN full_name TEXT"),
        (
            "totp_secret",
            "ALTER TABLE users ADD COLUMN totp_secret TEXT",
        ),
        (
            "fail_count",
            "ALTER TABLE users ADD COLUMN fail_count INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "lock_until",
            "ALTER TABLE users ADD COLUMN lock_until INTEGER",
        ),
    ] {
        if !cols.iter().any(|c| c == col) {
            conn.execute(ddl, [])?;
        }
    }
    // After the column ALTERs above — old DBs lack `email` until then,
    // so this can't live in AUTH_SCHEMA (it runs first).
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users(email COLLATE NOCASE);",
    )?;
    Ok(())
}

/// `NTOK_DB` override, else `reports/ntok.db` under the working dir —
/// matching where the web UI keeps `scan-*.json`.
pub fn db_path() -> PathBuf {
    std::env::var_os("NTOK_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("reports").join("ntok.db"))
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;
             PRAGMA cache_size=-16000;
             PRAGMA temp_store=MEMORY;
             PRAGMA mmap_size=268435456;",
        )?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(auth::AUTH_SCHEMA)?;
        conn.execute_batch(agent::AGENT_SCHEMA)?;
        migrate(&conn)?;
        Ok(Self { conn })
    }

    pub fn open_default() -> Result<Self> {
        Self::open(&db_path())
    }

    /// Upsert every open service in the report (one transaction).
    /// Returns rows written.
    pub fn ingest(&self, report: &ntok_core::ScanReport) -> Result<usize> {
        ingest::ingest_report(&self.conn, report)
    }

    /// Save an agent memory entry (unreviewed context, never policy).
    pub fn memory_save(&self, kind: &str, title: &str, body: &str, confidence: f64) -> Result<i64> {
        agent::memory_save(&self.conn, kind, title, body, confidence)
    }

    /// Keyword recall over agent memory.
    pub fn memory_search(&self, query: &str, limit: u32) -> Result<Vec<agent::Memory>> {
        agent::memory_search(&self.conn, query, limit)
    }

    /// High-confidence lessons ("instincts") for agent prompt injection.
    pub fn memory_lessons(&self, min_confidence: f64, limit: u32) -> Result<Vec<String>> {
        agent::memory_lessons(&self.conn, min_confidence, limit)
    }

    /// Most recent scans, newest first.
    pub fn recent_scans(&self, limit: u32) -> Result<Vec<agent::ScanRow>> {
        agent::recent_scans(&self.conn, limit)
    }

    /// Shodan-style search: `field:value` filters plus bare words that
    /// match the full-text index (banners, certs, tech). Empty query
    /// lists the most recently seen services.
    pub fn search(&self, query: &str, limit: u32) -> Result<Vec<Hit>> {
        let limit = limit.clamp(1, 1000);
        let (where_sql, params) = to_sql(&dsl::parse(query)?)?;
        let sql = format!(
            "SELECT s.ip, s.hostname, s.port, s.protocol, s.state, s.service,
                    s.banner, s.server, s.url, s.http_status, s.os, s.asn, s.org,
                    s.tls_subject, s.tls_expired, s.tech, s.risk,
                    s.favicon_mmh3, s.anomaly, s.findings, s.first_seen, s.last_seen
             FROM services s {where_sql} ORDER BY s.last_seen DESC LIMIT {limit}"
        );
        let mut st = self.conn.prepare(&sql)?;
        let rows = st.query_map(rusqlite::params_from_iter(params), |r| {
            Ok(Hit {
                ip: r.get(0)?,
                hostname: r.get(1)?,
                port: r.get::<_, u32>(2)? as u16,
                protocol: r.get(3)?,
                state: r.get(4)?,
                service: r.get(5)?,
                banner: r.get(6)?,
                server: r.get(7)?,
                url: r.get(8)?,
                http_status: r.get::<_, Option<u32>>(9)?.map(|s| s as u16),
                os: r.get(10)?,
                asn: r.get(11)?,
                org: r.get(12)?,
                tls_subject: r.get(13)?,
                tls_expired: r.get::<_, i64>(14)? != 0,
                tech: r.get(15)?,
                risk: r.get(16)?,
                favicon_mmh3: r.get(17)?,
                anomaly: r.get(18)?,
                findings: r.get(19)?,
                first_seen: r.get::<_, i64>(20)? as u64,
                last_seen: r.get::<_, i64>(21)? as u64,
            })
        })?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(Into::into)
    }

    /// Related-infrastructure pivot — edges to or from `target` at
    /// `depth` 1, or the wider neighborhood when depth > 1: discovered
    /// domains/hosts become new frontiers, Censys-map style. Bounded
    /// at 3 hops / 500 edges so a hub domain can't explode the walk.
    pub fn related(&self, target: &str, depth: u8) -> Result<Vec<Edge>> {
        let mut frontier = vec![target.to_string()];
        let mut visited: std::collections::HashSet<String> = frontier.iter().cloned().collect();
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for _ in 0..depth.clamp(1, 3) {
            let mut next = Vec::new();
            for node in std::mem::take(&mut frontier) {
                for e in self.edges_touching(&node)? {
                    if !seen.insert((e.src.clone(), e.dst.clone(), e.kind.clone())) {
                        continue;
                    }
                    for end in [&e.src, &e.dst] {
                        if visited.insert(end.clone()) {
                            next.push(end.clone());
                        }
                    }
                    out.push(e);
                    if out.len() >= 500 {
                        return Ok(out);
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }
        Ok(out)
    }

    /// Record edges observed outside a scan — `src` is the anchor
    /// (queried domain, scanned ip), `kind` e.g. `ct` for
    /// certificate-transparency results. Returns rows upserted.
    pub fn add_edges(&self, src: &str, kind: &str, dsts: &[String], now: u64) -> Result<usize> {
        let src_norm = src.trim_end_matches('.').to_lowercase();
        let tx = self.conn.unchecked_transaction()?;
        let mut n = 0;
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO edges (src, dst, kind, first_seen, last_seen)
                 VALUES (?,?,?,?,?)
                 ON CONFLICT(src, dst, kind) DO UPDATE SET
                  last_seen=excluded.last_seen",
            )?;
            for dst in dsts {
                let dst = dst.trim_end_matches('.').to_lowercase();
                if dst.is_empty() || dst == src_norm {
                    continue;
                }
                st.execute(rusqlite::params![src, dst, kind, now as i64, now as i64])?;
                n += 1;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    /// Edges where `node` is either endpoint.
    fn edges_touching(&self, node: &str) -> Result<Vec<Edge>> {
        let mut st = self.conn.prepare_cached(
            "SELECT e.src, e.dst, e.kind, e.last_seen,
                    EXISTS(SELECT 1 FROM services s
                           WHERE s.ip = e.dst OR s.hostname = e.dst)
             FROM edges e WHERE e.src = ? OR e.dst = ?
             ORDER BY e.kind, e.dst",
        )?;
        let rows = st.query_map(rusqlite::params![node, node], |r| {
            Ok(Edge {
                src: r.get(0)?,
                dst: r.get(1)?,
                kind: r.get(2)?,
                last_seen: r.get::<_, i64>(3)? as u64,
                indexed: r.get::<_, i64>(4)? != 0,
            })
        })?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(Into::into)
    }

    /// Port → number of distinct hosts it was open on, from the whole
    /// index. Feeds `--adaptive` ordering: scan ports history says are
    /// likely first.
    pub fn port_weights(&self) -> Result<std::collections::HashMap<u16, i64>> {
        let mut st = self
            .conn
            .prepare("SELECT port, COUNT(DISTINCT ip) FROM services GROUP BY port")?;
        let rows = st.query_map([], |r| {
            Ok((r.get::<_, u32>(0)? as u16, r.get::<_, i64>(1)?))
        })?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(Into::into)
    }

    /// Global weights plus a strong boost for ports previously seen
    /// open on `ips` themselves — rescanning a known host puts its
    /// own history first, not just the corpus's.
    pub fn port_weights_for(&self, ips: &[String]) -> Result<std::collections::HashMap<u16, i64>> {
        let mut w = self.port_weights()?;
        if ips.is_empty() {
            return Ok(w);
        }
        // Chunk below SQLITE_MAX_VARIABLE_NUMBER so large CIDRs (/16) never fail.
        for chunk in ips.chunks(500) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "SELECT port, COUNT(*) FROM services
                 WHERE ip IN ({placeholders}) GROUP BY port"
            );
            let mut st = self.conn.prepare(&sql)?;
            let rows = st.query_map(rusqlite::params_from_iter(chunk.iter()), |r| {
                Ok((r.get::<_, u32>(0)? as u16, r.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (port, n) = row?;
                *w.entry(port).or_default() += 10 * n;
            }
        }
        Ok(w)
    }

    pub fn stats(&self) -> Result<Stats> {
        let get = |sql: &str| {
            self.conn
                .query_row(sql, [], |r| r.get::<_, i64>(0))
                .map(|n| n as u64)
        };
        Ok(Stats {
            services: get("SELECT count(*) FROM services")?,
            hosts: get("SELECT count(DISTINCT ip) FROM services")?,
            scans: get("SELECT count(*) FROM scans")?,
        })
    }
}

/// Open the default DB and ingest — the call both frontends make after
/// every finished report. Errors are the caller's to soften to a note.
pub fn index_default(report: &ntok_core::ScanReport) -> Result<usize> {
    Store::open_default()?.ingest(report)
}

pub(crate) fn escape_like(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> ntok_core::ScanReport {
        serde_json::from_str(
            r#"{"scanner":"ntok","version":"0.1","args":"scan t","technique":"connect",
            "start_unix":1700000000,"end_unix":1700000005,"elapsed_secs":5.0,
            "hosts":[{"ip":"10.0.0.1","hostname":"web","state":"up","reason":"user-set",
                "ports":[{"port":443,"protocol":"tcp","state":"open","service":"https",
                          "banner":"nginx","reason":"conn-ack","rtt_ms":1.0}],
                "os_guess":"Linux",
                "findings":[{"tool":"nuclei","severity":"high","port":443,
                             "detail":"CVE-2021-41773 path traversal"},
                            {"tool":"nmap:ssl-cert","severity":"info","port":null,
                             "detail":"alt names enumerated"}],
                "web_profiles":[{
                  "url":"https://10.0.0.1:443","final_url":"https://login.corp.com/",
                  "status":200,"http_version":"HTTP/1.1","ttfb_ms":12,
                  "redirects":[{"status":301,"location":"https://login.corp.com/"}],
                  "server":"nginx",
                  "tls":{"protocol":"TLSv1.3","subject_cn":"web.corp.com",
                         "not_before":"x","not_after":"y",
                         "san":["web.corp.com","*.corp.com"],"expired":false,
                         "self_signed":false},
                  "external_domains":["cdn.example.com"],
                  "favicon_mmh3":-247388890}]
                }],
            "summary":{"hosts_up":1,"hosts_down":0,"open":1,"closed":0,"filtered":0,"unfiltered":0}}"#,
        )
        .unwrap()
    }

    /// A DB written before `email`/`full_name` existed opens cleanly and
    /// gets the new columns + unique index — the index DDL must run in
    /// `migrate`, not `AUTH_SCHEMA` (which executes before the ALTERs).
    #[test]
    fn migrate_adds_user_profile_columns() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                pass_hash TEXT NOT NULL,
                created_unix INTEGER NOT NULL
            );",
        )
        .unwrap();
        // Same order as Store::open: schema batches first, migrate after.
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute_batch(auth::AUTH_SCHEMA).unwrap();
        migrate(&conn).unwrap();
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(users)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        for col in [
            "email",
            "full_name",
            "totp_secret",
            "fail_count",
            "lock_until",
        ] {
            assert!(cols.iter().any(|c| c == col), "missing column {col}");
        }
        // duplicate emails (any case) rejected, NULL emails coexist
        conn.execute(
            "INSERT INTO users (name, email, pass_hash, created_unix) VALUES ('a','x@y','h',0)",
            [],
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT INTO users (name, email, pass_hash, created_unix) VALUES ('b','X@y','h',0)",
                [],
            )
            .is_err()
        );
        conn.execute(
            "INSERT INTO users (name, pass_hash, created_unix) VALUES ('c','h',0)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn ingest_then_search() {
        let store = Store {
            conn: Connection::open_in_memory().unwrap(),
        };
        store.conn.execute_batch(SCHEMA).unwrap();
        assert_eq!(store.ingest(&report()).unwrap(), 1);
        let hits = store.search("service:https", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].port, 443);
        assert_eq!(store.search("nginx", 10).unwrap().len(), 1); // FTS
        assert!(store.search("service:ssh", 10).unwrap().is_empty());
        assert_eq!(store.stats().unwrap().services, 1);
    }

    #[test]
    fn edges_and_weights() {
        let store = Store {
            conn: Connection::open_in_memory().unwrap(),
        };
        store.conn.execute_batch(SCHEMA).unwrap();
        store.ingest(&report()).unwrap();

        let edges = store.related("10.0.0.1", 1).unwrap();
        let kinds: std::collections::HashSet<_> = edges.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains("dns") && kinds.contains("san"));
        assert!(kinds.contains("redirect") && kinds.contains("asset"));
        assert!(edges.iter().any(|e| e.dst == "login.corp.com"));
        assert!(edges.iter().any(|e| e.dst == "*.corp.com"));
        // Reverse pivot: the SAN domain finds its way back to the host.
        assert_eq!(store.related("cdn.example.com", 1).unwrap().len(), 1);

        // favicon hash persisted + searchable
        let hits = store.search("favicon:-247388890", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].favicon_mmh3, Some(-247388890));

        // findings indexed: field match, severity word, has: flag, FTS
        let hits = store.search("finding:cve-2021-41773", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].findings.as_deref().unwrap().contains("high"));
        assert_eq!(store.search("sev:high", 10).unwrap().len(), 1);
        assert_eq!(store.search("has:findings", 10).unwrap().len(), 1);
        assert_eq!(store.search("traversal", 10).unwrap().len(), 1); // FTS
        assert!(store.search("sev:critical", 10).unwrap().is_empty());

        let w = store.port_weights().unwrap();
        assert_eq!(w.get(&443), Some(&1));
        // Same-target boost: 443 seen on 10.0.0.1 outweighs the corpus.
        let w = store.port_weights_for(&["10.0.0.1".into()]).unwrap();
        assert_eq!(w.get(&443), Some(&11));
        let w = store.port_weights_for(&["9.9.9.9".into()]).unwrap();
        assert_eq!(w.get(&443), Some(&1)); // unknown target → global only
    }

    #[test]
    fn related_walks_second_hop() {
        let store = Store {
            conn: Connection::open_in_memory().unwrap(),
        };
        store.conn.execute_batch(SCHEMA).unwrap();
        store.ingest(&report()).unwrap();
        // A second host whose cert shares the pivot's SAN domain — the
        // 2-hop walk from 10.0.0.2 reaches 10.0.0.1 through *.corp.com.
        let mut other = report();
        other.hosts[0].ip = "10.0.0.2".parse().unwrap();
        other.start_unix = 1700000200;
        other.end_unix = 1700000205;
        store.ingest(&other).unwrap();

        let one = store.related("10.0.0.2", 1).unwrap();
        assert!(
            !one.iter()
                .any(|e| e.src == "10.0.0.1" || e.dst == "10.0.0.1")
        );
        let two = store.related("10.0.0.2", 2).unwrap();
        assert!(two.iter().any(|e| e.src == "10.0.0.1"));
        assert!(two.len() > one.len());
    }

    #[test]
    fn upsert_preserves_first_seen() {
        let store = Store {
            conn: Connection::open_in_memory().unwrap(),
        };
        store.conn.execute_batch(SCHEMA).unwrap();
        store.ingest(&report()).unwrap();
        let mut later = report();
        later.start_unix = 1700000100;
        later.end_unix = 1700000105;
        later.hosts[0].ports[0].banner = Some("openresty".into());
        store.ingest(&later).unwrap();
        let hits = store.search("", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].first_seen, 1700000000);
        assert_eq!(hits[0].last_seen, 1700000105);
        assert_eq!(hits[0].banner.as_deref(), Some("openresty"));
    }
}
