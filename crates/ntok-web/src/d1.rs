//! Optional Cloudflare D1 mirror. Local SQLite in `reports/ntok.db`
//! stays the source of truth — when `NTOK_D1_ACCOUNT`, `NTOK_D1_DB` and
//! `NTOK_D1_TOKEN` are set, every finished report is also pushed to a
//! D1 database through the account REST API so scan history survives
//! this machine. Push failures are soft: recorded in `last`, never
//! fatal to the scan.
//!
//! Setup: `wrangler d1 create ntok`, then create an API token with
//! D1 read+write on the account and export the three env vars.

use ntok_core::ScanReport;
use std::sync::Mutex;

/// D1 tables are prefixed so the mirror can share a database with
/// other apps. Created idempotently on first push.
const DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS ntok_scans (
        start_unix INTEGER PRIMARY KEY,
        end_unix   INTEGER NOT NULL,
        args       TEXT NOT NULL,
        technique  TEXT NOT NULL,
        hosts_up   INTEGER NOT NULL,
        hosts_down INTEGER NOT NULL,
        open       INTEGER NOT NULL,
        synced_unix INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS ntok_services (
        scan_start INTEGER NOT NULL REFERENCES ntok_scans(start_unix),
        ip         TEXT NOT NULL,
        port       INTEGER NOT NULL,
        protocol   TEXT NOT NULL,
        service    TEXT,
        banner     TEXT,
        hostname   TEXT,
        PRIMARY KEY (scan_start, ip, port, protocol)
    )",
];

/// Rows per INSERT — D1's REST API caps bound parameters per call, so
/// service rows go up in chunks.
const CHUNK: usize = 40;

pub struct D1Sync {
    account: String,
    db: String,
    token: String,
    http: reqwest::Client,
    /// Last push outcome for the settings page — "ok 2026-…" or the error.
    pub last: Mutex<Option<String>>,
}

impl D1Sync {
    /// `None` unless all three env vars are present.
    pub fn from_env() -> Option<D1Sync> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Some(D1Sync {
            account: get("NTOK_D1_ACCOUNT")?,
            db: get("NTOK_D1_DB")?,
            token: get("NTOK_D1_TOKEN")?,
            http: reqwest::Client::new(),
            last: Mutex::new(None),
        })
    }

    /// Masked account id for the settings UI — last 4 chars only.
    pub fn label(&self) -> String {
        let tail: String = self.account.chars().rev().take(4).collect();
        format!("account …{}", tail.chars().rev().collect::<String>())
    }

    fn endpoint(&self) -> String {
        format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/d1/database/{}/query",
            self.account, self.db
        )
    }

    async fn exec(&self, sql: &str, params: &[serde_json::Value]) -> Result<(), String> {
        let resp = self
            .http
            .post(self.endpoint())
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "sql": sql, "params": params }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        if body["success"].as_bool() == Some(true) {
            return Ok(());
        }
        Err(body["errors"].to_string())
    }

    /// Push one finished report: the `scans` row plus one row per open
    /// service. Sequential calls — D1 REST runs one statement each, and
    /// sync volume (once per scan) doesn't warrant batching tricks.
    pub async fn push_scan(&self, rep: &ScanReport) {
        let out = self.push_inner(rep).await;
        let msg = match &out {
            Ok(()) => "pushed to D1".to_string(),
            Err(e) => format!("D1 push failed: {e}"),
        };
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg.clone());
        if let Err(e) = out {
            eprintln!("ntok-web: {e}");
        }
    }

    async fn push_inner(&self, rep: &ScanReport) -> Result<(), String> {
        for ddl in DDL {
            self.exec(ddl, &[]).await?;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.exec(
            "INSERT OR REPLACE INTO ntok_scans
             (start_unix, end_unix, args, technique, hosts_up, hosts_down, open, synced_unix)
             VALUES (?,?,?,?,?,?,?,?)",
            &[
                rep.start_unix.into(),
                rep.end_unix.into(),
                rep.args.clone().into(),
                rep.technique.clone().into(),
                rep.summary.hosts_up.into(),
                rep.summary.hosts_down.into(),
                rep.summary.open.into(),
                now.into(),
            ],
        )
        .await?;

        let rows: Vec<[serde_json::Value; 7]> = rep
            .hosts
            .iter()
            .flat_map(|h| {
                h.ports.iter().filter(|p| p.state.is_open()).map(|p| {
                    [
                        rep.start_unix.into(),
                        h.ip.to_string().into(),
                        (p.port as i64).into(),
                        p.protocol.as_str().into(),
                        p.service.clone().into(),
                        p.banner.clone().into(),
                        h.hostname.clone().into(),
                    ]
                })
            })
            .collect();
        for chunk in rows.chunks(CHUNK) {
            let ph = chunk
                .iter()
                .map(|_| "(?,?,?,?,?,?,?)")
                .collect::<Vec<_>>()
                .join(",");
            let params: Vec<serde_json::Value> = chunk.iter().flatten().cloned().collect();
            self.exec(
                &format!(
                    "INSERT OR REPLACE INTO ntok_services
                     (scan_start, ip, port, protocol, service, banner, hostname) VALUES {ph}"
                ),
                &params,
            )
            .await?;
        }
        Ok(())
    }
}
