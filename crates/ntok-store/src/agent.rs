//! Agent-facing surface of the store: the `agent_memory` table plus the
//! [`AgentTool`] implementations the recon agent calls to answer
//! operator questions from local scan data.
//!
//! Memory model mirrors ECC's vault: entries are *unreviewed context*,
//! never executable policy. `kind = "lesson"` entries double as learned
//! instincts — [`Store::memory_lessons`] recalls the high-confidence ones
//! for injection into the agent's system prompt.

use ntok_core::agent::{AgentTool, BoxFuture};
use rusqlite::Connection;
use serde::Serialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const AGENT_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS agent_memory (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT NOT NULL,
    title        TEXT NOT NULL,
    body         TEXT NOT NULL,
    confidence   REAL NOT NULL DEFAULT 0.5,
    created_unix INTEGER NOT NULL,
    updated_unix INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_memory_kind ON agent_memory(kind);
";

/// One `agent_memory` row.
#[derive(Debug, Clone, Serialize)]
pub struct Memory {
    pub id: i64,
    /// fact | lesson | note | handoff | runbook
    pub kind: String,
    pub title: String,
    pub body: String,
    pub confidence: f64,
    pub created_unix: u64,
    pub updated_unix: u64,
}

/// One row of `scans` for the `recent_scans` tool.
#[derive(Debug, Clone, Serialize)]
pub struct ScanRow {
    pub id: i64,
    pub args: String,
    pub technique: String,
    pub hosts_up: i64,
    pub hosts_down: i64,
    pub open: i64,
}

const KINDS: [&str; 5] = ["fact", "lesson", "note", "handoff", "runbook"];

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Memory + recall methods on the store (wired in `lib.rs` to keep this
/// impl next to the schema it depends on).
pub(crate) fn memory_save(
    conn: &Connection,
    kind: &str,
    title: &str,
    body: &str,
    confidence: f64,
) -> crate::Result<i64> {
    if !KINDS.contains(&kind) {
        return Err(crate::Error::InvalidInput(format!(
            "kind must be one of {KINDS:?}"
        )));
    }
    if title.trim().is_empty() || body.trim().is_empty() {
        return Err(crate::Error::InvalidInput(
            "title and body are required".into(),
        ));
    }
    let now = unix_now() as i64;
    conn.execute(
        "INSERT INTO agent_memory (kind, title, body, confidence, created_unix, updated_unix)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        rusqlite::params![kind, title, body, confidence.clamp(0.0, 1.0), now],
    )?;
    Ok(conn.last_insert_rowid())
}

pub(crate) fn memory_search(
    conn: &Connection,
    query: &str,
    limit: u32,
) -> crate::Result<Vec<Memory>> {
    let like = format!("%{}%", query.replace(['%', '_'], ""));
    let mut st = conn.prepare(
        "SELECT id, kind, title, body, confidence, created_unix, updated_unix
         FROM agent_memory
         WHERE title LIKE ?1 OR body LIKE ?1 OR kind LIKE ?1
         ORDER BY updated_unix DESC LIMIT ?2",
    )?;
    let rows = st
        .query_map(rusqlite::params![like, limit.min(100)], |r| {
            Ok(Memory {
                id: r.get(0)?,
                kind: r.get(1)?,
                title: r.get(2)?,
                body: r.get(3)?,
                confidence: r.get(4)?,
                created_unix: r.get::<_, i64>(5)? as u64,
                updated_unix: r.get::<_, i64>(6)? as u64,
            })
        })?
        .collect::<std::result::Result<_, _>>()?;
    Ok(rows)
}

/// Instinct recall: high-confidence lessons for system-prompt injection.
pub(crate) fn memory_lessons(
    conn: &Connection,
    min_confidence: f64,
    limit: u32,
) -> crate::Result<Vec<String>> {
    let mut st = conn.prepare(
        "SELECT title, body FROM agent_memory
         WHERE kind = 'lesson' AND confidence >= ?1
         ORDER BY confidence DESC, updated_unix DESC LIMIT ?2",
    )?;
    let rows = st
        .query_map(rusqlite::params![min_confidence, limit.min(20)], |r| {
            let title: String = r.get(0)?;
            let body: String = r.get(1)?;
            Ok(format!("{title} — {body}"))
        })?
        .collect::<std::result::Result<_, _>>()?;
    Ok(rows)
}

pub(crate) fn recent_scans(conn: &Connection, limit: u32) -> crate::Result<Vec<ScanRow>> {
    let mut st = conn.prepare(
        "SELECT start_unix, args, technique, hosts_up, hosts_down, open
         FROM scans ORDER BY start_unix DESC LIMIT ?1",
    )?;
    let rows = st
        .query_map([limit.min(100)], |r| {
            Ok(ScanRow {
                id: r.get(0)?,
                args: r.get(1)?,
                technique: r.get(2)?,
                hosts_up: r.get(3)?,
                hosts_down: r.get(4)?,
                open: r.get(5)?,
            })
        })?
        .collect::<std::result::Result<_, _>>()?;
    Ok(rows)
}

// ------------------------------------------------------------------
// Tools
// ------------------------------------------------------------------

/// `reports/` lives next to the index DB (`reports/ntok.db`).
fn reports_dir() -> PathBuf {
    crate::db_path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("reports"))
}

/// Resolve a report strictly inside `reports/` — basename or scan id only,
/// never arbitrary filesystem paths (the LLM receives untrusted scan banners).
fn resolve_report(arg: &str) -> std::result::Result<PathBuf, String> {
    let arg = arg.trim();
    if arg.is_empty() || arg.contains(['/', '\\']) || arg.contains("..") {
        return Err(format!("report must be a scan id or basename, got {arg:?}"));
    }
    let base = reports_dir()
        .canonicalize()
        .map_err(|e| format!("reports dir unavailable: {e}"))?;
    let stem = arg.strip_suffix(".json").unwrap_or(arg);
    for name in [format!("{stem}.json"), format!("scan-{stem}.json")] {
        if let Ok(p) = base.join(name).canonicalize()
            && p.starts_with(&base)
            && p.is_file()
        {
            return Ok(p);
        }
    }
    Err(format!("no report file for {arg:?} in reports/"))
}

fn load_report(arg: &str) -> std::result::Result<ntok_core::ScanReport, String> {
    let path = resolve_report(arg)?;
    ntok_core::import::load_report(&path).map_err(|e| format!("load {arg:?}: {e}"))
}

/// Store-backed tools for the recon agent. `reports_dir` is where
/// `scan-*.json` reports live — callers pass `reports/` (or the resolved
/// data dir); memory/search hit `store`.
pub fn agent_tools(store: Arc<Mutex<crate::Store>>) -> Vec<Arc<dyn AgentTool>> {
    vec![
        Arc::new(SearchIndex(store.clone())),
        Arc::new(RecentScans(store.clone())),
        Arc::new(ScanSummary),
        Arc::new(DiffScans),
        Arc::new(MemorySave(store.clone())),
        Arc::new(MemorySearch(store)),
    ]
}

struct SearchIndex(Arc<Mutex<crate::Store>>);

impl AgentTool for SearchIndex {
    fn name(&self) -> &'static str {
        "search_index"
    }
    fn description(&self) -> &'static str {
        "Full-text + fielded search over every service ntok has ever seen. Fields: ip: net: port: service: product: banner: hostname: os: asn: org: server: tech: risk: has: expired: selfsigned: state:"
    }
    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20}
            },
            "required": ["query"]
        })
    }
    fn call<'a>(&'a self, args: Value) -> BoxFuture<'a, std::result::Result<Value, String>> {
        let store = self.0.clone();
        Box::pin(async move {
            let q = args["query"].as_str().unwrap_or_default();
            let limit = (args["limit"].as_u64().unwrap_or(20).clamp(1, 50)) as u32;
            let s = store.lock().unwrap_or_else(|e| e.into_inner());
            let hits = s.search(q, limit).map_err(|e| e.to_string())?;
            Ok(
                json!({ "count": hits.len(), "hits": hits.iter().map(|h| json!({
                "ip": h.ip, "port": h.port, "protocol": h.protocol,
                "state": h.state, "service": h.service, "hostname": h.hostname,
                "server": h.server, "os": h.os, "org": h.org,
                "risk": h.risk, "tech": h.tech, "url": h.url,
            })).collect::<Vec<_>>() }),
            )
        })
    }
}

struct RecentScans(Arc<Mutex<crate::Store>>);

impl AgentTool for RecentScans {
    fn name(&self) -> &'static str {
        "recent_scans"
    }
    fn description(&self) -> &'static str {
        "List the most recent scans (id, args, technique, hosts up, open ports)"
    }
    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}
            }
        })
    }
    fn call<'a>(&'a self, args: Value) -> BoxFuture<'a, std::result::Result<Value, String>> {
        let store = self.0.clone();
        Box::pin(async move {
            let limit = (args["limit"].as_u64().unwrap_or(10).clamp(1, 50)) as u32;
            let s = store.lock().unwrap_or_else(|e| e.into_inner());
            let rows = s.recent_scans(limit).map_err(|e| e.to_string())?;
            serde_json::to_value(rows).map_err(|e| e.to_string())
        })
    }
}

struct ScanSummary;

impl AgentTool for ScanSummary {
    fn name(&self) -> &'static str {
        "scan_summary"
    }
    fn description(&self) -> &'static str {
        "Compact summary of one stored report — takes a scan id, reports/ basename, or path"
    }
    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "scan": {"type": "string", "description": "scan id, reports/ basename, or path"}
            },
            "required": ["scan"]
        })
    }
    fn call<'a>(&'a self, args: Value) -> BoxFuture<'a, std::result::Result<Value, String>> {
        Box::pin(async move {
            let scan = args["scan"].as_str().unwrap_or_default();
            let r = load_report(scan)?;
            let findings: Vec<Value> = r
                .hosts
                .iter()
                .filter_map(|h| {
                    let open: Vec<Value> = h
                        .ports
                        .iter()
                        .filter(|p| p.state.is_open())
                        .map(|p| {
                            json!({"port": p.port, "proto": p.protocol.as_str(),
                                   "service": p.service})
                        })
                        .collect();
                    (!open.is_empty()).then(|| json!({"ip": h.ip, "open": open}))
                })
                .take(40)
                .collect();
            Ok(json!({
                "hosts_up": r.summary.hosts_up,
                "hosts_down": r.summary.hosts_down,
                "open": r.summary.open,
                "elapsed_secs": r.elapsed_secs,
                "findings": findings,
            }))
        })
    }
}

struct DiffScans;

impl AgentTool for DiffScans {
    fn name(&self) -> &'static str {
        "diff_scans"
    }
    fn description(&self) -> &'static str {
        "Diff two stored reports (ndiff-style) — what hosts/ports/services changed between A and B"
    }
    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "a": {"type": "string", "description": "older scan id/basename/path"},
                "b": {"type": "string", "description": "newer scan id/basename/path"}
            },
            "required": ["a", "b"]
        })
    }
    fn call<'a>(&'a self, args: Value) -> BoxFuture<'a, std::result::Result<Value, String>> {
        Box::pin(async move {
            let a = load_report(args["a"].as_str().unwrap_or_default())?;
            let b = load_report(args["b"].as_str().unwrap_or_default())?;
            let d = ntok_core::diff::diff_reports(&a, &b);
            Ok(json!({
                "hosts_added": d.hosts_added.len(),
                "hosts_removed": d.hosts_removed.len(),
                "hosts_changed": d.hosts_changed.len(),
                "hosts_unchanged": d.hosts_unchanged,
                "text": ntok_core::diff::to_text(&d, "A", "B"),
            }))
        })
    }
}

struct MemorySave(Arc<Mutex<crate::Store>>);

impl AgentTool for MemorySave {
    fn name(&self) -> &'static str {
        "memory_save"
    }
    fn description(&self) -> &'static str {
        "Save a durable fact/lesson/note for future sessions. kind: fact|lesson|note|handoff|runbook. Use kind=lesson for learned preferences (0.0-1.0 confidence) — they are recalled on later runs"
    }
    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": KINDS, "default": "fact"},
                "title": {"type": "string"},
                "body": {"type": "string"},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1, "default": 0.5}
            },
            "required": ["title", "body"]
        })
    }
    fn call<'a>(&'a self, args: Value) -> BoxFuture<'a, std::result::Result<Value, String>> {
        let store = self.0.clone();
        Box::pin(async move {
            let s = store.lock().unwrap_or_else(|e| e.into_inner());
            // Cap agent-authored confidence below the 0.7 prompt-recall
            // threshold so untrusted scan banners can't inject persistent
            // instructions into future system prompts.
            let conf = args["confidence"].as_f64().unwrap_or(0.5).clamp(0.0, 0.6);
            let id = s
                .memory_save(
                    args["kind"].as_str().unwrap_or("fact"),
                    args["title"].as_str().unwrap_or_default(),
                    args["body"].as_str().unwrap_or_default(),
                    conf,
                )
                .map_err(|e| e.to_string())?;
            Ok(json!({"saved": id}))
        })
    }
}

struct MemorySearch(Arc<Mutex<crate::Store>>);

impl AgentTool for MemorySearch {
    fn name(&self) -> &'static str {
        "memory_search"
    }
    fn description(&self) -> &'static str {
        "Recall saved memories/lessons by keyword — check before answering questions about prior work or preferences"
    }
    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}
            },
            "required": ["query"]
        })
    }
    fn call<'a>(&'a self, args: Value) -> BoxFuture<'a, std::result::Result<Value, String>> {
        let store = self.0.clone();
        Box::pin(async move {
            let q = args["query"].as_str().unwrap_or_default();
            let limit = (args["limit"].as_u64().unwrap_or(10).clamp(1, 50)) as u32;
            let s = store.lock().unwrap_or_else(|e| e.into_inner());
            let rows = s.memory_search(q, limit).map_err(|e| e.to_string())?;
            serde_json::to_value(rows).map_err(|e| e.to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> crate::Store {
        crate::Store::open(&PathBuf::from(":memory:")).unwrap()
    }

    #[test]
    fn memory_round_trip_and_lesson_recall() {
        let s = store();
        let id = s
            .memory_save("fact", "lab net", "10.0.0.0/24 is the lab", 0.9)
            .unwrap();
        s.memory_save(
            "lesson",
            "prefer top:100",
            "operator picks top:100 over full sweeps",
            0.8,
        )
        .unwrap();
        s.memory_save("lesson", "low conf", "not recalled", 0.3)
            .unwrap();
        assert!(id > 0);
        assert_eq!(s.memory_search("lab", 10).unwrap().len(), 1);
        let lessons = s.memory_lessons(0.7, 10).unwrap();
        assert_eq!(lessons.len(), 1);
        assert!(lessons[0].contains("prefer top:100"));
    }

    #[test]
    fn memory_rejects_bad_input() {
        let s = store();
        assert!(s.memory_save("bogus", "t", "b", 0.5).is_err());
        assert!(s.memory_save("fact", "", "b", 0.5).is_err());
    }
}
