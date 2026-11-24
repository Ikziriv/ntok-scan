//! Tool implementations — each is a thin call into the same
//! ntok-core/ntok-store entry points ntok-cli uses. They return JSON or
//! text; `server.rs` wraps them into `CallToolResult`.

use crate::Opts;
use ntok_core::model::PortState;
use ntok_core::target::{TargetSpec, parse_target};
use ntok_core::{diff, import, report, web};
use ntok_store::Store;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Byte cap on `report` output — full reports can be megabytes; agents
/// that need more detail use `search`.
const REPORT_CAP: usize = 256 * 1024;

fn store(opts: &Opts) -> Result<Store, String> {
    let path = opts.db.clone().unwrap_or_else(ntok_store::db_path);
    Store::open(&path).map_err(|e| format!("index open failed: {e}"))
}

fn index(opts: &Opts, rep: &ntok_core::ScanReport) -> Result<usize, String> {
    store(opts)?
        .ingest(rep)
        .map_err(|e| format!("index ingest failed: {e}"))
}

fn json<T: Serialize>(v: &T) -> Result<String, String> {
    serde_json::to_string(v).map_err(|e| e.to_string())
}

pub fn stats(opts: &Opts) -> Result<String, String> {
    json(&store(opts)?.stats().map_err(|e| e.to_string())?)
}

pub fn search(opts: &Opts, query: &str, limit: u32) -> Result<String, String> {
    let hits = store(opts)?
        .search(query, limit.clamp(1, 500))
        .map_err(|e| e.to_string())?;
    json(&hits)
}

pub fn graph(opts: &Opts, target: &str, depth: u8) -> Result<String, String> {
    let edges = store(opts)?
        .related(target, depth)
        .map_err(|e| e.to_string())?;
    json(&edges)
}

/// Resolve a report strictly inside `dir` — basename or scan id only,
/// preventing arbitrary filesystem reads over remote MCP.
fn resolve_report_path(dir: &Path, arg: &str) -> Result<PathBuf, String> {
    let arg = arg.trim();
    if arg.is_empty() || arg.contains(['/', '\\']) || arg.contains("..") {
        return Err(format!("report must be a scan id or basename, got {arg:?}"));
    }
    let base = dir
        .canonicalize()
        .map_err(|e| format!("reports dir {} unavailable: {e}", dir.display()))?;
    let stem = arg.strip_suffix(".json").unwrap_or(arg);
    for name in [format!("{stem}.json"), format!("scan-{stem}.json")] {
        if let Ok(p) = base.join(name).canonicalize()
            && p.starts_with(&base)
            && p.is_file()
        {
            return Ok(p);
        }
    }
    Err(format!("no report file for {arg:?} in {}", dir.display()))
}

pub fn report(opts: &Opts, id_or_path: &str) -> Result<String, String> {
    let p = resolve_report_path(&opts.reports_dir, id_or_path)?;
    let text =
        std::fs::read_to_string(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
    if text.len() > REPORT_CAP {
        Ok(format!(
            "{}\n… truncated at {REPORT_CAP} bytes — use the search tool for targeted queries, full file at {}",
            &text[..REPORT_CAP],
            p.display()
        ))
    } else {
        Ok(text)
    }
}

pub fn scans(opts: &Opts) -> Result<String, String> {
    #[derive(Serialize)]
    struct Entry {
        file: String,
        bytes: u64,
        modified_unix: u64,
    }
    let mut out = Vec::new();
    let rd = std::fs::read_dir(&opts.reports_dir)
        .map_err(|e| format!("{}: {e}", opts.reports_dir.display()))?;
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let m = e.metadata().map_err(|e| e.to_string())?;
        let modified = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        out.push(Entry {
            file: p.display().to_string(),
            bytes: m.len(),
            modified_unix: modified,
        });
    }
    out.sort_by_key(|e| std::cmp::Reverse(e.modified_unix));
    json(&out)
}

pub fn diff_reports(opts: &Opts, a: &str, b: &str) -> Result<String, String> {
    let pa = resolve_report_path(&opts.reports_dir, a)?;
    let pb = resolve_report_path(&opts.reports_dir, b)?;
    let ra = import::load_report(&pa).map_err(|e| format!("{}: {e}", pa.display()))?;
    let rb = import::load_report(&pb).map_err(|e| format!("{}: {e}", pb.display()))?;
    let d = diff::diff_reports(&ra, &rb);
    Ok(diff::to_text(&d, a, b))
}

/// Import an nmap `-oX` or ntok JSON report into the index — same as
/// `ntok import`.
pub fn import_report(opts: &Opts, path: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let rep = import::parse_report(&text).map_err(|e| format!("import failed: {e}"))?;
    let rows = index(opts, &rep)?;
    Ok(format!(
        "imported {path}: {} hosts ({} up), {} open ports in {:.2}s — {rows} index rows updated",
        rep.hosts.len(),
        rep.summary.hosts_up,
        rep.summary.open,
        rep.elapsed_secs
    ))
}

/// Single-site tech profile — same call path as `ntok lookup`.
pub async fn lookup(target: &str, crawl: usize) -> Result<String, String> {
    let spec = match parse_target(target) {
        Ok(TargetSpec::Host(h)) => {
            parse_target(&format!("https://{h}")).map_err(|e| e.to_string())?
        }
        Ok(other) => other,
        Err(e) => parse_target(&format!("https://{target}")).map_err(|_| e.to_string())?,
    };
    let expanded = ntok_core::target::expand(&[spec])
        .await
        .map_err(|e| e.to_string())?;
    let Some(u) = expanded.urls.first() else {
        return Err(format!("{target}: not a URL or resolvable hostname"));
    };
    let p = tokio::time::timeout(
        web::PROFILE_TIMEOUT,
        web::profile(
            u.ip,
            &u.target.origin,
            CancellationToken::new(),
            ntok_core::advisor::null_advisor(),
            crawl.min(8),
        ),
    )
    .await;
    let Ok(Some(p)) = p else {
        return Err(format!("{target}: no response (or timed out)"));
    };
    json(&p)
}

/// Passive subdomain enumeration via crt.sh — one outbound HTTPS call,
/// zero packets toward the target. Names index as `ct` edges.
pub async fn subs(opts: &Opts, domain: &str) -> Result<String, String> {
    let names = web::dns::ct_subdomains(domain).await;
    let indexed = store(opts)
        .and_then(|s| {
            s.add_edges(domain, "ct", &names, unix_now())
                .map_err(|e| e.to_string())
        })
        .unwrap_or(0);
    #[derive(Serialize)]
    struct Out {
        count: usize,
        indexed_edges: usize,
        names: Vec<String>,
    }
    json(&Out {
        count: names.len(),
        indexed_edges: indexed,
        names,
    })
}

/// Progress callback wired by server.rs when the client sends a
/// `progressToken` — (done, total, message).
pub type Progress = Arc<dyn Fn(f64, f64, String) + Send + Sync>;

/// `scan` tool arguments — mirrors the `ntok scan` flag set.
#[derive(Default)]
pub struct ScanParams {
    pub targets: Vec<String>,
    pub ports: Option<String>,
    pub timing: Option<u8>,
    pub technique: Option<String>,
    pub skip_discovery: bool,
    pub service: bool,
    pub webscan: bool,
    pub crawl: usize,
    pub adaptive: bool,
    pub tools: Vec<String>,
    pub verbose: bool,
    pub concurrency: Option<usize>,
    pub timeout_ms: Option<u64>,
    pub delay_ms: Option<u64>,
}

/// The gated write tool — runs a real scan through the engine, writes
/// `reports/scan-<id>.json`, and feeds the index. Scope-checked before
/// a single packet is built.
pub async fn scan(
    opts: &Opts,
    progress: Option<Progress>,
    p: ScanParams,
) -> Result<String, String> {
    if !opts.allow_scan {
        return Err("scan is disabled — the operator started ntok-mcp without --allow-scan".into());
    }
    if p.targets.is_empty() {
        return Err("no targets".into());
    }
    let specs: Vec<TargetSpec> = p
        .targets
        .iter()
        .map(|t| parse_target(t).map_err(|e| format!("target {t:?}: {e}")))
        .collect::<Result<_, _>>()?;
    opts.scope.check(&specs).await?;

    let mut cfg = ntok_core::ScanConfig::new(specs);
    if let Some(ps) = &p.ports {
        cfg.ports = ntok_core::ports::parse_ports(ps).map_err(|e| format!("ports {ps:?}: {e}"))?;
    }
    if let Some(t) = p.timing {
        cfg.timing = ntok_core::Timing::template(t).map_err(|e| e.to_string())?;
    }
    if let Some(t) = p.technique.as_deref() {
        cfg.technique = match t {
            "connect" | "tcp" => ntok_core::ScanTechnique::Connect,
            "syn" => ntok_core::ScanTechnique::Syn,
            "udp" => ntok_core::ScanTechnique::Udp,
            "ack" => ntok_core::ScanTechnique::Ack,
            "fin" => ntok_core::ScanTechnique::Fin,
            "null" => ntok_core::ScanTechnique::Null,
            "xmas" => ntok_core::ScanTechnique::Xmas,
            _ => {
                return Err(format!(
                    "unknown technique {t:?} (connect|syn|udp|ack|fin|null|xmas)"
                ));
            }
        };
    }
    if let Some(c) = p.concurrency {
        cfg.timing.concurrency = c.max(1);
    }
    if let Some(ms) = p.timeout_ms {
        cfg.timing.timeout = std::time::Duration::from_millis(ms);
    }
    if let Some(ms) = p.delay_ms {
        cfg.timing.probe_delay = (ms > 0).then(|| std::time::Duration::from_millis(ms));
    }
    for name in &p.tools {
        match ntok_core::ToolKind::parse(name) {
            Some(k) => cfg.tools.push(k),
            None => {
                return Err(format!(
                    "unknown tool {name:?} (nmap, nuclei, masscan, naabu, rustscan)"
                ));
            }
        }
    }
    cfg.skip_discovery = p.skip_discovery;
    cfg.service_probe = p.service;
    cfg.web_scan = p.webscan;
    cfg.web_crawl = p.crawl;
    cfg.verbose = p.verbose;
    cfg.args = format!(
        "mcp scan {} -p {}",
        p.targets.join(" "),
        p.ports.as_deref().unwrap_or("default")
    );

    // Index-informed port order — same as `ntok scan --adaptive`: ports
    // this target was previously seen running go first.
    if p.adaptive
        && let Ok(store) = store(opts)
    {
        let ips: Vec<String> = cfg
            .targets
            .iter()
            .filter_map(|t| match t {
                TargetSpec::Ip(ip) => Some(ip.to_string()),
                _ => None,
            })
            .take(256)
            .collect();
        if let Ok(w) = store.port_weights_for(&ips)
            && !w.is_empty()
        {
            cfg.ports
                .sort_by_key(|p| std::cmp::Reverse(w.get(p).copied().unwrap_or(0)));
        }
    }

    let (tx, mut rx) = tokio::sync::broadcast::channel::<ntok_core::ScanEvent>(256);
    let cancel = CancellationToken::new();

    // Drain events either way — and forward Progress to the client when
    // it asked for progress notifications.
    match progress {
        Some(cb) => {
            tokio::spawn(async move {
                while let Ok(ev) = rx.recv().await {
                    if let ntok_core::ScanEvent::Progress { done, total } = ev {
                        cb(done as f64, total as f64, String::new());
                    }
                }
            });
        }
        None => drop(rx),
    }

    let res = tokio::time::timeout(
        std::time::Duration::from_secs(opts.scan_timeout_secs),
        ntok_core::run_scan(cfg, tx, cancel.clone()),
    )
    .await;
    let rep = match res {
        Err(_) => {
            cancel.cancel();
            return Err(format!("scan timed out after {}s", opts.scan_timeout_secs));
        }
        Ok(Err(e)) => return Err(format!("scan failed: {e}")),
        Ok(Ok(r)) => r,
    };

    let id = next_scan_id(&opts.reports_dir);
    let path = opts.reports_dir.join(format!("scan-{id}.json"));
    report::write_json(&rep, &path).map_err(|e| format!("write {}: {e}", path.display()))?;
    // Index failure never fails the scan — matches CLI behaviour.
    let indexed = index(opts, &rep).is_ok();

    #[derive(Serialize)]
    struct HostOut {
        ip: String,
        hostname: Option<String>,
        open_ports: Vec<u16>,
    }
    #[derive(Serialize)]
    struct Out {
        scan_id: u64,
        report: String,
        indexed: bool,
        hosts_up: usize,
        open_ports: usize,
        elapsed_secs: f64,
        hosts: Vec<HostOut>,
    }
    json(&Out {
        scan_id: id,
        report: path.display().to_string(),
        indexed,
        hosts_up: rep.summary.hosts_up,
        open_ports: rep.summary.open,
        elapsed_secs: rep.elapsed_secs,
        hosts: rep
            .hosts
            .iter()
            .map(|h| HostOut {
                ip: h.ip.to_string(),
                hostname: h.hostname.clone(),
                open_ports: h
                    .ports
                    .iter()
                    .filter(|p| p.state == PortState::Open)
                    .map(|p| p.port)
                    .collect(),
            })
            .collect(),
    })
}

/// Next `scan-<id>.json` id — max existing id + 1, same scheme ntok-web
/// uses when it writes reports.
fn next_scan_id(dir: &Path) -> u64 {
    let mut max = 0u64;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Some(name) = e.file_name().to_str()
                && let Some(n) = name
                    .strip_prefix("scan-")
                    .and_then(|s| s.strip_suffix(".json"))
            {
                max = max.max(n.parse().unwrap_or(0));
            }
        }
    }
    max + 1
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
