mod ui;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use ntok_core::event::ScanEvent;
use ntok_core::ports;
use ntok_core::report::{self, ReportFormat};
use ntok_core::target::{TargetSpec, parse_target};
use ntok_core::{ScanConfig, ScanReport, ScanTechnique, Timing, run_scan};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use ui::{ColorChoice, Ui};

#[derive(Parser)]
#[command(
    name = "ntok",
    version,
    about = "NTOK SCAN — Network Threat Observation & Knowledge (Discover. Analyze. Secure.)"
)]
struct Cli {
    /// Color output: auto (TTY only), always, or never.
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,

    /// Suppress banner and live progress output.
    #[arg(short = 'q', long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan targets for open ports.
    Scan(ScanArgs),
    /// Import an nmap -oX XML or ntok JSON file: view it or convert to
    /// other formats.
    Import(ImportArgs),
    /// Diff two reports (ndiff-style): what hosts/ports/services changed
    /// between A and B. Args may be file paths, scan ids, or basenames
    /// under reports/.
    Diff(DiffArgs),
    /// Search the local index of every open service ntok has ever seen —
    /// Shodan-style `field:value` filters plus bare words for full-text
    /// over banners/certs/tech. Empty query lists the most recent.
    ///
    /// Examples:
    ///   ntok search 'service:nginx port:443'
    ///   ntok search 'net:10.0. has:tls expired:true'
    ///   ntok search 'apache "openssl 1.0"'
    Search(SearchArgs),
    /// Related infrastructure for an IP or domain — the "internet map"
    /// pivot: cert SANs, redirect targets, third-party asset hosts, and
    /// DNS names observed across all indexed scans. `*` marks
    /// destinations that are already in the index.
    Graph(GraphArgs),
    /// Passive subdomain discovery via certificate-transparency logs
    /// (crt.sh) — one outbound HTTPS call, zero packets toward the
    /// target. Found names index as `ct` edges so `ntok graph` and
    /// `--depth 2` walks can pivot through them.
    Subs(SubsArgs),
    /// Ask in plain language — the AI advisor translates the question
    /// into a `ntok search` query and runs it. Needs the same
    /// NTOK_AI_* config as the scan advisor.
    Ask(SearchArgs),
    /// Chat with the recon agent — it answers from tools over the local
    /// index, report summaries, diffs, and its own memory. Read-only:
    /// it can propose a scan but never run one. Needs the same
    /// NTOK_AI_* config as the scan advisor (a keyless Ollama endpoint
    /// works fully offline).
    Agent(AgentArgs),
    /// Re-run scans on a schedule — the "Shodan loop": a JSON watch file
    /// describes targets + interval; each run feeds the index and diffs
    /// against the previous run, printing drift as it happens.
    ///
    /// watch.json: {"targets":["10.0.0.0/24"],"ports":"top:100",
    ///              "every_secs":3600,"web":true,"name":"lab"}
    /// (or an array of such objects). Ctrl-C stops the loop.
    Watch(WatchArgs),
    /// Look up one site's technology profile — headers, TLS, company,
    /// Wappalyzer-style technologies, favicon hash — with no port scan.
    /// `https://` is assumed for bare hostnames.
    ///
    /// Examples:
    ///   ntok lookup wordpress.org
    ///   ntok lookup https://gitlab.example.com --crawl 6 --oJ site.json
    Lookup(LookupArgs),
}

/// Report outputs shared by `scan` and `import`.
#[derive(Args)]
struct OutArgs {
    /// Write JSON report.
    #[arg(long = "oJ", value_name = "FILE")]
    out_json: Option<PathBuf>,

    /// Write nmap-compatible XML report.
    #[arg(long = "oX", value_name = "FILE")]
    out_xml: Option<PathBuf>,

    /// Write nmap-style text report.
    #[arg(long = "oN", value_name = "FILE")]
    out_normal: Option<PathBuf>,

    /// Write nmap-style greppable report (-oG).
    #[arg(long = "oG", value_name = "FILE")]
    out_greppable: Option<PathBuf>,

    /// Write CSV report (one row per port result).
    #[arg(long = "oC", value_name = "FILE")]
    out_csv: Option<PathBuf>,

    /// Write self-contained HTML report.
    #[arg(long = "oH", value_name = "FILE")]
    out_html: Option<PathBuf>,

    /// Write every format as BASE.json/.xml/.nmap/.gnmap/.csv/.html.
    #[arg(long = "oA", value_name = "BASE")]
    out_all: Option<PathBuf>,
}

impl OutArgs {
    fn any(&self) -> bool {
        [
            &self.out_json,
            &self.out_xml,
            &self.out_normal,
            &self.out_greppable,
            &self.out_csv,
            &self.out_html,
            &self.out_all,
        ]
        .iter()
        .any(|o| o.is_some())
    }

    /// Emit every requested file. `label` prefixes the confirmation lines.
    fn write_all(&self, report: &ScanReport) -> Result<()> {
        let named: [(ReportFormat, &Option<PathBuf>); 6] = [
            (ReportFormat::Json, &self.out_json),
            (ReportFormat::NmapXml, &self.out_xml),
            (ReportFormat::Normal, &self.out_normal),
            (ReportFormat::Greppable, &self.out_greppable),
            (ReportFormat::Csv, &self.out_csv),
            (ReportFormat::Html, &self.out_html),
        ];
        for (fmt, path) in &named {
            if let Some(p) = path {
                fmt.write(report, p)?;
                eprintln!("{} report: {}", fmt.ext(), p.display());
            }
        }
        if let Some(base) = &self.out_all {
            for &fmt in ReportFormat::ALL {
                let p = base.with_extension(fmt.ext());
                fmt.write(report, &p)?;
                eprintln!("{} report: {}", fmt.ext(), p.display());
            }
        }
        Ok(())
    }
}

#[derive(Args)]
struct ScanArgs {
    /// Targets: IPs, CIDRs, ranges, hostnames (space or comma separated).
    /// e.g. 10.0.0.1 10.0.0.0/24 10.0.0.1-50 host.example
    #[arg(required = true)]
    targets: Vec<String>,

    /// Ports: list, range, `top:N`, or `all` (default: common ports).
    #[arg(short = 'p', long)]
    ports: Option<String>,

    /// Timing template T0 (paranoid) .. T5 (insane).
    #[arg(short = 'T', long = "timing", default_value_t = 3)]
    timing: u8,

    /// Raw SYN scan (requires `privileged` build feature + Npcap/root).
    #[arg(long)]
    syn: bool,

    /// Raw ACK scan — firewall-rule mapping (-sA). Requires `privileged`.
    #[arg(long)]
    ack: bool,

    /// Raw FIN scan (-sF). Requires `privileged`.
    #[arg(long)]
    fin: bool,

    /// Raw NULL scan (-sN). Requires `privileged`.
    #[arg(long)]
    null: bool,

    /// Raw Xmas scan (-sX). Requires `privileged`.
    #[arg(long)]
    xmas: bool,

    /// UDP scan.
    #[arg(long)]
    udp: bool,

    /// Skip host discovery: scan all targets (nmap -Pn).
    #[arg(long = "Pn", visible_alias = "skip-discovery")]
    skip_discovery: bool,

    /// Service/version detection via banners (nmap -sV).
    #[arg(long = "sV", visible_alias = "service")]
    service: bool,

    /// Show closed/filtered ports too (nmap -v).
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Website reconnaissance: after the port scan, profile every HTTP(S)
    /// endpoint — server headers, TLS certificate, company/ownership
    /// (RDAP + DNS), technologies and asset inventory. URL targets
    /// (`https://example.com`) are profiled regardless.
    #[arg(long = "web", visible_alias = "website")]
    web: bool,

    /// Same-origin pages to fetch per profiled site (0-8, default 0 =
    /// homepage only). Inner pages often carry tech the homepage
    /// doesn't. WhatWeb-style "thorough" mode.
    #[arg(long, value_name = "N")]
    crawl: Option<usize>,

    /// Report outputs (-oJ/-oX/-oN/-oG/-oC/-oH/-oA).
    #[command(flatten)]
    out: OutArgs,

    /// Override concurrency cap.
    #[arg(long)]
    concurrency: Option<usize>,

    /// Override per-probe timeout (ms).
    #[arg(long)]
    timeout_ms: Option<u64>,

    /// Min delay between probe starts (ms). 0 = unthrottled.
    #[arg(long)]
    delay_ms: Option<u64>,

    /// Order the port plan by index history — ports seen open on the
    /// most indexed hosts first. The plan is unchanged; only the order
    /// probes go out changes, so likely hits surface sooner. Repeat
    /// scans of a known environment benefit most.
    #[arg(long)]
    adaptive: bool,

    /// Consult an AI advisor to plan the scan and annotate the report.
    /// Env: NTOK_AI_KEY (required for the default backend), NTOK_AI_MODEL
    /// (default: deepseek-chat), NTOK_AI_ENDPOINT (default: DeepSeek API).
    #[arg(long)]
    ai: bool,

    /// External tools alongside the engine (comma-separated):
    /// `masscan`/`naabu`/`rustscan` replace discovery; `nmap` and
    /// `nuclei` enrich the report after the scan. Binaries must be
    /// installed/on PATH (or in WSL — see --tool-prefix).
    #[arg(long, value_delimiter = ',')]
    tools: Vec<String>,

    /// Prefix prepended to tool invocations — e.g. "wsl -d kali-linux --"
    /// to run Kali tools inside WSL2 (env NTOK_TOOL_PREFIX is fallback).
    #[arg(long, value_name = "PREFIX")]
    tool_prefix: Option<String>,
}

#[derive(Args)]
struct ImportArgs {
    /// Path to an nmap XML (-oX) or ntok JSON file. `-` reads stdin.
    file: PathBuf,

    /// Report outputs (-oJ/-oX/-oN/-oG/-oC/-oH/-oA). With none, prints
    /// the normal text report.
    #[command(flatten)]
    out: OutArgs,
}

#[derive(Args)]
struct SearchArgs {
    /// Query tokens: `field:value` filters and bare full-text terms.
    /// Fields: ip net port protocol state service product banner
    /// hostname os asn org server tech status has expired selfsigned
    /// after before.
    query: Vec<String>,

    /// Index database (default: `reports/ntok.db`, env `NTOK_DB`).
    #[arg(long)]
    db: Option<PathBuf>,

    /// Max results.
    #[arg(long, default_value_t = 100)]
    limit: u32,

    /// Write results as JSON.
    #[arg(long = "oJ", value_name = "FILE")]
    out_json: Option<PathBuf>,
}

#[derive(Args)]
struct AgentArgs {
    /// The question to answer.
    question: Vec<String>,

    /// Index database (default: `reports/ntok.db`, env `NTOK_DB`).
    #[arg(long)]
    db: Option<PathBuf>,
}

#[derive(Args)]
struct GraphArgs {
    /// IP or domain to pivot on.
    target: String,

    /// Hops to traverse — 1 shows only edges touching the target, 2+
    /// walks outward through discovered domains/hosts (max 3).
    #[arg(long, default_value_t = 1)]
    depth: u8,

    /// Index database (default: `reports/ntok.db`, env `NTOK_DB`).
    #[arg(long)]
    db: Option<PathBuf>,

    /// Write edges as JSON.
    #[arg(long = "oJ", value_name = "FILE")]
    out_json: Option<PathBuf>,

    /// Write discovered (non-wildcard) destinations as a scan-target
    /// file — graph findings feeding the next scan.
    #[arg(long = "oT", value_name = "FILE")]
    out_targets: Option<PathBuf>,
}

#[derive(Args)]
struct SubsArgs {
    /// Registered domain to enumerate (e.g. example.com).
    domain: String,

    /// Write results as a scan-target file (one name per line).
    #[arg(long = "oT", value_name = "FILE")]
    out_targets: Option<PathBuf>,

    /// Index database (default: `reports/ntok.db`, env `NTOK_DB`).
    #[arg(long)]
    db: Option<PathBuf>,
}

#[derive(Args)]
struct WatchArgs {
    /// JSON watch file: one spec object or an array of specs.
    file: PathBuf,

    /// Run every spec once and exit — for cron/systemd timers.
    #[arg(long)]
    once: bool,
}

/// One scheduled scan. Same grammar as `ntok scan` flags.
#[derive(serde::Deserialize)]
struct WatchSpec {
    /// Targets: IPs, CIDRs, ranges, hostnames.
    targets: Vec<String>,
    /// Seconds between runs (default 3600).
    #[serde(default = "default_every")]
    every_secs: u64,
    /// `-p` spec — engine's common ports when omitted.
    ports: Option<String>,
    /// Timing template 0..5.
    timing: Option<u8>,
    /// `-sV` service detection.
    service: Option<bool>,
    /// `--web` reconnaissance.
    web: Option<bool>,
    /// `--tools` comma list.
    tools: Option<String>,
    /// Report basename under `reports/` (default `watch-N`).
    name: Option<String>,
}

fn default_every() -> u64 {
    3600
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum WatchFile {
    One(Box<WatchSpec>),
    Many(Vec<WatchSpec>),
}

#[derive(Args)]
struct LookupArgs {
    /// URL or bare hostname (https assumed).
    target: String,

    /// Same-origin pages to crawl for deeper detection (0-8).
    #[arg(long, default_value_t = 4)]
    crawl: usize,

    /// AI commentary on the detected stack (NTOK_AI_* env).
    #[arg(long)]
    ai: bool,

    /// Write the profile as JSON.
    #[arg(long = "oJ", value_name = "FILE")]
    out_json: Option<PathBuf>,
}

#[derive(Args)]
struct DiffArgs {
    /// Older report: path, `reports/` basename, or scan id.
    a: String,
    /// Newer report: path, `reports/` basename, or scan id.
    b: String,

    /// Write the diff as JSON.
    #[arg(long = "oJ", value_name = "FILE")]
    out_json: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let cli = Cli::parse();
    let ui = Ui::new(cli.color, cli.quiet);

    match cli.cmd {
        Cmd::Scan(a) => scan(a, ui).await,
        Cmd::Import(a) => import(a, ui),
        Cmd::Diff(a) => diff(a, ui),
        Cmd::Search(a) => search(a, ui),
        Cmd::Graph(a) => graph(a, ui),
        Cmd::Subs(a) => subs(a, ui).await,
        Cmd::Ask(a) => ask(a, ui).await,
        Cmd::Agent(a) => agent(a, ui).await,
        Cmd::Watch(a) => watch(a, ui).await,
        Cmd::Lookup(a) => lookup(a, ui).await,
    }
}

async fn scan(a: ScanArgs, ui: Ui) -> Result<()> {
    ui.banner("scan");
    let targets: Vec<_> = a
        .targets
        .iter()
        .flat_map(|t| t.split(','))
        .map(parse_target)
        .collect::<std::result::Result<_, _>>()?;

    let mut ports = match &a.ports {
        Some(spec) => ports::parse_ports(spec)?,
        None => ports::default_ports(),
    };
    if a.adaptive
        && let Ok(store) = ntok_store::Store::open_default()
    {
        // Ports this target itself was seen running dominate; the
        // corpus average fills in behind them.
        let ips: Vec<String> = targets
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
            ports.sort_by_key(|p| std::cmp::Reverse(w.get(p).copied().unwrap_or(0)));
            eprintln!(
                "adaptive order: {} ports weighted by index history",
                w.len()
            );
        }
    }

    let mut timing = Timing::template(a.timing)?;
    if let Some(c) = a.concurrency {
        timing.concurrency = c.max(1);
    }
    if let Some(ms) = a.timeout_ms {
        timing.timeout = Duration::from_millis(ms);
    }
    if let Some(ms) = a.delay_ms {
        timing.probe_delay = (ms > 0).then(|| Duration::from_millis(ms));
    }

    let technique = if a.syn {
        ScanTechnique::Syn
    } else if a.ack {
        ScanTechnique::Ack
    } else if a.fin {
        ScanTechnique::Fin
    } else if a.null {
        ScanTechnique::Null
    } else if a.xmas {
        ScanTechnique::Xmas
    } else if a.udp {
        ScanTechnique::Udp
    } else {
        ScanTechnique::Connect
    };

    let mut cfg = ScanConfig::new(targets);
    cfg.ports = ports;
    cfg.technique = technique;
    cfg.timing = timing;
    cfg.skip_discovery = a.skip_discovery;
    cfg.service_probe = a.service;
    cfg.verbose = a.verbose;
    cfg.web_scan = a.web;
    cfg.web_crawl = a.crawl.unwrap_or(0).min(8);
    cfg.args = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    if a.ai {
        match ntok_core::HttpAdvisor::from_env() {
            Ok(adv) => cfg.advisor = std::sync::Arc::new(adv),
            Err(e) => eprintln!("AI advisor disabled: {e}"),
        }
    }
    for t in &a.tools {
        match ntok_core::ToolKind::parse(t) {
            Some(k) => cfg.tools.push(k),
            None => {
                anyhow::bail!("unknown tool '{t}' (valid: nmap, nuclei, masscan, naabu, rustscan)")
            }
        }
    }
    if let Some(p) = &a.tool_prefix {
        cfg.tool_prefix = p.split_whitespace().map(str::to_string).collect();
    }

    let (tx, rx) = broadcast::channel(4096);
    let cancel = CancellationToken::new();
    {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("\nCancelling...");
                cancel.cancel();
            }
        });
    }

    let printer = tokio::spawn(print_events(rx, a.verbose, ui));

    let report = run_scan(cfg, tx, cancel).await.context("scan failed");
    let _ = printer.await;
    let report = report?;
    index(&report);

    ui.print_summary(&report);

    a.out.write_all(&report)?;
    if !a.out.any() {
        ui.print_scan_report(&report);
    }
    Ok(())
}

fn import(a: ImportArgs, ui: Ui) -> Result<()> {
    ui.banner("import");
    let xml = if a.file.as_os_str() == Path::new("-") {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        buf
    } else {
        std::fs::read_to_string(&a.file)
            .with_context(|| format!("cannot read {}", a.file.display()))?
    };
    let report = ntok_core::import::parse_report(&xml)
        .map_err(|e| anyhow::anyhow!("{}", e))
        .context("import failed")?;
    index(&report);
    eprintln!(
        "imported {}: {} hosts ({} up), {} open in {:.2}s",
        a.file.display(),
        report.hosts.len(),
        report.summary.hosts_up,
        report.summary.open,
        report.elapsed_secs
    );
    a.out.write_all(&report)?;
    if !a.out.any() {
        ui.print_scan_report(&report);
    }
    Ok(())
}

/// Resolve a diff operand: a literal path if it exists, otherwise
/// `reports/<arg>.json` or `reports/scan-<arg>.json`.
fn resolve_report_path(arg: &str) -> Result<PathBuf> {
    let direct = PathBuf::from(arg);
    if direct.is_file() {
        return Ok(direct);
    }
    for name in [format!("{arg}.json"), format!("scan-{arg}.json")] {
        let p = PathBuf::from("reports").join(name);
        if p.is_file() {
            return Ok(p);
        }
    }
    anyhow::bail!("no report file for {arg:?} (tried path and reports/)")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn watch_path(spec: &WatchSpec, i: usize) -> PathBuf {
    let slug = spec.name.clone().unwrap_or_else(|| format!("watch-{i}"));
    let slug: String = slug
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    PathBuf::from("reports").join(format!("{slug}.json"))
}

/// One watch cycle: scan → diff against the previous report for this
/// spec → persist + index. Same shape as `scan()` minus output flags.
async fn watch_once(
    spec: &WatchSpec,
    path: &Path,
    cancel: &CancellationToken,
    ui: Ui,
) -> Result<()> {
    let targets: Vec<_> = spec
        .targets
        .iter()
        .flat_map(|t| t.split(','))
        .map(parse_target)
        .collect::<std::result::Result<_, _>>()?;
    let ports = match &spec.ports {
        Some(s) if !s.trim().is_empty() => ports::parse_ports(s)?,
        _ => ports::default_ports(),
    };
    let mut cfg = ScanConfig::new(targets);
    cfg.ports = ports;
    cfg.timing = Timing::template(spec.timing.unwrap_or(3))?;
    cfg.service_probe = spec.service.unwrap_or(true);
    cfg.web_scan = spec.web.unwrap_or(false);
    cfg.verbose = false; // a daemon streams open/responded ports, not noise
    cfg.args = format!("watch: {}", spec.targets.join(" "));
    if let Some(tools) = &spec.tools {
        for t in tools.split(',') {
            match ntok_core::ToolKind::parse(t) {
                Some(k) => cfg.tools.push(k),
                None => anyhow::bail!("watch: unknown tool '{t}'"),
            }
        }
    }

    let (tx, rx) = broadcast::channel(4096);
    let printer = tokio::spawn(print_events(rx, false, ui));
    let rep = run_scan(cfg, tx, cancel.clone())
        .await
        .context("watch scan failed");
    let _ = printer.await;
    let rep = rep?;

    // Drift alert: diff the previous cycle's report if one exists.
    if let Ok(prev) = ntok_core::import::load_report(path) {
        let d = ntok_core::diff::diff_reports(&prev, &rep);
        if !(d.hosts_added.is_empty() && d.hosts_removed.is_empty() && d.hosts_changed.is_empty()) {
            ui.print_diff(&d, "previous", "now");
        }
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    report::write_json(&rep, path)?;
    index(&rep);
    Ok(())
}

async fn watch(a: WatchArgs, ui: Ui) -> Result<()> {
    ui.banner("watch");
    let text = std::fs::read_to_string(&a.file)
        .with_context(|| format!("cannot read {}", a.file.display()))?;
    let specs: Vec<WatchSpec> = match serde_json::from_str::<WatchFile>(&text)
        .with_context(|| format!("invalid watch file {}", a.file.display()))?
    {
        WatchFile::One(s) => vec![*s],
        WatchFile::Many(v) => v,
    };
    anyhow::ensure!(!specs.is_empty(), "watch file has no specs");

    let paths: Vec<PathBuf> = specs
        .iter()
        .enumerate()
        .map(|(i, s)| watch_path(s, i))
        .collect();
    if a.once {
        for (s, p) in specs.iter().zip(&paths) {
            watch_once(s, p, &CancellationToken::new(), ui).await?;
        }
        return Ok(());
    }

    let cancel = CancellationToken::new();
    {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("\nCancelling...");
                cancel.cancel();
            }
        });
    }

    eprintln!(
        "watching {} spec(s) — reports under reports/, index at {}",
        specs.len(),
        ntok_store::db_path().display()
    );
    let mut next_at = vec![0u64; specs.len()]; // all due immediately
    loop {
        let now = unix_now();
        let mut wake = u64::MAX;
        for (i, (s, p)) in specs.iter().zip(&paths).enumerate() {
            if now >= next_at[i] {
                eprintln!("[{}] watch {} running", now, p.display());
                if let Err(e) = watch_once(s, p, &cancel, ui).await {
                    eprintln!("watch {}: {e}", p.display());
                }
                next_at[i] = unix_now() + s.every_secs;
            }
            wake = wake.min(next_at[i]);
        }
        let wait = wake.saturating_sub(unix_now()).min(60);
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
        }
        if cancel.is_cancelled() {
            break;
        }
    }
    Ok(())
}

/// Feed the local index (reports/ntok.db). A store failure never fails
/// the scan — same rule as external tools.
fn index(report: &ScanReport) {
    match ntok_store::index_default(report) {
        Ok(0) => {}
        Ok(n) => eprintln!("indexed {n} services → {}", ntok_store::db_path().display()),
        Err(e) => eprintln!("index: {e}"),
    }
}

fn search(a: SearchArgs, ui: Ui) -> Result<()> {
    ui.banner("search");
    let db = a.db.unwrap_or_else(ntok_store::db_path);
    let store = ntok_store::Store::open(&db)?;
    let q = a.query.join(" ");
    run_search(&store, &q, a.limit, a.out_json.as_deref(), ui)
}

/// Plain-language → DSL via the scan advisor's endpoint, then the same
/// search. Translation failure points the user at explicit fields.
async fn ask(a: SearchArgs, ui: Ui) -> Result<()> {
    ui.banner("ask");
    let question = a.query.join(" ");
    let adv = ntok_core::HttpAdvisor::from_env().map_err(|e| {
        anyhow::anyhow!("AI advisor unavailable: {e} — set NTOK_AI_* or use `ntok search`")
    })?;
    let q = adv.translate_query(&question).await.ok_or_else(|| {
        anyhow::anyhow!("AI endpoint returned nothing — try `ntok search` with explicit fields")
    })?;
    eprintln!("→ {q}");
    let db = a.db.unwrap_or_else(ntok_store::db_path);
    let store = ntok_store::Store::open(&db)?;
    run_search(&store, &q, a.limit, a.out_json.as_deref(), ui)
}

/// Tool-calling agent over the index: same endpoint as `ask`, but the
/// model drives ntok-store tools itself. Degrades like `ask` when the
/// endpoint is unreachable; a missing index just means empty tools.
async fn agent(a: AgentArgs, ui: Ui) -> Result<()> {
    ui.banner("agent");
    let question = a.question.join(" ");
    if question.trim().is_empty() {
        anyhow::bail!("usage: ntok agent \"what changed on the lab net?\"");
    }
    let backend = ntok_core::agent::HttpChat::from_env().map_err(|e| {
        anyhow::anyhow!(
            "AI unavailable: {e} — set NTOK_AI_* (a keyless Ollama endpoint works offline)"
        )
    })?;
    let db = a.db.unwrap_or_else(ntok_store::db_path);
    let store = std::sync::Arc::new(std::sync::Mutex::new(ntok_store::Store::open(&db)?));
    let mut tools = ntok_core::agent::builtin_tools();
    tools.extend(ntok_store::agent::agent_tools(store.clone()));
    let lessons = store
        .lock()
        .ok()
        .and_then(|s| s.memory_lessons(0.7, 6).ok())
        .unwrap_or_default();
    let agent = ntok_core::agent::Agent::new(Box::new(backend), tools).lessons(lessons);
    let ans = agent.ask(&question).await?;
    println!("{}", ans.text);
    if !ui.quiet && !ans.trace.is_empty() {
        let names: Vec<&str> = ans.trace.iter().map(|t| t.name.as_str()).collect();
        eprintln!("tools used: {}", names.join(", "));
    }
    Ok(())
}

fn graph(a: GraphArgs, ui: Ui) -> Result<()> {
    ui.banner("graph");
    let db = a.db.unwrap_or_else(ntok_store::db_path);
    let store = ntok_store::Store::open(&db)?;
    let edges = store.related(&a.target, a.depth)?;
    if let Some(p) = &a.out_json {
        std::fs::write(p, serde_json::to_string_pretty(&edges)?)?;
        eprintln!("JSON edges: {}", p.display());
    }
    if edges.is_empty() {
        eprintln!("no known relationships for {}", a.target);
        return Ok(());
    }
    ui.print_graph(&a.target, &edges);
    if !ui.quiet {
        eprintln!("{} edges (* = also in the index)", edges.len());
    }
    if let Some(p) = &a.out_targets {
        let targets: Vec<&str> = {
            let mut v: Vec<_> = edges
                .iter()
                .map(|e| e.dst.as_str())
                .filter(|d| !d.starts_with("*."))
                .collect();
            v.sort();
            v.dedup();
            v
        };
        std::fs::write(p, targets.join("\n") + "\n")?;
        eprintln!("{} scan targets: {}", targets.len(), p.display());
    }
    Ok(())
}

/// crt.sh CT-log enumeration → `ct` edges + optional target file. The
/// outbound call is to crt.sh only; the target sees nothing.
async fn subs(a: SubsArgs, ui: Ui) -> Result<()> {
    ui.banner("subs");
    let names = ntok_core::web::dns::ct_subdomains(&a.domain).await;
    if names.is_empty() {
        eprintln!("no CT names for {}", a.domain);
        return Ok(());
    }
    for n in &names {
        println!("{n}");
    }
    eprintln!("{} names", names.len());
    let db = a.db.unwrap_or_else(ntok_store::db_path);
    if let Ok(store) = ntok_store::Store::open(&db) {
        let domain = a.domain.trim_end_matches('.').to_lowercase();
        match store.add_edges(&domain, "ct", &names, unix_now()) {
            Ok(n) => eprintln!("indexed {n} ct edges → {}", db.display()),
            Err(e) => eprintln!("index: {e}"),
        }
    }
    if let Some(p) = &a.out_targets {
        std::fs::write(p, names.join("\n") + "\n")?;
        eprintln!("targets: {}", p.display());
    }
    Ok(())
}

fn run_search(
    store: &ntok_store::Store,
    q: &str,
    limit: u32,
    out_json: Option<&Path>,
    ui: Ui,
) -> Result<()> {
    let hits = store.search(q, limit)?;
    if let Some(p) = out_json {
        std::fs::write(p, serde_json::to_string_pretty(&hits)?)?;
        eprintln!("JSON results: {}", p.display());
    }
    ui.print_search(&hits);
    Ok(())
}

/// Single-site technology lookup — Wappalyzer-parity UX: URL in,
/// profile out, no port scan. Bare hostnames get `https://`.
async fn lookup(a: LookupArgs, ui: Ui) -> Result<()> {
    ui.banner("lookup");
    let spec = match parse_target(&a.target) {
        Ok(TargetSpec::Host(h)) => parse_target(&format!("https://{h}"))?,
        Ok(other) => other,
        Err(e) => {
            // e.g. `example.com:8443` — try as an https origin.
            parse_target(&format!("https://{}", a.target)).map_err(|_| e)?
        }
    };
    let expanded = ntok_core::target::expand(&[spec]).await?;
    let Some(u) = expanded.urls.first() else {
        anyhow::bail!("{}: not a URL or resolvable hostname", a.target)
    };

    let advisor: std::sync::Arc<dyn ntok_core::advisor::ScanAdvisor> = if a.ai {
        match ntok_core::HttpAdvisor::from_env() {
            Ok(adv) => std::sync::Arc::new(adv),
            Err(e) => {
                eprintln!("AI advisor disabled: {e}");
                ntok_core::advisor::null_advisor()
            }
        }
    } else {
        ntok_core::advisor::null_advisor()
    };

    // Same 30s cap as `ntok scan` applies per endpoint — a lookup
    // shouldn't outlive it just because it skipped the port scan.
    let p = tokio::time::timeout(
        ntok_core::web::PROFILE_TIMEOUT,
        ntok_core::web::profile(
            u.ip,
            &u.target.origin,
            CancellationToken::new(),
            advisor,
            a.crawl.min(8),
        ),
    )
    .await;
    let Ok(Some(p)) = p else {
        anyhow::bail!("{}: no response (or timed out)", u.target.origin)
    };

    if let Some(ref path) = a.out_json {
        std::fs::write(path, serde_json::to_string_pretty(&p)?)?;
        eprintln!("json profile: {}", path.display());
    }

    ui.print_lookup(&p);
    Ok(())
}

fn diff(a: DiffArgs, ui: Ui) -> Result<()> {
    ui.banner("diff");
    let pa = resolve_report_path(&a.a)?;
    let pb = resolve_report_path(&a.b)?;
    let ra = ntok_core::import::load_report(&pa)
        .with_context(|| format!("cannot load {}", pa.display()))?;
    let rb = ntok_core::import::load_report(&pb)
        .with_context(|| format!("cannot load {}", pb.display()))?;
    let d = ntok_core::diff::diff_reports(&ra, &rb);
    if let Some(ref p) = a.out_json {
        std::fs::write(p, serde_json::to_string_pretty(&d)?)?;
        eprintln!("JSON diff: {}", p.display());
    }
    ui.print_diff(&d, &a.a, &a.b);
    Ok(())
}

async fn print_events(mut rx: broadcast::Receiver<ScanEvent>, verbose: bool, ui: Ui) {
    let started = Instant::now();
    let mut open_seen = 0usize;
    loop {
        match rx.recv().await {
            Ok(ScanEvent::Started {
                hosts,
                ports,
                technique,
            }) => {
                if !ui.quiet {
                    eprintln!(
                        "Starting {} {technique} scan: {hosts} hosts × {ports} ports",
                        ntok_core::brand::NAME
                    );
                }
            }
            Ok(ScanEvent::HostDiscovered { ip, up }) if verbose && !up => {
                ui.clear_progress();
                eprintln!("Host {ip} appears down");
            }
            Ok(ScanEvent::PortFound {
                ip,
                port,
                protocol,
                state,
                service,
            }) => {
                if state.is_open() {
                    open_seen += 1;
                }
                ui.print_discovered(
                    state,
                    port,
                    protocol.as_str(),
                    &ip.to_string(),
                    service.as_deref(),
                );
            }
            Ok(ScanEvent::Note { text }) => {
                ui.clear_progress();
                if !ui.quiet {
                    eprintln!("{text}");
                }
            }
            Ok(ScanEvent::Progress { done, total }) => {
                ui.progress(done, total, open_seen, started.elapsed().as_secs_f64());
            }
            Ok(ScanEvent::Finished { .. }) | Err(broadcast::error::RecvError::Closed) => {
                ui.clear_progress();
                break;
            }
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
        }
    }
}
