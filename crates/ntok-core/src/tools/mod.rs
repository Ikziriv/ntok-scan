//! External scanning-tool wrappers — Kali-style binaries (nmap, nuclei,
//! masscan, naabu, rustscan) run as subprocesses and parsed back into
//! the report model.
//!
//! Tools never replace the engine: masscan/naabu/rustscan run as the
//! discovery stage, nmap and nuclei enrich the finished report. Every
//! tool degrades to a
//! `Note` event when its binary isn't installed, matching the advisor's
//! "scans never depend on X" rule.
//!
//! Invocation is prefix-configurable so the same code path runs tools on
//! native Linux/Kali (empty prefix) or inside WSL2 from a Windows host
//! (`wsl -d kali-linux --`). Set via `--tool-prefix`/`NTOK_TOOL_PREFIX`.

pub mod masscan;
pub mod naabu;
pub mod nmap;
pub mod nuclei;
pub mod rustscan;

use crate::engine::ScanConfig;
use crate::error::{Error, Result};
use crate::event::ScanEvent;
use crate::model::ScanReport;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::broadcast;

/// External tools that can bolt onto a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    /// Real nmap `-sV` + default-script enrichment over ntok's open ports.
    Nmap,
    /// nuclei template scan against open ports → severity findings.
    Nuclei,
    /// masscan as the discovery + open-port stage (replaces ntok discovery).
    Masscan,
    /// naabu (ProjectDiscovery) as the discovery + open-port stage.
    Naabu,
    /// RustScan as the discovery + open-port stage.
    Rustscan,
}

impl ToolKind {
    pub const ALL: [Self; 5] = [
        Self::Nmap,
        Self::Nuclei,
        Self::Masscan,
        Self::Naabu,
        Self::Rustscan,
    ];

    /// Discovery-stage tools: each returns open `(ip, port)` pairs and
    /// stands in for ntok's own discovery. Preference order when several
    /// are selected.
    pub const DISCOVERY: [Self; 3] = [Self::Masscan, Self::Naabu, Self::Rustscan];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nmap => "nmap",
            Self::Nuclei => "nuclei",
            Self::Masscan => "masscan",
            Self::Naabu => "naabu",
            Self::Rustscan => "rustscan",
        }
    }

    /// The binary name to spawn.
    pub fn prog(self) -> &'static str {
        self.as_str()
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "nmap" => Some(Self::Nmap),
            "nuclei" => Some(Self::Nuclei),
            "masscan" => Some(Self::Masscan),
            "naabu" => Some(Self::Naabu),
            "rustscan" => Some(Self::Rustscan),
            _ => None,
        }
    }
}

/// How to reach the tool binaries and how long to let them run.
#[derive(Debug, Clone)]
pub struct ToolConfig {
    /// Command prefix prepended to every tool invocation — e.g.
    /// `["wsl", "-d", "kali-linux", "--"]` to run inside WSL2.
    pub prefix: Vec<String>,
    /// Per-tool wall-clock cap; a killed tool just yields no findings.
    pub timeout: Duration,
}

impl Default for ToolConfig {
    fn default() -> Self {
        Self {
            prefix: Vec::new(),
            timeout: Duration::from_secs(300),
        }
    }
}

impl ToolConfig {
    /// Env config: `NTOK_TOOL_PREFIX` (e.g. `wsl -d kali-linux --`),
    /// `NTOK_TOOL_TIMEOUT_MS` (default 300000).
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(p) = std::env::var("NTOK_TOOL_PREFIX") {
            c.prefix = p.split_whitespace().map(str::to_string).collect();
        }
        if let Ok(ms) = std::env::var("NTOK_TOOL_TIMEOUT_MS")
            && let Ok(ms) = ms.parse::<u64>()
        {
            c.timeout = Duration::from_millis(ms).max(Duration::from_millis(1000));
        }
        c
    }

    /// Build the invocation: `prefix... prog`, piped, kill-on-drop so a
    /// timed-out tool can't outlive the scan.
    fn command(&self, prog: &str) -> Command {
        let mut cmd = match self.prefix.split_first() {
            Some((head, rest)) => {
                let mut c = Command::new(head);
                c.args(rest).arg(prog);
                c
            }
            None => Command::new(prog),
        };
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd
    }

    /// Spawn `prog args`, capture stdout, enforce the timeout.
    pub async fn run(&self, prog: &str, args: &[String]) -> Result<String> {
        let out = tokio::time::timeout(self.timeout, self.command(prog).args(args).output())
            .await
            .map_err(|_| Error::Tool(format!("{prog}: timed out after {:?}", self.timeout)))?
            .map_err(|e| Error::Tool(format!("{prog}: {e}")))?;
        if !out.status.success() {
            let err: String = String::from_utf8_lossy(&out.stderr)
                .trim()
                .chars()
                .take(300)
                .collect();
            return Err(Error::Tool(format!("{prog} failed: {err}")));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Is the binary reachable? (`--version` exits zero.)
    pub async fn available(&self, prog: &str) -> bool {
        let mut c = self.command(prog);
        c.arg("--version");
        tokio::time::timeout(Duration::from_secs(10), c.output())
            .await
            .map(|r| r.map(|o| o.status.success()).unwrap_or(false))
            .unwrap_or(false)
    }
}

/// Post-scan enrichment: run the requested enrichment tools over the
/// finished report. Missing binaries and tool failures degrade to notes.
pub async fn enrich(
    report: &mut ScanReport,
    kinds: &[ToolKind],
    tcfg: &ToolConfig,
    events: &broadcast::Sender<ScanEvent>,
) {
    if kinds.contains(&ToolKind::Nmap) {
        if tcfg.available(ToolKind::Nmap.prog()).await {
            nmap::enrich_all(report, tcfg, events).await;
        } else {
            note(events, "nmap: binary not found — skipped");
        }
    }
    if kinds.contains(&ToolKind::Nuclei) {
        if tcfg.available(ToolKind::Nuclei.prog()).await {
            nuclei::enrich_all(report, tcfg, events).await;
        } else {
            note(events, "nuclei: binary not found — skipped");
        }
    }
}

/// Discovery-stage tools (masscan, naabu, rustscan): the first selected
/// binary that's reachable runs and returns open `(ip, port)` pairs —
/// the engine then probes just those ports for service detection.
/// Returns `None` when no discovery tool is selected or all fail — the
/// caller falls back to ntok's own discovery either way.
pub async fn external_discovery(
    cfg: &ScanConfig,
    tcfg: &ToolConfig,
    events: &broadcast::Sender<ScanEvent>,
) -> Option<Vec<(std::net::IpAddr, u16)>> {
    let mut wanted = false;
    for kind in ToolKind::DISCOVERY {
        if !cfg.tools.contains(&kind) {
            continue;
        }
        wanted = true;
        if !tcfg.available(kind.prog()).await {
            note(
                events,
                format!("{}: binary not found — skipped", kind.as_str()),
            );
            continue;
        }
        let result = match kind {
            ToolKind::Masscan => masscan::scan(cfg, tcfg).await,
            ToolKind::Naabu => naabu::scan(cfg, tcfg).await,
            ToolKind::Rustscan => rustscan::scan(cfg, tcfg).await,
            _ => unreachable!("DISCOVERY only holds discovery tools"),
        };
        match result {
            Ok(found) => {
                let hosts = found
                    .iter()
                    .map(|(ip, _)| ip)
                    .collect::<std::collections::HashSet<_>>()
                    .len();
                note(
                    events,
                    format!(
                        "{}: {hosts} hosts up, {} open ports",
                        kind.as_str(),
                        found.len()
                    ),
                );
                return Some(found);
            }
            Err(e) => note(events, format!("{} failed: {e}", kind.as_str())),
        }
    }
    if wanted {
        note(events, "external discovery unavailable — ntok discovery");
    }
    None
}

pub fn note(events: &broadcast::Sender<ScanEvent>, text: impl Into<String>) {
    let _ = events.send(ScanEvent::Note { text: text.into() });
}
