//! Report writers: JSON (canonical), nmap-style text, greppable and
//! nmap-compatible XML so existing tooling (e.g. metasploit imports,
//! searchsploit pipelines) can ingest ntok output — plus CSV and a
//! self-contained HTML report for handing results to humans.

use crate::error::Result;
use crate::model::{HostState, ScanReport};
use std::fmt::Write as _;
use std::path::Path;

/// Output format for a [`ScanReport`]. `Json` is the canonical stored form;
/// the rest are renders of the same data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    /// nmap `-oX`-compatible XML.
    NmapXml,
    /// nmap `-oN`-flavoured text.
    Normal,
    /// nmap `-oG`-flavoured greppable output.
    Greppable,
    /// One row per port result — spreadsheet/BI ingest.
    Csv,
    /// Self-contained styled page — the human deliverable.
    Html,
}

impl ReportFormat {
    /// Every format, in the order offered to users.
    pub const ALL: &'static [ReportFormat] = &[
        Self::Json,
        Self::NmapXml,
        Self::Normal,
        Self::Greppable,
        Self::Csv,
        Self::Html,
    ];

    /// `json`, `xml`, `normal`, `greppable`, `csv`, `html` — plus a few
    /// nmap-flavoured aliases. Returns `None` on anything else.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "json" => Self::Json,
            "xml" | "nmapxml" => Self::NmapXml,
            "normal" | "txt" | "nmap" | "text" => Self::Normal,
            "greppable" | "gnmap" => Self::Greppable,
            "csv" => Self::Csv,
            "html" => Self::Html,
            _ => return None,
        })
    }

    /// File extension (nmap conventions where they exist).
    pub fn ext(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::NmapXml => "xml",
            Self::Normal => "nmap",
            Self::Greppable => "gnmap",
            Self::Csv => "csv",
            Self::Html => "html",
        }
    }

    pub fn mime(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::NmapXml => "application/xml",
            Self::Normal | Self::Greppable => "text/plain; charset=utf-8",
            Self::Csv => "text/csv; charset=utf-8",
            Self::Html => "text/html; charset=utf-8",
        }
    }

    pub fn render(self, report: &ScanReport) -> Result<String> {
        Ok(match self {
            Self::Json => to_json(report)?,
            Self::NmapXml => to_xml(report),
            Self::Normal => to_normal(report),
            Self::Greppable => to_greppable(report),
            Self::Csv => to_csv(report),
            Self::Html => to_html(report),
        })
    }

    pub fn write(self, report: &ScanReport, path: &Path) -> Result<()> {
        std::fs::write(path, self.render(report)?)?;
        Ok(())
    }
}

pub fn to_json(report: &ScanReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

pub fn write_json(report: &ScanReport, path: &Path) -> Result<()> {
    ReportFormat::Json.write(report, path)
}

pub fn write_normal(report: &ScanReport, path: &Path) -> Result<()> {
    ReportFormat::Normal.write(report, path)
}

/// nmap `-oN`-flavoured plain text.
pub fn to_normal(report: &ScanReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# ntok {} scan initiated {} as: {}",
        report.version, report.start_unix, report.args
    );
    for host in &report.hosts {
        let name = host
            .hostname
            .as_deref()
            .map(|n| format!(" ({n})"))
            .unwrap_or_default();
        let _ = writeln!(out, "Ntok scan report for {}{}", host.ip, name);
        let _ = writeln!(
            out,
            "Host is {} ({}).",
            if host.state == HostState::Up {
                "up"
            } else {
                "down"
            },
            host.reason
        );
        if !host.ports.is_empty() {
            let _ = writeln!(out, "PORT\tSTATE\tSERVICE");
            for p in &host.ports {
                let _ = writeln!(
                    out,
                    "{}/{}\t{}\t{}",
                    p.port,
                    p.protocol.as_str(),
                    p.state.as_str(),
                    p.service.as_deref().unwrap_or("unknown")
                );
            }
        }
        if !host.findings.is_empty() {
            let _ = writeln!(out, "TOOL\tSEVERITY\tPORT\tFINDING");
            for f in &host.findings {
                let _ = writeln!(
                    out,
                    "{}\t{}\t{}\t{}",
                    f.tool,
                    f.severity,
                    f.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                    f.detail
                );
            }
        }
        for w in &host.web_profiles {
            let mut line = format!("WEB {} ({} {})", w.url, w.status, w.http_version);
            if let Some(s) = &w.server {
                let _ = write!(line, " server={s}");
            }
            if let Some(t) = &w.tls {
                let _ = write!(
                    line,
                    " tls={}{}",
                    t.protocol,
                    t.subject_cn
                        .as_deref()
                        .map(|c| format!(" {c}"))
                        .unwrap_or_default()
                );
            }
            if !w.company.names.is_empty() {
                let _ = write!(line, " org={}", w.company.names.join("/"));
            }
            if !w.technologies.is_empty() {
                let _ = write!(
                    line,
                    " tech={}",
                    w.technologies
                        .iter()
                        .map(|t| {
                            t.version
                                .as_deref()
                                .map(|v| format!("{}/v{}", t.name, v))
                                .unwrap_or_else(|| t.name.clone())
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            if !w.assets.is_empty() {
                let _ = write!(line, " assets={}", w.assets.len());
            }
            if let Some(e) = &w.error {
                let _ = write!(line, " error={e}");
            }
            let _ = writeln!(out, "{line}");
        }
        out.push('\n');
    }
    let _ = writeln!(
        out,
        "# Ntok done at {} -- {} hosts ({} up, {} down) scanned in {:.2} seconds",
        report.end_unix,
        report.summary.hosts_up + report.summary.hosts_down,
        report.summary.hosts_up,
        report.summary.hosts_down,
        report.elapsed_secs
    );
    out
}

/// nmap `-oX`-compatible XML.
pub fn to_xml(report: &ScanReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    let _ = writeln!(
        out,
        "<nmaprun scanner=\"ntok\" args=\"{}\" start=\"{}\" version=\"{}\" xmloutputversion=\"1.05\">",
        esc(&report.args),
        report.start_unix,
        esc(&report.version)
    );
    let _ = writeln!(
        out,
        "  <scaninfo type=\"{}\" numservices=\"{}\"/>",
        esc(&report.technique),
        report.hosts.iter().map(|h| h.ports.len()).sum::<usize>()
    );
    for host in &report.hosts {
        let _ = writeln!(
            out,
            "  <host><status state=\"{}\" reason=\"{}\"/>",
            if host.state == HostState::Up {
                "up"
            } else {
                "down"
            },
            esc(&host.reason)
        );
        let v = if host.ip.is_ipv4() { "ipv4" } else { "ipv6" };
        let _ = writeln!(
            out,
            "    <address addr=\"{}\" addrtype=\"{}\"/>",
            host.ip, v
        );
        if let Some(name) = &host.hostname {
            let _ = writeln!(
                out,
                "    <hostnames><hostname name=\"{}\"/></hostnames>",
                esc(name)
            );
        }
        if !host.ports.is_empty() {
            let _ = writeln!(out, "    <ports>");
            for p in &host.ports {
                let _ = writeln!(
                    out,
                    "      <port protocol=\"{}\" portid=\"{}\"><state state=\"{}\" reason=\"{}\"/>",
                    p.protocol.as_str(),
                    p.port,
                    p.state.as_str(),
                    esc(&p.reason)
                );
                if let Some(s) = &p.service {
                    // banner = nmap's product+version+extrainfo joined —
                    // `product` carries it back through the importer.
                    match &p.banner {
                        Some(b) => {
                            let _ = writeln!(
                                out,
                                "        <service name=\"{}\" product=\"{}\"/>",
                                esc(s),
                                esc(b)
                            );
                        }
                        None => {
                            let _ = writeln!(out, "        <service name=\"{}\"/>", esc(s));
                        }
                    }
                } else if let Some(b) = &p.banner {
                    let _ = writeln!(out, "        <service product=\"{}\"/>", esc(b));
                }
                for f in host.findings.iter().filter(|f| f.port == Some(p.port)) {
                    let _ = writeln!(out, "        {}", script_el(f));
                }
                let _ = writeln!(out, "      </port>");
            }
            let _ = writeln!(out, "    </ports>");
        }
        let host_findings: Vec<_> = host.findings.iter().filter(|f| f.port.is_none()).collect();
        if !host_findings.is_empty() || !host.web_profiles.is_empty() {
            let _ = writeln!(out, "    <hostscript>");
            for f in host_findings {
                let _ = writeln!(out, "      {}", script_el(f));
            }
            // Web intel rides as ntok:web script output — stays inside
            // nmap's schema and survives import as a Finding.
            for w in &host.web_profiles {
                let techs = w
                    .technologies
                    .iter()
                    .map(|t| t.name.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                let _ = writeln!(
                    out,
                    "      <script id=\"ntok:web\" output=\"{}\"/>",
                    esc(&format!(
                        "{} | {} | {} | tech={} | assets={} | org={}",
                        w.url,
                        w.status,
                        w.server.as_deref().unwrap_or("-"),
                        techs,
                        w.assets.len(),
                        w.company.names.join("/")
                    ))
                );
            }
            let _ = writeln!(out, "    </hostscript>");
        }
        let _ = writeln!(out, "  </host>");
    }
    let _ = writeln!(
        out,
        "  <runstats><finished time=\"{}\" elapsed=\"{:.2}\"/><hosts up=\"{}\" down=\"{}\" total=\"{}\"/></runstats>",
        report.end_unix,
        report.elapsed_secs,
        report.summary.hosts_up,
        report.summary.hosts_down,
        report.summary.hosts_up + report.summary.hosts_down
    );
    let _ = writeln!(out, "</nmaprun>");
    out
}

/// A finding as nmap's `<script>` element — `id` keeps the tool name
/// (`nmap:` prefix stripped back out), `output` the detail, with the
/// severity prefixed so it survives the text-only channel.
fn script_el(f: &crate::model::Finding) -> String {
    let id = f.tool.strip_prefix("nmap:").unwrap_or(&f.tool);
    let output = if f.severity == "info" {
        esc(&f.detail)
    } else {
        esc(&format!("[{}] {}", f.severity, f.detail))
    };
    format!("<script id=\"{}\" output=\"{}\"/>", esc(id), output)
}

pub fn write_xml(report: &ScanReport, path: &Path) -> Result<()> {
    ReportFormat::NmapXml.write(report, path)
}

/// nmap `-oG`-flavoured greppable output: one `Host:` line per host with
/// every probed port in the `Ports:` field.
pub fn to_greppable(report: &ScanReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# ntok {} scan initiated {} as: {}",
        report.version, report.start_unix, report.args
    );
    for host in &report.hosts {
        let name = host.hostname.as_deref().unwrap_or_default();
        let _ = write!(out, "Host: {} ({name})\t", host.ip);
        if host.ports.is_empty() {
            let _ = writeln!(
                out,
                "Status: {}",
                if host.state == HostState::Up {
                    "Up"
                } else {
                    "Down"
                }
            );
            continue;
        }
        let ports: Vec<String> = host
            .ports
            .iter()
            .map(|p| {
                format!(
                    "{}/{}/{}/{}/{}/{}/{}/",
                    p.port,
                    p.state.as_str(),
                    p.protocol.as_str(),
                    "",
                    p.service.as_deref().unwrap_or_default(),
                    "",
                    ""
                )
            })
            .collect();
        let _ = writeln!(out, "Ports: {}", ports.join(", "));
    }
    let _ = writeln!(
        out,
        "# Ntok done at {} -- {} IP addresses ({} hosts up) scanned in {:.2} seconds",
        report.end_unix,
        report.summary.hosts_up + report.summary.hosts_down,
        report.summary.hosts_up,
        report.elapsed_secs
    );
    out
}

/// One row per port result; hosts that answered no probes keep a single
/// portless row so they aren't lost in the spreadsheet.
pub fn to_csv(report: &ScanReport) -> String {
    let mut out = String::from(
        "host,hostname,host_state,host_reason,os_guess,port,protocol,state,service,reason,rtt_ms,finding_tool,finding_severity,finding_port,finding_detail\n",
    );
    for host in &report.hosts {
        let head = format!(
            "{},{},{},{},{}",
            csv_cell(&host.ip.to_string()),
            csv_cell(host.hostname.as_deref().unwrap_or_default()),
            if host.state == HostState::Up {
                "up"
            } else {
                "down"
            },
            csv_cell(&host.reason),
            csv_cell(host.os_guess.as_deref().unwrap_or_default()),
        );
        if host.ports.is_empty() {
            let _ = writeln!(out, "{head},,,,,,,,,,");
        }
        for p in &host.ports {
            let rtt = p.rtt_ms.map(|r| format!("{r:.2}")).unwrap_or_default();
            let _ = writeln!(
                out,
                "{head},{},{},{},{},{},{},,,,",
                p.port,
                p.protocol.as_str(),
                p.state.as_str(),
                csv_cell(p.service.as_deref().unwrap_or_default()),
                csv_cell(&p.reason),
                rtt,
            );
        }
        // Findings get their own rows — port columns stay empty so
        // filtering on finding_tool is enough to pivot them out.
        for f in &host.findings {
            let _ = writeln!(
                out,
                "{head},,,,,,{},{},{},{}",
                csv_cell(&f.tool),
                csv_cell(&f.severity),
                f.port.map(|p| p.to_string()).unwrap_or_default(),
                csv_cell(&f.detail),
            );
        }
        // Web profiles ride the findings columns as `ntok:web` rows —
        // keeps the schema unchanged.
        for w in &host.web_profiles {
            let techs = w
                .technologies
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let _ = writeln!(
                out,
                "{head},,,,,,{},{},{},{}",
                csv_cell("ntok:web"),
                csv_cell(&w.status.to_string()),
                csv_cell(&w.url),
                csv_cell(&format!(
                    "{} | {} | tech={} | assets={}",
                    w.status,
                    w.server.as_deref().unwrap_or("-"),
                    techs,
                    w.assets.len(),
                )),
            );
        }
    }
    out
}

fn csv_cell(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn fmt_utc(unix: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix as i64)
        .ok()
        .map(|dt| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                dt.year(),
                dt.month() as u8,
                dt.day(),
                dt.hour(),
                dt.minute(),
                dt.second()
            )
        })
        .unwrap_or_else(|| unix.to_string())
}

/// Self-contained HTML report — unified DESIGN.md v8 visual system with
/// light/dark support, port-map grid, security-header chips, and print styles.
pub fn to_html(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NTOK SCAN — Scan Report</title>
"#,
    );
    let _ = writeln!(
        out,
        "<link rel=\"icon\" href=\"{}\">",
        crate::brand::MARK_DATA_URI
    );
    out.push_str(r#"<style>
:root{
  color-scheme:light;
  --bg:#F3F6FA;--surface:#FFFFFF;--ceramic:#E8EEF6;--field:#F7F9FC;--well:#EDF2F8;
  --line:#DCE4F0;--line-soft:#E8EEF6;--ink:#0C1424;--fg:#1E293B;
  --muted:#5E6E85;--faint:#8B99AE;
  --obs:#0B1220;--obs-line:rgba(148,179,219,.16);--obs-fg:#DCE8F8;--obs-muted:#7E95B6;
  --accent:#2B62B8;--accent-deep:#1B417C;--accent-sky:#45C4EC;--accent-soft:#E4EFFB;--on-accent:#FFFFFF;
  --warn:#9A6E10;--warn-bg:#FCF1D6;--warn-line:#EED8A1;
  --err:#B93838;--err-bg:#FDEAEA;--err-line:#F5C2C2;
  --ok:#1F8A5B;--ok-bg:#E4F6EE;--ok-line:#B9E6D2;
  --mono:ui-monospace,"IBM Plex Mono","Cascadia Mono",SFMono-Regular,Menlo,monospace;
  --sans:"Work Sans",-apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",system-ui,sans-serif;
  --display:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",system-ui,sans-serif;
}
@media (prefers-color-scheme:dark){
  :root{
    color-scheme:dark;
    --bg:#060A12;--surface:#0D1524;--ceramic:#131F35;--field:#0A101C;--well:#111C2F;
    --line:#1C2B45;--line-soft:#152136;--ink:#F0F6FF;--fg:#C8D7EC;
    --muted:#7E95B5;--faint:#4E6484;
    --obs:#080E1A;--obs-line:rgba(69,196,236,.18);
    --accent:#45C4EC;--accent-deep:#2A89C4;--accent-soft:rgba(69,196,236,.13);--on-accent:#04131C;
    --warn:#E5BE5E;--warn-bg:#261E0A;--warn-line:#493914;
    --err:#F28482;--err-bg:#2B1315;--err-line:#522427;
    --ok:#4ADE9B;--ok-bg:#0D261C;--ok-line:#1F523D;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:400 14px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
.accent-bar{height:3px;background:linear-gradient(90deg,#193153,#2B62B8,#45C4EC)}
main{max-width:1120px;margin:0 auto;padding:34px 24px 72px}
.head{display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;
  background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:22px 26px}
.brand{display:flex;align-items:center;gap:14px}
.logo{width:46px;height:46px;border-radius:999px;background:var(--obs);display:grid;place-items:center;padding:9px;flex:none}
.logo svg{width:100%;height:auto;display:block}
h1{font:800 28px/1.05 var(--display);letter-spacing:-0.04em;margin:0;color:var(--ink)}
.brand-sub{font:600 10.5px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--accent);margin-top:4px}
.brand-exp{font:400 12px var(--sans);color:var(--muted);margin-top:2px}
.meta{text-align:right;font:500 11.5px/1.6 var(--mono);color:var(--muted)}
.cmd{font:500 12px var(--mono);color:var(--fg);background:var(--surface);
  border:1px solid var(--line);border-radius:999px;padding:8px 16px;margin-top:16px;display:inline-block;
  overflow-wrap:anywhere}
.cmd::before{content:"$ ";color:var(--accent);font-weight:700}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin:22px 0}
.stat{background:var(--ceramic);border:1px solid var(--line-soft);border-radius:14px;padding:18px 20px}
.stat.acc{background:var(--obs);border-color:var(--obs-line)}
.stat.acc .v{color:var(--accent-sky)}
.stat.acc .k{color:var(--obs-muted)}
.stat .v{font:700 28px/1 var(--display);letter-spacing:-0.035em;font-variant-numeric:tabular-nums;color:var(--ink)}
.stat.warn .v{color:var(--warn)}
.stat .k{font-size:12px;color:var(--muted);margin-top:6px}
.host-card{background:var(--surface);border:1px solid var(--line);border-radius:16px;
  padding:22px 24px;margin-top:20px;break-inside:avoid}
.host-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
  padding-bottom:12px;border-bottom:1px solid var(--line-soft);margin-bottom:14px}
.host-ip{font:700 15px var(--mono);color:var(--ink)}
.host-meta{font:500 11.5px var(--mono);color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(54px,1fr));gap:6px;margin:12px 0 18px;
  background-color:var(--obs);background-image:linear-gradient(rgba(69,196,236,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(69,196,236,.05) 1px,transparent 1px);
  background-size:24px 24px;padding:16px;border-radius:14px;border:1px solid var(--obs-line)}
.cell{height:30px;display:flex;align-items:center;justify-content:center;
  font:500 11px var(--mono);font-variant-numeric:tabular-nums;
  border:1px solid rgba(148,179,219,.14);border-radius:8px;background:rgba(255,255,255,.04);color:#5F7494}
.cell.open{background:var(--accent-sky);border-color:var(--accent-sky);color:#04151F;font-weight:700}
.cell.filtered{background:rgba(229,190,94,.16);border-color:rgba(229,190,94,.36);color:#F0CB6B}
.tbl-wrap{overflow-x:auto;margin-top:10px}
table{width:100%;border-collapse:collapse}
th{font:500 11px var(--sans);color:var(--muted);text-align:left;padding:8px 10px;
  border-bottom:1px solid var(--line);letter-spacing:.04em}
td{padding:8px 10px;border-bottom:1px solid var(--line-soft);font:400 12px var(--mono);
  font-variant-numeric:tabular-nums;color:var(--fg)}
tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right}
.pill{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:999px;
  border:1px solid var(--line);background:var(--field);font:500 10.5px var(--mono);color:var(--muted)}
.pill.open{color:var(--on-accent);background:var(--accent);border-color:var(--accent)}
.pill.ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-line)}
.pill.warn{color:var(--warn);background:var(--warn-bg);border-color:var(--warn-line)}
.pill.err{color:var(--err);background:var(--err-bg);border-color:var(--err-line)}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
.chip{display:inline-flex;align-items:baseline;gap:5px;padding:3px 9px;border-radius:999px;
  border:1px solid var(--line);background:var(--field);font:400 11px var(--mono);color:var(--fg)}
.chip b{color:var(--ink);font-weight:600}
.sec-sub{font:600 11px var(--sans);letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:16px 0 8px}
.muted{color:var(--muted)}
footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--line);
  display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px;
  font:400 11px var(--mono);color:var(--faint)}
@media print{
  body{background:#fff;color:#111}
  .accent-bar{display:none}
  .host-card{box-shadow:none;border-color:#ddd}
  .cell.open,.pill.open{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
</style></head><body><div class="accent-bar"></div><main>
"#);
    let _ = writeln!(
        out,
        "<header class=\"head\"><div class=\"brand\"><span class=\"logo\">{}</span><div>\
         <h1>{}</h1>\
         <div class=\"brand-sub\">{}</div>\
         <div class=\"brand-exp\">{}</div></div></div>\
         <div class=\"meta\"><div>technique: {}</div><div>started: {}</div><div>duration: {:.2}s</div></div></header>",
        crate::brand::MARK_SVG,
        crate::brand::NAME,
        crate::brand::SUBTITLE,
        crate::brand::EXPANSION,
        esc(&report.technique),
        fmt_utc(report.start_unix),
        report.elapsed_secs
    );
    let _ = writeln!(out, "<span class=\"cmd\">ntok {}</span>", esc(&report.args));
    let s = &report.summary;
    let _ = writeln!(
        out,
        "<div class=\"stats\">\
           <div class=\"stat\"><div class=\"v\">{}</div><div class=\"k\">hosts up</div></div>\
           <div class=\"stat acc\"><div class=\"v\">{}</div><div class=\"k\">open ports</div></div>\
           <div class=\"stat\"><div class=\"v\">{}</div><div class=\"k\">closed</div></div>\
           <div class=\"stat warn\"><div class=\"v\">{}</div><div class=\"k\">filtered</div></div>\
         </div>",
        s.hosts_up, s.open, s.closed, s.filtered
    );
    for host in &report.hosts {
        let state_pill = if host.state == HostState::Up {
            "<span class=\"pill ok\">up</span>"
        } else {
            "<span class=\"pill\">down</span>"
        };
        let mut extra = esc(&host.reason);
        if let Some(os) = &host.os_guess {
            let _ = write!(extra, " · {}", esc(os));
        }
        let host_label = match &host.hostname {
            Some(n) => format!(
                "{} <span class=\"muted\">({})</span>",
                esc(&host.ip.to_string()),
                esc(n)
            ),
            None => esc(&host.ip.to_string()),
        };
        let _ = writeln!(
            out,
            "<section class=\"host-card\"><div class=\"host-head\">\
             <div class=\"host-ip\">{host_label}</div>\
             <div class=\"host-meta\">{state_pill} · {extra}</div></div>"
        );
        if host.ports.is_empty() {
            out.push_str("<p class=\"muted\" style=\"margin:4px 0 0;font-size:12.5px\">No ports recorded for this host.</p>\n");
        } else {
            if host.ports.len() <= 512 {
                out.push_str("<div class=\"grid\">");
                for p in &host.ports {
                    let cls = match p.state.as_str() {
                        "open" => "cell open",
                        "open|filtered" | "filtered" | "unfiltered" => "cell filtered",
                        _ => "cell",
                    };
                    let title = match &p.service {
                        Some(svc) => format!(
                            "{}/{} {} — {}",
                            p.port,
                            p.protocol.as_str(),
                            p.state.as_str(),
                            svc
                        ),
                        None => format!("{}/{} {}", p.port, p.protocol.as_str(), p.state.as_str()),
                    };
                    let _ = write!(
                        out,
                        "<span class=\"{cls}\" title=\"{}\">{}</span>",
                        esc(&title),
                        p.port
                    );
                }
                out.push_str("</div>\n");
            }
            out.push_str(
                "<div class=\"tbl-wrap\"><table><tr><th class=\"num\">Port</th><th>Proto</th><th>State</th>\
                 <th>Service / Banner</th><th>Reason</th><th class=\"num\">RTT ms</th></tr>\n",
            );
            for p in &host.ports {
                let pill_cls = match p.state.as_str() {
                    "open" => "pill open",
                    "open|filtered" | "filtered" | "unfiltered" => "pill warn",
                    _ => "pill",
                };
                let rtt = p
                    .rtt_ms
                    .map(|r| format!("{r:.1}"))
                    .unwrap_or_else(|| "—".into());
                let svc = match (&p.service, &p.banner) {
                    (Some(sv), Some(b)) => format!("{sv} — {b}"),
                    (Some(sv), None) => sv.clone(),
                    _ => String::new(),
                };
                let _ = writeln!(
                    out,
                    "<tr><td class=\"num\" style=\"font-weight:600\">{}</td><td>{}</td>\
                     <td><span class=\"{pill_cls}\">{}</span></td><td>{}</td>\
                     <td class=\"muted\">{}</td><td class=\"num muted\">{}</td></tr>",
                    p.port,
                    p.protocol.as_str(),
                    p.state.as_str(),
                    esc(&svc),
                    esc(&p.reason),
                    rtt,
                );
            }
            out.push_str("</table></div>\n");
        }
        if !host.findings.is_empty() {
            out.push_str(
                "<div class=\"sec-sub\">Findings</div>\
                 <div class=\"tbl-wrap\"><table><tr><th>Tool</th><th>Severity</th>\
                 <th class=\"num\">Port</th><th>Detail</th></tr>\n",
            );
            for f in &host.findings {
                let cls = match f.severity.as_str() {
                    "critical" | "high" => "pill err",
                    "medium" => "pill warn",
                    _ => "pill",
                };
                let _ = writeln!(
                    out,
                    "<tr><td>{}</td><td><span class=\"{cls}\">{}</span></td><td class=\"num\">{}</td><td>{}</td></tr>",
                    esc(&f.tool),
                    esc(&f.severity),
                    f.port.map(|p| p.to_string()).unwrap_or_else(|| "—".into()),
                    esc(&f.detail),
                );
            }
            out.push_str("</table></div>\n");
        }
        for w in &host.web_profiles {
            let status_cls = if w.status >= 400 || w.status == 0 {
                "pill err"
            } else {
                "pill ok"
            };
            let _ = writeln!(
                out,
                "<div class=\"sec-sub\">Web Intelligence — {} <span class=\"{status_cls}\">{}</span> <span class=\"muted\">{} · {}ms</span></div>",
                esc(&w.url),
                w.status,
                esc(&w.http_version),
                w.ttfb_ms
            );
            if !w.technologies.is_empty() {
                out.push_str("<div class=\"chips\">");
                for t in &w.technologies {
                    let ver = t
                        .version
                        .as_deref()
                        .map(|v| format!(" {v}"))
                        .unwrap_or_default();
                    let _ = write!(
                        out,
                        "<span class=\"chip\"><b>{}</b>{} <span class=\"muted\">{}</span></span>",
                        esc(&t.name),
                        esc(&ver),
                        esc(&t.category)
                    );
                }
                out.push_str("</div>");
            }
            out.push_str("<div class=\"chips\">");
            for (label, ok) in [
                ("HSTS", w.security.hsts.is_some()),
                ("CSP", w.security.csp.is_some()),
                ("XFO", w.security.x_frame_options.is_some()),
                ("XCTO", w.security.x_content_type_options.is_some()),
                ("Referrer", w.security.referrer_policy.is_some()),
            ] {
                let pcls = if ok { "pill ok" } else { "pill" };
                let mark = if ok { "✓" } else { "×" };
                let _ = write!(out, "<span class=\"{pcls}\">{label} {mark}</span>");
            }
            let _ = write!(
                out,
                "<span class=\"pill\">Score {}/6</span></div>",
                w.security.score
            );
            out.push_str("<div class=\"tbl-wrap\"><table>");
            let mut row = |k: &str, v: &str| {
                if !v.is_empty() {
                    let _ = writeln!(
                        out,
                        "<tr><td class=\"muted\" style=\"width:150px\">{k}</td><td>{}</td></tr>",
                        esc(v)
                    );
                }
            };
            row("server", w.server.as_deref().unwrap_or_default());
            if let Some(t) = &w.tls {
                row(
                    "tls",
                    &format!(
                        "{}{}{}",
                        t.protocol,
                        t.subject_cn
                            .as_deref()
                            .map(|c| format!(" · {c}"))
                            .unwrap_or_default(),
                        t.org
                            .as_deref()
                            .map(|o| format!(" · {o}"))
                            .unwrap_or_default()
                    ),
                );
                row(
                    "issuer",
                    t.issuer_org
                        .as_deref()
                        .or(t.issuer_cn.as_deref())
                        .unwrap_or_default(),
                );
                row(
                    "valid",
                    &format!(
                        "{} → {}{}{}",
                        t.not_before,
                        t.not_after,
                        if t.expired { " (EXPIRED)" } else { "" },
                        if t.self_signed { " (self-signed)" } else { "" }
                    ),
                );
                if !t.san.is_empty() {
                    row("san", &t.san.join(", "));
                }
            }
            if !w.company.names.is_empty() {
                row("company", &w.company.names.join(" / "));
            }
            if let Some(r) = &w.company.registrar {
                row("registrar", r);
            }
            if let Some(a) = &w.company.asn {
                row("asn", a);
            }
            if !w.company.saas.is_empty() {
                row("saas", &w.company.saas.join(", "));
            }
            if !w.external_domains.is_empty() {
                row("external", &w.external_domains.join(", "));
            }
            if !w.api_hints.is_empty() {
                row("api", &w.api_hints.join(", "));
            }
            row("assets", &w.assets.len().to_string());
            if let Some(e) = &w.error {
                row("error", e);
            }
            out.push_str("</table></div>\n");
        }
        out.push_str("</section>\n");
    }
    let _ = writeln!(
        out,
        "<footer><span>{} v{} — {}</span><span>{} hosts ({} up, {} down) · finished {}</span></footer>\n</main></body></html>",
        crate::brand::NAME,
        esc(&report.version),
        crate::brand::SUBTITLE,
        s.hosts_up + s.hosts_down,
        s.hosts_up,
        s.hosts_down,
        fmt_utc(report.end_unix)
    );
    out
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HostResult, PortResult, PortState, Protocol, ScanSummary};

    fn sample() -> ScanReport {
        ScanReport {
            scanner: "ntok".into(),
            version: "0.1.0".into(),
            args: "connect 10.0.0.1".into(),
            technique: "connect".into(),
            start_unix: 1731700000,
            end_unix: 1731700002,
            elapsed_secs: 2.0,
            hosts: vec![
                HostResult {
                    ip: "10.0.0.1".parse().unwrap(),
                    hostname: Some("gw.local".into()),
                    state: HostState::Up,
                    reason: "syn-ack".into(),
                    ports: vec![
                        PortResult {
                            port: 22,
                            protocol: Protocol::Tcp,
                            state: PortState::Open,
                            service: Some("ssh".into()),
                            banner: None,
                            reason: "syn-ack".into(),
                            rtt_ms: Some(1.25),
                        },
                        PortResult {
                            port: 443,
                            protocol: Protocol::Tcp,
                            state: PortState::Filtered,
                            service: None,
                            banner: None,
                            reason: "no-response".into(),
                            rtt_ms: None,
                        },
                    ],
                    os_guess: None,
                    findings: vec![],
                    web_profiles: vec![],
                },
                HostResult {
                    ip: "10.0.0.2".parse().unwrap(),
                    hostname: None,
                    state: HostState::Down,
                    reason: "no-response".into(),
                    ports: vec![],
                    os_guess: None,
                    findings: vec![],
                    web_profiles: vec![],
                },
            ],
            summary: ScanSummary {
                hosts_up: 1,
                hosts_down: 1,
                open: 1,
                closed: 0,
                filtered: 1,
                unfiltered: 0,
            },
        }
    }

    #[test]
    fn greppable_lists_ports_per_host() {
        let out = to_greppable(&sample());
        assert!(out.contains(
            "Host: 10.0.0.1 (gw.local)\tPorts: 22/open/tcp//ssh///, 443/filtered/tcp////"
        ));
        assert!(out.contains("Host: 10.0.0.2 ()\tStatus: Down"));
    }

    #[test]
    fn csv_keeps_portless_hosts() {
        let out = to_csv(&sample());
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4); // header + 2 ports + 1 down host
        assert!(lines[1].starts_with("10.0.0.1,gw.local,up,syn-ack,,22,tcp,open,ssh"));
        assert_eq!(lines[3], "10.0.0.2,,down,no-response,,,,,,,,,,,");
    }

    #[test]
    fn format_parse_and_render() {
        assert_eq!(ReportFormat::parse("GNMAP"), Some(ReportFormat::Greppable));
        assert_eq!(ReportFormat::parse("bogus"), None);
        let r = sample();
        for fmt in ReportFormat::ALL {
            assert!(!fmt.render(&r).unwrap().is_empty());
        }
        assert!(to_html(&r).contains("<title>NTOK SCAN — Scan Report</title>"));
    }
}
