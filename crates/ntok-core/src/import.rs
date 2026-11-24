//! Import: parse nmap `-oX` XML output into a [`ScanReport`], so scans run
//! elsewhere get the same history, detail views and export formats as
//! native ntok reports. ntok's own `-oX` output round-trips through this.

use crate::error::{Error, Result};
use crate::model::{
    Finding, HostResult, HostState, PortResult, PortState, Protocol, ScanReport, ScanSummary,
};
use serde::Deserialize;
use std::net::IpAddr;

/// Parse an nmap `-oX` document into a [`ScanReport`].
///
/// Tolerant by design: unknown elements and attributes are ignored, hosts
/// without an IP address and ports with a protocol ntok doesn't model are
/// skipped, and missing `runstats` are recomputed from the hosts.
pub fn parse_nmap_xml(xml: &str) -> Result<ScanReport> {
    // quick-xml ignores the root element name — check it ourselves so an
    // arbitrary XML file doesn't come back as an empty report.
    if !has_nmaprun_root(xml) {
        return Err(Error::Import(
            "not an nmap -oX document (no <nmaprun> root element)".into(),
        ));
    }
    let run: NmapRun =
        quick_xml::de::from_str(xml).map_err(|e| Error::Import(format!("not nmap XML: {e}")))?;

    let mut summary = ScanSummary::default();
    let mut hosts = Vec::with_capacity(run.hosts.len());
    for h in run.hosts {
        let Some(host) = convert_host(h, &mut summary) else {
            continue;
        };
        hosts.push(host);
    }
    for h in &hosts {
        match h.state {
            HostState::Up => summary.hosts_up += 1,
            HostState::Down => summary.hosts_down += 1,
        }
    }
    // Prefer the file's own host tallies when present.
    if let Some(hs) = run.runstats.as_ref().and_then(|r| r.hosts.as_ref()) {
        summary.hosts_up = hs.up;
        summary.hosts_down = hs.down;
    }

    let finished = run.runstats.as_ref().and_then(|r| r.finished.as_ref());
    let elapsed = finished.and_then(|f| f.elapsed).unwrap_or(0.0);
    let technique = run
        .scaninfo
        .iter()
        .map(|s| s.kind.as_str())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("+");

    Ok(ScanReport {
        scanner: if run.scanner.is_empty() {
            "nmap".into()
        } else {
            run.scanner
        },
        version: run.version,
        args: run.args,
        technique: if technique.is_empty() {
            "import".into()
        } else {
            technique
        },
        start_unix: run.start,
        end_unix: finished.and_then(|f| f.time).unwrap_or(run.start),
        elapsed_secs: elapsed,
        hosts,
        summary,
    })
}

fn convert_host(h: NmapHost, summary: &mut ScanSummary) -> Option<HostResult> {
    let ip = h
        .address
        .iter()
        .find(|a| matches!(a.kind.as_str(), "ipv4" | "ipv6"))
        .and_then(|a| a.addr.parse::<IpAddr>().ok())?;
    let state = match h.status.as_ref().map(|s| s.state.as_str()) {
        Some("up") => HostState::Up,
        _ => HostState::Down,
    };
    let reason = h
        .status
        .map(|s| s.reason)
        .unwrap_or_else(|| "import".into());
    let hostname = h
        .hostnames
        .and_then(|hs| hs.hostname.into_iter().next())
        .map(|n| n.name)
        .filter(|n| !n.is_empty());
    let os_guess =
        h.os.and_then(|os| os.osmatch.into_iter().next())
            .map(|m| m.name)
            .filter(|n| !n.is_empty());

    let mut ports = Vec::new();
    let mut findings = Vec::new();
    let mut extra_filtered = 0usize;
    let mut extra_closed = 0usize;
    if let Some(ps) = h.ports {
        for x in ps.extraports {
            match x.state.as_str() {
                "filtered" => extra_filtered += x.count,
                "closed" => extra_closed += x.count,
                _ => {}
            }
        }
        for p in ps.port {
            let Some(protocol) = Protocol::parse(&p.protocol) else {
                continue;
            };
            let state = p
                .state
                .as_ref()
                .map(|s| PortState::parse(&s.state))
                .unwrap_or(PortState::Filtered);
            match state {
                PortState::Open | PortState::OpenFiltered => summary.open += 1,
                PortState::Closed => summary.closed += 1,
                PortState::Filtered => summary.filtered += 1,
                PortState::Unfiltered => summary.unfiltered += 1,
            }
            let reason = p
                .state
                .map(|s| s.reason.into())
                .unwrap_or_else(|| "import".into());
            for sc in p.script {
                findings.push(script_finding(sc, Some(p.portid)));
            }
            let (service, banner) = match p.service {
                Some(sv) => {
                    let banner = [sv.product, sv.version, sv.extrainfo]
                        .into_iter()
                        .flatten()
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(" ");
                    (
                        (!sv.name.is_empty()).then_some(sv.name),
                        (!banner.is_empty()).then_some(banner),
                    )
                }
                None => (None, None),
            };
            ports.push(PortResult {
                port: p.portid,
                protocol,
                state,
                service,
                banner,
                reason,
                rtt_ms: None,
            });
        }
    }
    summary.filtered += extra_filtered;
    summary.closed += extra_closed;

    if let Some(hs) = h.hostscript {
        for sc in hs.script {
            findings.push(script_finding(sc, None));
        }
    }

    Some(HostResult {
        ip,
        hostname,
        state,
        reason,
        ports,
        os_guess,
        findings,
        web_profiles: Vec::new(),
    })
}

/// One NSE `<script>` result → a finding. Output is trimmed and capped —
/// some scripts (ssl-cert, smb-enum) dump pages of text.
fn script_finding(sc: ScriptEl, port: Option<u16>) -> Finding {
    let detail = sc.output.trim().chars().take(600).collect();
    Finding {
        tool: format!("nmap:{}", sc.id),
        severity: "info".into(),
        port,
        detail,
    }
}

/// Load a [`ScanReport`] from file contents, sniffing the format: ntok
/// JSON (canonical), or nmap `-oX` XML. Anything else errors.
pub fn parse_report(text: &str) -> Result<ScanReport> {
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('{') {
        serde_json::from_str(text)
            .map_err(|e| Error::Import(format!("not an ntok JSON report: {e}")))
    } else if trimmed.starts_with('<') {
        parse_nmap_xml(text)
    } else {
        Err(Error::Import(
            "unrecognised report format (expected ntok JSON or nmap -oX XML)".into(),
        ))
    }
}

/// [`parse_report`] on a file path.
pub fn load_report(path: &std::path::Path) -> Result<ScanReport> {
    let text = std::fs::read_to_string(path)?;
    parse_report(&text)
}

/// Walk past the XML prolog (PIs, comments, DOCTYPE) and confirm the
/// document element is `<nmaprun>`.
fn has_nmaprun_root(xml: &str) -> bool {
    let mut rest = xml.trim_start_matches('\u{feff}').trim_start();
    loop {
        let skip = if let Some(r) = rest.strip_prefix("<?") {
            r.find("?>").map(|i| &r[i + 2..])
        } else if let Some(r) = rest.strip_prefix("<!--") {
            r.find("-->").map(|i| &r[i + 3..])
        } else if let Some(r) = rest.strip_prefix("<!") {
            r.find('>').map(|i| &r[i + 1..])
        } else {
            return rest.starts_with("<nmaprun");
        };
        match skip {
            Some(r) => rest = r.trim_start(),
            None => return false,
        }
    }
}

// ---------- nmap -oX schema (attributes bind via `@name`) ----------

#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(rename = "@args", default)]
    args: String,
    #[serde(rename = "@scanner", default)]
    scanner: String,
    #[serde(rename = "@version", default)]
    version: String,
    #[serde(rename = "@start", default)]
    start: u64,
    #[serde(default)]
    scaninfo: Vec<ScanInfo>,
    #[serde(default, rename = "host")]
    hosts: Vec<NmapHost>,
    runstats: Option<RunStats>,
}

#[derive(Debug, Deserialize)]
struct ScanInfo {
    #[serde(rename = "@type", default)]
    kind: String,
}

#[derive(Debug, Deserialize)]
struct NmapHost {
    status: Option<Status>,
    #[serde(default)]
    address: Vec<Address>,
    hostnames: Option<Hostnames>,
    ports: Option<Ports>,
    os: Option<Os>,
    hostscript: Option<HostScript>,
}

#[derive(Debug, Deserialize)]
struct HostScript {
    #[serde(default)]
    script: Vec<ScriptEl>,
}

#[derive(Debug, Deserialize)]
struct ScriptEl {
    #[serde(rename = "@id", default)]
    id: String,
    #[serde(rename = "@output", default)]
    output: String,
}

#[derive(Debug, Deserialize)]
struct Status {
    #[serde(rename = "@state", default)]
    state: String,
    #[serde(rename = "@reason", default)]
    reason: String,
}

#[derive(Debug, Deserialize)]
struct Address {
    #[serde(rename = "@addr", default)]
    addr: String,
    #[serde(rename = "@addrtype", default)]
    kind: String,
}

#[derive(Debug, Deserialize)]
struct Hostnames {
    #[serde(default)]
    hostname: Vec<Hostname>,
}

#[derive(Debug, Deserialize)]
struct Hostname {
    #[serde(rename = "@name", default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct Ports {
    #[serde(default)]
    port: Vec<NmapPort>,
    #[serde(default)]
    extraports: Vec<Extraports>,
}

#[derive(Debug, Deserialize)]
struct Extraports {
    #[serde(rename = "@state", default)]
    state: String,
    #[serde(rename = "@count", default)]
    count: usize,
}

#[derive(Debug, Deserialize)]
struct NmapPort {
    #[serde(rename = "@protocol", default)]
    protocol: String,
    #[serde(rename = "@portid")]
    portid: u16,
    state: Option<PortStateEl>,
    service: Option<Service>,
    #[serde(default)]
    script: Vec<ScriptEl>,
}

#[derive(Debug, Deserialize)]
struct PortStateEl {
    #[serde(rename = "@state", default)]
    state: String,
    #[serde(rename = "@reason", default)]
    reason: String,
}

#[derive(Debug, Deserialize)]
struct Service {
    #[serde(rename = "@name", default)]
    name: String,
    #[serde(rename = "@product")]
    product: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
    #[serde(rename = "@extrainfo")]
    extrainfo: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Os {
    #[serde(default)]
    osmatch: Vec<OsMatch>,
}

#[derive(Debug, Deserialize)]
struct OsMatch {
    #[serde(rename = "@name", default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct RunStats {
    finished: Option<Finished>,
    hosts: Option<Hosts>,
}

#[derive(Debug, Deserialize)]
struct Finished {
    #[serde(rename = "@time")]
    time: Option<u64>,
    #[serde(rename = "@elapsed")]
    elapsed: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct Hosts {
    #[serde(rename = "@up", default)]
    up: usize,
    #[serde(rename = "@down", default)]
    down: usize,
}

impl Protocol {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

impl PortState {
    /// nmap state strings → model. Compound verdicts collapse to the
    /// closest single state; anything unrecognised reads as filtered.
    fn parse(s: &str) -> Self {
        match s {
            "open" => Self::Open,
            "closed" => Self::Closed,
            "unfiltered" => Self::Unfiltered,
            "open|filtered" => Self::OpenFiltered,
            _ => Self::Filtered,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX out.xml 10.0.0.1" start="1731700000" version="7.94">
  <scaninfo type="syn" protocol="tcp" numservices="3" services="22,80,443"/>
  <host starttime="1731700000" endtime="1731700002">
    <status state="up" reason="echo-reply" reason_ttl="64"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Test"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <ports>
      <extraports state="closed" count="1"><extrareasons reason="conn-refused" count="1"/></extraports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="8.9" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="filtered" reason="no-response"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.x" accuracy="95"/></os>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished time="1731700002" elapsed="2.50" timestr="x"/>
    <hosts up="1" down="1" total="2"/>
  </runstats>
</nmaprun>"#;

    #[test]
    fn parses_nmap_xml() {
        let r = parse_nmap_xml(SAMPLE).unwrap();
        assert_eq!(r.scanner, "nmap");
        assert_eq!(r.technique, "syn");
        assert_eq!(r.start_unix, 1731700000);
        assert_eq!(r.end_unix, 1731700002);
        assert_eq!(r.elapsed_secs, 2.5);
        assert_eq!(r.hosts.len(), 2);

        let h = &r.hosts[0];
        assert_eq!(h.ip.to_string(), "10.0.0.1");
        assert_eq!(h.hostname.as_deref(), Some("router.local"));
        assert_eq!(h.state, HostState::Up);
        assert_eq!(h.os_guess.as_deref(), Some("Linux 5.x"));
        assert_eq!(h.ports.len(), 2);

        let p = &h.ports[0];
        assert_eq!(p.port, 22);
        assert_eq!(p.protocol, Protocol::Tcp);
        assert_eq!(p.state, PortState::Open);
        assert_eq!(p.service.as_deref(), Some("ssh"));
        assert_eq!(p.banner.as_deref(), Some("OpenSSH 8.9"));
        assert_eq!(p.reason, "syn-ack");
        assert_eq!(h.ports[1].state, PortState::Filtered);

        assert_eq!(r.summary.hosts_up, 1);
        assert_eq!(r.summary.hosts_down, 1);
        assert_eq!(r.summary.open, 1);
        assert_eq!(r.summary.filtered, 1);
        // the listed filtered port + 1 extraports closed
        assert_eq!(r.summary.closed, 1);
    }

    #[test]
    fn rejects_non_nmap_xml() {
        assert!(parse_nmap_xml("<html><body>nope</body></html>").is_err());
        assert!(parse_nmap_xml("not xml at all").is_err());
    }

    #[test]
    fn round_trips_ntok_xml() {
        // ntok's own -oX output must import cleanly.
        let report = ScanReport {
            scanner: "ntok".into(),
            version: "0.1.0".into(),
            args: "connect 10.0.0.1".into(),
            technique: "connect".into(),
            start_unix: 1731700000,
            end_unix: 1731700001,
            elapsed_secs: 1.0,
            hosts: vec![HostResult {
                ip: "10.0.0.1".parse().unwrap(),
                hostname: None,
                state: HostState::Up,
                reason: "syn-ack".into(),
                ports: vec![PortResult {
                    port: 443,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("https".into()),
                    banner: Some("nginx 1.25".into()),
                    reason: "syn-ack".into(),
                    rtt_ms: Some(1.5),
                }],
                os_guess: None,
                findings: vec![
                    Finding {
                        tool: "nmap:ssl-cert".into(),
                        severity: "info".into(),
                        port: Some(443),
                        detail: "subject: test".into(),
                    },
                    Finding {
                        tool: "nuclei".into(),
                        severity: "high".into(),
                        port: None,
                        detail: "cve-2024-0001".into(),
                    },
                ],
                web_profiles: vec![],
            }],
            summary: ScanSummary {
                hosts_up: 1,
                hosts_down: 0,
                open: 1,
                closed: 0,
                filtered: 0,
                unfiltered: 0,
            },
        };
        let xml = crate::report::to_xml(&report);
        let back = parse_nmap_xml(&xml).unwrap();
        assert_eq!(back.hosts.len(), 1);
        assert_eq!(back.hosts[0].ports[0].port, 443);
        assert_eq!(back.hosts[0].ports[0].state, PortState::Open);
        assert_eq!(back.summary.open, 1);
        // Banner rides back through <service product=…>; findings through
        // <script> (port-scoped and hostscript).
        assert_eq!(back.hosts[0].ports[0].banner.as_deref(), Some("nginx 1.25"));
        let fs = &back.hosts[0].findings;
        assert_eq!(fs.len(), 2);
        assert!(
            fs.iter()
                .any(|f| f.tool == "nmap:ssl-cert" && f.port == Some(443))
        );
        assert!(fs.iter().any(|f| f.detail.contains("cve-2024-0001")));
    }
}
