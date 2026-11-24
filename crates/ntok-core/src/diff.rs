//! Scan diffing: compare two [`ScanReport`]s — nmap's `ndiff` counterpart.
//! Hosts that appear/disappear, and per-host changes: state flips, ports
//! added or removed, port state transitions, service and OS changes.
//! Works on any report regardless of origin — ntok scans and imported
//! nmap `-oX` files compare the same way.

use crate::model::{Finding, HostResult, HostState, PortResult, PortState, Protocol, ScanReport};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize)]
pub struct ScanDiff {
    /// What A and B were (args strings) — shown in headers.
    pub a_args: String,
    pub b_args: String,
    /// In B but not A.
    pub hosts_added: Vec<HostResult>,
    /// In A but not B.
    pub hosts_removed: Vec<HostResult>,
    /// Present in both, with at least one change.
    pub hosts_changed: Vec<HostDiff>,
    /// Hosts byte-identical across both reports.
    pub hosts_unchanged: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostDiff {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    /// Host up/down flip: (was, now).
    pub state_changed: Option<(HostState, HostState)>,
    pub hostname_changed: Option<(Option<String>, Option<String>)>,
    pub os_changed: Option<(Option<String>, Option<String>)>,
    /// In B only.
    pub ports_added: Vec<PortResult>,
    /// In A only.
    pub ports_removed: Vec<PortResult>,
    /// Present in both, state differs.
    pub state_changes: Vec<PortChange>,
    /// Same port+state, different service/banner.
    pub service_changes: Vec<ServiceChange>,
    /// Findings (nmap scripts, nuclei …) new in B — e.g. a vuln appearing.
    pub findings_added: Vec<String>,
    /// Findings gone in B.
    pub findings_removed: Vec<String>,
    /// Web recon drift: endpoints, technologies and external domains
    /// appearing/disappearing between the two scans.
    pub web_changes: Vec<String>,
}

impl HostDiff {
    fn is_empty(&self) -> bool {
        self.state_changed.is_none()
            && self.hostname_changed.is_none()
            && self.os_changed.is_none()
            && self.ports_added.is_empty()
            && self.ports_removed.is_empty()
            && self.state_changes.is_empty()
            && self.service_changes.is_empty()
            && self.findings_added.is_empty()
            && self.findings_removed.is_empty()
            && self.web_changes.is_empty()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PortChange {
    pub port: u16,
    pub protocol: Protocol,
    pub old: PortState,
    pub new: PortState,
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceChange {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    /// (was, now) — service string is `name — banner` when both exist.
    pub old: Option<String>,
    pub new: Option<String>,
}

pub fn diff_reports(a: &ScanReport, b: &ScanReport) -> ScanDiff {
    let a_map = by_ip(&a.hosts);
    let b_map = by_ip(&b.hosts);

    let mut hosts_added = Vec::new();
    let mut hosts_removed = Vec::new();
    let mut hosts_changed = Vec::new();
    let mut hosts_unchanged = 0usize;

    for (ip, ha) in &a_map {
        match b_map.get(ip) {
            None => hosts_removed.push((*ha).clone()),
            Some(hb) => {
                let d = diff_host(ha, hb);
                if d.is_empty() {
                    hosts_unchanged += 1;
                } else {
                    hosts_changed.push(d);
                }
            }
        }
    }
    for (ip, hb) in &b_map {
        if !a_map.contains_key(ip) {
            hosts_added.push((*hb).clone());
        }
    }

    hosts_added.sort_by_key(|h| h.ip);
    hosts_removed.sort_by_key(|h| h.ip);
    hosts_changed.sort_by_key(|h| h.ip);

    ScanDiff {
        a_args: a.args.clone(),
        b_args: b.args.clone(),
        hosts_added,
        hosts_removed,
        hosts_changed,
        hosts_unchanged,
    }
}

fn by_ip(hosts: &[HostResult]) -> HashMap<IpAddr, &HostResult> {
    hosts.iter().map(|h| (h.ip, h)).collect()
}

fn by_key(ports: &[PortResult]) -> HashMap<(u16, Protocol), &PortResult> {
    ports.iter().map(|p| ((p.port, p.protocol), p)).collect()
}

fn diff_host(a: &HostResult, b: &HostResult) -> HostDiff {
    let a_map = by_key(&a.ports);
    let b_map = by_key(&b.ports);

    let mut d = HostDiff {
        ip: a.ip,
        hostname: b.hostname.clone().or_else(|| a.hostname.clone()),
        state_changed: (a.state != b.state).then_some((a.state, b.state)),
        hostname_changed: (a.hostname != b.hostname)
            .then_some((a.hostname.clone(), b.hostname.clone())),
        os_changed: (a.os_guess != b.os_guess).then_some((a.os_guess.clone(), b.os_guess.clone())),
        ports_added: Vec::new(),
        ports_removed: Vec::new(),
        state_changes: Vec::new(),
        service_changes: Vec::new(),
        findings_added: Vec::new(),
        findings_removed: Vec::new(),
        web_changes: Vec::new(),
    };

    // Findings match on identity (tool+port+severity+detail), not position.
    let a_find: HashSet<String> = a.findings.iter().map(finding_key).collect();
    let b_find: HashSet<String> = b.findings.iter().map(finding_key).collect();
    for f in &b.findings {
        if !a_find.contains(&finding_key(f)) {
            d.findings_added.push(finding_label(f));
        }
    }
    for f in &a.findings {
        if !b_find.contains(&finding_key(f)) {
            d.findings_removed.push(finding_label(f));
        }
    }

    // Web recon drift, matched per endpoint URL: technologies and
    // third-party domains gained or lost, cert subject changes.
    for wb in &b.web_profiles {
        match a.web_profiles.iter().find(|w| w.url == wb.url) {
            None => d
                .web_changes
                .push(format!("+ web {} — {}", wb.url, wb.status)),
            Some(wa) => {
                let ta: HashSet<&String> = wa.technologies.iter().map(|t| &t.name).collect();
                let tb: HashSet<&String> = wb.technologies.iter().map(|t| &t.name).collect();
                for t in tb.difference(&ta) {
                    d.web_changes.push(format!("+ tech {t} on {}", wb.url));
                }
                for t in ta.difference(&tb) {
                    d.web_changes.push(format!("- tech {t} on {}", wb.url));
                }
                let ea: HashSet<&String> = wa.external_domains.iter().collect();
                let eb: HashSet<&String> = wb.external_domains.iter().collect();
                for e in eb.difference(&ea) {
                    d.web_changes.push(format!("+ external {e} on {}", wb.url));
                }
                for e in ea.difference(&eb) {
                    d.web_changes.push(format!("- external {e} on {}", wb.url));
                }
                if let (Some(ta), Some(tb)) = (&wa.tls, &wb.tls)
                    && ta.subject_cn != tb.subject_cn
                {
                    d.web_changes.push(format!(
                        "tls {}: {} → {}",
                        wb.url,
                        ta.subject_cn.as_deref().unwrap_or("—"),
                        tb.subject_cn.as_deref().unwrap_or("—"),
                    ));
                }
            }
        }
    }
    for wa in &a.web_profiles {
        if !b.web_profiles.iter().any(|w| w.url == wa.url) {
            d.web_changes.push(format!("- web {}", wa.url));
        }
    }

    for (key, pa) in &a_map {
        match b_map.get(key) {
            None => d.ports_removed.push((*pa).clone()),
            Some(pb) => {
                if pa.state != pb.state {
                    d.state_changes.push(PortChange {
                        port: pa.port,
                        protocol: pa.protocol,
                        old: pa.state,
                        new: pb.state,
                        service: pb.service.clone().or_else(|| pa.service.clone()),
                    });
                } else if service_label(pa) != service_label(pb) {
                    d.service_changes.push(ServiceChange {
                        port: pa.port,
                        protocol: pa.protocol,
                        state: pb.state,
                        old: service_label(pa),
                        new: service_label(pb),
                    });
                }
            }
        }
    }
    for (key, pb) in &b_map {
        if !a_map.contains_key(key) {
            d.ports_added.push((*pb).clone());
        }
    }

    let key = |p: &PortResult| (p.port, p.protocol);
    d.ports_added.sort_by_key(key);
    d.ports_removed.sort_by_key(key);
    d.state_changes.sort_by_key(|c| (c.port, c.protocol));
    d.service_changes.sort_by_key(|c| (c.port, c.protocol));
    d
}

fn finding_key(f: &Finding) -> String {
    format!(
        "{}\u{0}{:?}\u{0}{}\u{0}{}",
        f.tool, f.port, f.severity, f.detail
    )
}

fn finding_label(f: &Finding) -> String {
    let at = f.port.map(|p| format!(":{p}")).unwrap_or_default();
    let detail: String = f.detail.chars().take(120).collect();
    format!("{}{at} [{}] {}", f.tool, f.severity, detail)
}

fn service_label(p: &PortResult) -> Option<String> {
    match (&p.service, &p.banner) {
        (Some(s), Some(b)) => Some(format!("{s} — {b}")),
        (Some(s), None) => Some(s.clone()),
        (None, Some(b)) => Some(b.clone()),
        (None, None) => None,
    }
}

// ---------- text renderer ----------

/// ndiff-style summary. `a_label`/`b_label` name the two sides (paths or
/// scan ids) — the reports' `args` go in as provenance.
pub fn to_text(d: &ScanDiff, a_label: &str, b_label: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "--- {a_label}  (ntok {})", d.a_args);
    let _ = writeln!(out, "+++ {b_label}  (ntok {})", d.b_args);
    out.push('\n');

    for h in &d.hosts_added {
        let _ = writeln!(
            out,
            "+ {} — appeared{}",
            host_head(h),
            ports_brief(&h.ports)
        );
    }
    for h in &d.hosts_removed {
        let _ = writeln!(
            out,
            "- {} — disappeared{}",
            host_head(h),
            ports_brief(&h.ports)
        );
    }
    for h in &d.hosts_changed {
        let mut head = h.ip.to_string();
        if let Some(n) = &h.hostname {
            let _ = write!(head, " ({n})");
        }
        let _ = writeln!(out, "  {head}:");
        if let Some((old, new)) = &h.state_changed {
            let _ = writeln!(out, "    host: {} → {}", state_word(*old), state_word(*new));
        }
        if let Some((old, new)) = &h.hostname_changed {
            let _ = writeln!(
                out,
                "    hostname: {} → {}",
                old.as_deref().unwrap_or("—"),
                new.as_deref().unwrap_or("—")
            );
        }
        if let Some((old, new)) = &h.os_changed {
            let _ = writeln!(
                out,
                "    os: {} → {}",
                old.as_deref().unwrap_or("—"),
                new.as_deref().unwrap_or("—")
            );
        }
        for p in &h.ports_added {
            let _ = writeln!(
                out,
                "    + port {}/{}: {}{}",
                p.port,
                p.protocol.as_str(),
                p.state.as_str(),
                svc_suffix(p)
            );
        }
        for p in &h.ports_removed {
            let _ = writeln!(
                out,
                "    - port {}/{}: was {}{}",
                p.port,
                p.protocol.as_str(),
                p.state.as_str(),
                svc_suffix(p)
            );
        }
        for c in &h.state_changes {
            let _ = writeln!(
                out,
                "    port {}/{}: {} → {}{}",
                c.port,
                c.protocol.as_str(),
                c.old.as_str(),
                c.new.as_str(),
                c.service
                    .as_deref()
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default()
            );
        }
        for f in &h.findings_added {
            let _ = writeln!(out, "    + finding: {f}");
        }
        for f in &h.findings_removed {
            let _ = writeln!(out, "    - finding: {f}");
        }
        for c in &h.service_changes {
            let _ = writeln!(
                out,
                "    port {}/{}: service {} → {}",
                c.port,
                c.protocol.as_str(),
                c.old.as_deref().unwrap_or("—"),
                c.new.as_deref().unwrap_or("—")
            );
        }
        for w in &h.web_changes {
            let _ = writeln!(out, "    {w}");
        }
    }
    if d.hosts_unchanged > 0 {
        let _ = writeln!(out, "  ({} hosts unchanged)", d.hosts_unchanged);
    }
    out
}

fn host_head(h: &HostResult) -> String {
    let mut s = h.ip.to_string();
    if let Some(n) = &h.hostname {
        let _ = write!(s, " ({n})");
    }
    let _ = write!(s, " {}", state_word(h.state));
    s
}

fn state_word(s: HostState) -> &'static str {
    match s {
        HostState::Up => "up",
        HostState::Down => "down",
    }
}

fn svc_suffix(p: &PortResult) -> String {
    service_label(p)
        .map(|s| format!(" ({s})"))
        .unwrap_or_default()
}

fn ports_brief(ports: &[PortResult]) -> String {
    if ports.is_empty() {
        return String::new();
    }
    let open = ports.iter().filter(|p| p.state.is_open()).count();
    format!(" — {} ports, {open} open", ports.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanSummary;

    fn host(ip: &str, up: bool, ports: Vec<(u16, PortState, Option<&str>)>) -> HostResult {
        HostResult {
            ip: ip.parse().unwrap(),
            hostname: None,
            state: if up { HostState::Up } else { HostState::Down },
            reason: "r".into(),
            ports: ports
                .into_iter()
                .map(|(port, state, svc)| PortResult {
                    port,
                    protocol: Protocol::Tcp,
                    state,
                    service: svc.map(str::to_string),
                    banner: None,
                    reason: "r".into(),
                    rtt_ms: None,
                })
                .collect(),
            os_guess: None,
            findings: vec![],
            web_profiles: vec![],
        }
    }

    fn report(hosts: Vec<HostResult>) -> ScanReport {
        ScanReport {
            scanner: "ntok".into(),
            version: "0".into(),
            args: "scan".into(),
            technique: "connect".into(),
            start_unix: 0,
            end_unix: 1,
            elapsed_secs: 1.0,
            hosts,
            summary: ScanSummary::default(),
        }
    }

    #[test]
    fn detects_all_change_kinds() {
        let a = report(vec![
            host(
                "10.0.0.1",
                true,
                vec![
                    (22, PortState::Open, Some("ssh")),
                    (80, PortState::Closed, None),
                ],
            ),
            host("10.0.0.2", true, vec![]),
            host("10.0.0.4", true, vec![(443, PortState::Filtered, None)]),
        ]);
        let b = report(vec![
            host(
                "10.0.0.1",
                true,
                vec![
                    (22, PortState::Filtered, Some("ssh")),
                    (80, PortState::Closed, Some("http")),
                    (8080, PortState::Open, Some("proxy")),
                ],
            ),
            host("10.0.0.3", true, vec![(53, PortState::Open, Some("dns"))]),
        ]);

        let d = diff_reports(&a, &b);
        assert_eq!(d.hosts_added.len(), 1);
        assert_eq!(d.hosts_added[0].ip.to_string(), "10.0.0.3");
        assert_eq!(d.hosts_removed.len(), 2); // .2 and .4
        assert_eq!(d.hosts_changed.len(), 1);

        let h = &d.hosts_changed[0];
        assert_eq!(h.ip.to_string(), "10.0.0.1");
        assert_eq!(h.state_changes.len(), 1);
        assert_eq!(h.state_changes[0].port, 22);
        assert_eq!(h.state_changes[0].old, PortState::Open);
        assert_eq!(h.state_changes[0].new, PortState::Filtered);
        assert_eq!(h.ports_added.len(), 1);
        assert_eq!(h.ports_added[0].port, 8080);
        assert_eq!(h.service_changes.len(), 1);
        assert_eq!(h.service_changes[0].port, 80);
        assert_eq!(d.hosts_unchanged, 0);
    }

    #[test]
    fn identical_reports_diff_empty() {
        let a = report(vec![host(
            "10.0.0.1",
            true,
            vec![(22, PortState::Open, Some("ssh"))],
        )]);
        let d = diff_reports(&a, &a);
        assert_eq!(d.hosts_unchanged, 1);
        assert!(
            d.hosts_changed.is_empty() && d.hosts_added.is_empty() && d.hosts_removed.is_empty()
        );
        assert!(to_text(&d, "a", "b").contains("1 hosts unchanged"));
    }

    #[test]
    fn text_renders_transitions() {
        let a = report(vec![host(
            "10.0.0.1",
            true,
            vec![(22, PortState::Closed, None)],
        )]);
        let b = report(vec![host(
            "10.0.0.1",
            true,
            vec![(22, PortState::Open, Some("ssh"))],
        )]);
        let out = to_text(&diff_reports(&a, &b), "A", "B");
        assert!(out.contains("--- A"));
        assert!(out.contains("port 22/tcp: closed → open (ssh)"));
    }
}
