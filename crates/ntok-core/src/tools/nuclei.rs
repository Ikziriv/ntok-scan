//! nuclei vulnerability templates against the scan's open ports. Web
//! services get `scheme://ip:port` targets (HTTP templates), everything
//! else gets bare `ip:port` (network templates). Output is `-jsonl`
//! parsed line-wise into severity-tagged findings.

use super::{ToolConfig, ToolKind, note};
use crate::event::ScanEvent;
use crate::model::{Finding, Protocol, ScanReport};
use serde::Deserialize;
use std::net::IpAddr;
use tokio::sync::broadcast;

/// Bound on `-u` args — nuclei is a heavy runner, and beyond this the
/// tail latency dominates the scan it enriched anyway.
const MAX_TARGETS: usize = 512;

pub async fn enrich_all(
    report: &mut ScanReport,
    tcfg: &ToolConfig,
    events: &broadcast::Sender<ScanEvent>,
) {
    let mut targets: Vec<String> = Vec::new();
    for h in &report.hosts {
        if h.state != crate::model::HostState::Up {
            continue;
        }
        for p in &h.ports {
            if p.protocol != Protocol::Tcp || !p.state.is_open() {
                continue;
            }
            targets.push(target_for(h.ip, p.port, p.service.as_deref()));
        }
    }
    if targets.is_empty() {
        return;
    }
    if targets.len() > MAX_TARGETS {
        note(
            events,
            format!("nuclei: capping {} targets at {MAX_TARGETS}", targets.len()),
        );
        targets.truncate(MAX_TARGETS);
    }
    note(
        events,
        format!("nuclei: scanning {} targets", targets.len()),
    );

    let mut args: Vec<String> = [
        "-silent",
        "-nc",
        "-jsonl",
        "-disable-update-check",
        "-timeout",
        "5",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for t in &targets {
        args.push("-u".into());
        args.push(t.clone());
    }

    match tcfg.run(ToolKind::Nuclei.prog(), &args).await {
        Ok(out) => {
            let mut n = 0usize;
            for line in out.lines() {
                let Some((ip, f)) = parse_line(line) else {
                    continue;
                };
                if let Some(h) = report.hosts.iter_mut().find(|h| h.ip == ip) {
                    h.findings.push(f);
                    n += 1;
                }
            }
            note(events, format!("nuclei: {n} findings"));
        }
        Err(e) => note(events, format!("nuclei failed: {e}")),
    }
}

/// `ip:port` for plain TCP services; `scheme://ip:port` when the service
/// smells like HTTP so nuclei's http templates apply.
fn target_for(ip: IpAddr, port: u16, service: Option<&str>) -> String {
    let svc = service.unwrap_or("");
    if svc.starts_with("http") || matches!(port, 80 | 443 | 8000 | 8080 | 8443 | 8888) {
        let scheme = if svc.contains("https") || port == 443 {
            "https"
        } else {
            "http"
        };
        format!("{scheme}://{ip}:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

// ---------- nuclei -jsonl ----------

#[derive(Deserialize)]
struct Line {
    #[serde(rename = "template-id", default)]
    template_id: String,
    #[serde(default)]
    info: Info,
    #[serde(default)]
    host: String,
    #[serde(rename = "matched-at", default)]
    matched_at: String,
}

#[derive(Deserialize, Default)]
struct Info {
    #[serde(default)]
    name: String,
    #[serde(default)]
    severity: String,
}

fn parse_line(line: &str) -> Option<(IpAddr, Finding)> {
    let l: Line = serde_json::from_str(line).ok()?;
    // host is "ip:port" or "scheme://ip:port" — take the host part, then
    // the port when present.
    let hostpart = l.host.split("://").last().unwrap_or(&l.host);
    let (ip_str, port) = match hostpart.rsplit_once(':') {
        Some((a, b)) => (a, b.parse::<u16>().ok()),
        None => (hostpart, None),
    };
    let ip: IpAddr = ip_str.trim_matches(['[', ']']).parse().ok()?;
    let detail = format!(
        "{}{}{}",
        l.template_id,
        if l.info.name.is_empty() { "" } else { " — " },
        l.info.name,
    );
    let detail = if l.matched_at.is_empty() {
        detail
    } else {
        format!("{detail} @ {}", l.matched_at)
    };
    Some((
        ip,
        Finding {
            tool: "nuclei".into(),
            severity: if l.info.severity.is_empty() {
                "unknown".into()
            } else {
                l.info.severity
            },
            port,
            detail,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_jsonl_line() {
        let line = r#"{"template-id":"apache-detect","info":{"name":"Apache HTTP Server","severity":"info"},"type":"http","host":"http://10.0.0.1:8080","matched-at":"http://10.0.0.1:8080"}"#;
        let (ip, f) = parse_line(line).unwrap();
        assert_eq!(ip.to_string(), "10.0.0.1");
        assert_eq!(f.severity, "info");
        assert_eq!(f.port, Some(8080));
        assert!(f.detail.contains("apache-detect"));
    }

    #[test]
    fn builds_targets() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(target_for(ip, 22, Some("ssh")), "10.0.0.1:22");
        assert_eq!(target_for(ip, 443, Some("https")), "https://10.0.0.1:443");
        assert_eq!(
            target_for(ip, 8080, Some("http-proxy")),
            "http://10.0.0.1:8080"
        );
    }
}
