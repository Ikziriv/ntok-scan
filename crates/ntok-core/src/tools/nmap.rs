//! Real nmap as a post-scan enrichment: `-sV` (service/version probes)
//! plus any `<script>` output, run only over the ports ntok already found
//! open — nmap verifies and labels, it doesn't re-scan the space.
//!
//! nmap's `-oX` XML comes back through `import::parse_nmap_xml`, so the
//! merge below is the same shape the `import` command produces.

use super::{ToolConfig, ToolKind, note};
use crate::event::ScanEvent;
use crate::model::{HostResult, PortState, Protocol, ScanReport};
use futures::stream::{self, StreamExt};
use std::net::IpAddr;
use tokio::sync::broadcast;

/// One `nmap -sV` run per up host that has open TCP ports, four hosts at
/// a time, merged back into the report.
pub async fn enrich_all(
    report: &mut ScanReport,
    tcfg: &ToolConfig,
    events: &broadcast::Sender<ScanEvent>,
) {
    let jobs: Vec<(IpAddr, Vec<u16>)> = report
        .hosts
        .iter()
        .filter(|h| h.state == crate::model::HostState::Up)
        .filter_map(|h| {
            let ports: Vec<u16> = h
                .ports
                .iter()
                .filter(|p| p.protocol == Protocol::Tcp && p.state.is_open())
                .map(|p| p.port)
                .collect();
            (!ports.is_empty()).then_some((h.ip, ports))
        })
        .collect();
    if jobs.is_empty() {
        return;
    }
    note(
        events,
        format!("nmap: enriching {} hosts (-sV)", jobs.len()),
    );

    let results: Vec<(IpAddr, Option<HostResult>)> = stream::iter(jobs)
        .map(|(ip, ports)| async move {
            let plist = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let args = vec![
                "-Pn".into(),
                "-sV".into(),
                "--version-light".into(),
                "-oX".into(),
                "-".into(),
                "-p".into(),
                plist,
                ip.to_string(),
            ];
            match tcfg.run(ToolKind::Nmap.prog(), &args).await {
                Ok(xml) => match crate::import::parse_nmap_xml(&xml) {
                    Ok(rep) => (ip, rep.hosts.into_iter().next()),
                    Err(_) => (ip, None),
                },
                Err(_) => (ip, None),
            }
        })
        .buffer_unordered(4)
        .collect()
        .await;

    let mut enriched = 0usize;
    for (ip, res) in results {
        let (Some(src), Some(dst)) = (res, report.hosts.iter_mut().find(|h| h.ip == ip)) else {
            continue;
        };
        merge_host(dst, src);
        enriched += 1;
    }
    note(events, format!("nmap: enriched {enriched} hosts"));
}

/// Fold nmap's view of a host into ntok's: service names, version banners,
/// OS guess, and script findings. An nmap `open` verdict upgrades a port
/// ntok couldn't classify; ntok's open ports are never downgraded.
fn merge_host(dst: &mut HostResult, src: HostResult) {
    if dst.os_guess.is_none() {
        dst.os_guess = src.os_guess;
    }
    for sp in src.ports {
        if let Some(dp) = dst
            .ports
            .iter_mut()
            .find(|p| p.port == sp.port && p.protocol == sp.protocol)
        {
            if sp.service.is_some() {
                dp.service = sp.service;
            }
            if sp.banner.is_some() {
                dp.banner = sp.banner;
            }
            if sp.state == PortState::Open && !dp.state.is_open() {
                dp.state = PortState::Open;
                dp.reason = "nmap".into();
            }
        }
    }
    dst.findings.extend(src.findings);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, HostState, PortResult};

    #[test]
    fn merge_upgrades_service_and_keeps_state() {
        let mut dst = HostResult {
            ip: "10.0.0.1".parse().unwrap(),
            hostname: None,
            state: HostState::Up,
            reason: "syn-ack".into(),
            ports: vec![PortResult {
                port: 22,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some("ssh".into()),
                banner: None,
                reason: "syn-ack".into(),
                rtt_ms: None,
            }],
            os_guess: None,
            findings: vec![],
            web_profiles: vec![],
        };
        let src = HostResult {
            ip: dst.ip,
            hostname: None,
            state: HostState::Up,
            reason: "nmap".into(),
            ports: vec![PortResult {
                port: 22,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some("ssh".into()),
                banner: Some("OpenSSH 9.6".into()),
                reason: "nmap".into(),
                rtt_ms: None,
            }],
            os_guess: Some("Linux 6.x".into()),
            findings: vec![Finding {
                tool: "nmap:ssh-hostkey".into(),
                severity: "info".into(),
                port: Some(22),
                detail: "rsa-sha2-512".into(),
            }],
            web_profiles: vec![],
        };
        merge_host(&mut dst, src);
        assert_eq!(dst.ports[0].banner.as_deref(), Some("OpenSSH 9.6"));
        assert_eq!(dst.ports[0].state, PortState::Open);
        assert_eq!(dst.ports[0].reason, "syn-ack"); // not downgraded/overwritten
        assert_eq!(dst.os_guess.as_deref(), Some("Linux 6.x"));
        assert_eq!(dst.findings.len(), 1);
    }
}
