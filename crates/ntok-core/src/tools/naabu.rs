//! naabu (ProjectDiscovery) as a discovery + open-port stage — same role
//! as masscan: it SYN-sweeps the target set and hands back open
//! `(ip, port)` pairs the engine then verifies/enriches. Lighter to set
//! up than masscan; its default `-scan-type syn` still needs raw-socket
//! privileges (Npcap/root), falling back degrades to ntok discovery.
//!
//! Invoked as `naabu -host <csv> -p <ports> -rate <pps> -json -silent`;
//! output is one JSON object per line on stdout:
//! `{"host":"1.2.3.4","ip":"1.2.3.4","port":443,"protocol":"tcp"}`.

use super::masscan::{ports_arg, rate, spec_arg};
use super::{ToolConfig, ToolKind};
use crate::engine::ScanConfig;
use crate::error::Result;
use serde::Deserialize;
use std::net::IpAddr;

/// Run naabu over the config's targets and ports. Returns open TCP
/// ports found, sorted.
pub async fn scan(cfg: &ScanConfig, tcfg: &ToolConfig) -> Result<Vec<(IpAddr, u16)>> {
    let targets = cfg
        .targets
        .iter()
        .map(spec_arg)
        .collect::<Vec<_>>()
        .join(",");
    let args = vec![
        "-host".into(),
        targets,
        "-p".into(),
        ports_arg(&cfg.ports),
        "-rate".into(),
        rate(&cfg.timing).to_string(),
        "-json".into(),
        "-silent".into(),
    ];
    let out = tcfg.run(ToolKind::Naabu.prog(), &args).await?;
    Ok(parse(&out))
}

#[derive(Deserialize)]
struct Obs {
    /// `ip` on current releases; `host` carries the same value on older
    /// ones (and is the literal for hostname targets).
    ip: Option<IpAddr>,
    host: Option<String>,
    port: u16,
    protocol: Option<String>,
}

fn parse(lines: &str) -> Vec<(IpAddr, u16)> {
    let mut found: Vec<(IpAddr, u16)> = lines
        .lines()
        .filter_map(|l| {
            let o: Obs = serde_json::from_str(l.trim()).ok()?;
            if matches!(&o.protocol, Some(p) if p != "tcp") {
                return None;
            }
            let ip =
                o.ip.or_else(|| o.host.as_deref().and_then(|h| h.parse().ok()))?;
            Some((ip, o.port))
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_naabu_json_lines() {
        let out = parse(
            "{\"host\":\"10.0.0.1\",\"ip\":\"10.0.0.1\",\"port\":443,\"protocol\":\"tcp\"}\n\
             {\"host\":\"10.0.0.1\",\"ip\":\"10.0.0.1\",\"port\":80,\"protocol\":\"tcp\"}\n\
             {\"host\":\"10.0.0.2\",\"port\":53,\"protocol\":\"udp\"}\n\
             not json\n",
        );
        assert_eq!(
            out,
            vec![
                ("10.0.0.1".parse().unwrap(), 80),
                ("10.0.0.1".parse().unwrap(), 443),
            ]
        );
    }
}
