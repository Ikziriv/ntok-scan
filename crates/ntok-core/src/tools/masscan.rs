//! masscan as the scan's discovery + open-port stage: it SYN-sweeps the
//! target set at wire speed and hands back open `(ip, port)` pairs. The
//! engine then probes only those ports for service detection — masscan
//! finds, ntok verifies.
//!
//! Output is `--output-format json` on stdout: one object per
//! `{ip, ports:[{port, proto, status}]}` observation.

use super::{ToolConfig, ToolKind};
use crate::engine::ScanConfig;
use crate::error::Result;
use crate::target::TargetSpec;
use serde::Deserialize;
use std::net::IpAddr;

/// Run masscan over the config's targets and ports. Returns open TCP
/// ports found, sorted.
pub async fn scan(cfg: &ScanConfig, tcfg: &ToolConfig) -> Result<Vec<(IpAddr, u16)>> {
    let mut args: Vec<String> = cfg.targets.iter().map(spec_arg).collect();
    args.push(format!("-p{}", ports_arg(&cfg.ports)));
    args.push(format!("--rate={}", rate(&cfg.timing)));
    args.extend(["-oJ".into(), "-".into()]);

    let out = tcfg.run(ToolKind::Masscan.prog(), &args).await?;
    let mut found = parse(&out);
    found.sort_unstable();
    found.dedup();
    Ok(found)
}

pub(crate) fn spec_arg(spec: &TargetSpec) -> String {
    match spec {
        TargetSpec::Ip(ip) => ip.to_string(),
        TargetSpec::Net(net) => net.to_string(),
        TargetSpec::Range(lo, hi) => format!("{lo}-{hi}"),
        TargetSpec::Host(name) => name.clone(),
        TargetSpec::Url(w) => w.host.clone(),
    }
}

/// `22,80-90,443` — range-compressed so big `-p all` plans stay a short argv.
pub(crate) fn ports_arg(ports: &[u16]) -> String {
    let mut sorted: Vec<u16> = ports.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = String::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i];
        let mut end = start;
        while i + 1 < sorted.len() && sorted[i + 1] == end + 1 {
            i += 1;
            end = sorted[i];
        }
        if !out.is_empty() {
            out.push(',');
        }
        if start == end {
            out.push_str(&start.to_string());
        } else {
            out.push_str(&format!("{start}-{end}"));
        }
        i += 1;
    }
    out
}

/// Timing → packets/sec. `probe_delay` maps directly; otherwise a rate
/// proportional to the concurrency cap.
pub(crate) fn rate(t: &crate::timing::Timing) -> u64 {
    match t.probe_delay {
        Some(d) => (1000 / d.as_millis().max(1)) as u64,
        None => (t.concurrency as u64 * 20).clamp(1_000, 100_000),
    }
}

// ---------- masscan JSON output ----------

#[derive(Deserialize)]
struct Obs {
    ip: IpAddr,
    ports: Vec<PObs>,
}

#[derive(Deserialize)]
struct PObs {
    port: u16,
    proto: String,
    status: String,
}

fn parse(json: &str) -> Vec<(IpAddr, u16)> {
    // masscan -oJ emits a JSON array (a trailing comma before ] is a
    // known quirk — tolerate it by parsing line-wise objects as a
    // fallback).
    if let Ok(obs) = serde_json::from_str::<Vec<Obs>>(json.trim()) {
        return collect(obs);
    }
    let obs: Vec<Obs> = json
        .lines()
        .filter_map(|l| {
            let l = l
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches(',');
            (!l.is_empty())
                .then(|| serde_json::from_str::<Obs>(l).ok())
                .flatten()
        })
        .collect();
    collect(obs)
}

fn collect(obs: Vec<Obs>) -> Vec<(IpAddr, u16)> {
    obs.into_iter()
        .flat_map(|o| {
            o.ports
                .into_iter()
                .filter(|p| p.proto == "tcp" && p.status == "open")
                .map(move |p| (o.ip, p.port))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_masscan_json() {
        let json = r#"[
            {"ip":"10.0.0.1","timestamp":"1731700000","ports":[{"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":64}]},
            {"ip":"10.0.0.1","timestamp":"1731700000","ports":[{"port":443,"proto":"tcp","status":"open","reason":"syn-ack","ttl":64}]},
            {"ip":"10.0.0.2","timestamp":"1731700000","ports":[{"port":53,"proto":"udp","status":"open","reason":"response","ttl":64}]}
        ]"#;
        let got = parse(json);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&("10.0.0.1".parse().unwrap(), 80)));
        assert!(got.contains(&("10.0.0.1".parse().unwrap(), 443)));
    }

    #[test]
    fn compresses_port_ranges() {
        assert_eq!(ports_arg(&[22, 80, 81, 82, 443]), "22,80-82,443");
        assert_eq!(ports_arg(&[80]), "80");
        assert_eq!(ports_arg(&[]), "");
    }
}
