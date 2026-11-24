//! RustScan as a discovery + open-port stage — same role as masscan and
//! naabu: it connect-scans with adaptive batching and hands back open
//! `(ip, port)` pairs the engine then verifies/enriches. Overlaps ntok's
//! own connect engine, but useful for parity and for environments where
//! the RustScan binary is what's installed.
//!
//! Invoked as `rustscan -a <csv> -p|-r <ports> -b <batch> -t <ms> -g
//! --scripts none` — greppable output is `1.2.3.4 -> [80,443]` lines;
//! `--scripts none` keeps it from chaining into nmap afterwards.

use super::masscan::spec_arg;
use super::{ToolConfig, ToolKind};
use crate::engine::ScanConfig;
use crate::error::Result;
use std::net::IpAddr;

/// Run RustScan over the config's targets and ports. Returns open TCP
/// ports found, sorted.
pub async fn scan(cfg: &ScanConfig, tcfg: &ToolConfig) -> Result<Vec<(IpAddr, u16)>> {
    let targets = cfg
        .targets
        .iter()
        .map(spec_arg)
        .collect::<Vec<_>>()
        .join(",");
    let mut args = vec![
        "-a".into(),
        targets,
        "-b".into(),
        batch(&cfg.timing).to_string(),
        "-t".into(),
        cfg.timing.timeout.as_millis().to_string(),
        "-g".into(),
        "--scripts".into(),
        "none".into(),
    ];
    // `-r` takes a single contiguous range; `-p` a comma list. A sorted
    // port plan that is contiguous (incl. `all` = 1-65535) uses `-r` so
    // argv stays short.
    match contiguous(&cfg.ports) {
        Some((lo, hi)) => args.extend(["-r".into(), format!("{lo}-{hi}")]),
        None => args.extend([
            "-p".into(),
            cfg.ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ]),
    }
    let out = tcfg.run(ToolKind::Rustscan.prog(), &args).await?;
    Ok(parse(&out))
}

/// RustScan's batch size — its equivalent of our concurrency cap.
fn batch(t: &crate::timing::Timing) -> u32 {
    (t.concurrency as u32 * 10).clamp(1_024, 65_535)
}

/// `Some((lo, hi))` when the sorted unique ports form `lo..=hi`.
fn contiguous(ports: &[u16]) -> Option<(u16, u16)> {
    let mut s: Vec<u16> = ports.to_vec();
    s.sort_unstable();
    s.dedup();
    match (s.first(), s.last()) {
        (Some(&lo), Some(&hi)) if s.len() == (hi - lo) as usize + 1 => Some((lo, hi)),
        _ => None,
    }
}

/// Greppable lines: `1.2.3.4 -> [80,443]`.
fn parse(out: &str) -> Vec<(IpAddr, u16)> {
    let mut found = Vec::new();
    for line in out.lines() {
        let Some((ip, ports)) = line.trim().split_once(" -> ") else {
            continue;
        };
        let Ok(ip) = ip.trim().parse::<IpAddr>() else {
            continue;
        };
        for p in ports
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
        {
            if let Ok(port) = p.trim().parse::<u16>() {
                found.push((ip, port));
            }
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_greppable() {
        let out = parse("10.0.0.1 -> [22,80,443]\n10.0.0.2 -> []\nnoise\n");
        assert_eq!(
            out,
            vec![
                ("10.0.0.1".parse().unwrap(), 22),
                ("10.0.0.1".parse().unwrap(), 80),
                ("10.0.0.1".parse().unwrap(), 443),
            ]
        );
    }

    #[test]
    fn detects_contiguous_ranges() {
        assert_eq!(contiguous(&[1, 2, 3, 4]), Some((1, 4)));
        assert_eq!(contiguous(&[80]), Some((80, 80)));
        assert_eq!(contiguous(&[22, 443]), None);
    }
}
