use crate::error::{Error, Result};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::net::lookup_host;

/// Safety bound on host expansion (~1M).
const MAX_HOSTS: usize = 1 << 20;

#[derive(Debug, Clone)]
pub enum TargetSpec {
    Ip(IpAddr),
    Net(IpNet),
    Range(IpAddr, IpAddr),
    Host(String),
    /// A website origin (`https://example.com:8443`) — resolved like a
    /// hostname, its port merged into the port plan, and profiled by the
    /// web reconnaissance pass.
    Url(WebTarget),
}

/// A `scheme://host[:port]` website origin parsed from a target token.
#[derive(Debug, Clone)]
pub struct WebTarget {
    /// Normalised origin URL without path/query, e.g. `https://example.com`.
    pub origin: String,
    /// Host for DNS, the Host header and TLS SNI — may be an IP literal.
    pub host: String,
    pub port: u16,
    pub https: bool,
}

/// A URL target after DNS resolution: each address it resolved to.
#[derive(Debug, Clone)]
pub struct ResolvedUrl {
    pub ip: IpAddr,
    pub target: WebTarget,
}

/// Parsed and expanded target set.
pub struct ExpandedTargets {
    pub hosts: Vec<IpAddr>,
    /// Hostnames that resolved to each address, where known.
    pub names: HashMap<IpAddr, String>,
    /// URL targets and the addresses they resolved to.
    pub urls: Vec<ResolvedUrl>,
}

/// Parse one target token: IP, CIDR, range, hostname or URL.
///
/// Accepted forms: `10.0.0.1`, `10.0.0.0/24`, `2001:db8::/64`,
/// `10.0.0.1-10.0.0.50`, `10.0.0.1-50`, `host.example`,
/// `https://example.com`, `http://10.0.0.5:8080`.
pub fn parse_target(s: &str) -> Result<TargetSpec> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::BadTarget("empty target".into()));
    }
    if let Some(t) = parse_url_target(s) {
        return t;
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(TargetSpec::Ip(ip));
    }
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(TargetSpec::Net(net));
    }
    if let Some((a, b)) = s.split_once('-') {
        let lo: IpAddr = a.trim().parse().map_err(|_| Error::BadTarget(s.into()))?;
        let hi = if let Ok(ip) = b.trim().parse::<IpAddr>() {
            ip
        } else {
            // Shorthand: 192.168.1.10-20 extends the last octet.
            let oct: u8 = b.trim().parse().map_err(|_| Error::BadTarget(s.into()))?;
            match lo {
                IpAddr::V4(v4) => {
                    let mut o = v4.octets();
                    o[3] = oct;
                    Ipv4Addr::from(o).into()
                }
                IpAddr::V6(_) => return Err(Error::BadTarget(s.into())),
            }
        };
        if lo.is_ipv4() != hi.is_ipv4() || ip_to_u128(&lo) > ip_to_u128(&hi) {
            return Err(Error::BadTarget(s.into()));
        }
        return Ok(TargetSpec::Range(lo, hi));
    }
    if s.len() <= 253
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Ok(TargetSpec::Host(s.to_string()));
    }
    Err(Error::BadTarget(s.into()))
}

/// `scheme://host[:port][/path]` → `WebTarget`. Only http/https; path and
/// query are dropped — reconnaissance profiles the origin.
fn parse_url_target(s: &str) -> Option<Result<TargetSpec>> {
    if !s.contains("://") {
        return None;
    }
    Some(
        url::Url::parse(s)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https"))
            .and_then(|u| {
                let host = u.host_str()?.to_string();
                let https = u.scheme() == "https";
                let port = u.port_or_known_default()?;
                let origin = match u.port() {
                    Some(p) => format!("{}://{host}:{p}", u.scheme()),
                    None => format!("{}://{host}", u.scheme()),
                };
                Some(TargetSpec::Url(WebTarget {
                    origin,
                    host,
                    port,
                    https,
                }))
            })
            .ok_or_else(|| Error::BadTarget(s.into())),
    )
}

fn ip_to_u128(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v) => u32::from(*v) as u128,
        IpAddr::V6(v) => u128::from(*v),
    }
}

fn u128_to_ip(v: u128, v4: bool) -> IpAddr {
    if v4 {
        Ipv4Addr::from(v as u32).into()
    } else {
        Ipv6Addr::from(v).into()
    }
}

/// Expand specs into concrete addresses, resolving hostnames.
/// Errors past [`MAX_HOSTS`] rather than allocating unboundedly.
pub async fn expand(specs: &[TargetSpec]) -> Result<ExpandedTargets> {
    let mut out = Vec::new();
    let mut names = HashMap::new();
    let mut urls = Vec::new();
    for spec in specs {
        match spec {
            TargetSpec::Ip(ip) => out.push(*ip),
            TargetSpec::Net(net) => {
                for ip in net.hosts() {
                    out.push(ip);
                }
            }
            TargetSpec::Range(lo, hi) => {
                let v4 = lo.is_ipv4();
                let (mut cur, end) = (ip_to_u128(lo), ip_to_u128(hi));
                while cur <= end {
                    out.push(u128_to_ip(cur, v4));
                    cur += 1;
                }
            }
            TargetSpec::Host(name) => {
                for ip in resolve(name, 0).await? {
                    out.push(ip);
                    names.entry(ip).or_insert_with(|| name.clone());
                }
            }
            TargetSpec::Url(w) => {
                if let Ok(ip) = w.host.parse::<IpAddr>() {
                    out.push(ip);
                    urls.push(ResolvedUrl {
                        ip,
                        target: w.clone(),
                    });
                    continue;
                }
                for ip in resolve(&w.host, w.port).await? {
                    out.push(ip);
                    names.entry(ip).or_insert_with(|| w.host.clone());
                    urls.push(ResolvedUrl {
                        ip,
                        target: w.clone(),
                    });
                }
            }
        }
        if out.len() > MAX_HOSTS {
            return Err(Error::TooManyHosts(MAX_HOSTS));
        }
    }
    out.sort();
    out.dedup();
    Ok(ExpandedTargets {
        hosts: out,
        names,
        urls,
    })
}

/// Resolve a hostname to its addresses; [`Error::Dns`] when none.
async fn resolve(name: &str, port: u16) -> Result<Vec<IpAddr>> {
    let addrs: Vec<IpAddr> = lookup_host((name, port))
        .await
        .map_err(|e| Error::Dns {
            host: name.into(),
            source: e,
        })?
        .map(|sa| sa.ip())
        .collect();
    if addrs.is_empty() {
        return Err(Error::Dns {
            host: name.into(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses"),
        });
    }
    Ok(addrs)
}

/// Reverse-DNS (PTR) via the system `nslookup` — reaches internal DNS
/// where a stub resolver would, on both Windows and Unix. Degrades to
/// `None` on any failure; never a scan error.
pub async fn reverse_lookup(ip: IpAddr) -> Option<String> {
    let out = tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        tokio::process::Command::new("nslookup")
            .arg(ip.to_string())
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // Windows prints "Name:    host.example"; bind prints "name = host.example.".
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("Name:")
                .or_else(|| l.strip_prefix("name ="))
                .or_else(|| l.strip_prefix("Name ="))
                .map(str::trim)
        })
        .next_back()
        .map(|n| n.trim_end_matches('.').to_string())
        .filter(|n| !n.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_cidr_range() {
        assert!(matches!(
            parse_target("10.0.0.1").unwrap(),
            TargetSpec::Ip(_)
        ));
        assert!(matches!(
            parse_target("10.0.0.0/24").unwrap(),
            TargetSpec::Net(_)
        ));
        assert!(matches!(
            parse_target("10.0.0.1-10").unwrap(),
            TargetSpec::Range(_, _)
        ));
        assert!(matches!(
            parse_target("example.com").unwrap(),
            TargetSpec::Host(_)
        ));
        assert!(parse_target("not a host!").is_err());
    }

    #[tokio::test]
    async fn expands_range_and_cidr() {
        let t = expand(&[
            parse_target("10.0.0.1-3").unwrap(),
            parse_target("127.0.0.1").unwrap(),
        ])
        .await
        .unwrap();
        assert_eq!(t.hosts.len(), 4);
        let t = expand(&[parse_target("10.0.0.0/30").unwrap()])
            .await
            .unwrap();
        assert_eq!(t.hosts.len(), 2); // .1 and .2; network+broadcast skipped
    }
}
