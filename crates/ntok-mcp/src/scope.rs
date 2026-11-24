//! Scan-target allowlist for the gated `scan` tool — the trust boundary
//! between an agent that can *ask* and packets actually leaving the
//! machine. Spec entries (`--scope` / `NTOK_MCP_SCOPE`, comma-separated):
//! CIDRs (`10.0.0.0/8`, `192.168.0.0/16`, a bare IP), hostname globs
//! (`corp.local`, `*.corp.local`), and the `private` keyword covering
//! RFC1918 + loopback + link-local + ULA. No spec at all means
//! unrestricted — passing `--allow-scan` alone is consent.

use ipnet::IpNet;
use ntok_core::target::{TargetSpec, WebTarget};
use std::net::IpAddr;

#[derive(Debug, Default, Clone)]
pub struct Scope {
    /// No spec was given — every target is allowed.
    any: bool,
    /// `private` keyword — RFC1918, loopback, link-local, ULA.
    private: bool,
    nets: Vec<IpNet>,
    globs: Vec<String>,
}

impl Scope {
    pub fn parse(entries: &[String]) -> Self {
        let mut s = Self::default();
        for entry in entries.iter().flat_map(|e| e.split(',')) {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if entry.eq_ignore_ascii_case("private") {
                s.private = true;
            } else if let Ok(net) = entry.parse::<IpNet>() {
                // Catches bare IPs too — IpNet treats them as host routes.
                s.nets.push(net);
            } else {
                s.globs.push(entry.trim_end_matches('.').to_lowercase());
            }
        }
        s.any = s.nets.is_empty() && s.globs.is_empty() && !s.private;
        s
    }

    fn ip_ok(&self, ip: &IpAddr) -> bool {
        self.any || (self.private && is_private(ip)) || self.nets.iter().any(|n| n.contains(ip))
    }

    fn name_ok(&self, name: &str) -> bool {
        self.any || self.globs.iter().any(|g| glob_match(g, name))
    }

    /// A scanned net must sit entirely inside one scope net — partially
    /// covered is refused.
    fn net_ok(&self, net: &IpNet) -> bool {
        if self.any {
            return true;
        }
        let (lo, hi) = (net.network(), net.broadcast());
        (self.private && is_private(&lo) && is_private(&hi))
            || self.nets.iter().any(|s| s.contains(&lo) && s.contains(&hi))
    }

    /// Check every spec before a scan runs. Hostnames that don't match a
    /// glob are resolved; every address they resolve to must be in scope.
    pub async fn check(&self, specs: &[TargetSpec]) -> Result<(), String> {
        for spec in specs {
            match spec {
                TargetSpec::Ip(ip) => self.need_ip(ip)?,
                TargetSpec::Net(n) => {
                    if !self.net_ok(n) {
                        return Err(format!("target {n} is outside MCP scope"));
                    }
                }
                TargetSpec::Range(a, b) => {
                    self.need_ip(a)?;
                    self.need_ip(b)?;
                }
                TargetSpec::Host(h) => self.check_host(h).await?,
                TargetSpec::Url(WebTarget { host, .. }) => self.check_host(host).await?,
            }
        }
        Ok(())
    }

    fn need_ip(&self, ip: &IpAddr) -> Result<(), String> {
        if self.ip_ok(ip) {
            Ok(())
        } else {
            Err(format!("target {ip} is outside MCP scope"))
        }
    }

    async fn check_host(&self, name: &str) -> Result<(), String> {
        if let Ok(ip) = name.parse::<IpAddr>() {
            return self.need_ip(&ip);
        }
        if self.name_ok(name) {
            return Ok(());
        }
        // Not glob-matched: resolve, then require every address in scope —
        // a name alone can't be trusted to keep pointing at it.
        let addrs: Vec<IpAddr> = tokio::net::lookup_host((name, 80))
            .await
            .map(|it| it.map(|a| a.ip()).collect())
            .unwrap_or_default();
        if addrs.is_empty() {
            return Err(format!(
                "target {name} does not match MCP scope and failed to resolve"
            ));
        }
        if let Some(ip) = addrs.iter().find(|ip| !self.ip_ok(ip)) {
            return Err(format!("target {name} resolves to {ip}, outside MCP scope"));
        }
        Ok(())
    }
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// `*.corp.local` matches `corp.local` and any depth of subdomain; a
/// bare name matches exactly. Case-insensitive, trailing dot ignored.
fn glob_match(pat: &str, name: &str) -> bool {
    let name = name.trim_end_matches('.').to_lowercase();
    if let Some(rest) = pat.strip_prefix("*.") {
        name == rest || name.ends_with(&format!(".{rest}"))
    } else {
        pat == name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(spec: &str) -> Scope {
        Scope::parse(&[spec.to_string()])
    }

    fn spec(s: &str) -> TargetSpec {
        ntok_core::target::parse_target(s).unwrap()
    }

    #[tokio::test]
    async fn private_scope() {
        let s = scope("private");
        assert!(s.check(&[spec("10.0.0.5")]).await.is_ok());
        assert!(s.check(&[spec("192.168.1.0/24")]).await.is_ok());
        assert!(s.check(&[spec("127.0.0.1")]).await.is_ok());
        assert!(s.check(&[spec("8.8.8.8")]).await.is_err());
        assert!(s.check(&[spec("0.0.0.0/0")]).await.is_err());
    }

    #[tokio::test]
    async fn cidr_and_glob() {
        let s = scope("10.1.0.0/16,*.corp.local");
        assert!(s.check(&[spec("10.1.2.3")]).await.is_ok());
        assert!(s.check(&[spec("10.1.0.0/24")]).await.is_ok());
        assert!(s.check(&[spec("10.2.0.0/24")]).await.is_err());
        assert!(s.check(&[spec("db.corp.local")]).await.is_ok());
        assert!(s.check(&[spec("corp.local")]).await.is_ok());
        assert!(s.check(&[spec("corp.local.evil.com")]).await.is_err());
    }

    #[tokio::test]
    async fn empty_is_unrestricted() {
        assert!(Scope::parse(&[]).check(&[spec("8.8.8.8")]).await.is_ok());
    }

    #[tokio::test]
    async fn url_target_uses_its_host() {
        let s = scope("10.0.0.0/8");
        assert!(s.check(&[spec("https://10.0.0.9:8443")]).await.is_ok());
        assert!(s.check(&[spec("https://9.9.9.9")]).await.is_err());
    }
}
