use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    /// UDP probes that get no reply can't distinguish open from filtered.
    #[serde(rename = "open|filtered")]
    OpenFiltered,
    /// ACK-scan (-sA) verdict: the port is reachable through the firewall —
    /// nmap can't and doesn't call it open or closed.
    Unfiltered,
}

impl PortState {
    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::OpenFiltered)
    }
    /// The host answered the probe — worth surfacing even when `-v` is off.
    pub fn responded(self) -> bool {
        self.is_open() || self == Self::Unfiltered
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
            Self::OpenFiltered => "open|filtered",
            Self::Unfiltered => "unfiltered",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<String>,
    pub banner: Option<String>,
    /// Why the state was decided (e.g. "syn-ack", "conn-refused", "no-response").
    /// `Cow` so the common static reasons cost no allocation per port.
    pub reason: Cow<'static, str>,
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostState {
    Up,
    Down,
}

/// Something an external tool (nmap script, nuclei template, …) reported
/// about a host or port. Kept as free text — tools have their own
/// severity vocabularies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Which tool produced it ("nmap:ssl-cert", "nuclei", "masscan").
    pub tool: String,
    /// Tool's severity word ("info", "low", "medium", "high", "critical").
    pub severity: String,
    /// Port the finding attaches to, when the tool scopes it to one.
    pub port: Option<u16>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub state: HostState,
    pub reason: String,
    pub ports: Vec<PortResult>,
    pub os_guess: Option<String>,
    /// External-tool findings (nmap scripts, nuclei, …). Empty for a
    /// plain ntok scan.
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// Website reconnaissance profiles — one per HTTP(S) endpoint that
    /// answered during a `--web` scan. Empty for port-only scans.
    #[serde(default)]
    pub web_profiles: Vec<WebProfile>,
}

// ---------- website reconnaissance ----------

/// One hop in a redirect chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectHop {
    pub status: u16,
    pub location: String,
}

/// TLS certificate + handshake details for an HTTPS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub protocol: String,
    /// Leaf certificate subject common name.
    pub subject_cn: Option<String>,
    /// Subject organisation (`O=`).
    pub org: Option<String>,
    pub issuer_cn: Option<String>,
    pub issuer_org: Option<String>,
    /// RFC 3339 validity bounds.
    pub not_before: String,
    pub not_after: String,
    /// Subject alternative names — sibling domains, internal hostnames.
    #[serde(default)]
    pub san: Vec<String>,
    pub expired: bool,
    /// Leaf == issuer, i.e. likely internal/self-signed PKI.
    pub self_signed: bool,
}

/// Security-relevant response headers and a simple 0–6 score of how many
/// of the main hardening headers are present.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityHeaders {
    pub hsts: Option<String>,
    pub csp: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: Option<String>,
    pub referrer_policy: Option<String>,
    /// `Access-Control-Allow-Origin` — only interesting when permissive.
    pub cors_origin: Option<String>,
    /// Count of hsts/csp/xfo/xcto/referrer/permissions-policy present.
    pub score: u8,
}

/// One DNS record surfaced during recon (MX/NS/TXT, bounded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub kind: String,
    pub value: String,
}

/// Who runs this site — from RDAP, the cert org, page metadata and DNS.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompanyInfo {
    /// Organisation names found (RDAP entity, cert O=, JSON-LD org,
    /// og:site_name), de-duplicated in priority order.
    #[serde(default)]
    pub names: Vec<String>,
    /// Domain registrar (RDAP), when the target is a domain.
    pub registrar: Option<String>,
    /// IP block owner (RDAP on the address) — the hosting company/ISP.
    pub ip_org: Option<String>,
    /// ASN + announced prefix owner, e.g. "AS13335 Cloudflare".
    pub asn: Option<String>,
    /// MX/NS/TXT hints, bounded.
    #[serde(default)]
    pub dns: Vec<DnsRecord>,
    /// SaaS providers claimed via TXT verification tokens
    /// ("google", "stripe", "atlassian", "hubspot", …).
    #[serde(default)]
    pub saas: Vec<String>,
    /// `/.well-known/security.txt` is published.
    pub security_txt: bool,
}

/// A detected technology (Wappalyzer-style) with the signals that matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    /// Primary category — "CMS" | "JavaScript frameworks" | "Web servers" | …
    pub category: String,
    /// All category names the fingerprint declares.
    #[serde(default)]
    pub categories: Vec<String>,
    pub version: Option<String>,
    /// Every signal that produced a hit — "header server", "meta
    /// generator", "script src", "dom", "js wp.ajax", "dns TXT", …
    /// (deserialized from the legacy single-string form too).
    #[serde(default, deserialize_with = "string_or_vec")]
    pub evidence: Vec<String>,
    /// Highest confidence of any matched pattern (0–100).
    #[serde(default)]
    pub confidence: u8,
    /// Added via another technology's `implies`, not a direct signal.
    #[serde(default)]
    pub implied: bool,
    #[serde(default)]
    pub cpe: Option<String>,
    /// Hosted/SaaS technology (per the fingerprint DB).
    #[serde(default)]
    pub saas: bool,
    #[serde(default)]
    pub oss: bool,
    #[serde(default)]
    pub website: Option<String>,
}

/// `evidence` was a single string before it became a list — accept both
/// when loading older reports.
fn string_or_vec<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<OneOrMany>::deserialize(d)? {
        Some(OneOrMany::One(s)) => vec![s],
        Some(OneOrMany::Many(v)) => v,
        None => Vec::new(),
    })
}

/// A web asset referenced by the page (script/style/media/font/doc/…).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAsset {
    /// "script" | "style" | "image" | "font" | "media" | "link" | "form" | "api"
    pub kind: String,
    pub url: String,
    /// Asset's host when it differs from the page host (CDN, third party).
    pub host: Option<String>,
    pub content_type: Option<String>,
    pub bytes: Option<u64>,
}

/// robots.txt summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RobotsInfo {
    pub present: bool,
    #[serde(default)]
    pub sitemaps: Vec<String>,
    /// Distinct Disallow paths — a rough hidden-surface hint.
    #[serde(default)]
    pub disallows: Vec<String>,
}

/// The full reconnaissance profile for one HTTP(S) endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebProfile {
    /// URL that was requested (origin, no path).
    pub url: String,
    /// URL after following redirects.
    pub final_url: String,
    /// Final response status; 0 when no response was received.
    pub status: u16,
    pub http_version: String,
    /// Milliseconds to response headers on the final request.
    pub ttfb_ms: u64,
    #[serde(default)]
    pub redirects: Vec<RedirectHop>,
    pub server: Option<String>,
    pub powered_by: Option<String>,
    /// All response headers on the final response (lowercased names).
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub security: SecurityHeaders,
    pub tls: Option<TlsInfo>,
    #[serde(default)]
    pub company: CompanyInfo,
    #[serde(default)]
    pub technologies: Vec<Technology>,
    #[serde(default)]
    pub assets: Vec<WebAsset>,
    /// Distinct third-party hosts referenced by assets.
    #[serde(default)]
    pub external_domains: Vec<String>,
    /// API-ish paths found in JS/HTML (`/api/`, `/graphql`, …), bounded.
    #[serde(default)]
    pub api_hints: Vec<String>,
    #[serde(default)]
    pub robots: Option<RobotsInfo>,
    /// Shodan-style mmh3 hash of `/favicon.ico`, when fetched — pivot
    /// key for `http.favicon.hash:` lookups.
    #[serde(default)]
    pub favicon_mmh3: Option<i32>,
    /// Set when profiling partially failed (connection refused, timeout,
    /// TLS error). The profile may still carry partial data.
    pub error: Option<String>,
    /// Optional AI advisor commentary on this stack. Never persisted —
    /// advisor output doesn't enter reports.
    #[serde(skip)]
    pub ai_note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub hosts_up: usize,
    pub hosts_down: usize,
    pub open: usize,
    pub closed: usize,
    pub filtered: usize,
    pub unfiltered: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scanner: String,
    pub version: String,
    pub args: String,
    pub technique: String,
    pub start_unix: u64,
    pub end_unix: u64,
    pub elapsed_secs: f64,
    pub hosts: Vec<HostResult>,
    pub summary: ScanSummary,
}
