//! MCP server wiring — tool surface over `crate::tools`. Doc comments on
//! the argument structs become the JSON Schema field descriptions the
//! client reads, so they carry the same grammar hints the CLI help does.

use crate::{scope::Scope, tools};
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{
    CallToolResult, ContentBlock, ErrorData as McpError, ProgressNotificationParam,
    ServerCapabilities, ServerConfig,
};
use rmcp::schemars;
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler, tool, tool_handler, tool_router};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

const INSTRUCTIONS: &str = "\
ntok — local-first port scanner and recon index (a local Shodan over the \
operator's own scans). Read tools query the index: `search` uses the \
field:value DSL (service:nginx port:443 net:10.0. tech:wordpress \
risk:high anomaly:high has:tls expired:true selfsigned:true \
favicon:-247388890 finding:cve-2021-41773 sev:high org:cloudflare \
after:YYYY-MM-DD — bare words are full-text over banners/certs/tech). \
`graph` pivots an IP/domain through cert SANs, redirects, assets, DNS \
and CT names. `scans`/`report`/`diff` work on stored reports \
(reports/scan-N.json). `lookup` profiles one site's tech/TLS/company \
live; `subs` enumerates subdomains passively via CT logs (no packets to \
the target). `import` files an nmap -oX / ntok JSON report into the \
index. `scan` sends real packets and only works when the operator \
started ntok-mcp with --allow-scan; targets outside --scope are \
refused. Only scan systems the operator owns or has permission to test.";

#[derive(Clone)]
pub struct NtokMcp {
    opts: Arc<Opts>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

fn text(r: Result<String, String>) -> Result<CallToolResult, McpError> {
    r.map(|s| CallToolResult::success(vec![ContentBlock::text(s)]))
        .map_err(|e| McpError::internal_error(e, None))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchArgs {
    /// Shodan-style query — field:value filters plus bare full-text words.
    /// Fields: ip net port protocol state service product/banner hostname os
    /// asn org server tech status has:banner|tls|web|tech|hostname|os|org|asn|
    /// findings expired selfsigned favicon:<mmh3> finding:<text> sev:<sev>
    /// risk:high|medium|low|<n> anomaly| rare:<band> after|before:<date>.
    /// Empty query lists the most recently seen services.
    pub query: String,
    /// Max hits (default 50, cap 500).
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GraphArgs {
    /// IP or domain to pivot on.
    pub target: String,
    /// Walk depth, 1–3 (default 1). Depth 2+ follows discovered domains
    /// into other hosts that also name them.
    pub depth: Option<u8>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReportArgs {
    /// Scan id, report basename, or path — same operands as `ntok diff`.
    pub id_or_path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DiffArgs {
    /// Older report: scan id, basename under reports/, or path.
    pub a: String,
    /// Newer report: same operand forms.
    pub b: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LookupArgs {
    /// Hostname, host:port, or URL — e.g. `wordpress.org`,
    /// `example.com:8443`, `https://example.com`.
    pub target: String,
    /// Same-origin pages to fetch, 0–8 (default 4 like `ntok lookup`).
    pub crawl: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SubsArgs {
    /// Domain to enumerate — e.g. `example.com`.
    pub domain: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ImportArgs {
    /// Path to an nmap -oX XML or ntok JSON report.
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ScanArgs {
    /// Target tokens: IPs, CIDRs, ranges, hostnames, URLs —
    /// e.g. ["10.0.0.0/24"], ["host.example"], ["10.0.0.1-50"].
    pub targets: Vec<String>,
    /// Port spec: `22,80,443` / `1-1024` / `top:N` / `all`. Default: the
    /// engine's common-port set.
    pub ports: Option<String>,
    /// Timing template 0–5 (default 3). Higher = faster and louder.
    pub timing: Option<u8>,
    /// connect|syn|udp|ack|fin|null|xmas — default connect. Raw
    /// techniques need a privileged build + Npcap/root.
    pub technique: Option<String>,
    /// Scan all targets without probing liveness first (nmap -Pn).
    pub skip_discovery: Option<bool>,
    /// Banner grab / service detection (nmap -sV).
    pub service: Option<bool>,
    /// Website recon on every open HTTP-ish port: headers, TLS cert,
    /// technologies, company, assets.
    pub web: Option<bool>,
    /// Same-origin pages to crawl per profiled site, 0–8 (default 0).
    pub crawl: Option<usize>,
    /// Probe ports in index-history order — ports previously seen open
    /// on this target go first (`ntok scan --adaptive`).
    pub adaptive: Option<bool>,
    /// External tools to merge in: nmap, nuclei, masscan, naabu,
    /// rustscan. Binaries must be on PATH (or NTOK_TOOL_PREFIX);
    /// missing ones degrade to warnings.
    pub tools: Option<Vec<String>>,
    /// Show closed/filtered ports in events (nmap -v).
    pub verbose: Option<bool>,
    /// Max concurrent probes — overrides the timing template.
    pub concurrency: Option<usize>,
    /// Per-probe timeout ms — overrides the timing template.
    pub timeout_ms: Option<u64>,
    /// Min ms between probe starts — 0 means unthrottled (default).
    pub delay_ms: Option<u64>,
}

#[tool_router]
impl NtokMcp {
    pub fn new(opts: Opts) -> Self {
        Self {
            opts: Arc::new(opts),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Index stats — counts of indexed services, hosts and scans in the local ntok index (reports/ntok.db)"
    )]
    async fn stats(&self) -> Result<CallToolResult, McpError> {
        text(tools::stats(&self.opts))
    }

    #[tool(
        description = "Shodan-style search over every service ever indexed — field:value DSL plus full-text. Use for 'what runs nginx', 'expired certs', 'finding cve-…', 'what changed since <date>'"
    )]
    async fn search(
        &self,
        Parameters(SearchArgs { query, limit }): Parameters<SearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        text(tools::search(&self.opts, &query, limit.unwrap_or(50)))
    }

    #[tool(
        description = "Relationship graph pivot — cert SANs, redirect targets, third-party asset hosts, DNS and CT names related to an IP or domain. Destinations already in the index are marked indexed:true"
    )]
    async fn graph(
        &self,
        Parameters(GraphArgs { target, depth }): Parameters<GraphArgs>,
    ) -> Result<CallToolResult, McpError> {
        text(tools::graph(&self.opts, &target, depth.unwrap_or(1)))
    }

    #[tool(
        description = "Stored scan report as JSON — by scan id, reports/ basename, or path. Large reports are capped; use search for targeted queries"
    )]
    async fn report(
        &self,
        Parameters(ReportArgs { id_or_path }): Parameters<ReportArgs>,
    ) -> Result<CallToolResult, McpError> {
        text(tools::report(&self.opts, &id_or_path))
    }

    #[tool(
        description = "List stored scan reports (reports/*.json) newest-first with size and mtime — feed ids to `report` or `diff`"
    )]
    async fn scans(&self) -> Result<CallToolResult, McpError> {
        text(tools::scans(&self.opts))
    }

    #[tool(
        description = "ndiff-style comparison of two reports — appeared/disappeared hosts, port state flips, service and finding changes"
    )]
    async fn diff(
        &self,
        Parameters(DiffArgs { a, b }): Parameters<DiffArgs>,
    ) -> Result<CallToolResult, McpError> {
        text(tools::diff_reports(&self.opts, &a, &b))
    }

    #[tool(
        description = "Import an nmap -oX XML or ntok JSON report into the index — same as `ntok import`"
    )]
    async fn import(
        &self,
        Parameters(ImportArgs { path }): Parameters<ImportArgs>,
    ) -> Result<CallToolResult, McpError> {
        text(tools::import_report(&self.opts, &path))
    }

    #[tool(
        description = "Live single-site tech profile — TLS cert, headers, technologies, company attribution, assets. One site, no port scan; ~1 HTTP fetch plus DNS/RDAP lookups"
    )]
    async fn lookup(
        &self,
        Parameters(LookupArgs { target, crawl }): Parameters<LookupArgs>,
    ) -> Result<CallToolResult, McpError> {
        text(tools::lookup(&target, crawl.unwrap_or(4)).await)
    }

    #[tool(
        description = "Passive subdomain enumeration via crt.sh CT logs — one outbound HTTPS call, zero packets toward the target; found names index as ct edges"
    )]
    async fn subs(
        &self,
        Parameters(SubsArgs { domain }): Parameters<SubsArgs>,
    ) -> Result<CallToolResult, McpError> {
        text(tools::subs(&self.opts, &domain).await)
    }

    #[tool(
        description = "Run a real port scan — sends packets, gated behind --allow-scan and --scope. Returns a summary plus the stored report id; query `report`/`search` afterwards. Only scan systems the operator owns or has permission to test"
    )]
    async fn scan(
        &self,
        Parameters(args): Parameters<ScanArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let progress = context.meta.get_progress_token().map(|token| {
            let peer = context.peer.clone();
            let cb: tools::Progress = std::sync::Arc::new(move |done, total, msg| {
                let peer = peer.clone();
                let token = token.clone();
                let mut p = ProgressNotificationParam::new(token, done).with_total(total);
                if !msg.is_empty() {
                    p = p.with_message(msg);
                }
                tokio::spawn(async move {
                    let _ = peer.notify_progress(p).await;
                });
            });
            cb
        });
        text(
            tools::scan(
                &self.opts,
                progress,
                tools::ScanParams {
                    targets: args.targets,
                    ports: args.ports,
                    timing: args.timing,
                    technique: args.technique,
                    skip_discovery: args.skip_discovery.unwrap_or(false),
                    service: args.service.unwrap_or(false),
                    webscan: args.web.unwrap_or(false),
                    crawl: args.crawl.unwrap_or(0),
                    adaptive: args.adaptive.unwrap_or(false),
                    tools: args.tools.unwrap_or_default(),
                    verbose: args.verbose.unwrap_or(false),
                    concurrency: args.concurrency,
                    timeout_ms: args.timeout_ms,
                    delay_ms: args.delay_ms,
                },
            )
            .await,
        )
    }
}

#[tool_handler]
impl ServerHandler for NtokMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
    }
}

/// Runtime options built from CLI flags + env in main.rs.
#[derive(Clone)]
pub struct Opts {
    /// `--allow-scan` — without it the `scan` tool errors out and no
    /// packets can be sent.
    pub allow_scan: bool,
    /// Target allowlist checked before any scan.
    pub scope: Scope,
    /// Index DB override (default: NTOK_DB or reports/ntok.db).
    pub db: Option<PathBuf>,
    /// Directory holding scan-N.json reports.
    pub reports_dir: PathBuf,
    /// Scan timeout in seconds.
    pub scan_timeout_secs: u64,
}
