//! `ntok-mcp` — MCP (stdio) server over the ntok engine and index.
//!
//! MCP clients (Claude Desktop, Cursor, Devin, …) spawn this binary and
//! talk JSON-RPC on stdin/stdout — everything log-like therefore goes to
//! stderr only. Read tools query the local index; the `scan` tool sends
//! real packets and exists only behind `--allow-scan` (targets checked
//! against `--scope` / `NTOK_MCP_SCOPE`).

mod http;
mod scope;
mod server;
mod tools;

use clap::Parser;
use rmcp::ServiceExt;
use server::{NtokMcp, Opts};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ntok-mcp",
    version,
    about = "MCP server over the ntok engine and index (stdio)"
)]
struct Args {
    /// Enable the `scan` tool — it sends real packets. Without this flag
    /// ntok-mcp only exposes read tools.
    #[arg(long)]
    allow_scan: bool,
    /// Scan-target scope: CIDRs, hostname globs (*.corp.local), or
    /// `private` (RFC1918+loopback). Comma-separated, repeatable; also
    /// read from NTOK_MCP_SCOPE. Unset = unrestricted.
    #[arg(long)]
    scope: Vec<String>,
    /// Index database path (default: reports/ntok.db, env NTOK_DB).
    #[arg(long)]
    db: Option<PathBuf>,
    /// Directory holding scan-N.json reports.
    #[arg(long, default_value = "reports")]
    reports_dir: PathBuf,
    /// Seconds before a running scan is cancelled.
    #[arg(long, default_value_t = 600)]
    scan_timeout: u64,
    /// Serve MCP over Streamable HTTP at this address instead of stdio —
    /// e.g. `--http 127.0.0.1:3001`. Requires Bearer auth: ntok-web API
    /// tokens (settings → API access) or the NTOK_MCP_TOKEN env secret.
    #[arg(long, value_name = "ADDR")]
    http: Option<std::net::SocketAddr>,
    /// Extra Host header values accepted by --http (loopback names are
    /// always allowed). Repeatable.
    #[arg(long)]
    allowed_host: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // stderr only — stdout is the JSON-RPC channel.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let mut args = Args::parse();
    if args.scope.is_empty()
        && let Ok(env) = std::env::var("NTOK_MCP_SCOPE")
    {
        args.scope = env
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    let opts = Opts {
        allow_scan: args.allow_scan,
        scope: scope::Scope::parse(&args.scope),
        db: args
            .db
            .or_else(|| std::env::var_os("NTOK_DB").map(PathBuf::from)),
        reports_dir: args.reports_dir,
        scan_timeout_secs: args.scan_timeout,
    };
    if opts.allow_scan {
        tracing::info!(scope = ?args.scope, "scan tool enabled");
    }

    if let Some(addr) = args.http {
        return http::serve(opts, addr, args.allowed_host).await;
    }

    let service = NtokMcp::new(opts).serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
