use crate::advisor::{self, PlanAdvice, PlanRequest, ScanAdvisor};
use crate::error::{Error, Result};
use crate::event::ScanEvent;
use crate::model::{HostResult, HostState, PortResult, PortState, ScanReport, ScanSummary};
use crate::scan::PortProber;
use crate::target::{TargetSpec, expand, reverse_lookup};
use crate::timing::Timing;
use crate::tools::{self, ToolConfig, ToolKind};
use crate::web;
use futures::stream::{self, StreamExt};
use governor::{Quota, RateLimiter};
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanTechnique {
    /// TCP connect() scan. Unprivileged, works everywhere.
    Connect,
    /// Raw SYN scan (-sS). Requires `privileged` feature + Npcap/root.
    Syn,
    /// Connected-socket UDP scan. Unprivileged.
    Udp,
    /// Raw ACK scan (-sA): maps firewall rules — unfiltered vs filtered.
    /// Requires `privileged`.
    Ack,
    /// Raw FIN scan (-sF): RST → closed, silence → open|filtered.
    /// Requires `privileged`.
    Fin,
    /// Raw NULL scan (-sN): no flags. Requires `privileged`.
    Null,
    /// Raw Xmas scan (-sX): FIN+PSH+URG. Requires `privileged`.
    Xmas,
}

impl ScanTechnique {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Syn => "syn",
            Self::Udp => "udp",
            Self::Ack => "ack",
            Self::Fin => "fin",
            Self::Null => "null",
            Self::Xmas => "xmas",
        }
    }

    /// Per-port prober for socket-level techniques; raw-packet scans run
    /// their own tx/rx loop and return `None`. Add new modules in
    /// `crate::scan` and register them here.
    fn prober(self) -> Option<&'static dyn PortProber> {
        match self {
            Self::Connect => Some(&crate::scan::connect::ConnectScan),
            Self::Udp => Some(&crate::scan::udp::UdpScan),
            _ => None,
        }
    }
}

pub struct ScanConfig {
    pub targets: Vec<TargetSpec>,
    pub ports: Vec<u16>,
    pub technique: ScanTechnique,
    pub timing: Timing,
    /// Scan every target without probing liveness first (nmap `-Pn`).
    pub skip_discovery: bool,
    /// Grab banners / identify services (nmap `-sV`).
    pub service_probe: bool,
    /// Emit `PortFound` for closed/filtered ports too (nmap `-v`).
    pub verbose: bool,
    /// Optional scan advisor (AI or heuristic). Defaults to a no-op —
    /// the deterministic path. See `crate::advisor`.
    pub advisor: Arc<dyn ScanAdvisor>,
    /// External tools to run: `Masscan` replaces discovery, `Nmap` and
    /// `Nuclei` enrich the report after the engine finishes. Missing
    /// binaries degrade to warnings. See `crate::tools`.
    pub tools: Vec<ToolKind>,
    /// Prefix prepended to every tool invocation — e.g.
    /// `wsl -d kali-linux --` to run tools inside WSL2. Empty = PATH.
    /// `NTOK_TOOL_PREFIX` env is the fallback when left empty.
    pub tool_prefix: Vec<String>,
    /// Website reconnaissance: profile HTTP(S) endpoints after the port
    /// scan (headers, TLS cert, company, technologies, assets). URL
    /// targets are profiled regardless of this flag.
    pub web_scan: bool,
    /// Same-origin pages to fetch per profiled site (0 = homepage only).
    /// Inner pages often carry tech the homepage doesn't.
    pub web_crawl: usize,
    /// Echo of the invocation, stored in the report.
    pub args: String,
}

impl ScanConfig {
    pub fn new(targets: Vec<TargetSpec>) -> Self {
        Self {
            targets,
            ports: crate::ports::default_ports(),
            technique: ScanTechnique::Connect,
            timing: Timing::template(3).expect("T3 is a valid template"),
            skip_discovery: false,
            service_probe: false,
            verbose: false,
            advisor: advisor::null_advisor(),
            tools: Vec::new(),
            tool_prefix: Vec::new(),
            web_scan: false,
            web_crawl: 0,
            args: String::new(),
        }
    }
}

/// Ports probed during host discovery (nmap-like: a few likely-answered ports).
const DISCOVERY_PORTS: [u16; 5] = [80, 443, 22, 445, 3389];

/// Run a full scan. Emits [`ScanEvent`]s on `events`; honour `cancel` for a
/// clean early stop. Returns the finished report.
pub async fn run_scan(
    mut cfg: ScanConfig,
    events: broadcast::Sender<ScanEvent>,
    cancel: CancellationToken,
) -> Result<ScanReport> {
    crate::ensure_crypto_provider();
    let start = Instant::now();
    let started_unix = unix_secs();
    let expanded = expand(&cfg.targets).await?;

    // URL targets contribute their port to the plan and to discovery —
    // a site that doesn't answer the usual ports still gets scanned.
    let mut url_ports: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    for r in &expanded.urls {
        url_ports.entry(r.ip).or_default().push(r.target.port);
        if !cfg.ports.contains(&r.target.port) {
            cfg.ports.push(r.target.port);
        }
    }
    if !expanded.urls.is_empty() {
        cfg.ports.sort_unstable();
        cfg.ports.dedup();
    }

    // Advisor planning pass — no-op under NullAdvisor. Clamped and applied
    // before `Started` so event counts reflect the real plan.
    let advice = cfg
        .advisor
        .plan(&PlanRequest {
            hosts: expanded.hosts.len(),
            ports: cfg.ports.len(),
            port_sample: cfg.ports.iter().take(64).copied().collect(),
            technique: cfg.technique.as_str(),
            concurrency: cfg.timing.concurrency,
            timeout_ms: cfg.timing.timeout.as_millis() as u64,
            retries: cfg.timing.retries,
            service_probe: cfg.service_probe,
        })
        .await;
    apply_advice(&mut cfg, advice, &events);

    emit(
        &events,
        ScanEvent::Started {
            hosts: expanded.hosts.len(),
            ports: cfg.ports.len(),
            technique: cfg.technique.as_str(),
        },
    );

    // Compile the service-probe regex DB in the background — banner
    // matching hits it lazily per port, so warm it while connect scans
    // are still in flight.
    if cfg.service_probe {
        tokio::task::spawn_blocking(crate::svcdb::warm);
    }

    let mut tcfg = ToolConfig::from_env();
    if !cfg.tool_prefix.is_empty() {
        tcfg.prefix = cfg.tool_prefix.clone();
    }

    // Optional external discovery: masscan/naabu/rustscan return open
    // (ip, port) pairs and stand in for ntok's discovery entirely. The
    // port plan narrows to what was found open — the engine then
    // verifies/enriches just those ports.
    let tool_found = tools::external_discovery(&cfg, &tcfg, &events).await;
    if let Some(found) = &tool_found {
        let mut union: Vec<u16> = found.iter().map(|(_, p)| *p).collect();
        union.sort_unstable();
        union.dedup();
        cfg.ports = union;
    }

    // Host discovery.
    let discovered = if let Some(found) = &tool_found {
        let up: std::collections::HashSet<IpAddr> = found.iter().map(|(ip, _)| *ip).collect();
        expanded
            .hosts
            .iter()
            .map(|ip| (*ip, up.contains(ip)))
            .collect()
    } else if cfg.skip_discovery {
        expanded
            .hosts
            .iter()
            .map(|ip| (*ip, true))
            .collect::<Vec<_>>()
    } else {
        discover(&expanded.hosts, &cfg, &url_ports, &events, &cancel).await
    };

    let up: Vec<IpAddr> = discovered
        .iter()
        .filter(|(_, up)| *up)
        .map(|(ip, _)| *ip)
        .collect();

    // Reverse DNS for up hosts we didn't get a name for — reaches
    // internal DNS where stub resolvers stop, bounded and silent on miss.
    let ptr: HashMap<IpAddr, String> = stream::iter(
        up.iter()
            .copied()
            .filter(|ip| !expanded.names.contains_key(ip))
            .collect::<Vec<_>>(),
    )
    .map(|ip| async move { reverse_lookup(ip).await.map(|n| (ip, n)) })
    .buffer_unordered(32)
    .filter_map(|x| async { x })
    .collect()
    .await;
    // Results accumulate per host indexed by position in `up` — a flat
    // Vec instead of a HashMap<IpAddr, _>: probe results land at a
    // direct index, no hash probe per result.
    let up_idx: HashMap<IpAddr, usize> = up.iter().enumerate().map(|(i, ip)| (*ip, i)).collect();
    let cap_per_host = cfg.ports.len().min(256);
    let mut host_ports: Vec<Vec<PortResult>> = (0..up.len())
        .map(|_| Vec::with_capacity(cap_per_host))
        .collect();
    let mut summary = ScanSummary {
        hosts_up: up.len(),
        hosts_down: discovered.len() - up.len(),
        ..ScanSummary::default()
    };

    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }

    // Raw scans also return per-host OS hints from reply TTL/window.
    let os_hints: HashMap<IpAddr, String> = match cfg.technique.prober() {
        Some(prober) => {
            run_socket_scan(
                &cfg,
                prober,
                &up,
                &mut host_ports,
                &mut summary,
                &events,
                &cancel,
            )
            .await;
            HashMap::new()
        }
        None => {
            #[cfg(feature = "privileged")]
            {
                use crate::scan::raw::{self, RawTechnique};
                let rt = match cfg.technique {
                    ScanTechnique::Syn => RawTechnique::Syn,
                    ScanTechnique::Ack => RawTechnique::Ack,
                    ScanTechnique::Fin => RawTechnique::Fin,
                    ScanTechnique::Null => RawTechnique::Null,
                    ScanTechnique::Xmas => RawTechnique::Xmas,
                    _ => unreachable!("prober() returned None for a socket technique"),
                };
                let (results, hints) = raw::run(&up, &cfg.ports, &cfg.timing, rt).await?;
                for (ip, r) in results {
                    tally(&mut summary, r.state);
                    maybe_emit_port(&cfg, &events, ip, &r);
                    if let Some(&i) = up_idx.get(&ip) {
                        host_ports[i].push(r);
                    }
                }
                hints
            }
            #[cfg(not(feature = "privileged"))]
            {
                return Err(Error::Unsupported(
                    "raw scan: rebuild with --features privileged",
                ));
            }
        }
    };

    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }

    let hosts: Vec<HostResult> = discovered
        .into_iter()
        .map(|(ip, up)| HostResult {
            ip,
            hostname: expanded
                .names
                .get(&ip)
                .cloned()
                .or_else(|| ptr.get(&ip).cloned()),
            state: if up { HostState::Up } else { HostState::Down },
            reason: if tool_found.is_some() {
                "external".into()
            } else if up {
                "user-set".into()
            } else {
                "no-response".into()
            },
            ports: {
                let mut p = up_idx
                    .get(&ip)
                    .map(|&i| std::mem::take(&mut host_ports[i]))
                    .unwrap_or_default();
                p.sort_by_key(|r| (r.port, r.protocol));
                p
            },
            os_guess: os_hints.get(&ip).cloned(),
            findings: Vec::new(),
            web_profiles: Vec::new(),
        })
        .collect();

    let elapsed = start.elapsed().as_secs_f64();
    let mut report = ScanReport {
        scanner: "ntok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        args: cfg.args.clone(),
        technique: cfg.technique.as_str().into(),
        start_unix: started_unix,
        end_unix: unix_secs(),
        elapsed_secs: elapsed,
        hosts,
        summary,
    };

    // External-tool enrichment (nmap -sV, nuclei) mutates the report in
    // place before the advisor comments on it.
    if cfg
        .tools
        .iter()
        .any(|t| matches!(t, ToolKind::Nmap | ToolKind::Nuclei))
    {
        tools::enrich(&mut report, &cfg.tools, &tcfg, &events).await;
    }

    // Website reconnaissance — explicit URL targets always; every open
    // HTTP-ish port too when `web_scan` was requested.
    if cfg.web_scan || !expanded.urls.is_empty() {
        web::enrich(
            &mut report,
            &expanded.urls,
            cfg.web_scan,
            &events,
            &cancel,
            &cfg.advisor,
            cfg.web_crawl,
        )
        .await;
    }

    // Post-scan advisor commentary — emitted before Finished so frontends
    // that stop reading at Finished still see it.
    if let Some(text) = cfg.advisor.analyze(&report).await {
        emit(&events, ScanEvent::Note { text });
    }

    emit(
        &events,
        ScanEvent::Finished {
            elapsed_secs: elapsed,
            open: report.summary.open,
            closed: report.summary.closed,
            filtered: report.summary.filtered,
            unfiltered: report.summary.unfiltered,
        },
    );

    Ok(report)
}

/// Clamp and apply whatever the advisor suggested; narrate via `Note`.
fn apply_advice(cfg: &mut ScanConfig, advice: PlanAdvice, events: &broadcast::Sender<ScanEvent>) {
    let mut notes: Vec<String> = Vec::new();
    if let Some(mut ports) = advice.ports {
        ports.retain(|p| *p != 0);
        ports.sort_unstable();
        ports.dedup();
        ports.truncate(u16::MAX as usize);
        if !ports.is_empty() && ports != cfg.ports {
            notes.push(format!("ports {} -> {}", cfg.ports.len(), ports.len()));
            cfg.ports = ports;
        }
    }
    if let Some(c) = advice.concurrency {
        cfg.timing.concurrency = c.clamp(1, 4096);
    }
    if let Some(t) = advice.timeout {
        cfg.timing.timeout = t.clamp(Duration::from_millis(50), Duration::from_secs(60));
    }
    if let Some(r) = advice.rationale {
        notes.push(r);
    }
    if !notes.is_empty() {
        emit(
            events,
            ScanEvent::Note {
                text: format!("advisor: {}", notes.join("; ")),
            },
        );
    }
}

/// TCP-ping each host on a few common ports — plus, in a `privileged` build,
/// an ICMP echo sweep (nmap -PE). A refused connection still means the host
/// is up; only silence means down.
async fn discover(
    hosts: &[IpAddr],
    cfg: &ScanConfig,
    url_ports: &HashMap<IpAddr, Vec<u16>>,
    events: &broadcast::Sender<ScanEvent>,
    cancel: &CancellationToken,
) -> Vec<(IpAddr, bool)> {
    let timeout = cfg.timing.timeout.min(Duration::from_secs(2));
    let conc = cfg.timing.concurrency.clamp(1, 256);
    let tcp: Vec<(IpAddr, bool)> = stream::iter(hosts.iter().copied())
        .map(|ip| async move {
            let mut up = false;
            if !cancel.is_cancelled() {
                let extra = url_ports.get(&ip).map(Vec::as_slice).unwrap_or(&[]);
                for port in DISCOVERY_PORTS.into_iter().chain(extra.iter().copied()) {
                    match tokio::time::timeout(timeout, TcpStream::connect((ip, port))).await {
                        Ok(Ok(_)) => {
                            up = true;
                            break;
                        }
                        Ok(Err(e)) => {
                            if e.kind() == io::ErrorKind::ConnectionRefused {
                                up = true;
                                break;
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            (ip, up)
        })
        .buffer_unordered(conc)
        .collect()
        .await;

    #[cfg(feature = "privileged")]
    let icmp: std::collections::HashSet<IpAddr> =
        crate::scan::ping::sweep(hosts, timeout, cfg.timing.retries)
            .await
            .unwrap_or_default(); // no raw socket? TCP ping alone still works
    #[cfg(not(feature = "privileged"))]
    let icmp: std::collections::HashSet<IpAddr> = std::collections::HashSet::new();

    let merged: Vec<(IpAddr, bool)> = tcp
        .into_iter()
        .map(|(ip, up)| (ip, up || icmp.contains(&ip)))
        .collect();
    for (ip, up) in &merged {
        emit(events, ScanEvent::HostDiscovered { ip: *ip, up: *up });
    }
    merged
}

/// The shared pipeline for socket-level techniques: a lazily-built
/// (host, port) stream, rate-limited, bounded-concurrency fan-out through a
/// [`PortProber`], with nmap-style adaptive timeouts shrinking toward the
/// observed RTT.
async fn run_socket_scan(
    cfg: &ScanConfig,
    prober: &'static dyn PortProber,
    up: &[IpAddr],
    host_ports: &mut [Vec<PortResult>],
    summary: &mut ScanSummary,
    events: &broadcast::Sender<ScanEvent>,
    cancel: &CancellationToken,
) {
    let ports = Arc::new(cfg.ports.clone());
    let total = up.len() * ports.len();
    emit(events, ScanEvent::Progress { done: 0, total });
    let done = AtomicUsize::new(0);
    let adaptive = AdaptiveTimeout::new(&cfg.timing);
    let limiter = cfg
        .timing
        .probe_delay
        .and_then(|d| Quota::with_period(d).map(RateLimiter::direct))
        .map(Arc::new);

    let mut stream = stream::iter(up.iter().copied().enumerate())
        .flat_map(move |(hi, ip)| {
            let ports = Arc::clone(&ports);
            stream::iter((0..ports.len()).map(move |i| (hi, ip, ports[i])))
        })
        .map(|(hi, ip, port)| {
            let limiter = limiter.clone();
            let adaptive = &adaptive;
            async move {
                if cancel.is_cancelled() {
                    return None;
                }
                if let Some(l) = &limiter {
                    l.until_ready().await;
                }
                if cancel.is_cancelled() {
                    return None;
                }
                let mut timing = cfg.timing;
                timing.timeout = adaptive.current();
                let r = prober.probe(ip, port, &timing, cfg.service_probe).await;
                if let Some(rtt) = r.rtt_ms {
                    adaptive.observe(rtt);
                }
                Some((hi, ip, r))
            }
        })
        .buffer_unordered(cfg.timing.concurrency);

    while let Some(item) = stream.next().await {
        if cancel.is_cancelled() {
            break;
        }
        let n = done.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some((hi, ip, r)) = item {
            tally(summary, r.state);
            maybe_emit_port(cfg, events, ip, &r);
            host_ports[hi].push(r);
        }
        if n.is_multiple_of(64) || n == total {
            emit(events, ScanEvent::Progress { done: n, total });
        }
    }
}

/// nmap-style adaptive timeout: tracks an EMA of observed connect RTTs and
/// shrinks the effective probe timeout toward ~4x it, bounded below by
/// `MIN_TIMEOUT` and above by the configured timeout. On a fast LAN a T3
/// scan drops from 3000ms waits to ~100ms — the difference between a
/// filtered port costing seconds and costing nothing.
struct AdaptiveTimeout {
    /// EMA of RTT in microseconds, stored as f64 bits.
    ema_us: AtomicU64,
    min: Duration,
    max: Duration,
}

const MIN_TIMEOUT: Duration = Duration::from_millis(100);

impl AdaptiveTimeout {
    fn new(t: &Timing) -> Self {
        Self {
            ema_us: AtomicU64::new((t.timeout.as_secs_f64() * 1e6).to_bits()),
            min: MIN_TIMEOUT.min(t.timeout),
            max: t.timeout,
        }
    }

    fn observe(&self, rtt_ms: f64) {
        let sample = rtt_ms * 1e3;
        let _ = self
            .ema_us
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |bits| {
                let ema = f64::from_bits(bits);
                Some((0.8 * ema + 0.2 * sample).to_bits())
            });
    }

    fn current(&self) -> Duration {
        let ema = f64::from_bits(self.ema_us.load(Ordering::Relaxed));
        Duration::from_secs_f64(
            (ema * 4.0 / 1e6).clamp(self.min.as_secs_f64(), self.max.as_secs_f64()),
        )
    }
}

fn tally(summary: &mut ScanSummary, state: PortState) {
    match state {
        PortState::Open | PortState::OpenFiltered => summary.open += 1,
        PortState::Closed => summary.closed += 1,
        PortState::Filtered => summary.filtered += 1,
        PortState::Unfiltered => summary.unfiltered += 1,
    }
}

fn maybe_emit_port(
    cfg: &ScanConfig,
    events: &broadcast::Sender<ScanEvent>,
    ip: IpAddr,
    r: &PortResult,
) {
    if r.state.responded() || cfg.verbose {
        emit(
            events,
            ScanEvent::PortFound {
                ip,
                port: r.port,
                protocol: r.protocol,
                state: r.state,
                service: r.service.clone(),
            },
        );
    }
}

fn emit(events: &broadcast::Sender<ScanEvent>, ev: ScanEvent) {
    // Lagged or absent receivers are fine — events are best-effort.
    let _ = events.send(ev);
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}
