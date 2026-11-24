# ntok — Technical Design Document (TDD)

## 1. Technical Overview

### 1.1 System Description
Cargo workspace of three crates implementing an nmap-style scanner:
`ntok-core` (engine library), `ntok-cli` (`ntok` binary), `ntok-web`
(Topcoat server-rendered UI). Rust 1.99+, edition 2024, MIT OR Apache-2.0.

### 1.2 Technical Objectives
- Async, bounded, cancellable probe fan-out with per-probe timeouts.
- nmap-compatible surface: targets, ports, `-T` timing, states, XML output.
- A single event seam (`broadcast<ScanEvent>`) both UIs consume.

---

## 2. Technology Stack

### 2.1 Core Dependencies (workspace)
| Package | Version | Purpose |
|---------|---------|---------|
| tokio | 1 | runtime, net, sync, time, signal |
| tokio-util | 0.7 | `CancellationToken` |
| futures | 0.3 | `buffer_unordered` fan-out |
| governor | 0.10 | token-bucket probe pacing |
| ipnet | 2 | CIDR parse/expand |
| serde / serde_json | 1 | report schema |
| thiserror | 2 | `ntok_core::Error` |
| pnet | 0.35 (opt) | raw SYN send/receive |
| clap | 4 | CLI derive parser |
| anyhow | 1 | bin error edge |
| tracing + subscriber | 0.1/0.3 | CLI diagnostics (RUST_LOG) |
| topcoat | 0.12 | web framework (ntok-web only) |

### 2.2 External Requirements
- Windows: Npcap SDK only to *link* the `privileged` build; Npcap driver + admin to *run* SYN.
- Unix: root or `CAP_NET_RAW` for SYN.
- Rust ≥1.99 (topcoat MSRV), edition 2024.

---

## 3. API Definitions

### 3.1 Engine entry point
```rust
pub async fn run_scan(
    cfg: ScanConfig,
    events: broadcast::Sender<ScanEvent>,
    cancel: CancellationToken,
) -> Result<ScanReport>
```
- `events`: best-effort broadcast (cap 4096); `send` errors ignored.
- `cancel`: checked before each probe and in the collect loop; exits `Err(Error::Cancelled)`.

```rust
pub struct ScanConfig {
    pub targets: Vec<TargetSpec>,
    pub ports: Vec<u16>,            // default_ports() ~top120
    pub technique: ScanTechnique,   // Connect | Syn | Udp
    pub timing: Timing,
    pub skip_discovery: bool,       // nmap -Pn
    pub service_probe: bool,        // nmap -sV
    pub verbose: bool,              // emit non-open PortFound too
    pub args: String,
}
impl ScanConfig { pub fn new(targets: Vec<TargetSpec>) -> Self /* T3 defaults */ }
```

```rust
pub struct Timing {
    pub concurrency: usize,        // in-flight cap
    pub timeout: Duration,         // per-probe
    pub retries: u32,              // extra rounds on filtered/no-response
    pub probe_delay: Option<Duration>, // min interval between starts
}
impl Timing { pub fn template(level: u8) -> Result<Timing> }
```

| Level | Concurrency | Timeout | Retries | Delay |
|-------|------------|---------|---------|-------|
| T0 | 1 | 30 s | 2 | 300 s |
| T1 | 1 | 15 s | 2 | 15 s |
| T2 | 4 | 10 s | 2 | 400 ms |
| T3 | 256 | 3 s | 1 | — |
| T4 | 512 | 1.25 s | 1 | — |
| T5 | 1024 | 400 ms | 0 | — |

### 3.2 Parsers
```rust
pub fn parse_target(s: &str) -> Result<TargetSpec>
// "10.0.0.1" | "10.0.0.0/24" | "10.0.0.1-10.0.0.50" | "10.0.0.1-50" | "host.example"
pub async fn expand(specs: &[TargetSpec]) -> Result<ExpandedTargets>
// resolves Host via lookup_host; caps at MAX_HOSTS = 1<<20

pub fn parse_ports(spec: &str) -> Result<Vec<u16>>
// "22,80" | "1-1024" | "top:N" | "all"; sorted, deduped, non-empty
```

### 3.3 Probes
```rust
async fn probe_tcp(ip, port, timing, service_probe) -> PortResult
// Ok(connect) → Open"syn-ack"; ConnectionRefused → Closed"conn-refused";
// timeout/other → Filtered. Retries only Filtered results.
// On Open: reuses the stream for grab_banner when service_probe.

async fn probe_udp(ip, port, timing, service_probe) -> PortResult
// connected UdpSocket; recv data → Open; ConnectionReset → Closed;
// timeout × retries → OpenFiltered.

#[cfg(feature="privileged")]
async fn syn::run(hosts, ports, timing) -> Result<Vec<(IpAddr, PortResult)>>
// Layer4(Tcp) transport channel; SYN → SYN/ACK=Open, RST=Closed, pending→Filtered.
// IPv4 only; detached receiver thread → tokio::mpsc bridge.
```

### 3.4 Reports
```rust
pub fn to_json(&ScanReport) -> Result<String>
pub fn to_normal(&ScanReport) -> String   // -oN style
pub fn to_xml(&ScanReport) -> String      // <nmaprun> compatible
pub fn write_{json,normal,xml}(&ScanReport, &Path) -> Result<()>
```

### 3.5 Web routes (ntok-web)
| Method | Path | Handler | Response |
|--------|------|---------|----------|
| GET | `/` | `index` (page) | form + scan list |
| POST | `/scans` | `start_scan` (`Form<ScanForm>`) | 303 → `/scans/{id}` |
| GET | `/scans/{id}` | `scan_page` (page) | live view shell |
| GET | `/scans/{id}/ports` | `ports_fragment` | `ViewHandle` fragment |
| POST | `/scans/{id}/stop` | `stop_scan` | 303 → `/scans/{id}` |
| GET | `/scans/{id}/report` | `report_route` | `Json<ScanReport>` / 404 |

---

## 4. Data Flow

### 4.1 Scan run (connect/UDP)
```
parse_target ×N ─▶ expand ─▶ Vec<IpAddr>            (+names map)
        │
        ├─ skip_discovery? ──no──▶ TCP-ping {80,443,22,445,3389} @≤256 conc
        │                          up = connect-ok OR conn-refused
        ▼
   stream::iter(up)
     .flat_map(host × ports)          // lazy cartesian via Arc<Vec<u16>>
     .map(|(ip,p)| limiter.await; probe(ip,p))  // governor token per probe
     .buffer_unordered(concurrency)
        │
        ▼ per PortResult
     tally summary; emit PortFound (open || verbose); HashMap<Ip,Vec<_>> push
     every 64 results / at 0 and total → emit Progress
        │
        ▼
   HostResult[] (+down hosts) → ScanReport → Finished event
```

### 4.2 Web scan lifecycle
```
POST /scans ─▶ App::start ─▶ insert ScanEntry(id) ─▶ spawn collector(rx→Snapshot)
                                       └▶ spawn runner(run_scan→write_json→status)
browser #live div ─hx every 750ms─▶ GET /scans/{id}/ports ─▶ render Snapshot clone
POST /scans/{id}/stop ─▶ cancel.cancel() ─▶ runner Err(Cancelled) → status Failed
```

### 4.3 Event→Snapshot mapping
```
PortFound{open} → snapshot.open_ports.push
Progress        → done/total
Finished        → counts + elapsed (status → Finished set by runner)
```

---

## 5. Implementation Guidelines

### 5.1 Thread Safety
- Shared web state in `std::sync::Mutex` — locks taken for copy-out only,
  never held across `.await` (see `ScanEntry::snap()`).
- Poisoned locks recovered via `lock().unwrap_or_else(|e| e.into_inner())`.
- `ScanConfig`/`Timing` are `Clone`-cheap value objects passed by ref.

### 5.2 Error Handling Strategy
- `thiserror` enum in the library; `anyhow::Context` at CLI edges.
- No `unwrap`/`expect`/`panic!` on data paths — enforced by
  `cargo clippy --workspace -- -D warnings`.
- Probe failures degrade to `PortResult.state`, never abort the run.

### 5.3 Logging
- `tracing` + `tracing-subscriber` with `EnvFilter` (default `warn`) in CLI.
- Web prints nothing per-request (topcoat handles errors → 500).

### 5.4 Configuration
- No config files: all knobs are CLI flags / form fields → `ScanConfig`.
- Web report dir: `./reports/` (created on boot).

---

## 6. Testing Strategy

### 6.1 Unit Tests (implemented)
| Component | Coverage | Key Scenarios |
|-----------|----------|---------------|
| `ports` | grammar + edge cases | lists, ranges, top:N, all, 0/garbage/reverse-range |
| `target` | parse + expand | IP/CIDR/range/host, broadcast skip, shorthand range |
| `probe` | service guess | SSH/HTTP/redis banners, port fallback, unknown |
| `connect` | live localhost | open (banner+service), closed (conn-refused) |

### 6.2 Integration (manual-verified)
- `ntok scan 127.0.0.1 -p top:15 --sV` → real open ports classified correctly.
- `ntok scan 127.0.0.1 --udp -p 135,137,9999` → closed vs open|filtered split.
- Web: POST → live fragment → finished → JSON report (curl-verified).

### 6.3 Performance smoke
- T5 localhost scan completes under ephemeral-port pressure; discovery bounded at 256.

---

## 7. Build and Deployment

### 7.1 Build Configuration
```toml
[profile.release]
lto = "thin"
codegen-units = 1
```
```sh
cargo build --release -p ntok-cli -p ntok-web
cargo build -p ntok-cli --features ntok-core/privileged   # SYN build
```

### 7.2 Platform Notes
- **Windows**: connect/UDP fully work; SYN build links `Packet.lib` (Npcap SDK)
  at final-link time and needs the Npcap driver + admin at runtime.
- **Linux/macOS**: SYN needs root/`CAP_NET_RAW`; everything else unprivileged.
- IPv6: supported in target parsing and connect/UDP probes; SYN is IPv4-only v1.

---

## 8. Version Control

### 8.1 Branch Strategy
- `main` always builds; feature branches for new techniques.

### 8.2 Commit Convention
- Conventional commits (`feat:`, `fix:`, `docs:`); keep engine commits free of UI changes and vice versa.

---

## 9. Security Checklist

- [x] No `unsafe`; no shell invocation anywhere.
- [x] All network timeouts bounded; no unbounded waits or channels.
- [x] Input validation at boundary (`parse_target`, `parse_ports`, `Form`).
- [x] Report output XML-escaped (`& < > " '`).
- [x] htmx loaded from pinned CDN version (`htmx.org@2.0.10`).
- [ ] Consider SRI hash on the htmx script tag for integrity.
- [ ] SYN scan needs operator authorization (documented usage warning).

---

## 10. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-11-16 | Devin | Initial release |
