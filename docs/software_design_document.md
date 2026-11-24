# ntok — Software Design Document (SDD)

## 1. Introduction

### 1.1 Purpose
Describes the architecture of ntok: a workspace of three crates — a
library engine (`ntok-core`) and two thin frontends (`ntok-cli`, `ntok-web`).

### 1.2 Scope
Whole system, v0.1.0 as implemented.

### 1.3 Definitions and Acronyms
| Term | Definition |
|------|------------|
| Technique | Scan method: connect / SYN / UDP |
| Probe | One (host, port) liveness test |
| Timing template | `-T0..-T5` preset: concurrency, timeout, retries, pacing |
| Event bus | `tokio::sync::broadcast<ScanEvent>` — engine→frontend seam |
| Privileged feature | Cargo feature `privileged` enabling pnet SYN scan |

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────┐   broadcast<ScanEvent>   ┌──────────────┐
│  ntok-cli   │◄────────────────────────┤              │
│  (clap)     │                         │              │
└─────────────┘                         │              │
                                        │  ntok-core   │
┌─────────────┐   Cx shared state       │  (engine)    │
│  ntok-web   │◄────────────────────────┤              │
│  (topcoat)  │   ScanEntry::snapshot   │              │
└─────────────┘                         └──────┬───────┘
                                               │
        ┌────────────┬────────────┬────────────┼────────────┐
        ▼            ▼            ▼            ▼            ▼
    target.rs    ports.rs    timing.rs   scan/*         report.rs
    (expand)     (portset)   (T0..T5)    connect/udp/syn json/xml/text
```

**Pipeline inside the engine:**

```
TargetSpec[] ──expand──▶ hosts[] ──discover──▶ up-hosts[]
                                                  │
        (host × port) lazy stream ──rate limit── buffer_unordered(N)
                                                  │
                              probe_tcp / probe_udp / syn::run
                                                  │
                                              PortResult ──▶ events, HashMap<Ip, Vec<_>>
                                                  │
                                              ScanReport
```

### 2.2 Design Patterns
- **Strategy**: `ScanTechnique` selects the probe implementation (`connect`,
  `udp`, feature-gated `syn`).
- **Observer**: `ScanEvent` broadcast decouples the engine from both UIs.
- **Template/preset**: `Timing::template(level)` maps nmap `-T0..-T5` to
  `{concurrency, timeout, retries, probe_delay}`.
- **Producer–consumer**: web collector task drains the broadcast into a
  `Snapshot` mutex; pages render snapshots (no locks held across await).
- **Typestate-lite / parse-don't-validate**: `TargetSpec`, port lists, and
  `Timing` are validated at the boundary; engine never sees raw strings.

### 2.3 Technology Stack
| Layer | Technology | Purpose |
|-------|-----------|---------|
| Async runtime | tokio 1 | multi-threaded executor, timers, channels |
| Raw packets | pnet 0.35 (optional) | SYN crafting/reception |
| Concurrency | futures `buffer_unordered`, governor | bounded fan-out + token bucket |
| Targets | ipnet | CIDR parsing/expansion |
| Errors | thiserror 2 (core), anyhow (bins) | typed library errors, app edges |
| Serialization | serde + serde_json | report schema |
| CLI | clap 4 (derive) | argument parsing |
| Web | topcoat 0.12 | server-rendered UI, router, view!, Form/Json, layouts |
| Live UI | htmx 2 (CDN script) | 750 ms fragment polling |

---

## 3. Component Design

### 3.1 ntok-core::target
```
enum TargetSpec { Ip, Net(IpNet), Range(IpAddr, IpAddr), Host(String) }
parse_target(&str) -> Result<TargetSpec>
expand(&[TargetSpec]) -> Result<ExpandedTargets { hosts, names }>
```
- Parse order matters: IP → CIDR → range → hostname.
- Expansion hard-capped at `MAX_HOSTS = 1<<20` — a `/8` can't OOM the process.

### 3.2 ntok-core::ports
```
parse_ports(&str) -> Result<Vec<u16>>  // "22,80", "1-1024", "top:N", "all"
default_ports() -> Vec<u16>            // ~120 common ports
```

### 3.3 ntok-core::timing
```
struct Timing { concurrency, timeout, retries, probe_delay: Option<Duration> }
Timing::template(0..=5) -> Result<Timing>
```
`probe_delay` feeds a `governor` `Quota::with_period` — one token per probe
start; `None` = unthrottled.

### 3.4 ntok-core::engine (the seam)
```
enum ScanTechnique { Connect, Syn, Udp }
struct ScanConfig { targets, ports, technique, timing,
                    skip_discovery, service_probe, verbose, args }
run_scan(cfg, events: broadcast::Sender<ScanEvent>, cancel: CancellationToken)
    -> Result<ScanReport>
```
- **Discovery**: TCP-connect to {80,443,22,445,3389}, ≤2 s each; `Up` on
  success OR `ConnectionRefused` (RST means alive). Bounded 1–256 concurrent.
- **Socket pipeline**: lazy `(host,port)` stream → `buffer_unordered(concurrency)`
  → per-probe `timeout`; results tallied and emitted (`PortFound` for open, or
  all if `verbose`; `Progress` every 64 and at start/end).
- **SYN path**: feature-gated `scan::syn::run` — Layer4 TCP channel, detached
  receiver thread bridged to `tokio::mpsc`, pending-map retry rounds.
- **Cancel**: `CancellationToken` checked per probe; run ends with
  `Err(Cancelled)`.

### 3.5 ntok-core::probe
```
service_name(u16) -> Option<&'static str>   // ~130-port table
grab_banner(&mut TcpStream, port, timeout) -> Option<String>
guess_service(port, banner) -> Option<String>
```
Client-speaks-first probes: `HEAD /` for HTTP ports, `PING` for redis,
`version` for memcached. Banner match (SSH-, HTTP/, +PONG, 220, * OK, RFB)
wins over the port table.

### 3.6 ntok-core::report
```
to_json / to_normal / to_xml  (nmap-compatible <nmaprun>)
write_json / write_normal / write_xml
```

### 3.7 ntok-cli
`clap` derive; converts flags → `ScanConfig`; printer task renders
`ScanEvent`s; output files via `report::*`; Ctrl-C → `CancellationToken`.

### 3.8 ntok-web (topcoat)
```
struct App  { scans: Mutex<HashMap<u64, Arc<ScanEntry>>>, next_id, reports_dir, last_error }
struct ScanEntry { args, meta: Mutex<Meta>, cells: Mutex<HashMap<(Ip,u16,Proto),PortCell>>,
                   log: Mutex<VecDeque<LogLine>>, cancel, report: Mutex<Option<ScanReport>> }
```
- `POST /scans` (Form) → `App::start`: builds `ScanConfig` (verbose=true so
  every port state streams in), inserts entry, spawns collector
  (events→meta/cells/log) + runner (engine→report file).
- `GET /scans/{id}` page embeds `#live` div; `hx-get` polls
  `GET /scans/{id}/ports` (a route returning a `ViewHandle` fragment).
- `GET /scanlist` → history-table fragment, polled every 1s from the index.
- `POST /scans/{id}/stop` → `cancel.cancel()` → 303 back.
- `GET /scans/{id}/report` → `Json<ScanReport>`, 404 until finished.
- Shared state via `Router::builder().with(app)`; `context::<App>(cx)` per request.

**Key design decisions:**
- Snapshot-pull (not event-push) for UI state — the fragment always renders a
  consistent whole; broadcast lag can't corrupt the view. State is split into a
  cheap `Meta` (index rows, stats) and heavier `cells`/`log` (fragment only),
  so the index never clones port maps. Port cells are capped (`MAX_CELLS`), the
  log is a 150-line ring buffer.
- Reports are plain files in `reports/`; no DB — YAGNI for a single-user tool.
- htmx polling chosen over topcoat `sse` — zero client JS to write; noted in
  code as a `shortcut:` comment with the upgrade path.
- Visual system (dark ops console, port-map signature element, IBM Plex
  Sans/Mono, OKLCH tokens) is defined in `DESIGN.md` and embedded as a single
  `<style>` const in the shell — no build step.

---

## 4. Data Models

### 4.1 ScanReport (canonical JSON)
```json
{
  "scanner": "ntok", "version": "0.1.0", "args": "...", "technique": "connect",
  "start_unix": 0, "end_unix": 0, "elapsed_secs": 0.0,
  "hosts": [{
    "ip": "10.0.0.1", "hostname": null, "state": "up|down",
    "reason": "user-set|no-response", "os_guess": null,
    "ports": [{
      "port": 80, "protocol": "tcp|udp",
      "state": "open|closed|filtered|open|filtered",
      "service": "http|null", "banner": "...", "reason": "syn-ack",
      "rtt_ms": 1.2
    }]
  }],
  "summary": { "hosts_up": 0, "hosts_down": 0, "open": 0, "closed": 0, "filtered": 0 }
}
```

### 4.2 ScanEvent (internal bus)
```rust
Started{hosts,ports,technique} | HostDiscovered{ip,up}
| PortFound{ip,port,protocol,state,service}
| Progress{done,total} | Finished{elapsed_secs,open,closed,filtered}
```

---

## 5. State Management

### 5.1 Scan lifecycle (web)
```
[form POST] → Running ──Finished event──▶ Finished (report written)
                 │
                 └──Stop──▶ Cancelled → Failed("scan cancelled") status
```

### 5.2 Port state machine
```
probe ──connect ok─────────▶ open     (reason: syn-ack)
     ├─ConnectionRefused───▶ closed   (reason: conn-refused)
     ├─timeout/error───────▶ filtered (reason: no-response|error)
     └─UDP: ICMP unreach───▶ closed; timeout after retries ─▶ open|filtered
```

---

## 6. Error Handling

### 6.1 Hierarchy
```
ntok_core::Error  (thiserror, one enum)
 ├─ BadTarget / BadPorts / BadTiming   ← boundary validation
 ├─ Dns { host, source }               ← expansion
 ├─ TooManyHosts                       ← expansion cap
 ├─ Cancelled                          ← control flow, not a failure
 ├─ Unsupported                        ← syn w/o feature, IPv6 syn
 ├─ Serialize / Io                     ← reports
```

### 6.2 Propagation
- Library: typed `Result<T, Error>`; binaries use `anyhow` with context.
- Per-probe errors never abort the scan — they fold into `PortResult.state`.
- Web: `RouterErrorExt::ok_or_not_found` maps misses to 404.

---

## 7. Performance Considerations

### 7.1 Multi-threading
- One tokio runtime per process; probes are async tasks, not threads.
- `buffer_unordered(concurrency)` bounds in-flight probes globally.
- governor `RateLimiter` paces probe starts for T0–T2.

### 7.2 Memory Management
- Lazy (host,port) stream — a /16 × 65k scan never materializes the cartesian product.
- Broadcast channel capped at 4096 events; lagged consumers skip, never block.
- `Arc<Vec<u16>>` port list shared across probe closures — no per-task clone.

### 7.3 Scalability Targets
- 1M host expansion cap; 1024 concurrent probes (T5); 256 concurrent discovery.

---

## 8. Security Considerations

- [x] No `unsafe` in the codebase; pnet raw sockets behind a feature.
- [x] No unwrap/panic on data paths (`clippy -D warnings` enforced).
- [x] Web binds localhost; no auth — treat as single-user tool.
- [x] Form inputs validated by the same parsers as the CLI (no raw injection paths; targets can't become shell input — nothing shells out).
- [x] Rate limit + expansion cap bound resource use of hostile input like `/0`.
- [ ] SYN scan sends raw packets — operator responsibility, documented.

---

## 9. Deployment Architecture

### 9.1 Build Process
```
cargo build --release -p ntok-cli    # ntok(.exe)
cargo build --release -p ntok-web    # ntok-web(.exe)
# SYN: --features ntok-core/privileged (needs Npcap SDK on Windows)
```

### 9.2 Distribution
- Single static binaries; `cargo install --path crates/ntok-cli`.
- `reports/` created next to the ntok-web binary at runtime.

---

## 10. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-11-16 | Devin | Initial release |
