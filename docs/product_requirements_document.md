# ntok — Product Requirements Document (PRD)

## 1. Product Vision

### 1.1 Vision Statement
An nmap-grade port scanner that feels native to Rust: library-first engine,
nmap-familiar CLI, and a zero-JS-build browser UI for live results.

### 1.2 Target Users
- **Primary**: security engineers and DevOps running reconnaissance/audits
- **Secondary**: Rust developers embedding a scanner via `ntok-core`
- **Tertiary**: occasional users who prefer a web form over CLI flags

### 1.3 Product Goals
1. Cover the everyday nmap workflow: discovery, port states, service names, reports.
2. Stream results as they arrive — never make the user wait for a whole scan.
3. Keep the privileged path optional; default works with no admin rights.

---

## 2. User Stories

### 2.1 Scanning
1. As a security engineer, I want to scan an IP, CIDR, range, or hostname so that I can target anything nmap can.
2. As a security engineer, I want `top:N` port lists so that fast recon covers common services first.
3. As a DevOps engineer, I want a UDP scan so that I can check DNS/SNMP/NBNS exposure.
4. As a security engineer, I want a SYN scan so that I can scan without completing handshakes (when privileged).
5. As an operator, I want host discovery so that dead hosts don't waste probe budget — and `-Pn` to override it.
6. As a security engineer, I want `-T0..-T5` timing so that I can trade speed for stealth.

### 2.2 Detection & Output
7. As a DevOps engineer, I want `--sV` service detection so that open ports carry names, not just numbers.
8. As an automation author, I want a JSON report so that results feed pipelines without text parsing.
9. As a security engineer, I want nmap-compatible XML so that existing tooling ingests ntok output.

### 2.3 Live feedback & control
10. As a user, I want open ports shown as they're found so that I get signal early.
11. As a user, I want to stop a running scan cleanly (Ctrl-C / Stop button) so that I can abort slow targets.
12. As a web user, I want a scan form and a live results page so that I never touch the terminal.
13. As a web user, I want past scans listed and reports downloadable so that results are shareable.

---

## 3. Functional Specifications

### 3.1 CLI (`ntok scan`)

#### 3.1.1 Target argument(s)
- **Type**: positional, repeatable; comma- or space-separated tokens
- **Behavior**: each token parsed as IP → CIDR → range → hostname (DNS-resolved)
- **Validation**: rejects malformed tokens; expansion capped at ~1M hosts
- **Error**: `invalid target spec: <token>` with exit code 1

#### 3.1.2 `-p/--ports`
- **Grammar**: `22,80,443` | `1-1024` | `top:N` | `all`; tokens mix freely
- **Default**: built-in common-port list (~top 120)
- **Validation**: port 0 and reversed ranges rejected

#### 3.1.3 Technique flags
- `--syn`, `--udp`, default connect. Mutually exclusive; first flag wins ordering not allowed (single technique per run).

#### 3.1.4 Timing
- `-T0..-T5` presets; `--concurrency`, `--timeout-ms`, `--delay-ms` override individually.

#### 3.1.5 Output
- Live: `Discovered open port 135/tcp on 10.0.0.1 (msrpc)` lines, progress counter on stderr.
- Files: `--oJ` JSON, `--oX` nmap XML, `--oN` text; with none, prints text report to stdout.

### 3.2 Web UI (`ntok-web`)

#### 3.2.1 Scan form (`GET /`)
- Fields: targets (required), ports, timing segmented control (T2–T5), technique segmented control, `-sV`, `-Pn` checkboxes.
- Submit → `POST /scans` → 303 redirect to `/scans/{id}`; validation errors redirect back with a banner.
- Below the form: stats strip (total scans, running, open ports found) and a live-updating scan-history table.

#### 3.2.2 Live scan page (`GET /scans/{id}`)
- Header: scan id, `$ ntok <args>` command echo, New scan button.
- `#live` region polls `GET /scans/{id}/ports` every 750 ms via htmx and swaps the fragment:
  status pill + elapsed + Stop, progress bar, open/closed/filtered/probe stats,
  per-host port-state grid ("port map", degrades to a proportion bar past 4096 ports),
  open-ports table, terminal-style log stream, JSON report link.

#### 3.2.3 Report route (`GET /scans/{id}/report`)
- Returns the completed `ScanReport` as JSON; 404 until finished.
- Reports also persisted to `reports/scan-{id}.json`.

#### 3.2.4 Scan list (`GET /` → `GET /scanlist` fragment)
- Table of all scans (id, command, status pill, open count, age), newest first; htmx-polled every 1s.

#### 3.2.5 Design system
- Dark ops-console theme defined in `DESIGN.md` (IBM Plex Sans/Mono, signal-cyan accent = open ports, amber = filtered); zero client JS beyond htmx.

---

## 4. Non-Functional Specifications

### 4.1 Performance
- T4/T5 sustain hundreds of concurrent probes; rate limiting via token bucket.
- Bounded queues everywhere; no unbounded channel in the engine.

### 4.2 Reliability
- Probe timeouts classify as `filtered`, never hang the run.
- Broadcast lag (slow UI consumer) never blocks the scanner.

### 4.3 Usability
- Flag names track nmap (`-p`, `-T`, `-Pn`, `-sV`, `-oX`) so muscle memory transfers.
- Web UI: one form, one results page; dark terminal-style theme.

### 4.4 Compatibility
- Rust ≥1.99 (topcoat requirement); edition 2024.
- Connect/UDP scans: Windows, Linux, macOS, no privileges.
- SYN: `privileged` feature + Npcap (Windows) or root/`CAP_NET_RAW` (Unix); IPv4 only in v1.

---

## 5. User Interface Mockups

### 5.1 Index / scan form
```
+-------------------------------------------------------+
| ntok                                             |
|  Targets  [10.0.0.0/24 host.example        ]          |
|  Ports    [blank = common ports            ]          |
|  Timing   [T3 normal ▼]  Technique [TCP connect ▼]    |
|  [x] Service detection (-sV)  [ ] Skip discovery (-Pn)|
|  [ Scan ]                                             |
|                                                       |
| Scans                                                 |
|  id | args                   | status   | open        |
|   2 | connect 127.0.0.1      | finished | 2           |
|   1 | udp 127.0.0.1          | finished | 1           |
+-------------------------------------------------------+
```

### 5.2 Live scan page
```
+-------------------------------------------------------+
| ← back          Scan #2                               |
| ntok connect 127.0.0.1                    [ Stop ]    |
| status: running — 8/15 probes                         |
|  port | proto | host       | service                  |
|   135 | tcp   | 127.0.0.1  | msrpc                    |
|   445 | tcp   | 127.0.0.1  | microsoft-ds             |
| JSON report                                           |
+-------------------------------------------------------+
```

---

## 6. Acceptance Criteria

### 6.1 Connect scan
```gherkin
Given a host with a listener on port P
When I run `ntok scan <host> -p P`
Then the report marks P "open" with reason "syn-ack"
And other probed ports are "closed" or "filtered"
```

### 6.2 UDP scan
```gherkin
Given a host that sends ICMP port-unreachable for port U
When I run `ntok scan <host> --udp -p U`
Then U reports "closed"; silent ports report "open|filtered"
```

### 6.3 Reports
```gherkin
Given any finished scan
When I pass --oJ out.json and --oX out.xml
Then out.json parses as the canonical ScanReport schema
And out.xml matches nmap's <nmaprun> structure
```

### 6.4 Web live view
```gherkin
Given a running scan started from the form
When the browser polls /scans/{id}/ports
Then open ports appear within ~1s of discovery
And the status shows "finished" with counts when done
```

### 6.5 Cancellation
```gherkin
Given a running scan
When Ctrl-C fires (CLI) or Stop is posted (web)
Then the scan ends with a cancelled error, no partial report marked finished
```

---

## 7. Out of Scope

- Full nmap OS fingerprinting (only a placeholder field exists).
- NSE-style scripting engine.
- ICMP echo / ARP discovery beyond TCP-ping (raw variants need privileges).
- IPv6 SYN scan; UDP protocol-specific payload probes.
- Multi-user auth, TLS, or remote access for the web UI (localhost tool).
- Persistent scan database (reports are files in `reports/`).

---

## 8. Release Criteria

### 8.1 Release Blockers
- [x] `cargo test --workspace` green (9 tests: parsers, probe, live connect)
- [x] `cargo clippy --workspace -- -D warnings` clean
- [x] CLI verified against live localhost ports (open/closed classification)
- [x] Web UI verified end-to-end (form → live fragment → JSON report)

### 8.2 Release Checklist
- [x] README with usage
- [x] docs/{brd,prd,sdd,tdd} generated
- [ ] crates.io publish (optional; binaries installable via `cargo install --path`)

---

## 9. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-11-16 | Devin | Initial release |
