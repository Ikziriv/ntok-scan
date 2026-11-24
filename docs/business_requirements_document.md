# ntok — Business Requirements Document (BRD)

## 1. Executive Summary

### 1.1 Project Overview
ntok is an nmap-style port scanner written in pure Rust. It provides a fast
async scanning engine (`tokio` + `pnet`) packaged two ways: a standalone CLI
(`ntok`) and an optional browser UI (`ntok-web`, built on the tokio team's
Topcoat framework) that triggers scans, shows open ports in real time, and
organizes scan reports.

### 1.2 Business Problem
- Nmap is powerful but C-based, awkward to embed, and heavyweight for simple
  automation pipelines.
- Teams who live in the Rust/tokio ecosystem lack a native, embeddable scanner
  library with a clean event API.
- Ad-hoc scanning from a terminal produces no shareable artifact; results are
  lost when the shell closes.

### 1.3 Business Opportunity
- A library-first engine (`ntok-core`) lets other Rust tools embed scanning
  without shelling out to nmap.
- A browser UI lowers the barrier for occasional users and produces persistent,
  shareable JSON/XML reports.
- Memory-safe Rust eliminates a class of vulnerabilities found in C-based
  scanners and reduces maintenance cost.

---

## 2. Business Objectives

### 2.1 Primary Objectives
| Objective | Success Metric | Target |
|-----------|---------------|--------|
| Deliver nmap-equivalent core scanning | Techniques implemented | TCP connect, UDP, SYN |
| Match nmap output conventions | Report formats | JSON, nmap XML, text |
| Provide real-time feedback | Event latency | <1s from probe to UI |
| Stay embeddable | Engine crate deps | No CLI/web deps in `ntok-core` |

### 2.2 Secondary Objectives
- Timing parity with nmap `-T0..-T5` so scan politeness is predictable.
- Zero-privilege default path (connect scan) so the tool runs anywhere.
- Single-binary distribution for both CLI and web UI.

---

## 3. Stakeholder Requirements

### 3.1 Primary Stakeholders

#### 3.1.1 Security engineer / pentester
- **Role**: runs ad-hoc reconnaissance
- **Needs**: nmap-compatible flags, output ingested by existing tooling (XML)
- **Pain Points**: nmap scripting friction; wants a scriptable alternative
- **Success Criteria**: `ntok scan` covers daily-driver nmap usage

#### 3.1.2 DevOps / platform engineer
- **Role**: automates network checks in pipelines
- **Needs**: machine-readable output (JSON), non-interactive CLI, exit codes
- **Pain Points**: parsing nmap's text output is brittle
- **Success Criteria**: `ntok scan --oJ report.json` drops into CI jobs

#### 3.1.3 Occasional user / helpdesk
- **Role**: checks "is the port open?" sporadically
- **Needs**: a web form, live feedback, saved reports
- **Pain Points**: can't remember CLI flags
- **Success Criteria**: runs a scan in a browser without reading a man page

#### 3.1.4 Rust developer (library consumer)
- **Role**: embeds scanning in a larger tool
- **Needs**: typed `ScanConfig`/`ScanReport`, event channel, no panics
- **Success Criteria**: `run_scan(cfg, tx, cancel)` integrates in <50 lines

### 3.2 Stakeholder Matrix
| Stakeholder | Influence | Interest | Engagement Strategy |
|-------------|-----------|----------|-------------------|
| Security engineer | High | High | nmap-compatible flags + XML |
| DevOps engineer | Medium | High | JSON reports, stable exit codes |
| Occasional user | Low | Medium | Web UI, no-install feel |
| Rust developer | Medium | Medium | docs.rs-quality API, events |

---

## 4. Functional Requirements

### 4.1 Scanning Engine
| ID | Requirement | Priority |
|----|------------|----------|
| FR-01 | Parse targets: IP, CIDR, ranges (`a-b`, `a.b.c.d-e`), hostnames | Must Have |
| FR-02 | Parse port specs: lists, ranges, `top:N`, `all` | Must Have |
| FR-03 | TCP connect scan (unprivileged default) | Must Have |
| FR-04 | UDP scan via connected-socket ICMP detection | Must Have |
| FR-05 | SYN scan via pnet (feature-gated, privileged) | Should Have |
| FR-06 | Host discovery with `-Pn` skip option | Must Have |
| FR-07 | Timing templates T0–T5 + manual overrides | Must Have |
| FR-08 | Service detection via banner grab + port table (`--sV`) | Should Have |
| FR-09 | Live event stream (started/port/progress/finished) | Must Have |
| FR-10 | Cancellation token for clean stop | Must Have |

### 4.2 Reporting
| ID | Requirement | Priority |
|----|------------|----------|
| FR-11 | JSON report (canonical format) | Must Have |
| FR-12 | nmap-compatible XML output (`--oX`) | Should Have |
| FR-13 | nmap-style text output (`--oN`) | Should Have |

### 4.3 CLI
| ID | Requirement | Priority |
|----|------------|----------|
| FR-14 | `ntok scan` subcommand with nmap-like flags | Must Have |
| FR-15 | Live "Discovered open port" lines + progress | Must Have |
| FR-16 | Ctrl-C graceful cancel | Must Have |

### 4.4 Web UI
| ID | Requirement | Priority |
|----|------------|----------|
| FR-17 | Scan form (targets, ports, timing, technique, -sV, -Pn) | Must Have |
| FR-18 | Live open-ports view during a running scan | Must Have |
| FR-19 | Stop a running scan | Should Have |
| FR-20 | Per-scan JSON report download + `reports/` archive | Must Have |
| FR-21 | Scan history list on the index page | Should Have |

---

## 5. Non-Functional Requirements

### 5.1 Performance
| ID | Requirement | Target |
|----|------------|--------|
| NFR-01 | Concurrent probes | ≥1024 in-flight (T5) |
| NFR-02 | Rate limiting | Token bucket, ms-resolution pacing |
| NFR-03 | Bounded memory | All work queues bounded; expansion cap 1M hosts |

### 5.2 Usability
- nmap flag familiarity: `-p`, `-T`, `-Pn`, `-sV`, `--oN/-oX/-oJ`.
- Web UI needs zero setup beyond `cargo run`.

### 5.3 Reliability
- No panics on data paths; all failures typed (`Result`/`Option`).
- Timeouts produce `filtered`, never a hang.

### 5.4 Compatibility
- Windows + Unix for unprivileged techniques; SYN needs Npcap/root.

---

## 6. Success Metrics and KPIs

### 6.1 Operational Metrics
| Metric | Baseline | Target | Measurement |
|--------|----------|--------|-------------|
| localhost 100-port connect scan | nmap ~1s | <5s | timed run |
| Report parse failures in CI | manual text parsing | 0 | JSON schema conformance |
| Time to first open-port display | scan completes first | <1s | UI event latency |

### 6.2 Technical Metrics
- `cargo clippy -D warnings` clean; `cargo test` green.
- No `unwrap`/`expect` on data paths.

---

## 7. Constraints and Assumptions

### 7.1 Constraints
- Raw SYN requires elevated privileges and Npcap on Windows — cannot be the
  default path.
- Topcoat is an early-stage framework; its API may break between minor versions.
- MIT OR Apache-2.0 license (see LICENSE-MIT, LICENSE-APACHE).

### 7.2 Assumptions
- Users run scans against networks they are authorized to test.
- The web UI is bound to localhost; no multi-user/auth requirement for v1.

---

## 8. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Topcoat breaking changes | High | Medium | Pin `topcoat = "0.12"`; isolate to `ntok-web` crate |
| Npcap absent on Windows | Medium | Low | Feature-gate SYN; connect scan unaffected |
| UDP false "closed" on hosts that drop ICMP | Medium | Medium | Document heuristic; retries configurable |
| Port-scan detection (IDS) flags traffic | Medium | Low | T0–T2 slow templates; document responsible use |
| Exhausting ephemeral ports at T5 | Low | Medium | Concurrency caps; document limits |

---

## 9. Timeline and Milestones

| Phase | Deliverables | Duration |
|-------|-------------|----------|
| M1 | ntok-core connect scan + CLI + JSON report | Done |
| M2 | Events, timing, service banners, UDP | Done |
| M3 | SYN scan (feature-gated) | Done (compile-verified) |
| M4 | Topcoat web UI | Done |
| M5 | nmap-XML output, hardening | Done |

---

## 10. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-11-16 | Devin | Initial release |
