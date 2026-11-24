# Contributing

Participation in this project is covered by the
[Contributor Covenant 3.0](CODE_OF_CONDUCT.md) — read it before opening
issues or pull requests.

- **Language:** Rust only, edition 2024.
- **License:** contributions are MIT OR Apache-2.0 (`LICENSE-MIT`,
  `LICENSE-APACHE`). Vendored data under `crates/ntok-core/data/` keeps its
  upstream license (Nmap Public Source, Wappalyzer community DB) — do not
  copy proprietary signatures or datasets in.
- **Local-first:** no telemetry, no accounts, no required network calls to
  ntok's own infra. Optional capabilities (`--ai`, external `--tools`,
  RDAP/DoH lookups) degrade to warnings when unavailable — a scan must
  never fail because an optional dependency is missing.
- **Bounded everything:** ports, concurrency, timeouts, body sizes,
  redirect counts, crawl depth, channels. No unbounded queues or retries.
- **Errors:** expected failures return `Result`; don't panic on attacker-
  or network-controlled input (banners, certs, XML, HTML, tool output).
- **Tests:** required for behavior changes — parsers get malformed-input
  tests, report formats get round-trip tests. Run
  `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`
  before submitting.
- **Style:** `cargo fmt`. Match surrounding code. Comments explain *why*.
- **Commits:** small, focused, clear subject line.
- **Security:** report vulnerabilities privately per `SECURITY.md` — never
  in a public issue or PR description.

## Layout

```
crates/
  ntok-core/   scanning engine (library)
  ntok-cli/    `ntok` binary — clap frontend over ntok-core
  ntok-web/    `ntok-web` binary — Topcoat/htmx UI over ntok-core
  ntok-store/  SQLite + FTS5 index — `ntok search`/`graph` backend
```

`ntok-core` is laid out like nmap so the vocabulary stays familiar.

## Adding a scan technique

1. New module under `crates/ntok-core/src/scan/` implementing the
   `PortProber` trait (see `connect.rs`, `udp.rs`, `ping.rs`).
2. One `ScanTechnique` variant + one entry in `ScanTechnique::prober`.
3. Wire the `-s*` flag in `ntok-cli` and the mode selector in `ntok-web`
   if it needs UI exposure.
4. Raw-socket techniques go behind the `privileged` feature like
   `scan/raw.rs` — keep connect-scan fallbacks working unprivileged.

## Adding an external tool

Subprocess integrations live in `crates/ntok-core/src/tools/` behind
`ToolKind` (see the `masscan`/`nmap`/`nuclei`/`naabu`/`rustscan`
modules): resolve on `PATH`, honor `--tool-prefix`/`NTOK_TOOL_PREFIX` and
`NTOK_TOOL_TIMEOUT_MS`, parse stdout — never shell-concatenate user input
into the command line, and degrade to a log warning when the binary is
missing.

## Adding a report format or search field

- Report format: implement the writer next to the existing `--oJ/--oX/--oN/
  --oG/--oC/--oH` emitters and register the flag; make it round-trip
  through `ntok import` where the format supports it.
- Search field: extend the `ntok-store` schema/ingest, add the
  `field:value` token to the DSL, and index a migration-free rebuild path
  (the DB must rebuild from `reports/` when deleted).
