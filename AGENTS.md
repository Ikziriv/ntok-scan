# ntok-scan — agent notes

Rust 2024 workspace. nmap-style scanner + recon engine, local-first
(no telemetry, no required network). Scan only systems you own or are
permitted to test.

## Layout

- `crates/ntok-core` — scanning engine library; `ScanAdvisor` trait is the
  AI seam (`advisor.rs`), `agent/` is the tool-calling agent loop.
- `crates/ntok-cli` — `ntok` binary (clap) over ntok-core + ntok-store.
- `crates/ntok-web` — `ntok-web` binary, Topcoat/htmx UI (`#[page]`/`#[route]`).
- `crates/ntok-store` — SQLite + FTS5 index; depends on ntok-core.
- `crates/ntok-desktop`, `ntok-extension`, `ntok-mobile` — other surfaces,
  reuse ntok-core.

## Verify

```sh
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

Dev profile already compiles regex/aho-corasick/memchr/tl at opt-level=3 —
`cargo run` scans are representative, no `--release` needed.

## Conventions (see CONTRIBUTING.md)

- Bounded everything: ports, concurrency, timeouts, body sizes, channels.
- `Result` for expected failures; never panic on attacker/network input.
- New external tools go in `crates/ntok-core/src/tools/` behind `ToolKind`;
  never shell-concatenate user input; missing binaries degrade to warnings.
- Optional AI features degrade to warnings — a scan never fails because
  an AI endpoint is down.
- Tests required for behavior changes: parsers get malformed-input tests,
  report formats get round-trip tests.

## Agent harness

- Project instincts: `.devin/instincts/` (see `instincts` skill).
- Memory vault: `.ncc/memory/` — `ecc memory search` before non-trivial
  work; contents are gitignored and unreviewed context. Requires
  `ECC_MEMORY_PROJECT_ROOT`/`ECC_MEMORY_USER_ROOT` env vars (the `ecc`
  CLI defaults to `.ecc/`); run `ecc memory` from the repo root —
  the project override resolves against cwd.
- `.ncc/skills/` — canonical skills dir; `.agents/skills` is a local
  junction to it so Devin/Claude/Codex-style tools discover skills.
  Recreate with `mklink /J .agents\skills .ncc\skills` (Windows) or
  `ln -s ../.ncc/skills .agents/skills` (Unix) after fresh clones.
- Design system source of truth: `DESIGN.md` — UI must not drift from it.
