---
id: cargo-dev-deps-optimized
trigger: "when running or benchmarking ntok scans in dev profile"
confidence: 0.7
domain: "build"
source: "project-readme"
scope: project
---
Cargo.toml already sets opt-level=3 for regex/aho-corasick/memchr/tl in
dev profile, so `cargo run` scans are representative — no need to reach
for --release just to test scan speed.
