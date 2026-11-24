<div align="center">
<img src="docs/logo.svg" width="140" alt="NTOK SCAN logo">
<h1>NTOK SCAN</h1>
<p><strong>Discover. Analyze. Secure.</strong></p>
<p><em>Network Threat Observation &amp; Knowledge</em></p>
<p>
An open-source, nmap-style port scanner and recon engine in pure Rust —<br>
same flags, same XML, plus a live web UI, website intel, and one-click scan diffing.<br>
Local-first: no cloud account, no telemetry — your accounts and targets never leave your machine.
</p>
<p>
<a href="#license"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="License: MIT OR Apache-2.0"></a>
<a href="https://github.com/Ikziriv/ntok-scan/actions/workflows/release.yml"><img src="https://github.com/Ikziriv/ntok-scan/actions/workflows/release.yml/badge.svg" alt="Release"></a>
<a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-2024%20edition-orange.svg" alt="Rust 2024 edition"></a>
<a href="#privileged-scans"><img src="https://img.shields.io/badge/platform-Windows%20%C2%B7%20Linux%20%C2%B7%20macOS-lightgrey.svg" alt="Platform: Windows, Linux, macOS"></a>
</p>
<p><strong>⚠ Scan only systems you own or have permission to test.</strong></p>
</div>

<!-- demo asset to record: split screen — `ntok scan --web` CLI left,
     ntok-web port map lighting up right. 20–30s loop → docs/demo.gif -->

## Contents

- [Quick start](#quick-start)
- [Why ntok](#why-ntok)
- [Installation](#installation)
- [Commands](#commands)
- [CLI](#cli)
- [Website reconnaissance](#website-reconnaissance)
- [nmap file import](#nmap-file-import)
- [Scan diff](#scan-diff)
- [Search index](#search-index)
  - [Relationship graph](#relationship-graph)
  - [Passive subdomains](#passive-subdomains)
  - [Adaptive port ordering](#adaptive-port-ordering)
- [Continuous scanning](#continuous-scanning)
- [External tools](#external-tools)
- [AI advisor](#ai-advisor)
- [MCP server](#mcp-server)
- [Web UI](#web-ui)
- [Deploying on a public host](#deploying-on-a-public-host)
- [Privileged scans](#privileged-scans)
- [Project layout](#project-layout)
- [Development](#development)
- [Documentation](#documentation)
- [Acknowledgements](#acknowledgements)
- [Contributing](#contributing)
- [License](#license)

## Quick start

```sh
# prebuilt binaries → https://github.com/Ikziriv/ntok-scan/releases
cargo install --git https://github.com/Ikziriv/ntok-scan ntok-cli

ntok scan 10.0.0.0/24 -p top:100 -T4 --sV      # nmap-style scan
ntok scan https://example.com --web            # ports + website intel
ntok diff 3 4                                  # what changed since last scan

cargo run -p ntok-web                          # live UI → http://127.0.0.1:3000
```

## Why ntok

- **nmap-fluent, no nmap dependency** — same `-sT/-sS/-sU` vocabulary,
  timing templates, and `-oX` XML; imports your existing nmap reports.
- **Live port-map UI** — watch a dense grid of port cells light up as
  probes land, not after.
- **Recon beyond ports** — TLS certs, security headers, tech stack,
  company attribution, and asset inventory per web port.
- **A local Shodan** — every scan feeds a SQLite FTS5 index; `ntok search`,
  `ntok graph`, and `ntok subs` pivot over everything you've ever seen.
- **Drift as a loop** — rescan → compare is one click; `ntok diff` shows
  appeared hosts, port flips, and finding deltas.
- **Orchestrates the tools you trust** — `--tools masscan,nmap,nuclei`
  merge into one report; missing binaries degrade to warnings.
- **Optional AI advisor** — any OpenAI-compatible endpoint, including a
  local Ollama; off by default and never written into reports.
- **Windows-first-class** — Npcap for raw scans, `--tool-prefix` for
  Kali tools under WSL.

ntok plays with the ecosystem rather than claiming to replace it: nmap
stays the reference (import its `-oX`), masscan does the internet-scale
sweep, nuclei brings the vulnerability templates — ntok is the cockpit
over all of them.

## Installation

| Method | Command |
|---|---|
| Prebuilt binaries | [Releases](https://github.com/Ikziriv/ntok-scan/releases) — Windows, Linux, macOS |
| crates (git) | `cargo install --git https://github.com/Ikziriv/ntok-scan ntok-cli` |
| From source | `git clone … && cargo build --release -p ntok-cli -p ntok-web` |

Feature flags (see [Privileged scans](#privileged-scans) for the Npcap/
root requirements of raw techniques):

```sh
cargo build -p ntok-cli --features ntok-core/privileged   # raw -sS/-sA/-sF/-sN/-sX + ICMP
cargo build -p ntok-cli --no-default-features            # drop the AI advisor + reqwest
```

## Commands

| Command | What it does |
|---|---|
| `ntok scan` | Port scan + service detection + optional web recon — writes reports, feeds the index |
| `ntok import` | Read an nmap `-oX` or ntok JSON report — view it or convert formats |
| `ntok diff` | ndiff-style comparison of two reports — what changed between A and B |
| `ntok search` | Shodan-style `field:value` query over every indexed service |
| `ntok ask` | Plain-language question → AI translates it into a `search` query |
| `ntok graph` | Pivot an IP/domain through cert SANs, redirects, assets, DNS, CT names |
| `ntok subs` | Passive subdomain enumeration via crt.sh CT logs — zero packets to target |
| `ntok watch` | Scan on a schedule from a JSON spec; diffs each run against the last |
| `ntok lookup` | Single-site tech profile — no port scan |
| `ntok-mcp` | MCP (stdio) server — exposes the engine + index as tools for AI agents |
| `ntok-web` | The web UI — same engine, live port map, history, compare, search |
| `ntok-desktop` | Desktop app — Tauri window over `ntok-web` on a private port, data dir under your profile |

## CLI

```sh
cargo run -p ntok-cli -- scan 10.0.0.0/24 -p top:100 -T4 --sV
ntok scan host.example 10.0.0.1-50 -p 22,80,443,8000-9000
ntok scan 10.0.0.5 --udp -p 53,137,161 --Pn
ntok scan 10.0.0.5 --syn -p all            # needs privileged feature + Npcap/root
```

Options: `-p` ports (`22,80` / `1-1024` / `top:N` / `all`), `-T0..-T5` timing,
`--syn` / `--ack` / `--fin` / `--null` / `--xmas` / `--udp`, `--Pn` skip
discovery, `--sV` service detection, `-v` show closed/filtered, `--web`
website reconnaissance, `--adaptive` index-informed port order,
`--concurrency`, `--timeout-ms`, `--delay-ms` overrides, `--ai` advisor,
`--tools` external-tool modules (`nmap, nuclei, masscan, naabu, rustscan`).

Reports: `--oJ` JSON · `--oX` nmap-XML · `--oN` text · `--oG` greppable ·
`--oC` CSV · `--oH` HTML · `--oA BASE` writes all six as `BASE.*`.

## Website reconnaissance

Targets may be full URLs; `--web` additionally profiles every open
HTTP-ish port (80/443/8080/8443 or an `HTTP/` banner). Each endpoint
yields a `WebProfile` on the host:

```sh
ntok scan https://example.com                  # URL target — recon runs anyway
ntok scan 10.0.0.0/24 -p top:100 --web         # ports + web profiles
ntok scan example.com --web --crawl 4          # + inner-page detection
ntok lookup wordpress.org                      # tech profile, no port scan
```

Per profile: redirect chain + final URL, status/TTFB, server and
security-header score, TLS cert (subject/org/issuer/SANs/validity —
self-signed and expired are data, not errors), detected technologies
(the full Wappalyzer community fingerprint DB — ~7.7k fingerprints
vendored in `ntok-core/data/web-tech.json` — matched over headers,
cookies, meta, script URLs, DOM selectors, JS globals, page URL, DNS,
robots.txt, TLS issuer, first-party JS bundles, and body text; every
hit reports its confidence, version and evidence trail, and
`implies`/`excludes` inference adds dependent techs like PHP under
WordPress), favicon mmh3 hash matched against a 700+ product table
(Shodan's `http.favicon.hash` pivot space — catches infra the page
never mentions),
company attribution (RDAP registrar/IP-owner/ASN, cert org, page
metadata, DNS MX/NS/TXT + SaaS verification hints), the full asset
inventory (scripts/styles/media/fonts/links/forms, third-party
domains), API-path hints from JS, and robots.txt sitemaps/disallows.
`--crawl N` fetches up to N same-origin links per site (bounded like
everything else) — inner pages' bodies, inline JS, meta and script
srcs merge into detection, and `ntok lookup` defaults to a 4-page
crawl for the deepest single-site profile.
Requests pin the resolved IP, cap bodies and redirects, and every
external lookup (RDAP, DoH) degrades quietly on air-gapped networks.
JS-rendered SPA-only assets aren't caught — that's the headless-browser
boundary; `tools/` external binaries remain the extension seam.

## nmap file import

`ntok import <file>` reads an nmap `-oX` report — or an ntok JSON report —
(ntok's own `-oX` output round-trips too, including `<script>` findings and
service banners): prints the normal report, or converts with the same
`--o*` flags — e.g. `ntok import out.xml --oC out.csv`.

## Scan diff

`ntok diff A B` is an ndiff-style comparison of two reports: hosts that
appeared/disappeared, port state flips, service changes, hostname/OS
changes, and findings that came or went. Operands are paths, `reports/`
basenames, or bare scan ids — ntok JSON and nmap XML mix freely:

```sh
ntok diff 3 4                          # reports/scan-3.json vs scan-4.json
ntok diff baseline.xml reports/scan-4.json --oJ drift.json
```

## Search index

Every finished scan and import feeds `reports/ntok.db` — a local
Shodan-style index (SQLite + FTS5) holding one row per open service ever
seen, joined with its TLS/web/tech enrichment. `ntok search` queries
across the union of all past scans:

```sh
ntok search 'service:nginx port:443'
ntok search 'net:10.0. has:tls expired:true'
ntok search 'apache "openssl_1.0"'        # bare words → full-text
ntok search 'risk:high'                   # exposure score ≥ 70
ntok search 'favicon:-247388890'          # Shodan-style http.favicon.hash
ntok search 'anomaly:high'                # ports seen on few indexed hosts
ntok search 'sev:high'                    # hosts with high-severity findings
ntok search 'finding:cve-2021-41773'      # nuclei/nmap finding text
ntok ask 'expired certs on the lab net'   # AI translates to the DSL
ntok search 'org:cloudflare after:2025-11-01' --oJ hits.json
```

Fields: `ip` `net` `port` (`80` or `1-1024`) `protocol` `state`
`service` `product`/`banner` `hostname` `os` `asn` `org` `server`
`tech` `status` `has:banner|tls|web|tech|hostname|os|org|asn|findings`
`expired` `selfsigned` `favicon:<mmh3-hash>` `finding:<text>`
`sev:<severity>` `risk:high|medium|low|<n>` `anomaly`/`rare:same bands`
`after`/`before` (unix or `YYYY-MM-DD`). Re-scans update `last_seen` and
keep `first_seen`, so `after:`/`before:` answer "what changed since".
Index failures never fail a scan; the DB path is `reports/ntok.db` unless
`NTOK_DB` or `--db` says otherwise — delete it and it rebuilds from
whatever reports you feed it next.

`risk` is a deterministic exposure score (0–100) computed at ingest —
no model, fully explainable: risky-port table (telnet/SMB/RDP/VNC,
unauthenticated Docker, database & queue surface) plus expired/
self-signed certs and missing hardening headers. `anomaly` is the same
idea inverted: `100 − % of indexed hosts this port is open on`, so
`anomaly:high` surfaces the "why is *that* here" outliers. `favicon`
carries the mmh3 hash of `/favicon.ico` — the `http.favicon.hash`
pivot Shodan users know — resolved to a product name in output when
the vendored table knows it.

`ntok ask` sends the question to the configured AI endpoint (same
settings as the scan advisor) which writes the `field:value` query —
the translated query prints to stderr so you can learn/verify it.

### Relationship graph

Every ingest also records the relationships a scan surfaced into an
`edges` table — cert SANs, redirect targets, third-party asset hosts,
and DNS names. `ntok graph` pivots on any IP or domain, in both
directions, and marks destinations already in the index with `*`:

```sh
ntok graph 93.184.216.34
#  → dns       example.com                    *
#  → san       *.internal.example.com
#  → san       www.example.com
#  → redirect  accounts.corp.io
#  → asset     cdn.jsdelivr.net
ntok graph '*.internal.example.com'   # reverse: who named it?
#  ← san       93.184.216.34
ntok graph 93.184.216.34 --depth 2    # walk outward through shared domains
#  · san       10.0.0.7 → *.internal.example.com
ntok graph corp.com --depth 2 --oT next.txt   # discoveries → scan targets
```

That's the Censys "internet map" idea, local: a wildcard or internal
SAN on one cert tells you sibling hostnames to scan next, and the `*`
marker shows which you've already covered. `--depth 2` follows the
domains a scan discovered into other hosts that also name them (max 3
hops, 500 edges) — how "a.internal.example.com" on one cert surfaces a
different machine entirely.

The same index is browsable in the web UI at `/search` — same DSL,
server-rendered, queries are plain GET URLs you can bookmark.

### Passive subdomains

`ntok subs <domain>` adds the passive side — certificate-transparency
enumeration through crt.sh, one outbound HTTPS call and zero packets
toward the target. Found names index as `ct` edges (so `ntok graph` and
`--depth 2` walks link them to scanned hosts) and `--oT` writes them
straight into a target file:

```sh
ntok subs example.com --oT targets.txt
ntok scan $(cat targets.txt | tr '\n' ' ')   # feed them back
```

### Adaptive port ordering

`ntok scan --adaptive` keeps the same port plan but probes in order of
index history — ports seen open on the most indexed hosts go first.
Literal IP targets get an extra boost from *their own* history, so
re-scanning a known host probes its usual ports first. With no index
history the order is unchanged.

## Continuous scanning

`ntok watch <file>` runs a scan on a schedule and diffs each run against
the previous one — drift (hosts appearing, ports flipping, services
changing) prints as it happens while every run feeds the index:

```json
{"targets":["10.0.0.0/24"],"ports":"top:100","every_secs":3600,
 "service":true,"web":true,"tools":"nmap,nuclei","name":"lab"}
```

```sh
ntok watch watch.json          # loop until Ctrl-C
ntok watch watch.json --once   # one cycle — for cron/systemd timers
```

The file may be one spec object or an array of specs (each gets its own
`reports/<name>.json` baseline). Fields mirror the scan flags:
`targets` `ports` `timing` `service` `web` `tools` `every_secs` `name`.

## External tools

`--tools` bolts Kali-style binaries onto a scan — they run as subprocesses,
never as libraries, and a missing binary degrades to a log warning so scans
never depend on tools being installed:

- **`masscan`** — replaces host discovery: it SYN-sweeps the target set and
  reports open `(ip, port)` pairs; the engine then probes just those ports
  for service detection. Needs raw-socket privileges wherever it runs.
- **`naabu`** (ProjectDiscovery) — same discovery-stage role as masscan
  with less config friction; first selected binary that's installed wins.
- **`rustscan`** — same discovery-stage role via RustScan's adaptive
  connect engine (`-g` greppable output, `--scripts none` so it doesn't
  chain into nmap).
- **`nmap`** — runs a real `nmap -Pn -sV --version-light -oX -` over each up
  host's open ports, merging service names, version banners, OS guesses and
  NSE `<script>` output as findings.
- **`nuclei`** — runs vulnerability templates against open ports
  (`scheme://ip:port` for HTTP services, bare `ip:port` otherwise) and
  attaches severity-tagged findings.

```sh
ntok scan 10.0.0.0/24 -p top:1000 --tools masscan,nmap,nuclei
ntok scan 10.0.0.0/24 -p top:1000 --tools naabu
ntok scan 10.0.0.5 --tools nmap --tool-prefix "wsl -d kali-linux --"
```

Tool binaries resolve on `PATH` by default; `--tool-prefix` (or
`NTOK_TOOL_PREFIX`) prepends a prefix to every invocation — the typical use
is running Kali tools inside WSL2 from the Windows binary
(`wsl -d kali-linux --`). `NTOK_TOOL_TIMEOUT_MS` caps each tool run
(default 300000). In the web UI the same five tools are checkboxes on the
scan form; the prefix still comes from the env var.

## AI advisor

`--ai` (CLI flag, or the "AI advisor" checkbox in the web UI) installs an
advisor that asks an OpenAI-compatible chat endpoint to adjust the scan plan
(port focus, concurrency, timeout) before probing and to summarize the
findings after. Every advisor failure degrades to a warning — scans never
depend on AI being reachable.

The web UI has an **AI settings** page (top-right nav): provider presets,
endpoint, model, API key, and operator instructions, plus a test-connection
button. Settings persist to `%APPDATA%\ntok\config.json`
(`~/.config/ntok/` elsewhere) and take precedence over env once saved.
The "AI options" disclosure on the scan form overrides model/instructions
for that scan only. The key is never rendered back, logged, or written to
reports. CLI/headless env config:

```sh
set NTOK_AI_KEY=sk-...                                        # required (DeepSeek API key)
set NTOK_AI_MODEL=deepseek-chat                               # default
set NTOK_AI_ENDPOINT=https://api.deepseek.com/chat/completions  # default: DeepSeek
```

Any OpenAI-compatible endpoint works — point `NTOK_AI_ENDPOINT` at a
local Ollama (`http://localhost:11434/v1/chat/completions`) and
`NTOK_AI_KEY` becomes optional.

Custom advisor implementations plug into `ScanConfig::advisor` — anything
implementing the `ScanAdvisor` trait works; `NullAdvisor` is the default.
The `ai` cargo feature (default on) brings in `reqwest` for `HttpAdvisor`;
build with `--no-default-features` to drop it.

## Recon agent

`ntok agent` (CLI) and `/agent` (web) run a bounded tool-calling loop over
the same `NTOK_AI_*` endpoint. The model answers questions by invoking
read tools over local data — never by guessing:

| Tool | What it reads |
|---|---|
| `search_index` | The FTS5 index — every service ever seen |
| `recent_scans` | Scan history |
| `scan_summary` | A stored report's open services |
| `diff_scans` | ndiff-style drift between two reports |
| `service_lookup` | The port→service DB |
| `propose_scan` | Returns a plan for *operator* approval — runs nothing |
| `memory_save` / `memory_search` | Durable facts and learned lessons |

```sh
ntok agent "what changed on the lab net since last week?"
ntok agent "any hosts with expired certs?" --db reports/ntok.db
```

**Boundaries**: read-only — the agent can propose a scan but cannot launch
probes; turns (8), per-tool result bytes (8 KB), and request timeouts are
all capped. `memory` rows are unreviewed context, never executable policy;
`kind=lesson` entries with confidence ≥ 0.7 are recalled into the agent's
system prompt — the in-app equivalent of learned instincts. A keyless
Ollama endpoint keeps every byte on the host.

For exposing these tools to *external* agents instead, see the MCP server
below — `ntok-mcp` is the outward-facing tool surface, `agent` is the
internal loop.

## MCP server

`ntok-mcp` is an MCP (stdio) server over the same engine and index — point
an MCP-capable agent (Claude Desktop, Cursor, Devin, …) at the binary and
it gets the read tools ungated and `scan` behind an explicit opt-in:

```sh
cargo run -p ntok-mcp                                    # read-only: index + recon tools
cargo run -p ntok-mcp -- --allow-scan --scope private    # + gated scan tool
```

Client config (e.g. `claude_desktop_config.json` / `.mcp.json`):

```json
{ "mcpServers": { "ntok": {
  "command": "ntok-mcp",
  "args": ["--allow-scan", "--scope", "private,*.corp.local"]
}}}
```

Remote agents can reach it over Streamable HTTP instead of stdio —
`--http` serves POST `/mcp` on its own listener with Bearer auth. The
same `ntok_…` API tokens the browser extension uses work here (mint in
ntok-web settings → "API access"), or set `NTOK_MCP_TOKEN` for a shared
secret on installs with no web users:

```sh
NTOK_MCP_TOKEN=… ntok-mcp --http 127.0.0.1:3001 --allow-scan --scope private
# client URL: http://127.0.0.1:3001/mcp   header: Authorization: Bearer ntok_…
```

Tools mirror the CLI verbs: `stats`, `search` (the full `field:value` DSL),
`graph`, `subs`, `lookup`, `scans`, `report`, `diff`, `import` — all read or
index-side and always on. `scan` sends real packets and exists only behind
`--allow-scan`; `--scope` / `NTOK_MCP_SCOPE` is a comma-separated allowlist
of CIDRs, hostname globs (`*.corp.local`), or `private` (RFC1918 +
loopback) checked before a packet is built — out-of-scope targets get a
clean error. The `scan` args mirror the CLI flags too: `ports`, `timing`,
`technique`, `skip_discovery`, `service`, `web`, `crawl`, `adaptive`,
`tools` (external nmap/nuclei/masscan/…), `verbose`, `concurrency`,
`timeout_ms`, `delay_ms`. `--scan-timeout` (default 600s) bounds each run;
finished scans land in `reports/scan-<id>.json` and feed the index like
any CLI run, so agent-initiated scans join the same history, diff, and
graph.

## Web UI

```sh
cargo run -p ntok-web          # http://127.0.0.1:3000 — register first, then sign in
cargo run -p ntok-web -- --open   # also opens your browser once it's up
cargo run -p ntok-desktop      # the app form: native window, private port, OS data dir
                               # (falls back to your browser if no webview is available)
```

The **browser extension** (`crates/ntok-extension`, load-unpacked for now)
adds a "Scan \<host\>" popup and a right-click "Scan host with ntok" menu —
it authenticates to the same `ntok-web` API with a Bearer token minted in
settings → "API access".

Start scans from the browser and watch results stream in live (htmx polling):
a per-host port-state grid, open-ports table, host detail, website-intel
panels (technologies, TLS, company/DNS, asset inventory), a live
throughput waveform, and a terminal-style log — plus progress, per-scan
stop, and downloads in every
format (JSON / XML / text / greppable / CSV / HTML / full log). The scan
form's mode selector (ports / website intel / ports+web) maps to `--web`.
Finished
reports land in `reports/scan-<id>.json` (logs in `scan-<id>.log`) and are
loaded back at startup, so history and detail pages survive restarts.
An "Import nmap XML" panel files external `-oX` reports into the same
history. Each scan page links `compare with:` every other finished scan —
`/compare/A/B` shows the ndiff view (appeared/disappeared hosts, port and
service flips, finding deltas), and a **Rescan** button replays the stored
form as a new scan so the drift loop is one click: rescan → compare.
Tool findings (nmap scripts, nuclei) render on the detail page and in the
normal/CSV/HTML exports. History rows have a confirm-guarded delete that
removes the entry and its report files. The visual system lives in
`DESIGN.md`.

## Deploying on a public host

`ntok-web` binds `HOST`/`PORT` env (default `127.0.0.1:3000`) and requires
an account: register at `/register`, sign in at `/login`. Accounts,
sessions and API tokens live in `reports/ntok.db` (argon2id password
hashes — the DB is the only place credentials exist). The browser
extension, `ntok-desktop` and CI clients send
`Authorization: Bearer ntok_…` — mint tokens under settings → "API
access", or exchange credentials once at `POST /api/auth/login`.

| Env var | Effect |
|---|---|
| `NTOK_AUTH` | `off`/`0`/`false` disables login entirely — the old single-user localhost behavior. Every route is then open to anyone who can reach the port. |
| `NTOK_REGISTRATION` | `0`/`false` closes `/register` once the first account exists (bootstrap can never lock you out). |
| `NTOK_WEB_PASSWORD` | Legacy bootstrap: when set **and no users exist**, seeds an `admin` account with this password at startup. Prefer registering normally. |
| `NTOK_WEB_EMAIL` | Optional email for the `admin` account seeded by `NTOK_WEB_PASSWORD`. Ignored otherwise; email can also be set later in settings → Account security. |
| `NTOK_WEB_COOKIE_SECURE` | `0`/`false` drops the `Secure` cookie flag — only for plain-HTTP setups with no TLS proxy. |
| `NTOK_DATA_DIR` | Desktop launcher's data dir (`reports/`, `ntok.db`, config). |
| `HOST` / `PORT` | Listen address. Containers ship `0.0.0.0:8080`. |
| `NTOK_DB`, `NTOK_AI_*`, `NTOK_TOOL_PREFIX` | Index path and advisor/tool config, as usual. |

Everything the app writes lives under its working dir (`reports/`,
`reports/ntok.db`) plus `$HOME/.config/ntok/` — the `Dockerfile` points both
at `/data`, so **one volume at `/data` keeps scan history and settings**
across deploys.

**Fly.io** — `fly.toml` ships in the repo:

```sh
fly launch                      # adopts fly.toml (rename `app` if taken)
fly volumes create ntok_data --size 1
fly deploy                      # then register at /register — first account wins
```

Idle machines suspend rather than stop, so an in-flight scan survives.

**Railway** — `railway.toml` builds the Dockerfile; in the dashboard add a
volume at `/data` (it holds `ntok.db`, where accounts live). Railway
injects `PORT` automatically.

**Hetzner / any VM** — `docker-compose.yml` runs the app behind Caddy
(automatic HTTPS):

```sh
cp .env.example .env   # optional NTOK_* tuning
# set your domain in Caddyfile
docker compose up -d --build
# then register at https://your-domain/register
```

Two caveats stay true everywhere: **put it behind TLS** (credentials and
bearer tokens go over the wire — Fly/Railway/Caddy all terminate TLS
already), and
**scans run from the host's egress IP** — the "targets never leave your
machine" promise becomes "your server" instead; scanning ranges you don't
own from a cloud IP can trip provider abuse policies. Raw `-sS`/ICMP
techniques and external `--tools` aren't in the container build — connect
scans and web recon work everywhere.

Raw flag scans (SYN/ACK/FIN/NULL/Xmas), ICMP echo discovery, and TTL/window
OS hints are behind the `privileged` cargo feature and need Npcap (Windows)
or root/`CAP_NET_RAW` (Unix):

```sh
cargo build -p ntok-cli --features ntok-core/privileged
```

On Windows the link needs `Packet.lib` from the
[Npcap SDK](https://npcap.com/#download) — unpack it somewhere and point the
linker at it, e.g. in `.cargo/config.toml`:

```toml
[env]
LIB = 'C:\\npcap-sdk\\Lib\\x64'
```

## Project layout

```
crates/
  ntok-core/   scanning engine (library) — target/port parsing, timing
               templates, technique modules, service probes, reports
  ntok-cli/    `ntok` binary — clap frontend over ntok-core
  ntok-web/    `ntok-web` binary — Topcoat UI + JSON API over ntok-core
  ntok-store/  searchable index (SQLite + FTS5) — `ntok search` backend,
               plus accounts/sessions/API tokens
  ntok-mcp/    `ntok-mcp` binary — MCP (stdio) frontend exposing engine +
               index tools to AI agents, `scan` gated by --allow-scan/scope
  ntok-desktop/ desktop app — Tauri v2 window over a local `ntok-web`
               sidecar, data dir under the OS profile
  ntok-extension/ MV3 browser extension (not Rust) — "scan this site" via
               the local/hosted `ntok-web` API
  ntok-mobile/ Android + iOS shells (Kotlin WebView / SwiftUI WKWebView,
               not Rust) — viewer/control over a hosted `ntok-web`
```

`ntok-core` is laid out like nmap: each `-s*` technique is a module under
`scan/` behind the `PortProber` trait (connect = -sT, udp = -sU; the raw
flag-scan family -sS/-sA/-sF/-sN/-sX lives in `scan/raw.rs` behind the
`privileged` feature, and `scan/ping.rs` adds ICMP echo discovery). Adding a
technique = new module + one `ScanTechnique` variant + one entry in
`ScanTechnique::prober`. Probing uses adaptive timeouts — an EMA of observed
connect RTT shrinks the effective timeout toward ~4x RTT, so filtered ports
on fast networks don't stall the scan.

Service detection leans on nmap's own data, vendored under `ntok-core/data/`
(Nmap Public Source license): `svcdb` parses `nmap-services` for the
port→name table and the `match`/`softmatch` lines of `nmap-service-probes`
for banner→name regexes. External scanning tools (Kali binaries run as
subprocesses) live in `tools/` behind `ToolKind` — see "External tools".

## Development

```sh
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

## Documentation

| Document | Contents |
|---|---|
| [`DESIGN.md`](DESIGN.md) | The visual system — tokens, components, voice |
| [`docs/software_design_document.md`](docs/software_design_document.md) | Architecture and module design |
| [`docs/technical_design_document.md`](docs/technical_design_document.md) | Technical decisions and constraints |
| [`docs/product_requirements_document.md`](docs/product_requirements_document.md) | Product scope and requirements |
| [`docs/business_requirements_document.md`](docs/business_requirements_document.md) | Business context and constraints |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to add a technique, a tool, a report format |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Contributor Covenant 3.0 — community rules and reporting |
| [`SECURITY.md`](SECURITY.md) | Vulnerability reporting and scope |
| [`docs/legal/privacy-policy.md`](docs/legal/privacy-policy.md) | What data the app stores and when anything leaves the host |
| [`docs/legal/terms-of-service.md`](docs/legal/terms-of-service.md) | Terms of service — also served in-app at `/terms` |
| [`docs/legal/acceptable-use-policy.md`](docs/legal/acceptable-use-policy.md) | Authorized-use rules every scan must follow |
| [`docs/legal/README.md`](docs/legal/README.md) | Operator checklist — what to customize before launch |

## Acknowledgements

ntok stands on the tools and datasets its users already trust.

**Data, vendored under `crates/ntok-core/data/`** (each keeps its own
license — see the `NOTICE-*` files there):

- [nmap](https://nmap.org) — `nmap-services` and `nmap-service-probes`
  drive the port→service table and banner matching (Nmap Public Source
  license); the `-oX` format and ndiff semantics come from nmap/ndiff.
- [webappanalyzer](https://github.com/enthec/webappanalyzer) — the
  community Wappalyzer fingerprint DB behind technology detection.
- [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
  — the MurmurHash3 favicon→product table (`http.favicon.hash`).

**External tools orchestrated via `--tools`:**

- [masscan](https://github.com/robertdavidgraham/masscan) — internet-scale
  SYN discovery.
- [nmap](https://nmap.org) — real `nmap -sV` runs and NSE findings.
- [nuclei](https://github.com/projectdiscovery/nuclei) — vulnerability
  templates and severities.
- [naabu](https://github.com/projectdiscovery/naabu) and
  [RustScan](https://github.com/bee-san/RustScan) — alternative discovery
  engines.

**Ideas borrowed honestly:**

- [Shodan](https://www.shodan.io) — the `field:value` search DSL and the
  `http.favicon.hash` pivot.
- [Censys](https://search.censys.io) — the "internet map" relationship
  graph behind `ntok graph`.
- [crt.sh](https://crt.sh) — certificate-transparency subdomain
  enumeration behind `ntok subs`.
- [ndiff](https://nmap.org/ndiff/) — the diff model behind `ntok diff`.

**Built with:** [tokio](https://tokio.rs) · [pnet](https://github.com/libpnet/libpnet) ·
[rusqlite](https://github.com/rusqlite/rusqlite) + SQLite FTS5 ·
[clap](https://github.com/clap-rs/clap) · [reqwest](https://github.com/seanmonstar/reqwest)
+ [rustls](https://github.com/rustls/rustls) · [htmx](https://htmx.org) ·
Npcap on Windows.

## Contributing

Contributions are welcome — read [`CONTRIBUTING.md`](CONTRIBUTING.md) for
the extension seams (new scan techniques, external tools, report formats,
search fields) and the project rules. Participation is governed by the
[Contributor Covenant 3.0](CODE_OF_CONDUCT.md). Report security issues
privately per [`SECURITY.md`](SECURITY.md); use GitHub issues for
everything else.

## Ringkas (Bahasa Indonesia)

**ntok** adalah pemindai port dan mesin rekons gaya nmap berbasis Rust
yang open-source — flag dan XML yang sama, plus UI web langsung,
intelijen situs web, dan diff antar pemindaian dalam satu klik.
Berjalan lokal: tanpa akun, tanpa telemetri — target Anda tidak pernah
keluar dari mesin Anda. Hanya pindai sistem yang Anda miliki atau yang
Anda miliki izin untuk menguji.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.

Vendored data under `crates/ntok-core/data/` keeps its upstream license
(Nmap Public Source license for `nmap-services`/`nmap-service-probes`,
GPL-3.0 for the Wappalyzer community fingerprint DB, MIT for the favicon
hash table).

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
