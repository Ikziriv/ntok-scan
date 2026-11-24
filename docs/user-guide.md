# User guide

NTOK SCAN is a local-first recon console — every scan runs on this machine, and every report and index entry stays under its working directory. Nothing leaves the host unless you configure an external AI endpoint. This page walks through each tool in the top navigation.

## Scans — run your first scan

The home page is the scan console.

- Pick a **mode**: **Network / ports** probes TCP and UDP services, **Website intel** crawls pages and fingerprints the web stack, **Ports + web** does both in one pass.
- Enter **targets**: an IP, a range like `192.168.1.1-50`, a CIDR like `10.0.0.0/24`, a hostname, or a URL.
- Set **ports** only if you need to — blank scans the common set. Otherwise use lists (`22,80,443`), ranges (`1-1024`), presets (`top:100`, `web`), or `all` for all 65,535 ports.
- Press **Launch scan** and watch the port map light up live.

Open **Scan parameters & external tools** on the form for finer control:

- **Technique** — TCP connect needs no privileges; UDP, SYN, ACK, FIN, NULL, and Xmas are there for deeper probing.
- **Timing** — T2 polite through T5 insane. T3 normal is the right default.
- **Core flags** — service detection (`-sV`) is on by default; skip discovery (`-Pn`) probes hosts that do not answer ping; the AI advisor annotates results when configured.
- **External tools** — nmap, nuclei, masscan, naabu, and rustscan run alongside the built-in engine when their binaries are installed. A missing tool degrades to a warning, never a failed scan.
- **Import nmap XML** — under Scan history, pull any `nmap -oX` output file into the same index.

## Reading results

Each scan page shows the live port map, analytics, the open-port table, per-host detail, website intelligence for web scans, and the raw engine log.

- **Port states** — `open` means a service accepted the probe, `filtered` means a firewall swallowed it, `closed` means the host answered but nothing listens.
- **Export** — finished scans download as HTML, JSON, XML, Text, Greppable, or CSV from the Export toolbar.
- **Compare** — pick a second scan in the compare dropdown to diff what appeared and disappeared between the two runs.
- **rescan · stop · delete** — manage runs from the scan page or the history list.

## Index — search everything ever seen

[Index](/search) is a full-text knowledge base of every service, certificate, and technology the engine has observed. Bare words search everything; field filters work Shodan-style:

- `service:nginx port:443` — combine fields freely
- `has:tls expired:true` — certificates past their validity date
- `risk:high` `anomaly:high` `selfsigned:true` — risk and anomaly signals
- `has:web` `has:findings` `finding:text` `sev:critical` — web and finding filters
- `after:2025-01-01` `before:2025-12-31` — date bounds

The full field list lives in the **Query syntax reference** fold on the Index page. Queries are plain GET parameters, so results can be bookmarked and shared.

## Agent — ask in plain language

[Agent](/agent) answers questions from your local index — "what changed on the lab net since last week", "any hosts with expired certs". Its tools can search the index, summarize scans, diff two runs, look up services, and consult its own memory.

- The agent is **read-only** — it can propose a scan, never run one.
- It needs an AI endpoint configured on [Settings](/settings); a keyless local Ollama endpoint keeps every byte on this host.

## Settings — configure the platform

[Settings](/settings) holds four panels:

- **AI advisor** — pick a provider preset (DeepSeek, OpenAI, OpenRouter, or keyless local Ollama), then set endpoint, model, API key, and operator instructions.
- **API access** — mint `ntok_…` Bearer tokens for the browser extension, desktop app, and CI clients. A token is shown once at creation — copy it immediately.
- **Account security** — change your password, review and revoke sessions, and enroll TOTP two-factor.
- **Cloud sync** — optional Cloudflare D1 backup.

## Accounts & API

Register once at `/register`, then sign in at `/login`. Five failed password attempts lock the account for 60 seconds. Scripts and other surfaces authenticate with `Authorization: Bearer ntok_…` — mint tokens under Settings → API access, or exchange credentials once at `POST /api/auth/login`.

## Surfaces

The same engine backs four surfaces: this web console, the `ntok` CLI, the desktop launcher, and the browser extension. Target syntax and the `field:value` query language are identical everywhere — a query that works in [Index](/search) works verbatim in `ntok search`.

## Rules of engagement

Scan only systems you own or are authorized to test — see the [Acceptable Use Policy](/acceptable-use).
