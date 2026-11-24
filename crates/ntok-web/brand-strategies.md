# NTOK — Brand & Promotion Strategy

**Document version:** 2.0
**Product status:** Working open-source tool (MIT/Apache-2.0): nmap-style network
scanner in pure Rust — CLI + local web UI (`ntok-web`)
**Audience:** Security engineers, pentesters, DevOps/netadmins — people who
read nmap output for a living. Secondary: developers, DevSecOps, IT teams.
**Languages:** English primary · Bahasa Indonesia secondary
**Tagline:** Discover. Analyze. Secure.

> v2.0 note: this revision grounds the strategy in the shipped product
> (README, `DESIGN.md`, `docs/logo.svg`). v1 described a hosted SaaS
> "vulnerability platform" with a different palette and type system; where
> this document and `DESIGN.md` disagree, `DESIGN.md` wins for product UI
> and this document wins for marketing surfaces.

------------------------------------------------------------------------

# 1. What ntok actually is (ground truth)

Position every claim against this list — it is the only thing marketing
is allowed to say exists:

- **Engine (`ntok-core`):** pure-Rust async port scanner (`tokio` + `pnet`).
  nmap-style layout: connect (-sT), UDP (-sU), raw flag scans
  (-sS/-sA/-sF/-sN/-sX behind `privileged` + Npcap/root), ICMP discovery,
  timing templates `-T0..-T5`, adaptive EMA-RTT timeouts, service
  detection from vendored nmap data (`nmap-services`, probe match lines).
- **Web recon (`--web`):** per open HTTP port — redirect chain, security
  headers, TLS cert detail, technology fingerprinting, company
  attribution (RDAP/ASN/cert org/DNS), asset inventory, API hints,
  robots.txt. Degrades quietly on air-gapped networks.
- **Reports:** JSON, nmap-XML, text, greppable, CSV, HTML. Imports real
  nmap `-oX` and round-trips its own. `ntok diff` = ndiff-style drift
  (appeared/disappeared hosts, port/service flips, finding deltas).
- **External tools:** `--tools masscan,nmap,nuclei` as subprocess
  orchestration — ntok merges their output into one report. Missing
  binaries degrade to warnings.
- **AI advisor:** optional OpenAI-compatible endpoint adjusts scan plan
  and summarizes findings; never required, never in reports.
- **Web UI (`ntok-web`):** local-first on `127.0.0.1:3000` — live port-map
  grid, host detail, website-intel panels, throughput waveform, terminal
  log, history/compare/rescan, import, downloads in every format.
- **Platform honesty:** first-class Windows (Npcap, WSL tool prefix) plus
  Unix. No account, no cloud, no telemetry — scans live on the machine.

**What ntok is NOT (never claim):** a hosted SaaS, a vulnerability
management platform, a replacement for pentesting, "protection," or full
OWASP/DAST coverage. Vulnerability findings today come from `nuclei`
templates — say that, not more.

------------------------------------------------------------------------

# 2. Positioning

## 2.1 Category and wedge

| Element | Recommendation |
|---|---|
| Category | Open-source network scanner & recon engine |
| One-liner | "An nmap-style scanner in Rust, with a live web UI" |
| Promise | Better visibility into what's exposed — and what changed |
| Tagline | Discover. Analyze. Secure. |
| Visual direction | Print instrument — engineering field log (see `DESIGN.md`) |
| Primary symbol | Faceted N monogram (`docs/logo.svg`) |
| Mascot | Muscovy duck — *it is the name* (see §4) |
| License posture | MIT/Apache-2.0, free, local-first |

Positioning statement (EN):

> ntok is an open-source, nmap-style network scanner and recon engine in
> Rust. It speaks nmap's language — techniques, timing templates, XML —
> adds website intelligence, scan diffing, and optional AI summaries, and
> ships a local web UI so results are watchable live, not grepped after.

Positioning statement (ID):

> ntok adalah pemindai jaringan dan mesin rekons gaya nmap berbasis Rust
> yang open-source. Ia menggunakan bahasa nmap — teknik, templat timing,
> XML — menambah intelijen situs web, diff antar pemindaian, dan ringkasan
> AI opsional, dengan UI web lokal agar hasil dapat dipantau langsung.

## 2.2 Competitive frame — promote *with* the ecosystem, not against it

Security people distrust "nmap killers." ntok imports nmap XML and shells
out to masscan/nmap/nuclei — the honest frame is **a better cockpit over
the tools they already trust**.

| Tool | Relationship | ntok's angle |
|---|---|---|
| **nmap** | Complement + alternative | Same flag vocabulary, imports/exports `-oX`, but with live GUI, web recon, diff workflow built in |
| **masscan** | Orchestrated tool | Raw-speed discovery feeding ntok's prober (`--tools masscan`) |
| **RustScan** | Closest comp | RustScan is a fast front-end that pipes into nmap; ntok is a full engine — reports, recon, diff, UI — not a wrapper |
| **naabu / PD suite** | Alternative | Single binary, batteries included, no toolkit assembly |
| **nuclei** | Orchestrated tool | Vuln templates run as a module; findings land in ntok's report |

Differentiators worth repeating (all verifiable today):

1. **nmap-native without nmap dependency** — same flags, same XML,
   imports your old `-oX` files.
2. **Live port-map UI** — the grid lighting up as probes land is the
   demo. Nothing else in the category looks like it.
3. **Recon beyond ports** — TLS, tech stack, company attribution, asset
   inventory per web port.
4. **Drift as a first-class loop** — rescan → compare is one click;
   appeared/disappeared hosts and service flips.
5. **Local-first & offline-tolerant** — air-gapped scans work; no
   account, no telemetry, AI optional.
6. **Windows-first-class** — Npcap + WSL tool-prefix; rare in this
   category.

## 2.3 Brand values and voice

Precision · transparency · craft · respect for the operator's time.

- Precise: never exaggerate coverage; "open ports and exposure," not
  "vulnerabilities" unless nuclei produced them.
- Honest about limits: SPA-only assets missed, raw scans need
  privileges, AI is advisory.
- Respectful: authorized-targets messaging everywhere (see §8.4).
- Voice is the DESIGN.md voice: a lab notebook, not a hype page.
  Sentence case, short sentences, data in mono.

------------------------------------------------------------------------

# 3. Name & visual identity (aligned to shipped assets)

## 3.1 The name story — lead with this

**ntok** (Javanese/Indonesian *entok/entog*) is the Muscovy duck — the
mascot isn't decoration, it **is the name**. A quiet, watchful,
ground-patrolling bird is the right spirit animal for a scanner: it sees
everything on the surface and doesn't make noise about it.

This gives ntok something almost no security tool has: a name that
carries its own mascot, its own story, and a bilingual wink — English
audiences get a memorable four-letter name; Indonesian audiences get the
joke immediately. Use it: "The duck sees your open ports."

## 3.2 Color — one ramp, two surfaces

Marketing surfaces and product UI share the logo ramp (`logo.svg` /
`MARK_SVG`):

| Token | Hex | Role |
|---|---|---|
| Deep navy | `#193153` / `#25406B` | dark hero surfaces, hover |
| Brand blue | `#376AB3` | primary accent, CTAs, open ports |
| Sky cyan | `#409FD5` / `#45C4EC` | gradient highlights, dark-mode accent |
| Ink | `#1A1814` | text, light-surface foreground |
| Bone | `#F6F5F2` | light canvas (matches product UI) |
| Muted | `#7A756B` | secondary text |

Semantic palette stays as shipped in `DESIGN.md` (amber filtered, red
error, green finished). Marketing severity graphics reuse the same
muted-pastel semantics — never neon severity rainbows.

## 3.3 Typography — reuse the product trio

| Role | Face |
|---|---|
| Display / headlines | Instrument Serif (400) |
| UI & body | Switzer (400/500/600) |
| Data, code, scan output | IBM Plex Mono (400/500/600) |

This is deliberate: the marketing site and the tool should feel like the
same lab notebook. Serif carries voice, grotesk carries UI, mono carries
data — mono especially is subject-authentic (a scanner is a terminal
tool), so every screenshot, command, and stat renders in it.

## 3.4 Signature visual assets

- **The port map** — the dense numbered-cell grid lighting up blue is
  the hero image, the README GIF, and the social card. It is the
  brand's "screenshot people recognize."
- **`$ ntok <args>` echo** — every demo shows the command line it
  replays; marketing copy uses real commands, never mockup UI.
- **Faceted N** — the logo's low-poly facets map cleanly onto scan
  brackets / radar motifs for patterns.

## 3.5 Mascot system (unchanged from v1, now with meaning)

Hero / Scanner / Analyst / Secure / Thinking / Chibi variants; navy
uniform, cyan N emblem, Muscovy red facial area preserved. Sparingly in
the pro UI — dashboard stays instrument-serious; the duck lives on the
site, docs, empty states, and community swag.

------------------------------------------------------------------------

# 4. Promotion strategy — open-source go-to-market

This section replaces v1's SaaS early-access funnel. An OSS scanner is
promoted through **credibility in the places security engineers already
read**, not landing-page conversion.

## 4.1 Channel priority

| Priority | Channel | Why |
|---|---|---|
| 1 | **GitHub** | The product page IS the README. Stars, releases, topics are the funnel |
| 2 | **Hacker News / Reddit** | r/netsec, r/rust, r/Pentesting, r/sysadmin — the exact audience |
| 3 | **Dev.to / blog** | Technical articles rank for dev-tool queries and feed the above |
| 4 | **Awesome lists** | awesome-rust, awesome-security, awesome-pentest, awesome-honeypots-adjacent |
| 5 | **Package registries** | crates.io (`cargo install ntok-cli`), Scoop/Homebrew/AUR later |
| 6 | **Indonesian community** | Bilingual advantage: local infosec groups, OWASP Jakarta, ID dev communities — near-zero competition for attention |
| 7 | **X/Twitter infosec** | Demo GIFs of the port map; launch-day clips |
| 8 | **Product Hunt / BetaList** | Minor; dev tools do better on HN — do it once, cheaply |
| 9 | **Kali/tools submission** | Long-term legitimacy: `apt install ntok` is a moat |

## 4.2 The demo asset stack (build once, reuse everywhere)

- **README hero GIF** (the single highest-ROI asset): terminal split —
  `ntok scan --web` on the left, `ntok-web` port map filling in live on
  the right. 20–30s, looped.
- **30s screen recording** of rescan → compare showing a port flip.
- **Report samples** in-repo: `reports/` examples in JSON/XML/HTML that
  people can open without installing.
- **Compare-page screenshots**: `ntok diff` output vs. ndiff.
- **Mascot + port-map social card** (1200×630) on the brand ramp.

## 4.3 Launch playbook

**Phase 0 — storefront (before any post):**
- README top: GIF → one-line pitch → `cargo install` → 3 real commands.
- GitHub topics: `port-scanner` `nmap` `rust` `network-security`
  `recon` `pentesting` `osint` `infosec`.
- LICENSE (MIT/Apache-2.0 ✓), CONTRIBUTING stub, screenshots folder, release
  binaries for Windows/Linux/macOS via CI.

**Phase 1 — soft launch:**
- r/rust "what's everyone working on" + a dev.to build-story post
  ("Building an nmap-style scanner in Rust: adaptive timeouts, vendored
  nmap probe data, and a live UI in Topcoat"). Technical meat first,
  product second — that's what gets shared.
- Awesome-list PRs (each is a permanent inbound link).

**Phase 2 — main launch:**
- Show HN, weekday ~14:00 UTC. Title pattern: "Show HN: ntok – an
  nmap-style network scanner in Rust with a live web UI". First comment
  by you: honest scope (what it does today, what it doesn't, why
  another scanner — the cockpit-over-tools frame from §2.2).
- r/netsec post emphasizing `--tools` orchestration + nmap XML import
  (credibility signals for that audience).
- Indonesian launch in parallel: bilingual README section +
  community posts — the name story does the marketing there.

**Phase 3 — compounding content (the SEO engine):**
- Honest comparison posts: "ntok vs nmap", "ntok vs RustScan" — with
  benchmarks, methodology, and where ntok loses. Dev audiences reward
  the honest version, and comparison queries are the highest-intent
  search traffic for tools.
- Tutorials: "Import and diff your nmap scans", "Web recon on a /24",
  "Scanning from Windows: Npcap + WSL setup".
- Ecosystem posts: nuclei/masscan orchestration, AI-advisor with local
  Ollama (privacy angle: fully offline recon).
- Feature-led releases: every notable feature ships with a
  GIF/changelog entry — releases are marketing events.

## 4.4 Distribution & trust signals

- `cargo install ntok-cli` in the first README paragraph.
- Release binaries + checksums; package managers (Scoop, Homebrew, AUR)
  after v0.x stabilization.
- Kali tool submission once the CLI is stable — the credibility
  endpoint of the whole funnel.
- Repeat everywhere: **MIT/Apache-2.0, local-first, no telemetry, AI off by
  default.** For a scanner, "your targets never leave your machine" is
  a feature competitors can't all say.
- Keep vendored nmap data licensing visible (NPSL) — transparency is a
  trust signal in this community.

## 4.5 Metrics that matter (replace SaaS KPIs)

GitHub stars & forks · crates.io + release downloads · unique cloners ·
inbound links/awesome-list acceptances · HN/Reddit thread quality ·
contributor count · doc-site traffic (when it exists). Do not track or
gate behind accounts — the product has no funnel by design.

------------------------------------------------------------------------

# 5. Web & SEO strategy (corrected keywords)

## 5.1 Keyword reality check

v1 targeted OWASP Top 10 / SQLi / XSS — wrong category; that's DAST
territory ntok doesn't claim. The real search space:

| Intent | Keywords |
|---|---|
| Primary | port scanner, network scanner, open port check |
| Comparative (highest intent) | nmap alternative, rust port scanner, nmap gui, nmap xml viewer, ndiff alternative |
| Feature | website reconnaissance tool, TLS certificate inspection tool, scan diff, masscan gui |
| Localized (ID) | pemindai port, pemindai jaringan, alternatif nmap, keamanan jaringan |

## 5.2 Site architecture (when a marketing site exists)

Docs-first beats marketing-first for dev tools. Proposed split:

- `ntok.dev` (or `ntokscan.com`) — landing + docs + blog
- docs live in-repo (`docs/*.md` already exist) rendered to the site —
  one source of truth, always accurate
- `/compare/nmap`, `/compare/rustscan` — honest comparison pages
- app itself stays local; **no** `app.` subdomain or auth story until a
  hosted product exists

Bilingual: `/en/` + `/id/` with reciprocal hreflang (v1's hreflang and
canonical guidance is unchanged — see §6).

## 5.3 Page metadata (EN; ID mirrors with localized slugs)

| Page | Title | Primary keyword |
|---|---|---|
| Home | ntok — nmap-style port scanner in Rust | port scanner |
| Features | Features — scanning, recon & reports \| ntok | network scanner |
| Docs | ntok documentation — CLI & web UI | nmap alternative |
| Compare/nmap | ntok vs nmap — honest comparison | nmap alternative |
| Compare/rustscan | ntok vs RustScan — full engine vs fast front-end | rust port scanner |
| Blog | Network scanning & recon notes \| ntok | website reconnaissance |

Meta descriptions must describe real capability: "Open-source
nmap-style port scanner in Rust. Live web UI, website recon, scan
diffing, nmap XML import. MIT/Apache-2.0, local-first."

## 5.4 Technical SEO checklist (unchanged, still applies)

Unique titles/descriptions · canonicals · hreflang EN↔ID + x-default ·
sitemap.xml · robots.txt · Organization + SoftwareApplication +
Article + BreadcrumbList schema (accurate only — no invented ratings,
downloads, or reviews) · OG images on brand ramp · Search Console ·
Core Web Vitals.

------------------------------------------------------------------------

# 6. Landing page copy (EN hero — rewritten for the real product)

**Eyebrow:** OPEN-SOURCE NETWORK SCANNER · MIT/Apache-2.0

**H1:** See every open port. Live.

**Sub:** ntok is an nmap-style scanner and recon engine in Rust —
same flags, same XML, plus a live web UI, website intelligence, and
one-click scan diffing. Runs locally; your targets never leave your
machine.

**Primary CTA:** `cargo install ntok-cli` (copy-to-clipboard)
**Secondary CTA:** Watch it scan ↓ (GIF) · Read the docs

**Three principles:** Discover (ports, services, web stack) ·
Analyze (reports, diff, findings) · Track (rescan → compare drift).

**Proof blocks:** real terminal output · port-map GIF · import-nmap-XML
demo · `ntok diff` excerpt · OS badges (Windows/Linux/macOS).

**ID hero mirror:**

**Eyebrow:** PEMINDAI JARINGAN OPEN-SOURCE · MIT/Apache-2.0
**H1:** Lihat setiap port terbuka. Langsung.
**Sub:** ntok adalah pemindai dan mesin rekons gaya nmap berbasis Rust —
flag dan XML yang sama, plus UI web langsung, intelijen situs, dan diff
pemindaian satu klik. Berjalan lokal; target Anda tidak pernah keluar
dari mesin Anda.

------------------------------------------------------------------------

# 7. Content engine (bilingual blog, corrected topics)

| Category | Example posts |
|---|---|
| Scanner fundamentals | "What a port scanner actually does", "SYN vs connect scans, explained by the state machine" |
| ntok workflows | "Diff two scans and catch the port that appeared overnight", "Recon a subnet with `--web`" |
| Ecosystem | "Orchestrating masscan + nmap + nuclei from one report", "Running ntok on Windows with Npcap and WSL" |
| Honest comparisons | "ntok vs nmap vs RustScan — benchmarks and where each wins" |
| Build story (r/rust bait) | "Adaptive scan timeouts with an RTT EMA", "Parsing nmap-service-probes in Rust" |

Rules (unchanged): original technical content, reviewed for accuracy,
cite sources, clearly separate "what the tool does" from education, and
keep EN/ID parity — the ID side is where the name story and low
competition compound.

------------------------------------------------------------------------

# 8. Governance & guardrails

1. The faceted N is the primary mark; the duck is mascot + name story,
   never a logo replacement.
2. Brand colors = logo ramp (`#193153`→`#45C4EC`) on bone or navy;
   product UI follows `DESIGN.md` exactly.
3. Marketing claims must map to §1's ground-truth list — features ship
   first, copy follows.
4. **Authorized use, always:** every page/post carries "scan only
   systems you own or have permission to test." Credibility in infosec
   requires it; it's also legally prudent.
5. No telemetry, no accounts, no "early access" gating — the product's
   local-first stance is a marketing asset; don't contradict it.
6. EN and ID content carries equivalent technical information.
7. Honest comparisons only — benchmarks with methodology, credit
   competitors where they win.
8. Scanner, not shield: sell *visibility*, never "protection."

**Final brand statement:**

> **ntok** — Discover. Analyze. Secure.
> The nmap-fluent scanner in Rust, with a duck's quiet eye for what
> others leave open.
