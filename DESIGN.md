# DESIGN.md — NTOK SCAN Design System

**NTOK SCAN** — *Network Threat Observation & Knowledge*
Subtitle: **Discover. Analyze. Secure.**

Source of truth for the unified visual system across **Web (`ntok-web`)**,
**Desktop (`ntok-desktop`)**, **Browser Extension (`ntok-extension`)**,
**CLI (`ntok-cli`)**, and **Standalone HTML Reports (`ntok-core`)**.
If any surface drifts from this file, this file wins.

## Discovery context

- **Artifact**: pro tool / ops console — a network scanning dashboard
  (dashboard artifact type; density and legibility over air).
- **Audience**: security engineers, DevOps — people who read nmap output
  for a living.
- **Positioning**: technical/professional. Primary action: launch a scan
  and watch port states resolve live.
- **Adjectives**: precise, quiet, editorial, premium, instrument-like.
- **Aesthetic essence**: *night instrument* — a flight-deck gauge cluster
  or a well-typeset field log after dark: a deep royal-blue canvas,
  elevated navy panels, and obsidian telemetry islands. Elevation by
  hairline rules, lightness steps, and one floating glass layer.
  Enterprise-minimal in the lineage of observability dashboards — not a
  SaaS marketing page, not hacker-phosphor cosplay.

## Principles

1. **Data is the hero.** Chrome recedes; port states, IPs, and timings
   carry the visual weight. The loudest element on any screen is the
   freshest signal.
2. **One accent, one elevation system.** The faceted-N blue ramp is the
   only chromatic voice; hairlines are the only resting elevation.
   Anything louder is a bug, not a flourish.
3. **Live means live.** Motion exists only where state is genuinely
   changing right now — the pulsing engine dot, the running pill, the
   blink cursor. Nothing pulses for decoration.
4. **Bounded and degradable.** Every opt-in seam (AI advisor, external
   sweeps, web enrichment) degrades to a warning, never a failure;
   every display is capped — log lines, table scroll, crawl depth.
   The UI promises what the engine can keep.
5. **Designed, not inverted.** One authored night theme — every
   component reads the same semantic tokens, so the palette lives
   entirely in `:root`. The dark UI is designed, not a light theme
   photo-negatived: near-navy not `#000`, off-white not `#FFF`,
   elevation by lightness steps.

## Committed aesthetic & signature move

**Direction**: **Deep Field** — a `#050D24` royal-blue night canvas
carrying elevated navy panels, `#122148` ceramic stat tiles, and
embedded `#040A1C` obsidian telemetry islands (port map, waveform,
topology, pipeline flow, donut). One accent family: the faceted-N blue
ramp (`#2E6BE8` royal for actions, `#45C4EC` logo sky for live
telemetry inside obsidian). The single ambient gesture is a fixed
royal-blue radial glow at viewport top — atmosphere, not decoration;
it never sits inside a card.

**Restraint rules** — one elevation system, one accent, collapsed radii.
Hairline `1px` borders are the only elevation on resting cards;
`--shadow-float` exists solely for layers that physically float over
content (the floating glass nav, popovers, menus). No gradients on
fills, no colored glow shadows, no shadow + decorative-border stacking
on the same element. `--r-pill` is reserved for true pills (chips,
segmented controls, the CTA) — panels and tiles use the stepped radii.

**Signature move**: the **port map** — a dense grid of numbered port
cells, grouped per host, that lights up by state as probes land — the
grid lives on an obsidian island, so open cells fill solid `--accent-sky`
with dark numerals: open ports are the only thing a scanner should
shout about, and the logo sky is the loudest thing the palette owns.
Supporting motif: every scan echoes its args as a `$ ntok <args>`
command line.

## Typography

Three families, three jobs: **Inter** carries display — headings,
titles, big numerals. **Work Sans** carries voice and UI — body,
paragraphs, labels. **IBM Plex Mono** carries data. Mono is
subject-authentic (a scanner is a terminal tool), so it is the *data*
face — not a label accent. All three families ship as files: the web app serves bundled
woff2 from `/fonts/*` (no CDN), the extension and desktop splash embed
the same woff2 set, Android bundles TTFs in `res/font`, iOS registers
them via `UIAppFonts`. Reports keep name-first stacks so they stay
portable single files — they pick up a locally installed face and fall
back to system-ui.

| Role | Face | Notes |
|------|------|-------|
| Display (`--display`) | Inter (400/500/600/700/800) | headings, titles, hero numerals; tight `-0.04em` tracking |
| UI + body (`--sans`) | Work Sans (400/500/600/700) | paragraphs, labels, controls; sentence case |
| Data: ports, IPs, args, stats, log (`--mono`) | IBM Plex Mono (400/500/600) | tabular numerals everywhere figures appear |

Scale (used, not aspirational):

| Step | Spec | Use |
|------|------|-----|
| Display | `700 40px/1.02`, `-0.04em`, `text-wrap: balance` | `h1` page titles |
| Stage title | `700 28px/1.08`, `-0.035em` | auth-stage headline |
| Section | `700 12px`, `+0.04em`, uppercase, `--muted` | `.sec-title` |
| Brand | `800 13.5px`, `-0.02em` | wordmark in `.top` |
| Body/UI | `400–600 11–14px` | controls, lede, menus |
| Micro label | `600 10.5px` mono, `+0.08em`, uppercase | `.eyebrow`, pill keys, chart captions |

Tracking never goes past `-0.04em`; uppercase is confined to micro
labels and section titles — never body, never headings ≥ 16px.

## Color

| Token | Value | Role |
|-------|-------|------|
| `--bg` | `#050D24` | deep-field royal-blue canvas |
| `--surface` | `#0B1734` | panels, topbar, tables, popovers |
| `--ceramic` / `--ceramic-hov` | `#122148` / `#18295C` | stat tiles, segmented tracks, chips |
| `--field` / `--well` | `#081228` / `#0E1C3E` | inset inputs / inset areas (log) |
| `--line` / `--line-soft` / `--line-strong` | `#1B2C55` / `#142344` / `#2A4070` | hairline rules / separators / hover |
| `--ink` / `--fg` | `#F0F6FF` / `#C9D8F2` | headings / body text |
| `--muted` / `--faint` | `#8298BD` / `#506684` | secondary / tertiary text |
| `--obs` family | `#040A1C` + `--obs-line`/`--obs-fg`/`--obs-muted`/`--obs-faint` | obsidian telemetry islands |
| `--warn` family | `#E5BE5E` on `#261E0A` | filtered / open\|filtered cells |
| `--err` family | `#F28482` on `#2B1315` | failed scans, Stop button, banners |
| `--ok` family | `#4ADE9B` on `#0D261C` | finished status pill |
| `--accent` | `#2E6BE8` | royal blue: primary action, links, progress, running state, focus |
| `--accent-deep` / `--accent-soft` / `--accent-line` | `#2456C4` / royal .15 / sky .35 | hover navy / focus ring / checked tint |
| `--accent-sky` | `#45C4EC` | logo sky — live telemetry inside obsidian islands |
| `--on-accent` | `#FFFFFF` | text on the accent |

Brand ramp (from `MARK_SVG`): deep navy `#0B1220`/`#1B417C` → mid
`#2B62B8`/`#3B8CE2` → bright sky `#45C4EC`. Actions ride the royal
step (`#2E6BE8`), live telemetry the sky step.

State semantics: open = solid accent (the signal), filtered = amber
pastel, closed = faint neutral, unfiltered/open|filtered = amber tint,
failed = red pastel. Color is never the only signal — cells carry port
numbers and `title` tooltips, the log spells states out.

## Tokens

- **Spacing**: base 4px. Tight within a group (4–12px), loose between
  groups (16–24px), sections break at 28px (`.sec`). One uniform gap
  everywhere is a tell — spacing varies by relationship.
- **Radius**: `--r-sm: 8px` (controls, cells), `--r-md: 12px` (inputs,
  small cards, `.top` nav), `--r-lg: 16px` (panels, islands),
  `--r-pill: 999px` (chips, segmented controls, CTA, dots). Four values,
  one job each; pill is a shape reserved for interactive pills, not a
  radius tier for cards. Outer/inner radii stay concentric.
- **Glass (nav only)**: `--top-bg` = `color-mix` of `--surface` at 62%,
  `--top-blur` = `blur(16px)` + saturate,
  `--top-hi` = 1px inner edge-light. Glass exists for one reason: the
  sticky nav frosts content scrolling beneath it. It is not decoration
  and appears nowhere else except the auth-stage glass chips.
- **Elevation / depth model** — five layers, each with exactly one cue:

  | Layer | Surface | Cue |
  |-------|---------|-----|
  | L0 canvas | `--bg` | flat |
  | L1 panels | `--surface` / `--ceramic` | 1px `--line` hairline |
  | L2 insets | `--field` / `--well` | lightness step *down*, hairline |
  | L3 islands | `--obs` | darkness step + `--obs-line` hairline |
  | L4 floating | nav glass, popovers, menus | `--shadow-float` + `--top-hi` + blur |

  `z-index` is systemic, not decorative: sticky nav `20`, menus/popovers
  above it, auth canvas `0` behind its glass chips `2`. Nothing else
  carries `z-index`.
- **Motion**: `--ease = cubic-bezier(0.22, 1, 0.36, 1)` (expo-out) on
  everything; hovers .14–.22s, structural moves ≤ .45s. Animate
  `transform`/`opacity` only — plus `backdrop-filter` and `box-shadow`
  where they stay smooth. Press feedback = `scale(.985)` on `.cta-pill`.
  One ambient animation: the `pulse` dot (1.4–1.5s) on genuinely live
  markers. No entry animations on htmx-swapped fragments (they re-fire
  every poll). `prefers-reduced-motion` kills all, including the
  blink cursor.

## Layout

A detached floating glass nav (`.top`: brand mark, segmented nav,
system-status pill, account menu — `--r-md` corners, hairline +
`--shadow-float` + `--top-hi` edge-light, translucent `--top-bg` over
`--top-blur` backdrop) sits
over `<main>` at `--content-w` (72rem) with `--pad-x` gutters. Every
page opens with a `.page-head`: tight-tracked grotesk title +
right-aligned muted lede, separated by a hairline rule — the editorial
spread-header.

Page inventory: **Index** stacks error banner → scan capsule (`.frm` +
`.cta-pill`) → pipeline flow card → stat tiles → live scan-history
table. **Scan**: title + `$ ntok` command echo → live fragment (status
line, progress, stats, obsidian telemetry island with port map +
waveform, open table, log, report link). **Index/Search**: FTS5 index
browser. **Agent**: tool-calling console. **Settings**: 2-column bento
with clickable provider-preset cards. **Docs** (`/guide`, `/privacy`,
`/terms`, `/acceptable-use`): `.legal-nav` pill switcher over a
`.doc-layout` grid — measure-constrained prose (76ch) beside a sticky
`.doc-rail` "On this page" TOC built from the rendered h2/h3s; h1 keeps
the global page-title scale, h2s carry hairline section rules, hover
`#` permalinks (`.h-anchor`) with `scroll-margin-top`; the rail hides
≤900px. **Auth**: `.auth-split` — obsidian live-canvas stage beside
the form card.

Density: pro-tool — compact cells (30px), 11–13px data text, generous
section breaks.

Responsive: ≤900px collapses the
bento hero, auth split, settings, and analytics grids to one column and
hides `.sys-pill`; ≤760px collapses the form to one column, stats to
2×2, enforces `16px` input font size (preventing iOS Safari auto-zoom),
and tightens `main` padding and h1; ≤640px transitions primary navigation
to a frosted thumb-zone bottom dock (`.mob-nav`, 5 items, safe-area
padded via `env(safe-area-inset-*)`) so the topbar
stays clean and uncluttered on phones. Coarse pointers (`@media (pointer:
coarse)`) lift interactive controls to touch-friendly heights. Overflow
never reaches the page: tables scroll *inside* their panel, the technique
`.seg` strip scrolls horizontally with hidden scrollbar, `.links` wraps,
`.cmd` breaks anywhere, the scan status row wraps.

## Cross-surface adaptation (`data-surface`)

`ntok-web` serves Web, Desktop (`NTOK_SURFACE=desktop`), and Mobile
(`User-Agent` containing `NtokMobile`) from one DOM:
- **Desktop (`ntok-desktop`)**: Tauri 2 window renders the branded
  obsidian splash immediately on frame 1 (zero blank flash) while booting
  the sidecar, then navigates seamlessly; `data-surface="desktop"` enables
  thin scrollbars and non-selectable app chrome while keeping data, IPs,
  commands, and logs selectable.
- **Mobile (`ntok-mobile`)**: Android (`MainActivity.kt`) and iOS
  (`NtokMobileApp.swift`) inject `NtokMobile/1.0` into the WebView user
  agent, sync native status/navigation bar polarity via the JS theme
  bridge (`NtokAndroid.onThemeChanged` / `webkit.messageHandlers.ntokTheme`),
  and provide an obsidian offline/reconnect screen with configurable
  server URL persistence.

## Components & states

**Chrome**

- **`.top` floating nav**: glass bar — translucent `--top-bg`,
  `blur(16px) saturate()` backdrop, `--top-hi` inner edge-light,
  `--shadow-float`.
- **`.nav` segmented links**: hairline-ruled pill track on `--ceramic`;
  current page = solid `--accent` chip; hover = ink text on a `--hover`
  step chip.
- **`.sys-pill` engine status**: obsidian capsule in the topbar — muted
  key, mono value, 7px sky dot; `.live` pulses the dot (justified: the
  engine is actually alive).
- **`.foot` site footer**: hairline-topped colophon — `.foot-grid`
  carries the brand block (mark, wordmark, responsible-use tag in mono)
  beside Product and Legal link columns; `.foot-bar` is the bottom
  strip: version + "local-first, no telemetry" left, live engine-status
  echo (`.foot-status`, ok-dot idle / sky pulsing live) right. Auth
  pages render the bar alone — note + legal links — no link grid.
  ≤760px the brand block spans the row above the two link columns.
- **`.menu` popovers**: native `<details>` disclosure — caret rotates
  180° on open, pop animates `menu-in` .15s, items hairline-separated.

**Forms**

- **Scan capsule** `.frm`: two-column grid in a navy panel —
  `.scan-head` eyebrow/title/lede over a hairline rule, micro-tracked
  muted labels over `--field` inputs with a 4px `--accent-soft` focus
  ring; `.hint-chip` port presets; collapses to one column ≤760px.
  `details.adv` inside the capsule flattens to a hairline-topped row
  (boxed elsewhere).
- **`.cta-pill`**: the signature button — solid `--accent` pill with a
  44px obsidian circular arrow chip nested flush right (button-in-
  button). Hover `translateY(-1px)` + arrow `translateX(3px)
  scale(1.04)`; press `scale(.985)`; `.loading` swaps the arrow for a
  spinning ring. Title `--on-accent`, sub at 78% via `color-mix`.
- **`.seg` segmented radios** (technique, timing): hairline-ruled pill
  track on `--ceramic`; selected = raised `--hover` chip + accent text
  + inset hairline;
  hidden input keeps it a plain POST form; `focus-visible` ring via
  `+ .opt`.
- **Buttons**: primary solid accent → `--accent-deep` hover; hairline
  ghost for navigation; pastel-red danger for Stop; `.btn-white` inside
  obsidian islands.

**Data display**

- **Stats tiles**: `.tile-ceramic` tiles and `.tile-obs` obsidian hero
  metric — large grotesk tabular numerals over muted keys.
- **Port cell**: 30px chip on the obsidian island; `.open` sky-filled
  dark numeral, `.openfilt` amber pastel,
  `.filtered` amber text, `.closed` faint. `title` =
  port/proto/state/service. Hosts >4096 probed ports degrade to a
  proportion bar (`.stack`).
- **Port DataTables** `.dt`: live search, state/protocol filter pills,
  sortable headers persisted across htmx swaps; hairline row
  separators, right-aligned tabular numerals, mono data, faint row
  hover.
- **Log**: `--well` inset, `+t` timestamps faint, discoveries ink-lit,
  newest first, capped at 150 lines.

**Telemetry islands** (server-rendered SVG on `--obs`, sky accent)

- **`.wave-card`**: live waveform — spline of probes/sec from a 48-point
  ring, open-port nodes, dotted baseline, micro-label row
  (window / rate / open count). Renders inside the polled `#live`
  fragment — zero client charting.
- **`.srv-map`**: obsidian SVG cards — Detected Infrastructure topology
  (engine → host cards → port/web chips) and the **scan-flow diagram**
  (`.pf-*`): the real `run_scan` stages as a spine — TARGETS → EXPAND →
  DISCOVER → PROBE → ENRICH → REPORT → INDEX — solid links always run,
  dashed feeders are opt-in seams (AI advisor, external sweep, index
  outputs).
- **Charts**: port-state donut, RTT latency bars, area waveform —
  same obsidian + sky language, `fill`/`stroke` inline so they
  self-contain in reports.

**Auth**

- **`.auth-split`**: obsidian `.auth-stage` (cyan-grid backdrop, live
  telemetry canvas) beside the `.auth-card`. Glass `.stage-badge`,
  `.stage-live`, `.auth-stage-bottom` chips float over the canvas — the
  only other place blur is allowed.

**Feedback**

- **Status pill**: pastel chip + colored dot (running = blue-outlined,
  pulsing sky dot; finished = green; failed = red).
- **Empty/error**: dashed-rule invite on empty history; pastel-red
  banner for start failures (redirect back with message).
- **Selection**: `::selection` paints accent — the one place the accent
  fills the page outside live elements.

## Iconography

One authored set (`icons.rs`): inline SVG, 1.5px stroke, `currentColor`,
geometric construction — no icon font, no third-party set. Sizes are
systemic: 13px in nav links, 11px carets, 16–18px in section titles and
CTAs. Icons sit *before* their label and never carry meaning alone
(text or `title` always accompanies).

## Theme — Deep Field night

One theme, authored dark. There is no view switcher: every component
reads the same semantic tokens, so the entire palette lives in the
`:root` block. htmx fragments swap inside the themed document — the
theme never touches routes or views.

- **Canvas**: `#050D24` deep royal blue with a fixed ambient glow —
  two `background-attachment: fixed` radial washes at viewport top
  (royal `.24`, sky `.09`). Atmosphere only: never inside cards, never
  behind text at readable alpha.
- **Panels**: navy surfaces elevated by lightness steps + 1px hairlines
  — the same geometry a light system would use, designed for dark.
- **Accents**: royal `#2E6BE8` for actions (CTA, links, focus);
  logo sky `#45C4EC` reserved for live telemetry inside obsidian
  islands (waveform spline, open-port fills, status dots).
- **Glass**: the floating `.top` nav and `.mob-nav` dock carry the only
  blur — `--top-bg` 62% surface + `--top-blur` + `--top-hi` edge-light.
- **Native chrome**: `color-scheme: dark` everywhere (scrollbars,
  native inputs), `theme-color` `#050D24`, and the mobile theme bridge
  reports `night` so native status/nav bars stay dark.

`data-surface` (web/desktop/mobile) is orthogonal — it adjusts chrome
density and scrollbars, never the palette.

## Live data & degradation

- **Polling**: scan fragments re-render via htmx on a poll interval —
  fragments never animate entry (they'd re-fire constantly). The
  waveform samples server-side into a 48-point ring; the client draws
  nothing.
- **Opt-in seams**: AI advisor, external sweepers (masscan/naabu/
  rustscan), and tool/web enrichment are *dashed lines* in the flow
  diagram because they degrade to warnings — a scan never fails because
  an advisor endpoint or a missing binary is down. The UI mirrors the
  engine's promise.
- **Bounded display**: log capped at 150 lines, >4096-port hosts become
  `.stack` proportion bars, tables scroll inside panels, `.seg` strips
  swipe-scroll — overflow is always contained in its own region.

## Accessibility

- Focus: `:focus-visible` 2px `--accent` outline everywhere; text inputs
  add a 3px `--accent-soft` ring; segmented radios keep native rings via
  `input:focus-visible + .opt`.
- Contrast (approximate, text surfaces): `--ink`/`--fg` on
  `#050D24`/`#0B1734` ≈ 15:1 / 12:1, `--muted` on surface ≈ 5.5:1
  (secondary text only), `--on-accent` on `#2E6BE8` ≈ 4.7:1.
- Targets ≥24px (port cells 30px); real `<label for>` on inputs;
  `aria-current="page"` on nav; `aria-label` on icon-only controls;
  SVG diagrams carry `role="img"` + `aria-label`.
- Browser chrome is themed: `::selection` accent, `color-scheme: dark`
  (scrollbars, native inputs), focus rings never removed without
  replacement.
- `prefers-reduced-motion` kills all animation. Color is never the only
  signal — cells carry numbers, the log spells states out.

## Slop-audit result

Pass (re-scored at v12). No gradient fills or gradient text, no
colored glow shadows, no shadow+border stacking on resting cards, no
card-kit chrome, no tracked-out eyebrow labels stacked over headings,
no layout-property animation, no color-only signals, no marketing hero
structure inside a working console. Inter + Work Sans split display
from body deliberately — Inter's tight tracking earns the headings,
Work Sans keeps body text from reading like a system default. The remaining shadows
are structural, not decorative: `--shadow-float` on genuinely floating
layers. Blur is earmarked, not sprinkled: the sticky nav frosting
content beneath it, and the auth-stage chips over the live canvas. The
canvas glow is one fixed ambient wash — behind everything, inside
nothing. The `pulse` animation marks genuinely live edges and dies
with reduced-motion. Designed dark, not inverted: near-navy not `#000`,
off-white not `#FFF`, elevation by lightness, desaturated state tints,
royal-blue signal instead of phosphor-green cliché.

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-11-16 | Initial system: dark ops console, port-map signature, Plex Sans+Mono |
| 2.0 | 2026-11-16 | Light editorial monochrome: bone/ink palette, Instrument Serif + Switzer + Plex Mono, ink-filled open cells, pastel semantics |
| 3.0 | 2026-11-20 | friendly/terminal view switch: `data-view` token gate, dark TUI theme, localStorage persistence, `.vsw` topbar toggle |
| 3.1 | 2026-11-20 | Responsive pass: panel-internal table scroll, swipable `.seg`, wrapping links/status row, 560px topbar compaction |
| 4.0 | 2026-11-20 | Brand: ribbon-"N" mark (inline SVG, blue facet gradients) replaces the ink square; product name `ntok` everywhere |
| 5.0 | 2026-11-24 | Signal glass view (default): obsidian + smoked glass + muted emerald telemetry; server-rendered SVG waveform card fed by a 48-point ring; three-way view switch; scan-mode selector (ports/web/full); website-intel panels (tech chips, TLS, company/DNS, asset inventory) |
| 6.0 | 2026-11-24 | Brand-blue pass: `--accent`/`--accent-deep`/`--accent-soft`/`--on-accent` tokens from the logo ramp (#376AB3 / #40A1D6 / #45C4EC) replace ink-as-accent on all views; signal moves navy-obsidian; terminal rebuilt as a console window — CSS title bar with traffic-light dots, ANSI green/yellow/red state semantics, `ntok>` prompt |
| 7.0 | 2026-11-20 | Minimal pass: views renamed paper/night/terminal, paper is the default; signal glass replaced by flat **night** (no blur/glow — paper inverted); scan form rebuilt as `.ledger` spec-sheet; micro-tracked labels, `--accent-soft` input focus ring, button press state; `.signal-card` → `.wave-card` |
| 8.0 | 2026-11-20 | Cross-surface unification & rebrand: **NTOK SCAN** (*Network Threat Observation & Knowledge* · *Discover. Analyze. Secure.*); unified tokens across Web, Tauri Desktop, Browser Extension (`theme.css` + Instant Recon Cockpit), CLI (`ui.rs` ANSI terminal palette + non-tearing progress), and print-ready standalone HTML reports; mode-aware scan form, interactive port map filters, structured security-header badges, copyable commands & API tokens |
| 9.0 | 2026-11-20 | **Blue Ceramic + Obsidian Bento** evolution: Pilo-inspired modular bento architecture anchored in the faceted-N blue ramp (`#0B1220` Obsidian Navy telemetry islands, `#F3F6FA` Ceramic Mist canvas, `#E8EEF6` soft bento tiles, `#2B62B8 → #3B8CE2` Signal Cobalt pill CTAs with trailing circular arrow button, `#45C4EC` Logo Sky Cyan telemetry on obsidian); tight geometric grotesk display (`Plus Jakarta Sans` / `Switzer` 700, `-0.04em` tracking) + `IBM Plex Mono`; concentric squircle radii (`24px` / `16px` / `999px`); floating pill navigation, obsidian engine status pill, and 4-circle tactile extension dock |
| 9.1 | 2026-11-20 | **Instrument-grade detail pass**: centralized 1.5px-stroke inline SVG icon set (`icons.rs`, `currentColor`, zero icon font) across nav, forms (`.field-in` icon-prefixed inputs + `.hint-chip` port presets), operator pill + icon logout, and export toolbar; server-rendered telemetry visuals (`charts.rs`): obsidian **Detected Infrastructure** topology map (engine → host cards → port/web chips), port-state donut, RTT latency bars, area-filled waveform; **Port DataTables** (`.dt`) with live search, state/protocol filter pills, sortable headers persisted across htmx swaps; Website intelligence split into icon-led **Security & TLS** / **Infrastructure & attribution** cards with category-mapped technology chips; Settings rebuilt as 2-column bento with clickable provider preset cards |
| 10.0 | 2026-11-21 | **Restraint pass (reconciliation + minimal)**: DESIGN.md body rewritten to match shipped v9.1 reality (it still documented the retired paper/ink system); fonts Inter + Manjari → **Space Grotesk** (`--display` + `--sans`); all gradient fills killed — `--cta-grad` removed, CTA/bars use solid `--accent`/`--accent-sky`; all colored glow shadows removed (nav current, status dots, open cells, stage-live); `--shadow-sm`/`--shadow-card`/`--shadow-obs` collapsed into single `--shadow-float` used only on floating layers (nav pill, popovers) — resting cards are hairline-only; radii collapsed 5→4 (`--r-xl` folded into `--r-lg`, tightened to 8/12/16/999); `--r-pill` reserved for true pills; CTA title/sub use `--on-accent` + `color-mix`; extension `theme.css`, report CSS, and desktop splash realigned to the same tokens |
| 10.1 | 2026-11-21 | Floating nav de-pilled: `.top` drops `--r-pill` for `--r-md` (rounded-xl) and gains a per-view glass treatment — translucent `--top-bg` (color-mix of `--surface`) over a `--top-blur` backdrop-filter on paper + night; terminal opts out (`--top-bg: var(--surface)`, `--top-blur: none`) to keep flat console chrome |
| 11.0 | 2026-11-21 | **Codification + premium pass**: doc restructured from description to spec — Principles, five-layer depth model, type scale, motion spec (real `--ease` token), iconography doctrine, live-data & degradation rules; component inventory completed (`.dt`, `.srv-map`, `.pf` scan-flow diagram, `.sys-pill`, `.menu`, auth stage, settings bento); glass nav gains `--top-hi` 1px inner edge-light; stale values fixed (contrast numbers from retired ink palette, paper accent `#376AB3`→`#2B62B8` note, 1120px→72rem content width); night no-glass rule amended for the shared glass nav |
| 11.1 | 2026-11-21 | **Cross-surface Web/Desktop/Mobile craft pass**: safe-area tokens (`--sat`/`--sab`/`--sal`/`--sar`) + `viewport-fit=cover` + dynamic `theme-color`; thumb-zone `.mob-nav` bottom dock (≤640px) + coarse-pointer touch targets + 16px mobile inputs; accessible `.skip-link`, L4 `.toast` feedback pill, keyboard shortcuts (`/` focus, `Cmd/Ctrl+Enter` launch, `Alt+T` view cycle), baseline HTTP security headers (`nosniff`, `Referrer-Policy`, `X-Frame-Options`); Tauri desktop instant branded splash + async sidecar boot + error UI; Android & iOS native shells upgraded with `NtokMobile/1.0` surface detection, live status-bar theme bridge, loading progress, and branded offline/server-URL recovery overlay |
| 11.2 | 2026-11-22 | **Type split**: Space Grotesk retired — `--display` → **Inter** (400–800, headings/titles/numerals), `--sans` → **Work Sans** (400–700, body/UI); `--mono` unchanged (IBM Plex Mono). Web fetches all three via Google Fonts; extension, reports, and desktop splash switched to name-first stacks (`"Inter"`/`"Work Sans"` → system-ui fallback) — no webfont fetch on self-contained surfaces; report `--serif` token renamed `--display` to match |
| 11.3 | 2026-11-22 | **Self-hosted fonts**: web drops the Google Fonts CDN — `@font-face` in `app.css` loads bundled woff2 from `/fonts/{name}` (new whitelisted `font_route`, `include_bytes!`, immutable cache, open path in `auth_gate`); extension embeds the same woff2 set in `fonts/` (relative `@font-face`, no `web_accessible_resources` needed on extension pages); desktop splash does the same and gets Plex-first mono stacks; Android bundles `inter.ttf`/`worksans.ttf` in `res/font` (native `Resources.getFont`, API 26+, graceful fallback below); iOS gets `fonts/*.ttf` + `UIAppFonts` + `.custom()` calls. Reports intentionally stay name-first — single-file portability beats exact faces |
| 12.0 | 2026-11-23 | **Deep Field — single royal-blue night theme**: the three-view system (paper/night/terminal) is retired in favor of one authored dark theme. `#050D24` royal-blue canvas with a fixed ambient radial glow at viewport top; navy surfaces elevated by lightness steps + hairlines; royal `#2E6BE8` replaces cobalt/sky as the action accent (logo sky `#45C4EC` reserved for live telemetry in obsidian islands); `color-scheme: dark` + `theme-color #050D24`. View machinery removed: `data-view` attr + boot script, `.vsw`/appearance menu + `.top-sep`, `ntokView()`/`markView()`/Alt+T cycle, `[data-view]` overrides, terminal console chrome, blink cursor. Mobile theme bridge reports a fixed `night` |
