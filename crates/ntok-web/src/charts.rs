//! Server-rendered telemetry visuals: port-state donut, RTT latency bars,
//! and the obsidian server topology map. All output is numbers + static
//! class names only — safe to inject as `Unescaped`, zero client JS.

use ntok_core::model::{HostResult, PortState, ScanReport};
use std::fmt::Write as _;

/// Port-state donut for the analytics bento: open (sky), filtered-ish
/// (amber), closed (dim) as stroked circle arcs around an `open` callout.
/// `None` when there's nothing probed yet.
pub fn port_donut(open: usize, filtered: usize, closed: usize) -> Option<String> {
    let total = open + filtered + closed;
    if total == 0 {
        return None;
    }
    const R: f64 = 46.0;
    let c = 2.0 * std::f64::consts::PI * R;
    let f = |n: usize| n as f64 / total as f64;
    let (fo, ff) = (f(open), f(filtered));
    // arcs drawn clockwise from 12 o'clock: open -> filtered -> closed(rest)
    let mut s = String::with_capacity(700);
    let _ = write!(
        s,
        "<svg class=\"donut\" viewBox=\"0 0 120 120\" role=\"img\" aria-label=\"port state distribution\">\
         <circle class=\"d-track\" cx=\"60\" cy=\"60\" r=\"{R}\"/>\
         <circle class=\"d-open\" cx=\"60\" cy=\"60\" r=\"{R}\" \
           stroke-dasharray=\"{a:.2} {c:.2}\" transform=\"rotate(-90 60 60)\"/>",
        a = fo * c
    );
    if ff > 0.0 {
        let _ = write!(
            s,
            "<circle class=\"d-filt\" cx=\"60\" cy=\"60\" r=\"{R}\" \
             stroke-dasharray=\"{a:.2} {c:.2}\" \
             stroke-dashoffset=\"{off:.2}\" transform=\"rotate(-90 60 60)\"/>",
            a = ff * c,
            off = -fo * c
        );
    }
    let _ = write!(
        s,
        "<text class=\"d-num\" x=\"60\" y=\"58\" text-anchor=\"middle\">{open}</text>\
         <text class=\"d-lbl\" x=\"60\" y=\"73\" text-anchor=\"middle\">open</text></svg>"
    );
    Some(s)
}

/// Latency bars for open ports, slowest first — exposes proxied/slow
/// services instantly. HTML (not SVG) so text stays crisp. `None` when
/// no RTT data exists (e.g. imported reports without timings).
pub fn rtt_bars(report: &ScanReport) -> Option<String> {
    let mut rows: Vec<(&std::net::IpAddr, u16, &str, &str, f64)> = Vec::new();
    for h in &report.hosts {
        for p in &h.ports {
            if p.state.is_open()
                && let Some(r) = p.rtt_ms
            {
                rows.push((
                    &h.ip,
                    p.port,
                    p.protocol.as_str(),
                    p.service.as_deref().unwrap_or(""),
                    r,
                ));
            }
        }
    }
    if rows.is_empty() {
        return None;
    }
    rows.sort_by(|a, b| b.4.partial_cmp(&a.4).unwrap_or(std::cmp::Ordering::Equal));
    let max = rows.first().map(|r| r.4).unwrap_or(1.0).max(1.0);
    let mut s = String::with_capacity(1400);
    s.push_str("<div class=\"rtt\">");
    for (ip, port, proto, svc, r) in rows.iter().take(8) {
        let w = (r / max * 100.0).clamp(4.0, 100.0);
        let label = if svc.is_empty() {
            format!("{port}/{proto}")
        } else {
            format!("{port}/{proto} · {svc}")
        };
        let _ = write!(
            s,
            "<div class=\"rtt-row\" title=\"{ip} — {label} — {r:.1} ms\">\
             <span class=\"rtt-name\">{label}</span>\
             <span class=\"rtt-bar\"><i style=\"--w:{w:.0}%\"></i></span>\
             <span class=\"rtt-ms\">{r:.1}<small>ms</small></span></div>"
        );
    }
    if rows.len() > 8 {
        let _ = write!(
            s,
            "<div class=\"rtt-more\">+{} more open ports</div>",
            rows.len() - 8
        );
    }
    s.push_str("</div>");
    Some(s)
}

// ---------- server topology map ----------

const MAP_W: f64 = 960.0;
const HOST_X: f64 = 300.0;
const HOST_W: f64 = 240.0;
const HOST_H: f64 = 86.0;
const CHIP_X: f64 = 640.0;
const CHIP_W: f64 = 176.0;
const CHIP_H: f64 = 26.0;
const CHIP_GAP: f64 = 8.0;
const MAX_HOST_ROWS: usize = 6;
const MAX_CHIPS: usize = 6;

fn esc(t: &mut String, s: &str) {
    for c in s.chars() {
        t.push_str(match c {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            _ => {
                t.push(c);
                continue;
            }
        });
    }
}

fn txt(t: &mut String, s: &str, max: usize) {
    let short: String = s.chars().take(max).collect();
    esc(t, &short);
    if s.chars().count() > max {
        t.push('…');
    }
}

/// Curved link between two anchor points (horizontal bezier).
fn link(t: &mut String, x1: f64, y1: f64, x2: f64, y2: f64, cls: &str) {
    let mx = (x1 + x2) / 2.0;
    let _ = write!(
        t,
        "<path class=\"{cls}\" d=\"M{x1:.0} {y1:.0} C{mx:.0} {y1:.0} {mx:.0} {y2:.0} {x2:.0} {y2:.0}\"/>"
    );
}

/// The obsidian server map: NTOK engine -> detected hosts -> open
/// port/service and web chips, wired with telemetry links. Built only
/// from `ScanReport` data — `None` when the report has no hosts.
pub fn server_map(report: &ScanReport) -> Option<String> {
    if report.hosts.is_empty() {
        return None;
    }
    let hosts: Vec<&HostResult> = report.hosts.iter().take(MAX_HOST_ROWS).collect();
    let extra_hosts = report.hosts.len().saturating_sub(hosts.len());

    // Per-host row: card height or chip fan height, whichever is taller.
    struct Row {
        /// All chip `<g>` strings concatenated, `%Y` marking each translate offset.
        chips: String,
        card: String,
        h: f64,
    }
    let mut rows: Vec<Row> = Vec::with_capacity(hosts.len() + 1);

    for h in &hosts {
        let slug = h.ip.to_string().replace(['.', ':'], "-");
        let open_ports: Vec<_> = h.ports.iter().filter(|p| p.state.is_open()).collect();
        // Port chips first (open only — filtered noise would bury signal),
        // then one web chip per profiled endpoint.
        let mut chips = String::new();
        let mut n_chips = 0usize;
        let mut leftover = String::new();
        for p in &open_ports {
            if n_chips >= MAX_CHIPS {
                break;
            }
            let mut label = String::new();
            let _ = write!(label, "{}/{}", p.port, p.protocol.as_str());
            if let Some(s) = &p.service {
                let _ = write!(label, " · {s}");
            }
            let mut t = String::new();
            txt(&mut t, &label, 22);
            chips.push_str(&format!(
                "<a href=\"#p-{slug}-{}\"><g class=\"sm-chip open\" transform=\"translate({CHIP_X:.0},%Y)\">\
                 <rect width=\"{CHIP_W:.0}\" height=\"{CHIP_H:.0}\" rx=\"13\"/>\
                 <circle cx=\"14\" cy=\"{cy}\" r=\"3.4\"/>\
                 <text x=\"26\" y=\"{ty}\">{t}</text></g></a>",
                p.port,
                cy = CHIP_H / 2.0,
                ty = CHIP_H / 2.0 + 3.5
            ));
            n_chips += 1;
        }
        let mut extra = open_ports.len().saturating_sub(n_chips);
        for w in &h.web_profiles {
            if n_chips >= MAX_CHIPS {
                extra += 1;
                continue;
            }
            let mut t = String::new();
            txt(&mut t, &w.final_url, 24);
            chips.push_str(&format!(
                "<g class=\"sm-chip web\" transform=\"translate({CHIP_X:.0},%Y)\">\
                 <rect width=\"{CHIP_W:.0}\" height=\"{CHIP_H:.0}\" rx=\"13\"/>\
                 <circle cx=\"14\" cy=\"{cy}\" r=\"4.2\" fill=\"none\"/>\
                 <path d=\"M9.8 {cy}h8.4M14 {cy1}a4.4 4.4 0 0 1 0 8 4.4 4.4 0 0 1 0-8Z\"/>\
                 <text x=\"26\" y=\"{ty}\">{t}</text></g>",
                cy = CHIP_H / 2.0,
                cy1 = CHIP_H / 2.0 - 4.4,
                ty = CHIP_H / 2.0 + 3.5
            ));
            n_chips += 1;
        }
        if extra > 0 {
            leftover = format!(
                "<g class=\"sm-chip more\" transform=\"translate({CHIP_X:.0},%Y)\">\
                 <rect width=\"{CHIP_W:.0}\" height=\"{CHIP_H:.0}\" rx=\"13\"/>\
                 <text x=\"{CHIP_W2:.0}\" y=\"{ty}\" text-anchor=\"middle\">+{extra} more</text></g>",
                CHIP_W2 = CHIP_W / 2.0,
                ty = CHIP_H / 2.0 + 3.5
            );
            n_chips += 1;
        }

        // Host card: status dot, IP, hostname, OS · open badge.
        let up = h.state == ntok_core::HostState::Up;
        let mut card = String::with_capacity(600);
        card.push_str(&format!(
            "<a href=\"#host-{slug}\"><g class=\"sm-host{}\">\
             <rect width=\"{HOST_W:.0}\" height=\"{HOST_H:.0}\" rx=\"14\"/>\
             <circle class=\"sdot\" cx=\"18\" cy=\"22\" r=\"4.2\"/>",
            if up { " up" } else { "" }
        ));
        let mut ip = String::new();
        txt(&mut ip, &h.ip.to_string(), 20);
        let _ = write!(card, "<text class=\"hip\" x=\"32\" y=\"26\">{ip}</text>");
        if let Some(n) = &h.hostname {
            let mut t = String::new();
            txt(&mut t, n, 26);
            let _ = write!(card, "<text class=\"hname\" x=\"32\" y=\"42\">{t}</text>");
        }
        let mut sub = h.reason.clone();
        if let Some(os) = &h.os_guess {
            let _ = write!(sub, " · {os}");
        }
        let mut t = String::new();
        txt(&mut t, &sub, 30);
        let _ = write!(
            card,
            "<text class=\"hmeta\" x=\"18\" y=\"{y}\">{t}</text>",
            y = HOST_H - 14.0
        );
        let n_open = open_ports.len();
        if n_open > 0 {
            let _ = write!(
                card,
                "<g class=\"hopen\"><rect x=\"{x:.0}\" y=\"12\" width=\"62\" height=\"20\" rx=\"10\"/>\
                 <text x=\"{cx:.0}\" y=\"26\" text-anchor=\"middle\">{n_open} open</text></g>",
                x = HOST_W - 74.0,
                cx = HOST_W - 43.0
            );
        }
        if !h.web_profiles.is_empty() {
            card.push_str(&format!(
                "<g class=\"hweb\"><rect x=\"{x:.0}\" y=\"{y:.0}\" width=\"44\" height=\"18\" rx=\"9\"/>\
                 <text x=\"{cx:.0}\" y=\"{ty:.0}\" text-anchor=\"middle\">web</text></g>",
                x = HOST_W - 56.0,
                y = HOST_H - 28.0,
                cx = HOST_W - 34.0,
                ty = HOST_H - 15.5
            ));
        }
        card.push_str("</g></a>");

        let chips_h = n_chips as f64 * (CHIP_H + CHIP_GAP);
        rows.push(Row {
            chips: chips + &leftover,
            card,
            h: chips_h.max(HOST_H + 12.0) + 26.0,
        });
    }

    if extra_hosts > 0 {
        rows.push(Row {
            chips: String::new(),
            card: format!(
                "<g class=\"sm-host more\"><rect width=\"{HOST_W:.0}\" height=\"{HOST_H:.0}\" rx=\"14\"/>\
                 <text x=\"{cx:.0}\" y=\"{cy:.0}\" text-anchor=\"middle\">+{extra_hosts} more hosts</text>\
                 <text class=\"hmeta\" x=\"{cx:.0}\" y=\"{cy2:.0}\" text-anchor=\"middle\">see host detail</text></g>",
                cx = HOST_W / 2.0,
                cy = HOST_H / 2.0 - 2.0,
                cy2 = HOST_H / 2.0 + 15.0
            ),
            h: HOST_H + 26.0,
        });
    }

    let head = 66.0;
    let h_total = head + rows.iter().map(|r| r.h).sum::<f64>() + 10.0;
    let engine_y = h_total / 2.0;

    let mut s = String::with_capacity(4_096);
    let _ = write!(
        s,
        "<svg class=\"srv-map-svg\" viewBox=\"0 0 {MAP_W:.0} {h_total:.0}\" \
         role=\"img\" aria-label=\"detected server topology\">"
    );

    // Radar halo behind the engine node.
    let _ = write!(
        s,
        "<circle class=\"sm-halo\" cx=\"110\" cy=\"{engine_y:.0}\" r=\"52\"/>\
         <circle class=\"sm-halo2\" cx=\"110\" cy=\"{engine_y:.0}\" r=\"34\"/>"
    );

    // Links first so nodes sit on top.
    let mut y = head;
    for r in &rows {
        let card_cy = y + r.h / 2.0;
        link(&mut s, 150.0, engine_y, HOST_X, card_cy, "sm-link");
        // trunk + branch to each chip
        let n = r.chips.matches("%Y").count();
        if n > 0 {
            let chips_h = n as f64 * (CHIP_H + CHIP_GAP) - CHIP_GAP;
            let chips_top = card_cy - chips_h / 2.0;
            link(
                &mut s,
                HOST_X + HOST_W,
                card_cy,
                CHIP_X - 26.0,
                card_cy,
                "sm-link dim",
            );
            for i in 0..n {
                let cy = chips_top + i as f64 * (CHIP_H + CHIP_GAP) + CHIP_H / 2.0;
                link(&mut s, CHIP_X - 26.0, card_cy, CHIP_X, cy, "sm-link dim");
            }
        }
        y += r.h;
    }

    // Engine node: faceted brand mark on the radar disc (nested svg so the
    // canonical mark stays the single source of truth).
    let mark = ntok_core::brand::MARK_SVG.replacen(
        "<svg ",
        "<svg x=\"-17\" y=\"-12.2\" width=\"34\" height=\"24.4\" ",
        1,
    );
    let _ = write!(
        s,
        "<g class=\"sm-engine\" transform=\"translate(110,{engine_y:.0})\">\
         <circle r=\"26\"/>{mark}\
         <text class=\"e-lbl\" y=\"48\" text-anchor=\"middle\">NTOK ENGINE</text>\
         <text class=\"e-sub\" y=\"63\" text-anchor=\"middle\">local · zero telemetry</text></g>"
    );

    // Header labels.
    let _ = write!(
        s,
        "<text class=\"sm-col\" x=\"{HOST_X:.0}\" y=\"30\">DETECTED SERVERS</text>\
         <text class=\"sm-col\" x=\"{CHIP_X:.0}\" y=\"30\">OPEN SERVICES & WEB</text>"
    );

    // Rows: host card + chips.
    let mut y = head;
    for r in &rows {
        let card_cy = y + r.h / 2.0;
        let card_y = card_cy - HOST_H / 2.0;
        let _ = write!(
            s,
            "<g transform=\"translate({HOST_X:.0},{card_y:.0})\">{}</g>",
            r.card
        );
        if !r.chips.is_empty() {
            // %Y placeholder per chip -> stacked offset.
            let mut chips = String::new();
            let n = r.chips.matches("%Y").count();
            let chips_h = n as f64 * (CHIP_H + CHIP_GAP) - CHIP_GAP;
            let chips_top = card_cy - chips_h / 2.0;
            for (i, part) in r.chips.split("%Y").enumerate() {
                if i > 0 {
                    let _ = write!(
                        chips,
                        "{:.0}",
                        chips_top + (i - 1) as f64 * (CHIP_H + CHIP_GAP)
                    );
                }
                chips.push_str(part);
            }
            s.push_str(&chips);
        }
        y += r.h;
    }

    s.push_str("</svg>");
    Some(s)
}

/// Scan-pipeline transparency diagram for the index page — the real
/// `run_scan` stages. The solid spine always runs; dashed feeders are
/// the opt-in seams (AI advisor, external sweeps, tool/web enrichment)
/// that degrade to warnings rather than fail a scan. Fully static —
/// safe for `Unescaped`.
pub fn pipeline_map() -> &'static str {
    PIPELINE_SVG
}

const PIPELINE_SVG: &str = r#"
<svg class="pf-svg" viewBox="0 0 1100 282" role="img" aria-label="ntok scan pipeline — targets to report to index">
<defs><marker id="pf-arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path class="pf-arr" d="M0.5 0.5 7.5 4 0.5 7.5Z"/></marker></defs>
<g class="pf-stage opt" transform="translate(430,24)"><rect width="210" height="42" rx="10"/><text class="pf-name" x="105" y="18" text-anchor="middle">AI ADVISOR</text><text class="pf-sub" x="105" y="32" text-anchor="middle">plan → summary · off by default</text></g>
<path class="pf-dlink" d="M466 66 C410 84 356 108 324 143" marker-end="url(#pf-arr)"/>
<text class="pf-note" x="334" y="112">plan</text>
<path class="pf-dlink" d="M604 66 C660 84 716 110 764 143" marker-end="url(#pf-arr)"/>
<text class="pf-note" x="710" y="112">summary</text>
<path class="pf-link" d="M150 151h22" marker-end="url(#pf-arr)"/>
<path class="pf-link" d="M302 151h22" marker-end="url(#pf-arr)"/>
<path class="pf-link" d="M454 151h22" marker-end="url(#pf-arr)"/>
<path class="pf-link" d="M606 151h22" marker-end="url(#pf-arr)"/>
<path class="pf-link" d="M758 151h22" marker-end="url(#pf-arr)"/>
<path class="pf-link" d="M910 151h22" marker-end="url(#pf-arr)"/>
<path class="pf-flow" d="M150 151h22" style="animation-delay:-0s"/>
<path class="pf-flow" d="M302 151h22" style="animation-delay:-0.25s"/>
<path class="pf-flow" d="M454 151h22" style="animation-delay:-0.5s"/>
<path class="pf-flow" d="M606 151h22" style="animation-delay:-0.75s"/>
<path class="pf-flow" d="M758 151h22" style="animation-delay:-1s"/>
<path class="pf-flow" d="M910 151h22" style="animation-delay:-1.25s"/>
<g class="pf-stage" transform="translate(20,118)" style="--pd:0s"><rect width="130" height="66" rx="10"/><text class="pf-name" x="65" y="26" text-anchor="middle">TARGETS</text><text class="pf-sub" x="65" y="42" text-anchor="middle">ip · cidr · url · range</text></g>
<g class="pf-stage" transform="translate(172,118)" style="--pd:0.8s"><rect width="130" height="66" rx="10"/><text class="pf-name" x="65" y="26" text-anchor="middle">EXPAND</text><text class="pf-sub" x="65" y="42" text-anchor="middle">dns → host list</text></g>
<g class="pf-stage" transform="translate(324,118)" style="--pd:1.6s"><rect width="130" height="66" rx="10"/><text class="pf-name" x="65" y="26" text-anchor="middle">DISCOVER</text><text class="pf-sub" x="65" y="42" text-anchor="middle">tcp-ping + icmp</text><text class="pf-note" x="65" y="57" text-anchor="middle">-Pn skips</text></g>
<g class="pf-stage" transform="translate(476,118)" style="--pd:2.4s"><rect width="130" height="66" rx="10"/><text class="pf-name" x="65" y="26" text-anchor="middle">PROBE</text><text class="pf-sub" x="65" y="42" text-anchor="middle">connect · syn · udp · -sV</text><text class="pf-note" x="65" y="57" text-anchor="middle">bounded + adaptive</text></g>
<g class="pf-stage opt" transform="translate(628,118)"><rect width="130" height="66" rx="10"/><text class="pf-name" x="65" y="26" text-anchor="middle">ENRICH</text><text class="pf-sub" x="65" y="42" text-anchor="middle">nmap · nuclei · web recon</text></g>
<g class="pf-stage" transform="translate(780,118)" style="--pd:4s"><rect width="130" height="66" rx="10"/><text class="pf-name" x="65" y="26" text-anchor="middle">REPORT</text><text class="pf-sub" x="65" y="42" text-anchor="middle">json · xml · csv · html</text></g>
<g class="pf-stage" transform="translate(932,118)" style="--pd:4.8s"><rect width="130" height="66" rx="10"/><text class="pf-name" x="65" y="26" text-anchor="middle">INDEX</text><text class="pf-sub" x="65" y="42" text-anchor="middle">sqlite fts5 + edges</text></g>
<g class="pf-stage opt" transform="translate(314,218)"><rect width="150" height="42" rx="10"/><text class="pf-name" x="75" y="18" text-anchor="middle">EXT SWEEP</text><text class="pf-sub" x="75" y="32" text-anchor="middle">masscan · naabu · rustscan</text></g>
<path class="pf-dlink" d="M389 218V188" marker-end="url(#pf-arr)"/>
<text class="pf-note" x="398" y="206">replaces discovery</text>
<path class="pf-dlink" d="M997 184 C940 196 760 206 690 230" marker-end="url(#pf-arr)"/>
<path class="pf-dlink" d="M997 184 C960 198 850 210 806 230" marker-end="url(#pf-arr)"/>
<path class="pf-dlink" d="M997 184 C985 200 950 212 922 230" marker-end="url(#pf-arr)"/>
<path class="pf-dlink" d="M997 184 C1010 198 1026 212 1038 230" marker-end="url(#pf-arr)"/>
<g class="pf-out" transform="translate(636,232)"><rect width="108" height="26" rx="13"/><text x="54" y="17" text-anchor="middle">search · ask</text></g>
<g class="pf-out" transform="translate(752,232)"><rect width="108" height="26" rx="13"/><text x="54" y="17" text-anchor="middle">diff</text></g>
<g class="pf-out" transform="translate(868,232)"><rect width="108" height="26" rx="13"/><text x="54" y="17" text-anchor="middle">graph · subs</text></g>
<g class="pf-out" transform="translate(984,232)"><rect width="108" height="26" rx="13"/><text x="54" y="17" text-anchor="middle">agent · mcp</text></g>
<text class="pf-note" x="20" y="276">every stage bounded — ports · concurrency · timeouts · bodies · crawl depth</text>
</svg>"#;

/// Count every probed port state across a report (donut + summary feeds).
/// Returns (open, filtered-ish, closed).
pub fn port_state_counts(report: &ScanReport) -> (usize, usize, usize) {
    let mut o = 0;
    let mut f = 0;
    let mut c = 0;
    for h in &report.hosts {
        for p in &h.ports {
            match p.state {
                PortState::Open | PortState::OpenFiltered => o += 1,
                PortState::Filtered | PortState::Unfiltered => f += 1,
                PortState::Closed => c += 1,
            }
        }
    }
    (o, f, c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntok_core::model::{HostState, Protocol, ScanSummary};
    use std::net::IpAddr;

    fn port(n: u16, state: PortState) -> ntok_core::model::PortResult {
        ntok_core::model::PortResult {
            port: n,
            protocol: Protocol::Tcp,
            state,
            service: Some("http".into()),
            banner: None,
            reason: "syn-ack".into(),
            rtt_ms: Some(1.2),
        }
    }

    #[test]
    fn pipeline_map_covers_engine_stages() {
        let svg = pipeline_map();
        for stage in [
            "TARGETS", "EXPAND", "DISCOVER", "PROBE", "ENRICH", "REPORT", "INDEX",
        ] {
            assert!(svg.contains(stage), "missing {stage}");
        }
        // Opt-in seams drawn dashed: advisor, external sweep, index outputs.
        assert!(svg.contains("AI ADVISOR"));
        assert!(svg.contains("EXT SWEEP"));
        assert!(svg.contains("pf-dlink"));
    }

    #[test]
    fn server_map_embeds_brand_mark() {
        let report = ScanReport {
            scanner: "ntok".into(),
            version: "0.1.0".into(),
            args: "scanme".into(),
            technique: "connect".into(),
            start_unix: 0,
            end_unix: 1,
            elapsed_secs: 1.0,
            hosts: vec![HostResult {
                ip: IpAddr::from([93, 184, 216, 34]),
                hostname: Some("example.com".into()),
                state: HostState::Up,
                reason: "syn-ack".into(),
                ports: vec![port(80, PortState::Open), port(443, PortState::Open)],
                os_guess: None,
                findings: vec![],
                web_profiles: vec![],
            }],
            summary: ScanSummary::default(),
        };
        let svg = server_map(&report).unwrap();
        assert!(svg.contains("sm-engine"));
        // Nested brand mark, sized into the engine disc — not the old stroked N.
        assert!(svg.contains("viewBox=\"0 0 209 150\""));
        assert!(svg.contains("url(#g0)"));
    }
}
