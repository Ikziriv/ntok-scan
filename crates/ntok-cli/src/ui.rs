//! Terminal presentation layer for NTOK SCAN CLI.
//!
//! Enforces a strict TTY vs pipe contract:
//! - Interactive TTY (unless `NO_COLOR` or `--color never`): aligned tables,
//!   non-tearing progress bar on stderr, and ANSI semantics matching DESIGN.md.
//! - Piped / non-TTY (unless `--color always`): clean, deterministic, ANSI-free
//!   output safe for grep, awk, and CI logs.

use clap::ValueEnum;
use ntok_core::diff::ScanDiff;
use ntok_core::model::{HostState, PortState, ScanReport, WebProfile};
use std::io::{IsTerminal, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug)]
pub struct Ui {
    pub out_color: bool,
    pub err_color: bool,
    pub err_tty: bool,
    pub quiet: bool,
}

impl Ui {
    pub fn new(choice: ColorChoice, quiet: bool) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        let force = std::env::var("CLICOLOR_FORCE")
            .ok()
            .is_some_and(|v| !v.is_empty() && v != "0");
        let out_tty = std::io::stdout().is_terminal();
        let err_tty = std::io::stderr().is_terminal();
        let resolve = |tty: bool| match choice {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => (tty || force) && !no_color,
        };
        Self {
            out_color: resolve(out_tty),
            err_color: resolve(err_tty),
            err_tty,
            quiet,
        }
    }

    pub fn banner(&self, subcommand: &str) {
        if self.quiet || !self.err_tty {
            return;
        }
        let dot = self.e_cyan("●");
        let name = self.e_bold_cyan(ntok_core::brand::NAME);
        let ver = self.e_dim(concat!("v", env!("CARGO_PKG_VERSION")));
        let sub = self.e_bold(ntok_core::brand::SUBTITLE);
        let exp = self.e_dim(ntok_core::brand::EXPANSION);
        let cmd = self.e_cyan(&format!("[ {subcommand} ]"));
        let rule = self.e_dim(&"─".repeat(66));
        eprintln!("{dot} {name} {ver}  ·  {sub}  {cmd}");
        eprintln!("  {exp}");
        eprintln!("{rule}");
    }

    pub fn clear_progress(&self) {
        if self.err_tty {
            eprint!("\r\x1b[2K");
            let _ = std::io::stderr().flush();
        }
    }

    pub fn progress(&self, done: usize, total: usize, open: usize, elapsed_secs: f64) {
        if self.quiet || !self.err_tty || total == 0 {
            return;
        }
        let frac = (done as f64 / total as f64).clamp(0.0, 1.0);
        let width = 24usize;
        let filled = ((frac * width as f64).round() as usize).min(width);
        let bar_on = "━".repeat(filled);
        let bar_off = "─".repeat(width - filled);
        let rate = if elapsed_secs > 0.05 {
            done as f64 / elapsed_secs
        } else {
            0.0
        };
        let pct = (frac * 100.0).round() as u8;
        let open_s = if open > 0 {
            self.e_cyan(&format!("● {open} open"))
        } else {
            self.e_dim("○ 0 open")
        };
        eprint!(
            "\r\x1b[2K  {}{} {:>3}%  ·  {}/{}  ·  {}  ·  {:.0}/s  ·  {:.1}s",
            self.e_cyan(&bar_on),
            self.e_dim(&bar_off),
            pct,
            done,
            total,
            open_s,
            rate,
            elapsed_secs
        );
        let _ = std::io::stderr().flush();
    }

    pub fn print_discovered(
        &self,
        state: PortState,
        port: u16,
        proto: &str,
        ip: &str,
        svc: Option<&str>,
    ) {
        self.clear_progress();
        let svc_str = svc.map(|s| format!(" ({s})")).unwrap_or_default();
        if !self.out_color {
            println!(
                "Discovered {} port {port}/{proto} on {ip}{svc_str}",
                state.as_str()
            );
            return;
        }
        let badge = match state {
            PortState::Open => self.o_green("OPEN"),
            PortState::OpenFiltered | PortState::Filtered => self.o_yellow(state.as_str()),
            PortState::Unfiltered => self.o_cyan("unfiltered"),
            PortState::Closed => self.o_dim("closed"),
        };
        println!(
            "  {}  {:<10} {} {}{}",
            self.o_cyan("•"),
            badge,
            self.o_bold(&format!("{port}/{proto}")),
            ip,
            self.o_dim(&svc_str)
        );
    }

    pub fn print_summary(&self, report: &ScanReport) {
        self.clear_progress();
        if self.quiet {
            return;
        }
        let s = &report.summary;
        if !self.err_color {
            eprintln!(
                "\n{} done: {} up / {} down, {} open, {} closed, {} filtered in {:.2}s",
                ntok_core::brand::NAME,
                s.hosts_up,
                s.hosts_down,
                s.open,
                s.closed,
                s.filtered,
                report.elapsed_secs
            );
            return;
        }
        let rule = self.e_dim(&"─".repeat(64));
        eprintln!("\n{rule}");
        eprintln!(
            "  {}  {} up {}  ·  {} open  ·  {} closed  ·  {} filtered  ·  {}",
            self.e_bold_cyan("DONE"),
            self.e_bold(&s.hosts_up.to_string()),
            self.e_dim(&format!("/ {} down", s.hosts_down)),
            if s.open > 0 {
                self.e_green(&s.open.to_string())
            } else {
                self.e_dim("0")
            },
            self.e_dim(&s.closed.to_string()),
            if s.filtered > 0 {
                self.e_yellow(&s.filtered.to_string())
            } else {
                self.e_dim("0")
            },
            self.e_dim(&format!("{:.2}s", report.elapsed_secs))
        );
    }

    pub fn print_scan_report(&self, report: &ScanReport) {
        if !self.out_color {
            print!("{}", ntok_core::report::to_normal(report));
            return;
        }
        for host in &report.hosts {
            let name = host
                .hostname
                .as_deref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default();
            let state = if host.state == HostState::Up {
                self.o_green("up")
            } else {
                self.o_dim("down")
            };
            let os = host
                .os_guess
                .as_deref()
                .map(|o| format!(" · {o}"))
                .unwrap_or_default();
            println!(
                "\n{} {}{}  [{}]  {}",
                self.o_cyan("▸"),
                self.o_bold(&host.ip.to_string()),
                self.o_dim(&name),
                state,
                self.o_dim(&format!("{}{os}", host.reason))
            );
            if !host.ports.is_empty() {
                println!(
                    "  {}  {}  {}  {}",
                    self.o_dim(&format!("{:<11}", "PORT")),
                    self.o_dim(&format!("{:<14}", "STATE")),
                    self.o_dim(&format!("{:<26}", "SERVICE")),
                    self.o_dim("RTT")
                );
                for p in &host.ports {
                    let port_col = format!("{}/{}", p.port, p.protocol.as_str());
                    let st_raw = format!("{:<14}", p.state.as_str());
                    let st = match p.state {
                        PortState::Open => self.o_green(&st_raw),
                        PortState::Filtered | PortState::OpenFiltered => self.o_yellow(&st_raw),
                        PortState::Unfiltered => self.o_cyan(&st_raw),
                        PortState::Closed => self.o_dim(&st_raw),
                    };
                    let svc = match (&p.service, &p.banner) {
                        (Some(s), Some(b)) => format!("{s} — {b}"),
                        (Some(s), None) => s.clone(),
                        _ => "—".into(),
                    };
                    let rtt = p
                        .rtt_ms
                        .map(|r| format!("{r:.1}ms"))
                        .unwrap_or_else(|| "—".into());
                    println!(
                        "  {:<11}  {}  {:<26}  {}",
                        if p.state.is_open() {
                            self.o_bold(&port_col)
                        } else {
                            port_col
                        },
                        st,
                        svc,
                        self.o_dim(&rtt)
                    );
                }
            }
            if !host.findings.is_empty() {
                println!("  {}", self.o_dim("FINDINGS"));
                for f in &host.findings {
                    let sev = match f.severity.as_str() {
                        "critical" | "high" => self.o_red(&f.severity),
                        "medium" => self.o_yellow(&f.severity),
                        _ => self.o_dim(&f.severity),
                    };
                    let port = f.port.map(|p| format!(":{p}")).unwrap_or_default();
                    println!("    [{sev}] {}{port} — {}", f.tool, f.detail);
                }
            }
            for w in &host.web_profiles {
                self.print_web_compact(w);
            }
        }
    }

    fn print_web_compact(&self, w: &WebProfile) {
        let status = if w.status == 0 {
            self.o_red("no response")
        } else if w.status >= 400 {
            self.o_red(&w.status.to_string())
        } else {
            self.o_green(&w.status.to_string())
        };
        let srv = w
            .server
            .as_deref()
            .map(|s| format!(" · {s}"))
            .unwrap_or_default();
        println!(
            "  {} {} [{}] {}{}",
            self.o_cyan("WEB"),
            self.o_bold(&w.url),
            status,
            self.o_dim(&format!("{} · {}ms", w.http_version, w.ttfb_ms)),
            self.o_dim(&srv)
        );
        if !w.technologies.is_empty() {
            let techs = w
                .technologies
                .iter()
                .take(10)
                .map(|t| match &t.version {
                    Some(v) => format!("{} {v}", t.name),
                    None => t.name.clone(),
                })
                .collect::<Vec<_>>()
                .join(", ");
            println!("    {} {techs}", self.o_dim("tech:"));
        }
        if let Some(t) = &w.tls {
            let mut flags = String::new();
            if t.expired {
                flags.push_str(&format!(" {}", self.o_red("EXPIRED")));
            }
            if t.self_signed {
                flags.push_str(&format!(" {}", self.o_yellow("self-signed")));
            }
            println!(
                "    {} {} {}{}",
                self.o_dim("tls: "),
                t.protocol,
                t.subject_cn.as_deref().unwrap_or("—"),
                flags
            );
        }
    }

    pub fn print_lookup(&self, p: &WebProfile) {
        let status_raw = if p.status == 0 {
            "no response".to_string()
        } else {
            p.status.to_string()
        };
        let status = if !self.out_color {
            status_raw
        } else if p.status == 0 || p.status >= 400 {
            self.o_red(&status_raw)
        } else {
            self.o_green(&status_raw)
        };
        let meta_tail = format!(
            "{}{}",
            p.server
                .as_deref()
                .map(|s| format!(" · {s}"))
                .unwrap_or_default(),
            p.powered_by
                .as_deref()
                .map(|s| format!(" · {s}"))
                .unwrap_or_default()
        );
        println!(
            "{}  [{}]  {}{}",
            self.o_bold(&p.final_url),
            status,
            self.o_dim(&format!("{} · {}ms", p.http_version, p.ttfb_ms)),
            self.o_dim(&meta_tail)
        );
        if p.final_url != p.url {
            println!("  {} {}", self.o_dim("redirected:"), p.url);
        }
        for c in &p.company.names {
            println!("  {} {c}", self.o_dim("company:   "));
        }
        if let Some(asn) = &p.company.asn {
            println!("  {} {asn}", self.o_dim("asn:       "));
        }
        if let Some(t) = &p.tls {
            let mut flags = String::new();
            if t.expired {
                flags.push_str(&format!(" · {}", self.o_red("EXPIRED")));
            }
            if t.self_signed {
                flags.push_str(&format!(" · {}", self.o_yellow("self-signed")));
            }
            println!(
                "  {} {} · {}{}",
                self.o_dim("tls:       "),
                t.protocol,
                t.issuer_org.as_deref().unwrap_or("unknown issuer"),
                flags
            );
        }
        if let Some(h) = p.favicon_mmh3 {
            println!("  {} http.favicon.hash:{h}", self.o_dim("favicon:   "));
        }
        let pips = security_pips(p.security.score, self.out_color);
        let checks = [
            ("HSTS", p.security.hsts.is_some()),
            ("CSP", p.security.csp.is_some()),
            ("XFO", p.security.x_frame_options.is_some()),
            ("XCTO", p.security.x_content_type_options.is_some()),
            ("Ref", p.security.referrer_policy.is_some()),
        ]
        .iter()
        .map(|(k, ok)| {
            if *ok {
                self.o_green(&format!("{k}✓"))
            } else {
                self.o_dim(&format!("{k}×"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
        println!(
            "  {} {pips} {}/6  {checks}",
            self.o_dim("headers:   "),
            p.security.score
        );

        if !p.technologies.is_empty() {
            println!("\n  {}", self.o_bold_cyan("Technologies"));
            for t in &p.technologies {
                let label = match &t.version {
                    Some(v) => format!("{} {v}", t.name),
                    None => t.name.clone(),
                };
                let implied = if t.implied { " (implied)" } else { "" };
                println!(
                    "    {:<30} {:<24} {}",
                    self.o_bold(&label),
                    self.o_dim(&t.category),
                    self.o_dim(&format!("{}%{implied}", t.confidence))
                );
            }
        }
        if !p.api_hints.is_empty() {
            println!("\n  {}", self.o_bold_cyan("API hints"));
            for hint in p.api_hints.iter().take(10) {
                println!("    {} {hint}", self.o_cyan("→"));
            }
        }
        if let Some(e) = &p.error {
            println!("  {} {}", self.o_red("error:"), e);
        }
        if let Some(n) = &p.ai_note {
            println!("\n  {} {n}", self.o_bold_cyan("AI analysis:"));
        }
    }

    pub fn print_search(&self, hits: &[ntok_store::Hit]) {
        if !self.quiet {
            eprintln!("{} hits", hits.len());
        }
        if !self.out_color {
            for h in hits {
                let mut extra = Vec::new();
                if let Some(s) = &h.hostname {
                    extra.push(s.clone());
                }
                if let Some(s) = h.server.as_deref().or(h.banner.as_deref()) {
                    extra.push(s.chars().take(80).collect());
                }
                if let Some(t) = &h.tech {
                    extra.push(format!("tech: {t}"));
                }
                if h.tls_expired {
                    extra.push("EXPIRED CERT".into());
                }
                if h.risk > 0 {
                    extra.push(format!("risk {}", h.risk));
                }
                if let Some(f) = &h.findings {
                    let n = f.matches(" | ").count() + 1;
                    let top = ["critical", "high"].iter().find(|s| f.contains(**s));
                    extra.push(match top {
                        Some(s) => format!("findings:{n}({s})"),
                        None => format!("findings:{n}"),
                    });
                }
                if let Some(h3) = h.favicon_mmh3 {
                    let name = ntok_core::web::favicon::lookup(h3 as i32)
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default();
                    extra.push(format!("favicon {h3}{name}"));
                }
                if h.anomaly >= 70 {
                    extra.push("rare port".into());
                }
                let extra = if extra.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", extra.join(" · "))
                };
                println!(
                    "{}:{}/{} {}{}{}",
                    h.ip,
                    h.port,
                    h.protocol,
                    h.state,
                    h.service
                        .as_deref()
                        .map(|s| format!(" {s}"))
                        .unwrap_or_default(),
                    extra
                );
            }
            return;
        }

        if hits.is_empty() {
            return;
        }
        println!(
            "  {}  {}  {}  {}",
            self.o_dim(&format!("{:<24}", "TARGET")),
            self.o_dim(&format!("{:<12}", "SERVICE")),
            self.o_dim(&format!("{:<32}", "HOST / BANNER")),
            self.o_dim("SIGNALS")
        );
        for h in hits {
            let target = format!("{}:{}/{}", h.ip, h.port, h.protocol);
            let svc = h.service.as_deref().unwrap_or(&h.state);
            let detail: String = h
                .hostname
                .as_deref()
                .or(h.server.as_deref())
                .or(h.banner.as_deref())
                .unwrap_or("—")
                .chars()
                .take(30)
                .collect();
            let mut sigs = Vec::new();
            if h.risk >= 70 {
                sigs.push(self.o_red(&format!("risk:{}", h.risk)));
            } else if h.risk >= 40 {
                sigs.push(self.o_yellow(&format!("risk:{}", h.risk)));
            }
            if h.tls_expired {
                sigs.push(self.o_red("EXPIRED"));
            }
            if h.anomaly >= 70 {
                sigs.push(self.o_yellow("rare"));
            }
            if let Some(t) = &h.tech {
                sigs.push(self.o_dim(&t.chars().take(28).collect::<String>()));
            }
            println!(
                "  {:<24}  {:<12}  {:<32}  {}",
                self.o_cyan(&format!("{target:<24}")),
                self.o_green(&format!("{svc:<12}")),
                detail,
                sigs.join(" ")
            );
        }
    }

    pub fn print_diff(&self, d: &ScanDiff, a: &str, b: &str) {
        let plain = ntok_core::diff::to_text(d, a, b);
        if !self.out_color {
            print!("{plain}");
            return;
        }
        for line in plain.lines() {
            if line.starts_with('+') || line.starts_with("  +") {
                println!("{}", self.o_green(line));
            } else if line.starts_with('-') || line.starts_with("  -") {
                println!("{}", self.o_red(line));
            } else if line.contains("->") || line.contains("→") {
                println!("{}", self.o_yellow(line));
            } else if line.starts_with("===") || line.starts_with("---") {
                println!("{}", self.o_bold_cyan(line));
            } else {
                println!("{line}");
            }
        }
    }

    pub fn print_graph(&self, target: &str, edges: &[ntok_store::Edge]) {
        if !self.out_color {
            println!("{target}");
            for e in edges {
                let star = if e.indexed { " *" } else { "" };
                if e.src == target {
                    println!("  → {:<9} {:<45}{star}", e.kind, e.dst);
                } else if e.dst == target {
                    println!("  ← {:<9} {:<45}{star}", e.kind, e.src);
                } else {
                    println!("  · {:<9} {} → {}{star}", e.kind, e.src, e.dst);
                }
            }
            return;
        }
        println!("{}", self.o_bold_cyan(target));
        let last = edges.len().saturating_sub(1);
        for (i, e) in edges.iter().enumerate() {
            let branch = if i == last { "└─" } else { "├─" };
            let star = if e.indexed {
                format!(" {}", self.o_green("*"))
            } else {
                String::new()
            };
            let kind = self.o_cyan(&format!("{:<8}", e.kind));
            if e.src == target {
                println!("  {} → {kind} {}{star}", self.o_dim(branch), e.dst);
            } else if e.dst == target {
                println!("  {} ← {kind} {}{star}", self.o_dim(branch), e.src);
            } else {
                println!(
                    "  {} · {kind} {} {} {}{star}",
                    self.o_dim(branch),
                    e.src,
                    self.o_dim("→"),
                    e.dst
                );
            }
        }
    }

    fn paint(on: bool, code: &str, s: &str) -> String {
        if on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn o_bold(&self, s: &str) -> String {
        Self::paint(self.out_color, "1", s)
    }
    fn o_dim(&self, s: &str) -> String {
        Self::paint(self.out_color, "2", s)
    }
    fn o_cyan(&self, s: &str) -> String {
        Self::paint(self.out_color, "36", s)
    }
    fn o_bold_cyan(&self, s: &str) -> String {
        Self::paint(self.out_color, "1;36", s)
    }
    fn o_green(&self, s: &str) -> String {
        Self::paint(self.out_color, "1;32", s)
    }
    fn o_yellow(&self, s: &str) -> String {
        Self::paint(self.out_color, "33", s)
    }
    fn o_red(&self, s: &str) -> String {
        Self::paint(self.out_color, "1;31", s)
    }

    fn e_bold(&self, s: &str) -> String {
        Self::paint(self.err_color, "1", s)
    }
    fn e_dim(&self, s: &str) -> String {
        Self::paint(self.err_color, "2", s)
    }
    fn e_cyan(&self, s: &str) -> String {
        Self::paint(self.err_color, "36", s)
    }
    fn e_bold_cyan(&self, s: &str) -> String {
        Self::paint(self.err_color, "1;36", s)
    }
    fn e_green(&self, s: &str) -> String {
        Self::paint(self.err_color, "1;32", s)
    }
    fn e_yellow(&self, s: &str) -> String {
        Self::paint(self.err_color, "33", s)
    }
}

pub fn security_pips(score: u8, color: bool) -> String {
    let clamped = score.min(6) as usize;
    let on = "■".repeat(clamped);
    let off = "□".repeat(6 - clamped);
    if !color {
        return format!("{on}{off}");
    }
    let code = if clamped >= 4 {
        "32"
    } else if clamped >= 2 {
        "33"
    } else {
        "31"
    };
    format!("\x1b[{code}m{on}\x1b[0m\x1b[2m{off}\x1b[0m")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_pips_have_no_ansi() {
        let s = security_pips(4, false);
        assert_eq!(s, "■■■■□□");
        assert!(!s.contains('\x1b'));
    }

    #[test]
    fn colored_pips_wrap_ansi() {
        let s = security_pips(5, true);
        assert!(s.contains('\x1b'));
        assert!(s.contains("■■■■■"));
    }
}
