//! Service-identification data vendored from nmap (`nmap-services` port
//! table and the `match`/`softmatch` lines of `nmap-service-probes`).
//! Nmap Public Source License — see the license header in `data/`.
//!
//! Two lookups:
//! - [`service_name`]: port → service name, from the highest-frequency
//!   entry per port in nmap-services.
//! - [`match_banner`]: banner → service name, applying nmap's match
//!   regexes in file order, with `softmatch` as fallback — the same
//!   precedence nmap itself uses.
//!
//! The probe regexes compile lazily on first use (~12k patterns): the
//! common cases (SSH/HTTP/SMTP/…) resolve through `probe::guess_service`
//! hand rules first, so the DB only costs when a banner is genuinely
//! unusual. Patterns the `regex` crate can't express (backrefs,
//! lookaround) are skipped at load.

use aho_corasick::AhoCorasick;
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

const SERVICES: &str = include_str!("../data/nmap-services.txt");
const PROBES: &str = include_str!("../data/nmap-service-probes.txt");

/// Port → service name for `proto` ("tcp"/"udp").
pub fn service_name(port: u16, proto: &str) -> Option<&'static str> {
    // nmap's file marks unassigned ports "unknown" — that's absence, not a name.
    table()
        .get(&(port, proto))
        .copied()
        .filter(|n| *n != "unknown")
}

fn table() -> &'static HashMap<(u16, &'static str), &'static str> {
    static T: OnceLock<HashMap<(u16, &'static str), &'static str>> = OnceLock::new();
    T.get_or_init(|| {
        SERVICES
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| {
                let (name, spec) = l.split_once('\t')?;
                let (port, proto) = spec.rsplit_once('/')?;
                Some(((port.parse().ok()?, proto), name))
            })
            .collect()
    })
}

/// Banner → service name. `match` rules win over `softmatch` regardless
/// of file order, mirroring nmap's tentative-vs-confident semantics.
/// Patterns anchor on the line endings real banners carry; a banner that
/// lost its trailing newline at a read boundary is retried with one.
pub fn match_banner(banner: &str) -> Option<&'static str> {
    let db = probe_db();
    let find = |hay: &str| {
        // One AC pass over the banner → literal ids present. A pattern
        // whose mandatory literal is absent can't match — skip its DFA.
        // Ungated patterns always evaluate; order within each class is
        // file order, and `hard` fully precedes `soft` — same precedence
        // as a sequential scan.
        let mut hit: Vec<u32> = db
            .ac
            .find_overlapping_iter(hay)
            .map(|m| m.pattern().as_u32())
            .collect();
        hit.sort_unstable();
        hit.dedup();
        let eval = |table: &[(Regex, &'static str)], gate: &[Option<u32>]| {
            table
                .iter()
                .zip(gate)
                .find(|((re, _), g)| {
                    g.is_none_or(|g| hit.binary_search(&g).is_ok()) && re.is_match(hay)
                })
                .map(|((_, name), _)| *name)
        };
        eval(&db.hard, &db.hard_gate).or_else(|| eval(&db.soft, &db.soft_gate))
    };
    if let Some(hit) = find(banner) {
        return Some(hit);
    }
    if banner.ends_with('\n') {
        return None;
    }
    find(&format!("{banner}\n"))
}

/// Per-class pattern tables in file order plus one shared Aho-Corasick
/// over each gated pattern's mandatory literal. A single automaton
/// replaces the per-regex scan most banners would pay for: the working
/// set per lookup is the banner + the AC table + a handful of
/// candidate DFAs, not ~3k compiled patterns streamed through cache.
/// Same gate shape as `web::tech`.
struct ProbeDb {
    hard: Vec<(Regex, &'static str)>,
    soft: Vec<(Regex, &'static str)>,
    ac: AhoCorasick,
    /// Table index → AC pattern id; `None` = no reliable literal,
    /// evaluate unconditionally.
    hard_gate: Vec<Option<u32>>,
    soft_gate: Vec<Option<u32>>,
}

/// Cap on compiled patterns per service name: nmap's file carries
/// thousands of banner variants for common services (http alone has
/// ~4.5k); the first few in file order are the highest-priority forms
/// and bound the one-time compile cost.
const MAX_PATTERNS_PER_SERVICE: usize = 3;

fn probe_db() -> &'static ProbeDb {
    static DB: OnceLock<ProbeDb> = OnceLock::new();
    DB.get_or_init(|| {
        let mut hard = Vec::new();
        let mut soft = Vec::new();
        let mut hard_gate = Vec::new();
        let mut soft_gate = Vec::new();
        let mut lits = Vec::new();
        let mut seen: HashMap<(&'static str, bool), usize> = HashMap::new();
        for line in PROBES.lines().filter(|l| !l.starts_with('#')) {
            let is_soft = line.starts_with("softmatch ");
            let rest = line
                .strip_prefix("match ")
                .or_else(|| line.strip_prefix("softmatch "));
            let Some(rest) = rest else { continue };
            let Some((re, gate_src, name)) = parse_match_line(rest) else {
                continue;
            };
            let n = seen.entry((name, is_soft)).or_default();
            if *n >= MAX_PATTERNS_PER_SERVICE {
                continue;
            }
            *n += 1;
            let gate = gate_literal(&gate_src).map(|lit| {
                lits.push(lit);
                (lits.len() - 1) as u32
            });
            if is_soft {
                soft.push((re, name));
                soft_gate.push(gate);
            } else {
                hard.push((re, name));
                hard_gate.push(gate);
            }
        }
        ProbeDb {
            hard,
            soft,
            ac: AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&lits)
                .expect("literal automaton"),
            hard_gate,
            soft_gate,
        }
    })
}

/// Force the lazy probe DB to compile — spawn on a blocking thread at
/// scan start so the one-time regex cost overlaps port scanning instead
/// of blocking the first banner that needs it.
pub fn warm() {
    let _ = probe_db();
}

/// `m<delim><pattern><delim><flags>` following the service name.
/// Returns (compiled regex, flag-free pattern text for the gate, name).
fn parse_match_line(rest: &'static str) -> Option<(Regex, String, &'static str)> {
    let (name, spec) = rest.split_once(' ')?;
    let spec = spec.strip_prefix('m')?;
    let delim = spec.as_bytes().first().copied()?;
    // Closing delimiter = first unescaped occurrence after the opening one.
    let bytes = spec.as_bytes();
    let mut end = 1;
    loop {
        end = spec[end..].find(delim as char).map(|i| end + i)?;
        let backslashes = bytes[..end]
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count();
        if backslashes % 2 == 0 {
            break;
        }
        end += 1;
    }
    let pat = &spec[1..end];
    // regex crate has no backrefs/lookaround — skip what we can't compile.
    if pat.contains("\\1")
        || pat.contains("\\2")
        || pat.contains("\\3")
        || pat.contains("\\4")
        || pat.contains("\\5")
        || pat.contains("\\6")
        || pat.contains("\\7")
        || pat.contains("\\8")
        || pat.contains("\\9")
        || pat.contains("(?=")
        || pat.contains("(?!")
        || pat.contains("(?<")
        || pat.contains("(?>")
    {
        return None;
    }
    // nmap's \0 shorthand for NUL → regex crate's \x00.
    let pat = pat.replace("\\0", "\\x00");
    // Flags end at whitespace — anything after is the p/d/o/cpe description.
    // Fold them inline so the regex and the gate read the same syntax.
    let flags = spec[end + 1..].split_whitespace().next().unwrap_or("");
    let i = flags.contains('i');
    let s = flags.contains('s');
    let src = if i || s {
        format!(
            "(?{}{}:{pat})",
            if i { "i" } else { "" },
            if s { "s" } else { "" }
        )
    } else {
        pat.clone()
    };
    let re = Regex::new(&src).ok()?;
    Some((re, pat, name))
}

/// Longest byte run every match of `pat` must contain — the AC gate
/// key. Conservative: top-level `|` bails entirely; `[...]` and
/// `(...)` spans are skipped (runs on either side stay mandatory);
/// `?`/`*`/`{` drop the previous char (it became optional); escapes of
/// punctuation rejoin the run. Anything unprovable returns None → the
/// regex always evaluates.
fn gate_literal(pat: &str) -> Option<String> {
    const LIT_MIN: usize = 4;
    fn flush(cur: &mut Vec<u8>, best: &mut Vec<u8>) {
        if cur.len() > best.len() {
            std::mem::swap(cur, best);
        }
        cur.clear();
    }
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut best: Vec<u8> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut it = pat.bytes().peekable();
    while let Some(b) = it.next() {
        match b {
            b'\\' => match it.next() {
                Some(b'x') => match (it.next().and_then(hex), it.next().and_then(hex)) {
                    (Some(h), Some(l)) => cur.push(h << 4 | l),
                    _ => flush(&mut cur, &mut best),
                },
                Some(b'n') => cur.push(b'\n'),
                Some(b'r') => cur.push(b'\r'),
                Some(b't') => cur.push(b'\t'),
                // Escaped punctuation is a literal char; class/boundary
                // escapes (\d \s \w \b \A …) end the run.
                Some(c) if c.is_ascii_punctuation() => cur.push(c),
                _ => flush(&mut cur, &mut best),
            },
            b'[' => {
                // Char class: nothing inside is a usable literal. Skip
                // [^ then literal-] then to the unescaped ].
                flush(&mut cur, &mut best);
                if it.peek() == Some(&b'^') {
                    it.next();
                }
                if it.peek() == Some(&b']') {
                    it.next();
                }
                while let Some(c) = it.next() {
                    match c {
                        b'\\' => {
                            it.next();
                        }
                        b']' => break,
                        _ => {}
                    }
                }
            }
            b'(' => {
                // Group: contents unprovable (alternation, nesting);
                // skip the balanced span — runs on either side stay
                // mandatory regardless of the group's quantifier.
                flush(&mut cur, &mut best);
                let mut depth = 1u32;
                while let Some(c) = it.next() {
                    match c {
                        b'\\' => {
                            it.next();
                        }
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                if depth != 0 {
                    return None;
                }
            }
            b'|' => return None, // top-level alternation → unprovable
            b'*' | b'?' | b'{' => {
                cur.pop(); // previous char became optional/repeated
                flush(&mut cur, &mut best);
            }
            // `+` keeps the previous char mandatory; wildcards and
            // anchors just end the run.
            b'.' | b'^' | b'$' | b'+' | b')' => flush(&mut cur, &mut best),
            _ => cur.push(b),
        }
    }
    flush(&mut cur, &mut best);
    let best = String::from_utf8_lossy(&best);
    let best = best.trim();
    (best.len() >= LIT_MIN).then(|| best.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_table() {
        assert_eq!(service_name(80, "tcp"), Some("http"));
        assert_eq!(service_name(443, "tcp"), Some("https"));
        assert_eq!(service_name(22, "tcp"), Some("ssh"));
        assert_eq!(service_name(53, "udp"), Some("domain"));
        assert_eq!(service_name(65000, "tcp"), None);
    }

    #[test]
    fn gate_literals() {
        // Mandatory runs survive; wildcard/quantifier/optional chars don't.
        assert_eq!(gate_literal("^SSH-2\\.0-"), Some("SSH-2.0-".into()));
        assert_eq!(gate_literal("^220.*SMTP"), Some("SMTP".into()));
        assert_eq!(gate_literal("colou?r banner"), Some("r banner".into()));
        assert_eq!(gate_literal("^ab*cdef"), Some("cdef".into()));
        assert_eq!(gate_literal("foo|bar"), None); // top-level alternation → unprovable
        assert_eq!(gate_literal("^(a|b)cdef"), Some("cdef".into())); // group skipped
        assert_eq!(gate_literal("^HTTP/1\\.[01]"), Some("HTTP/1.".into())); // class skipped
        assert_eq!(gate_literal("a[0-9]bcd"), None); // runs too short either side
        assert_eq!(gate_literal("\\d+\\s"), None); // no literal at all
    }

    #[test]
    fn banner_matches() {
        assert_eq!(match_banner("SSH-2.0-OpenSSH_9.6"), Some("ssh"));
        assert_eq!(match_banner("+PONG\r\n"), Some("redis"));
        assert_eq!(match_banner("RFB 003.008"), Some("vnc"));
        assert!(match_banner("random garbage text").is_none());
    }
}
