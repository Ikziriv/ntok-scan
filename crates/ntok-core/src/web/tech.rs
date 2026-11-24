//! Technology detection — the vendored Wappalyzer community fingerprint
//! DB (`data/web-tech.json`, ~7.7k fingerprints, GPL; see
//! `data/NOTICE-web-tech.md`) matched against headers, cookies, meta,
//! script URLs, DOM selectors, JS globals, the page URL, DNS, robots.txt,
//! TLS issuer and the page body.
//!
//! Matching is two-stage: every body/URL-side pattern contributes its
//! longest literal core to a pair of Aho-Corasick automatons, so only
//! candidate fingerprints ever evaluate their regexes — one pass over the
//! body instead of ~15k per-pattern scans. Regexes compile lazily; JS
//! look-around constructs Rust can't express degrade to no-match.
//!
//! Scoring follows the DB's `\;confidence:N` and `\;version:\1` pattern
//! options; `implies`/`excludes`/`requires` form a small inference graph
//! resolved after detection. Every hit is kept as evidence — the
//! "receipts" view of which signal named the technology.

use crate::model::{DnsRecord, Technology};
use aho_corasick::AhoCorasick;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

const TECH_DB: &str = include_str!("../../data/web-tech.json");
const CATS_DB: &str = include_str!("../../data/web-cats.json");

/// Literal cores shorter than this don't prefilter (too generic).
const MIN_LITERAL: usize = 5;

// ---------- raw DB schema (Wappalyzer format) ----------

#[derive(Debug, Deserialize)]
struct RawFp {
    #[serde(default)]
    cats: Vec<u32>,
    #[serde(default)]
    website: Option<String>,
    #[serde(default)]
    cpe: Option<String>,
    #[serde(default)]
    saas: bool,
    #[serde(default)]
    oss: bool,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    cookies: HashMap<String, String>,
    #[serde(default)]
    meta: HashMap<String, String>,
    /// DNS values are `str` or `[str]` in the DB.
    #[serde(default)]
    dns: HashMap<String, StrOrVec>,
    #[serde(default)]
    js: HashMap<String, String>,
    #[serde(default)]
    html: Vec<String>,
    #[serde(default)]
    text: Vec<String>,
    #[serde(default)]
    css: Vec<String>,
    /// Inline `<script>` bodies.
    #[serde(default)]
    scripts: Vec<String>,
    #[serde(rename = "scriptSrc", default)]
    script_src: Vec<String>,
    #[serde(default)]
    xhr: Vec<String>,
    #[serde(default)]
    url: Vec<String>,
    #[serde(default)]
    robots: Vec<String>,
    #[serde(rename = "certIssuer", default)]
    cert_issuer: Option<String>,
    /// Selector strings, or `{selector: {…}}` (options ignored — an
    /// exists-check is close enough without a JS runtime).
    #[serde(default)]
    dom: serde_json::Value,
    #[serde(default)]
    implies: Vec<String>,
    #[serde(default)]
    excludes: Vec<String>,
    #[serde(default)]
    requires: Vec<String>,
    #[serde(rename = "requiresCategory", default)]
    requires_cat: Vec<u32>,
}

#[derive(Debug, Deserialize)]
struct RawCat {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StrOrVec {
    One(String),
    Many(Vec<String>),
}

// ---------- compiled DB ----------

/// One fingerprint pattern. `src` is the regex source after `\;options`
/// are split off; empty `src` is a presence check on the keyed signal.
struct Pat {
    src: String,
    /// `\;version:` template — `\1`..`\9` group backrefs.
    version: Option<String>,
    /// `\;confidence:N`, default 100.
    confidence: u8,
    /// AC pattern ids this pattern registered — evaluated only when one
    /// hit the hay. Empty = ungated (no literal core).
    lits: Vec<u32>,
    re: OnceLock<Option<Regex>>,
}

impl Pat {
    fn parse(raw: &str) -> Pat {
        let mut version = None;
        let mut confidence = 100;
        let mut it = raw.split("\\;");
        let src = it.next().unwrap_or_default().to_string();
        for opt in it {
            if let Some(v) = opt.strip_prefix("version:") {
                version = Some(v.to_string());
            } else if let Some(c) = opt.strip_prefix("confidence:") {
                confidence = c.parse().unwrap_or(100);
            }
        }
        Pat {
            src,
            version,
            confidence,
            lits: Vec::new(),
            re: OnceLock::new(),
        }
    }

    /// `None` = no match, `Some(v)` = matched (v = extracted version).
    fn eval(&self, hay: &str) -> Option<Option<String>> {
        if self.src.is_empty() {
            return Some(None);
        }
        if hay.is_empty() {
            return None;
        }
        let re = self
            .re
            .get_or_init(|| {
                RegexBuilder::new(&self.src)
                    .case_insensitive(true)
                    .build()
                    .ok()
            })
            .as_ref()?;
        let caps = re.captures(hay)?;
        Some(self.version.as_deref().map(|t| expand(t, &caps)))
    }
}

/// Dense bitset over AC pattern ids — the per-pattern gate test is a
/// one-word load instead of a SipHash probe.
#[derive(Clone, Default)]
struct Bits(Vec<u64>);

impl Bits {
    fn with_bits(n: usize) -> Self {
        Self(vec![0; n.div_ceil(64)])
    }
    fn set(&mut self, id: u32) {
        self.0[id as usize / 64] |= 1 << (id % 64);
    }
    #[inline]
    fn test(&self, id: u32) -> bool {
        self.0
            .get(id as usize / 64)
            .is_some_and(|w| w & (1 << (id % 64)) != 0)
    }
    fn merge(&mut self, o: &Bits) {
        for (a, b) in self.0.iter_mut().zip(&o.0) {
            *a |= *b;
        }
    }
}

/// `apache-tomcat` → `Apache Tomcat` for display.
fn prettify(slug: &str) -> String {
    slug.split('-')
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `\1`..`\9` backref expansion into a version template.
fn expand(tmpl: &str, caps: &regex::Captures) -> String {
    let mut out = String::new();
    let mut it = tmpl.chars();
    while let Some(c) = it.next() {
        match c {
            '\\' => match it.next() {
                Some(d @ '1'..='9') => {
                    if let Some(g) = caps.get(d as usize - '0' as usize) {
                        out.push_str(g.as_str());
                    }
                }
                Some(o) => out.push(o),
                None => out.push('\\'),
            },
            c => out.push(c),
        }
    }
    out
}

struct Imply {
    name: String,
    version: Option<String>,
    confidence: u8,
}

/// A `js` global: presence is an identifier-boundary match (case-
/// sensitive — JS identifiers are) over inline script text; `pat`
/// extracts the value/version around it.
struct JsGlobal {
    name: String,
    pat: Pat,
    /// AC ids for the global name — skips the presence regex entirely
    /// when no js hay contains the identifier.
    lits: Vec<u32>,
    pres: OnceLock<Option<Regex>>,
}

impl JsGlobal {
    fn pres_re(&self) -> Option<&Regex> {
        self.pres
            .get_or_init(|| {
                Regex::new(&format!(
                    "(?:^|[^A-Za-z0-9_$]){}(?:[^A-Za-z0-9_$]|$)",
                    regex::escape(&self.name)
                ))
                .ok()
            })
            .as_ref()
    }
}

/// One `dom` check: a selector, optionally narrowed by element text and
/// attribute patterns (upstream `properties`/`css` conditions can't be
/// evaluated without a JS runtime — those checks are dropped at parse).
struct DomCheck {
    sel: String,
    text: Option<Pat>,
    attrs: Vec<(String, Pat)>,
    /// Literal version from `exists: "\;version:…"`.
    version: Option<String>,
    confidence: u8,
    /// AC ids — skips selector + condition eval when absent from the hay.
    lits: Vec<u32>,
}

struct Fp {
    name: String,
    cats: Vec<u32>,
    website: Option<String>,
    cpe: Option<String>,
    saas: bool,
    oss: bool,
    headers: Vec<(String, Pat)>,
    cookies: Vec<(String, Pat)>,
    meta: Vec<(String, Pat)>,
    dns: Vec<(String, Pat)>,
    js: Vec<JsGlobal>,
    html: Vec<Pat>,
    text: Vec<Pat>,
    css: Vec<Pat>,
    /// Patterns over inline `<script>` content.
    scripts: Vec<Pat>,
    script_src: Vec<Pat>,
    xhr: Vec<Pat>,
    url: Vec<Pat>,
    robots: Vec<Pat>,
    cert_issuer: Option<Pat>,
    dom: Vec<DomCheck>,
    implies: Vec<Imply>,
    excludes: Vec<String>,
    requires: Vec<String>,
    requires_cat: Vec<u32>,
    /// Some body-side pattern has no usable literal — always evaluate.
    body_always: bool,
    url_always: bool,
}

struct Db {
    fps: Vec<Fp>,
    /// AC over literal cores of body-side patterns, js globals and dom
    /// selectors → fp index candidates.
    body_ac: AhoCorasick,
    body_map: Vec<u32>,
    /// AC over literal cores of scriptSrc/xhr/url patterns.
    url_ac: AhoCorasick,
    url_map: Vec<u32>,
    by_name: HashMap<String, usize>,
    cats: HashMap<u32, String>,
}

/// Longest mandatory literal run in a pattern — the AC prefilter key.
/// Patterns with alternation/groups/char-classes bail (the run might not
/// be mandatory); escapes of punctuation rejoin the run.
fn literal_core(src: &str) -> Option<String> {
    if src.contains('|') || src.contains('(') || src.contains('[') {
        return None;
    }
    const LIT: &str =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-. /:%@~=?&#+";
    let mut best = String::new();
    let mut cur = String::new();
    let end_run = |cur: &mut String, best: &mut String| {
        if cur.len() > best.len() {
            std::mem::swap(cur, best);
        }
        cur.clear();
    };
    let mut it = src.chars();
    while let Some(c) = it.next() {
        match c {
            '\\' => match it.next() {
                Some(n) if ".-_/:?&=%@#~+*$^".contains(n) => cur.push(n),
                _ => end_run(&mut cur, &mut best),
            },
            c if LIT.contains(c) => cur.push(c),
            _ => end_run(&mut cur, &mut best),
        }
    }
    end_run(&mut cur, &mut best);
    let best = best.trim();
    (best.len() >= MIN_LITERAL).then(|| best.to_string())
}

/// Literal core of a DOM selector — longest alnum run that isn't a
/// generic HTML word (those would candidate-mark every page).
fn dom_literal(sel: &str) -> Option<String> {
    const GENERIC: &[&str] = &[
        "script",
        "style",
        "stylesheet",
        "class",
        "content",
        "xmlns",
        "href",
        "false",
        "true",
        "html",
        "body",
        "input",
    ];
    sel.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .filter(|s| s.len() >= MIN_LITERAL && !GENERIC.contains(&s.to_ascii_lowercase().as_str()))
        .max_by_key(|s| s.len())
        .map(str::to_string)
}

fn parse_imply(raw: &str) -> Imply {
    let mut it = raw.split("\\;");
    let name = it.next().unwrap_or_default().to_string();
    let mut version = None;
    let mut confidence = 100;
    for opt in it {
        if let Some(v) = opt.strip_prefix("version:") {
            version = Some(v.to_string());
        } else if let Some(c) = opt.strip_prefix("confidence:") {
            confidence = c.parse().unwrap_or(100);
        }
    }
    Imply {
        name,
        version,
        confidence,
    }
}

/// Selectors that are bare universal elements — an exists-check on them
/// fires on every page, so they're dropped when no text/attribute
/// condition narrows them.
fn tautological(sel: &str) -> bool {
    !sel.contains(['[', '.', '#', ':', '>', ' ', ',', '\''])
        && matches!(
            sel,
            "*" | "html"
                | "head"
                | "body"
                | "title"
                | "div"
                | "span"
                | "a"
                | "p"
                | "img"
                | "ul"
                | "li"
                | "script"
                | "style"
                | "meta"
                | "link"
                | "noscript"
                | "iframe"
                | "form"
                | "input"
                | "button"
        )
}

/// Normalize `dom` (array of selectors, or `{selector: conditions}`)
/// into checks. `properties`/`css` conditions need a JS runtime — the
/// check is dropped rather than silently weakened to an exists-check.
fn dom_checks(v: &serde_json::Value) -> Vec<DomCheck> {
    let mut out = Vec::new();
    match v {
        serde_json::Value::Array(a) => {
            for s in a.iter().filter_map(|x| x.as_str()) {
                if !tautological(s.trim()) {
                    out.push(DomCheck {
                        sel: s.trim().to_string(),
                        text: None,
                        attrs: Vec::new(),
                        version: None,
                        confidence: 100,
                        lits: Vec::new(),
                    });
                }
            }
        }
        serde_json::Value::Object(o) => {
            for (sel, cond) in o {
                let Some(c) = cond.as_object() else {
                    if !tautological(sel.trim()) {
                        out.push(DomCheck {
                            sel: sel.trim().to_string(),
                            text: None,
                            attrs: Vec::new(),
                            version: None,
                            confidence: 100,
                            lits: Vec::new(),
                        });
                    }
                    continue;
                };
                if c.contains_key("properties") || c.contains_key("css") {
                    continue;
                }
                let mut text = None;
                let mut attrs = Vec::new();
                let mut version = None;
                let mut confidence = 100u8;
                if let Some(x) = c.get("exists").and_then(|e| e.as_str()) {
                    let p = Pat::parse(x);
                    version = p.version.clone().filter(|v| !v.contains('\\'));
                    confidence = p.confidence;
                }
                if let Some(x) = c.get("text").and_then(|e| e.as_str()) {
                    let p = Pat::parse(x);
                    // Backref templates can't expand without captures.
                    version = version.or_else(|| p.version.clone().filter(|v| !v.contains('\\')));
                    confidence = p.confidence;
                    text = Some(p);
                }
                if let Some(x) = c.get("attributes").and_then(|e| e.as_object()) {
                    for (name, pat) in x {
                        if let Some(ps) = pat.as_str() {
                            let p = Pat::parse(ps);
                            version = version.or(p.version.clone().filter(|v| !v.contains('\\')));
                            attrs.push((name.clone(), p));
                        }
                    }
                }
                if tautological(sel.trim()) && text.is_none() && attrs.is_empty() {
                    continue;
                }
                out.push(DomCheck {
                    sel: sel.trim().to_string(),
                    text,
                    attrs,
                    version,
                    confidence,
                    lits: Vec::new(),
                });
            }
        }
        _ => {}
    }
    out
}

fn db() -> &'static Db {
    static DB_ONCE: OnceLock<Db> = OnceLock::new();
    DB_ONCE.get_or_init(|| {
        let raw: HashMap<String, RawFp> =
            serde_json::from_str(TECH_DB).expect("web-tech.json parses");
        let cats: HashMap<u32, RawCat> =
            serde_json::from_str(CATS_DB).expect("web-cats.json parses");

        let mut fps = Vec::with_capacity(raw.len());
        let mut by_name = HashMap::with_capacity(raw.len());
        let mut body_lits: Vec<String> = Vec::new();
        let mut body_map: Vec<u32> = Vec::new();
        let mut url_lits: Vec<String> = Vec::new();
        let mut url_map: Vec<u32> = Vec::new();
        let mut no_lit = 0usize;

        for (name, r) in raw {
            let mut body_always = false;
            let mut url_always = false;
            let idx = fps.len() as u32;

            let keyed = |v: HashMap<String, String>| -> Vec<(String, Pat)> {
                v.into_iter()
                    .map(|(k, p)| (k.to_ascii_lowercase(), Pat::parse(&p)))
                    .collect()
            };
            let listed = |v: Vec<String>| -> Vec<Pat> { v.iter().map(|p| Pat::parse(p)).collect() };

            let mut html = listed(r.html);
            let mut text = listed(r.text);
            let mut css = listed(r.css);
            let mut scripts = listed(r.scripts);
            let mut script_src = listed(r.script_src);
            let mut xhr = listed(r.xhr);
            let mut url = listed(r.url);
            let robots = listed(r.robots);
            let mut dom = dom_checks(&r.dom);
            let mut js: Vec<JsGlobal> =
                r.js.into_iter()
                    .map(|(g, p)| JsGlobal {
                        name: g,
                        pat: Pat::parse(&p),
                        lits: Vec::new(),
                        pres: OnceLock::new(),
                    })
                    .collect();

            // Body-side literals → body AC (one automaton serves html,
            // text, css, inline-script, js-global and dom-selector gates).
            // Each pattern records its AC ids so a candidate fp only
            // evaluates the patterns whose literal actually hit.
            for p in html
                .iter_mut()
                .chain(&mut text)
                .chain(&mut css)
                .chain(&mut scripts)
            {
                match literal_core(&p.src) {
                    Some(l) => {
                        p.lits.push(body_lits.len() as u32);
                        body_lits.push(l);
                        body_map.push(idx);
                    }
                    None => {
                        if !p.src.is_empty() {
                            body_always = true;
                            no_lit += 1;
                        }
                    }
                }
            }
            for g in &mut js {
                if g.name.len() >= MIN_LITERAL {
                    g.lits.push(body_lits.len() as u32);
                    body_lits.push(g.name.clone());
                    body_map.push(idx);
                } else {
                    body_always = true;
                }
            }
            for c in &mut dom {
                let lit = dom_literal(&c.sel)
                    .or_else(|| c.text.as_ref().and_then(|p| literal_core(&p.src)))
                    .or_else(|| {
                        c.attrs
                            .iter()
                            .map(|(n, _)| n.trim())
                            .filter(|n| n.len() >= MIN_LITERAL)
                            .max_by_key(|n| n.len())
                            .map(str::to_string)
                    })
                    .or_else(|| {
                        c.attrs
                            .iter()
                            .filter_map(|(_, p)| literal_core(&p.src))
                            .max_by_key(|l| l.len())
                    });
                match lit {
                    Some(l) => {
                        c.lits.push(body_lits.len() as u32);
                        body_lits.push(l);
                        body_map.push(idx);
                    }
                    None => body_always = true,
                }
            }

            // URL-side literals → url AC.
            for p in script_src.iter_mut().chain(&mut xhr).chain(&mut url) {
                match literal_core(&p.src) {
                    Some(l) => {
                        p.lits.push(url_lits.len() as u32);
                        url_lits.push(l);
                        url_map.push(idx);
                    }
                    None => {
                        if !p.src.is_empty() {
                            url_always = true;
                            no_lit += 1;
                        }
                    }
                }
            }

            by_name.insert(name.clone(), fps.len());
            fps.push(Fp {
                name,
                cats: r.cats,
                website: r.website,
                cpe: r.cpe,
                saas: r.saas,
                oss: r.oss,
                headers: keyed(r.headers),
                cookies: keyed(r.cookies),
                meta: keyed(r.meta),
                dns: r
                    .dns
                    .into_iter()
                    .flat_map(|(k, v)| {
                        let k = k.to_ascii_lowercase();
                        match v {
                            StrOrVec::One(p) => vec![(k, Pat::parse(&p))],
                            StrOrVec::Many(ps) => ps
                                .into_iter()
                                .map(|p| (k.clone(), Pat::parse(&p)))
                                .collect(),
                        }
                    })
                    .collect(),
                js,
                html,
                text,
                css,
                scripts,
                script_src,
                xhr,
                url,
                robots,
                cert_issuer: r.cert_issuer.as_deref().map(Pat::parse),
                dom,
                implies: r.implies.iter().map(|s| parse_imply(s)).collect(),
                excludes: r.excludes,
                requires: r.requires,
                requires_cat: r.requires_cat,
                body_always,
                url_always,
            });
        }

        tracing::debug!(
            "tech db: {} fingerprints, {} body literals, {} url literals, {} no-literal patterns",
            fps.len(),
            body_lits.len(),
            url_lits.len(),
            no_lit
        );
        Db {
            fps,
            body_ac: AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&body_lits)
                .expect("body automaton"),
            body_map,
            url_ac: AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&url_lits)
                .expect("url automaton"),
            url_map,
            by_name,
            cats: cats.into_iter().map(|(k, v)| (k, v.name)).collect(),
        }
    })
}

// ---------- matching ----------

/// Everything a fingerprint may match against.
pub struct Signals<'a> {
    /// Response headers (lowercased names).
    pub headers: &'a [(String, String)],
    /// Joined set-cookie values.
    pub cookies: String,
    /// (name, content) meta pairs.
    pub meta: &'a [(String, String)],
    /// External script src URLs.
    pub scripts: Vec<&'a str>,
    /// Inline `<script>` bodies.
    pub inline_js: &'a [String],
    /// First-party JS bundle texts (capped) — `scripts`/`js` fingerprints
    /// live here more than in the HTML.
    pub js_bundles: &'a [String],
    /// Bodies of shallow-crawled same-origin pages — tech often only
    /// appears on inner pages.
    pub crawl: &'a [String],
    /// Response body.
    pub body: &'a str,
    /// URL after redirects — for `url` patterns.
    pub final_url: &'a str,
    pub server: Option<&'a str>,
    pub powered_by: Option<&'a str>,
    pub dns: &'a [DnsRecord],
    pub tls_issuer: Option<&'a str>,
    /// Raw robots.txt body, when fetched.
    pub robots_body: Option<&'a str>,
    /// mmh3 favicon hash, when `/favicon.ico` fetched — matches a
    /// known-product table (Shodan's `http.favicon.hash` space).
    pub favicon_mmh3: Option<i32>,
}

/// One matched signal: evidence text, pattern confidence, and the
/// version the pattern extracted.
struct Hit {
    evidence: String,
    confidence: u8,
    version: Option<String>,
}

fn eval_pats(pats: &[Pat], hay: &str, gate: &Bits, label: &str, hits: &mut Vec<Hit>) {
    for p in pats {
        // A pattern with a registered literal can't match a hay the AC
        // didn't mark — skipping saves the lazy regex compile AND the
        // multi-MB scan.
        if !p.lits.is_empty() && !p.lits.iter().any(|id| gate.test(*id)) {
            continue;
        }
        if let Some(version) = p.eval(hay) {
            let version = version.filter(|v| !v.is_empty());
            hits.push(Hit {
                evidence: label.to_string(),
                confidence: p.confidence,
                version,
            });
        }
    }
}

fn eval_pats_many(pats: &[Pat], hays: &[(&str, &Bits)], label: &str, hits: &mut Vec<Hit>) {
    for (h, g) in hays {
        eval_pats(pats, h, g, label, hits);
    }
}

/// `dom` check: selector must match a node, then every `text`/
/// `attributes` condition applies to that same node (AND semantics).
/// Returns `Some(version)` on a hit — attr/text patterns carry the
/// `\;version:` captures, so eval does the extraction upstream's
/// DOM backend would do.
fn dom_eval(dom: &tl::VDom, c: &DomCheck) -> Option<Option<String>> {
    let nodes = dom.query_selector(&c.sel)?;
    let parser = dom.parser();
    for h in nodes {
        let Some(n) = h.get(parser) else {
            continue;
        };
        let mut ver = None;
        if let Some(tp) = &c.text {
            match tp.eval(n.inner_text(parser).as_ref()) {
                Some(v) => ver = ver.or(v),
                None => continue,
            }
        }
        let mut attrs_ok = true;
        for (name, p) in &c.attrs {
            match n
                .as_tag()
                .and_then(|t| t.attributes().get(name.as_str()).flatten())
                .map(|b| p.eval(b.as_utf8_str().as_ref()))
            {
                Some(Some(v)) => ver = ver.or(v),
                _ => {
                    attrs_ok = false;
                    break;
                }
            }
        }
        if attrs_ok {
            return Some(
                ver.filter(|v| v.chars().any(|ch| ch.is_ascii_alphanumeric()))
                    .or_else(|| c.version.clone()),
            );
        }
    }
    None
}

/// Match the fingerprint DB against the signals. Technologies carry a
/// confidence and the full evidence list; `implies` inference adds
/// dependent techs, `excludes`/`requires` prune the result.
pub fn detect(s: &Signals<'_>) -> Vec<Technology> {
    let db = db();

    // Inline script text — `scripts` patterns and `js` globals run here
    // (inline JS is inside `body` too, so body stays the fallback).
    let script_text = {
        let mut t = String::with_capacity(s.inline_js.iter().map(|j| j.len()).sum::<usize>() + 64);
        for j in s.inline_js {
            t.push_str(j);
            t.push('\n');
        }
        t
    };

    // --- candidate gates + per-hay literal hit sets ---
    // body_hits[i] = AC pattern ids that hit body-side hay i. Gated
    // patterns eval only on hays that contain their literal.
    let mut body_hits: Vec<Bits> = Vec::new();
    let mut body_cand = vec![false; db.fps.len()];
    let mut run_body_ac = |hay: &str| {
        let i = body_hits.len();
        let mut set = Bits::with_bits(db.body_map.len());
        for m in db.body_ac.find_overlapping_iter(hay) {
            let pid = m.pattern().as_usize();
            set.set(pid as u32);
            body_cand[db.body_map[pid] as usize] = true;
        }
        body_hits.push(set);
        i
    };
    let h_body = run_body_ac(s.body);
    let h_script = run_body_ac(&script_text);
    let h_bundles: Vec<usize> = s
        .js_bundles
        .iter()
        .map(|b| run_body_ac(b.as_str()))
        .collect();
    let h_crawl: Vec<usize> = s.crawl.iter().map(|b| run_body_ac(b.as_str())).collect();

    let url_hays: Vec<&str> = s
        .scripts
        .iter()
        .copied()
        .chain(std::iter::once(s.final_url))
        .collect();
    let mut url_cand = vec![false; db.fps.len()];
    let url_hits: Vec<Bits> = url_hays
        .iter()
        .map(|h| {
            let mut set = Bits::with_bits(db.url_map.len());
            for m in db.url_ac.find_overlapping_iter(h) {
                let pid = m.pattern().as_usize();
                set.set(pid as u32);
                url_cand[db.url_map[pid] as usize] = true;
            }
            set
        })
        .collect();

    // DOM parsed once per page — only when some candidate uses selectors.
    let dom_needed = db
        .fps
        .iter()
        .enumerate()
        .any(|(i, f)| !f.dom.is_empty() && (body_cand[i] || f.body_always));
    // (dom, its hay's hit-set index) — a failed body parse must not
    // shift crawl doms into the body gate. `parse_owned` yields a
    // Send+Sync guard so doms can be shared by the parallel eval below.
    let mut doms = Vec::new();
    if dom_needed {
        // unsafe: tl's self-referential guard — documented as unable to
        // cause UB in its current form; it owns the input string.
        if let Ok(d) = unsafe { tl::parse_owned(s.body.to_string(), tl::ParserOptions::default()) }
        {
            doms.push((h_body, d));
        }
        for (k, b) in s.crawl.iter().enumerate() {
            if let Ok(d) = unsafe { tl::parse_owned(b.clone(), tl::ParserOptions::default()) } {
                doms.push((h_crawl[k], d));
            }
        }
    }

    // (hay, its literal-hit set) pairs for the gated evals.
    let body_js: Vec<(&str, &Bits)> = vec![
        (s.body, &body_hits[h_body]),
        (script_text.as_str(), &body_hits[h_script]),
    ];
    let crawl_hays: Vec<(&str, &Bits)> = s
        .crawl
        .iter()
        .enumerate()
        .map(|(k, b)| (b.as_str(), &body_hits[h_crawl[k]]))
        .collect();
    let bundle_hays: Vec<(&str, &Bits)> = s
        .js_bundles
        .iter()
        .enumerate()
        .map(|(k, b)| (b.as_str(), &body_hits[h_bundles[k]]))
        .collect();
    let url_pairs: Vec<(&str, &Bits)> = url_hays
        .iter()
        .enumerate()
        .map(|(k, h)| (*h, &url_hits[k]))
        .collect();
    // Where `js` globals may live: inline scripts and first-party bundles.
    let js_hays: Vec<&str> = std::iter::once(script_text.as_str())
        .chain(s.js_bundles.iter().map(String::as_str))
        .collect();
    // Union of the js hays' hit sets — a global absent from all of them
    // skips its presence regex entirely.
    let mut js_gate: Bits = body_hits[h_script].clone();
    for &k in &h_bundles {
        js_gate.merge(&body_hits[k]);
    }
    let no_gate = Bits::default();

    // Per-fingerprint eval — pure CPU and read-only over the db and
    // signals, so the loop parallelizes across cores (see below).
    let eval_fp = |i: usize, fp: &Fp| -> Option<Technology> {
        let mut hits: Vec<Hit> = Vec::new();

        // Keyed signals — cheap lookups, always evaluated.
        for (k, p) in &fp.headers {
            if let Some((_, v)) = s.headers.iter().find(|(n, _)| n == k)
                && let Some(ver) = p.eval(v)
            {
                hits.push(Hit {
                    evidence: format!("header {k}"),
                    confidence: p.confidence,
                    version: ver.filter(|v| v.chars().any(|c| c.is_ascii_alphanumeric())),
                });
            }
        }
        for (k, p) in &fp.cookies {
            // Pattern applies to the "name=value" pair, wappalyzer-style.
            let found_pair = s
                .cookies
                .split(';')
                .map(str::trim)
                .find(|c| c.split('=').next().unwrap_or("").eq_ignore_ascii_case(k));
            if let Some(pair) = found_pair
                && let Some(ver) = p.eval(pair)
            {
                hits.push(Hit {
                    evidence: format!("cookie {k}"),
                    confidence: p.confidence,
                    version: ver.filter(|v| v.chars().any(|c| c.is_ascii_alphanumeric())),
                });
            }
        }
        for (k, p) in &fp.meta {
            if let Some((_, v)) = s.meta.iter().find(|(n, _)| n.eq_ignore_ascii_case(k))
                && let Some(ver) = p.eval(v)
            {
                hits.push(Hit {
                    evidence: format!("meta {k}"),
                    confidence: p.confidence,
                    version: ver.filter(|v| v.chars().any(|c| c.is_ascii_alphanumeric())),
                });
            }
        }
        for (kind, p) in &fp.dns {
            for d in s.dns.iter().filter(|d| d.kind.eq_ignore_ascii_case(kind)) {
                if let Some(ver) = p.eval(&d.value) {
                    hits.push(Hit {
                        evidence: format!("dns {kind}"),
                        confidence: p.confidence,
                        version: ver.filter(|v| v.chars().any(|c| c.is_ascii_alphanumeric())),
                    });
                }
            }
        }
        if let (Some(p), Some(issuer)) = (&fp.cert_issuer, s.tls_issuer)
            && let Some(ver) = p.eval(issuer)
        {
            hits.push(Hit {
                evidence: "tls issuer".into(),
                confidence: p.confidence,
                version: ver.filter(|v| v.chars().any(|c| c.is_ascii_alphanumeric())),
            });
        }
        if let Some(robots) = s.robots_body {
            eval_pats(&fp.robots, robots, &no_gate, "robots.txt", &mut hits);
        }

        // Body-side signals — AC-gated.
        if body_cand[i] || fp.body_always {
            let body_gate = &body_hits[h_body];
            eval_pats(&fp.html, s.body, body_gate, "html", &mut hits);
            eval_pats_many(&fp.html, &crawl_hays, "crawl html", &mut hits);
            eval_pats(&fp.text, s.body, body_gate, "text", &mut hits);
            eval_pats_many(&fp.text, &crawl_hays, "crawl text", &mut hits);
            eval_pats(&fp.css, s.body, body_gate, "css", &mut hits);
            eval_pats_many(&fp.css, &crawl_hays, "crawl css", &mut hits);
            eval_pats_many(&fp.scripts, &body_js, "script body", &mut hits);
            eval_pats_many(&fp.scripts, &bundle_hays, "script bundle", &mut hits);
            eval_pats_many(&fp.scripts, &crawl_hays, "crawl script", &mut hits);
            for g in &fp.js {
                if !g.lits.is_empty() && !g.lits.iter().any(|id| js_gate.test(*id)) {
                    continue;
                }
                // Identifier-boundary presence on script text — a prose
                // word in the body is not a window global.
                let Some(re) = g.pres_re() else { continue };
                let Some(hay) = js_hays.iter().find(|h| !h.is_empty() && re.is_match(h)) else {
                    continue;
                };
                if let Some(ver) = g.pat.eval(hay) {
                    hits.push(Hit {
                        evidence: format!("js {}", g.name),
                        confidence: g.pat.confidence,
                        version: ver.filter(|v| v.chars().any(|c| c.is_ascii_alphanumeric())),
                    });
                }
            }
            for (hi, d) in &doms {
                let dgate = &body_hits[*hi];
                for c in &fp.dom {
                    if !c.lits.is_empty() && !c.lits.iter().any(|id| dgate.test(*id)) {
                        continue;
                    }
                    if let Some(ver) = dom_eval(d.get_ref(), c) {
                        hits.push(Hit {
                            evidence: format!("dom {}", c.sel),
                            confidence: c.confidence,
                            version: ver,
                        });
                    }
                }
            }
        }

        // URL-side signals — AC-gated.
        if url_cand[i] || fp.url_always {
            eval_pats_many(&fp.script_src, &url_pairs, "script src", &mut hits);
            eval_pats_many(&fp.xhr, &url_pairs, "xhr", &mut hits);
            if let Some(g) = url_hits.last() {
                eval_pats(&fp.url, s.final_url, g, "url", &mut hits);
            }
        }

        if hits.is_empty() {
            return None;
        }
        let confidence = hits.iter().map(|h| h.confidence).max().unwrap_or(100);
        let version = hits.iter().find_map(|h| h.version.clone());
        let categories: Vec<String> = fp
            .cats
            .iter()
            .filter_map(|c| db.cats.get(c).cloned())
            .collect();
        Some(Technology {
            name: fp.name.clone(),
            category: categories.first().cloned().unwrap_or_default(),
            categories,
            version,
            evidence: hits.into_iter().map(|h| h.evidence).collect(),
            confidence,
            implied: false,
            cpe: fp.cpe.clone(),
            saas: fp.saas,
            oss: fp.oss,
            website: fp.website.clone(),
        })
    };

    // The dominant cost is lazy regex compile across candidate patterns —
    // pure CPU, so fan the fp loop out over a bounded worker set.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(8);
    let mut found: Vec<(usize, Technology)> = if workers <= 1 {
        db.fps
            .iter()
            .enumerate()
            .filter_map(|(i, fp)| eval_fp(i, fp).map(|t| (i, t)))
            .collect()
    } else {
        let next = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|_| {
                    scope.spawn(|| {
                        let mut local = Vec::new();
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            if i >= db.fps.len() {
                                break;
                            }
                            if let Some(t) = eval_fp(i, &db.fps[i]) {
                                local.push((i, t));
                            }
                        }
                        local
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().expect("detect worker panicked"))
                .collect()
        })
    };
    // Deterministic output order — same as the sequential scan.
    found.sort_unstable_by_key(|(i, _)| *i);

    // --- inference graph ---

    // implies: BFS over fingerprint references; implied techs keep a
    // fixed low confidence and name their source as evidence.
    let mut seen: HashSet<String> = found.iter().map(|(_, t)| t.name.clone()).collect();
    let mut queue: VecDeque<usize> = found.iter().map(|(i, _)| *i).collect();
    while let Some(i) = queue.pop_front() {
        for imp in &db.fps[i].implies {
            if !seen.insert(imp.name.clone()) {
                continue;
            }
            let (cats_, fp_ref) = match db.by_name.get(&imp.name) {
                Some(&j) => {
                    queue.push_back(j);
                    (
                        db.fps[j]
                            .cats
                            .iter()
                            .filter_map(|c| db.cats.get(c).cloned())
                            .collect::<Vec<_>>(),
                        Some(j),
                    )
                }
                None => (Vec::new(), None),
            };
            let t = Technology {
                name: imp.name.clone(),
                category: cats_.first().cloned().unwrap_or_default(),
                categories: cats_,
                version: imp.version.clone(),
                evidence: vec![format!("implied by {}", db.fps[i].name)],
                confidence: imp.confidence,
                implied: true,
                cpe: fp_ref.and_then(|j| db.fps[j].cpe.clone()),
                saas: fp_ref.is_some_and(|j| db.fps[j].saas),
                oss: fp_ref.is_some_and(|j| db.fps[j].oss),
                website: fp_ref.and_then(|j| db.fps[j].website.clone()),
            };
            // usize::MAX = implied entry without a fingerprint.
            found.push((fp_ref.unwrap_or(usize::MAX), t));
        }
    }

    // requires / requiresCategory: iterate to a fixpoint — dropping one
    // tech can invalidate another's requirement.
    for _ in 0..3 {
        let names: HashSet<String> = found.iter().map(|(_, t)| t.name.clone()).collect();
        let catset: HashSet<u32> = found
            .iter()
            .filter(|(i, _)| *i != usize::MAX)
            .flat_map(|(i, _)| db.fps[*i].cats.iter().copied())
            .collect();
        let before = found.len();
        found.retain(|(i, _)| {
            if *i == usize::MAX {
                return true;
            }
            let f = &db.fps[*i];
            f.requires.iter().all(|r| names.contains(r))
                && (f.requires_cat.is_empty() || f.requires_cat.iter().any(|c| catset.contains(c)))
        });
        if found.len() == before {
            break;
        }
    }

    // excludes: a matched tech vetoes the ones it names.
    let excluded: HashSet<&String> = found
        .iter()
        .filter(|(i, _)| *i != usize::MAX)
        .flat_map(|(i, _)| db.fps[*i].excludes.iter())
        .collect();
    found.retain(|(_, t)| !excluded.contains(&t.name));

    let mut out: Vec<Technology> = found.into_iter().map(|(_, t)| t).collect();

    // Favicon mmh3 → known-product table — infra the page never
    // mentions (panels, appliances, default installs).
    if let Some(h) = s.favicon_mmh3
        && let Some(name) = super::favicon::lookup(h)
    {
        let name = prettify(name);
        if !out.iter().any(|t| t.name.eq_ignore_ascii_case(&name)) {
            out.push(Technology {
                name,
                category: "application".into(),
                categories: vec!["application".into()],
                version: None,
                evidence: vec![format!("favicon mmh3 {h}")],
                confidence: 75,
                implied: false,
                cpe: None,
                saas: false,
                oss: false,
                website: None,
            });
        }
    }

    // Generic fallbacks: the raw server/powered-by values are tech info
    // even when no fingerprint named them.
    if let Some(srv) = s.server
        && !srv.is_empty()
        && !out.iter().any(|t| t.name.eq_ignore_ascii_case(srv))
    {
        out.push(Technology {
            name: srv.to_string(),
            category: "server".into(),
            categories: vec!["server".into()],
            version: None,
            evidence: vec!["header server".into()],
            confidence: 50,
            implied: false,
            cpe: None,
            saas: false,
            oss: false,
            website: None,
        });
    }
    if let Some(pb) = s.powered_by
        && !pb.is_empty()
        && !out.iter().any(|t| t.name.eq_ignore_ascii_case(pb))
    {
        out.push(Technology {
            name: pb.to_string(),
            category: "framework".into(),
            categories: vec!["framework".into()],
            version: None,
            evidence: vec!["header x-powered-by".into()],
            confidence: 50,
            implied: false,
            cpe: None,
            saas: false,
            oss: false,
            website: None,
        });
    }

    out.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.name.cmp(&b.name))
    });
    out.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig<'a>() -> Signals<'a> {
        Signals {
            headers: &[],
            cookies: String::new(),
            meta: &[],
            scripts: Vec::new(),
            inline_js: &[],
            js_bundles: &[],
            crawl: &[],
            body: "",
            final_url: "https://example.com/",
            server: None,
            powered_by: None,
            dns: &[],
            tls_issuer: None,
            robots_body: None,
            favicon_mmh3: None,
        }
    }

    #[test]
    fn db_loads_and_has_fingerprints() {
        let db = db();
        assert!(db.fps.len() > 5000, "expected thousands of fingerprints");
        assert!(db.by_name.contains_key("WordPress"));
        assert!(!db.cats.is_empty());
    }

    #[test]
    fn parses_pattern_options() {
        let p = Pat::parse("^WordPress(?: ([\\d.]+))?\\;version:\\1\\;confidence:80");
        assert!(p.src.starts_with("^WordPress"));
        assert_eq!(p.version.as_deref(), Some("\\1"));
        assert_eq!(p.confidence, 80);
    }

    #[test]
    fn literal_cores() {
        assert_eq!(literal_core("wp-content"), Some("wp-content".into()));
        // groups/alternation → run may not be mandatory → no literal
        assert_eq!(literal_core("/wp-(?:content|includes)/"), None);
        assert_eq!(literal_core("foo|bar"), None);
        // escapes rejoin: wp\.com → wp.com
        assert_eq!(literal_core("wp\\.com"), Some("wp.com".into()));
    }

    #[test]
    fn version_template_expands_backrefs() {
        let re = Regex::new("WordPress ([0-9.]+)").unwrap();
        let caps = re.captures("generator WordPress 6.4.1").unwrap();
        assert_eq!(expand("\\1", &caps), "6.4.1");
        assert_eq!(expand("v\\1-x", &caps), "v6.4.1-x");
    }

    #[test]
    fn detects_wordpress_and_implies_php() {
        let headers = vec![
            ("server".to_string(), "nginx/1.25".to_string()),
            (
                "x-pingback".to_string(),
                "https://example.com/xmlrpc.php".to_string(),
            ),
        ];
        let meta = vec![("generator".to_string(), "WordPress 6.4.1".to_string())];
        let mut s = sig();
        s.headers = &headers;
        s.meta = &meta;
        s.body = r#"<html><link rel="stylesheet" href="/wp-content/themes/x/style.css"><script src="/wp-includes/js/wp-embed.min.js"></script></html>"#;
        let out = detect(&s);
        let wp = out
            .iter()
            .find(|t| t.name == "WordPress")
            .expect("WordPress detected");
        assert_eq!(wp.version.as_deref(), Some("6.4.1"));
        assert!(wp.confidence > 0);
        assert!(!wp.evidence.is_empty());
        let php = out
            .iter()
            .find(|t| t.name == "PHP")
            .expect("PHP implied by WordPress");
        assert!(php.implied);
        // nginx detected by its server-header fingerprint.
        let ngx = out
            .iter()
            .find(|t| t.name == "Nginx")
            .expect("Nginx detected");
        assert_eq!(ngx.version.as_deref(), Some("1.25"));
    }

    #[test]
    fn empty_page_detects_nothing() {
        let s = sig();
        assert!(detect(&s).is_empty());
    }

    #[test]
    fn detects_tech_inside_js_bundle() {
        // jQuery's fingerprints are js-globals/script-content — they only
        // fire when bundle text reaches the detector.
        let bundle = "=\"3.7.1\";jQuery.fn.jquery;(function(){})()".to_string();
        let mut s = sig();
        s.js_bundles = std::slice::from_ref(&bundle);
        let out = detect(&s);
        let jq = out
            .iter()
            .find(|t| t.name == "jQuery")
            .expect("jQuery from bundle");
        assert_eq!(jq.version.as_deref(), Some("3.7.1"));
        // Same bundle text absent → nothing.
        assert!(detect(&sig()).iter().all(|t| t.name != "jQuery"));
    }
}
