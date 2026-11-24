//! In-app documentation pages — User Guide, Privacy Policy, Terms of
//! Service, Acceptable Use Policy. The markdown in `docs/` is the
//! single source of truth: `include_str!` keeps the served text
//! identical to the repo copies, and a small renderer covers exactly
//! the subset those files use (h1–h3, paragraphs, "- " bullets,
//! **bold**, `code`, [links]).

use topcoat::{
    Result,
    context::Cx,
    router::{href, page},
    view::{Unescaped, View, view},
};

const GUIDE: &str = include_str!("../../../docs/user-guide.md");
const PRIVACY: &str = include_str!("../../../docs/legal/privacy-policy.md");
const TERMS: &str = include_str!("../../../docs/legal/terms-of-service.md");
const ACCEPTABLE_USE: &str = include_str!("../../../docs/legal/acceptable-use-policy.md");

#[page("/guide")]
pub async fn guide_page(cx: &Cx) -> Result<impl View> {
    Ok(doc(cx, "guide", GUIDE))
}

#[page("/privacy")]
pub async fn privacy_page(cx: &Cx) -> Result<impl View> {
    Ok(doc(cx, "privacy", PRIVACY))
}

#[page("/terms")]
pub async fn terms_page(cx: &Cx) -> Result<impl View> {
    Ok(doc(cx, "terms", TERMS))
}

#[page("/acceptable-use")]
pub async fn acceptable_use_page(cx: &Cx) -> Result<impl View> {
    Ok(doc(cx, "aup", ACCEPTABLE_USE))
}

fn doc(cx: &Cx, active: &str, md: &str) -> impl View {
    let (body, toc) = render(md);
    let cur = move |id: &str| if id == active { "page" } else { "false" };
    let mut rail = String::new();
    if !toc.is_empty() {
        rail.push_str("<aside class=\"doc-rail\"><span class=\"doc-rail-h\">On this page</span><nav class=\"doc-toc\" aria-label=\"On this page\">");
        for t in &toc {
            rail.push_str(&format!(
                "<a class=\"h{}\" href=\"#{}\">{}</a>",
                t.level,
                t.id,
                escape(&t.label)
            ));
        }
        rail.push_str("</nav></aside>");
    }
    view! {
        <article class="legal">
            <nav class="legal-nav" aria-label="Documentation">
                <a href=(href!(guide_page)) aria-current=(cur("guide"))>"User Guide"</a>
                <a href=(href!(privacy_page)) aria-current=(cur("privacy"))>"Privacy Policy"</a>
                <a href=(href!(terms_page)) aria-current=(cur("terms"))>"Terms of Service"</a>
                <a href=(href!(acceptable_use_page)) aria-current=(cur("aup"))>"Acceptable Use"</a>
            </nav>
            <div class="doc-layout">
                <div class="doc-prose">(Unescaped::new_unchecked(body))</div>
                (Unescaped::new_unchecked(rail))
            </div>
        </article>
    }
}

struct Toc {
    level: u8,
    id: String,
    label: String,
}

fn render(md: &str) -> (String, Vec<Toc>) {
    let mut html = String::with_capacity(md.len() * 2);
    let mut toc = Vec::new();
    let mut seen_ids = std::collections::HashMap::<String, u32>::new();
    let mut in_list = false;
    for line in md.lines() {
        let t = line.trim();
        if t.is_empty() {
            if in_list {
                html.push_str("</ul>");
                in_list = false;
            }
            continue;
        }
        let is_item = t.starts_with("- ");
        if in_list && !is_item {
            html.push_str("</ul>");
            in_list = false;
        }
        if let Some(item) = t.strip_prefix("- ") {
            if !in_list {
                html.push_str("<ul>");
                in_list = true;
            }
            html.push_str("<li>");
            html.push_str(&inline(item));
            html.push_str("</li>");
        } else if let Some((level, rest)) = t
            .strip_prefix("### ")
            .map(|r| (3u8, r))
            .or_else(|| t.strip_prefix("## ").map(|r| (2, r)))
        {
            let base = slugify(rest);
            let n = seen_ids.entry(base.clone()).or_insert(0);
            *n += 1;
            let id = if *n == 1 { base } else { format!("{base}-{n}") };
            html.push_str(&format!(
                "<h{level} id=\"{id}\">{}<a class=\"h-anchor\" href=\"#{id}\" aria-hidden=\"true\" tabindex=\"-1\">#</a></h{level}>",
                inline(rest)
            ));
            toc.push(Toc {
                level,
                id,
                label: rest.to_string(),
            });
        } else if let Some(rest) = t.strip_prefix("# ") {
            html.push_str(&format!("<h1>{}</h1>", inline(rest)));
        } else {
            html.push_str("<p>");
            html.push_str(&inline(t));
            html.push_str("</p>");
        }
    }
    if in_list {
        html.push_str("</ul>");
    }
    (html, toc)
}

/// ASCII slug for heading anchors — "2. Data we store" → "2-data-we-store".
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "section".to_string()
    } else {
        out
    }
}

/// Escape HTML, then apply `code`, **bold**, and [text](url).
fn inline(raw: &str) -> String {
    let escaped = escape(raw);
    let mut out = String::with_capacity(escaped.len() + 16);
    for (i, seg) in escaped.split('`').enumerate() {
        if i % 2 == 1 {
            out.push_str("<code>");
            out.push_str(seg);
            out.push_str("</code>");
            continue;
        }
        for (j, b) in seg.split("**").enumerate() {
            if j % 2 == 1 {
                out.push_str("<strong>");
                out.push_str(&links(b));
                out.push_str("</strong>");
            } else {
                out.push_str(&links(b));
            }
        }
    }
    out
}

fn links(seg: &str) -> String {
    let mut out = String::with_capacity(seg.len());
    let mut rest = seg;
    while let Some(open) = rest.find('[') {
        let Some(mid) = rest[open..].find("](") else {
            break;
        };
        let Some(close) = rest[open + mid + 2..].find(')') else {
            break;
        };
        out.push_str(&rest[..open]);
        out.push_str("<a href=\"");
        out.push_str(&rest[open + mid + 2..open + mid + 2 + close]);
        out.push_str("\">");
        out.push_str(&rest[open + 1..open + mid]);
        out.push_str("</a>");
        rest = &rest[open + mid + 2 + close + 1..];
    }
    out.push_str(rest);
    out
}

fn escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_covers_doc_subset() {
        let (html, toc) = render("# T\n\npara **b** [x](/y) `z`\n\n- a\n- b\n\n## H\n\nafter");
        assert!(html.contains("<h1>T</h1>"));
        assert!(html.contains("<strong>b</strong>"));
        assert!(html.contains("<a href=\"/y\">x</a>"));
        assert!(html.contains("<code>z</code>"));
        assert!(html.contains("<ul><li>a</li><li>b</li></ul>"));
        assert!(html.contains("<h2 id=\"h\">H<a class=\"h-anchor\""));
        assert!(html.contains("<p>after</p>"));
        assert_eq!(toc.len(), 1);
        assert_eq!(toc[0].id, "h");
        assert_eq!(toc[0].label, "H");
    }

    #[test]
    fn heading_ids_slugify_and_dedupe() {
        let (html, toc) = render("## 2. Data we store\n\nx\n\n## Data we store\n");
        assert!(html.contains("id=\"2-data-we-store\""));
        assert!(html.contains("id=\"data-we-store\""));
        assert_eq!(toc.len(), 2);
        let (dup, _) = render("## Dup\n\n## Dup\n");
        assert!(dup.contains("id=\"dup\""));
        assert!(dup.contains("id=\"dup-2\""));
    }

    #[test]
    fn escapes_markup() {
        assert_eq!(inline("<b> & \"x\""), "&lt;b&gt; &amp; &quot;x&quot;");
    }

    #[test]
    fn shipped_docs_render() {
        for md in [GUIDE, PRIVACY, TERMS, ACCEPTABLE_USE] {
            let (html, toc) = render(md);
            assert!(html.contains("<h1>"), "doc missing title");
            assert!(html.contains("</ul>"), "doc missing list");
            assert!(!toc.is_empty(), "doc missing TOC headings");
        }
    }
}
