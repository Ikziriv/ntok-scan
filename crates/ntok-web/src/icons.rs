//! Inline 1.5px-stroke icon set — one geometric family drawn on a 24×24
//! grid, `currentColor` so icons inherit pill/ink/obsidian tones. Kept as
//! string consts: zero icon font, zero CDN, works fully air-gapped.
//! A few consts are kept for consistency of the set even where unused.

#![allow(dead_code)]

use topcoat::view::Unescaped;

/// Wrap a trusted icon const for the view macro (same pattern as `mark()`).
pub fn ic(raw: &'static str) -> Unescaped<&'static str> {
    Unescaped::new_unchecked(raw)
}

macro_rules! icon {
    ($name:ident, $inner:expr) => {
        pub const $name: &str = concat!(
            r##"<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">"##,
            $inner,
            "</svg>"
        );
    };
}

// navigation & account
icon!(
    RADAR,
    r##"<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 18.5 5.5"/><circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none"/>"##
);
icon!(
    DATABASE,
    r##"<ellipse cx="12" cy="5.5" rx="8" ry="3"/><path d="M4 5.5v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/><path d="M4 11.5v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/>"##
);
icon!(
    SLIDERS,
    r##"<path d="M4 7h8"/><circle cx="15.5" cy="7" r="2.2"/><path d="M18.5 7H20"/><path d="M4 12h3"/><circle cx="10.5" cy="12" r="2.2"/><path d="M13.5 12H20"/><path d="M4 17h9"/><circle cx="16.5" cy="17" r="2.2"/><path d="M19.5 17H20"/>"##
);
icon!(
    USER,
    r##"<circle cx="12" cy="8" r="3.6"/><path d="M5 19.5c1.2-3.2 4-4.8 7-4.8s5.8 1.6 7 4.8"/>"##
);
icon!(
    LOGOUT,
    r##"<path d="M14 4h-7v16h7"/><path d="M10 12h11"/><path d="m17.5 8.5 3.5 3.5-3.5 3.5"/>"##
);
icon!(
    SEARCH,
    r##"<circle cx="11" cy="11" r="7"/><path d="m20 20-3.6-3.6"/>"##
);
icon!(CHEVRON, r##"<path d="m6 9.5 6 6 6-6"/>"##);
icon!(
    PALETTE,
    r##"<path d="M12 21a9 9 0 1 1 9-9c0 2.1-1.5 3.5-3.5 3.5h-2a2.5 2.5 0 0 0-1.8 4.2c.4.5.4 1.3-.7 1.3Z"/><circle cx="7.6" cy="10.4" r="1.1"/><circle cx="10.6" cy="7" r="1.1"/><circle cx="14.8" cy="7.4" r="1.1"/><circle cx="16.9" cy="10.8" r="1.1"/>"##
);

// form fields
icon!(
    TARGET,
    r##"<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="1.1" fill="currentColor" stroke="none"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22"/>"##
);
icon!(
    GRID,
    r##"<rect x="4" y="4" width="6.5" height="6.5" rx="1.4"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.4"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.4"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.4"/>"##
);
icon!(
    GLOBE,
    r##"<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.6 2.4 4 5.6 4 9s-1.4 6.6-4 9c-2.6-2.4-4-5.6-4-9s1.4-6.6 4-9Z"/>"##
);
icon!(
    CLOCK,
    r##"<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>"##
);
icon!(
    KEY,
    r##"<circle cx="8" cy="15.5" r="4"/><path d="m11 12.5 8.5-8.5"/><path d="m15.5 8 2.5 2.5M18 5.5l2 2"/>"##
);
icon!(
    SPARKLES,
    r##"<path d="M11 4.5 12.8 9l4.5 1.8-4.5 1.8L11 17l-1.8-4.5L4.7 10.8 9.2 9 11 4.5Z"/><path d="M18.5 14.5l.9 2.3 2.3.9-2.3.9-.9 2.3-.9-2.3-2.3-.9 2.3-.9.9-2.3Z"/>"##
);
icon!(
    WRENCH,
    r##"<path d="M14.5 5a4.6 4.6 0 0 0-5.9 5.9L4 15.5V20h4.5l4.6-4.6a4.6 4.6 0 0 0 5.9-5.9l-3 3-2.7-.7-.7-2.7 3-3Z"/>"##
);
icon!(
    EDIT,
    r##"<path d="m14.5 5.5 4 4L8 20H4v-4L14.5 5.5Z"/><path d="m12.5 7.5 4 4"/>"##
);
icon!(
    FILE,
    r##"<path d="M6 3h8l4 4v14H6V3Z"/><path d="M14 3v4h4"/>"##
);
icon!(
    LINK,
    r##"<path d="M10 14a4 4 0 0 0 6 .4l3-3a4 4 0 0 0-5.6-5.6l-1.7 1.7"/><path d="M14 10a4 4 0 0 0-6-.4l-3 3a4 4 0 0 0 5.6 5.6l1.7-1.7"/>"##
);

// host / infra / intel
icon!(
    SERVER,
    r##"<rect x="3.5" y="4" width="17" height="7" rx="1.6"/><rect x="3.5" y="13" width="17" height="7" rx="1.6"/><path d="M7 7.5h.01M7 16.5h.01"/><path d="M11 7.5h4M11 16.5h4"/>"##
);
icon!(
    CPU,
    r##"<rect x="6" y="6" width="12" height="12" rx="1.8"/><rect x="9.6" y="9.6" width="4.8" height="4.8" rx="1"/><path d="M9 2.5V6M15 2.5V6M9 18v3.5M15 18v3.5M2.5 9H6M2.5 15H6M18 9h3.5M18 15h3.5"/>"##
);
icon!(
    SHIELD,
    r##"<path d="M12 3 5 5.8v5.4c0 4.4 3 7.6 7 9.8 4-2.2 7-5.4 7-9.8V5.8L12 3Z"/><path d="m9 11.8 2.2 2.2 4-4.2"/>"##
);
icon!(
    LOCK,
    r##"<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/><path d="M12 14.5v2.5"/>"##
);
icon!(
    CODE,
    r##"<path d="m8.5 8-4.5 4 4.5 4"/><path d="m15.5 8 4.5 4-4.5 4"/><path d="m13.5 5-3 14"/>"##
);
icon!(
    LAYOUT,
    r##"<rect x="3.5" y="4" width="17" height="16" rx="2"/><path d="M3.5 9h17"/><path d="M9.5 9v11"/><path d="M6 6.6h.01M8 6.6h.01"/>"##
);
icon!(
    CLOUD,
    r##"<path d="M7 18a4.5 4.5 0 0 1-.9-8.9A6 6 0 0 1 17.7 8 4.8 4.8 0 0 1 17.5 17.6H7Z"/>"##
);
icon!(
    ACTIVITY,
    r##"<path d="M3 12h4l2.5-6.5 4.5 13L16.5 12H21"/>"##
);
icon!(
    FINGERPRINT,
    r##"<path d="M6.5 6.5A8.5 8.5 0 0 1 20 11.5V14c0 2.5.3 4 .9 5"/><path d="M4 10.6a8.6 8.6 0 0 0-.5 2.9c0 1.6.2 3 .6 4.4"/><path d="M8.2 9a5 5 0 0 1 8.8 2.2v.3c0 3 .3 4.9 1 6.5"/><path d="M12 9.5a5 5 0 0 0-2.5 4.2c0 2-.3 3.4-.8 4.8"/><path d="M12 12v2.3c0 2-.3 3.9-1 5.7"/>"##
);
icon!(
    BUILDING,
    r##"<path d="M4 20V5.5L12 3v17"/><path d="M12 8h8v12"/><path d="M4 20h16"/><path d="M7 8h1.5M7 11.5h1.5M7 15h1.5M15.5 12h1.5M15.5 15.5h1.5"/>"##
);
icon!(
    MAIL,
    r##"<rect x="3.5" y="5.5" width="17" height="13" rx="2"/><path d="m4.5 7 7.5 6 7.5-6"/>"##
);
icon!(
    BOX,
    r##"<path d="m12 3 8 4.2v9.6L12 21l-8-4.2V7.2L12 3Z"/><path d="m4 7.2 8 4.2 8-4.2"/><path d="M12 11.4V21"/>"##
);
icon!(
    LAYERS,
    r##"<path d="m12 4 8.5 4.5L12 13 3.5 8.5 12 4Z"/><path d="m4.5 12.5 7.5 4 7.5-4"/><path d="m4.5 16.5 7.5 4 7.5-4"/>"##
);
icon!(
    BRANCH,
    r##"<circle cx="6.5" cy="6" r="2.6"/><circle cx="6.5" cy="18" r="2.6"/><circle cx="17.5" cy="7.5" r="2.6"/><path d="M6.5 8.6v6.8"/><path d="M6.5 15c0-3.5 3.5-4.3 6.5-4.8 1.7-.3 4.5-.8 4.5-2.7"/>"##
);
icon!(
    TERMINAL,
    r##"<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3.5 3L7 15"/><path d="M12.5 15.5H17"/>"##
);
icon!(
    ALERT,
    r##"<path d="M12 4 3 19.5h18L12 4Z"/><path d="M12 9.5V14"/><path d="M12 16.8h.01"/>"##
);
icon!(
    CHECK,
    r##"<circle cx="12" cy="12" r="9"/><path d="m8.5 12.3 2.4 2.4 4.6-4.9"/>"##
);
icon!(
    EYE,
    r##"<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="3"/>"##
);
icon!(
    BOOK,
    r##"<path d="M5 4.5A1.5 1.5 0 0 1 6.5 3H19v16H6.5A1.5 1.5 0 0 0 5 20.5V4.5Z"/><path d="M5 19.5A1.5 1.5 0 0 1 6.5 18H19"/>"##
);
icon!(
    CAMERA,
    r##"<rect x="3" y="7" width="18" height="13" rx="2"/><path d="m8.5 7 1.4-2.8h4.2L15.5 7"/><circle cx="12" cy="13.2" r="3.6"/>"##
);
icon!(
    CARD,
    r##"<rect x="3" y="5.5" width="18" height="13" rx="2"/><path d="M3 9.5h18"/><path d="M6.5 14.5h4"/>"##
);
icon!(
    PEN,
    r##"<path d="M12 19.5 4.7 20l.5-7.3L15.7 2.2l6.1 6.1L12 19.5Z" transform="scale(.92) translate(1 1)"/><path d="m13.8 4.2 6.1 6.1"/>"##
);
icon!(
    PLAY,
    r##"<circle cx="12" cy="12" r="9"/><path d="M10 8.5v7l5.5-3.5L10 8.5Z"/>"##
);
icon!(
    VIDEO,
    r##"<rect x="3" y="6.5" width="13" height="11" rx="2"/><path d="m16 11 5-3v8l-5-3"/>"##
);
icon!(
    MAP_PIN,
    r##"<path d="M12 21s-6.8-6-6.8-11.3a6.8 6.8 0 0 1 13.6 0C18.8 15 12 21 12 21Z"/><circle cx="12" cy="9.5" r="2.5"/>"##
);

// actions & exports
icon!(
    STOP,
    r##"<circle cx="12" cy="12" r="9"/><rect x="8.5" y="8.5" width="7" height="7" rx="1.2" fill="currentColor" stroke="none"/>"##
);
icon!(
    REFRESH,
    r##"<path d="M20 5v5h-5"/><path d="M4 19v-5h5"/><path d="M19.2 10a7.8 7.8 0 0 0-13.4-3.6L4 8.6"/><path d="M4.8 14a7.8 7.8 0 0 0 13.4 3.6L20 15.4"/>"##
);
icon!(
    PLUS,
    r##"<circle cx="12" cy="12" r="9"/><path d="M12 8.5v7M8.5 12h7"/>"##
);
icon!(
    TRASH,
    r##"<path d="M4.5 6.5h15"/><path d="M8.5 6.5V4.5A1.5 1.5 0 0 1 10 3h4a1.5 1.5 0 0 1 1.5 1.5v2"/><path d="M6.5 6.5 7.4 20h9.2l.9-13.5"/><path d="M10 10.5v6M14 10.5v6"/>"##
);
icon!(
    COPY,
    r##"<rect x="8.5" y="8.5" width="12" height="12" rx="2"/><path d="M15.5 8.5v-3a2 2 0 0 0-2-2h-8a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3"/>"##
);
icon!(
    DOWNLOAD,
    r##"<path d="M12 4v11"/><path d="m7.5 11.5 4.5 4.5 4.5-4.5"/><path d="M4 19.5h16"/>"##
);
icon!(
    REPORT,
    r##"<path d="M6 3h8l4 4v14H6V3Z"/><path d="M14 3v4h4"/><path d="M9 12h6M9 15.5h6M9 8.5h2"/>"##
);
icon!(
    BRACES,
    r##"<path d="M8.5 4c-2 0-2.5 1.4-2.5 3v2.5c0 1.4-1 2.5-2.5 2.5 1.5 0 2.5 1.1 2.5 2.5V17c0 1.6.5 3 2.5 3"/><path d="M15.5 4c2 0 2.5 1.4 2.5 3v2.5c0 1.4 1 2.5 2.5 2.5-1.5 0-2.5 1.1-2.5 2.5V17c0 1.6-.5 3-2.5 3"/>"##
);
icon!(
    TAG,
    r##"<path d="m4 4 7-1 9 9-7 7-9-9V4Z"/><circle cx="9" cy="9" r="1.4"/>"##
);
icon!(
    UPLOAD,
    r##"<path d="M12 15V4"/><path d="m7.5 8.5 4.5-4.5 4.5 4.5"/><path d="M4 19.5h16"/>"##
);
icon!(
    ARROW,
    r##"<path d="M4.5 12h15"/><path d="m14 6.5 5.5 5.5-5.5 5.5"/>"##
);
icon!(
    FILTER,
    r##"<path d="M4 5.5h16l-6.5 7.5v5.5l-3-1.8V13L4 5.5Z"/>"##
);
icon!(
    HOME,
    r##"<path d="m4 11 8-7.5L20 11"/><path d="M6.5 9.5V20h11V9.5"/>"##
);
icon!(
    EXT,
    r##"<path d="M15 4h5v5"/><path d="m20 4-8.5 8.5"/><path d="M19 13.5V19a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5.5"/>"##
);
icon!(
    INFO,
    r##"<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 7.5h.01"/>"##
);
icon!(
    DNS,
    r##"<ellipse cx="12" cy="5.5" rx="8" ry="3"/><path d="M4 5.5v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/><path d="M4 11.5v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/><path d="m18.5 14.5-2.5 2.5 2.5 2.5"/><path d="m16 17-5 3"/>"##
);
icon!(
    SCALE,
    r##"<path d="M12 3v18"/><path d="M5 6.5h14"/><path d="M6 6.5 3.5 13h5L6 6.5Z"/><path d="M18 6.5 15.5 13h5L18 6.5Z"/><path d="M8 21h8"/>"##
);
icon!(
    ZAP,
    r##"<path d="M13 2.5 4.5 13.5H11l-1 8 8.5-11H12l1-8Z"/>"##
);
icon!(
    LIST,
    r##"<path d="M8.5 6.5H20M8.5 12H20M8.5 17.5H20"/><path d="M4 6.5h.01M4 12h.01M4 17.5h.01"/>"##
);
icon!(
    TABLE,
    r##"<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><path d="M3.5 9.5h17"/><path d="M3.5 14.5h17"/><path d="M9.5 9.5v10"/><path d="M15.5 9.5v10"/>"##
);
icon!(
    MOBILE,
    r##"<rect x="7" y="3" width="10" height="18" rx="2"/><path d="M11 17.5h2"/>"##
);
icon!(
    CHAT,
    r##"<path d="M4 5.5h16v11H9l-5 4V5.5Z"/><path d="M8 9.5h8M8 12.5h5"/>"##
);
icon!(
    ROBOT,
    r##"<rect x="5" y="9" width="14" height="10" rx="2.5"/><path d="M12 9V5.5"/><circle cx="12" cy="4" r="1.4"/><path d="M9.5 13h.01M14.5 13h.01"/><path d="M9.5 16h5"/><path d="M5 13H3v3h2M19 13h2v3h-2"/>"##
);

/// Map a Wappalyzer-style technology category to the closest icon const.
/// Keyword match on the lowercased category — unknown buckets get CPU.
pub fn tech(category: &str) -> &'static str {
    let c = category.to_lowercase();
    let has = |k: &str| c.contains(k);
    if has("cdn") || has("cloud") || has("paas") || has("hosting") || has("load balancer") {
        CLOUD
    } else if has("javascript")
        || has("framework")
        || has("programming")
        || has("web server extension")
        || has("static site")
        || has("build")
    {
        CODE
    } else if has("web server") || has("reverse prox") || has("cach") || has("server") {
        SERVER
    } else if has("cms")
        || has("page builder")
        || has("blog")
        || has("wiki")
        || has("forum")
        || has("message board")
        || has("ecommerce")
        || has("lms")
        || has("documentation")
    {
        LAYOUT
    } else if has("database") || has("dbms") {
        DATABASE
    } else if has("security")
        || has("waf")
        || has("ddos")
        || has("captcha")
        || has("consent")
        || has("cookie")
        || has("privacy")
        || has("fingerprint")
    {
        SHIELD
    } else if has("ssl")
        || has("tls")
        || has("certificate")
        || has("authentication")
        || has("identity")
        || has("login")
    {
        LOCK
    } else if has("analytics")
        || has("rum")
        || has("tag")
        || has("ab test")
        || has("personalisation")
        || has("marketing")
        || has("advertis")
        || has("retarget")
        || has("seo")
        || has("surveys")
        || has("affiliate")
        || has("referral")
    {
        ACTIVITY
    } else if has("font") || has("ui ") || has("css") || has("graphics") || has("photo") {
        PEN
    } else if has("video") || has("media") || has("audio") || has("player") {
        VIDEO
    } else if has("map") || has("geolocation") || has("location") {
        MAP_PIN
    } else if has("payment")
        || has("checkout")
        || has("buy now")
        || has("currency")
        || has("tax")
        || has("shipping")
        || has("inventory")
    {
        CARD
    } else if has("email") || has("newsletter") || has("mx") {
        MAIL
    } else if has("chat")
        || has("crm")
        || has("ticket")
        || has("comment")
        || has("review")
        || has("booking")
        || has("scheduling")
        || has("recruit")
        || has("loyalty")
    {
        CHAT
    } else if has("container")
        || has("docker")
        || has("kubernetes")
        || has("ci")
        || has("devops")
        || has("issue track")
        || has("feature management")
        || has("monitor")
    {
        BOX
    } else if has("mobile") || has("app") {
        MOBILE
    } else if has("dns") || has("network") || has("device") || has("proxy") {
        DNS
    } else if has("operating system") || has("os ") {
        CPU
    } else if has("widget")
        || has("social")
        || has("translation")
        || has("accessib")
        || has("user generated")
        || has("performance")
        || has("search engine")
        || has("editor")
    {
        LAYERS
    } else {
        CPU
    }
}

/// Icon for a DNS record kind (MX/NS/TXT/A/CNAME…).
pub fn dns(kind: &str) -> &'static str {
    match kind.to_uppercase().as_str() {
        "MX" => MAIL,
        "NS" => SERVER,
        "TXT" | "SPF" => FILE,
        "CAA" => SHIELD,
        _ => GLOBE,
    }
}

/// Icon for a web-asset kind (script/style/font/media/…).
pub fn asset(kind: &str) -> &'static str {
    match kind {
        "script" => CODE,
        "style" | "font" => PEN,
        "image" | "media" => CAMERA,
        "api" | "form" => ZAP,
        _ => FILE,
    }
}
