//! ntok web UI: a topcoat app that spawns engine scans, streams results
//! into a live console page via an htmx-polled fragment, and archives JSON
//! reports under `reports/`.
//!
//! shortcut: live updates use `hx-trigger="every 750ms"` polling rather than
//! topcoat's `sse` feature — one route, zero client JS. If scans get busy
//! enough that polling cost matters, move the fragment onto `content::sse`.
//! shortcut: `last_error` is process-global rather than per-session — fine for
//! a localhost single-user tool; revisit if sessions ever matter.

use ntok_core::event::ScanEvent;
use ntok_core::model::{PortState, Protocol};
use ntok_core::target::parse_target;
use ntok_core::{
    AiSettings, ReportFormat, ScanConfig, ScanReport, ScanTechnique, Timing, ports, report,
    run_scan,
};
mod charts;
mod d1;
mod docs;
mod icons;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use topcoat::{
    Result,
    context::{Cx, context},
    cookie::{Cookie, CookieLayer, Cookies, SameSite, cookies, time as cookie_time},
    router::{
        Body, LayerFn, LayerFuture, Method, Next, Router, Slot,
        content::{Form, Json},
        error::{RouterErrorExt, SeeOther, not_found, see_other, unauthorized},
        href, layout, page, parse_query_params, path_param,
        request::{headers, method, remote_addr, uri},
        response::Response,
        route,
    },
    view::{Unescaped, View, ViewExt, ViewHandle, component, view},
};

/// Cap on remembered port cells — beyond this only open results are kept,
/// so a huge scan can't balloon memory. The grid renders at most ~4k chips
/// anyway; past that it degrades to a proportion bar.
const MAX_CELLS: usize = 200_000;
const MAX_LOG: usize = 150;
const GRID_CHIP_LIMIT: usize = 4096;
/// Per-host cap on rows in the host-detail table — exports carry the rest.
const DETAIL_ROWS: usize = 1024;

path_param!(scan_id: u64 else not_found);
path_param!(other_id: u64 else not_found);
path_param!(font_name: String else not_found);

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let reports_dir = PathBuf::from("reports");
    std::fs::create_dir_all(&reports_dir).ok();
    let surface = match std::env::var("NTOK_SURFACE").as_deref() {
        Ok("desktop") => "desktop",
        _ => "web",
    };
    let app = App {
        scans: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        reports_dir,
        last_error: Mutex::new(None),
        ai: Mutex::new(load_ai_settings()),
        settings_msg: Mutex::new(None),
        last_token: Mutex::new(None),
        agent_log: Mutex::new(VecDeque::new()),
        surface,
        auth: Auth::from_env(),
        auth_db: Mutex::new(None),
        login_fails: Mutex::new(HashMap::new()),
        pending_totp: Mutex::new(HashMap::new()),
        d1: d1::D1Sync::from_env().map(Arc::new),
    };
    app.restore();
    app.init_auth();
    let router = Router::builder()
        .with(app)
        .layout(shell)
        .page(index)
        .page(scan_page)
        .page(compare_page)
        .page(settings_page)
        .page(search_page)
        .page(agent_page)
        .page(login_page)
        .page(register_page)
        .page(docs::guide_page)
        .page(docs::privacy_page)
        .page(docs::terms_page)
        .page(docs::acceptable_use_page)
        .route(start_scan)
        .route(save_settings)
        .route(agent_ask)
        .route(import_scan)
        .route(ports_fragment)
        .route(scan_list_fragment)
        .route(stop_scan)
        .route(rescan_scan)
        .route(delete_scan)
        .route(report_route)
        .route(log_route)
        .route(font_route)
        .route(login_submit)
        .route(register_submit)
        .route(logout)
        .route(api_login)
        .route(api_me)
        .route(api_host_intel)
        .route(api_scans)
        .route(api_scan_detail)
        .route(api_start_scan)
        .route(create_token)
        .route(revoke_token)
        .route(account_password)
        .route(account_profile)
        .route(account_sessions)
        .route(account_totp)
        // same-path layers run newest-first — CookieLayer stays outermost so
        // auth_gate can read the jar; security_headers stamps response headers.
        .layer(LayerFn::new(Some("/"), security_headers))
        .layer(LayerFn::new(Some("/"), auth_gate))
        .layer(CookieLayer::new())
        .build();
    if std::env::args().any(|a| a == "--open") {
        tokio::spawn(open_when_ready());
    }
    topcoat::start(router).await
}

/// `ntok-web --open` — poll the listener, then open the OS browser.
async fn open_when_ready() {
    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);
    let connect_at = host
        .parse::<IpAddr>()
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    for _ in 0..50 {
        if tokio::net::TcpStream::connect((connect_at, port))
            .await
            .is_ok()
        {
            open_browser(&format!("http://{host}:{port}"));
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn open_browser(url: &str) {
    let r = if cfg!(windows) {
        std::process::Command::new("cmd")
            .args(["/c", "start", "", url])
            .spawn()
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).spawn()
    } else {
        std::process::Command::new("xdg-open").arg(url).spawn()
    };
    if let Err(e) = r {
        eprintln!("could not open a browser ({e}) — visit {url} yourself");
    }
}

fn app(cx: &Cx) -> &App {
    context::<App>(cx)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The brand mark as inline SVG — trusted constant markup.
fn mark() -> Unescaped<&'static str> {
    Unescaped::new_unchecked(ntok_core::brand::MARK_SVG)
}

// ---------- shared state ----------

struct App {
    scans: Mutex<HashMap<u64, Arc<ScanEntry>>>,
    next_id: AtomicU64,
    reports_dir: PathBuf,
    last_error: Mutex<Option<String>>,
    ai: Mutex<AiSettings>,
    /// One-shot flash for the settings page: (ok, text).
    settings_msg: Mutex<Option<(bool, String)>>,
    /// One-shot newly minted API token: (name, raw_token) for copyable display.
    last_token: Mutex<Option<(String, String)>>,
    /// Agent chat transcript — last 20 turns, process-global like
    /// `last_error` (localhost single-user tool).
    agent_log: Mutex<VecDeque<AgentTurn>>,
    /// `"web"` or `"desktop"` — tunes layout density and labels.
    surface: &'static str,
    auth: Option<Auth>,
    /// `reports/ntok.db` — users, sessions, API tokens. `None` only when
    /// auth is off or the DB failed to open (gate then fails closed).
    auth_db: Mutex<Option<ntok_store::Store>>,
    /// Failed-login counter per client IP — brute-force throttle on the
    /// open endpoints. In-memory: restart resets, which is fine.
    login_fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    /// TOTP secrets shown to the user but not yet confirmed by a valid
    /// code — keyed by user id, cleared on enable/disable.
    pending_totp: Mutex<HashMap<i64, String>>,
    /// Optional Cloudflare D1 mirror — `None` unless NTOK_D1_* env vars set.
    d1: Option<Arc<d1::D1Sync>>,
}

// ---------- auth ----------

const AUTH_COOKIE: &str = "ntok_auth";
const SESSION_TTL: u64 = 30 * 24 * 3600;

/// Per-user auth: accounts live in `reports/ntok.db`, the browser gets a
/// session cookie, API clients (`/api/*`, extension, desktop, CI) send
/// `Authorization: Bearer ntok_…`. On by default — `NTOK_AUTH=off` restores
/// the old localhost no-login behavior. `NTOK_WEB_COOKIE_SECURE=0` drops
/// `Secure` on the cookie for plain-HTTP deployments.
struct Auth {
    secure: bool,
}

impl Auth {
    fn from_env() -> Option<Auth> {
        if matches!(
            std::env::var("NTOK_AUTH").as_deref(),
            Ok("off") | Ok("0") | Ok("false")
        ) {
            eprintln!("ntok-web: NTOK_AUTH=off — no login; anyone who reaches the port is in");
            return None;
        }
        Some(Auth {
            secure: !matches!(
                std::env::var("NTOK_WEB_COOKIE_SECURE").as_deref(),
                Ok("0") | Ok("false")
            ),
        })
    }
}

impl App {
    /// Open the auth DB (same `ntok.db` as the search index) and seed an
    /// `admin` user from legacy `NTOK_WEB_PASSWORD` when there are no
    /// accounts yet — keeps old deployments working after upgrade.
    fn init_auth(&self) {
        if self.auth.is_none() {
            return;
        }
        match ntok_store::Store::open_default() {
            Ok(s) => {
                if s.user_count().unwrap_or(1) == 0
                    && let Ok(pw) = std::env::var("NTOK_WEB_PASSWORD")
                    && !pw.is_empty()
                {
                    let email = std::env::var("NTOK_WEB_EMAIL").unwrap_or_default();
                    match s.create_user("admin", &email, "", &pw) {
                        Ok(_) => eprintln!("ntok-web: seeded user 'admin' from NTOK_WEB_PASSWORD"),
                        Err(e) => {
                            eprintln!(
                                "ntok-web: NTOK_WEB_PASSWORD ignored ({e}) — register at /register"
                            )
                        }
                    }
                }
                *lock(&self.auth_db) = Some(s);
                eprintln!("ntok-web: auth on — register at /register; API tokens in settings");
            }
            Err(e) => eprintln!("ntok-web: auth DB unavailable ({e}) — logins will fail"),
        }
    }
}

/// Who's asking: `Authorization: Bearer ntok_…` first (extension, desktop,
/// CI), then the session cookie (browsers). `None` = anonymous.
fn current_user(cx: &Cx) -> Option<ntok_store::User> {
    let db = lock(&app(cx).auth_db);
    let db = db.as_ref()?;
    if let Some(t) = headers(cx)
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        && let Ok(Some(u)) = db.user_for_api_token(t)
    {
        return Some(u);
    }
    cookies(cx)
        .get(AUTH_COOKIE)
        .and_then(|c| db.user_for_session(c.value()).ok().flatten())
}

/// `/register` is open while `NTOK_REGISTRATION` isn't off, and always
/// while zero accounts exist (first-run bootstrap can never lock out).
fn registration_open(cx: &Cx) -> bool {
    !matches!(
        std::env::var("NTOK_REGISTRATION").as_deref(),
        Ok("0") | Ok("false") | Ok("off")
    ) || lock(&app(cx).auth_db)
        .as_ref()
        .and_then(|db| db.user_count().ok())
        .is_none_or(|n| n == 0)
}

/// Lockout after this many failed logins from one IP.
const LOGIN_MAX_FAILS: u32 = 5;
const LOGIN_LOCKOUT: Duration = Duration::from_secs(60);

/// Client IP — `X-Forwarded-For` first (Fly/Railway/Caddy set it), else
/// the direct peer. `None` skips throttling (unroutable anyway).
fn client_ip(cx: &Cx) -> Option<IpAddr> {
    headers(cx)
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| remote_addr(cx).map(|a| a.ip()))
}

/// `true` while this IP sits in lockout.
fn login_locked(cx: &Cx) -> bool {
    let Some(ip) = client_ip(cx) else {
        return false;
    };
    lock(&app(cx).login_fails)
        .get(&ip)
        .is_some_and(|(n, t)| *n >= LOGIN_MAX_FAILS && t.elapsed() < LOGIN_LOCKOUT)
}

fn login_failed(cx: &Cx) {
    let Some(ip) = client_ip(cx) else {
        return;
    };
    let mut m = lock(&app(cx).login_fails);
    // Bound map size against spoofed X-Forwarded-For floods.
    if m.len() >= 1024 {
        m.retain(|_, (_, t)| t.elapsed() < LOGIN_LOCKOUT);
        if m.len() >= 4096 {
            m.clear();
        }
    }
    let e = m.entry(ip).or_insert((0, Instant::now()));
    if e.1.elapsed() >= LOGIN_LOCKOUT {
        *e = (0, Instant::now());
    }
    e.0 += 1;
}

fn login_succeeded(cx: &Cx) {
    if let Some(ip) = client_ip(cx) {
        lock(&app(cx).login_fails).remove(&ip);
    }
}

/// Cross-site mutation check: browsers always send `Origin` on
/// cross-origin POSTs; if it disagrees with `Host`, the request didn't
/// come from this UI. Bearer callers skip it — a token isn't ambient.
fn csrf_blocked(cx: &Cx) -> bool {
    if headers(cx).get("authorization").is_some() {
        return false;
    }
    let (Some(o), Some(h)) = (
        headers(cx).get("origin").and_then(|v| v.to_str().ok()),
        headers(cx).get("host").and_then(|v| v.to_str().ok()),
    ) else {
        return false;
    };
    let origin_host = o
        .strip_prefix("http://")
        .or_else(|| o.strip_prefix("https://"))
        .unwrap_or(o);
    origin_host != h
}

fn set_session_cookie(cx: &Cx, token: String) {
    cookies(cx).add(
        Cookie::build((AUTH_COOKIE, token))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .secure(app(cx).auth.as_ref().is_some_and(|a| a.secure))
            .max_age(cookie_time::Duration::days(30))
            .build(),
    );
}

/// Baseline browser security headers (nosniff, referrer policy, clickjacking guard).
fn security_headers<'a>(cx: &'a Cx, body: Body, next: Next<'a>) -> LayerFuture<'a> {
    Box::pin(async move {
        let mut resp = next.run(cx, body).await?;
        let h = resp.headers_mut();
        h.insert(
            "x-content-type-options",
            "nosniff".parse().expect("valid header value"),
        );
        h.insert(
            "referrer-policy",
            "strict-origin-when-cross-origin"
                .parse()
                .expect("valid header value"),
        );
        h.insert(
            "x-frame-options",
            "SAMEORIGIN".parse().expect("valid header value"),
        );
        h.insert(
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()"
                .parse()
                .expect("valid header value"),
        );
        h.insert(
            "cross-origin-opener-policy",
            "same-origin".parse().expect("valid header value"),
        );
        Ok(resp)
    })
}

/// Gate: `/login`, `/register` and `/api/auth/login` stay open; `/api/*`
/// accepts Bearer or session; pages want a session.
fn auth_gate<'a>(cx: &'a Cx, body: Body, next: Next<'a>) -> LayerFuture<'a> {
    Box::pin(async move {
        if app(cx).auth.is_none() {
            return next.run(cx, body).await;
        }
        let path = uri(cx).path().to_string();
        let open = matches!(path.as_str(), "/login" | "/register" | "/api/auth/login")
            || path.starts_with("/fonts/");
        if !open && *method(cx) != Method::GET && csrf_blocked(cx) {
            return Err(unauthorized().into());
        }
        if open || current_user(cx).is_some() {
            return next.run(cx, body).await;
        }
        if path.starts_with("/api/") || *method(cx) != Method::GET {
            Err(unauthorized().into())
        } else {
            Err(see_other("/login").into())
        }
    })
}

// ---------- AI settings persistence ----------

fn config_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|d| {
            let new = d.join("ntok");
            // one-time migration of the pre-rename config dir
            let old = d.join("ntok-scan");
            if old.is_dir() && !new.exists() {
                let _ = std::fs::rename(&old, &new);
            }
            new.join("config.json")
        })
}

fn load_ai_settings() -> AiSettings {
    config_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(AiSettings::from_env)
}

fn save_ai_settings(s: &AiSettings) -> std::io::Result<()> {
    let Some(path) = config_path() else {
        return Ok(());
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_string_pretty(s).map_err(std::io::Error::other)?;
    std::fs::write(&path, body)?;
    // Holds an API key — owner-only where the OS gives us a knob. On Windows
    // the file already sits under the user's private profile dir.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

struct ScanEntry {
    args: String,
    /// The form that launched the scan — enables one-click rescan.
    /// `None` for restored or imported entries (no form to replay).
    form: Option<ScanForm>,
    meta: Mutex<Meta>,
    cells: Mutex<HashMap<(IpAddr, u16, Protocol), PortCell>>,
    log: Mutex<VecDeque<LogLine>>,
    /// Probe-throughput telemetry for the signal waveform — bounded.
    tele: Mutex<VecDeque<TelemetrySample>>,
    cancel: CancellationToken,
    report: Mutex<Option<ScanReport>>,
    /// `reports/scan-<id>.log` — every deque line is also appended here,
    /// lazily opened, so the full log survives restart and can be exported.
    log_path: PathBuf,
    log_sink: Mutex<Option<std::fs::File>>,
}

/// Light state cloned for the index page and every fragment render.
#[derive(Clone)]
struct Meta {
    status: Status,
    done: usize,
    total: usize,
    open: usize,
    closed: usize,
    filtered: usize,
    elapsed_secs: f64,
    /// Wall-clock start (monotonic for live log timestamps).
    started: Instant,
    /// Unix start for "N ago" — correct across restarts for restored scans.
    started_unix: u64,
    open_count: usize,
}

#[derive(Clone)]
struct PortCell {
    ip: IpAddr,
    port: u16,
    proto: Protocol,
    state: PortState,
    service: Option<String>,
}

#[derive(Clone)]
struct LogLine {
    at: f64,
    hot: bool,
    text: String,
}

/// One waveform point: probe progress at a moment in the scan.
#[derive(Clone)]
struct TelemetrySample {
    at: f64,
    done: usize,
    open: usize,
}

/// Ring depth for the waveform — ~36s at the 750ms poll cadence.
const MAX_TELE: usize = 48;

#[derive(Clone, Default)]
enum Status {
    #[default]
    Running,
    Finished,
    Failed(String),
}

impl Status {
    fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }
    fn label(&self) -> String {
        match self {
            Self::Running => "running".into(),
            Self::Finished => "finished".into(),
            Self::Failed(_) => "failed".into(),
        }
    }
}

impl ScanEntry {
    fn meta(&self) -> Meta {
        lock(&self.meta).clone()
    }

    /// Everything the live fragment renders, in one cheap snapshot.
    fn live_data(&self, id: u64) -> LiveData {
        let meta = self.meta();
        let mut cells: Vec<PortCell> = lock(&self.cells).values().cloned().collect();
        cells.sort_by_key(|c| (c.ip, c.port, c.proto));
        let log: Vec<LogLine> = lock(&self.log).iter().cloned().collect();
        // The report exists only once the scan finished; cloning it then is
        // fine — finished pages stop polling (see `live`).
        let tele: Vec<TelemetrySample> = lock(&self.tele).iter().cloned().collect();
        let report = lock(&self.report).clone();
        LiveData {
            scan_id: id,
            meta,
            cells,
            log,
            tele,
            report,
        }
    }

    /// Record a waveform point — at most one per 500ms so busy events
    /// can't flood the ring.
    fn sample(&self) {
        let m = lock(&self.meta);
        let at = m.started.elapsed().as_secs_f64();
        let mut tele = lock(&self.tele);
        if let Some(last) = tele.back()
            && at - last.at < 0.5
        {
            return;
        }
        tele.push_back(TelemetrySample {
            at,
            done: m.done,
            open: m.open_count,
        });
        while tele.len() > MAX_TELE {
            tele.pop_front();
        }
    }

    /// On-disk log line format: `+12.3s` timestamp, `*` marks open-port hits.
    /// Parsed back by [`parse_log_line`].
    fn log(&self, hot: bool, text: String) {
        let at = self.meta().started.elapsed().as_secs_f64();
        let file_line = format!("+{at:.1}s{} {text}\n", if hot { "*" } else { "" });
        {
            let mut log = lock(&self.log);
            log.push_back(LogLine { at, hot, text });
            while log.len() > MAX_LOG {
                log.pop_front();
            }
        }
        let mut sink = lock(&self.log_sink);
        if sink.is_none() {
            *sink = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)
                .ok();
        }
        if let Some(f) = sink.as_mut() {
            let _ = f.write_all(file_line.as_bytes());
        }
    }
}

/// Reverse of the on-disk format written in `ScanEntry::log`.
fn parse_log_line(line: &str) -> Option<LogLine> {
    let (t, text) = line.strip_prefix('+')?.split_once(' ')?;
    let hot = t.ends_with('*');
    let at = t.trim_end_matches(['s', '*']).parse().ok()?;
    Some(LogLine {
        at,
        hot,
        text: text.to_string(),
    })
}

#[derive(Clone)]
struct LiveData {
    scan_id: u64,
    meta: Meta,
    cells: Vec<PortCell>,
    log: Vec<LogLine>,
    tele: Vec<TelemetrySample>,
    report: Option<ScanReport>,
}

impl App {
    fn get(&self, id: u64) -> Option<Arc<ScanEntry>> {
        lock(&self.scans).get(&id).cloned()
    }

    fn list(&self) -> Vec<(u64, Arc<ScanEntry>)> {
        let mut v: Vec<_> = lock(&self.scans)
            .iter()
            .map(|(id, e)| (*id, e.clone()))
            .collect();
        v.sort_by_key(|(id, _)| std::cmp::Reverse(*id));
        v
    }

    /// Load `reports/scan-*.json` back into the scans map so history,
    /// detail pages and exports survive restarts — and feed the
    /// searchable index (`reports/ntok.db`) so `ntok search` sees scans
    /// made before the store existed.
    fn restore(&self) {
        let Ok(rd) = std::fs::read_dir(&self.reports_dir) else {
            return;
        };
        let store = ntok_store::Store::open_default().ok();
        let mut max_id = 0u64;
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(id) = name
                .strip_prefix("scan-")
                .and_then(|n| n.strip_suffix(".json"))
                .and_then(|n| n.parse::<u64>().ok())
            else {
                continue;
            };
            let Some(rep) = std::fs::read_to_string(e.path())
                .ok()
                .and_then(|s| serde_json::from_str::<ScanReport>(&s).ok())
            else {
                continue;
            };
            if let Some(s) = &store {
                let _ = s.ingest(&rep);
            }
            let log = self.load_log(id);
            let entry = self.finished_entry(id, rep.args.clone(), rep, log);
            lock(&self.scans).insert(id, entry);
            max_id = max_id.max(id);
        }
        self.next_id.store(max_id + 1, Ordering::Relaxed);
    }

    /// Tail of `reports/scan-<id>.log`, or a placeholder line when a
    /// restored report has no log file.
    fn load_log(&self, id: u64) -> VecDeque<LogLine> {
        let path = self.reports_dir.join(format!("scan-{id}.log"));
        let mut dq = VecDeque::new();
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                if let Some(l) = parse_log_line(line) {
                    dq.push_back(l);
                    while dq.len() > MAX_LOG {
                        dq.pop_front();
                    }
                }
            }
        }
        if dq.is_empty() {
            dq.push_back(LogLine {
                at: 0.0,
                hot: false,
                text: format!("restored from {}", path.with_extension("json").display()),
            });
        }
        dq
    }

    /// A `Finished` entry built from a report — used for both restored
    /// files and freshly imported nmap XML.
    fn finished_entry(
        &self,
        id: u64,
        args: String,
        rep: ScanReport,
        log: VecDeque<LogLine>,
    ) -> Arc<ScanEntry> {
        let mut cells = HashMap::new();
        let mut total = 0usize;
        for h in &rep.hosts {
            for p in &h.ports {
                total += 1;
                if p.state.is_open() || cells.len() < MAX_CELLS {
                    cells.insert(
                        (h.ip, p.port, p.protocol),
                        PortCell {
                            ip: h.ip,
                            port: p.port,
                            proto: p.protocol,
                            state: p.state,
                            service: p.service.clone(),
                        },
                    );
                }
            }
        }
        let s = &rep.summary;
        Arc::new(ScanEntry {
            args,
            form: None,
            meta: Mutex::new(Meta {
                status: Status::Finished,
                done: total,
                total,
                open: s.open,
                closed: s.closed,
                filtered: s.filtered,
                elapsed_secs: rep.elapsed_secs,
                started: Instant::now()
                    .checked_sub(Duration::from_secs_f64(rep.elapsed_secs))
                    .unwrap_or_else(Instant::now),
                started_unix: rep.start_unix,
                open_count: s.open,
            }),
            cells: Mutex::new(cells),
            log: Mutex::new(log),
            tele: Mutex::new(VecDeque::new()),
            cancel: CancellationToken::new(),
            report: Mutex::new(Some(rep)),
            log_path: self.reports_dir.join(format!("scan-{id}.log")),
            log_sink: Mutex::new(None),
        })
    }

    /// Import an nmap `-oX` XML file from disk as a finished scan —
    /// full detail page, all export formats, and it persists like a
    /// native scan's `reports/scan-<id>.json`.
    fn import(&self, path: &str) -> ntok_core::Result<u64> {
        let xml = std::fs::read_to_string(path)?;
        let rep = ntok_core::import::parse_nmap_xml(&xml)?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        report::write_json(&rep, &self.reports_dir.join(format!("scan-{id}.json")))?;
        let _ = ntok_store::index_default(&rep);
        let entry = self.finished_entry(
            id,
            format!("import {path} — {}", rep.args),
            rep,
            VecDeque::new(),
        );
        entry.log(false, format!("imported nmap report from {path}"));
        lock(&self.scans).insert(id, Arc::clone(&entry));
        Ok(id)
    }

    /// Ids of scans that have a finished report (restored, imported or
    /// done), newest first — the "compare with" list.
    fn comparable_ids(&self, except: u64) -> Vec<u64> {
        let mut ids: Vec<u64> = lock(&self.scans)
            .iter()
            .filter(|(id, e)| **id != except && lock(&e.report).is_some())
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable_by_key(|id| std::cmp::Reverse(*id));
        ids.truncate(8);
        ids
    }

    /// Remove a finished/failed scan from history plus its report files.
    /// Refuses while running — a live writer still owns the log file.
    fn delete(&self, id: u64) -> ntok_core::Result<()> {
        let Some(entry) = lock(&self.scans).get(&id).cloned() else {
            return Ok(());
        };
        if entry.meta().status.is_running() {
            return Err(ntok_core::Error::Unsupported(
                "stop the scan before deleting it",
            ));
        }
        *lock(&entry.log_sink) = None; // close the log handle (Windows can't delete an open file)
        lock(&self.scans).remove(&id);
        for ext in ["json", "log"] {
            let p = self.reports_dir.join(format!("scan-{id}.{ext}"));
            match std::fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn start(&self, form: &ScanForm) -> ntok_core::Result<u64> {
        let targets = form
            .targets
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|t| !t.is_empty())
            .map(parse_target)
            .collect::<ntok_core::Result<Vec<_>>>()?;
        let ports = match form.ports.as_deref().map(str::trim) {
            Some(spec) if !spec.is_empty() => ports::parse_ports(spec)?,
            _ => ports::default_ports(),
        };
        let technique = match form.technique.as_deref() {
            Some("udp") => ScanTechnique::Udp,
            Some("syn") => ScanTechnique::Syn,
            Some("ack") => ScanTechnique::Ack,
            Some("fin") => ScanTechnique::Fin,
            Some("null") => ScanTechnique::Null,
            Some("xmas") => ScanTechnique::Xmas,
            _ => ScanTechnique::Connect,
        };
        let mut cfg = ScanConfig::new(targets);
        cfg.ports = ports;
        cfg.technique = technique;
        cfg.timing = Timing::template(form.timing.unwrap_or(3))?;
        cfg.skip_discovery = form.skip_discovery.is_some();
        cfg.service_probe = form.service.is_some();
        cfg.web_scan = matches!(form.mode.as_deref(), Some("web") | Some("full"));
        cfg.web_crawl = if cfg.web_scan {
            form.crawl.unwrap_or(0).min(8)
        } else {
            0
        };
        cfg.verbose = true; // stream every port state so the grid can render it
        cfg.args = format!("{} {}", technique.as_str(), form.targets);
        if cfg.web_scan {
            cfg.args.push_str(" --web");
            if cfg.web_crawl > 0 {
                cfg.args.push_str(&format!(" --crawl {}", cfg.web_crawl));
            }
        }
        let mut ai_note = None;
        if form.ai.is_some() {
            let mut s = lock(&self.ai).clone();
            if let Some(m) = non_empty(form.ai_model.as_deref()) {
                s.model = m.to_string();
            }
            if let Some(i) = non_empty(form.ai_instructions.as_deref()) {
                s.instructions = Some(i.to_string());
            }
            match ntok_core::HttpAdvisor::new(s) {
                Ok(adv) => {
                    cfg.advisor = Arc::new(adv);
                    cfg.args.push_str(" --ai");
                }
                Err(e) => ai_note = Some(format!("AI advisor disabled: {e}")),
            }
        }
        for (field, kind) in [
            (form.tool_nmap.as_ref(), ntok_core::ToolKind::Nmap),
            (form.tool_nuclei.as_ref(), ntok_core::ToolKind::Nuclei),
            (form.tool_masscan.as_ref(), ntok_core::ToolKind::Masscan),
            (form.tool_naabu.as_ref(), ntok_core::ToolKind::Naabu),
            (form.tool_rustscan.as_ref(), ntok_core::ToolKind::Rustscan),
        ] {
            if field.is_some() {
                cfg.tools.push(kind);
                cfg.args.push_str(&format!(" --tools {}", kind.as_str()));
            }
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(ScanEntry {
            args: cfg.args.clone(),
            form: Some(form.clone()),
            meta: Mutex::new(Meta {
                status: Status::Running,
                done: 0,
                total: 0,
                open: 0,
                closed: 0,
                filtered: 0,
                elapsed_secs: 0.0,
                started: Instant::now(),
                started_unix: now_unix(),
                open_count: 0,
            }),
            cells: Mutex::new(HashMap::new()),
            log: Mutex::new(VecDeque::new()),
            tele: Mutex::new(VecDeque::new()),
            cancel: CancellationToken::new(),
            report: Mutex::new(None),
            log_path: self.reports_dir.join(format!("scan-{id}.log")),
            log_sink: Mutex::new(None),
        });
        lock(&self.scans).insert(id, Arc::clone(&entry));

        let (tx, _) = broadcast::channel::<ScanEvent>(4096);
        let mut rx = tx.subscribe();
        if let Some(text) = ai_note {
            let _ = tx.send(ScanEvent::Note { text });
        }

        // Collector: events -> meta + cells + log.
        {
            let entry = Arc::clone(&entry);
            tokio::spawn(async move {
                while let Ok(ev) = rx.recv().await {
                    match ev {
                        ScanEvent::Started {
                            hosts,
                            ports,
                            technique,
                        } => entry.log(
                            false,
                            format!("ntok: {hosts} hosts × {ports} ports — {technique} scan"),
                        ),
                        ScanEvent::HostDiscovered { ip, up } => entry.log(
                            false,
                            if up {
                                format!("host {ip} is up")
                            } else {
                                format!("host {ip} seems down — skipped")
                            },
                        ),
                        ScanEvent::PortFound {
                            ip,
                            port,
                            protocol,
                            state,
                            service,
                        } => {
                            {
                                let mut cells = lock(&entry.cells);
                                let open = state.is_open();
                                // Keep open results unconditionally; bound the rest.
                                if open || cells.len() < MAX_CELLS {
                                    cells.insert(
                                        (ip, port, protocol),
                                        PortCell {
                                            ip,
                                            port,
                                            proto: protocol,
                                            state,
                                            service: service.clone(),
                                        },
                                    );
                                }
                                if open {
                                    lock(&entry.meta).open_count += 1;
                                }
                            }
                            if state.is_open() {
                                entry.sample();
                            }
                            if state.is_open() {
                                let svc = service
                                    .as_deref()
                                    .map(|s| format!(" ({s})"))
                                    .unwrap_or_default();
                                entry.log(
                                    true,
                                    format!(
                                        "discovered {} port {}/{} on {ip}{svc}",
                                        state.as_str(),
                                        port,
                                        protocol.as_str()
                                    ),
                                );
                            }
                        }
                        ScanEvent::Note { text } => entry.log(false, text),
                        ScanEvent::Progress { done, total } => {
                            {
                                let mut m = lock(&entry.meta);
                                m.done = done;
                                m.total = total;
                            }
                            entry.sample();
                        }
                        ScanEvent::Finished {
                            elapsed_secs,
                            open,
                            closed,
                            filtered,
                            unfiltered,
                        } => {
                            {
                                let mut m = lock(&entry.meta);
                                m.elapsed_secs = elapsed_secs;
                                m.open = open;
                                m.closed = closed;
                                m.filtered = filtered;
                            }
                            let extra = if unfiltered > 0 {
                                format!(", {unfiltered} unfiltered")
                            } else {
                                String::new()
                            };
                            entry.log(
                                false,
                                format!(
                                    "scan complete in {elapsed_secs:.2}s — {open} open, {closed} closed, {filtered} filtered{extra}"
                                ),
                            );
                        }
                    }
                }
            });
        }

        // Runner: engine -> report file + final status.
        {
            let entry = Arc::clone(&entry);
            let path = self.reports_dir.join(format!("scan-{id}.json"));
            let d1 = self.d1.clone();
            tokio::spawn(async move {
                let result = run_scan(cfg, tx, entry.cancel.clone()).await;
                let mut m = lock(&entry.meta);
                match result {
                    Ok(rep) => {
                        let _ = report::write_json(&rep, &path);
                        let _ = ntok_store::index_default(&rep);
                        if let Some(d1) = d1.clone() {
                            let rep = rep.clone();
                            tokio::spawn(async move { d1.push_scan(&rep).await });
                        }
                        *lock(&entry.report) = Some(rep);
                        m.status = Status::Finished;
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        m.status = Status::Failed(msg.clone());
                        drop(m);
                        entry.log(false, format!("error: {msg}"));
                    }
                }
            });
        }

        Ok(id)
    }
}

// ---------- form ----------

#[derive(Deserialize, Clone)]
struct ScanForm {
    targets: String,
    /// "net" | "web" | "full" — web/full enable the reconnaissance pass.
    mode: Option<String>,
    ports: Option<String>,
    crawl: Option<usize>,
    timing: Option<u8>,
    technique: Option<String>,
    service: Option<String>,
    skip_discovery: Option<String>,
    ai: Option<String>,
    tool_nmap: Option<String>,
    tool_nuclei: Option<String>,
    tool_masscan: Option<String>,
    tool_naabu: Option<String>,
    tool_rustscan: Option<String>,
    ai_model: Option<String>,
    ai_instructions: Option<String>,
}

#[derive(Deserialize)]
struct SettingsForm {
    action: Option<String>,
    endpoint: Option<String>,
    model: Option<String>,
    api_key: Option<String>,
    clear_key: Option<String>,
    instructions: Option<String>,
}

fn non_empty(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

/// Form fields merged over the stored settings: blank endpoint/model fall
/// back to defaults, blank key keeps the saved one.
fn merge_settings(form: &SettingsForm, current: &AiSettings) -> AiSettings {
    let mut s = AiSettings::default();
    if let Some(e) = non_empty(form.endpoint.as_deref()) {
        s.endpoint = e.to_string();
    }
    if let Some(m) = non_empty(form.model.as_deref()) {
        s.model = m.to_string();
    }
    s.api_key = if form.clear_key.is_some() {
        None
    } else {
        non_empty(form.api_key.as_deref())
            .map(str::to_string)
            .or_else(|| current.api_key.clone())
    };
    s.instructions = non_empty(form.instructions.as_deref()).map(str::to_string);
    s
}

// ---------- helpers ----------

fn fmt_secs(secs: f64) -> String {
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else {
        format!("{}m {:02.0}s", (secs / 60.0) as u64, secs % 60.0)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fmt_ago(started_unix: u64) -> String {
    let s = now_unix().saturating_sub(started_unix);
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else {
        format!("{}h ago", s / 3600)
    }
}

fn cell_class(state: PortState) -> &'static str {
    match state {
        PortState::Open => "cell open",
        PortState::OpenFiltered => "cell openfilt",
        PortState::Filtered => "cell filtered",
        PortState::Closed => "cell closed",
        PortState::Unfiltered => "cell openfilt",
    }
}

// ---------- layout & pages ----------

// Single Deep Field night theme — the whole palette lives in :root tokens
// (see DESIGN.md).
const CSS: &str = include_str!("../assets/app.css");

const APP_JS: &str = include_str!("../assets/app.js");
const AUTH3D_JS: &str = include_str!("../assets/auth3d.js");

fn page_title(path: &str) -> String {
    let brand = ntok_core::brand::NAME;
    if path == "/" {
        format!("{brand} — {}", ntok_core::brand::SUBTITLE)
    } else if path.starts_with("/scans/") {
        format!("Scan · {brand}")
    } else if path.starts_with("/compare/") {
        format!("Compare · {brand}")
    } else if path == "/search" {
        format!("Index · {brand}")
    } else if path == "/agent" {
        format!("Agent · {brand}")
    } else if path == "/settings" {
        format!("Settings · {brand}")
    } else if path == "/guide" {
        format!("Guide · {brand}")
    } else if path == "/login" {
        format!("Sign in · {brand}")
    } else if path == "/register" {
        format!("Register · {brand}")
    } else if path == "/privacy" {
        format!("Privacy · {brand}")
    } else if path == "/terms" {
        format!("Terms · {brand}")
    } else if path == "/acceptable-use" {
        format!("Acceptable Use · {brand}")
    } else {
        brand.to_string()
    }
}

#[layout("/")]
async fn shell(cx: &Cx, slot: Slot<'_>) -> Result<impl View> {
    let authed = app(cx).auth.is_some();
    let ua_mobile = headers(cx)
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ua| ua.contains("NtokMobile"));
    let surface = if ua_mobile { "mobile" } else { app(cx).surface };
    let path = uri(cx).path().to_string();
    let title = page_title(&path);
    let is_auth_page = path == "/login" || path == "/register";
    let scans_cur = if path == "/" || path.starts_with("/scans/") || path.starts_with("/compare/") {
        "page"
    } else {
        "false"
    };
    let search_cur = if path == "/search" { "page" } else { "false" };
    let agent_cur = if path == "/agent" { "page" } else { "false" };
    let settings_cur = if path == "/settings" { "page" } else { "false" };
    let guide_cur = if path == "/guide" { "page" } else { "false" };
    let active_scans = app(cx)
        .list()
        .iter()
        .filter(|(_, e)| e.meta().status.is_running())
        .count();
    let sys_cls = if active_scans > 0 {
        "sys-pill live"
    } else {
        "sys-pill"
    };
    let sys_state = if active_scans > 0 {
        format!("{active_scans} running")
    } else if surface == "desktop" {
        "Desktop OK".to_string()
    } else {
        "Ready".to_string()
    };
    let foot_cls = if active_scans > 0 {
        "foot-status live"
    } else {
        "foot-status"
    };
    let version = env!("CARGO_PKG_VERSION");
    let user = if authed { current_user(cx) } else { None };
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en" data-surface=(surface)>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
                <meta name="theme-color" content="#050D24">
                <meta name="color-scheme" content="dark">
                <title>(title)</title>
                <link rel="icon" href=(ntok_core::brand::MARK_DATA_URI)>
                <script src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.10/dist/htmx.min.js"></script>
                <style>(Unescaped::new_unchecked(CSS))</style>
            </head>
            <body>
                <a class="skip-link" href="#main-content">"Skip to content"</a>
                <div class="top-wrap">
                    <header class="top">
                        <a class="brand" href="/" title=(ntok_core::brand::EXPANSION)>
                            <span class="mark">(mark())</span>
                            <span class="brand-text">
                                <span class="brand-name">(ntok_core::brand::NAME)</span>
                                <span class="brand-sub">(ntok_core::brand::SUBTITLE)</span>
                            </span>
                        </a>
                        if !is_auth_page {
                            <nav class="nav" aria-label="Primary">
                                <a href=(href!(index)) aria-current=(scans_cur)>(icons::ic(icons::RADAR))"Scans"</a>
                                <a href=(href!(search_page)) aria-current=(search_cur)>(icons::ic(icons::DATABASE))"Index"</a>
                                <a href=(href!(agent_page)) aria-current=(agent_cur)>(icons::ic(icons::SPARKLES))"Agent"</a>
                                <a href=(href!(settings_page)) aria-current=(settings_cur)>(icons::ic(icons::SLIDERS))"Settings"</a>
                                <a href=(href!(docs::guide_page)) aria-current=(guide_cur)>(icons::ic(icons::BOOK))"Guide"</a>
                            </nav>
                        }
                        <div class="top-right">
                            if !is_auth_page {
                                <span class=(sys_cls) title="Local engine health">
                                    <span class="sys-k">"Engine"</span>
                                    <span class="sys-st"><span class="sys-dot"></span>(sys_state.clone())</span>
                                </span>
                                if let Some(u) = &user {
                                    <details class="menu">
                                        <summary class="op-pill" title="Account">
                                            <span class="op-ic">(icons::ic(icons::USER))</span>
                                            <span class="op-name">(u.name.clone())</span>
                                            <span class="caret">(icons::ic(icons::CHEVRON))</span>
                                        </summary>
                                        <div class="menu-pop" role="menu">
                                            <div class="menu-head">
                                                <b>(u.full_name.clone().unwrap_or_else(|| u.name.clone()))</b>
                                                <small>(u.email.clone().unwrap_or_else(|| format!("@{}", u.name)))</small>
                                            </div>
                                            <a class="menu-item" href=(href!(settings_page))>
                                                (icons::ic(icons::SLIDERS))"Settings & API tokens"
                                            </a>
                                            <form method="post" action=(href!(logout))>
                                                <button class="menu-item danger" type="submit">
                                                    (icons::ic(icons::LOGOUT))"Sign out"
                                                </button>
                                            </form>
                                        </div>
                                    </details>
                                }
                            }
                        </div>
                    </header>
                </div>
                <main id="main-content">(slot)</main>
                if !is_auth_page {
                    <nav class="mob-nav" aria-label="Mobile navigation">
                        <a href=(href!(index)) aria-current=(scans_cur)>(icons::ic(icons::RADAR))<span>"Scans"</span></a>
                        <a href=(href!(search_page)) aria-current=(search_cur)>(icons::ic(icons::DATABASE))<span>"Index"</span></a>
                        <a href=(href!(agent_page)) aria-current=(agent_cur)>(icons::ic(icons::SPARKLES))<span>"Agent"</span></a>
                        <a href=(href!(settings_page)) aria-current=(settings_cur)>(icons::ic(icons::SLIDERS))<span>"Settings"</span></a>
                        <a href=(href!(docs::guide_page)) aria-current=(guide_cur)>(icons::ic(icons::BOOK))<span>"Guide"</span></a>
                    </nav>
                }
                <footer class="foot">
                    if !is_auth_page {
                        <div class="foot-grid">
                            <div class="foot-brand">
                                <a class="brand" href="/" title=(ntok_core::brand::EXPANSION)>
                                    <span class="mark">(mark())</span>
                                    <span class="brand-text">
                                        <span class="brand-name">(ntok_core::brand::NAME)</span>
                                        <span class="brand-sub">(ntok_core::brand::SUBTITLE)</span>
                                    </span>
                                </a>
                                <p class="foot-tag">
                                    (ntok_core::brand::EXPANSION)
                                    " — scan only systems you own or are authorized to test."
                                </p>
                            </div>
                            <nav class="foot-col" aria-label="Product">
                                <span class="foot-h">"Product"</span>
                                <a href=(href!(index))>"Scans"</a>
                                <a href=(href!(search_page))>"Index"</a>
                                <a href=(href!(agent_page))>"Agent"</a>
                                <a href=(href!(docs::guide_page))>"Guide"</a>
                                <a href=(href!(settings_page))>"Settings"</a>
                            </nav>
                            <nav class="foot-col" aria-label="Legal">
                                <span class="foot-h">"Legal"</span>
                                <a href=(href!(docs::privacy_page))>"Privacy"</a>
                                <a href=(href!(docs::terms_page))>"Terms"</a>
                                <a href=(href!(docs::acceptable_use_page))>"Acceptable Use"</a>
                            </nav>
                        </div>
                    }
                    <div class="foot-bar">
                        if is_auth_page {
                            <span class="foot-note">(ntok_core::brand::NAME) " — scan only systems you own or are authorized to test."</span>
                            <nav class="foot-links" aria-label="Legal">
                                <a href=(href!(docs::privacy_page))>"Privacy"</a>
                                <a href=(href!(docs::terms_page))>"Terms"</a>
                                <a href=(href!(docs::acceptable_use_page))>"Acceptable Use"</a>
                            </nav>
                        } else {
                            <span class="foot-note">(ntok_core::brand::NAME) " v" (version) " — local-first, no telemetry."</span>
                            <span class=(foot_cls)>
                                <span class="sys-dot"></span>"engine · " (sys_state)
                            </span>
                        }
                    </div>
                </footer>
                <div id="ntok-toast" class="toast" role="status" aria-live="polite" aria-atomic="true"></div>
                <script>(Unescaped::new_unchecked(APP_JS))</script>
            </body>
        </html>
    })
}

#[page("/")]
async fn index(cx: &Cx) -> Result<impl View> {
    let app = app(cx);
    let rows = scan_rows(app);
    let error = lock(&app.last_error).take();

    let running = rows
        .iter()
        .filter(|(_, _, m, _)| m.status.is_running())
        .count();
    let open_total: usize = rows.iter().map(|(_, _, m, _)| m.open_count).sum();
    let stats = ntok_store::Store::open_default()
        .and_then(|s| s.stats())
        .ok();
    let indexed_services = stats.map(|st| st.services).unwrap_or(0);
    let indexed_hosts = stats.map(|st| st.hosts).unwrap_or(0);
    let idx_progress = (indexed_services as f64 / 200.0).clamp(0.12, 1.0);

    Ok(view! {
        if let Some(e) = error {
            <div class="banner">(e)</div>
        }

        <section class="bento-hero">
            <form id="scan-form" data-mode="net" class="panel scan-stack" method="post" action=(href!(start_scan))>
                <div class="scan-head">
                    <span class="eyebrow">(ntok_core::brand::EXPANSION)</span>
                    <h1>"Discover. Analyze. Secure."</h1>
                    <p class="lede">"Point at any IP, subnet, or URL — watch every port and service resolve live."</p>
                </div>

                <div>
                    <div class="seg" role="radiogroup" aria-label="Scan mode">
                        <label><input type="radio" name="mode" value="net" checked="checked"><span class="opt">(icons::ic(icons::RADAR))"Network / ports"</span></label>
                        <label><input type="radio" name="mode" value="web"><span class="opt">(icons::ic(icons::GLOBE))"Website intel"</span></label>
                        <label><input type="radio" name="mode" value="full"><span class="opt">(icons::ic(icons::LAYERS))"Ports + web"</span></label>
                    </div>
                </div>

                <div class="frm">
                    <div class="full">
                        <label class="lbl" for="targets">"Targets"</label>
                        <div class="field-in">
                            (icons::ic(icons::TARGET))
                            <input class="txt hero-in" id="targets" name="targets" required="required"
                                placeholder="10.0.0.0/24  192.168.1.1-50  host.example  https://example.com">
                        </div>
                    </div>

                    <div class="full net-only">
                        <label class="lbl" for="ports">"Ports"</label>
                        <div class="field-in">
                            (icons::ic(icons::GRID))
                            <input class="txt" id="ports" name="ports"
                                placeholder="leave blank for common ports · 22,80,443 · 1-1024 · top:100 · all">
                        </div>
                        <div class="hint-chips">
                            <span class="hk">"quick"</span>
                            <button type="button" class="hint-chip" onclick="ntokPortPreset('top:100')">"top:100"</button>
                            <button type="button" class="hint-chip" onclick="ntokPortPreset('web')">"web ports"</button>
                            <button type="button" class="hint-chip" onclick="ntokPortPreset('1-1024')">"1-1024"</button>
                            <button type="button" class="hint-chip" onclick="ntokPortPreset('all')">"all 65k"</button>
                        </div>
                    </div>

                    <div class="full web-only">
                        <label class="lbl">"Crawl depth"</label>
                        <div class="seg">
                            <label><input type="radio" name="crawl" value="0" checked="checked"><span class="opt">"Home only"</span></label>
                            <label><input type="radio" name="crawl" value="2"><span class="opt">"2 pages"</span></label>
                            <label><input type="radio" name="crawl" value="4"><span class="opt">"4 pages"</span></label>
                            <label><input type="radio" name="crawl" value="6"><span class="opt">"6 pages"</span></label>
                        </div>
                    </div>
                </div>

                <button class="cta-pill" type="submit">
                    <span class="cta-pill-copy">
                        <span class="cta-pill-title">"Launch scan"</span>
                        <span class="cta-pill-sub">"Local-first engine · reports saved in reports/"</span>
                    </span>
                    <span class="cta-pill-arrow" aria-hidden="true">"→"</span>
                </button>

                <details class="adv">
                    <summary>"Scan parameters & external tools"<span class="adv-hint">"technique · timing · -sV / -Pn · nmap / nuclei · AI advisor"</span></summary>
                    <div class="adv-body one" style="gap:16px">
                        <div class="net-only">
                            <span class="lbl">"Technique"</span>
                            <div class="seg">
                                <label><input type="radio" name="technique" value="connect" checked="checked"><span class="opt">"TCP connect"</span></label>
                                <label><input type="radio" name="technique" value="udp"><span class="opt">"UDP"</span></label>
                                <label><input type="radio" name="technique" value="syn"><span class="opt">"SYN"</span></label>
                                <label><input type="radio" name="technique" value="ack"><span class="opt">"ACK"</span></label>
                                <label><input type="radio" name="technique" value="fin"><span class="opt">"FIN"</span></label>
                                <label><input type="radio" name="technique" value="null"><span class="opt">"NULL"</span></label>
                                <label><input type="radio" name="technique" value="xmas"><span class="opt">"Xmas"</span></label>
                            </div>
                        </div>
                        <div>
                            <span class="lbl">"Timing"</span>
                            <div class="seg">
                                <label><input type="radio" name="timing" value="2"><span class="opt">"T2 polite"</span></label>
                                <label><input type="radio" name="timing" value="3" checked="checked"><span class="opt">"T3 normal"</span></label>
                                <label><input type="radio" name="timing" value="4"><span class="opt">"T4 aggressive"</span></label>
                                <label><input type="radio" name="timing" value="5"><span class="opt">"T5 insane"</span></label>
                            </div>
                        </div>
                        <div>
                            <span class="lbl">"Core flags"</span>
                            <div class="tgl">
                                <label><input type="checkbox" name="service" checked="checked">"Service detection (-sV)"</label>
                                <label><input type="checkbox" name="skip_discovery">"Skip discovery (-Pn)"</label>
                                <label><input type="checkbox" name="ai">"AI advisor"</label>
                            </div>
                        </div>
                        <div>
                            <span class="lbl">"External tools"</span>
                            <div class="tgl">
                                <label><input type="checkbox" name="tool_nmap">"nmap -sV"</label>
                                <label><input type="checkbox" name="tool_nuclei">"nuclei"</label>
                                <label><input type="checkbox" name="tool_masscan">"masscan"</label>
                                <label><input type="checkbox" name="tool_naabu">"naabu"</label>
                                <label><input type="checkbox" name="tool_rustscan">"rustscan"</label>
                            </div>
                        </div>
                        <div class="frm">
                            <div>
                                <label class="lbl" for="ai_model">"AI model override"</label>
                                <div class="field-in">
                                    (icons::ic(icons::SPARKLES))
                                    <input class="txt" id="ai_model" name="ai_model" placeholder="deepseek-chat">
                                </div>
                            </div>
                            <div>
                                <label class="lbl" for="ai_instructions">"AI instructions"</label>
                                <div class="field-in">
                                    (icons::ic(icons::EDIT))
                                    <input class="txt" id="ai_instructions" name="ai_instructions" placeholder="e.g. focus on web services">
                                </div>
                            </div>
                        </div>
                    </div>
                </details>
            </form>

            <aside class="bento-side">
                <div class="tile-obs">
                    <div class="tile-obs-head">
                        <span class="tile-obs-label">"Knowledge Index"</span>
                        <a class="tile-obs-pill" href=(href!(search_page))>"Explore →"</a>
                    </div>
                    <div class="tile-obs-val">
                        <span>(indexed_services)</span>
                        <small>"services"</small>
                    </div>
                    <div class="obs-bar"><i style=(format!("--p:{idx_progress:.2}"))></i></div>
                    <div class="tile-obs-foot">
                        (indexed_hosts) " indexed hosts · " (open_total) " open ports seen"
                    </div>
                </div>

                <div class="bento-pair">
                    <div class="tile-ceramic">
                        <div class="tv">(rows.len())</div>
                        <div class="tk">"Scans archived"</div>
                    </div>
                    <div class="tile-ceramic">
                        <div class="tv" style=(if running > 0 { "color:var(--accent)" } else { "" })>(running)</div>
                        <div class="tk">
                            "Running now"
                            if running > 0 {
                                <span class="live-dot" aria-hidden="true"></span>
                            }
                        </div>
                    </div>
                </div>
            </aside>
        </section>

        <div class="sec">
            <div class="srv-map">
                <div class="c-head">
                    (icons::ic(icons::BRANCH))"How a scan flows"
                    <span class="m-hint">"solid: always runs · dashed: opt-in — degrades to warnings, never fails the scan"</span>
                </div>
                (Unescaped::new_unchecked(charts::pipeline_map()))
            </div>
        </div>

        <div class="sec">
            <div class="sec-head">
                <p class="sec-title">(icons::ic(icons::CLOCK))"Scan history"</p>
                <details class="adv" style="min-width:260px">
                    <summary style="padding:7px 14px;font-size:12px">"Import nmap XML"</summary>
                    <form class="adv-body one" method="post" action=(href!(import_scan)) style="padding:12px">
                        <div style="display:flex;gap:8px;align-items:center">
                            <div class="field-in" style="flex:1">
                                (icons::ic(icons::FILE))
                                <input class="txt" id="import_path" name="path" required="required"
                                    placeholder="path to nmap -oX .xml" style="padding:8px 12px 8px 36px">
                            </div>
                            <button class="btn sm" type="submit">(icons::ic(icons::UPLOAD))"Import"</button>
                        </div>
                    </form>
                </details>
            </div>
            scan_list(rows: rows)
        </div>
    })
}

/// Row data for the history table: (id, args, meta, can_rescan).
type ScanRows = Vec<(u64, String, Meta, bool)>;

fn scan_rows(app: &App) -> ScanRows {
    app.list()
        .iter()
        .map(|(id, e)| (*id, e.args.clone(), e.meta(), e.form.is_some()))
        .collect()
}

#[component]
async fn scan_list(cx: &Cx, rows: ScanRows) -> Result<impl View> {
    let _ = cx;
    let has_running = rows.iter().any(|(_, _, m, _)| m.status.is_running());
    Ok(view! {
        if has_running {
            <div
                id="scanlist"
                hx-get=(href!(scan_list_fragment))
                hx-trigger="every 1s"
                hx-swap="outerHTML"
            >
                scan_list_table(rows: rows)
            </div>
        } else {
            <div id="scanlist">
                scan_list_table(rows: rows)
            </div>
        }
    })
}

#[component]
async fn scan_list_table(cx: &Cx, rows: ScanRows) -> Result<impl View> {
    let _ = cx;
    Ok(view! {
        if rows.is_empty() {
            <div class="empty">"No scans yet — enter a target above to launch your first scan."</div>
        } else {
            <div class="panel flush">
                <table>
                    <thead>
                        <tr>
                            <th class="num">"#"</th>
                            <th>"Command"</th>
                            <th>"Status"</th>
                            <th class="num">"Open"</th>
                            <th>"Started"</th>
                            <th class="num">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody>
                        for (id, args, m, can_rescan) in &rows {
                            let cls = match &m.status {
                                Status::Running => "pill running",
                                Status::Finished => "pill done",
                                Status::Failed(_) => "pill err",
                            };
                            <tr>
                                <td class="num"><a href=(href!(scan_page, scan_id: *id))>(id)</a></td>
                                <td><a href=(href!(scan_page, scan_id: *id))>"ntok " (args.clone())</a></td>
                                <td><span class=(cls)>(m.status.label())</span></td>
                                <td class="num acc">(m.open_count)</td>
                                <td style="color:var(--muted)">(fmt_ago(m.started_unix))</td>
                                <td class="num" style="white-space:nowrap">
                                    if *can_rescan {
                                        <form method="post" action=(href!(rescan_scan, scan_id: *id)) style="display:inline;margin-right:6px">
                                            <button class="btn xs ghost" type="submit">(icons::ic(icons::REFRESH))"rescan"</button>
                                        </form>
                                    }
                                    if !m.status.is_running() {
                                        <form
                                            method="post"
                                            action=(href!(delete_scan, scan_id: *id))
                                            style="display:inline"
                                            onsubmit=(format!("return confirm('Delete scan #{id} and its report files?')"))
                                        >
                                            <button class="btn xs danger" type="submit">(icons::ic(icons::TRASH))"delete"</button>
                                        </form>
                                    }
                                </td>
                            </tr>
                        }
                    </tbody>
                </table>
            </div>
        }
    })
}

#[page("/scans/{scan_id}")]
async fn scan_page(cx: &Cx) -> Result<impl View> {
    let id = *scan_id(cx)?;
    let entry = app(cx).get(id).ok_or_not_found()?;
    let rescan = entry.form.is_some();
    let data = entry.live_data(id);
    let full_cmd = format!("ntok {}", entry.args);
    let copy_js = format!(
        "ntokCopy(this, {})",
        serde_json::to_string(&full_cmd).unwrap_or_else(|_| "\"\"".into())
    );
    Ok(view! {
        <div class="page-head">
            <div>
                <span class="eyebrow">(ntok_core::brand::NAME) " · Scan Telemetry"</span>
                <h1>"Scan #" (id)</h1>
            </div>
            <span class="sp"></span>
            <div class="page-actions">
                if rescan {
                    <form method="post" action=(href!(rescan_scan, scan_id: id))>
                        <button class="btn sm ghost" type="submit">(icons::ic(icons::REFRESH))"Rescan"</button>
                    </form>
                }
                <a class="btn sm ghost" href=(href!(index))>(icons::ic(icons::PLUS))"New scan"</a>
            </div>
        </div>
        <div class="cmd-row">
            <span class="cmd">(full_cmd)</span>
            <button type="button" class="copy-btn" onclick=(copy_js)>"copy"</button>
        </div>
        live(data: data)
    })
}

#[component]
async fn live(cx: &Cx, data: LiveData) -> Result<impl View> {
    // The #live div carries the htmx polling attrs only while the scan runs;
    // hx-swap="outerHTML" replaces it whole, so a finished render drops the
    // trigger and the browser stops polling.
    Ok(view! {
        if data.meta.status.is_running() {
            <div
                id="live"
                hx-get=(href!(ports_fragment, scan_id: data.scan_id))
                hx-trigger="every 750ms"
                hx-swap="outerHTML"
            >
                live_body(data: data)
            </div>
        } else {
            <div id="live">live_body(data: data)</div>
        }
    })
}

/// Server-rendered sparkline for the telemetry ring: probes/sec between
/// samples as an emerald spline, nodes where open ports landed, peak rate
/// callout. Numbers-only markup — safe for Unescaped.
fn waveform(tele: &[TelemetrySample]) -> Option<(String, f64, f64)> {
    if tele.len() < 2 {
        return None;
    }
    const W: f64 = 640.0;
    const H: f64 = 72.0;
    // rate[i] = probes/sec between sample i-1 and i.
    let mut rates: Vec<f64> = Vec::with_capacity(tele.len() - 1);
    for i in 1..tele.len() {
        let dt = (tele[i].at - tele[i - 1].at).max(0.05);
        rates.push(tele[i].done.saturating_sub(tele[i - 1].done) as f64 / dt);
    }
    let peak = rates.iter().cloned().fold(1.0_f64, f64::max);
    let last = rates.last().copied().unwrap_or(0.0);
    let span = tele.last().map(|t| t.at).unwrap_or(0.0) - tele[0].at;
    let mut d = String::new();
    let mut circles = String::new();
    let steps = (rates.len() - 1).max(1) as f64;
    for (i, r) in rates.iter().enumerate() {
        let x = i as f64 / steps * W;
        let y = H - 6.0 - (r / peak) * (H - 16.0);
        d.push_str(&format!("{}{x:.1} {y:.1}", if i == 0 { "M" } else { " L" }));
        if tele[i + 1].open > tele[i].open {
            circles.push_str(&format!(
                "<circle class=\"hit\" cx=\"{x:.1}\" cy=\"{y:.1}\" r=\"2.6\"/>"
            ));
        }
    }
    let svg = format!(
        "<svg class=\"wave\" viewBox=\"0 0 {W:.0} {H:.0}\" preserveAspectRatio=\"none\" \
         role=\"img\" aria-label=\"probe throughput waveform\">\
         <defs><linearGradient id=\"ntok-wfill\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\">\
         <stop offset=\"0\" stop-color=\"#45C4EC\" stop-opacity=\".20\"/>\
         <stop offset=\"1\" stop-color=\"#45C4EC\" stop-opacity=\"0\"/></linearGradient></defs>\
         <line class=\"base\" x1=\"0\" y1=\"{base:.0}\" x2=\"{W:.0}\" y2=\"{base:.0}\"/>\
         <path class=\"fill\" fill=\"url(#ntok-wfill)\" d=\"{d} L{W:.0} {H:.0} L0 {H:.0} Z\"/>\
         <path class=\"sig\" d=\"{d}\"/>{circles}</svg>",
        base = H * 0.6
    );
    Some((svg, last, span))
}

#[component]
async fn live_body(cx: &Cx, data: LiveData) -> Result<impl View> {
    // Destructure into owned locals — view! captures by move, so anything
    // referenced inside must be owned here; borrows happen inside the view.
    let report_url = href!(report_route, scan_id: data.scan_id).resolve(cx);
    let log_url = href!(log_route, scan_id: data.scan_id).resolve(cx);
    let other_ids = app(cx).comparable_ids(data.scan_id);
    let LiveData {
        scan_id,
        meta,
        cells,
        log,
        tele,
        report,
    } = data;
    let running = meta.status.is_running();
    let elapsed = if let Status::Finished = meta.status {
        meta.elapsed_secs
    } else {
        meta.started.elapsed().as_secs_f64()
    };
    let frac = if meta.total > 0 {
        (meta.done as f64 / meta.total as f64).min(1.0)
    } else {
        0.0
    };
    let pill = match &meta.status {
        Status::Running => "pill running",
        Status::Finished => "pill done",
        Status::Failed(_) => "pill err",
    };

    let open_cells: Vec<PortCell> = cells
        .iter()
        .filter(|c| c.state.is_open())
        .cloned()
        .collect();
    // Group port cells per host for the grid.
    let mut by_host: BTreeMap<IpAddr, Vec<PortCell>> = BTreeMap::new();
    for c in cells {
        by_host.entry(c.ip).or_default().push(c);
    }
    let wave = waveform(&tele);
    // Finished-report visuals: topology map, state donut, latency bars.
    let srv_map = report.as_ref().and_then(charts::server_map);
    let (d_open, d_filt, d_cls) = report
        .as_ref()
        .map(charts::port_state_counts)
        .unwrap_or_default();
    let donut = charts::port_donut(d_open, d_filt, d_cls);
    let d_total = (d_open + d_filt + d_cls).max(1) as f64;
    let rtt = report.as_ref().and_then(charts::rtt_bars);

    Ok(view! {
        <section class="telemetry-island">
            <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
                <span class=(pill)>(meta.status.label())</span>
                <span class="prog" style="flex:1;gap:14px">
                    <span>(fmt_secs(elapsed))</span>
                    if meta.total > 0 {
                        <span>(meta.done) " / " (meta.total) " probes (" (format!("{:.0}%", frac * 100.0)) ")"</span>
                    }
                </span>
                if running {
                    <form method="post" action=(href!(stop_scan, scan_id: scan_id))>
                        <button class="btn-white danger" type="submit">(icons::ic(icons::STOP))"Stop scan"</button>
                    </form>
                } else {
                    <a class="btn-white" href=(href!(index))>(icons::ic(icons::PLUS))"New scan"</a>
                }
            </div>

            if meta.total > 0 {
                <div class="bar"><i style=(format!("--p:{frac:.4}"))></i></div>
            }

            if let Status::Failed(e) = &meta.status {
                <div class="banner" style="margin-top:14px;margin-bottom:0">(e.clone())</div>
            }

            if let Some((svg, rate, span)) = &wave {
                <div class="wave-wrap">
                    (Unescaped::new_unchecked(svg.clone()))
                    <div class="wave-meta">
                        <span>(format!("{span:.0}s telemetry window"))</span>
                        <span class="peak">(format!("{rate:.0} probes/s"))</span>
                        <span>(meta.open_count) " open"</span>
                    </div>
                </div>
            } else if running {
                <div class="wave-wrap" aria-hidden="true"><span class="sk sk-wave"></span></div>
            }

            if !by_host.is_empty() {
                <div class="port-bar">
                    <p class="sec-title" style="margin:0">"Live port map"</p>
                    <div class="legend">
                        <span><i class="l-open"></i>"open"</span>
                        <span><i class="l-filt"></i>"filtered"</span>
                        <span><i class="l-closed"></i>"closed"</span>
                    </div>
                    <div class="filter-pills" role="group" aria-label="Filter port cells">
                        <button type="button" class="fbtn active" data-f="all" onclick="ntokFilterPorts('all')">"All"</button>
                        <button type="button" class="fbtn" data-f="open" onclick="ntokFilterPorts('open')">"Open"</button>
                        <button type="button" class="fbtn" data-f="filtered" onclick="ntokFilterPorts('filtered')">"Filtered"</button>
                    </div>
                </div>
                for (ip, host_cells) in by_host {
                    let n_open = host_cells.iter().filter(|c| c.state.is_open()).count();
                    let n_cells = host_cells.len();
                    let ip_slug = ip.to_string().replace(['.', ':'], "-");
                    <div class="host-head">
                        (ip.to_string())
                        <span class="hc">" — " (n_cells) " probed · " (n_open) " open"</span>
                    </div>
                    if n_cells <= GRID_CHIP_LIMIT {
                        <div class="grid" data-portgrid="1">
                            for c in host_cells {
                                let title = match &c.service {
                                    Some(s) => format!("{}/{} {} — {}", c.port, c.proto.as_str(), c.state.as_str(), s),
                                    None => format!("{}/{} {}", c.port, c.proto.as_str(), c.state.as_str()),
                                };
                                if c.state.is_open() {
                                    <a class=(cell_class(c.state)) title=(title) href=(format!("#p-{ip_slug}-{}", c.port))>(c.port)</a>
                                } else {
                                    <span class=(cell_class(c.state)) title=(title)>(c.port)</span>
                                }
                            }
                        </div>
                    } else {
                        let n = n_cells as f64;
                        let p_open = host_cells.iter().filter(|c| c.state.is_open()).count() as f64 / n;
                        let p_filt = host_cells
                            .iter()
                            .filter(|c| {
                                matches!(c.state, PortState::Filtered | PortState::Unfiltered)
                            })
                            .count() as f64
                            / n;
                        <div class="stack">
                            <span class="s-open" style=(format!("width:{:.2}%", p_open * 100.0))></span>
                            <span class="s-filt" style=(format!("width:{:.2}%", p_filt * 100.0))></span>
                            <span class="s-closed" style="flex:1"></span>
                        </div>
                    }
                }
            } else if running {
                <div class="port-bar" aria-hidden="true">
                    <p class="sec-title" style="margin:0">"Live port map"</p>
                    <div class="legend">
                        <span><i class="l-open"></i>"open"</span>
                        <span><i class="l-filt"></i>"filtered"</span>
                        <span><i class="l-closed"></i>"closed"</span>
                    </div>
                </div>
                <div class="grid" aria-hidden="true">
                    for _ in 0..36 {
                        <span class="sk sk-cell"></span>
                    }
                </div>
            }
        </section>

        <div class="sec">
            <div class="stats">
                <div class="stat acc"><span class="si">(icons::ic(icons::GRID))</span><div class="v">(meta.open_count)</div><div class="k">"open ports"</div></div>
                <div class="stat"><span class="si">(icons::ic(icons::LOCK))</span><div class="v">(meta.closed)</div><div class="k">"closed"</div></div>
                <div class="stat warn"><span class="si">(icons::ic(icons::SHIELD))</span><div class="v">(meta.filtered)</div><div class="k">"filtered"</div></div>
                <div class="stat"><span class="si">(icons::ic(icons::ACTIVITY))</span><div class="v">(meta.total)</div><div class="k">"total probes"</div></div>
            </div>
        </div>

        if let Some(map) = &srv_map {
            <div class="sec">
                <div class="srv-map">
                    <div class="c-head">
                        (icons::ic(icons::RADAR))"Detected infrastructure"
                        <span class="m-hint">"engine → servers → open services"</span>
                    </div>
                    (Unescaped::new_unchecked(map.clone()))
                </div>
            </div>
        }

        if donut.is_some() || rtt.is_some() {
            <div class="sec">
                <p class="sec-title">(icons::ic(icons::ACTIVITY))"Scan analytics"</p>
                <div class="analytics">
                    if let Some(d) = &donut {
                        <div class="chart-obs">
                            <div class="c-head">(icons::ic(icons::TARGET))"Port state distribution"</div>
                            <div class="donut-wrap">
                                (Unescaped::new_unchecked(d.clone()))
                                <div class="donut-leg">
                                    <span><i class="i-open"></i><b>(d_open)</b>"open"<span class="pct">(format!("{:.0}%", d_open as f64 / d_total * 100.0))</span></span>
                                    <span><i class="i-filt"></i><b>(d_filt)</b>"filtered"<span class="pct">(format!("{:.0}%", d_filt as f64 / d_total * 100.0))</span></span>
                                    <span><i class="i-cls"></i><b>(d_cls)</b>"closed"<span class="pct">(format!("{:.0}%", d_cls as f64 / d_total * 100.0))</span></span>
                                </div>
                            </div>
                        </div>
                    }
                    if let Some(b) = &rtt {
                        <div class="chart-card">
                            <div class="c-head">(icons::ic(icons::CLOCK))"Service latency — slowest open ports first"</div>
                            (Unescaped::new_unchecked(b.clone()))
                        </div>
                    }
                </div>
            </div>
        }

        if meta.open_count > 0 && report.is_none() {
            <div class="sec">
                <p class="sec-title">(icons::ic(icons::GRID))"Open ports"</p>
                <div class="dt" id="dt-live">
                    <div class="dt-tools">
                        <div class="field-in dt-search-wrap">
                            (icons::ic(icons::SEARCH))
                            <input class="txt dt-search" type="search" placeholder="Filter port, service, host…" aria-label="Filter open ports">
                        </div>
                        <span class="filter-pills" role="group" aria-label="Protocol filter">
                            <button type="button" class="fbtn dtp active" data-proto="all">"All"</button>
                            <button type="button" class="fbtn dtp" data-proto="tcp">"TCP"</button>
                            <button type="button" class="fbtn dtp" data-proto="udp">"UDP"</button>
                        </span>
                        <span class="dt-count">(open_cells.len()) " ports"</span>
                    </div>
                    <div class="panel flush">
                        <table class="dt-table">
                            <thead>
                                <tr>
                                    <th class="num dt-sort" data-sort="port">"Port"<span class="car">"▲"</span></th>
                                    <th class="dt-sort" data-sort="proto">"Proto"<span class="car">"▲"</span></th>
                                    <th class="dt-sort" data-sort="state">"State"<span class="car">"▲"</span></th>
                                    <th class="dt-sort" data-sort="svc">"Service"<span class="car">"▲"</span></th>
                                    <th class="dt-sort" data-sort="host">"Host"<span class="car">"▲"</span></th>
                                </tr>
                            </thead>
                            <tbody>
                                for c in &open_cells {
                                    let ip_slug = c.ip.to_string().replace(['.', ':'], "-");
                                    let svc_txt = c.service.clone().unwrap_or_default();
                                    let search = format!(
                                        "{} {} {} {} {}",
                                        c.port, c.proto.as_str(), c.state.as_str(), svc_txt.to_lowercase(), c.ip
                                    );
                                    <tr id=(format!("p-{ip_slug}-{}", c.port)) data-p="1"
                                        data-port=(c.port)
                                        data-proto=(c.proto.as_str())
                                        data-state=(c.state.as_str())
                                        data-svc=(svc_txt.clone())
                                        data-host=(c.ip.to_string())
                                        data-search=(search)>
                                        <td class="num acc">(c.port)</td>
                                        <td>(c.proto.as_str())</td>
                                        <td><span class="pill open">(c.state.as_str())</span></td>
                                        <td>(svc_txt)</td>
                                        <td>(c.ip.to_string())</td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        } else if running && report.is_none() {
            <div class="sec" aria-hidden="true">
                <p class="sec-title">(icons::ic(icons::GRID))"Open ports"</p>
                <div class="panel flush">
                    <table class="dt-table">
                        <tbody>
                            for w in [58u8, 74, 42, 66] {
                                <tr><td colspan="5"><span class="sk sk-line" style=(format!("width:{w}%"))></span></td></tr>
                            }
                        </tbody>
                    </table>
                </div>
            </div>
        }

        if running && report.is_none() {
            <div class="sec" aria-hidden="true">
                <p class="sec-title">
                    (icons::ic(icons::SERVER))"Host detail"
                    <span class="sk-note">"pending — builds when the scan finishes"</span>
                </p>
                <div class="host-head"><span class="sk sk-block" style="width:240px;max-width:60%"></span></div>
                <div class="panel flush">
                    <table class="dt-table">
                        <tbody>
                            for w in [70u8, 48, 60] {
                                <tr><td colspan="6"><span class="sk sk-line" style=(format!("width:{w}%"))></span></td></tr>
                            }
                        </tbody>
                    </table>
                </div>
            </div>
        }

        if let Some(rep) = &report {
            <div class="sec">
                <p class="sec-title">(icons::ic(icons::SERVER))"Host detail"</p>
                for h in &rep.hosts {
                    let ip_slug = h.ip.to_string().replace(['.', ':'], "-");
                    let head = {
                        let mut s = h.ip.to_string();
                        if let Some(n) = &h.hostname {
                            s.push_str(&format!(" ({n})"));
                        }
                        s
                    };
                    let meta_str = {
                        let mut s = h.reason.clone();
                        if let Some(os) = &h.os_guess {
                            s.push_str(&format!(" · {os}"));
                        }
                        s
                    };
                    let host_pill = if h.state == ntok_core::HostState::Up { "pill done" } else { "pill" };
                    let host_word = if h.state == ntok_core::HostState::Up { "up" } else { "down" };
                    <div class="host-head" id=(format!("host-{ip_slug}"))>
                        (icons::ic(icons::SERVER))
                        (head)
                        <span class=(host_pill)>(host_word)</span>
                        <span class="hc">(meta_str)</span>
                    </div>
                    if h.ports.is_empty() {
                        <div class="empty" style="padding:16px;margin-top:8px">"No ports in this report."</div>
                    } else {
                        <div class="dt" id=(format!("dt-{ip_slug}"))>
                            <div class="dt-tools">
                                <div class="field-in dt-search-wrap">
                                    (icons::ic(icons::SEARCH))
                                    <input class="txt dt-search" type="search"
                                        placeholder="Filter port, service, banner, reason…"
                                        aria-label="Filter port results">
                                </div>
                                <span class="filter-pills" role="group" aria-label="State filter">
                                    <button type="button" class="fbtn dtf active" data-state="all">"All"</button>
                                    <button type="button" class="fbtn dtf" data-state="open">"Open"</button>
                                    <button type="button" class="fbtn dtf" data-state="filtered">"Filtered"</button>
                                    <button type="button" class="fbtn dtf" data-state="closed">"Closed"</button>
                                </span>
                                <span class="filter-pills" role="group" aria-label="Protocol filter">
                                    <button type="button" class="fbtn dtp active" data-proto="all">"All"</button>
                                    <button type="button" class="fbtn dtp" data-proto="tcp">"TCP"</button>
                                    <button type="button" class="fbtn dtp" data-proto="udp">"UDP"</button>
                                </span>
                                <span class="dt-count">(h.ports.len().min(DETAIL_ROWS)) " ports"</span>
                            </div>
                            <div class="panel flush">
                                <table class="dt-table">
                                    <thead>
                                        <tr>
                                            <th class="num dt-sort" data-sort="port">"Port"<span class="car">"▲"</span></th>
                                            <th class="dt-sort" data-sort="proto">"Proto"<span class="car">"▲"</span></th>
                                            <th class="dt-sort" data-sort="state">"State"<span class="car">"▲"</span></th>
                                            <th class="dt-sort" data-sort="svc">"Service / Banner"<span class="car">"▲"</span></th>
                                            <th class="dt-sort" data-sort="reason">"Reason"<span class="car">"▲"</span></th>
                                            <th class="num dt-sort" data-sort="rtt">"RTT ms"<span class="car">"▲"</span></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        for p in h.ports.iter().take(DETAIL_ROWS) {
                                            let svc = match (&p.service, &p.banner) {
                                                (Some(s), Some(b)) => format!("{s} — {b}"),
                                                (Some(s), None) => s.clone(),
                                                _ => String::new(),
                                            };
                                            let p_pill = match p.state {
                                                PortState::Open => "pill open",
                                                PortState::Filtered | PortState::OpenFiltered | PortState::Unfiltered => "pill warn",
                                                PortState::Closed => "pill",
                                            };
                                            let rtt_s = p.rtt_ms.map(|r| format!("{r:.1}")).unwrap_or_default();
                                            let search = format!(
                                                "{} {} {} {} {}",
                                                p.port, p.protocol.as_str(), p.state.as_str(),
                                                svc.to_lowercase(), p.reason.to_lowercase()
                                            );
                                            <tr id=(format!("p-{ip_slug}-{}", p.port)) data-p="1"
                                                data-port=(p.port)
                                                data-proto=(p.protocol.as_str())
                                                data-state=(p.state.as_str())
                                                data-svc=(svc.clone())
                                                data-reason=(p.reason.clone())
                                                data-rtt=(rtt_s)
                                                data-search=(search)>
                                                <td class="num acc">(p.port)</td>
                                                <td>(p.protocol.as_str())</td>
                                                <td><span class=(p_pill)>(p.state.as_str())</span></td>
                                                <td>(svc)</td>
                                                <td style="color:var(--muted)">(p.reason.clone())</td>
                                                <td class="num" style="color:var(--muted)">
                                                    (p.rtt_ms.map(|r| format!("{r:.1}")).unwrap_or_else(|| "—".into()))
                                                </td>
                                            </tr>
                                        }
                                        if h.ports.len() > DETAIL_ROWS {
                                            <tr class="dt-more">
                                                <td colspan="6" style="color:var(--muted)">
                                                    "… and " (h.ports.len() - DETAIL_ROWS)
                                                    " more — export JSON or CSV for the full set"
                                                </td>
                                            </tr>
                                        }
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    }
                    if !h.findings.is_empty() {
                        <div class="panel flush" style="margin-top:10px">
                            <table>
                                <thead>
                                    <tr>
                                        <th>"Tool"</th><th>"Severity"</th>
                                        <th class="num">"Port"</th><th>"Finding"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    for f in h.findings.iter().take(20) {
                                        let sev_cls = match f.severity.as_str() {
                                            "high" | "critical" => "pill err",
                                            "medium" => "pill warn",
                                            _ => "pill",
                                        };
                                        <tr>
                                            <td>(f.tool.clone())</td>
                                            <td><span class=(sev_cls)>(f.severity.clone())</span></td>
                                            <td class="num">
                                                (f.port.map(|p| p.to_string()).unwrap_or_else(|| "—".into()))
                                            </td>
                                            <td style="color:var(--muted)">(f.detail.clone())</td>
                                        </tr>
                                    }
                                    if h.findings.len() > 20 {
                                        <tr>
                                            <td colspan="4" style="color:var(--muted)">
                                                "… and " (h.findings.len() - 20) " more — see the JSON report"
                                            </td>
                                        </tr>
                                    }
                                </tbody>
                            </table>
                        </div>
                    }
                }
            </div>
        }

        if let Some(rep) = &report
            && rep.hosts.iter().any(|h| !h.web_profiles.is_empty())
        {
            <div class="sec">
                <p class="sec-title">(icons::ic(icons::GLOBE))"Website intelligence"</p>
                for h in &rep.hosts {
                    for w in &h.web_profiles {
                        let kinds = w.assets.iter().fold(
                            BTreeMap::<&str, usize>::new(),
                            |mut m, a| {
                                *m.entry(a.kind.as_str()).or_default() += 1;
                                m
                            },
                        );
                        let score = w.security.score;
                        let pip_cls = if score < 3 { "sec-pips low" } else { "sec-pips" };
                        let has_sec = w.tls.is_some() || w.server.is_some()
                            || w.powered_by.is_some() || score > 0;
                        let has_infra = !w.company.names.is_empty()
                            || w.company.registrar.is_some()
                            || w.company.ip_org.is_some()
                            || w.company.asn.is_some()
                            || !w.company.dns.is_empty()
                            || !w.company.saas.is_empty()
                            || w.company.security_txt
                            || !w.external_domains.is_empty()
                            || !w.api_hints.is_empty()
                            || w.robots.as_ref().is_some_and(|r| r.present)
                            || w.favicon_mmh3.is_some();
                        <div class="panel" style="margin-top:12px">
                            <div class="webprof">
                                <div class="web-head">
                                    (icons::ic(icons::GLOBE))
                                    <span class="weburl">(w.url.clone())</span>
                                    if w.final_url != w.url {
                                        <span style="color:var(--muted);font:400 11.5px var(--mono)">"→ " (w.final_url.clone())</span>
                                    }
                                    <span class=(if w.status >= 400 || w.status == 0 { "pill err" } else { "pill done" })>
                                        (if w.status == 0 { "no response".to_string() } else { w.status.to_string() })
                                    </span>
                                    <span style="color:var(--faint);font:400 11px var(--mono)">
                                        (w.http_version.clone()) " · " (w.ttfb_ms) "ms TTFB"
                                    </span>
                                </div>
                                if let Some(e) = &w.error {
                                    <div class="banner" style="margin:12px 0 0;padding:9px 14px;font-size:12px">
                                        (icons::ic(icons::ALERT))" " (e.clone())
                                    </div>
                                }
                                if !w.technologies.is_empty() {
                                    <div class="chips">
                                        for t in &w.technologies {
                                            let conf_cls = if t.confidence >= 80 {
                                                "conf c-hi"
                                            } else if t.confidence >= 50 {
                                                "conf c-md"
                                            } else {
                                                "conf c-lo"
                                            };
                                            <span class="chip" title=(format!("{} · {}%{}", t.evidence.join(", "), t.confidence, if t.implied { " · implied" } else { "" }))>
                                                (icons::ic(icons::tech(&t.category)))
                                                <b>(t.name.clone())</b>
                                                (t.version.clone().unwrap_or_default())
                                                <span class="cat">(t.category.clone())</span>
                                                <i class=(conf_cls)></i>
                                            </span>
                                        }
                                    </div>
                                }
                                <div class="intel-grid">
                                    if has_sec {
                                        <div class="icard">
                                            <div class="icard-head">
                                                (icons::ic(icons::SHIELD))"Security & TLS"
                                                <span class="ib">(format!("{score}/6 hardening"))</span>
                                            </div>
                                            <div class="irow">
                                                <span class="ik">(icons::ic(icons::SHIELD))"headers"</span>
                                                <span class="iv">
                                                    <div class="sec-meter">
                                                        <span class=(pip_cls) aria-label=(format!("Security score {score} of 6"))>
                                                            for idx in 0..6u8 {
                                                                <i class=(if idx < score { "on" } else { "" })></i>
                                                            }
                                                        </span>
                                                        <span class="sec-badges">
                                                            <span class=(if w.security.hsts.is_some() { "sbadge on" } else { "sbadge" }) title="Strict-Transport-Security">"HSTS"</span>
                                                            <span class=(if w.security.csp.is_some() { "sbadge on" } else { "sbadge" }) title="Content-Security-Policy">"CSP"</span>
                                                            <span class=(if w.security.x_frame_options.is_some() { "sbadge on" } else { "sbadge" }) title="X-Frame-Options">"XFO"</span>
                                                            <span class=(if w.security.x_content_type_options.is_some() { "sbadge on" } else { "sbadge" }) title="X-Content-Type-Options">"XCTO"</span>
                                                            <span class=(if w.security.referrer_policy.is_some() { "sbadge on" } else { "sbadge" }) title="Referrer-Policy">"Referrer"</span>
                                                        </span>
                                                    </div>
                                                </span>
                                            </div>
                                            if let Some(s) = &w.server {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::SERVER))"server"</span>
                                                    <span class="iv">(s.clone())</span>
                                                </div>
                                            }
                                            if let Some(p) = &w.powered_by {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::ZAP))"powered by"</span>
                                                    <span class="iv">(p.clone())</span>
                                                </div>
                                            }
                                            if let Some(t) = &w.tls {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::LOCK))"tls"</span>
                                                    <span class="iv">
                                                        (t.protocol.clone())
                                                        (t.subject_cn.clone().map(|c| format!(" · {c}")).unwrap_or_default())
                                                        (t.org.clone().map(|o| format!(" · {o}")).unwrap_or_default())
                                                    </span>
                                                </div>
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::BUILDING))"issuer"</span>
                                                    <span class="iv">(t.issuer_org.clone().or_else(|| t.issuer_cn.clone()).unwrap_or_else(|| "—".into()))</span>
                                                </div>
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::CLOCK))"certificate"</span>
                                                    <span class="iv" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                                                        <span>(t.not_before.clone()) " → " (t.not_after.clone())</span>
                                                        if t.expired {
                                                            <span class="pill err">"EXPIRED"</span>
                                                        } else {
                                                            <span class="pill done">"valid"</span>
                                                        }
                                                        if t.self_signed {
                                                            <span class="pill warn">"self-signed"</span>
                                                        }
                                                    </span>
                                                </div>
                                                if !t.san.is_empty() {
                                                    <div class="irow">
                                                        <span class="ik">(icons::ic(icons::LINK))"san"</span>
                                                        <span class="iv">(t.san.join(", "))</span>
                                                    </div>
                                                }
                                            }
                                        </div>
                                    }
                                    if has_infra {
                                        <div class="icard">
                                            <div class="icard-head">
                                                (icons::ic(icons::GLOBE))"Infrastructure & attribution"
                                            </div>
                                            if !w.company.names.is_empty() {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::BUILDING))"company"</span>
                                                    <span class="iv">(w.company.names.join(" / "))</span>
                                                </div>
                                            }
                                            if let Some(r) = &w.company.registrar {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::FILE))"registrar"</span>
                                                    <span class="iv">(r.clone())</span>
                                                </div>
                                            }
                                            if let Some(o) = &w.company.ip_org {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::SERVER))"ip owner"</span>
                                                    <span class="iv">(o.clone())</span>
                                                </div>
                                            }
                                            if let Some(a) = &w.company.asn {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::DNS))"asn"</span>
                                                    <span class="iv">(a.clone())</span>
                                                </div>
                                            }
                                            for r in w.company.dns.iter().take(10) {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::dns(&r.kind)))"dns "(r.kind.clone())</span>
                                                    <span class="iv">(r.value.clone())</span>
                                                </div>
                                            }
                                            if !w.company.saas.is_empty() {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::CLOUD))"saas"</span>
                                                    <span class="iv"><span class="chips">
                                                        for s in &w.company.saas {
                                                            <span class="chip">(icons::ic(icons::CLOUD))<b>(s.clone())</b></span>
                                                        }
                                                    </span></span>
                                                </div>
                                            }
                                            if w.company.security_txt {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::CHECK))"security.txt"</span>
                                                    <span class="iv">"published"</span>
                                                </div>
                                            }
                                            if !w.external_domains.is_empty() {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::EXT))"external"</span>
                                                    <span class="iv"><span class="chips">
                                                        for d in &w.external_domains {
                                                            <span class="chip">(icons::ic(icons::EXT))<b>(d.clone())</b></span>
                                                        }
                                                    </span></span>
                                                </div>
                                            }
                                            if !w.api_hints.is_empty() {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::ZAP))"api hints"</span>
                                                    <span class="iv"><span class="chips">
                                                        for a in &w.api_hints {
                                                            <span class="chip">(icons::ic(icons::CODE))<b>(a.clone())</b></span>
                                                        }
                                                    </span></span>
                                                </div>
                                            }
                                            if let Some(r) = &w.robots
                                                && r.present
                                            {
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::ROBOT))"robots"</span>
                                                    <span class="iv">
                                                        (format!("{} sitemap(s), {} disallows",
                                                            r.sitemaps.len(), r.disallows.len()))
                                                        if !r.disallows.is_empty() {
                                                            " — " (r.disallows.iter().take(6).cloned().collect::<Vec<_>>().join(", "))
                                                        }
                                                    </span>
                                                </div>
                                            }
                                            if let Some(h) = w.favicon_mmh3 {
                                                let fav_copy = format!(
                                                    "ntokCopy(this, {})",
                                                    serde_json::to_string(&format!("http.favicon.hash:{h}")).unwrap_or_else(|_| "\"\"".into())
                                                );
                                                <div class="irow">
                                                    <span class="ik">(icons::ic(icons::FINGERPRINT))"favicon"</span>
                                                    <span class="iv" style="display:flex;align-items:center;gap:8px">
                                                        <span class="cmd-inline">(format!("http.favicon.hash:{h}"))</span>
                                                        <button type="button" class="copy-btn" onclick=(fav_copy)>"copy"</button>
                                                    </span>
                                                </div>
                                            }
                                        </div>
                                    }
                                    if let Some(a) = &w.ai_note {
                                        <div class="icard wide">
                                            <div class="icard-head">
                                                (icons::ic(icons::SPARKLES))"AI advisor note"
                                            </div>
                                            <div class="irow">
                                                <span class="ik">(icons::ic(icons::SPARKLES))"analysis"</span>
                                                <span class="iv">(a.clone())</span>
                                            </div>
                                        </div>
                                    }
                                </div>
                                if !w.assets.is_empty() {
                                    <details class="adv" style="margin-top:14px">
                                        <summary>
                                            "Asset inventory"
                                            <span class="adv-hint">
                                                (format!("{} references · {} external domains",
                                                    w.assets.len(), w.external_domains.len()))
                                            </span>
                                        </summary>
                                        <div class="adv-body one">
                                            <div class="chips">
                                                for (k, n) in &kinds {
                                                    <span class="chip"><b>(*k)</b>(n)</span>
                                                }
                                            </div>
                                            <table>
                                                <thead><tr><th>"Kind"</th><th>"Asset"</th><th>"Host"</th></tr></thead>
                                                <tbody>
                                                    for a in w.assets.iter().take(60) {
                                                        <tr>
                                                            <td>(icons::ic(icons::asset(&a.kind)))" "(a.kind.clone())</td>
                                                            <td style="overflow-wrap:anywhere">(a.url.clone())</td>
                                                            <td style="color:var(--muted)">(a.host.clone().unwrap_or_default())</td>
                                                        </tr>
                                                    }
                                                    if w.assets.len() > 60 {
                                                        <tr><td colspan="3" style="color:var(--muted)">
                                                            "… and " (w.assets.len() - 60) " more — see the JSON report"
                                                        </td></tr>
                                                    }
                                                </tbody>
                                            </table>
                                        </div>
                                    </details>
                                }
                            </div>
                        </div>
                    }
                }
            </div>
        }

        if !log.is_empty() {
            <div class="sec">
                <p class="sec-title">(icons::ic(icons::TERMINAL))"Live log"</p>
                <div class="log">
                    for line in log.iter().rev() {
                        <div>
                            <span class="t">"+" (format!("{:6.1}s", line.at)) " "</span>
                            if line.hot {
                                <span class="hl">(line.text.clone())</span>
                            } else {
                                <span>(line.text.clone())</span>
                            }
                        </div>
                    }
                </div>
            </div>
        } else if running {
            <div class="sec" aria-hidden="true">
                <p class="sec-title">(icons::ic(icons::TERMINAL))"Live log"</p>
                <div class="log">
                    for w in [62u8, 84, 47, 71] {
                        <div><span class="sk sk-line" style=(format!("width:{w}%"))></span></div>
                    }
                </div>
            </div>
        }

        <div class="toolbar">
            <div class="toolbar-group">
                <span class="toolbar-label">(icons::ic(icons::DOWNLOAD))"Export"</span>
                if report.is_some() {
                    for (name, fmt, icon) in [
                        ("HTML", "html", icons::REPORT),
                        ("JSON", "json", icons::BRACES),
                        ("XML", "xml", icons::CODE),
                        ("Text", "txt", icons::FILE),
                        ("Greppable", "gnmap", icons::TERMINAL),
                        ("CSV", "csv", icons::TABLE),
                    ] {
                        <a class="btn xs ghost" href=(format!("{report_url}?fmt={fmt}")) title=(format!("Download {name} report"))>(icons::ic(icon))(name)</a>
                    }
                } else {
                    <span style="color:var(--muted);font-size:12px">"reports available when scan finishes"</span>
                }
                <a class="btn xs ghost" href=(log_url) title="Download full scan log">(icons::ic(icons::LIST))"Full log"</a>
            </div>
            if !other_ids.is_empty() {
                <div class="toolbar-group">
                    <span class="toolbar-label">(icons::ic(icons::BRANCH))"Compare"</span>
                    <select class="compare-sel" onchange="if(this.value)window.location.href=this.value">
                        <option value="">"Diff against scan…"</option>
                        for other in &other_ids {
                            <option value=(href!(compare_page, scan_id: scan_id, other_id: *other))>
                                "Compare with #" (other)
                            </option>
                        }
                    </select>
                </div>
            }
        </div>
    })
}

// ---------- routes ----------

#[derive(Deserialize)]
struct LoginForm {
    name: String,
    password: String,
    otp: Option<String>,
}

#[derive(Deserialize)]
struct LoginQuery {
    err: Option<String>,
}

/// Cell state in the pre-login compare matrix.
enum Vs {
    Y,
    N,
    T(&'static str),
}

struct VsRow(&'static str, [Vs; 5]);

/// Shown below the fold on `/login` — cells are (ntok, nmap, OpenVAS/GVM,
/// Nessus, hosted VM). Claims stay inside brand-strategies.md ground truth:
/// ntok is a local-first recon engine, not a VM suite.
const VS_ROWS: &[VsRow] = &[
    VsRow(
        "Price",
        [
            Vs::T("Free · MIT/Apache"),
            Vs::T("Free"),
            Vs::T("Free"),
            Vs::T("Free tier"),
            Vs::N,
        ],
    ),
    VsRow(
        "Runs fully local & offline",
        [Vs::Y, Vs::Y, Vs::Y, Vs::T("agent"), Vs::N],
    ),
    VsRow(
        "No account · zero telemetry",
        [Vs::Y, Vs::Y, Vs::Y, Vs::N, Vs::N],
    ),
    VsRow(
        "Live web UI & port map",
        [Vs::Y, Vs::N, Vs::Y, Vs::Y, Vs::Y],
    ),
    VsRow(
        "Web intel — TLS, headers, tech fingerprint",
        [
            Vs::Y,
            Vs::T("via NSE"),
            Vs::T("partial"),
            Vs::T("partial"),
            Vs::T("partial"),
        ],
    ),
    VsRow(
        "Scan-to-scan drift diff",
        [
            Vs::Y,
            Vs::T("via ndiff"),
            Vs::N,
            Vs::T("reports"),
            Vs::T("reports"),
        ],
    ),
    VsRow(
        "CVE / vuln correlation",
        [Vs::T("via nuclei"), Vs::T("via NSE"), Vs::Y, Vs::Y, Vs::Y],
    ),
    VsRow(
        "nmap XML import & export",
        [Vs::Y, Vs::T("native"), Vs::T("import"), Vs::N, Vs::N],
    ),
    VsRow(
        "Orchestrates nmap · nuclei · masscan",
        [Vs::Y, Vs::N, Vs::N, Vs::N, Vs::N],
    ),
    VsRow(
        "Single-binary install",
        [Vs::Y, Vs::Y, Vs::T("stack"), Vs::T("agent"), Vs::T("agent")],
    ),
    VsRow(
        "First-class Windows support",
        [Vs::Y, Vs::Y, Vs::T("Linux"), Vs::Y, Vs::Y],
    ),
];

#[page("/login")]
async fn login_page(cx: &Cx) -> Result<impl View> {
    app(cx).auth.as_ref().ok_or_not_found()?;
    let err = parse_query_params::<LoginQuery>(cx)
        .ok()
        .and_then(|q| q.err);
    let can_register = registration_open(cx);
    let no_users = lock(&app(cx).auth_db)
        .as_ref()
        .and_then(|db| db.user_count().ok())
        .is_none_or(|n| n == 0);
    Ok(view! {
        <section class="auth-split">
            <div class="auth-stage" aria-hidden="true">
                <canvas id="auth-canvas" class="auth-canvas"></canvas>
                <div class="auth-stage-top">
                    <div class="stage-badge">
                        <span class="sm-mark">(mark())</span>
                        <span class="sm-name">(ntok_core::brand::NAME)</span>
                    </div>
                    <span class="stage-live"><i></i>"3D Topology · Live"</span>
                </div>
                <div class="auth-stage-bottom">
                    <h2>(ntok_core::brand::SUBTITLE)</h2>
                    <p>(ntok_core::brand::EXPANSION) " — high-speed async port discovery, TLS inspection, and website intelligence running strictly on your machine."</p>
                    <div class="stage-pills">
                        <span class="stage-pill">"Local-first"</span>
                        <span class="stage-pill">"Argon2id Auth"</span>
                        <span class="stage-pill">"Zero Telemetry"</span>
                    </div>
                </div>
            </div>

            <div class="auth-card">
                if can_register {
                    <nav class="auth-tabs" aria-label="Authentication mode">
                        <a class="active" href=(href!(login_page))>"Sign in"</a>
                        <a href=(href!(register_page))>"Register"</a>
                    </nav>
                }
                <span class="eyebrow">(ntok_core::brand::NAME)</span>
                <h1>"Welcome back"</h1>
                <p class="lede">"Sign in to your local recon console and search index."</p>

                if let Some(e) = &err {
                    <div class="banner">
                        (if e == "lock" {
                            "Too many attempts — account or address locked briefly."
                        } else if e == "totp" {
                            "That authenticator code didn't match — try the current one."
                        } else {
                            "Wrong username or password."
                        })
                    </div>
                }
                if no_users {
                    <div class="banner ok">
                        "No accounts yet — " <a href=(href!(register_page))>"create the first account"</a> "."
                    </div>
                }

                <form class="auth-form" method="post" action=(href!(login_submit))>
                    <div>
                        <label class="lbl" for="name">"Username or email"</label>
                        <div class="field-in">
                            (icons::ic(icons::USER))
                            <input class="txt" id="name" name="name" autocomplete="username"
                                placeholder="operator or you@example.com" autofocus="autofocus" required="required">
                        </div>
                    </div>
                    <div>
                        <label class="lbl" for="password">"Password"</label>
                        <div class="pw-wrap">
                            <div class="field-in">
                                (icons::ic(icons::LOCK))
                                <input class="txt" type="password" id="password" name="password"
                                    autocomplete="current-password" placeholder="••••••••" required="required">
                            </div>
                            <button type="button" class="pw-btn" data-pw-toggle="password" aria-pressed="false">"show"</button>
                        </div>
                    </div>
                    <div>
                        <label class="lbl" for="otp">"Authenticator code"</label>
                        <div class="field-in">
                            (icons::ic(icons::SHIELD))
                            <input class="txt" id="otp" name="otp" inputmode="numeric"
                                autocomplete="one-time-code" maxlength="6" placeholder="optional — only if 2FA is on">
                        </div>
                    </div>
                    <button class="cta-pill" type="submit" style="margin-top:6px">
                        <span class="cta-pill-copy">
                            <span class="cta-pill-title">"Sign in"</span>
                            <span class="cta-pill-sub">"Open NTOK SCAN workspace"</span>
                        </span>
                        <span class="cta-pill-arrow" aria-hidden="true">"→"</span>
                    </button>
                </form>

                <div class="auth-foot">
                    "Accounts & sessions stay local in reports/ntok.db — nothing leaves your host."
                </div>
            </div>
        </section>

        <section class="vs">
            <span class="eyebrow">"Compare"</span>
            <h2>"Why operators pick " (ntok_core::brand::NAME)</h2>
            <p class="vs-lede">
                "The recon layer the heavy scanners don't give you — free, local-first, and fluent in nmap's own language. It orchestrates the tools you already trust instead of asking you to replace them."
            </p>
            <div class="vs-wrap">
                <table class="vs-table">
                    <thead>
                        <tr>
                            <th>"Capability"</th>
                            <th class="col-nt">(ntok_core::brand::NAME)<span class="vs-tag">"our pick"</span></th>
                            <th>"nmap"</th>
                            <th>"OpenVAS / GVM"</th>
                            <th>"Nessus"</th>
                            <th>"Hosted VM"</th>
                        </tr>
                    </thead>
                    <tbody>
                        for VsRow(feature, cells) in VS_ROWS {
                            <tr>
                                <td class="vs-f">(feature)</td>
                                for (i, v) in cells.iter().enumerate() {
                                    <td class=(if i == 0 { "col-nt" } else { "" })>
                                        if matches!(v, Vs::Y) {
                                            <span class="vs-y">(icons::ic(icons::CHECK))</span>
                                        } else if let Vs::T(t) = v {
                                            <span class="vs-t">(t)</span>
                                        } else {
                                            <span class="vs-n">"—"</span>
                                        }
                                    </td>
                                }
                            </tr>
                        }
                    </tbody>
                </table>
            </div>
            <div class="vs-foot">
                <p>
                    "Honest scope: CVE findings come from nuclei templates — "
                    (ntok_core::brand::NAME)
                    " is recon, web intel, and drift tracking that complements every tool above, not a vulnerability-management suite."
                </p>
                if can_register {
                    <a class="btn sm" href=(href!(register_page))>"Create a local account" (icons::ic(icons::ARROW))</a>
                }
            </div>
        </section>

        <script>(Unescaped::new_unchecked(AUTH3D_JS))</script>
    })
}

#[page("/register")]
async fn register_page(cx: &Cx) -> Result<impl View> {
    app(cx).auth.as_ref().ok_or_not_found()?;
    if !registration_open(cx) {
        return Err(see_other("/login").into());
    }
    let err = parse_query_params::<LoginQuery>(cx)
        .ok()
        .and_then(|q| q.err);
    Ok(view! {
        <section class="auth-split">
            <div class="auth-stage" aria-hidden="true">
                <canvas id="auth-canvas" class="auth-canvas"></canvas>
                <div class="auth-stage-top">
                    <div class="stage-badge">
                        <span class="sm-mark">(mark())</span>
                        <span class="sm-name">(ntok_core::brand::NAME)</span>
                    </div>
                    <span class="stage-live"><i></i>"Local Engine Ready"</span>
                </div>
                <div class="auth-stage-bottom">
                    <h2>"Your local recon cockpit."</h2>
                    <p>(ntok_core::brand::EXPANSION) " — map exposed ports, inspect web stacks, and track infrastructure drift with full privacy."</p>
                    <div class="stage-pills">
                        <span class="stage-pill">"SQLite FTS5 Index"</span>
                        <span class="stage-pill">"API Tokens"</span>
                        <span class="stage-pill">"Offline Capable"</span>
                    </div>
                </div>
            </div>

            <div class="auth-card">
                <nav class="auth-tabs" aria-label="Authentication mode">
                    <a href=(href!(login_page))>"Sign in"</a>
                    <a class="active" href=(href!(register_page))>"Register"</a>
                </nav>
                <span class="eyebrow">(ntok_core::brand::NAME)</span>
                <h1>"Create account"</h1>
                <p class="lede">"Bootstrap your local operator account in seconds."</p>

                if err.as_deref() == Some("taken") {
                    <div class="banner">"That username or email is already taken."</div>
                }
                if err.as_deref() == Some("1") {
                    <div class="banner">
                        "Username and a valid email are required; passwords must match and be at least 8 characters."
                    </div>
                }
                if err.as_deref() == Some("consent") {
                    <div class="banner">
                        "Please accept the Terms of Service, Privacy Policy and Acceptable Use Policy to continue."
                    </div>
                }

                <form class="auth-form" method="post" action=(href!(register_submit))>
                    <div>
                        <label class="lbl" for="reg-fullname">"Full name"</label>
                        <div class="field-in">
                            (icons::ic(icons::USER))
                            <input class="txt" id="reg-fullname" name="full_name" autocomplete="name"
                                placeholder="optional — shown in your account">
                        </div>
                    </div>
                    <div>
                        <label class="lbl" for="reg-email">"Email"</label>
                        <div class="field-in">
                            (icons::ic(icons::GLOBE))
                            <input class="txt" id="reg-email" name="email" type="email"
                                autocomplete="email" placeholder="you@example.com" required="required">
                        </div>
                    </div>
                    <div>
                        <label class="lbl" for="name">"Username"</label>
                        <div class="field-in">
                            (icons::ic(icons::USER))
                            <input class="txt" id="name" name="name" autocomplete="username"
                                placeholder="operator" required="required">
                        </div>
                    </div>
                    <div>
                        <label class="lbl" for="reg-password">"Password"</label>
                        <div class="pw-wrap">
                            <div class="field-in">
                                (icons::ic(icons::LOCK))
                                <input class="txt" type="password" id="reg-password" name="password"
                                    autocomplete="new-password" placeholder="minimum 8 characters" required="required">
                            </div>
                            <button type="button" class="pw-btn" data-pw-toggle="reg-password" aria-pressed="false">"show"</button>
                        </div>
                    </div>
                    <div>
                        <label class="lbl" for="reg-confirm">"Confirm password"</label>
                        <div class="pw-wrap">
                            <div class="field-in">
                                (icons::ic(icons::CHECK))
                                <input class="txt" type="password" id="reg-confirm" name="confirm"
                                    autocomplete="new-password" placeholder="repeat password" required="required">
                            </div>
                            <button type="button" class="pw-btn" data-pw-toggle="reg-confirm" aria-pressed="false">"show"</button>
                        </div>
                    </div>
                    <div class="pw-hints">
                        <span class="pw-hint" id="pw-len">"8+ characters"</span>
                        <span class="pw-hint" id="pw-match">"passwords match"</span>
                    </div>
                    <label class="consent" for="accept">
                        <input type="checkbox" id="accept" name="accept" required="required">
                        <span>
                            "I accept the "
                            <a href=(href!(docs::terms_page))>"Terms of Service"</a> ", "
                            <a href=(href!(docs::privacy_page))>"Privacy Policy"</a> " and "
                            <a href=(href!(docs::acceptable_use_page))>"Acceptable Use Policy"</a> "."
                        </span>
                    </label>
                    <button class="cta-pill" type="submit" style="margin-top:4px">
                        <span class="cta-pill-copy">
                            <span class="cta-pill-title">"Create account"</span>
                            <span class="cta-pill-sub">"Hashed locally with Argon2id"</span>
                        </span>
                        <span class="cta-pill-arrow" aria-hidden="true">"→"</span>
                    </button>
                </form>

                <div class="auth-foot">
                    "Stored exclusively in reports/ntok.db — no cloud account, no external sync."
                </div>
            </div>
        </section>
        <script>(Unescaped::new_unchecked(AUTH3D_JS))</script>
    })
}

#[route(POST "/login")]
async fn login_submit(cx: &Cx, Form(form): Form<LoginForm>) -> Result<SeeOther> {
    if login_locked(cx) {
        return Ok(see_other("/login?err=lock"));
    }
    let guard = lock(&app(cx).auth_db);
    let Some(db) = guard.as_ref() else {
        return Ok(see_other("/login?err=1"));
    };
    let ip = client_ip(cx).map(|i| i.to_string()).unwrap_or_default();
    let audit = |name: &str, event: &str| {
        let _ = db.log_auth(name, &ip, event);
    };
    // Per-account lock — survives the attacker rotating IPs.
    if db.login_lock_remaining(&form.name).unwrap_or(0) > 0 {
        audit(&form.name, "login_locked");
        return Ok(see_other("/login?err=lock"));
    }
    let Ok(user_opt) = db.verify_user(&form.name, &form.password) else {
        login_failed(cx);
        return Ok(see_other("/login?err=1"));
    };
    let Some(user) = user_opt else {
        login_failed(cx);
        audit(&form.name, "login_fail");
        let secs = db
            .record_login_fail(&form.name, LOGIN_MAX_FAILS, LOGIN_LOCKOUT.as_secs())
            .unwrap_or(0);
        return Ok(see_other(if secs > 0 {
            "/login?err=lock"
        } else {
            "/login?err=1"
        }));
    };
    // Second factor when the account enrolled one.
    if let Ok(Some(secret)) = db.totp_secret(user.id)
        && !form
            .otp
            .as_deref()
            .is_some_and(|c| ntok_store::totp_check(&secret, c))
    {
        login_failed(cx);
        audit(&user.name, "totp_fail");
        return Ok(see_other("/login?err=totp"));
    }
    let Ok(token) = db.create_session(user.id, SESSION_TTL) else {
        return Ok(see_other("/login?err=1"));
    };
    let _ = db.clear_login_fails(&form.name);
    audit(&user.name, "login_ok");
    drop(guard);
    login_succeeded(cx);
    set_session_cookie(cx, token);
    Ok(see_other("/"))
}

#[derive(Deserialize)]
struct RegisterForm {
    name: String,
    email: String,
    full_name: String,
    password: String,
    confirm: String,
    accept: Option<String>,
}

#[route(POST "/register")]
async fn register_submit(cx: &Cx, Form(form): Form<RegisterForm>) -> Result<SeeOther> {
    if app(cx).auth.is_none() || !registration_open(cx) || login_locked(cx) {
        return Ok(see_other("/login"));
    }
    // Explicit consent — the checkbox makes the audit-logged "register"
    // event a clickwrap acceptance record, not just browsewrap text.
    if form.accept.is_none() {
        return Ok(see_other("/register?err=consent"));
    }
    if form.name.trim().is_empty()
        || !form.email.trim().contains('@')
        || form.password.len() < 8
        || form.password != form.confirm
    {
        return Ok(see_other("/register?err=1"));
    }
    let guard = lock(&app(cx).auth_db);
    let Some(db) = guard.as_ref() else {
        return Ok(see_other("/register?err=1"));
    };
    let Ok(user) = db.create_user(&form.name, &form.email, &form.full_name, &form.password) else {
        return Ok(see_other("/register?err=taken"));
    };
    let Ok(token) = db.create_session(user.id, SESSION_TTL) else {
        return Ok(see_other("/register?err=1"));
    };
    let ip = client_ip(cx).map(|i| i.to_string()).unwrap_or_default();
    let _ = db.log_auth(&user.name, &ip, "register");
    drop(guard);
    set_session_cookie(cx, token);
    Ok(see_other("/"))
}

#[route(POST "/logout")]
async fn logout(cx: &Cx) -> Result<SeeOther> {
    if let Some(c) = cookies(cx).get(AUTH_COOKIE)
        && let Some(db) = lock(&app(cx).auth_db).as_ref()
    {
        if let Ok(Some(u)) = db.user_for_session(c.value()) {
            let ip = client_ip(cx).map(|i| i.to_string()).unwrap_or_default();
            let _ = db.log_auth(&u.name, &ip, "logout");
        }
        let _ = db.drop_session(c.value());
    }
    let mut c = Cookie::from(AUTH_COOKIE);
    c.set_path("/");
    cookies(cx).remove(c);
    Ok(see_other("/"))
}

// ---------- JSON API — extension, desktop, CI ----------

#[derive(Deserialize)]
struct ApiLogin {
    name: String,
    password: String,
    otp: Option<String>,
}

#[derive(Serialize)]
struct ApiLoginOut {
    token: String,
    name: String,
}

/// `POST /api/auth/login {"name","password"}` → a reusable API token.
/// Open route — it *is* the auth check.
#[route(POST "/api/auth/login")]
async fn api_login(cx: &Cx, Json(form): Json<ApiLogin>) -> Result<Json<ApiLoginOut>> {
    if login_locked(cx) {
        return Err(unauthorized().into());
    }
    let db = lock(&app(cx).auth_db);
    let Some(db) = db.as_ref() else {
        return Err(unauthorized().into());
    };
    if db.login_lock_remaining(&form.name).unwrap_or(0) > 0 {
        return Err(unauthorized().into());
    }
    let Ok(user_opt) = db.verify_user(&form.name, &form.password) else {
        login_failed(cx);
        return Err(unauthorized().into());
    };
    let Some(user) = user_opt else {
        login_failed(cx);
        let _ = db.record_login_fail(&form.name, LOGIN_MAX_FAILS, LOGIN_LOCKOUT.as_secs());
        return Err(unauthorized().into());
    };
    if let Ok(Some(secret)) = db.totp_secret(user.id)
        && !form
            .otp
            .as_deref()
            .is_some_and(|c| ntok_store::totp_check(&secret, c))
    {
        return Err(unauthorized().into());
    }
    login_succeeded(cx);
    let _ = db.clear_login_fails(&form.name);
    let Ok(token) = db.create_api_token(user.id, "api-client") else {
        return Err(unauthorized().into());
    };
    Ok(Json(ApiLoginOut {
        token,
        name: user.name,
    }))
}

#[derive(Serialize)]
struct ApiMe {
    name: String,
    email: Option<String>,
    full_name: Option<String>,
}

/// `GET /api/me` — cheap token probe for clients before they do real work.
#[route(GET "/api/me")]
async fn api_me(cx: &Cx) -> Result<Json<ApiMe>> {
    if app(cx).auth.is_none() {
        return Ok(Json(ApiMe {
            name: "local".into(),
            email: None,
            full_name: None,
        }));
    }
    let Some(u) = current_user(cx) else {
        return Err(unauthorized().into());
    };
    Ok(Json(ApiMe {
        name: u.name,
        email: u.email,
        full_name: u.full_name,
    }))
}

#[derive(Deserialize)]
struct HostIntelQuery {
    q: Option<String>,
}

#[derive(Serialize)]
struct ApiHostPort {
    ip: String,
    port: u16,
    protocol: String,
    service: Option<String>,
    risk: i64,
}

#[derive(Serialize)]
struct ApiHostIntel {
    host: String,
    services: usize,
    open_ports: Vec<ApiHostPort>,
    technologies: Vec<String>,
    max_risk: i64,
    last_seen: Option<u64>,
}

/// `GET /api/host?q=<hostname-or-ip>` — passive index summary for the browser extension.
#[route(GET "/api/host")]
async fn api_host_intel(cx: &Cx) -> Result<Json<ApiHostIntel>> {
    let q = parse_query_params::<HostIntelQuery>(cx)
        .ok()
        .and_then(|p| p.q)
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut open_ports = Vec::new();
    let mut techs = std::collections::BTreeSet::new();
    let mut max_risk = 0i64;
    let mut last_seen: Option<u64> = None;

    if !q.is_empty()
        && let Ok(store) = ntok_store::Store::open_default()
    {
        let query = if q.parse::<IpAddr>().is_ok() {
            format!("ip:{q}")
        } else {
            format!("hostname:{q}")
        };
        let hits = store.search(&query, 64).unwrap_or_default();
        for h in hits {
            max_risk = max_risk.max(h.risk);
            last_seen = Some(last_seen.map_or(h.last_seen, |prev| prev.max(h.last_seen)));
            if let Some(t) = h.tech {
                for item in t.split([',', ';']).map(str::trim).filter(|s| !s.is_empty()) {
                    techs.insert(item.to_string());
                }
            }
            if open_ports.len() < 16 {
                open_ports.push(ApiHostPort {
                    ip: h.ip,
                    port: h.port,
                    protocol: h.protocol,
                    service: h.service,
                    risk: h.risk,
                });
            }
        }
    }
    let services = open_ports.len();
    Ok(Json(ApiHostIntel {
        host: q,
        services,
        open_ports,
        technologies: techs.into_iter().take(12).collect(),
        max_risk,
        last_seen,
    }))
}

#[derive(Serialize)]
struct ApiScan {
    id: u64,
    args: String,
    status: String,
    done: usize,
    total: usize,
    open: usize,
    elapsed_secs: f64,
    url: String,
}

fn api_scan(id: u64, e: &ScanEntry) -> ApiScan {
    let m = e.meta();
    ApiScan {
        id,
        args: e.args.clone(),
        status: m.status.label(),
        done: m.done,
        total: m.total,
        open: m.open_count,
        elapsed_secs: m.elapsed_secs,
        url: format!("/scans/{id}"),
    }
}

#[route(GET "/api/scans")]
async fn api_scans(cx: &Cx) -> Result<Json<Vec<ApiScan>>> {
    let v = app(cx)
        .list()
        .iter()
        .map(|(id, e)| api_scan(*id, e))
        .collect();
    Ok(Json(v))
}

#[route(GET "/api/scans/{scan_id}")]
async fn api_scan_detail(cx: &Cx) -> Result<Json<ApiScan>> {
    let id = *scan_id(cx)?;
    let e = app(cx).get(id).ok_or_not_found()?;
    Ok(Json(api_scan(id, &e)))
}

#[derive(Deserialize)]
struct ApiScanForm {
    targets: String,
    mode: Option<String>,
    ports: Option<String>,
    crawl: Option<usize>,
    timing: Option<u8>,
    technique: Option<String>,
    service: Option<bool>,
    skip_discovery: Option<bool>,
    ai: Option<bool>,
}

#[derive(Serialize)]
struct ApiStarted {
    id: u64,
    url: String,
    error: Option<String>,
}

/// `POST /api/scans` — same knobs as the web form, minus external tools.
#[route(POST "/api/scans")]
async fn api_start_scan(cx: &Cx, Json(f): Json<ApiScanForm>) -> Result<Json<ApiStarted>> {
    let on = |b: Option<bool>| b.unwrap_or(false).then(|| "on".to_string());
    let form = ScanForm {
        targets: f.targets,
        mode: f.mode,
        ports: f.ports,
        crawl: f.crawl,
        timing: f.timing,
        technique: f.technique,
        service: on(f.service),
        skip_discovery: on(f.skip_discovery),
        ai: on(f.ai),
        tool_nmap: None,
        tool_nuclei: None,
        tool_masscan: None,
        tool_naabu: None,
        tool_rustscan: None,
        ai_model: None,
        ai_instructions: None,
    };
    match app(cx).start(&form) {
        Ok(id) => Ok(Json(ApiStarted {
            id,
            url: format!("/scans/{id}"),
            error: None,
        })),
        Err(e) => Ok(Json(ApiStarted {
            id: 0,
            url: String::new(),
            error: Some(e.to_string()),
        })),
    }
}

#[route(POST "/scans")]
async fn start_scan(cx: &Cx, Form(form): Form<ScanForm>) -> Result<SeeOther> {
    match app(cx).start(&form) {
        Ok(id) => Ok(see_other(href!(scan_page, scan_id: id).resolve(cx))),
        Err(e) => {
            *lock(&app(cx).last_error) = Some(format!("Scan not started: {e}"));
            Ok(see_other(href!(index).resolve(cx)))
        }
    }
}

#[route(GET "/scans/{scan_id}/ports")]
async fn ports_fragment(cx: &Cx) -> Result<ViewHandle> {
    let id = *scan_id(cx)?;
    let entry = app(cx).get(id).ok_or_not_found()?;
    let data = entry.live_data(id);
    view! { live(data: data) }.single().await
}

#[route(GET "/scanlist")]
async fn scan_list_fragment(cx: &Cx) -> Result<ViewHandle> {
    let rows = scan_rows(app(cx));
    view! { scan_list(rows: rows) }.single().await
}

#[route(POST "/scans/{scan_id}/stop")]
async fn stop_scan(cx: &Cx) -> Result<SeeOther> {
    let id = *scan_id(cx)?;
    let entry = app(cx).get(id).ok_or_not_found()?;
    entry.cancel.cancel();
    Ok(see_other(href!(scan_page, scan_id: id).resolve(cx)))
}

#[page("/settings")]
async fn settings_page(cx: &Cx) -> Result<impl View> {
    let s = lock(&app(cx).ai).clone();
    let msg = lock(&app(cx).settings_msg).take();
    let new_token = lock(&app(cx).last_token).take();
    let key_set = s.api_key.is_some();
    let user = current_user(cx);
    let tokens = user
        .as_ref()
        .and_then(|u| {
            lock(&app(cx).auth_db)
                .as_ref()
                .and_then(|db| db.list_api_tokens(u.id).ok())
        })
        .unwrap_or_default();
    let path = config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "config dir unavailable".into());

    // Account-security panel data — everything below only exists when
    // auth is on and someone is signed in.
    let mut sessions = Vec::new();
    let mut totp_on = false;
    let mut events: Vec<ntok_store::AuthEvent> = Vec::new();
    let mut pending_secret: Option<String> = None;
    let mut qr_svg: Option<String> = None;
    let session_tok = cookies(cx).get(AUTH_COOKIE).map(|c| c.value().to_string());
    if let Some(u) = &user {
        let guard = lock(&app(cx).auth_db);
        if let Some(db) = guard.as_ref() {
            sessions = db.list_sessions(u.id).unwrap_or_default();
            totp_on = db.totp_secret(u.id).ok().flatten().is_some();
            events = db.auth_events(&u.name, 15).unwrap_or_default();
        }
        drop(guard);
        if let Some(secret) = lock(&app(cx).pending_totp).get(&u.id).cloned() {
            let uri = format!("otpauth://totp/ntok:{}?secret={secret}&issuer=ntok", u.name);
            qr_svg = qrcode::QrCode::new(uri.as_bytes()).ok().map(|c| {
                c.render::<qrcode::render::svg::Color>()
                    .min_dimensions(150, 150)
                    .build()
            });
            pending_secret = Some(secret);
        }
    }
    let d1_info = app(cx)
        .d1
        .as_ref()
        .map(|d| (d.label(), lock(&d.last).clone()));

    // Posture-strip state — everything the four status tiles report.
    let ai_ready = s.validate().is_ok();
    let (ai_pill, ai_state) = if ai_ready {
        ("pill done", "ready")
    } else {
        ("pill warn", "needs key")
    };
    let ep_host = s
        .endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string();
    let (tok_pill, tok_state) = if user.is_none() {
        ("pill", "sign-in")
    } else if tokens.is_empty() {
        ("pill", "none")
    } else {
        ("pill acc", "active")
    };
    let tok_value = if user.is_none() {
        "account required".to_string()
    } else {
        format!(
            "{} token{}",
            tokens.len(),
            if tokens.len() == 1 { "" } else { "s" }
        )
    };
    let (sec_pill, sec_state) = if user.is_none() {
        ("pill", "sign-in")
    } else if totp_on {
        ("pill done", "2FA on")
    } else {
        ("pill warn", "2FA off")
    };
    let sec_value = if user.is_some() {
        format!(
            "{} session{}",
            sessions.len(),
            if sessions.len() == 1 { "" } else { "s" }
        )
    } else {
        "—".to_string()
    };
    let (d1_pill, d1_state, d1_value, d1_sub) = match &d1_info {
        Some((label, last)) => (
            "pill done",
            "on",
            label.clone(),
            last.clone()
                .map(|l| format!("last: {l}"))
                .unwrap_or_else(|| "no pushes yet".into()),
        ),
        None => (
            "pill",
            "local",
            "D1 mirror".into(),
            "local-first storage".into(),
        ),
    };
    let cur_endpoint = s.endpoint.clone();
    let prov_cls = move |ep: &str| {
        if cur_endpoint == ep {
            "prov-card active"
        } else {
            "prov-card"
        }
    };

    Ok(view! {
        <div class="page-head">
            <div>
                <span class="eyebrow">(ntok_core::brand::NAME) " · Configuration"</span>
                <h1>"Settings"</h1>
            </div>
            <span class="sp"></span>
            <p class="lede">"AI advisor provider, operator instructions, and API access tokens."</p>
        </div>
        if let Some((ok, text)) = msg {
            <div class=(if ok { "banner ok" } else { "banner" }) style="margin-top:20px">(text)</div>
        }
        if let Some((tname, raw)) = new_token {
            let copy_js = format!(
                "ntokCopy(this, {})",
                serde_json::to_string(&raw).unwrap_or_else(|_| "\"\"".into())
            );
            <div class="token-callout">
                <div class="tc-title">"API token '" (tname) "' created — copy it now, it will not be shown again:"</div>
                <div class="tc-box">
                    <code>(raw)</code>
                    <button type="button" class="copy-btn" onclick=(copy_js)>"copy"</button>
                </div>
            </div>
        }
        <div class="cfg-strip">
            <div class="cfg-tile">
                <div class="ct-k"><span class="kk">(icons::ic(icons::SPARKLES))"AI advisor"</span><span class=(ai_pill)>(ai_state)</span></div>
                <div class="ct-v">(s.model.clone())</div>
                <div class="ct-sub">(ep_host)</div>
            </div>
            <div class="cfg-tile">
                <div class="ct-k"><span class="kk">(icons::ic(icons::KEY))"API access"</span><span class=(tok_pill)>(tok_state)</span></div>
                <div class="ct-v">(tok_value)</div>
                <div class="ct-sub">"bearer · extension & CI"</div>
            </div>
            <div class="cfg-tile">
                <div class="ct-k"><span class="kk">(icons::ic(icons::SHIELD))"Security"</span><span class=(sec_pill)>(sec_state)</span></div>
                <div class="ct-v">(sec_value)</div>
                <div class="ct-sub">"password · sessions · 2FA"</div>
            </div>
            <div class="cfg-tile">
                <div class="ct-k"><span class="kk">(icons::ic(icons::CLOUD))"Cloud sync"</span><span class=(d1_pill)>(d1_state)</span></div>
                <div class="ct-v">(d1_value)</div>
                <div class="ct-sub">(d1_sub)</div>
            </div>
        </div>
        <div class="settings-grid">
            <div class="panel">
                <div class="p-head">
                    <span class="p-ic">(icons::ic(icons::SPARKLES))</span>
                    <div>
                        <div class="p-title">"AI advisor"</div>
                        <div class="p-sub">"optional · OpenAI-compatible endpoint"</div>
                    </div>
                    <span class="p-count">(s.model.clone())</span>
                </div>
                <form class="frm" method="post" action=(href!(save_settings))>
                    <div class="full">
                        <label class="lbl">"Provider preset"</label>
                        <div class="prov-grid">
                            <button type="button" class=(prov_cls("https://api.deepseek.com/chat/completions"))
                                onclick="ntokProvider(this)"
                                data-endpoint="https://api.deepseek.com/chat/completions" data-model="deepseek-chat">
                                <span class="pc-ic">(icons::ic(icons::SPARKLES))</span>
                                <span><span class="pc-name">"DeepSeek"</span><span class="pc-sub">"cloud api · deepseek-chat"</span></span>
                                <span class="pc-check">(icons::ic(icons::CHECK))</span>
                            </button>
                            <button type="button" class=(prov_cls("https://api.openai.com/v1/chat/completions"))
                                onclick="ntokProvider(this)"
                                data-endpoint="https://api.openai.com/v1/chat/completions" data-model="gpt-4o-mini">
                                <span class="pc-ic">(icons::ic(icons::CPU))</span>
                                <span><span class="pc-name">"OpenAI"</span><span class="pc-sub">"cloud api · gpt-4o-mini"</span></span>
                                <span class="pc-check">(icons::ic(icons::CHECK))</span>
                            </button>
                            <button type="button" class=(prov_cls("https://openrouter.ai/api/v1/chat/completions"))
                                onclick="ntokProvider(this)"
                                data-endpoint="https://openrouter.ai/api/v1/chat/completions" data-model="deepseek/deepseek-chat">
                                <span class="pc-ic">(icons::ic(icons::GLOBE))</span>
                                <span><span class="pc-name">"OpenRouter"</span><span class="pc-sub">"cloud api · any model"</span></span>
                                <span class="pc-check">(icons::ic(icons::CHECK))</span>
                            </button>
                            <button type="button" class=(prov_cls("http://localhost:11434/v1/chat/completions"))
                                onclick="ntokProvider(this)"
                                data-endpoint="http://localhost:11434/v1/chat/completions" data-model="qwen2.5:3b">
                                <span class="pc-ic">(icons::ic(icons::SERVER))</span>
                                <span><span class="pc-name">"Ollama"</span><span class="pc-sub">"local · keyless"</span></span>
                                <span class="pc-check">(icons::ic(icons::CHECK))</span>
                            </button>
                        </div>
                    </div>
                    <div>
                        <label class="lbl" for="endpoint">"Endpoint"</label>
                        <div class="field-in">
                            (icons::ic(icons::CLOUD))
                            <input class="txt" id="endpoint" name="endpoint" value=(s.endpoint)>
                        </div>
                    </div>
                    <div>
                        <label class="lbl" for="model">"Model"</label>
                        <div class="field-in">
                            (icons::ic(icons::CPU))
                            <input class="txt" id="model" name="model" value=(s.model)>
                        </div>
                    </div>
                    <div class="full">
                        <div class="lbl-row">
                            <label class="lbl" for="api_key">"API key"</label>
                            if key_set { <span class="pill done">"saved"</span> }
                        </div>
                        <div class="field-in">
                            (icons::ic(icons::KEY))
                            <input class="txt" type="password" id="api_key" name="api_key" autocomplete="off"
                                placeholder=(if key_set { "saved — enter a new key to replace" } else { "not set — required for hosted endpoints" })>
                        </div>
                        if key_set {
                            <div class="tgl" style="margin-top:8px">
                                <label><input type="checkbox" name="clear_key">"Clear saved key"</label>
                            </div>
                        }
                    </div>
                    <div class="full">
                        <label class="lbl" for="instructions">"Operator instructions"</label>
                        <div class="field-in tall">
                            (icons::ic(icons::EDIT))
                            <textarea class="txt" id="instructions" name="instructions" rows="3"
                                placeholder="optional — appended to every advisor prompt">(s.instructions.unwrap_or_default())</textarea>
                        </div>
                        <div class="sub">"e.g. stay conservative on timeouts, prioritize web services"</div>
                    </div>
                    <div class="full" style="display:flex;gap:10px;flex-wrap:wrap">
                        <button class="btn" type="submit" name="action" value="save">(icons::ic(icons::CHECK))"Save settings"</button>
                        <button class="btn ghost" type="submit" name="action" value="test">(icons::ic(icons::ZAP))"Test connection"</button>
                    </div>
                </form>
                <div class="p-foot">(icons::ic(icons::FILE))"Stored at " <code>(path)</code>
                    "· NTOK_AI_* env vars apply until first save."</div>
            </div>
            <div class="panel">
                <div class="p-head">
                    <span class="p-ic">(icons::ic(icons::KEY))</span>
                    <div>
                        <div class="p-title">"API access"</div>
                        <div class="p-sub">"Bearer tokens for extension & CI"</div>
                    </div>
                    <span class="p-count">(tokens.len()) " active"</span>
                </div>
                if let Some(u) = &user {
                    <div style="margin-bottom:14px">
                        <span class="acct-chip">
                            <span class="ai">(icons::ic(icons::USER))</span>
                            (u.full_name.clone().unwrap_or_else(|| u.name.clone()))
                        </span>
                        <div class="sub" style="margin-top:6px">
                            "@" (u.name.clone())
                            (u.email.as_ref().map(|e| format!(" · {e}")).unwrap_or_default())
                        </div>
                    </div>
                    <p class="sub" style="margin:0 0 14px">
                        "Tokens authenticate via "
                        <span class="cmd-inline">"Authorization: Bearer ntok_…"</span>
                        " — mint one per client so revoking is surgical."
                    </p>
                    if !tokens.is_empty() {
                        <table>
                            <thead>
                                <tr><th>"Token"</th><th>"Activity"</th><th class="num">"Action"</th></tr>
                            </thead>
                            <tbody>
                                for t in &tokens {
                                    <tr>
                                        <td style="font-weight:600;color:var(--ink)">(icons::ic(icons::KEY))" "(t.name.clone())</td>
                                        <td style="color:var(--muted);font:500 11.5px var(--mono)">
                                            "created " (fmt_ago(t.created_unix))
                                            (t.last_used.map(|l| format!(" · used {}", fmt_ago(l)))
                                                .unwrap_or_else(|| " · never used".into()))
                                        </td>
                                        <td class="num">
                                            <form method="post" action=(href!(revoke_token)) style="display:inline">
                                                <input type="hidden" name="id" value=(t.id)>
                                                <button class="btn xs danger" type="submit" title="Revoke this token">(icons::ic(icons::TRASH))"revoke"</button>
                                            </form>
                                        </td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                    } else {
                        <div class="empty" style="padding:22px 16px;font-size:12.5px;margin-bottom:14px">
                            (icons::ic(icons::KEY))"No tokens yet — mint one for the browser extension or CI."
                        </div>
                    }
                    <div class="p-sec rule">"Mint a token"</div>
                    <form method="post" action=(href!(create_token))
                        style="display:flex;gap:10px;align-items:end;flex-wrap:wrap">
                        <div style="flex:1;min-width:200px">
                            <label class="lbl" for="token_name">"Label"</label>
                            <div class="field-in">
                                (icons::ic(icons::TAG))
                                <input class="txt" id="token_name" name="name"
                                    placeholder="e.g. chrome extension" required="required">
                            </div>
                        </div>
                        <button class="btn" type="submit">(icons::ic(icons::PLUS))"Mint token"</button>
                    </form>
                } else {
                    <div class="empty" style="padding:26px 18px;font-size:12.5px">
                        (icons::ic(icons::LOCK))
                        "API tokens need an account — enable auth (NTOK_AUTH) and sign in to mint Bearer tokens."
                    </div>
                }
            </div>
            <div class="panel">
                <div class="p-head">
                    <span class="p-ic">(icons::ic(icons::SHIELD))</span>
                    <div>
                        <div class="p-title">"Account security"</div>
                        <div class="p-sub">"password · sessions · two-factor"</div>
                    </div>
                    if user.is_some() {
                        <span class="p-count">(if totp_on { "2FA on" } else { "2FA off" })</span>
                    }
                </div>
                if let Some(u) = &user {
                    if u.email.is_none() {
                        <div class="banner" style="margin-bottom:14px">
                            "This account has no email — set one below; it can also be used to sign in."
                        </div>
                    }
                    <div class="p-sec">"Profile"</div>
                    <form class="frm" method="post" action=(href!(account_profile))>
                        <div>
                            <label class="lbl" for="prof-email">"Email"</label>
                            <div class="field-in">
                                (icons::ic(icons::GLOBE))
                                <input class="txt" id="prof-email" name="email" type="email"
                                    autocomplete="email" placeholder="you@example.com"
                                    value=(u.email.clone().unwrap_or_default()) required="required">
                            </div>
                        </div>
                        <div>
                            <label class="lbl" for="prof-name">"Full name"</label>
                            <div class="field-in">
                                (icons::ic(icons::USER))
                                <input class="txt" id="prof-name" name="full_name"
                                    autocomplete="name" placeholder="optional"
                                    value=(u.full_name.clone().unwrap_or_default())>
                            </div>
                        </div>
                        <div>
                            <label class="lbl" for="prof-pw">"Confirm password"</label>
                            <div class="field-in">
                                (icons::ic(icons::LOCK))
                                <input class="txt" type="password" id="prof-pw" name="password"
                                    autocomplete="current-password" required="required">
                            </div>
                        </div>
                        <div class="full" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                            <button class="btn sm" type="submit">"Save profile"</button>
                            <span class="sub">"email doubles as a login identifier — password confirms it's you"</span>
                        </div>
                    </form>

                    <div class="p-sec rule">"Change password"</div>
                    <form class="frm" method="post" action=(href!(account_password))>
                        <div>
                            <label class="lbl" for="cur-pw">"Current"</label>
                            <div class="field-in">
                                (icons::ic(icons::LOCK))
                                <input class="txt" type="password" id="cur-pw" name="current"
                                    autocomplete="current-password" required="required">
                            </div>
                        </div>
                        <div>
                            <label class="lbl" for="new-pw">"New"</label>
                            <div class="field-in">
                                (icons::ic(icons::LOCK))
                                <input class="txt" type="password" id="new-pw" name="password"
                                    autocomplete="new-password" required="required" minlength="8">
                            </div>
                        </div>
                        <div>
                            <label class="lbl" for="new-pw2">"Repeat new"</label>
                            <div class="field-in">
                                (icons::ic(icons::CHECK))
                                <input class="txt" type="password" id="new-pw2" name="confirm"
                                    autocomplete="new-password" required="required" minlength="8">
                            </div>
                        </div>
                        <div class="full" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                            <button class="btn sm" type="submit">"Change password"</button>
                            <span class="sub">"signs out your other sessions"</span>
                        </div>
                    </form>

                    <div class="p-sec rule">"Active sessions · " (sessions.len())</div>
                    if !sessions.is_empty() {
                        <table>
                            <tbody>
                                for s in &sessions {
                                    let is_cur = session_tok.as_deref() == Some(s.token.as_str());
                                    <tr>
                                        <td style="font-weight:600;color:var(--ink)">
                                            (format!("{}…", &s.token[..s.token.len().min(12)]))
                                            if is_cur { <span class="pill acc" style="margin-left:8px">"this browser"</span> }
                                        </td>
                                        <td style="color:var(--muted)">
                                            "opened " (fmt_ago(s.created_unix))
                                            " · expires " (fmt_ago(s.expires_unix))
                                        </td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                        <form method="post" action=(href!(account_sessions)) style="margin-top:10px">
                            <button class="btn xs danger" type="submit">(icons::ic(icons::LOGOUT))"Sign out all other sessions"</button>
                        </form>
                    }

                    <div class="p-sec rule">"Two-factor authentication"</div>
                    if totp_on {
                        <p class="sub" style="margin:0 0 10px">"Enabled — sign-in asks for an authenticator code on top of the password."</p>
                        <form method="post" action=(href!(account_totp))
                            style="display:flex;gap:10px;align-items:end;flex-wrap:wrap">
                            <input type="hidden" name="action" value="disable">
                            <div style="flex:1;min-width:180px">
                                <div class="field-in">
                                    (icons::ic(icons::LOCK))
                                    <input class="txt" type="password" name="password"
                                        autocomplete="current-password" placeholder="confirm password" required="required">
                                </div>
                            </div>
                            <button class="btn xs danger" type="submit">"Disable 2FA"</button>
                        </form>
                    } else if let (Some(svg), Some(b32)) = (&qr_svg, &pending_secret) {
                        <div class="totp-setup">
                            <div class="totp-qr">(Unescaped::new_unchecked(svg.clone()))</div>
                            <div>
                                <p class="sub" style="margin:0 0 8px">
                                    "Scan with your authenticator app, or enter the key manually:"
                                </p>
                                <div class="cmd-inline" style="user-select:all">(b32.clone())</div>
                            </div>
                        </div>
                        <form method="post" action=(href!(account_totp))
                            style="display:flex;gap:10px;align-items:end;flex-wrap:wrap;margin-top:12px">
                            <input type="hidden" name="action" value="confirm">
                            <div style="flex:1;min-width:180px">
                                <div class="field-in">
                                    (icons::ic(icons::SHIELD))
                                    <input class="txt" name="code" inputmode="numeric" maxlength="6"
                                        autocomplete="one-time-code" placeholder="6-digit code" required="required">
                                </div>
                            </div>
                            <button class="btn sm" type="submit">"Confirm & enable"</button>
                        </form>
                    } else {
                        <p class="sub" style="margin:0 0 10px">"Adds an authenticator-app code on top of the password."</p>
                        <form method="post" action=(href!(account_totp))>
                            <input type="hidden" name="action" value="start">
                            <button class="btn sm" type="submit">(icons::ic(icons::SHIELD))"Set up 2FA"</button>
                        </form>
                    }

                    <div class="p-sec rule">"Recent account activity"</div>
                    if events.is_empty() {
                        <p class="sub" style="margin:0">"No events yet — logins, lockouts, and security changes land here."</p>
                    } else {
                        <table>
                            <tbody>
                                for e in &events {
                                    <tr>
                                        <td style="font-weight:600;color:var(--ink)">(e.event.clone())</td>
                                        <td style="color:var(--muted)">(e.ip.clone())</td>
                                        <td class="num" style="color:var(--muted)">(fmt_ago(e.unix_ts))</td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                    }
                } else {
                    <div class="empty" style="padding:22px 16px;font-size:12.5px">
                        (icons::ic(icons::SHIELD))"Sign in to manage account security."
                    </div>
                }
            </div>
            <div class="panel">
                <div class="p-head">
                    <span class="p-ic">(icons::ic(icons::CLOUD))</span>
                    <div>
                        <div class="p-title">"Cloud sync"</div>
                        <div class="p-sub">"optional Cloudflare D1 mirror"</div>
                    </div>
                    <span class="p-count">(if d1_info.is_some() { "on" } else { "off" })</span>
                </div>
                if let Some((label, last)) = &d1_info {
                    <p class="sub" style="margin:0 0 8px">
                        "Mirroring every finished scan to Cloudflare D1 (" (label.clone()) ")."
                    </p>
                    if let Some(l) = last {
                        <p class="sub" style="margin:0">"Last push: " (l.clone())</p>
                    }
                } else {
                    <p class="sub" style="margin:0 0 10px">
                        "Local-first by default — reports live in reports/. To also mirror scan
                         history into Cloudflare D1, create a database, mint an API token with
                         D1 access, then restart with:"
                    </p>
                    <div class="cmd-inline" style="user-select:all">"NTOK_D1_ACCOUNT · NTOK_D1_DB · NTOK_D1_TOKEN"</div>
                }
            </div>
        </div>
    })
}

#[route(POST "/settings")]
async fn save_settings(cx: &Cx, Form(form): Form<SettingsForm>) -> Result<SeeOther> {
    let current = lock(&app(cx).ai).clone();
    let s = merge_settings(&form, &current);
    let msg = if form.action.as_deref() == Some("test") {
        match ntok_core::HttpAdvisor::new(s) {
            Ok(adv) => match adv.test().await {
                Ok(reply) => (true, format!("Connected — model replied: {reply}")),
                Err(e) => (false, format!("Connection failed: {e}")),
            },
            Err(e) => (false, e),
        }
    } else {
        match save_ai_settings(&s) {
            Ok(()) => {
                *lock(&app(cx).ai) = s;
                (true, "Settings saved.".to_string())
            }
            Err(e) => (false, format!("Could not write config file: {e}")),
        }
    };
    *lock(&app(cx).settings_msg) = Some(msg);
    Ok(see_other(href!(settings_page).resolve(cx)))
}

#[derive(Deserialize)]
struct TokenForm {
    name: String,
}

#[route(POST "/settings/tokens")]
async fn create_token(cx: &Cx, Form(form): Form<TokenForm>) -> Result<SeeOther> {
    match current_user(cx) {
        Some(u) => match lock(&app(cx).auth_db)
            .as_ref()
            .and_then(|db| db.create_api_token(u.id, &form.name).ok())
        {
            Some(t) => {
                *lock(&app(cx).last_token) = Some((form.name, t));
            }
            None => {
                *lock(&app(cx).settings_msg) = Some((
                    false,
                    "Could not create token (auth DB unavailable).".into(),
                ));
            }
        },
        None => {
            *lock(&app(cx).settings_msg) = Some((false, "Sign in to create tokens.".into()));
        }
    }
    Ok(see_other(href!(settings_page).resolve(cx)))
}

#[derive(Deserialize)]
struct RevokeForm {
    id: i64,
}

#[route(POST "/settings/tokens/revoke")]
async fn revoke_token(cx: &Cx, Form(form): Form<RevokeForm>) -> Result<SeeOther> {
    if let Some(u) = current_user(cx)
        && let Some(db) = lock(&app(cx).auth_db).as_ref()
    {
        let _ = db.revoke_api_token(u.id, form.id);
    }
    Ok(see_other(href!(settings_page).resolve(cx)))
}

// ---------- account security ----------

fn audit(cx: &Cx, db: &ntok_store::Store, name: &str, event: &str) {
    let ip = client_ip(cx).map(|i| i.to_string()).unwrap_or_default();
    let _ = db.log_auth(name, &ip, event);
}

#[derive(Deserialize)]
struct PasswordForm {
    current: String,
    password: String,
    confirm: String,
}

/// Change password — verifies the current one, then revokes every
/// session but this browser's so a stolen session dies with the change.
#[route(POST "/account/password")]
async fn account_password(cx: &Cx, Form(form): Form<PasswordForm>) -> Result<SeeOther> {
    let Some(u) = current_user(cx) else {
        return Err(unauthorized().into());
    };
    let msg = {
        let guard = lock(&app(cx).auth_db);
        let Some(db) = guard.as_ref() else {
            return Err(unauthorized().into());
        };
        if form.password != form.confirm || form.password.len() < 8 {
            (
                false,
                "New passwords must match and be at least 8 characters.".into(),
            )
        } else if !matches!(db.verify_user(&u.name, &form.current), Ok(Some(_))) {
            (false, "Current password is wrong.".into())
        } else {
            match db.change_password(u.id, &form.password) {
                Ok(()) => {
                    if let Some(c) = cookies(cx).get(AUTH_COOKIE) {
                        let _ = db.drop_other_sessions(u.id, c.value());
                    }
                    audit(cx, db, &u.name, "pw_change");
                    (
                        true,
                        "Password changed — other sessions were signed out.".into(),
                    )
                }
                Err(e) => (false, format!("Could not change password: {e}")),
            }
        }
    };
    *lock(&app(cx).settings_msg) = Some(msg);
    Ok(see_other(href!(settings_page).resolve(cx)))
}

#[derive(Deserialize)]
struct ProfileForm {
    email: String,
    full_name: String,
    password: String,
}

/// Update email + display name — legacy accounts (seeded before these
/// columns existed, or registered with a blank email) use this to gain
/// an email, which then also works as a login identifier. Re-verifies
/// the password like `account_password` does, and keeps email
/// mandatory so every account keeps a reachable identifier.
#[route(POST "/account/profile")]
async fn account_profile(cx: &Cx, Form(form): Form<ProfileForm>) -> Result<SeeOther> {
    let Some(u) = current_user(cx) else {
        return Err(unauthorized().into());
    };
    let msg = {
        let guard = lock(&app(cx).auth_db);
        let Some(db) = guard.as_ref() else {
            return Err(unauthorized().into());
        };
        if form.email.trim().is_empty() {
            (
                false,
                "An email is required — it doubles as a login identifier.".into(),
            )
        } else if !matches!(db.verify_user(&u.name, &form.password), Ok(Some(_))) {
            audit(cx, db, &u.name, "profile_denied");
            (false, "Current password is wrong.".into())
        } else {
            match db.update_profile(u.id, &form.email, &form.full_name) {
                Ok(_) => {
                    audit(cx, db, &u.name, "profile_update");
                    (true, "Profile updated.".into())
                }
                Err(e) if e.to_string().contains("UNIQUE") => (
                    false,
                    "That email is already used by another account.".into(),
                ),
                Err(e) => (false, format!("Could not update profile: {e}")),
            }
        }
    };
    *lock(&app(cx).settings_msg) = Some(msg);
    Ok(see_other(href!(settings_page).resolve(cx)))
}

/// "Sign out other sessions" — every token except the caller's cookie.
#[route(POST "/account/sessions")]
async fn account_sessions(cx: &Cx) -> Result<SeeOther> {
    let Some(u) = current_user(cx) else {
        return Err(unauthorized().into());
    };
    let guard = lock(&app(cx).auth_db);
    if let (Some(db), Some(c)) = (guard.as_ref(), cookies(cx).get(AUTH_COOKIE)) {
        let _ = db.drop_other_sessions(u.id, c.value());
        audit(cx, db, &u.name, "sessions_revoked");
        *lock(&app(cx).settings_msg) = Some((true, "All other sessions were signed out.".into()));
    }
    Ok(see_other(href!(settings_page).resolve(cx)))
}

#[derive(Deserialize)]
struct TotpForm {
    action: Option<String>,
    code: Option<String>,
    password: Option<String>,
}

/// TOTP lifecycle in three actions: `start` stages a secret and shows
/// the QR, `confirm` enables it once the user proves a code, `disable`
/// removes it behind a password re-check.
#[route(POST "/account/totp")]
async fn account_totp(cx: &Cx, Form(form): Form<TotpForm>) -> Result<SeeOther> {
    let Some(u) = current_user(cx) else {
        return Err(unauthorized().into());
    };
    let guard = lock(&app(cx).auth_db);
    let Some(db) = guard.as_ref() else {
        return Err(unauthorized().into());
    };
    let msg = match form.action.as_deref() {
        Some("start") => {
            if db.totp_secret(u.id).ok().flatten().is_some() {
                (false, "2FA is already enabled — disable it first.".into())
            } else {
                let secret = ntok_store::new_totp_secret();
                lock(&app(cx).pending_totp).insert(u.id, secret);
                (
                    true,
                    "Secret generated — scan the QR and confirm a code.".into(),
                )
            }
        }
        Some("confirm") => {
            let pending = lock(&app(cx).pending_totp).get(&u.id).cloned();
            match (pending, form.code.as_deref()) {
                (Some(secret), Some(code)) if ntok_store::totp_check(&secret, code) => {
                    let _ = db.set_totp(u.id, &secret);
                    lock(&app(cx).pending_totp).remove(&u.id);
                    audit(cx, db, &u.name, "totp_enabled");
                    (true, "Two-factor enabled.".into())
                }
                (Some(_), _) => (
                    false,
                    "That code didn't match — try the current one.".into(),
                ),
                (None, _) => (false, "Start 2FA setup first.".into()),
            }
        }
        Some("disable") => {
            let ok = form
                .password
                .as_deref()
                .is_some_and(|p| matches!(db.verify_user(&u.name, p), Ok(Some(_))));
            if ok {
                let _ = db.clear_totp(u.id);
                lock(&app(cx).pending_totp).remove(&u.id);
                audit(cx, db, &u.name, "totp_disabled");
                (true, "Two-factor disabled.".into())
            } else {
                (false, "Password needed to disable 2FA.".into())
            }
        }
        _ => (false, "Unknown action.".into()),
    };
    drop(guard);
    *lock(&app(cx).settings_msg) = Some(msg);
    Ok(see_other(href!(settings_page).resolve(cx)))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
}

/// The local index — same `field:value` DSL as `ntok search`, rendered
/// server-side. Plain GET so queries are linkable/bookmarkable.
#[page("/search")]
async fn search_page(cx: &Cx) -> Result<impl View> {
    let q = parse_query_params::<SearchQuery>(cx)
        .ok()
        .and_then(|p| p.q)
        .unwrap_or_default()
        .trim()
        .to_string();
    let (hits, err) = match ntok_store::Store::open_default() {
        Ok(s) => match s.search(&q, 200) {
            Ok(h) => (h, None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        },
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    let quick_filters = [
        ("High risk", "risk:high"),
        ("Expired TLS", "expired:true"),
        ("Web services", "has:web"),
        ("Findings", "has:findings"),
        ("Rare ports", "anomaly:high"),
        ("Self-signed", "selfsigned:true"),
    ];
    Ok(view! {
        <div class="page-head">
            <div>
                <span class="eyebrow">(ntok_core::brand::NAME) " · Knowledge Base"</span>
                <h1>"Index"</h1>
            </div>
            <span class="sp"></span>
            <p class="lede">"Query every open service, certificate, and technology ever observed."</p>
        </div>
        <form class="panel" method="get" action=(href!(search_page)) style="margin-top:20px">
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                <div class="field-in" style="flex:1;min-width:240px">
                    (icons::ic(icons::SEARCH))
                    <input class="txt" name="q" value=(q.clone())
                        placeholder="service:nginx port:443 · has:tls expired:true · bare words full-text">
                </div>
                <button class="btn" type="submit">(icons::ic(icons::SEARCH))"Search"</button>
                if !q.is_empty() {
                    <a class="btn ghost" href=(href!(search_page))>"Clear"</a>
                }
            </div>
            <div class="chips" style="margin-top:12px">
                for (label, expr) in quick_filters {
                    <a class="chip chip-link" href=(format!("/search?q={expr}"))>
                        <b>(label)</b>
                        <span class="cat">(expr)</span>
                    </a>
                }
            </div>
            <details class="adv" style="margin-top:12px">
                <summary>"Query syntax reference"<span class="adv-hint">"Shodan-style field:value filters + full-text"</span></summary>
                <div class="adv-body one" style="font:400 11.5px/1.7 var(--mono);color:var(--muted)">
                    "ip · net · port (80 or 1-1024) · protocol · state · service · product · banner · hostname · os · asn · org · server · tech · status · has:banner|tls|web|tech|findings · expired:true · selfsigned:true · favicon:<mmh3> · finding:<text> · sev:high|critical · risk:high|medium|low · anomaly:high · after:YYYY-MM-DD · before:YYYY-MM-DD"
                </div>
            </details>
        </form>
        if let Some(e) = &err {
            <div class="banner" style="margin-top:20px">(e.clone())</div>
        }
        if !hits.is_empty() {
            <div class="sec" style="margin-top:24px">
                <div class="sec-head">
                    <p class="sec-title">"Results"</p>
                    <span class="pill acc">(format!("{} hits", hits.len()))</span>
                </div>
                <div class="panel flush">
                    <table>
                        <thead>
                            <tr>
                                <th>"Target"</th>
                                <th>"Service"</th>
                                <th>"Host / Banner"</th>
                                <th>"Technologies"</th>
                                <th>"Signals"</th>
                            </tr>
                        </thead>
                        <tbody>
                            for h in &hits {
                                let risk_cls = if h.risk >= 70 {
                                    "pill err"
                                } else if h.risk >= 40 {
                                    "pill warn"
                                } else {
                                    "pill"
                                };
                                <tr>
                                    <td class="acc">(format!("{}:{}/{}", h.ip, h.port, h.protocol))</td>
                                    <td>(h.service.clone().unwrap_or_else(|| h.state.clone()))</td>
                                    <td>(h.hostname.clone().or(h.banner.clone())
                                        .map(|s| s.chars().take(60).collect::<String>())
                                        .unwrap_or_default())</td>
                                    <td style="color:var(--muted)">(h.tech.clone().unwrap_or_default())</td>
                                    <td style="white-space:nowrap">
                                        if h.risk >= 40 {
                                            <span class=(risk_cls)>(format!("risk {}", h.risk))</span>
                                        }
                                        if h.tls_expired {
                                            <span class="pill err" style="margin-left:4px">"expired"</span>
                                        }
                                        if h.anomaly >= 70 {
                                            <span class="pill warn" style="margin-left:4px">"rare"</span>
                                        }
                                    </td>
                                </tr>
                            }
                        </tbody>
                    </table>
                </div>
            </div>
        } else if err.is_none() {
            <div class="empty" style="margin-top:20px">
                "No indexed services match — run a scan or import an nmap XML report to populate the knowledge base."
            </div>
        }
    })
}

#[derive(Deserialize)]
struct ReportQuery {
    fmt: Option<String>,
}

#[route(GET "/scans/{scan_id}/report")]
async fn report_route(cx: &Cx) -> Result<Response> {
    let id = *scan_id(cx)?;
    let entry = app(cx).get(id).ok_or_not_found()?;
    let rep = lock(&entry.report).clone().ok_or_not_found()?;
    let fmt = parse_query_params::<ReportQuery>(cx)
        .ok()
        .and_then(|q| q.fmt)
        .and_then(|f| ReportFormat::parse(&f))
        .unwrap_or(ReportFormat::Json);
    let body = fmt.render(&rep)?;
    Ok(Response::builder()
        .header("Content-Type", fmt.mime())
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"ntok-{id}.{}\"", fmt.ext()),
        )
        .body(Body::from(body))?)
}

/// The whole log file — the deque only keeps the last `MAX_LOG` lines.
#[route(GET "/scans/{scan_id}/log")]
async fn log_route(cx: &Cx) -> Result<Response> {
    let id = *scan_id(cx)?;
    let entry = app(cx).get(id).ok_or_not_found()?;
    let body = match std::fs::read_to_string(&entry.log_path) {
        Ok(text) => text,
        Err(_) => lock(&entry.log)
            .iter()
            .map(|l| format!("+{:.1}s{} {}", l.at, if l.hot { "*" } else { "" }, l.text))
            .collect::<Vec<_>>()
            .join("\n"),
    };
    Ok(Response::builder()
        .header("Content-Type", "text/plain; charset=utf-8")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"ntok-{id}.log\""),
        )
        .body(Body::from(body))?)
}

/// Self-hosted woff2 — the UI ships its fonts, so pages render the same
/// offline (no Google Fonts fetch). Whitelisted names, embedded at build.
#[route(GET "/fonts/{font_name}")]
async fn font_route(cx: &Cx) -> Result<Response> {
    let bytes: &'static [u8] = match font_name(cx)?.as_str() {
        "inter-var.woff2" => include_bytes!("../assets/fonts/inter-var.woff2"),
        "work-sans-var.woff2" => include_bytes!("../assets/fonts/work-sans-var.woff2"),
        "ibm-plex-mono-400.woff2" => include_bytes!("../assets/fonts/ibm-plex-mono-400.woff2"),
        "ibm-plex-mono-500.woff2" => include_bytes!("../assets/fonts/ibm-plex-mono-500.woff2"),
        "ibm-plex-mono-600.woff2" => include_bytes!("../assets/fonts/ibm-plex-mono-600.woff2"),
        _ => return Err(not_found().into()),
    };
    Ok(Response::builder()
        .header("Content-Type", "font/woff2")
        .header("Cache-Control", "public, max-age=31536000, immutable")
        .body(Body::from(bytes))?)
}

#[derive(Deserialize)]
struct ImportForm {
    path: String,
}

#[route(POST "/import")]
async fn import_scan(cx: &Cx, Form(form): Form<ImportForm>) -> Result<SeeOther> {
    match app(cx).import(form.path.trim()) {
        Ok(id) => Ok(see_other(href!(scan_page, scan_id: id).resolve(cx))),
        Err(e) => {
            *lock(&app(cx).last_error) = Some(format!("Import failed: {e}"));
            Ok(see_other(href!(index).resolve(cx)))
        }
    }
}
/// ndiff-style page: what changed between scan A and scan B. Any pair of
/// reports compares — ntok scans and imported nmap files alike.
#[page("/compare/{scan_id}/{other_id}")]
async fn compare_page(cx: &Cx) -> Result<impl View> {
    let a_id = *scan_id(cx)?;
    let b_id = *other_id(cx)?;
    let app = app(cx);
    let ra = {
        let e = app.get(a_id).ok_or_not_found()?;
        lock(&e.report).clone().ok_or_not_found()?
    };
    let rb = {
        let e = app.get(b_id).ok_or_not_found()?;
        lock(&e.report).clone().ok_or_not_found()?
    };
    let d = ntok_core::diff::diff_reports(&ra, &rb);
    let empty =
        d.hosts_added.is_empty() && d.hosts_removed.is_empty() && d.hosts_changed.is_empty();
    Ok(view! {
        <div class="page-head">
            <div>
                <span class="eyebrow">(ntok_core::brand::NAME) " · Drift Analysis"</span>
                <h1>"Scan #" (a_id) " vs #" (b_id)</h1>
            </div>
            <span class="sp"></span>
            <div class="page-actions">
                <a class="btn sm ghost" href=(href!(compare_page, scan_id: b_id, other_id: a_id))>(icons::ic(icons::REFRESH))"Swap order"</a>
                <a class="btn sm ghost" href=(href!(scan_page, scan_id: a_id))>"Scan #" (a_id)</a>
                <a class="btn sm ghost" href=(href!(scan_page, scan_id: b_id))>"Scan #" (b_id)</a>
            </div>
        </div>
        <div class="cmd-row">
            <span class="cmd">"ntok " (d.a_args.clone()) "  →  ntok " (d.b_args.clone())</span>
        </div>

        <div class="sec" style="margin-top:24px">
            <div class="stats">
                <div class="stat ok"><span class="si">(icons::ic(icons::PLUS))</span><div class="v">"+" (d.hosts_added.len())</div><div class="k">"hosts appeared"</div></div>
                <div class="stat err"><span class="si">(icons::ic(icons::TRASH))</span><div class="v">"−" (d.hosts_removed.len())</div><div class="k">"hosts disappeared"</div></div>
                <div class="stat warn"><span class="si">(icons::ic(icons::BRANCH))</span><div class="v">(d.hosts_changed.len())</div><div class="k">"hosts changed"</div></div>
                <div class="stat"><span class="si">(icons::ic(icons::CHECK))</span><div class="v">(d.hosts_unchanged)</div><div class="k">"hosts identical"</div></div>
            </div>
        </div>

        if empty {
            <div class="empty" style="margin-top:20px">
                "No differences detected"
                if d.hosts_unchanged > 0 {
                    " — " (d.hosts_unchanged) " hosts identical across both scans"
                }
                "."
            </div>
        } else {
            if !d.hosts_added.is_empty() {
                <div class="sec">
                    <p class="sec-title">"Appeared in #" (b_id)</p>
                    <div class="panel flush">
                        <table>
                            <thead><tr><th>"Host"</th><th>"Hostname"</th><th>"State"</th><th>"Ports"</th></tr></thead>
                            <tbody>
                                for h in &d.hosts_added {
                                    <tr class="diff-add">
                                        <td class="acc">"+ " (h.ip.to_string())</td>
                                        <td>(h.hostname.clone().unwrap_or_default())</td>
                                        <td><span class="pill done">(host_word(h.state))</span></td>
                                        <td style="color:var(--muted)">(ports_brief(h))</td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                    </div>
                </div>
            }
            if !d.hosts_removed.is_empty() {
                <div class="sec">
                    <p class="sec-title">"Disappeared since #" (a_id)</p>
                    <div class="panel flush">
                        <table>
                            <thead><tr><th>"Host"</th><th>"Hostname"</th><th>"State"</th><th>"Ports"</th></tr></thead>
                            <tbody>
                                for h in &d.hosts_removed {
                                    <tr class="diff-rem">
                                        <td style="color:var(--err);font-weight:600">"− " (h.ip.to_string())</td>
                                        <td>(h.hostname.clone().unwrap_or_default())</td>
                                        <td><span class="pill">(host_word(h.state))</span></td>
                                        <td style="color:var(--muted)">(ports_brief(h))</td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                    </div>
                </div>
            }
            for h in &d.hosts_changed {
                let head = {
                    let mut s = h.ip.to_string();
                    if let Some(n) = &h.hostname {
                        s.push_str(&format!(" ({n})"));
                    }
                    s
                };
                <div class="sec">
                    <p class="sec-title">(head)</p>
                    <div class="panel flush">
                        <table>
                            <tbody>
                                if let Some((old, new)) = &h.state_changed {
                                    <tr class="diff-chg">
                                        <td style="width:140px;color:var(--muted)">"host"</td>
                                        <td>(host_word(*old)) " → " (host_word(*new))</td>
                                    </tr>
                                }
                                if let Some((old, new)) = &h.hostname_changed {
                                    <tr class="diff-chg">
                                        <td style="width:140px;color:var(--muted)">"hostname"</td>
                                        <td>
                                            (old.clone().unwrap_or_else(|| "—".into()))
                                            " → "
                                            (new.clone().unwrap_or_else(|| "—".into()))
                                        </td>
                                    </tr>
                                }
                                if let Some((old, new)) = &h.os_changed {
                                    <tr class="diff-chg">
                                        <td style="width:140px;color:var(--muted)">"os"</td>
                                        <td>
                                            (old.clone().unwrap_or_else(|| "—".into()))
                                            " → "
                                            (new.clone().unwrap_or_else(|| "—".into()))
                                        </td>
                                    </tr>
                                }
                                for p in &h.ports_added {
                                    <tr class="diff-add">
                                        <td class="acc">"+ " (p.port) "/" (p.protocol.as_str())</td>
                                        <td>(p.state.as_str()) (svc_label(p))</td>
                                    </tr>
                                }
                                for p in &h.ports_removed {
                                    <tr class="diff-rem">
                                        <td style="color:var(--err)">"− " (p.port) "/" (p.protocol.as_str())</td>
                                        <td>"was " (p.state.as_str()) (svc_label(p))</td>
                                    </tr>
                                }
                                for c in &h.state_changes {
                                    <tr class="diff-chg">
                                        <td style="color:var(--warn)">(c.port) "/" (c.protocol.as_str())</td>
                                        <td>
                                            (c.old.as_str()) " → " (c.new.as_str())
                                            (c.service.clone().map(|s| format!(" ({s})")).unwrap_or_default())
                                        </td>
                                    </tr>
                                }
                                for c in &h.service_changes {
                                    <tr class="diff-chg">
                                        <td style="color:var(--warn)">(c.port) "/" (c.protocol.as_str())</td>
                                        <td>
                                            "service " (c.old.clone().unwrap_or_else(|| "—".into()))
                                            " → " (c.new.clone().unwrap_or_else(|| "—".into()))
                                        </td>
                                    </tr>
                                }
                                for f in &h.findings_added {
                                    <tr class="diff-add">
                                        <td class="acc">"+ finding"</td>
                                        <td>(f.clone())</td>
                                    </tr>
                                }
                                for f in &h.findings_removed {
                                    <tr class="diff-rem">
                                        <td style="color:var(--err)">"− finding"</td>
                                        <td>(f.clone())</td>
                                    </tr>
                                }
                                for w in &h.web_changes {
                                    <tr class="diff-chg">
                                        <td style="color:var(--muted)">"web"</td>
                                        <td>(w.clone())</td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                    </div>
                </div>
            }
        }
    })
}

fn host_word(s: ntok_core::HostState) -> &'static str {
    match s {
        ntok_core::HostState::Up => "up",
        ntok_core::HostState::Down => "down",
    }
}

fn ports_brief(h: &ntok_core::model::HostResult) -> String {
    let open = h.ports.iter().filter(|p| p.state.is_open()).count();
    if h.ports.is_empty() {
        "no ports".into()
    } else {
        format!("{} ports, {open} open", h.ports.len())
    }
}

fn svc_label(p: &ntok_core::model::PortResult) -> String {
    match (&p.service, &p.banner) {
        (Some(s), Some(b)) => format!(" ({s} — {b})"),
        (Some(s), None) => format!(" ({s})"),
        _ => String::new(),
    }
}

/// Replay a scan's stored form as a new scan — the drift-detection loop:
/// rescan, then `compare` old vs new. Entries without a form (restored
/// before this existed, or imported) can't replay.
#[route(POST "/scans/{scan_id}/rescan")]
async fn rescan_scan(cx: &Cx) -> Result<SeeOther> {
    let id = *scan_id(cx)?;
    let entry = app(cx).get(id).ok_or_not_found()?;
    let Some(form) = entry.form.clone() else {
        *lock(&app(cx).last_error) = Some(format!("Scan #{id} has no replayable form"));
        return Ok(see_other(href!(scan_page, scan_id: id).resolve(cx)));
    };
    match app(cx).start(&form) {
        Ok(new_id) => Ok(see_other(href!(scan_page, scan_id: new_id).resolve(cx))),
        Err(e) => {
            *lock(&app(cx).last_error) = Some(format!("Rescan not started: {e}"));
            Ok(see_other(href!(scan_page, scan_id: id).resolve(cx)))
        }
    }
}

/// Delete a finished/failed scan's report files and drop it from history.
/// Confirmed client-side; refused while running server-side.
#[route(POST "/scans/{scan_id}/delete")]
async fn delete_scan(cx: &Cx) -> Result<SeeOther> {
    let id = *scan_id(cx)?;
    if let Err(e) = app(cx).delete(id) {
        *lock(&app(cx).last_error) = Some(format!("Delete failed: {e}"));
    }
    Ok(see_other(href!(index).resolve(cx)))
}

// ---------- agent ----------

const MAX_AGENT_TURNS: usize = 20;

/// One exchange in the `/agent` transcript.
struct AgentTurn {
    question: String,
    answer: String,
    /// Tool names invoked, in order.
    tools: Vec<String>,
    /// Rendered as an error block when true.
    err: bool,
}

/// Build a run-ready agent: saved AI settings, builtin + store-backed
/// tools, and recalled lessons. Store is `reports/ntok.db` via a second
/// WAL connection — same pattern as the search page.
fn build_agent(app: &App) -> std::result::Result<ntok_core::agent::Agent, String> {
    let backend = ntok_core::agent::HttpChat::new(lock(&app.ai).clone())?;
    let store = std::sync::Arc::new(std::sync::Mutex::new(
        ntok_store::Store::open_default().map_err(|e| e.to_string())?,
    ));
    let mut tools = ntok_core::agent::builtin_tools();
    tools.extend(ntok_store::agent::agent_tools(store.clone()));
    let lessons = store
        .lock()
        .ok()
        .and_then(|s| s.memory_lessons(0.7, 6).ok())
        .unwrap_or_default();
    Ok(ntok_core::agent::Agent::new(Box::new(backend), tools).lessons(lessons))
}

#[page("/agent")]
async fn agent_page(cx: &Cx) -> Result<impl View> {
    let configured = lock(&app(cx).ai).validate().is_ok();
    let log: Vec<AgentTurn> = lock(&app(cx).agent_log)
        .iter()
        .map(|t| AgentTurn {
            question: t.question.clone(),
            answer: t.answer.clone(),
            tools: t.tools.clone(),
            err: t.err,
        })
        .collect();
    Ok(view! {
        <div class="page-head">
            <div>
                <span class="eyebrow">(ntok_core::brand::NAME) " · Agent"</span>
                <h1>"Recon agent"</h1>
            </div>
            <span class="sp"></span>
            <p class="lede">
                "Ask in plain language — the agent answers from your local scan index, "
                "report summaries, diffs, and its own memory. Read-only: it can propose "
                "a scan, never run one."
            </p>
        </div>
        if !configured {
            <div class="banner" style="margin-top:20px">
                "AI endpoint not configured — set a provider and key on "
                <a href=(href!(settings_page))>"Settings"</a>
                " (a keyless Ollama endpoint keeps every byte on this host)."
            </div>
        }
        <form class="panel" method="post" action=(href!(agent_ask)) style="margin-top:20px">
            <div class="field-in tall">
                (icons::ic(icons::EDIT))
                <textarea class="txt" name="question" rows="3" required="required"
                    placeholder="what changed on the lab net since last week? · any hosts with expired certs?"></textarea>
            </div>
            <div style="display:flex;gap:10px;align-items:center;margin-top:12px">
                <button class="btn" type="submit">(icons::ic(icons::SPARKLES))"Ask"</button>
                <span class="sub">"tools: search_index · recent_scans · scan_summary · diff_scans · service_lookup · propose_scan · memory"</span>
            </div>
        </form>
        if !log.is_empty() {
            <div class="sec" style="margin-top:24px">
                <div class="sec-head">
                    <p class="sec-title">"Transcript"</p>
                    <span class="pill acc">(format!("{} turns", log.len()))</span>
                </div>
                for t in &log {
                    <div class="panel" style="margin-top:14px">
                        <div class="p-sub" style="font-family:var(--mono)">"› " (t.question.clone())</div>
                        if t.err {
                            <div class="banner" style="margin-top:10px">(t.answer.clone())</div>
                        } else {
                            <p style="margin-top:10px;white-space:pre-wrap">(t.answer.clone())</p>
                        }
                        if !t.tools.is_empty() {
                            <div class="chips" style="margin-top:10px">
                                for tool in &t.tools {
                                    <span class="chip"><span class="cat">(tool.clone())</span></span>
                                }
                            </div>
                        }
                    </div>
                }
            </div>
        }
    })
}

#[derive(Deserialize)]
struct AgentForm {
    question: String,
}

#[route(POST "/agent")]
async fn agent_ask(cx: &Cx, Form(form): Form<AgentForm>) -> Result<SeeOther> {
    let question = form.question.trim().to_string();
    if question.is_empty() || question.len() > 4096 {
        return Ok(see_other(href!(agent_page).resolve(cx)));
    }
    let turn = match build_agent(app(cx)) {
        Ok(agent) => match agent.ask(&question).await {
            Ok(a) => AgentTurn {
                question,
                answer: a.text,
                tools: a.trace.iter().map(|t| t.name.clone()).collect(),
                err: false,
            },
            Err(e) => AgentTurn {
                question,
                answer: e.to_string(),
                tools: Vec::new(),
                err: true,
            },
        },
        Err(e) => AgentTurn {
            question,
            answer: e,
            tools: Vec::new(),
            err: true,
        },
    };
    let mut log = lock(&app(cx).agent_log);
    while log.len() >= MAX_AGENT_TURNS {
        log.pop_front();
    }
    log.push_back(turn);
    Ok(see_other(href!(agent_page).resolve(cx)))
}

#[cfg(test)]
mod tests {
    use super::Status;

    #[test]
    fn default_status_is_running() {
        assert!(Status::default().is_running());
    }
}
