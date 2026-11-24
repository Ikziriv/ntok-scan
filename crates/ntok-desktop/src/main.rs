//! ntok desktop app — spawns `ntok-web` on a private localhost port with
//! the OS data dir as its working directory (so `reports/` and `ntok.db`
//! land under the user's profile, not next to the binary), then loads the
//! UI in a native webview window.
//!
//! Ship `ntok-web` next to this binary for a double-click install, or
//! have it on PATH. If the webview can't start (e.g. no WebView2 on an
//! old Windows install) it falls back to opening the system browser —
//! same server, same UX, minus the app window.
//!
//! shortcut: the fallback browser mode leaves `ntok-web` running if the
//! console is closed abruptly; the Tauri path kills it on Exit.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::Manager;

fn io_err(msg: &str) -> io::Error {
    io::Error::other(msg.to_string())
}

/// Where reports, the index DB, and auth accounts live.
/// `NTOK_DATA_DIR` overrides; else the per-OS user data dir.
fn data_dir() -> io::Result<PathBuf> {
    if let Some(d) = std::env::var_os("NTOK_DATA_DIR") {
        return Ok(PathBuf::from(d));
    }
    if cfg!(windows) {
        return std::env::var_os("APPDATA")
            .map(|d| PathBuf::from(d).join("ntok"))
            .ok_or_else(|| io_err("APPDATA is not set"));
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io_err("HOME is not set"))?;
    Ok(if cfg!(target_os = "macos") {
        home.join("Library/Application Support/ntok")
    } else {
        home.join(".local/share/ntok")
    })
}

/// `ntok-web` next to this binary first (the installer layout), then PATH.
fn ntok_web() -> io::Result<PathBuf> {
    let exe = if cfg!(windows) {
        "ntok-web.exe"
    } else {
        "ntok-web"
    };
    if let Ok(me) = std::env::current_exe()
        && let Some(dir) = me.parent()
    {
        let sib = dir.join(exe);
        if sib.is_file() {
            return Ok(sib);
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let p = dir.join(exe);
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    Err(io_err(
        "ntok-web not found — put it next to ntok-desktop or on PATH",
    ))
}

/// A free localhost port. The listener is dropped before `ntok-web`
/// binds — a tiny race, irrelevant on a single-user machine.
fn free_port() -> io::Result<u16> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
        .local_addr()?
        .port())
}

/// Spawn the sidecar; returns the child and the URL it will serve.
fn start_server() -> io::Result<(Child, String)> {
    let dir = data_dir()?;
    std::fs::create_dir_all(&dir)?;
    let web = ntok_web()?;
    let port = free_port()?;
    let mut cmd = Command::new(&web);
    cmd.current_dir(&dir)
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("NTOK_DATA_DIR", &dir)
        .env("NTOK_SURFACE", "desktop")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Private ephemeral loopback port for single-user desktop UX; honor explicit NTOK_AUTH override.
    if std::env::var_os("NTOK_AUTH").is_none() {
        cmd.env("NTOK_AUTH", "off");
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| io_err(&format!("spawning {}: {e}", web.display())))?;
    eprintln!("NTOK SCAN desktop → http://127.0.0.1:{port}");
    eprintln!("data dir          → {}", dir.display());
    wait_ready(port, &mut child);
    Ok((child, format!("http://127.0.0.1:{port}")))
}

/// Poll until the server accepts connections, the child dies, or 15s.
fn wait_ready(port: u16, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok()
            || child.try_wait().ok().flatten().is_some()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn open_browser(url: &str) {
    let r = if cfg!(windows) {
        Command::new("cmd").args(["/c", "start", "", url]).spawn()
    } else if cfg!(target_os = "macos") {
        Command::new("open").arg(url).spawn()
    } else {
        Command::new("xdg-open").arg(url).spawn()
    };
    if let Err(e) = r {
        eprintln!("could not open a browser ({e}) — visit {url} yourself");
    }
}

/// Fallback when no webview is available: same server, system browser.
fn run_browser() -> io::Result<()> {
    let (mut child, url) = start_server()?;
    eprintln!("Ctrl-C quits the app.");
    open_browser(&url);
    let status = child.wait()?;
    eprintln!("ntok-web exited: {status}");
    Ok(())
}

fn run_tauri() -> tauri::Result<()> {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(Mutex::new(Option::<Child>::None));
            // Render the branded splash immediately (zero blank flash), then boot
            // `ntok-web` on a background thread and navigate once listening.
            let win = tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("index.html".into()),
            )
            .title("NTOK SCAN — Discover. Analyze. Secure.")
            .inner_size(1400.0, 900.0)
            .min_inner_size(960.0, 640.0)
            .center()
            .build()?;

            let handle = app.handle().clone();
            std::thread::spawn(move || match start_server() {
                Ok((child, url)) => {
                    if let Some(slot) = handle.try_state::<Mutex<Option<Child>>>()
                        && let Ok(mut guard) = slot.lock()
                    {
                        *guard = Some(child);
                    }
                    if let Ok(parsed) = url.parse::<tauri::Url>() {
                        let _ = win.navigate(parsed);
                    }
                }
                Err(e) => {
                    let msg = format!("{e}")
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"")
                        .replace('\n', " ");
                    let _ = win.eval(format!("window.__ntokBootError(\"{msg}\")"));
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())?
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event
                && let Some(slot) = app.try_state::<Mutex<Option<Child>>>()
                && let Ok(mut guard) = slot.lock()
                && let Some(mut child) = guard.take()
            {
                let _ = child.kill();
            }
        });
    Ok(())
}

fn main() {
    if let Err(e) = run_tauri() {
        eprintln!("no app window ({e}) — falling back to your browser");
        if let Err(e) = run_browser() {
            eprintln!("ntok-desktop: {e}");
            std::process::exit(1);
        }
    }
}
