//! headroom menu-bar / system-tray popover.
//!
//! A tray icon that toggles a frameless, always-on-top panel anchored under
//! (macOS) or above (Windows) the tray icon. The panel is a plain webview
//! pointed at the locally served liquid-glass widget page
//! (`http://127.0.0.1:8377/widget` by default, `HEADROOM_WIDGET_URL` to
//! override — loopback only, enforced).
//!
//! Security model: this app is a *viewer*, not a data path. It never reads
//! auth or credentials, exposes no IPC to the page (no capabilities), and the
//! webview is only ever allowed to navigate to the bundled fallback page,
//! `about:blank`, or the ONE configured widget document — everything else,
//! other loopback origins and paths included, is blocked in `on_navigation`.
//! A `localhost` override is pinned to `127.0.0.1` at startup, so neither the
//! probe nor any navigation ever consults the OS resolver (a poisoned hosts
//! file or DNS entry cannot redirect the panel to a public IP), and
//! `window.open` is neutered with a non-configurable stub before any page
//! runs.

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    webview::PageLoadEvent,
    AppHandle, Manager, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent,
};
use tauri_plugin_positioner::{Position, WindowExt};

mod icon;

/// Default widget URL; the fleet dashboard serves `/widget` on this port.
const DEFAULT_WIDGET_URL: &str = "http://127.0.0.1:8377/widget";
/// Env var that overrides the widget URL (validated: loopback http only).
const WIDGET_URL_ENV: &str = "HEADROOM_WIDGET_URL";
const WINDOW_LABEL: &str = "popover";
const WINDOW_WIDTH: f64 = 360.0;
const WINDOW_HEIGHT: f64 = 640.0;
/// TCP connect + HTTP response-read budget for the reachability probe.
const PROBE_TIMEOUT: Duration = Duration::from_millis(600);
/// How often the background watcher retries while the fallback page is shown.
const RETRY_INTERVAL: Duration = Duration::from_secs(3);
/// Clicking the tray icon while the panel is open fires focus-loss (hide)
/// first and the click event second; suppress the immediate re-open.
const REOPEN_SUPPRESS: Duration = Duration::from_millis(350);
/// How often the tray icon's battery level re-reads the widget feed.
const ICON_INTERVAL: Duration = Duration::from_secs(60);
/// Corner radius of the popover panel (matches the system panels).
const PANEL_RADIUS: f64 = 14.0;
/// Reject a runaway feed body instead of buffering it (the real feed is a
/// few KB).
const FEED_MAX_BYTES: usize = 256 * 1024;
/// Wall-clock bound for one whole feed exchange — a drip-feeding endpoint
/// must not hold a worker thread open indefinitely.
const FEED_DEADLINE: Duration = Duration::from_secs(6);

struct AppState {
    /// Validated loopback widget URL. Never changes after startup.
    widget_url: Url,
    /// True once the widget page finished loading in the webview.
    widget_loaded: AtomicBool,
    /// Result of the most recent reachability probe.
    last_probe_ok: AtomicBool,
    /// When the panel was last hidden because it lost focus.
    last_auto_hide: Mutex<Option<Instant>>,
    /// The tray icon's screen rect from its most recent event, for anchoring
    /// the panel like a native menu-bar popover (right edges aligned).
    last_tray_rect: Mutex<Option<tauri::Rect>>,
}

/// Resolve the widget URL from the environment, falling back to the default
/// if it is missing or fails loopback validation.
fn resolve_widget_url() -> Url {
    let default = Url::parse(DEFAULT_WIDGET_URL).expect("default widget URL is valid");
    let Some(raw) = std::env::var(WIDGET_URL_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        return default;
    };
    match Url::parse(&raw) {
        Ok(url) if url.scheme() == "http" && is_acceptable_widget_host(&url) => {
            canonicalize_loopback(url)
        }
        Ok(_) => {
            eprintln!(
                "headroom-menubar: {WIDGET_URL_ENV}={raw} is not a loopback http URL; \
                 using {DEFAULT_WIDGET_URL}"
            );
            default
        }
        Err(err) => {
            eprintln!(
                "headroom-menubar: {WIDGET_URL_ENV}={raw} is not a valid URL ({err}); \
                 using {DEFAULT_WIDGET_URL}"
            );
            default
        }
    }
}

/// NUMERIC-loopback-only host check: a literal `127.0.0.0/8` or `::1`
/// address. A hostname — `localhost` included — is NOT accepted here: names
/// go through the OS resolver, and a poisoned hosts file or DNS entry could
/// answer with a public IP.
fn is_loopback_host(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Accepted spellings for the env override: a numeric loopback literal, or
/// the literal `localhost` name — which is then PINNED to `127.0.0.1` by
/// `canonicalize_loopback` without ever consulting the resolver.
fn is_acceptable_widget_host(url: &Url) -> bool {
    url.host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case("localhost"))
        || is_loopback_host(url)
}

/// Pin a `localhost` host to the numeric IPv4 loopback literal. After this,
/// nothing — the probe, webview navigation, or "Open in Browser" — carries a
/// resolvable name.
fn canonicalize_loopback(mut url: Url) -> Url {
    if url
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case("localhost"))
    {
        url.set_host(Some("127.0.0.1"))
            .expect("http URL accepts a loopback IP host");
    }
    url
}

/// URL of the bundled offline-fallback page (`dist/index.html`) as served by
/// Tauri's embedded asset protocol. Windows uses `http://tauri.localhost`,
/// macOS/Linux use `tauri://localhost` (`useHttpsScheme` is left at its
/// default of `false`).
fn fallback_page_url() -> Url {
    let raw = if cfg!(windows) {
        "http://tauri.localhost/index.html"
    } else {
        "tauri://localhost/index.html"
    };
    Url::parse(raw).expect("static fallback URL is valid")
}

/// True when `url` IS this platform's bundled fallback document. Tauri
/// simplifies `WebviewUrl::App("index.html")` to the asset-origin BASE for
/// the initial navigation (`tauri://localhost` with an empty path), while
/// our explicit fallback navigations use `/index.html` — so the base, its
/// `/` form, and `/index.html` are the three spellings of this ONE document.
/// Nothing else on the origin passes (no other assets, ports, queries, or
/// the other platform's asset form: on macOS/Linux `http://tauri.localhost`
/// is ordinary HTTP to a resolvable hostname).
fn is_bundled_page(url: &Url) -> bool {
    let fallback = fallback_page_url();
    url.scheme() == fallback.scheme()
        && url.host_str() == fallback.host_str()
        && url.port() == fallback.port()
        && matches!(url.path(), "" | "/" | "/index.html")
        && url.query().is_none()
        && url.fragment().is_none()
}

/// Navigation policy for the webview: ONLY the bundled fallback page, the
/// initial blank document (`about:blank` exactly — no other `about:` URL),
/// and the ONE configured widget document (scheme, numeric loopback host,
/// port, path, and query all equal). Everything else — remote origins,
/// other loopback origins, other paths on the widget origin — is refused.
fn navigation_allowed(widget: &Url, url: &Url) -> bool {
    if url.as_str() == "about:blank" || is_bundled_page(url) {
        return true;
    }
    url.scheme() == widget.scheme()
        && is_loopback_host(url)
        && url.host_str() == widget.host_str()
        && url.port_or_known_default() == widget.port_or_known_default()
        && url.path() == widget.path()
        && url.query() == widget.query()
}

/// Cheap HTTP reachability probe, run off the UI thread. A bare TCP connect
/// is not enough: an `ssh -L` listener accepts even when the remote side is
/// down, so require at least the start of an HTTP response.
fn server_reachable(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    // numeric loopback only — the probe NEVER performs a resolver lookup
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false;
    };
    if !ip.is_loopback() {
        return false;
    }
    let port = url.port_or_known_default().unwrap_or(80);
    let addr = std::net::SocketAddr::new(ip, port);
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(PROBE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(PROBE_TIMEOUT));
    let request = format!(
        "HEAD {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        url.path(),
        host,
        port
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).is_ok() && &buf == b"HTTP/"
}

/// GET a small same-origin document from the widget server over the same
/// numeric-loopback-only raw socket the reachability probe uses (never a
/// resolver lookup, never a non-loopback address). Returns the response body
/// for an exact 200 with no transfer-encoding tricks; None on anything else.
/// The whole exchange is bounded by a wall-clock deadline — a drip-feeding
/// endpoint can't hold the worker beyond it.
fn fetch_loopback(url: &Url, path: &str) -> Option<String> {
    let host = url.host_str()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ip: std::net::IpAddr = host.parse().ok()?;
    if !ip.is_loopback() {
        return None;
    }
    let port = url.port_or_known_default().unwrap_or(80);
    let deadline = Instant::now() + FEED_DEADLINE;
    let mut stream =
        TcpStream::connect_timeout(&std::net::SocketAddr::new(ip, port), PROBE_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;
    // bracket IPv6 literals: an unbracketed `Host: ::1:8377` is malformed
    let host_header = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > FEED_MAX_BYTES {
                    return None;
                }
            }
            // a 1s read timeout loops back to the deadline check above
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
                || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return None,
        }
    }
    let text = String::from_utf8(raw).ok()?;
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status_line = head.lines().next()?;
    // exact status parse: "HTTP/1.x 200 ..." — not a prefix match
    let mut parts = status_line.split(' ');
    let version_ok = matches!(parts.next(), Some("HTTP/1.1") | Some("HTTP/1.0"));
    if !version_ok || parts.next() != Some("200") {
        return None;
    }
    if head.to_ascii_lowercase().contains("transfer-encoding") {
        return None;
    }
    Some(body.to_owned())
}

/// The fleet's average 5h battery as a fraction, from `/widget.json` on the
/// widget server — applying the SAME fail-closed feed contract as the
/// JavaScript clients before trusting a single number: exact schema, a
/// current freshness block with sane timing (no future evaluation beyond a
/// small NTP tolerance, age within the snapshot window), and only live
/// (current/limited) accounts' 5h windows. A current window contributes its
/// left_percent, a limited one an honest 0; held/stale never count. `None`
/// when anything is off — the icon then shows the no-reading dash.
fn fetch_avg_battery(widget: &Url) -> Option<f32> {
    let body = fetch_loopback(widget, "/widget.json")?;
    let value: serde_json::Value = serde_json::from_str(&body).ok()?;
    if value.get("schema").and_then(|s| s.as_str()) != Some("headroom_widget@1") {
        return None;
    }
    let freshness = value.get("freshness")?;
    if freshness.get("state").and_then(|s| s.as_str()) != Some("current") {
        return None;
    }
    let evaluated_at = freshness.get("evaluated_at").and_then(|v| v.as_f64())?;
    let age = freshness.get("age_seconds").and_then(|v| v.as_f64())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs_f64();
    if !evaluated_at.is_finite() || !age.is_finite() || age < 0.0 {
        return None;
    }
    if evaluated_at > now + 10.0 {
        return None; // future evaluation beyond NTP tolerance: never trust
    }
    if age + (now - evaluated_at).max(0.0) > 900.0 {
        return None; // outside the snapshot freshness window: held, not live
    }
    let accounts = value.get("accounts")?.as_array()?;
    let mut sum = 0.0f64;
    let mut count = 0u32;
    for account in accounts {
        let account_state = account.get("state").and_then(|s| s.as_str());
        if !matches!(account_state, Some("current") | Some("limited")) {
            continue;
        }
        let window = account.get("windows").and_then(|w| w.get("5h"));
        let state = window.and_then(|w| w.get("state")).and_then(|s| s.as_str());
        match state {
            Some("current") => {
                let Some(left) = window
                    .and_then(|w| w.get("left_percent"))
                    .and_then(|v| v.as_f64())
                else {
                    continue;
                };
                if (0.0..=100.0).contains(&left) {
                    sum += left;
                    count += 1;
                }
            }
            Some("limited") => {
                count += 1; // an exhausted tank is an honest 0, not missing
            }
            _ => {}
        }
    }
    (count > 0).then(|| (sum / f64::from(count) / 100.0) as f32)
}

/// One icon fetch in flight at a time: manual Refresh spam and a slow feed
/// must not accumulate worker threads.
static ICON_FETCH_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Redraw the tray icon (and tooltip) from the latest feed reading.
fn update_tray_icon(app: &AppHandle) {
    if ICON_FETCH_ACTIVE.swap(true, Ordering::SeqCst) {
        return; // a fetch is already running; it will paint the result
    }
    let level = fetch_avg_battery(&app.state::<AppState>().widget_url);
    ICON_FETCH_ACTIVE.store(false, Ordering::SeqCst);
    let Some(tray) = app.tray_by_id("headroom-tray") else {
        return;
    };
    let (rgba, width, height) = icon::tray_icon_rgba(level);
    let _ = tray.set_icon(Some(Image::new_owned(rgba, width, height)));
    let _ = tray.set_icon_as_template(true);
    let tooltip = match level {
        Some(level) => format!("headroom — avg 5h battery {}%", (level * 100.0).round()),
        None => "headroom — no live reading".to_owned(),
    };
    let _ = tray.set_tooltip(Some(tooltip));
}

/// Escape a string for embedding inside a double-quoted JS string literal.
fn js_string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '<' => out.push_str("\\u003c"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Tell the fallback page (if it is the current document) what state we are
/// in: `"probing"` or `"down"`. No-op on any other page.
fn push_fallback_status(window: &WebviewWindow, status: &str) {
    let script = format!(
        "window.__headroomStatus && window.__headroomStatus({});",
        js_string_literal(status)
    );
    let _ = window.eval(&script);
}

/// Probe the widget server and point the webview at the right document:
/// widget page when reachable, bundled fallback when not. `force` reloads
/// the widget page even if it is already loaded (menu "Refresh").
///
/// Blocking (network probe) — always call from a worker thread.
fn sync_view(app: &AppHandle, force: bool) {
    let Some(window) = app.get_webview_window(WINDOW_LABEL) else {
        return;
    };
    let state = app.state::<AppState>();
    let reachable = server_reachable(&state.widget_url);
    state.last_probe_ok.store(reachable, Ordering::SeqCst);
    let loaded = state.widget_loaded.load(Ordering::SeqCst);

    if reachable {
        if force || !loaded {
            let _ = window.navigate(state.widget_url.clone());
        }
    } else if !loaded {
        // Nothing ever loaded (cold start with the tunnel down): the bundled
        // fallback with its tunnel hint is the only useful view.
        let _ = window.navigate(fallback_page_url());
        push_fallback_status(&window, "down");
    }
    // else: the widget page is already showing — KEEP IT. The page demotes
    // itself (staleness banner, held tones) through its own failed feed
    // fetches; a probe failure must never replace live content with an
    // error page (the last known reading beats a dead-end screen).
}

/// Run `sync_view` on a worker thread so tray/menu handlers never block the
/// UI thread on a network probe.
fn sync_view_async(app: &AppHandle, force: bool) {
    let app = app.clone();
    std::thread::spawn(move || sync_view(&app, force));
}

/// Toggle the popover like a native menu-bar panel.
fn toggle_popover(app: &AppHandle) {
    let Some(window) = app.get_webview_window(WINDOW_LABEL) else {
        return;
    };
    if window.is_visible().unwrap_or(false) {
        let _ = window.hide();
        return;
    }
    let state = app.state::<AppState>();
    // If the click that re-focused the tray icon just auto-hid the panel,
    // this click means "close" — don't instantly re-open it.
    if let Some(hidden_at) = *state
        .last_auto_hide
        .lock()
        .expect("last_auto_hide poisoned")
    {
        if hidden_at.elapsed() < REOPEN_SUPPRESS {
            return;
        }
    }
    // Anchor like a native menu-bar popover: the panel's RIGHT edge aligns
    // with the icon's right edge, directly below the menu bar (macOS). The
    // positioner presets can't express right-edge alignment, so the panel is
    // placed from the tray rect captured off the click event; when no rect
    // has been seen yet (or off macOS), fall back to the platform-aware
    // constrained TrayCenter.
    if !anchor_below_tray(&window, app) {
        let _ = window.move_window_constrained(Position::TrayCenter);
    }
    let _ = window.show();
    let _ = window.set_focus();
    sync_view_async(app, false);
}

/// Place the panel right-edge-aligned under the tray icon (macOS layout).
/// Returns false when the placement can't be computed.
fn anchor_below_tray(window: &WebviewWindow, app: &AppHandle) -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    let rect = *app
        .state::<AppState>()
        .last_tray_rect
        .lock()
        .expect("last_tray_rect poisoned");
    let Some(rect) = rect else {
        return false;
    };
    let scale = window.scale_factor().unwrap_or(1.0);
    let to_logical_pos = |value: tauri::Position| match value {
        tauri::Position::Physical(p) => (f64::from(p.x) / scale, f64::from(p.y) / scale),
        tauri::Position::Logical(p) => (p.x, p.y),
    };
    let to_logical_size = |value: tauri::Size| match value {
        tauri::Size::Physical(s) => (f64::from(s.width) / scale, f64::from(s.height) / scale),
        tauri::Size::Logical(s) => (s.width, s.height),
    };
    let (tray_x, tray_y) = to_logical_pos(rect.position);
    let (tray_w, tray_h) = to_logical_size(rect.size);
    let mut x = tray_x + tray_w - WINDOW_WIDTH; // right edges aligned
    let y = tray_y + tray_h + 5.0; // just below the menu bar
    // clamp against the monitor that CONTAINS the tray icon — the hidden
    // window's current monitor may be a different display entirely
    let monitor = monitor_containing(window, tray_x, tray_y)
        .or_else(|| window.current_monitor().ok().flatten());
    if let Some(monitor) = monitor {
        let monitor_scale = monitor.scale_factor();
        let position = monitor.position().to_logical::<f64>(monitor_scale);
        let size = monitor.size().to_logical::<f64>(monitor_scale);
        x = x
            .max(position.x + 8.0)
            .min(position.x + size.width - WINDOW_WIDTH - 8.0);
    }
    window
        .set_position(tauri::LogicalPosition::new(x, y))
        .is_ok()
}

/// The monitor whose logical bounds contain the given point, if any.
#[cfg(target_os = "macos")]
fn monitor_containing(
    window: &WebviewWindow,
    x: f64,
    y: f64,
) -> Option<tauri::Monitor> {
    for monitor in window.available_monitors().ok()? {
        let scale = monitor.scale_factor();
        let position = monitor.position().to_logical::<f64>(scale);
        let size = monitor.size().to_logical::<f64>(scale);
        if x >= position.x
            && x < position.x + size.width
            && y >= position.y
            && y < position.y + size.height
        {
            return Some(monitor);
        }
    }
    None
}

/// Build the hidden popover webview window.
fn build_popover(app: &AppHandle, widget_url: &Url) -> tauri::Result<WebviewWindow> {
    // The window.open stub is non-configurable, so no page script can delete
    // it to restore the native popup path: new windows are denied outright.
    //
    // On macOS the window itself provides the native panel chrome (HUD
    // vibrancy + rounded corners via window effects), so the widget page's
    // own wall — the gradient, grid, and blobs behind the glass card — is
    // stripped with injected CSS and the glass card sits directly on the
    // real material, like a system popover. Elsewhere the page keeps its
    // bundled wall.
    let embed_css = if cfg!(target_os = "macos") {
        // The system's popover material provides the frost; the page lays a
        // dark tint OVER it so the panel stays legible on light content
        // behind the window — the same trick the built-in dark panels use
        // (pure vibrancy alone washes out ~40% white-through on a white
        // page). Tint alpha tuned to match the system Bluetooth/Wi-Fi
        // panels' density. backdrop-filter must stay off — it forces an
        // opaque layer in WKWebView and blacks out window transparency.
        "html,body{background:transparent !important}\
         .hr{background:transparent !important;padding:0 !important}\
         .hr-wall{display:none !important}\
         .hr-pop{width:100% !important;max-width:none !important;\
                 min-height:100vh;border:0 !important;\
                 border-radius:0 !important;\
                 background:rgba(13,16,24,.62) !important;\
                 backdrop-filter:none !important;\
                 -webkit-backdrop-filter:none !important;\
                 box-shadow:none !important}"
    } else {
        ""
    };
    let init_script = format!(
        "window.__HEADROOM_WIDGET_URL__ = {widget};\n\
         Object.defineProperty(window, \"open\", {{\n\
           value: function () {{ return null; }},\n\
           writable: false, configurable: false\n\
         }});\n\
         addEventListener(\"DOMContentLoaded\", function () {{\n\
           var css = {css};\n\
           if (!css || location.href !== window.__HEADROOM_WIDGET_URL__) return;\n\
           var style = document.createElement(\"style\");\n\
           style.textContent = css;\n\
           document.head.appendChild(style);\n\
         }});",
        widget = js_string_literal(widget_url.as_str()),
        css = js_string_literal(embed_css)
    );
    let navigation_widget = widget_url.clone();
    let builder = WebviewWindowBuilder::new(app, WINDOW_LABEL, WebviewUrl::App("index.html".into()))
        .title("headroom")
        .inner_size(WINDOW_WIDTH, WINDOW_HEIGHT)
        .visible(false)
        .decorations(false)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .closable(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .visible_on_all_workspaces(true)
        .transparent(true);
    // The system's adaptive popover material provides the standard dropdown
    // background; the page paints nothing over it. Dark theme pinned so the
    // widget's ink colors always sit on the dark material.
    #[cfg(target_os = "macos")]
    let builder = builder
        .theme(Some(tauri::Theme::Dark))
        .effects(tauri::utils::config::WindowEffectsConfig {
            effects: vec![tauri::utils::WindowEffect::Popover],
            state: Some(tauri::utils::WindowEffectState::Active),
            radius: Some(PANEL_RADIUS),
            color: None,
        });
    builder
        .initialization_script(&init_script)
        .on_navigation(move |url| {
            let allowed = navigation_allowed(&navigation_widget, url);
            if !allowed {
                eprintln!(
                    "headroom-menubar: blocked navigation outside the widget document: {url}"
                );
            }
            allowed
        })
        .on_page_load(|window, payload| {
            if payload.event() != PageLoadEvent::Finished {
                return;
            }
            let state = window.app_handle().state::<AppState>();
            let on_widget = {
                let current = payload.url();
                let widget = &state.widget_url;
                current.scheme() == widget.scheme()
                    && current.host_str() == widget.host_str()
                    && current.port_or_known_default() == widget.port_or_known_default()
            };
            state.widget_loaded.store(on_widget, Ordering::SeqCst);
            if !on_widget && !state.last_probe_ok.load(Ordering::SeqCst) {
                push_fallback_status(&window, "down");
            }
        })
        .build()
}

/// Round the window's contentView layer so EVERYTHING in the window — the
/// native material AND the webview above it — is clipped to the popover
/// radius. (The effect view's own radius cannot clip the webview, which is
/// why CSS-only rounding left square material corners peeking out.) The
/// window shadow is recomputed from the clipped shape.
#[cfg(target_os = "macos")]
fn round_window_corners(window: &WebviewWindow, radius: f64) {
    use objc2::msg_send;
    use objc2::runtime::{AnyObject, Bool};
    let Ok(ns_window) = window.ns_window() else {
        return;
    };
    let ns_window = ns_window.cast::<AnyObject>();
    if ns_window.is_null() {
        return;
    }
    unsafe {
        let content_view: *mut AnyObject = msg_send![ns_window, contentView];
        if content_view.is_null() {
            return;
        }
        let _: () = msg_send![content_view, setWantsLayer: Bool::YES];
        let layer: *mut AnyObject = msg_send![content_view, layer];
        if layer.is_null() {
            return;
        }
        let _: () = msg_send![layer, setCornerRadius: radius];
        let _: () = msg_send![layer, setMasksToBounds: Bool::YES];
        let _: () = msg_send![ns_window, invalidateShadow];
    }
}

/// Build the tray icon with its context menu.
fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let refresh = MenuItem::with_id(app, "refresh", "Refresh", true, None::<&str>)?;
    let open_browser =
        MenuItem::with_id(app, "open-browser", "Open in Browser", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Headroom", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&refresh, &open_browser, &quit])?;

    // Startup icon: the battery-head with no reading yet; the feed watcher
    // fills the level in as soon as /widget.json answers.
    let (rgba, width, height) = icon::tray_icon_rgba(None);
    TrayIconBuilder::with_id("headroom-tray")
        .icon(Image::new_owned(rgba, width, height))
        .icon_as_template(true)
        .tooltip("headroom")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "refresh" => {
                sync_view_async(app, true);
                let icon_app = app.clone();
                std::thread::spawn(move || update_tray_icon(&icon_app));
            }
            "open-browser" => {
                let url = app.state::<AppState>().widget_url.clone();
                if let Err(err) = open::that_detached(url.as_str()) {
                    eprintln!("headroom-menubar: failed to open browser: {err}");
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // Feed the positioner so Position::Tray* knows where the icon is.
            tauri_plugin_positioner::on_tray_event(tray.app_handle(), &event);
            // Remember the icon's rect for native-style right-edge anchoring.
            if let TrayIconEvent::Click { rect, .. }
            | TrayIconEvent::Enter { rect, .. }
            | TrayIconEvent::Move { rect, .. } = &event
            {
                let app = tray.app_handle();
                *app.state::<AppState>()
                    .last_tray_rect
                    .lock()
                    .expect("last_tray_rect poisoned") = Some(*rect);
            }
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_popover(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

pub fn run() {
    let widget_url = resolve_widget_url();

    tauri::Builder::default()
        .plugin(tauri_plugin_positioner::init())
        .manage(AppState {
            widget_url: widget_url.clone(),
            widget_loaded: AtomicBool::new(false),
            last_probe_ok: AtomicBool::new(false),
            last_auto_hide: Mutex::new(None),
            last_tray_rect: Mutex::new(None),
        })
        .setup(move |app| {
            // Menu-bar app: no Dock icon / app switcher entry on macOS.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let handle = app.handle();
            build_popover(handle, &widget_url)?;
            #[cfg(target_os = "macos")]
            if let Some(window) = handle.get_webview_window(WINDOW_LABEL) {
                round_window_corners(&window, PANEL_RADIUS);
            }
            build_tray(handle)?;

            // Warm the view so the first click shows content instantly, then
            // keep retrying in the background while the fallback is visible.
            sync_view_async(handle, false);
            let watcher = handle.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(RETRY_INTERVAL);
                let Some(window) = watcher.get_webview_window(WINDOW_LABEL) else {
                    continue;
                };
                let state = watcher.state::<AppState>();
                let visible = window.is_visible().unwrap_or(false);
                if visible && !state.widget_loaded.load(Ordering::SeqCst) {
                    sync_view(&watcher, false);
                }
            });
            // Keep the tray icon's battery level current (worker thread —
            // the feed read is a blocking loopback fetch).
            let icon_watcher = handle.clone();
            std::thread::spawn(move || loop {
                update_tray_icon(&icon_watcher);
                std::thread::sleep(ICON_INTERVAL);
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != WINDOW_LABEL {
                return;
            }
            match event {
                // Native popover behaviour: clicking away hides the panel.
                WindowEvent::Focused(false) => {
                    let _ = window.hide();
                    let state = window.app_handle().state::<AppState>();
                    *state
                        .last_auto_hide
                        .lock()
                        .expect("last_auto_hide poisoned") = Some(Instant::now());
                }
                // No visible close button, but if a close ever arrives
                // (Cmd+W, taskbar), hide instead of destroying the window.
                WindowEvent::CloseRequested { api, .. } => {
                    api.prevent_close();
                    let _ = window.hide();
                }
                _ => {}
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running headroom menubar app");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> Url {
        Url::parse(raw).expect("test URL parses")
    }

    #[test]
    fn numeric_loopback_hosts_are_accepted() {
        assert!(is_loopback_host(&url("http://127.0.0.1:8377/widget")));
        assert!(is_loopback_host(&url("http://127.0.0.53:8377/widget")));
        assert!(is_loopback_host(&url("http://[::1]:8377/widget")));
    }

    #[test]
    fn hostnames_are_rejected_even_localhost() {
        // `localhost` goes through the resolver — a poisoned hosts file or
        // DNS entry could answer with a public IP, so the name is never
        // trusted at probe/navigation time (it is pinned at startup instead)
        assert!(!is_loopback_host(&url("http://localhost:8377/widget")));
        assert!(!is_loopback_host(&url("http://192.168.1.10:8377/widget")));
        assert!(!is_loopback_host(&url("http://example.com/widget")));
        assert!(!is_loopback_host(&url("http://10.0.0.1/")));
        assert!(!is_loopback_host(&url("http://[fe80::1]:8377/")));
    }

    #[test]
    fn localhost_is_pinned_to_numeric_loopback() {
        assert!(is_acceptable_widget_host(&url(
            "http://localhost:8377/widget"
        )));
        assert!(is_acceptable_widget_host(&url(
            "http://127.0.0.1:8377/widget"
        )));
        assert!(!is_acceptable_widget_host(&url("http://example.com:8377/")));
        assert_eq!(
            canonicalize_loopback(url("http://localhost:8377/widget")).as_str(),
            "http://127.0.0.1:8377/widget"
        );
        assert_eq!(
            canonicalize_loopback(url("http://LOCALHOST:8377/widget")).as_str(),
            "http://127.0.0.1:8377/widget"
        );
        // already-numeric URLs pass through untouched
        assert_eq!(
            canonicalize_loopback(url("http://127.0.0.53:9000/x")).as_str(),
            "http://127.0.0.53:9000/x"
        );
    }

    #[test]
    fn navigation_policy_is_exact_widget_document_or_bundled_only() {
        let widget = url("http://127.0.0.1:8377/widget");
        assert!(navigation_allowed(&widget, &widget));
        assert!(navigation_allowed(&widget, &fallback_page_url()));
        // the INITIAL navigation: tauri simplifies WebviewUrl::App to the
        // asset-origin base — both base spellings must pass or the popover
        // never loads its own fallback document at startup
        if cfg!(windows) {
            assert!(navigation_allowed(&widget, &url("http://tauri.localhost")));
            assert!(navigation_allowed(&widget, &url("http://tauri.localhost/")));
        } else {
            assert!(navigation_allowed(&widget, &url("tauri://localhost")));
            assert!(navigation_allowed(&widget, &url("tauri://localhost/")));
        }
        assert!(navigation_allowed(&widget, &url("about:blank")));
        // the bundled exception is the EXACT platform fallback document,
        // never its origin: other assets, ports, or the other platform's
        // asset-protocol form are all refused
        assert!(!navigation_allowed(
            &widget,
            &url("tauri://localhost/main.js")
        ));
        assert!(!navigation_allowed(
            &widget,
            &url("http://tauri.localhost:9000/not-index?x=1")
        ));
        if cfg!(windows) {
            assert!(!navigation_allowed(
                &widget,
                &url("tauri://localhost/index.html")
            ));
        } else {
            assert!(!navigation_allowed(
                &widget,
                &url("http://tauri.localhost/index.html")
            ));
        }
        // NOT the configured document: other paths, ports, queries, origins
        assert!(!navigation_allowed(&widget, &url("http://127.0.0.1:8377/")));
        assert!(!navigation_allowed(
            &widget,
            &url("http://127.0.0.1:8377/widget?size=small")
        ));
        assert!(!navigation_allowed(
            &widget,
            &url("http://127.0.0.1:9999/widget")
        ));
        assert!(!navigation_allowed(
            &widget,
            &url("http://127.0.0.53:8377/widget")
        ));
        assert!(!navigation_allowed(
            &widget,
            &url("http://localhost:8377/widget")
        ));
        // only the blank initial document, not other about: URLs
        assert!(!navigation_allowed(&widget, &url("about:srcdoc")));
        assert!(!navigation_allowed(&widget, &url("https://example.com/")));
        assert!(!navigation_allowed(&widget, &url("http://example.com/")));
        assert!(!navigation_allowed(
            &widget,
            &url("https://127.0.0.1:8377/widget")
        ));
        assert!(!navigation_allowed(&widget, &url("file:///etc/passwd")));
        assert!(!navigation_allowed(
            &widget,
            &url("http://127.0.0.1.evil.com/widget")
        ));
        // a widget URL carrying a query allows exactly that document
        let sized = url("http://127.0.0.1:8377/widget?size=small");
        assert!(navigation_allowed(&sized, &sized));
        assert!(!navigation_allowed(
            &sized,
            &url("http://127.0.0.1:8377/widget")
        ));
    }

    #[test]
    fn js_string_literal_escapes() {
        assert_eq!(js_string_literal("plain"), "\"plain\"");
        assert_eq!(
            js_string_literal("a\"b\\c\n<script>"),
            "\"a\\\"b\\\\c\\n\\u003cscript>\""
        );
    }
}
