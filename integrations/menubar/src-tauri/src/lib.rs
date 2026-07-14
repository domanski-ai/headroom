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

struct AppState {
    /// Validated loopback widget URL. Never changes after startup.
    widget_url: Url,
    /// True once the widget page finished loading in the webview.
    widget_loaded: AtomicBool,
    /// Result of the most recent reachability probe.
    last_probe_ok: AtomicBool,
    /// When the panel was last hidden because it lost focus.
    last_auto_hide: Mutex<Option<Instant>>,
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
    } else if loaded || force {
        // Widget gone (tunnel down): swap to the bundled fallback.
        state.widget_loaded.store(false, Ordering::SeqCst);
        let _ = window.navigate(fallback_page_url());
    } else {
        // Fallback already showing; just refresh its status line.
        push_fallback_status(&window, "down");
    }
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
    // Anchor at the tray icon, then show immediately; the probe + navigation
    // happens in the background. `TrayCenter` is platform-aware inside the
    // positioner (macOS: below the menu-bar icon; Windows: above the tray),
    // and `_constrained` keeps the panel on-screen at monitor edges.
    let _ = window.move_window_constrained(Position::TrayCenter);
    let _ = window.show();
    let _ = window.set_focus();
    sync_view_async(app, false);
}

/// Build the hidden popover webview window.
fn build_popover(app: &AppHandle, widget_url: &Url) -> tauri::Result<WebviewWindow> {
    // The window.open stub is non-configurable, so no page script can delete
    // it to restore the native popup path: new windows are denied outright.
    let init_script = format!(
        "window.__HEADROOM_WIDGET_URL__ = {};\n\
         Object.defineProperty(window, \"open\", {{\n\
           value: function () {{ return null; }},\n\
           writable: false, configurable: false\n\
         }});",
        js_string_literal(widget_url.as_str())
    );
    let navigation_widget = widget_url.clone();
    WebviewWindowBuilder::new(app, WINDOW_LABEL, WebviewUrl::App("index.html".into()))
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
        .transparent(true)
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

/// Build the tray icon with its context menu.
fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let refresh = MenuItem::with_id(app, "refresh", "Refresh", true, None::<&str>)?;
    let open_browser =
        MenuItem::with_id(app, "open-browser", "Open in Browser", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Headroom", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&refresh, &open_browser, &quit])?;

    TrayIconBuilder::with_id("headroom-tray")
        .icon(Image::from_bytes(include_bytes!("../icons/tray.png"))?)
        .icon_as_template(true)
        .tooltip("headroom")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "refresh" => sync_view_async(app, true),
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
        })
        .setup(move |app| {
            // Menu-bar app: no Dock icon / app switcher entry on macOS.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let handle = app.handle();
            build_popover(handle, &widget_url)?;
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
