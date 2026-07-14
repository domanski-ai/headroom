# headroom menubar — native click-down popover

A tiny [Tauri v2](https://v2.tauri.app) menu-bar (macOS) / system-tray
(Windows) app that shows headroom's liquid-glass `/widget` page as a real
click-down panel — the thing a SwiftBar text menu can't do.

- **Left-click** the tray icon: toggle a frameless, always-on-top 360×640
  panel anchored at the icon (below it on macOS, above the taskbar tray on
  Windows). Clicking anywhere else hides it, like a native popover.
- **Right-click**: menu with **Refresh**, **Open in Browser**, **Quit**.
- No Dock icon / app-switcher entry on macOS (accessory activation policy +
  `LSUIElement`).
- If the widget server can't be reached (tunnel down), the panel shows a
  small glass fallback card — "server unreachable — is the tunnel up?" —
  with a Retry button, and auto-recovers within ~3 s of the server coming
  back.

## Security model

This app is a **viewer, not a data path**:

- The webview only ever loads **loopback** URLs. `HEADROOM_WIDGET_URL` is
  validated at startup (must be `http://` + `127.0.0.0/8`, `::1`, or
  `localhost`); anything else is rejected and the default is used.
- A Rust-side `on_navigation` allowlist additionally blocks every navigation
  that is not the bundled fallback page or a loopback `http://` URL — even a
  link inside the page can't take the webview off-loopback.
- The page gets **no Tauri IPC**: no capabilities are granted, `withGlobalTauri`
  is off, and the app defines no commands.
- The app never reads headroom auth, tokens, or account state. It renders a
  page your local server already serves — nothing more.
- No telemetry, no network calls other than the loopback reachability probe
  and the webview page load itself.

## Prerequisites

- [Rust](https://rustup.rs) (1.88+; stable toolchain — the pinned Cargo.lock needs 1.88)
- Tauri CLI: `cargo install tauri-cli --version "^2" --locked`
- **macOS**: Xcode Command Line Tools (`xcode-select --install`)
- **Windows**: [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
  and the [WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/)
  (preinstalled on Windows 11)
- **Linux** (untested, should work): `webkit2gtk-4.1`, `libayatana-appindicator3`
  dev packages

## Build & run

```sh
cd integrations/menubar

# development (uses the bundled assets; no frontend dev server needed)
cargo tauri dev

# release bundle
cargo tauri build
```

Artifacts land under `src-tauri/target/release/bundle/`:
`macos/Headroom.app` (+ `dmg/`) on macOS, `nsis/*-setup.exe` on Windows.

Move `Headroom.app` to `/Applications` and launch it — the battery glyph
appears in the menu bar.

## Configuration

| Env var              | Default                          | Meaning                                  |
| -------------------- | -------------------------------- | ---------------------------------------- |
| `HEADROOM_WIDGET_URL`| `http://127.0.0.1:8377/widget`   | Widget page URL (**loopback only**)      |

If the fleet's dashboard runs on another machine, bring it to loopback with
an SSH tunnel (this is the assumed setup):

```sh
ssh -N -L 8377:127.0.0.1:8377 user@headroom-host
```

For a GUI app on macOS, per-shell exports don't apply; set the variable for
launchd-spawned apps if you need a non-default URL:

```sh
launchctl setenv HEADROOM_WIDGET_URL http://127.0.0.1:8377/widget
```

## Autostart at login

- **macOS**: System Settings → General → Login Items → add `Headroom.app`.
- **Windows**: press `Win+R`, run `shell:startup`, drop a shortcut to
  `Headroom.exe` there.

## Behavior details

- The panel window is created hidden at startup and warmed with the widget
  page, so the first click is instant.
- Reachability is probed Rust-side (a real HTTP `HEAD`, not just a TCP
  connect — an `ssh -L` listener accepts even when its remote side is dead).
- While the fallback card is visible, a watcher re-probes every 3 s and swaps
  the widget page back in as soon as the server responds.
- Clicking the tray icon while the panel is open closes it (the focus-loss
  hide and the click toggle are debounced so it doesn't instantly reopen).

## Troubleshooting

- **Blank/old panel after sleep or tunnel restart** — right-click → Refresh.
- **Icon not visible on macOS** — the menu bar may be full (notch); menu-bar
  managers like Bartender/Ice can hide new items.
- **Panel opens on the wrong monitor edge (Windows)** — the panel anchors to
  the tray icon's reported position; with auto-hidden taskbars, unhide the
  taskbar once so the position updates.
- **`cargo tauri dev` shows the fallback card** — the widget server isn't
  reachable on the configured URL; start `headroom serve` or the SSH tunnel.
