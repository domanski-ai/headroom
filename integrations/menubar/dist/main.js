// Offline fallback logic. This page is only ever shown when the Rust side
// decided the widget server is unreachable (or during the very first probe).
// It has NO Tauri IPC access (no capabilities are granted) — the only thing
// it can do is navigate to the loopback widget URL, and even that is
// re-checked by the Rust `on_navigation` allowlist.

(function () {
  "use strict";

  var DEFAULT_URL = "http://127.0.0.1:8377/widget";
  var widgetUrl = window.__HEADROOM_WIDGET_URL__ || DEFAULT_URL;

  var card = document.querySelector(".card");
  var urlEl = document.getElementById("widget-url");
  var retryBtn = document.getElementById("retry");
  var probeTimer = null;

  urlEl.textContent = widgetUrl;

  function setState(state) {
    card.dataset.state = state;
  }

  // Rust pushes status updates here after each probe ("probing" | "down").
  window.__headroomStatus = function (state) {
    if (state === "down" || state === "probing") {
      if (probeTimer) {
        clearTimeout(probeTimer);
        probeTimer = null;
      }
      setState(state);
    }
  };

  function armProbeTimeout(ms) {
    if (probeTimer) {
      clearTimeout(probeTimer);
    }
    // If the server were up, the Rust watcher would have navigated this
    // webview to the widget page (unloading this document). Still being
    // here after `ms` means the probe failed.
    probeTimer = setTimeout(function () {
      setState("down");
    }, ms);
  }

  retryBtn.addEventListener("click", function () {
    setState("probing");
    // Top-level navigation to the loopback widget URL. If the server is
    // down the engine keeps (macOS) or replaces (Windows) this document;
    // the Rust 3s watcher recovers either way.
    armProbeTimeout(1500);
    window.location.assign(widgetUrl);
  });

  // Initial load: Rust probes in the background and either navigates away
  // (server up) or evals __headroomStatus("down").
  armProbeTimeout(3500);
})();
