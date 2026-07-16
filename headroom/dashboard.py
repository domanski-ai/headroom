"""Build and serve the themed usage dashboard.

`build` renders ``dashboard/template.html`` with the user's settings injected
into one JSON block and writes it next to the public snapshot, so the whole
dashboard is two static files: ``index.html`` + ``usage.json``. Host them
anywhere — or don't: `serve` runs a tiny local server whose ``/usage.json``
transparently re-collects when the snapshot is stale, so the page is always
current with zero cron setup.
"""
import http.server
import ipaddress
import json
import math
import os
import sys
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass

from . import collect as collector
from . import history, paths, registry, tokens, widget

TEMPLATE = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "dashboard", "template.html")
SERVE_MAX_AGE = paths.env_int("HEADROOM_SERVE_MAX_AGE", 300)
FAILURE_BACKOFF_BASE = paths.env_int("HEADROOM_SERVE_FAILURE_BACKOFF_BASE", 5)
FAILURE_BACKOFF_CAP = paths.env_int("HEADROOM_SERVE_FAILURE_BACKOFF_CAP", 300)


def display_snapshot(snapshot, evaluated_at=None, force_noncurrent_reason=None,
                     config=None):
    """Attach the central display projection consumed by dashboard JavaScript."""
    value = dict(snapshot)
    # The source snapshot is untrusted with respect to the current opt-in.
    # Remove any stale/cached payload before consulting one exact config view.
    value.pop("token_stats", None)
    value["_headroom_display"] = widget.project_dashboard(
        snapshot, evaluated_at, force_noncurrent_reason)
    try:
        live_config = registry.load() if config is None else config
        if registry.token_stats_enabled(live_config):
            token_stats = tokens.load_summary(
                registry.accounts(live_config), now=evaluated_at)
            if token_stats is not None:
                value["token_stats"] = token_stats
    except Exception:
        pass  # an optional private store can never break the usage payload
    return value


@dataclass(frozen=True)
class RefreshResult:
    snapshot: object
    refresh_failed: bool = False
    reason: object = None


def _within_freshness_window(snapshot, clock=time.time):
    """True while the snapshot's age is inside the widget freshness window
    (the same bound the projection itself demotes on)."""
    generated = RefreshGate._generated(snapshot)
    if generated is None:
        return False
    age = clock() - generated
    return 0 <= age <= widget.SNAPSHOT_MAX_AGE


class RefreshGate:
    """Single-flight collection with success TTL and bounded failure retry."""

    def __init__(self, success_ttl=SERVE_MAX_AGE,
                 failure_base=FAILURE_BACKOFF_BASE,
                 failure_cap=FAILURE_BACKOFF_CAP, clock=None):
        self.success_ttl = success_ttl
        self.failure_base = failure_base
        self.failure_cap = failure_cap
        self.clock = clock or time.time
        self.failure_count = 0
        self.retry_at = 0.0
        self.last_delay = 0.0
        self._last_success_at = None
        self._collecting = False
        self._condition = threading.Condition()

    @staticmethod
    def _generated(snapshot):
        value = snapshot.get("generated") if isinstance(snapshot, dict) else None
        if (isinstance(value, (int, float)) and not isinstance(value, bool)
                and math.isfinite(value)):
            return value
        return None

    def _published_current(self, snapshot, now):
        generated = self._generated(snapshot)
        return (generated is not None and 0 <= now - generated
                <= self.success_ttl)

    def get(self, load_snapshot, collect_snapshot):
        """Return one snapshot result; only the admitted caller may collect."""
        while True:
            with self._condition:
                now = self.clock()
                snapshot = load_snapshot()
                if self._last_success_at is None \
                        and self._published_current(snapshot, now):
                    self._last_success_at = self._generated(snapshot)
                if (self._last_success_at is not None
                        and now - self._last_success_at < self.success_ttl):
                    return RefreshResult(snapshot)
                if now < self.retry_at:
                    return RefreshResult(snapshot, True, "refresh_failed")
                if self._collecting:
                    self._condition.wait()
                    continue
                self._collecting = True
                break

        try:
            collect_snapshot()
            completed = self.clock()
            snapshot = load_snapshot()
            if not self._published_current(snapshot, completed):
                raise RuntimeError("collector did not publish a current snapshot")
        except Exception:  # noqa: BLE001 — callers receive stale/503, never live
            with self._condition:
                self.failure_count += 1
                self.last_delay = min(
                    self.failure_base if self.last_delay <= 0
                    else self.last_delay * 2,
                    self.failure_cap)
                self.retry_at = self.clock() + self.last_delay
                self._collecting = False
                self._condition.notify_all()
                return RefreshResult(load_snapshot(), True, "refresh_failed")
        with self._condition:
            self.failure_count = 0
            self.retry_at = 0.0
            self.last_delay = 0.0
            self._last_success_at = self.clock()
            self._collecting = False
            self._condition.notify_all()
            return RefreshResult(snapshot)


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_demo(out_dir=None):
    """Render the dashboard from the bundled sample data — no accounts, no
    config, no network. Lets anyone preview it in seconds before connecting."""
    import time
    sample = os.path.join(_repo_root(), "examples", "usage.sample.json")
    with open(sample) as handle:
        data = json.load(handle)
    now = int(time.time())
    data["generated"] = now - 30
    resets = {"5h": now + 2 * 3600 + 11 * 60, "7d": now + 3 * 86400}
    for index, account in enumerate(data.get("accounts", []), 1):
        account["id"] = f"{index:012x}"
        account["captured_at"] = now - 30
        for key, window in (account.get("windows") or {}).items():
            window["resets_at"] = resets["5h"] if key == "5h" else resets["7d"]
            if "observed_at" in window:
                window["observed_at"] = now - 30
        sub = account.get("subscription")
        if sub and sub.get("status") == "active_through":
            sub["active_until"] = now + 21 * 86400
            sub["checked_at"] = now - 3600
    out_dir = out_dir or os.path.join(paths.base_dir(), "demo")
    os.makedirs(out_dir, exist_ok=True)
    demo_config = {"schema_version": 1,
                   "dashboard": {"theme": "midnight", "title": "headroom (demo)"},
                   "accounts": [{"id": a["id"], "name": a["name"],
                                 "provider": a["provider"],
                                 "home": "/tmp/demo/" + a["name"]}
                                for a in data["accounts"]]}
    build(demo_config, out_dir)
    with open(os.path.join(out_dir, "usage.json"), "w") as handle:
        json.dump(display_snapshot(data, config=demo_config),
                  handle, allow_nan=False)
    return out_dir


def build(config=None, out_dir=None, snapshot_file=None):
    config = registry.load() if config is None else config
    settings = registry.dashboard_settings(config)
    out_dir = paths.public_dir() if out_dir is None else out_dir
    os.makedirs(out_dir, exist_ok=True)
    with open(TEMPLATE) as handle:
        html = handle.read()
    injected = {
        "theme": settings["theme"],
        "title": settings["title"],
        "redact": bool(settings.get("redact_emails", True)),
        "snapshot_max_age": widget.SNAPSHOT_MAX_AGE,
        "observation_max_age": widget.OBSERVATION_MAX_AGE,
        "accounts": [{"name": account["name"], "provider": account["provider"]}
                     for account in registry.accounts(config)],
    }
    # script-safe serialization: <, >, & escaped so a hostile title/name can
    # never terminate the <script> element (stored XSS via config)
    payload = (json.dumps(injected, indent=None)
               .replace("<", "\\u003c").replace(">", "\\u003e")
               .replace("&", "\\u0026"))
    html = html.replace("/*__HEADROOM_CONFIG__*/ null", payload)
    index = os.path.join(out_dir, "index.html")
    with open(index, "w") as handle:
        handle.write(html)
    target = os.path.join(out_dir, "usage.json")
    if snapshot_file and os.path.exists(snapshot_file):
        with open(snapshot_file) as handle:
            snapshot = json.load(handle)
        with open(target, "w") as handle:
            json.dump(display_snapshot(snapshot, config=config),
                      handle, allow_nan=False)
    print(f"dashboard built: {index}")
    return index


class Handler(http.server.SimpleHTTPRequestHandler):
    demo = False
    refresh_gate = RefreshGate()

    def __init__(self, *args, directory=None, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format, *args):  # noqa: A002 — stdlib signature
        pass

    # The dashboard and /widget pages are single self-contained documents:
    # inline style/script, same-origin feed fetches, no frames, objects,
    # forms, or external subresources — the CSP pins exactly that, so the
    # pages stay contained even inside an embedding webview (the menu-bar
    # popover) where the app's own top-level navigation gate cannot see
    # subresource or frame loads.
    _CSP = ("default-src 'none'; script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-src 'none'; object-src 'none'; "
            "form-action 'none'; base-uri 'none'")

    def end_headers(self):
        # Every response, including static errors and Host rejections, carries
        # the same browser hardening and cannot be cached as a live reading.
        self.send_header("cache-control", "no-store")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("content-security-policy", self._CSP)
        super().end_headers()

    def _host_ok(self):
        # reject anything but a loopback Host, so a remote page can't reach the
        # server via DNS-rebinding and read the usage feed cross-origin.
        raw = (self.headers.get("Host") or "").strip()
        if not raw:
            return False
        if raw.startswith("["):            # [::1]:port
            host = raw[1:].split("]")[0]
        elif raw.count(":") == 1:          # host:port (IPv4 or name)
            host = raw.split(":")[0]
        else:                              # bare name or bracketless IPv6
            host = raw
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def _dashboard_href(self):
        # the port this server is actually bound to, so a tunneled client's
        # "Open dashboard" link points at the same tunnel it fetched through
        try:
            return f"http://127.0.0.1:{self.server.server_address[1]}/"
        except (AttributeError, IndexError, TypeError):
            return None

    def do_GET(self):
        if not self._host_ok():
            self.send_response(403)
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"forbidden: non-loopback Host")
            return
        route = urllib.parse.urlsplit(self.path).path
        if route == "/history.json":
            self._serve_history()
            return
        if route in ("/usage.json", "/widget.json", "/widget.txt"):
            self._serve_feed(route)
            return
        if route == "/widget":
            original = self.path
            self.path = "/index.html"
            try:
                super().do_GET()
            finally:
                self.path = original
            return
        super().do_GET()

    def _snapshot_result(self):
        if self.demo:
            snapshot = paths.load_json(os.path.join(self.directory, "usage.json"))
            return RefreshResult(snapshot)
        return self.refresh_gate.get(
            lambda: paths.load_json(paths.public_snapshot_path()),
            lambda: collector.run_collect(quiet=True))

    def _send_body(self, status, content_type, body):
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_history(self):
        try:
            if not history.enabled():
                self._send_body(
                    503, "application/json", b'{"error":"history_disabled"}')
                return
            query = urllib.parse.parse_qs(
                urllib.parse.urlsplit(self.path).query)
            try:
                days = int((query.get("days") or [7])[0])
            except (TypeError, ValueError):
                days = 7
            days = min(history.retention_days(), max(1, days))
            if self.demo:
                snapshot = paths.load_json(
                    os.path.join(self.directory, "usage.json"))
                live_ids = {account.get("id")
                            for account in (snapshot or {}).get("accounts", [])
                            if account.get("id")}
                rows = history.demo_rows(snapshot, days) \
                    if isinstance(snapshot, dict) else []
            else:
                config = registry.load()
                live_ids = {account["id"] for account in registry.accounts(config)
                            if account.get("id")}
                rows = history.load_series(days, live_ids)
            if not rows:
                self._send_body(
                    503, "application/json", b'{"error":"no history yet"}')
                return
            value = history.response(
                days, live_ids, rows=rows, generated=int(time.time()))
            body = json.dumps(value, allow_nan=False,
                              separators=(",", ":")).encode("utf-8")
        except Exception:
            self._send_body(
                503, "application/json", b'{"error":"invalid history"}')
            return
        self._send_body(200, "application/json", body)

    def _serve_feed(self, route):
        result = self._snapshot_result()
        if not isinstance(result.snapshot, dict):
            if route == "/widget.txt":
                body = widget.render_swiftbar(
                    None, dashboard_href=self._dashboard_href()).encode("utf-8")
                content_type = "text/plain; charset=utf-8"
            else:
                body = b'{"error":"no usage snapshot yet"}'
                content_type = "application/json"
            self._send_body(503, content_type, body)
            return
        # A failed refresh ATTEMPT must not invalidate a snapshot that is
        # still inside the widget freshness window: age-based demotion
        # (the projection's freshness state) already handles genuinely old
        # data, and forcing noncurrent here flashed the whole fleet to
        # "held, never promoted to live" whenever an inline refresh raced
        # another collector holding the collect lock (2026-07-14).
        stale_failed = result.refresh_failed \
            and not _within_freshness_window(result.snapshot)
        reason = result.reason if stale_failed else None
        try:
            if route == "/usage.json":
                value = display_snapshot(
                    result.snapshot, force_noncurrent_reason=reason)
                if stale_failed:
                    value["refresh_failed"] = True
                if result.refresh_failed:
                    # non-demoting diagnostic: a failing collector should be
                    # VISIBLE (warning) long before the freshness window
                    # finally demotes the data
                    value["refresh_attempt_failed"] = True
                body = json.dumps(value, allow_nan=False,
                                  separators=(",", ":")).encode("utf-8")
                content_type = "application/json"
            elif route == "/widget.json":
                value = widget.project(result.snapshot,
                                       force_noncurrent_reason=reason)
                body = json.dumps(value, allow_nan=False,
                                  separators=(",", ":")).encode("utf-8")
                content_type = "application/json"
            else:
                body = widget.render_swiftbar(
                    result.snapshot, force_noncurrent_reason=reason,
                    dashboard_href=self._dashboard_href()).encode("utf-8")
                content_type = "text/plain; charset=utf-8"
        except (TypeError, ValueError, OverflowError):
            body = (widget.render_swiftbar(
                None, dashboard_href=self._dashboard_href()).encode("utf-8")
                    if route == "/widget.txt"
                    else b'{"error":"invalid usage snapshot"}')
            content_type = ("text/plain; charset=utf-8"
                            if route == "/widget.txt" else "application/json")
            self._send_body(503, content_type, body)
            return
        self._send_body(200, content_type, body)


def serve(open_browser=False, port=None, demo=False):
    if demo:
        out_dir = build_demo()
        port = port or 8377
    else:
        config = registry.load()
        settings = registry.dashboard_settings(config)
        port = settings["port"] if port is None else port
        out_dir = paths.public_dir()
        build(config, out_dir)
    handler_cls = type("HeadroomHandler", (Handler,),
                       {"demo": demo, "refresh_gate": RefreshGate()})
    handler = lambda *args, **kwargs: handler_cls(*args, directory=out_dir, **kwargs)  # noqa: E731
    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    except OSError as error:
        print(f"headroom: cannot bind port {port} ({error}). "
              f"Is `headroom serve` already running? Try --port <N>.",
              file=sys.stderr)
        return 1
    url = f"http://127.0.0.1:{port}/"
    print(f"headroom dashboard: {url}  (Ctrl-C to stop)")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
        return 0
