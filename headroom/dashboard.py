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
# How long a CARRIED reading may still be presented as a live measurement.
#
# Paul set this number himself, twice: "As long as it's accurate within 60
# minutes, I don't care. You must ALWAYS show me." Both halves are law, and
# before 2026-08-16 only the second half was implemented - the carry had no
# ceiling at all, so a reading of any age was served wearing its original
# per-window state. Measured that morning: the `system` row was serving a
# 29-hour-old "100% left" as state "current" (green, live) while that seat had
# been unreadable since 2026-08-15T12:20Z, and codex-gmail was serving a
# 6.4-day-old one. That is the failure Paul reported as "the readings are
# inaccurate" - not a blank row, a CONFIDENT WRONG row, which is worse,
# because a blank row makes him check and a green row makes him trust it.
#
# Past this ceiling the reading is still SHOWN (never blank) but it is shown as
# what it is: demoted to "stale", the number moved to
# last_observed_left_percent, and the row's own observed_at left intact so the
# dashboard renders its "last verified <age> ago" line against it.
CARRY_LIVE_MAX_AGE = paths.env_int("HEADROOM_CARRY_LIVE_MAX_AGE", 3600)

# The statusline "tee": every live session writes its own provider rate_limits
# header here, one file per seat, at most once a minute.
# ~/.system/bin/usage-truth-merge.py folds these into the published feeds on a
# two-minute cron. That cron is not enough on its own, and this is why:
# the collector republishes the feed roughly every minute and publishes
# BLINDNESS for any account the usage API is throttling, so for up to two
# minutes out of every cycle a seat with a perfectly good live reading is blind
# in the served file. Paul checks the widget at arbitrary moments; a recurring
# window is a window he lands in, and he has landed in it repeatedly.
#
# So the fold is ALSO done here, in memory, at the moment of serving. Nothing
# is written: this transforms the response only, the private snapshot the
# ROUTER reads is untouched, and the cron remains the durable writer.
SESSION_TRUTH_DIR = os.environ.get(
    "HEADROOM_SESSION_TRUTH_DIR",
    "/home/paulsportsza/ai-accounts/state/session-truth")
SESSION_TRUTH_MAX_AGE = paths.env_int("HEADROOM_SESSION_TRUTH_MAX_AGE", 1800)


def _session_truth(name):
    """This seat's newest session-header reading, or None.

    Tries both spellings because the two sides name seats differently: the
    headroom registry uses the short name (mzansiedge) and the fleet writes the
    alias (claude-mzansiedge).
    """
    for candidate in (name, "claude-%s" % name):
        if not isinstance(candidate, str) or not candidate:
            continue
        try:
            with open(os.path.join(SESSION_TRUTH_DIR,
                                   candidate + ".json")) as handle:
                truth = json.load(handle)
        except (OSError, ValueError):
            continue
        if isinstance(truth, dict):
            return truth
    return None


def _fold_session_truth(snapshot, now=None):
    """Return a copy of the snapshot with fresh session-header readings folded in.

    WHY A BLIND ROW MAY BE PROMOTED TO LIVE. The collector's `ok: false` means
    "the usage API would not answer ME, just now". It is not evidence that the
    account is unreadable or unhealthy, and headroom's own router already draws
    that distinction ("the rate-limit CHECK being rate-limited is not evidence
    of missing capacity"). A session header is a stronger reading than the one
    that failed: it came back from the provider inside an authenticated live
    session on that exact account, seconds ago, and it is the number the
    statusline and DMUX are already showing. Refusing it here is what made
    Paul's three surfaces contradict each other.

    FAIL-CLOSED EVERYWHERE ELSE. A reading older than SESSION_TRUTH_MAX_AGE is
    ignored, a reading OLDER than the row's own is ignored (an equal one is
    re-folded on purpose, see the guard below), a malformed file is ignored, and
    every original row is passed through untouched when there is nothing to
    fold. Nothing here can invent a number.
    """
    now = time.time() if now is None else now
    rows = snapshot.get("accounts") if isinstance(snapshot, dict) else None
    if not isinstance(rows, list):
        return snapshot
    out = []
    folded_any = False
    for row in rows:
        if not isinstance(row, dict):
            out.append(row)
            continue
        truth = _session_truth(row.get("name"))
        captured = (truth or {}).get("captured_at")
        if (not isinstance(captured, (int, float))
                or isinstance(captured, bool)
                or now - captured > SESSION_TRUTH_MAX_AGE
                or captured > now):
            out.append(row)
            continue
        existing = row.get("captured_at")
        existing = existing if isinstance(existing, (int, float)) else 0
        # `<` not `<=`, deliberately. The two-minute cron merge folds the same
        # tee reading into the published file and stamps the row's captured_at
        # with it, but it leaves `ok: false` exactly as the collector wrote it.
        # On the equal case an earlier cut of this function skipped the row, so
        # the numbers were present and correct and the row was STILL held: the
        # page printed a grey "last verified 6m ago" over a reading that was
        # six minutes old and perfectly good, while the statusline and DMUX
        # showed it live. Re-folding an identical reading is idempotent; what
        # actually matters on this path is the promotion below.
        if captured < existing:
            out.append(row)
            continue
        windows = dict(row.get("windows") or {})
        folded = False
        for key in ("5h", "7d"):
            source = (truth.get("windows") or {}).get(key)
            if not isinstance(source, dict):
                continue
            used = source.get("used_percent")
            if not isinstance(used, (int, float)) or isinstance(used, bool):
                continue
            window = dict(windows.get(key) or {})
            window["used_percent"] = float(used)
            if isinstance(source.get("resets_at"), (int, float)):
                window["resets_at"] = float(source["resets_at"])
            window["observed_at"] = int(captured)
            window["truth_source"] = "session_header"
            windows[key] = window
            folded = True
        if not folded:
            out.append(row)
            continue
        merged = dict(row)
        merged["windows"] = windows
        merged["captured_at"] = int(captured)
        merged["truth_source"] = "session_header"
        merged["stale"] = False
        # The reading is proven, so the row must be allowed to render as one.
        # Left as published, `ok: false` / `trust_state: held` would make the
        # projection hold the row and the page would print "n/a" over a number
        # it is holding. The ORIGINAL verdict is preserved beside it rather
        # than erased, so nothing downstream loses the collector's own finding.
        merged["collector_ok"] = row.get("ok")
        merged["collector_error_code"] = row.get("error_code")
        merged["ok"] = True
        merged["trust_state"] = "verified_local"
        out.append(merged)
        folded_any = True
    if not folded_any:
        return snapshot
    result = dict(snapshot)
    result["accounts"] = out
    return result


def display_snapshot(snapshot, evaluated_at=None, force_noncurrent_reason=None,
                     config=None):
    """Attach the central display projection consumed by dashboard JavaScript."""
    value = dict(snapshot)
    # The source snapshot is untrusted with respect to the current opt-in.
    # Remove any stale/cached payload before consulting one exact config view.
    value.pop("token_stats", None)
    value.pop("token_stats_enabled", None)
    value["_headroom_display"] = _carry_lastgood_rows(widget.project_dashboard(
        snapshot, evaluated_at, force_noncurrent_reason))
    # THE DASHBOARD CARDS GET THE SAME NEVER-BLANK CARRY AS THE MENUBAR.
    #
    # 2026-08-16: the carry was wired to /widget.json only, and /widget.json is
    # read by the SwiftBar/menubar contract - NOT by the page Paul actually
    # opens at 127.0.0.1:8377. Its cards render from this payload instead, so
    # the one surface he was complaining about was the one surface the
    # protection never reached. Measured that morning, his `system` card read
    # "n/a / no reading yet" under the note "usage source temporarily
    # rate-limited", while that account's last verified numbers had been on
    # disk for 29 hours and the real cause was an expired login, not a
    # throttle. Two protections on the two surfaces nobody was looking at, and
    # none on the third.
    #
    # The row count is preserved by the carry (rows are replaced in place, never
    # added or dropped), which the page's own validate() requires: it rejects
    # the whole payload when display.accounts.length !== data.accounts.length,
    # and the client joins __display to each raw account BY INDEX.
    try:
        live_config = registry.load() if config is None else config
        enabled = registry.token_stats_enabled(live_config)
        value["token_stats_enabled"] = enabled
        if enabled:
            token_accounts, roots_partial = registry.token_accounts(
                live_config, include_status=True)
            token_stats = tokens.load_summary(
                token_accounts, now=evaluated_at, partial=roots_partial)
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
        "token_scan_interval": tokens.scan_interval(),
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
        def collect_for_dashboard():
            snapshot = collector.run_collect(quiet=True)
            collector._trigger_token_scan(synchronous=False)
            return snapshot

        return self.refresh_gate.get(
            lambda: paths.load_json(paths.public_snapshot_path()),
            collect_for_dashboard)

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
        # Fold live session-header readings before ANY of the three routes
        # project, so the page, the widget JSON and the SwiftBar text can never
        # disagree with each other or with the statusline about the same seat.
        # In memory only: nothing is written and the router's private snapshot
        # is untouched.
        try:
            served = _fold_session_truth(result.snapshot)
        except Exception:
            served = result.snapshot  # a freshness upgrade may never break serving
        try:
            if route == "/usage.json":
                value = display_snapshot(
                    served, force_noncurrent_reason=reason)
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
                value = widget.project(served,
                                       force_noncurrent_reason=reason)
                value = _carry_lastgood_rows(value)
                body = json.dumps(value, allow_nan=False,
                                  separators=(",", ":")).encode("utf-8")
                content_type = "application/json"
            else:
                # Same projection, same carry, same numbers as /widget.json.
                body = widget.render_swiftbar(
                    served, force_noncurrent_reason=reason,
                    dashboard_href=self._dashboard_href(),
                    projection=_carry_lastgood_rows(widget.project(
                        served, force_noncurrent_reason=reason))
                    ).encode("utf-8")
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


_LASTGOOD_LOCK = threading.Lock()


def _carry_lastgood_rows(value):
    """NEVER BLANK — Paul's widget law (2026-08-07, respecified 2026-08-08:
    "work until the widget is perfect and bulletproof... 100% uptime").

    The usage API rate-limits in ~hourly cycles; during a cycle every claude
    row projects held with no numbers, and the menubar renders batteries with
    no measurements — the exact artifact Paul keeps finding. His spec:
    "accurate within 60 minutes, I don't care. You must ALWAYS show me."

    So: whenever a projected account row carries NO usable percentage, serve
    the last row that DID, flagged honestly (state "carried", carried_seconds,
    served_from "lastgood"). Rows we carried are never re-remembered (only
    real reads update the store), the store write is atomic, and EVERY failure
    path returns the original value unchanged — this shim may never break
    serving. The same contract as .system/bin/widget_lastgood.py, applied at
    the one surface the menubar actually reads (8377), which the file-level
    protectors never covered."""
    try:
        store_path = os.path.join(paths.state_dir(), "widget-lastgood-rows.json")
        now = time.time()
        with _LASTGOOD_LOCK:
            try:
                store = json.load(open(store_path))
                store = store if isinstance(store, dict) else {}
            except (OSError, ValueError):
                store = {}
            changed = False
            accounts = value.get("accounts")
            accounts = accounts if isinstance(accounts, list) else []
            for index, row in enumerate(accounts):
                if not isinstance(row, dict):
                    continue
                name = row.get("name")
                if not isinstance(name, str) or not name:
                    continue
                if row.get("unpaid") is True:
                    # NEVER CARRY NUMBERS ONTO AN UNPAID SEAT (2026-08-17).
                    # The carry exists so a rate-limited collector cannot
                    # blank a seat that HAS a reading. An unpaid seat has no
                    # reading by definition, and resurrecting last week's
                    # percentages would show Paul capacity he is not paying
                    # for. Drop any stored row for it too, so paying the bill
                    # starts from a real read.
                    if name in store:
                        del store[name]
                        changed = True
                    continue
                windows = row.get("windows")
                windows = windows if isinstance(windows, dict) else {}
                has_numbers = any(
                    isinstance(w, dict) and w.get("left_percent") is not None
                    for w in windows.values())
                if has_numbers and row.get("served_from") != "lastgood":
                    store[name] = {"row": row, "saved_at": now}
                    changed = True
                elif not has_numbers and name in store:
                    # Speak the widget contract's OWN stale dialect (learned
                    # 2026-08-08 the hard way: a "carried" state failed
                    # hrValidFeed's enum and the menubar rendered the whole
                    # feed as "unreachable"). Per hrValidWindow's invariant,
                    # only a CURRENT window may hold a live left_percent —
                    # a stale window carries the number in
                    # last_observed_left_percent with left_percent null, and
                    # the renderer shows it greyed with honest age.
                    saved = store[name]
                    carried = json.loads(json.dumps(saved.get("row") or {}))
                    age = int(now - (saved.get("saved_at") or now))
                    # PAUL'S LAW, restated 2026-08-08 and now absolute:
                    # "If something is greyed out there should never be
                    # anything grayed out ever. It should always clearly show
                    # me what the situation is. If it's greyed out it means it
                    # is fundamentally broken at its core."
                    #
                    # Grey is therefore RESERVED for genuinely-unknown, and a
                    # number we hold IS known. A carried row keeps its live
                    # colour and its percentages at every age; the honesty
                    # lives in the row's own "last verified N ago" line, which
                    # the renderer derives from observed_at. The previous cut
                    # greyed anything over an hour, which is how correct codex
                    # numbers (97% / 38%, verified against the collector) read
                    # to Paul as a broken feed.
                    carried["carried_seconds"] = age
                    carried["served_from"] = "lastgood"
                    # EVERY ROW SAYS WHERE ITS NUMBER CAME FROM AND HOW OLD IT
                    # IS. Additive fields only - the widget contract's required
                    # keys are untouched, and hrValidFeed ignores extras - so
                    # every existing consumer (the dashboard page, DMUX's
                    # seat-usage.py, the SwiftBar text) keeps reading exactly
                    # what it read before.
                    carried["reading_source"] = "lastgood"
                    carried["reading_age_seconds"] = age
                    # A CARRIED ROW IS ALWAYS MARKED STALE, AT EVERY AGE.
                    #
                    # It was tempting to demote only past CARRY_LIVE_MAX_AGE and
                    # let a recent carry keep its live look. That is wrong twice.
                    #
                    # It is wrong in FACT: the collector did not read this
                    # account this cycle. That is what "carried" means. A row
                    # wearing state "current" is claiming a live measurement,
                    # and there isn't one.
                    #
                    # It is wrong in PRACTICE, which is how it was caught: the
                    # dashboard's displayState() ages a row off the RAW
                    # account's captured_at, and a rate-limited raw row has no
                    # captured_at at all. So a row left "current" was demoted to
                    # "held" by the client anyway, and "held" renders the number
                    # as "n/a" - the carry did all its work and Paul still saw a
                    # blank. Demoting here puts the number in
                    # last_observed_left_percent, which is the one place every
                    # renderer on both surfaces already looks for a number it is
                    # allowed to show greyed.
                    #
                    # So: the badge tells the truth (STALE), the number is
                    # visible, and the age is printed beside it. Accurate AND
                    # available, which is the whole of what Paul asked for.
                    widget._demote_windows(carried.get("windows") or {},
                                           "stale")
                    carried["state"] = "stale"
                    carried["reading_note"] = (
                        ("no live reading for %d minutes; showing the last "
                         "verified one" % (age // 60))
                        if age > CARRY_LIVE_MAX_AGE
                        else "last verified %d minutes ago" % (age // 60))
                    accounts[index] = carried
            if changed:
                tmp = store_path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(store, f, separators=(",", ":"))
                os.replace(tmp, store_path)
        return value
    except Exception:
        return value


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
        collector._trigger_token_scan(synchronous=False)
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
