"""Display-only widget projection and SwiftBar rendering.

The widget contract deliberately contains observations, not routing advice.  It
is projected from the sanitized public snapshot and fails closed whenever a
timestamp, trust marker, or percentage cannot be proven current.
"""
import datetime
import math
import os
import time
import unicodedata
from urllib.parse import urlsplit

from . import paths, registry


SCHEMA = "headroom_widget@1"
TEXT_SCHEMA = "headroom_widget_txt@1"
WINDOW_KEYS = ("5h", "7d")
SNAPSHOT_MAX_AGE = paths.env_int("HEADROOM_SNAPSHOT_MAX_AGE", 900)
OBSERVATION_MAX_AGE = paths.env_int("HEADROOM_OBSERVATION_MAX_AGE", 1800)
DASHBOARD_HREF = "http://127.0.0.1:8377/"


def _number(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def _epoch(value):
    return value if _number(value) else None


def _freshness(snapshot, evaluated_at, force_noncurrent_reason=None):
    if (not isinstance(snapshot, dict)
            or not isinstance(snapshot.get("accounts"), list)):
        return {"state": "held", "age_seconds": None,
                "reason": "invalid_snapshot_shape",
                "evaluated_at": evaluated_at}
    generated = _epoch(snapshot.get("generated")) \
        if isinstance(snapshot, dict) else None
    if generated is None:
        return {"state": "held", "age_seconds": None,
                "reason": "missing_or_invalid_snapshot_time",
                "evaluated_at": evaluated_at}
    age = evaluated_at - generated
    age_seconds = max(0, int(math.floor(age)))
    if age < 0:
        return {"state": "held", "age_seconds": age_seconds,
                "reason": "clock_skew", "evaluated_at": evaluated_at}
    if force_noncurrent_reason:
        return {"state": "stale", "age_seconds": age_seconds,
                "reason": str(force_noncurrent_reason),
                "evaluated_at": evaluated_at}
    if age > SNAPSHOT_MAX_AGE:
        return {"state": "stale", "age_seconds": age_seconds,
                "reason": "snapshot_expired", "evaluated_at": evaluated_at}
    return {"state": "current", "age_seconds": age_seconds,
            "reason": "snapshot_current", "evaluated_at": evaluated_at}


def _account_base_state(account, freshness, evaluated_at):
    if freshness["state"] == "held":
        return "held"
    if freshness["state"] == "stale":
        return "stale"
    if not isinstance(account, dict) or account.get("ok") is not True:
        return "held"
    # the display layer must accept exactly the trust states the router
    # routes on (route.block_reason): a slot verified via local credential
    # binding is routable and must not render as held
    if account.get("trust_state") not in ("verified", "verified_local"):
        return "held"
    captured_at = _epoch(account.get("captured_at"))
    if captured_at is None or captured_at > evaluated_at:
        return "held"
    if account.get("stale") is True \
            or evaluated_at - captured_at > OBSERVATION_MAX_AGE:
        return "stale"
    return "current"


def _window_projection(raw, captured_at, base_state, evaluated_at):
    resets_at = _epoch(raw.get("resets_at")) \
        if isinstance(raw, dict) else None
    observed_at = None
    used_percent = None
    valid_percent = False
    if isinstance(raw, dict):
        observed_at = _epoch(raw.get("observed_at", captured_at))
        used_percent = raw.get("used_percent")
        valid_percent = (_number(used_percent)
                         and 0 <= used_percent <= 100)
    last_left = 100.0 - float(used_percent) if valid_percent else None

    if not valid_percent or observed_at is None:
        state = "held"
    elif observed_at > evaluated_at:
        state = "held"
    elif base_state == "held":
        state = "held"
    elif base_state == "stale" \
            or evaluated_at - observed_at > OBSERVATION_MAX_AGE:
        state = "stale"
    elif used_percent >= 100:
        state = "limited"
    else:
        state = "current"

    return {
        "left_percent": last_left if state == "current" else None,
        "resets_at": resets_at,
        "observed_at": observed_at,
        "state": state,
        "last_observed_left_percent": (None if state == "current"
                                         else last_left),
    }


def _demote_windows(windows, state):
    for window in windows.values():
        if _number(window.get("left_percent")):
            window["last_observed_left_percent"] = window["left_percent"]
        window["left_percent"] = None
        window["state"] = state


def calculate_headline(accounts):
    """The glanceable metrics: fullest current 5h tank (legacy) plus the
    fleet's average battery per window.

    An average includes every LIVE reading: a current window contributes its
    left_percent and a limited window contributes 0 (an exhausted tank is an
    honest 0%, not a missing reading). Held/stale windows never count —
    unverified data must not move an average."""
    current = sum(1 for account in accounts
                  if account.get("state") == "current")
    candidates = []
    averages = {"5h": [], "7d": []}
    for account in accounts:
        windows = account.get("windows") or {}
        window = windows.get("5h") or {}
        value = window.get("left_percent")
        if (account.get("state") == "current"
                and window.get("state") == "current" and _number(value)):
            candidates.append(float(value))
        for key, pool in averages.items():
            entry = windows.get(key) or {}
            state = entry.get("state")
            left = entry.get("left_percent")
            if state == "current" and _number(left):
                pool.append(float(left))
            elif state == "limited":
                pool.append(0.0)
    def _avg(pool):
        return round(sum(pool) / len(pool), 1) if pool else None
    return {
        "current_accounts": current,
        "total_accounts": len(accounts),
        "fullest_5h_left_percent": max(candidates) if candidates else None,
        "avg_5h_left_percent": _avg(averages["5h"]),
        "avg_7d_left_percent": _avg(averages["7d"]),
    }


def project(snapshot, evaluated_at=None, force_noncurrent_reason=None):
    """Project a public usage snapshot to the ``headroom_widget@1`` contract."""
    evaluated_at = time.time() if evaluated_at is None else evaluated_at
    if not _number(evaluated_at):
        raise ValueError("evaluated_at must be a finite timestamp")
    freshness = _freshness(snapshot, evaluated_at, force_noncurrent_reason)
    raw_accounts = snapshot.get("accounts") \
        if isinstance(snapshot, dict) else None
    raw_accounts = raw_accounts if isinstance(raw_accounts, list) else []
    accounts = []
    for raw in raw_accounts:
        raw = raw if isinstance(raw, dict) else {}
        captured_at = _epoch(raw.get("captured_at"))
        base_state = _account_base_state(raw, freshness, evaluated_at)
        raw_windows = raw.get("windows")
        raw_windows = raw_windows if isinstance(raw_windows, dict) else {}
        windows = {}
        for key in WINDOW_KEYS:
            raw_window = raw_windows.get(key)
            # The 5h window is optional ONLY for the providers that lifted/omit
            # it (codex, grok — see NO_5H_PROVIDERS): a live codex seat reports
            # only weekly, and grok exposes a single weekly pool. A genuinely
            # ABSENT 5h on such an account is a lifted limit — omit it so it
            # neither renders as a failed read nor poisons the account state
            # below. A PRESENT but malformed 5h (e.g. "5h": null in a corrupt
            # snapshot) is NOT lifted: it falls through and projects held
            # (fail-closed). For any other provider a missing 5h is a failed read
            # that must project held, and the weekly (7d) stays mandatory for
            # everyone: a missing 7d still holds the seat.
            if (key == "5h" and key not in raw_windows and base_state != "held"
                    and raw.get("provider") in registry.NO_5H_PROVIDERS):
                continue
            windows[key] = _window_projection(raw_window, captured_at,
                                              base_state, evaluated_at)
        # model-scoped weekly windows (e.g. "scoped:Fable") ride along for
        # display with the same projection/demotion rules — but they never
        # drive the ACCOUNT state below: a scoped model cap does not block
        # the account's other models
        for key, raw_window in raw_windows.items():
            if isinstance(key, str) and key.startswith("scoped:") \
                    and key not in windows:
                windows[key] = _window_projection(
                    raw_window, captured_at, base_state, evaluated_at)
        states = {window["state"] for key, window in windows.items()
                  if key in WINDOW_KEYS}
        if base_state == "held" or "held" in states:
            state = "held"
        elif base_state == "stale" or "stale" in states:
            state = "stale"
        elif "limited" in states:
            state = "limited"
        else:
            state = "current"
        if state in {"held", "stale"}:
            _demote_windows(windows, state)
        accounts.append({
            "name": raw.get("name") if isinstance(raw.get("name"), str)
            else "unknown",
            "provider": (raw.get("provider")
                         if isinstance(raw.get("provider"), str) else "unknown"),
            "state": state,
            "windows": windows,
        })
    result = {"schema": SCHEMA, "freshness": freshness,
              "accounts": accounts}
    result["headline"] = calculate_headline(accounts)
    return result


project_widget = project
headline = calculate_headline


def sanitize(value, limit=160):
    """Make field-derived text inert in a one-line SwiftBar label."""
    text = str(value if value is not None else "")
    text = "".join(" " if unicodedata.category(char) in ("Cc", "Cf") else char
                   for char in text)
    text = " ".join(text.split())
    # A pipe begins SwiftBar parameters.  Full-width replacements also ensure
    # hostile field text cannot spell an execution parameter such as `bash=`.
    text = text.replace("|", "¦").replace("=", "﹦")
    return text[:limit]


sanitize_swiftbar = sanitize


def _display_percent(value):
    if not _number(value):
        return "--"
    rounded = round(value, 1)
    return str(int(rounded)) if rounded.is_integer() else str(rounded)


def _reset_label(value):
    if not _number(value):
        return "reset unknown"
    try:
        stamp = datetime.datetime.fromtimestamp(
            value, datetime.timezone.utc).strftime("%Y-%m-%d %H:%MZ")
    except (OSError, OverflowError, ValueError):
        return "reset unknown"
    return "resets " + stamp


def _tone(value):
    if not _number(value):
        return "gray"
    if value <= 10:
        return "red"
    if value <= 50:
        return "orange"
    return "green"


def _dashboard_tone(value):
    if not _number(value):
        return "unknown"
    if value <= 10:
        return "red"
    if value <= 30:
        return "orange"
    if value <= 50:
        return "yellow"
    return "green"


def _canonical_dashboard_href(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (parsed.scheme != "http" or parsed.hostname not in
            {"127.0.0.1", "localhost"} or port is None
            or not 1 <= port <= 65535
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        return None
    return "http://127.0.0.1:{}/".format(port)


def project_dashboard(snapshot, evaluated_at=None, force_noncurrent_reason=None):
    """Return the central projection plus inert tones used by dashboard DOM."""
    evaluated_at = time.time() if evaluated_at is None else evaluated_at
    result = project(snapshot, evaluated_at, force_noncurrent_reason)
    raw_accounts = snapshot.get("accounts") if isinstance(snapshot, dict) else []
    for index, account in enumerate(result["accounts"]):
        raw = raw_accounts[index] if index < len(raw_accounts) else {}
        raw = raw if isinstance(raw, dict) else {}
        raw_windows = raw.get("windows")
        raw_windows = raw_windows if isinstance(raw_windows, dict) else {}
        base_state = _account_base_state(raw, result["freshness"], evaluated_at)
        for key, raw_window in raw_windows.items():
            if not isinstance(key, str) or key in account["windows"]:
                continue
            window = _window_projection(
                raw_window, _epoch(raw.get("captured_at")), base_state,
                evaluated_at)
            if account["state"] in {"held", "stale"}:
                _demote_windows({key: window}, account["state"])
            account["windows"][key] = window
        for window in account["windows"].values():
            if (account["state"] == "current"
                    and window["state"] == "current"):
                window["tone"] = _dashboard_tone(window["left_percent"])
            elif (account["state"] == "limited"
                  and window["state"] == "limited"):
                window["tone"] = "red"
            else:
                window["tone"] = "unknown"
    return result


def render_swiftbar(value, evaluated_at=None, force_noncurrent_reason=None,
                    dashboard_href=None):
    """Render the one trusted SwiftBar representation, including sentinel."""
    href = _canonical_dashboard_href(dashboard_href) or DASHBOARD_HREF
    if value is None:
        return "\n".join([
            TEXT_SCHEMA,
            "hr OFFLINE | color=gray",
            "---",
            "Headroom feed unavailable | color=gray",
            "Refresh | refresh=true",
            "Open dashboard | href=" + href,
            "",
        ])
    widget = project(value, evaluated_at, force_noncurrent_reason)
    summary = widget["headline"]
    avg5 = summary["avg_5h_left_percent"]
    avg7 = summary["avg_7d_left_percent"]
    shown = _display_percent(avg5)
    suffix = shown + "%" if shown != "--" else shown
    shown7 = _display_percent(avg7)
    suffix7 = shown7 + "%" if shown7 != "--" else shown7
    lines = [TEXT_SCHEMA,
             "hr {}/{} · {} | color={}".format(
                 summary["current_accounts"], summary["total_accounts"],
                 suffix, _tone(avg5)),
             "---",
             "Avg battery: 5h {} · 7d {} | color=gray".format(
                 suffix if shown != "--" else "unavailable",
                 suffix7 if shown7 != "--" else "unavailable")]
    for account in widget["accounts"]:
        name = sanitize(account.get("name"))
        provider = sanitize(account.get("provider"))
        state = account.get("state") \
            if account.get("state") in {"current", "limited", "stale", "held"} \
            else "held"
        windows_map = account.get("windows") or {}
        # A lifted/absent 5h (codex, grok — NO_5H_PROVIDERS): when the session
        # window is absent, color the account row from the weekly (7d) so a
        # current seat reads green, not grey. project() already omitted the 5h
        # for those providers, so this fallback is reached only for them.
        primary = windows_map.get("5h") or windows_map.get("7d") or {}
        account_value = primary.get("left_percent")
        color = _tone(account_value) if state == "current" \
            else ("red" if state == "limited" else "gray")
        lines.append("{} · {} · {} | color={}".format(
            name, provider, state.upper(), color))
        for key in WINDOW_KEYS:
            # project() omits an absent 5h for a lifted-5h provider (codex, grok);
            # skip the dropped key so a current seat gets no phantom
            # "--5h: -- (held)" sub-row. 7d is always present (mandatory).
            if key not in windows_map:
                continue
            window = windows_map.get(key) or {}
            window_state = window.get("state")
            current_value = window.get("left_percent")
            last_value = window.get("last_observed_left_percent")
            display = current_value if _number(current_value) else last_value
            percent = _display_percent(display)
            if percent != "--":
                percent += "% left"
            live = state == "current" and window_state == "current"
            limited = state == "limited" and window_state == "limited"
            label = percent if live else "{} ({})".format(
                percent, sanitize(window_state or "held"))
            lines.append("--{}: {} · {} | color={}".format(
                key, label, _reset_label(window.get("resets_at")),
                _tone(current_value) if live else ("red" if limited else "gray")))
    lines.extend(["---", "Refresh | refresh=true",
                  "Open dashboard | href=" + href])
    return "\n".join(lines) + "\n"
