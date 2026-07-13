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


SCHEMA = "headroom_widget@1"
TEXT_SCHEMA = "headroom_widget_txt@1"
WINDOW_KEYS = ("5h", "7d")
SNAPSHOT_MAX_AGE = int(os.environ.get("HEADROOM_SNAPSHOT_MAX_AGE", "900"))
OBSERVATION_MAX_AGE = int(os.environ.get(
    "HEADROOM_OBSERVATION_MAX_AGE", "1800"))
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
    if account.get("trust_state") != "verified":
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


def calculate_headline(accounts):
    """Return the one glanceable metric: fullest current 5h tank."""
    current = sum(1 for account in accounts
                  if account.get("state") == "current")
    candidates = []
    for account in accounts:
        window = (account.get("windows") or {}).get("5h") or {}
        value = window.get("left_percent")
        if (account.get("state") == "current"
                and window.get("state") == "current" and _number(value)):
            candidates.append(float(value))
    return {
        "current_accounts": current,
        "total_accounts": len(accounts),
        "fullest_5h_left_percent": max(candidates) if candidates else None,
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
        windows = {
            key: _window_projection(raw_windows.get(key), captured_at,
                                    base_state, evaluated_at)
            for key in WINDOW_KEYS
        }
        states = {window["state"] for window in windows.values()}
        if base_state == "held" or "held" in states:
            state = "held"
        elif base_state == "stale" or "stale" in states:
            state = "stale"
        elif "limited" in states:
            state = "limited"
        else:
            state = "current"
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


def render_swiftbar(value, evaluated_at=None, force_noncurrent_reason=None,
                    dashboard_href=None):
    """Render the one trusted SwiftBar representation, including sentinel."""
    href = dashboard_href if isinstance(dashboard_href, str) \
        and dashboard_href.startswith(("http://127.0.0.1:",
                                       "http://localhost:")) else DASHBOARD_HREF
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
    widget = value if isinstance(value, dict) and value.get("schema") == SCHEMA \
        else project(value, evaluated_at, force_noncurrent_reason)
    summary = widget["headline"]
    fullest = summary["fullest_5h_left_percent"]
    shown = _display_percent(fullest)
    suffix = shown + "%" if shown != "--" else shown
    lines = [TEXT_SCHEMA,
             "hr {}/{} · {} | color={}".format(
                 summary["current_accounts"], summary["total_accounts"],
                 suffix, _tone(fullest)),
             "---",
             "Fullest tank: {} (current 5h) | color=gray".format(
                 suffix if shown != "--" else "unavailable")]
    for account in widget["accounts"]:
        name = sanitize(account.get("name"))
        provider = sanitize(account.get("provider"))
        state = account.get("state") \
            if account.get("state") in {"current", "limited", "stale", "held"} \
            else "held"
        five = (account.get("windows") or {}).get("5h") or {}
        account_value = five.get("left_percent")
        color = _tone(account_value) if state == "current" \
            else ("red" if state == "limited" else "gray")
        lines.append("{} · {} · {} | color={}".format(
            name, provider, state.upper(), color))
        for key in WINDOW_KEYS:
            window = (account.get("windows") or {}).get(key) or {}
            current_value = window.get("left_percent")
            last_value = window.get("last_observed_left_percent")
            display = current_value if _number(current_value) else last_value
            percent = _display_percent(display)
            if percent != "--":
                percent += "% left"
            label = percent if window.get("state") == "current" \
                else "{} ({})".format(percent, sanitize(window.get("state") or "held"))
            lines.append("--{}: {} · {} | color={}".format(
                key, label, _reset_label(window.get("resets_at")),
                _tone(current_value) if window.get("state") == "current"
                else ("red" if window.get("state") == "limited" else "gray")))
    lines.extend(["---", "Refresh | refresh=true",
                  "Open dashboard | href=" + href])
    return "\n".join(lines) + "\n"
