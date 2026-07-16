"""Private rolling history of public usage-window percentages."""
import json
import math
import os
import tempfile
import time

from . import paths


SCHEMA_VERSION = 1
DEFAULT_MIN_INTERVAL = 60
DEFAULT_RETENTION_DAYS = 30
MAX_CHART_POINTS = 200


def enabled():
    return os.environ.get("HEADROOM_HISTORY", "1") != "0"


def retention_days():
    return max(1, paths.env_int(
        "HEADROOM_HISTORY_RETENTION_DAYS", DEFAULT_RETENTION_DAYS))


def min_interval():
    return max(0, paths.env_int(
        "HEADROOM_HISTORY_MIN_INTERVAL", DEFAULT_MIN_INTERVAL))


def _finite_number(value, low=None, high=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        finite = math.isfinite(value)
        value = float(value)
    except (OverflowError, ValueError):
        return None
    if not finite:
        return None
    if low is not None and value < low:
        return None
    if high is not None and value > high:
        return None
    return value


def _project_account(account):
    if not isinstance(account, dict):
        return None
    name = account.get("name")
    provider = account.get("provider")
    if not isinstance(name, str) or not isinstance(provider, str):
        return None
    plan = account.get("plan")
    plan = plan if isinstance(plan, str) else None
    source_windows = account.get("windows")
    if source_windows is None:
        source_windows = {}
    if not isinstance(source_windows, dict):
        return None
    windows = {}
    for key, window in source_windows.items():
        if not isinstance(key, str) or not isinstance(window, dict):
            continue
        used = _finite_number(window.get("used_percent"), 0, 100)
        reset = _finite_number(window.get("resets_at"))
        windows[key] = {
            "used_percent": used,
            "resets_at": int(reset) if reset is not None else None,
        }
    return {
        "name": name,
        "provider": provider,
        "plan": plan,
        "ok": account.get("ok") is True,
        "stale": account.get("stale") is True,
        "windows": windows,
    }


def project_snapshot(snapshot, ts=None):
    """Deep-whitelist one public snapshot into the history row contract."""
    if not isinstance(snapshot, dict):
        raise ValueError("history snapshot must be an object")
    if ts is None:
        ts = int(time.time())
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) \
            or not math.isfinite(ts):
        raise ValueError("history timestamp must be finite")
    accounts = []
    for account in snapshot.get("accounts") or []:
        projected = _project_account(account)
        if projected is not None:
            accounts.append(projected)
    return {"ts": int(ts), "accounts": accounts}


def _normalize_row(value):
    if not isinstance(value, dict):
        return None
    ts = value.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, int):
        return None
    accounts = value.get("accounts")
    if not isinstance(accounts, list):
        return None
    projected = []
    for account in accounts:
        normalized = _project_account(account)
        if normalized is None:
            return None
        projected.append(normalized)
    return {"ts": ts, "accounts": projected}


def _read_rows(path):
    rows = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = _normalize_row(json.loads(line))
                except (TypeError, ValueError, json.JSONDecodeError):
                    row = None
                if row is not None:
                    rows.append(row)
    except OSError:
        return []
    rows.sort(key=lambda row: row["ts"])
    return rows


def _ensure_storage():
    paths.ensure_private(paths.base_dir())
    paths.ensure_private(paths.state_dir())
    return paths.ensure_private(paths.history_dir())


def _write_rows_atomic(rows):
    directory = _ensure_storage()
    descriptor, temporary = tempfile.mkstemp(
        prefix=".headroom-", suffix=".jsonl.tmp", dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for row in rows:
                json.dump(row, handle, allow_nan=False, separators=(",", ":"))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, paths.history_path())
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _append_row(row):
    _ensure_storage()
    descriptor = os.open(
        paths.history_path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        json.dump(row, handle, allow_nan=False, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def append_snapshot(snapshot, now=None):
    """Append one public snapshot, returning False when disabled/throttled."""
    if not enabled():
        return False
    now = int(time.time() if now is None else now)
    rows = _read_rows(paths.history_path())
    if rows and now - rows[-1]["ts"] < min_interval():
        return False
    row = project_snapshot(snapshot, ts=now)
    cutoff = now - retention_days() * 86400
    retained = [old for old in rows if old["ts"] >= cutoff]
    if len(retained) != len(rows):
        _write_rows_atomic(retained + [row])
    else:
        _append_row(row)
    return True


def load_series(days):
    """Load sanitized rows from the requested trailing-day range."""
    try:
        days = max(1, int(days))
    except (TypeError, ValueError):
        days = 1
    now = int(time.time())
    cutoff = now - days * 86400
    return [row for row in _read_rows(paths.history_path())
            if cutoff <= row["ts"] <= now]


def _samples(rows):
    accounts = {}
    for row in sorted(rows, key=lambda value: value["ts"]):
        ts = row["ts"]
        for account in row["accounts"]:
            if not account["ok"] or account["stale"]:
                continue
            identity = (account["provider"], account["name"])
            target = accounts.setdefault(identity, {
                "name": account["name"], "provider": account["provider"],
                "plan": account["plan"], "windows": {},
            })
            if account["plan"]:
                target["plan"] = account["plan"]
            for key, window in account["windows"].items():
                used = _finite_number(window.get("used_percent"), 0, 100)
                if used is None:
                    continue
                target["windows"].setdefault(key, []).append((ts, used))
    return accounts


def _episode_count(samples):
    episodes = 0
    active = False
    for _, value in samples:
        if not active and value >= 99.5:
            episodes += 1
            active = True
        elif active and value < 90:
            active = False
    return episodes


def summarize(days, rows=None):
    rows = load_series(days) if rows is None else rows
    result = []
    for account in _samples(rows).values():
        windows = {}
        for key, samples in account["windows"].items():
            peak_ts, peak_value = max(samples, key=lambda item: item[1])
            windows[key] = {
                "current": samples[-1][1],
                "peak": {"value": peak_value, "ts": peak_ts},
                "average": round(
                    sum(value for _, value in samples) / len(samples), 2),
                "cap_hit_episodes": _episode_count(samples),
                "sample_count": len(samples),
                "first_ts": samples[0][0],
                "last_ts": samples[-1][0],
            }
        result.append({
            "name": account["name"], "provider": account["provider"],
            "plan": account["plan"], "windows": windows,
        })
    return sorted(result, key=lambda item: (item["name"], item["provider"]))


def _bucket(samples):
    if not samples:
        return []
    span = max(1, samples[-1][0] - samples[0][0] + 1)
    width = max(1, math.ceil(span / MAX_CHART_POINTS))
    buckets = {}
    origin = samples[0][0]
    for ts, value in samples:
        index = (ts - origin) // width
        buckets.setdefault(index, []).append((ts, value))
    points = []
    for values in buckets.values():
        points.append({
            "ts": values[-1][0],
            "mean": round(sum(value for _, value in values) / len(values), 2),
            "max": max(value for _, value in values),
        })
    return points


def chart_series(days, rows=None):
    rows = load_series(days) if rows is None else rows
    result = []
    for account in _samples(rows).values():
        result.append({
            "name": account["name"], "provider": account["provider"],
            "plan": account["plan"],
            "windows": {key: _bucket(samples)
                        for key, samples in account["windows"].items()},
        })
    return sorted(result, key=lambda item: (item["name"], item["provider"]))


def leaderboard(days, rows=None):
    rows = load_series(days) if rows is None else rows
    ranked = []
    for account in summarize(days, rows=rows):
        weekly = account["windows"].get("7d")
        if weekly is None:
            continue
        ranked.append({
            "name": account["name"], "provider": account["provider"],
            "plan": account["plan"], "window": "7d",
            "average": weekly["average"],
            "cap_hit_episodes": weekly["cap_hit_episodes"],
            "current": weekly["current"], "peak": weekly["peak"],
            "sample_count": weekly["sample_count"],
        })
    ranked.sort(key=lambda item: (
        -item["average"], -item["cap_hit_episodes"],
        item["name"], item["provider"]))
    for index, account in enumerate(ranked, 1):
        account["rank"] = index
    return ranked


def response(days, rows=None, generated=None):
    rows = load_series(days) if rows is None else rows
    generated = int(time.time() if generated is None else generated)
    return {
        "schema_version": SCHEMA_VERSION, "generated": generated,
        "days": int(days), "series": chart_series(days, rows=rows),
        "summary": summarize(days, rows=rows),
        "leaderboard": leaderboard(days, rows=rows),
    }


def demo_rows(snapshot, days, now=None):
    """Create deterministic percentage-only history for ``serve --demo``."""
    now = int(time.time() if now is None else now)
    days = max(1, int(days))
    span = days * 86400
    points = 49
    rows = []
    source = project_snapshot(snapshot, ts=now)["accounts"]
    for index in range(points):
        ts = now - span + round(span * index / (points - 1))
        fraction = index / (points - 1)
        accounts = []
        for account_index, account in enumerate(source):
            windows = {}
            for window_index, (key, window) in enumerate(
                    account["windows"].items()):
                base = window["used_percent"]
                if base is None:
                    continue
                if index == points - 1:
                    used = base
                elif key == "5h":
                    cycle = (index % 8) / 7
                    used = base * .3 + cycle * max(12, base * .7)
                else:
                    wave = math.sin((index + account_index * 3
                                     + window_index) * .48) * 6
                    used = base * (.52 + .48 * fraction) + wave
                windows[key] = {
                    "used_percent": round(min(100, max(0, used)), 2),
                    "resets_at": window["resets_at"],
                }
            accounts.append({
                "name": account["name"], "provider": account["provider"],
                "plan": account["plan"], "ok": True, "stale": False,
                "windows": windows,
            })
        rows.append({"ts": ts, "accounts": accounts})
    return rows
