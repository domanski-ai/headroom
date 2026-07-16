"""Private rolling history of public usage-window percentages.

Ordinary writes are O(1) appends. Retention rewrites are amortized by waiting
until the oldest row exceeds retention by a full day, while a configurable
``HEADROOM_HISTORY_MAX_BYTES`` cap (32 MiB by default, 1 MiB minimum) forces
an earlier prune and trims an oversized retained set to 80%.
"""
import json
import math
import os
import tempfile
import time

from . import paths


SCHEMA_VERSION = 1
DEFAULT_MIN_INTERVAL = 60
DEFAULT_RETENTION_DAYS = 30
DEFAULT_MAX_BYTES = 32 * 1024 * 1024
MIN_MAX_BYTES = 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_CHART_POINTS = 200


def enabled():
    return os.environ.get("HEADROOM_HISTORY", "1") != "0"


def retention_days():
    return max(1, paths.env_int(
        "HEADROOM_HISTORY_RETENTION_DAYS", DEFAULT_RETENTION_DAYS))


def min_interval():
    return max(0, paths.env_int(
        "HEADROOM_HISTORY_MIN_INTERVAL", DEFAULT_MIN_INTERVAL))


def max_bytes():
    return max(MIN_MAX_BYTES, paths.env_int(
        "HEADROOM_HISTORY_MAX_BYTES", DEFAULT_MAX_BYTES))


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
        if isinstance(account, dict) and account.get("throttle_carryover"):
            continue
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


def _parse_line(line):
    payload = line.rstrip(b"\r\n")
    if not payload or len(payload) > MAX_LINE_BYTES:
        return None
    try:
        return _normalize_row(json.loads(
            payload.decode("utf-8", errors="replace")))
    except Exception:
        return None


def _read_rows(path):
    rows = []
    try:
        with open(path, "rb") as handle:
            for line in handle:
                row = _parse_line(line)
                if row is not None:
                    rows.append(row)
    except OSError:
        return []
    rows.sort(key=lambda row: row["ts"])
    return rows


def _oldest_row(path):
    try:
        with open(path, "rb") as handle:
            for line in handle:
                row = _parse_line(line)
                if row is not None:
                    return row
    except OSError:
        pass
    return None


def _tail_row(path):
    """Read only the final physical row; a corrupt tail is treated as empty."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            end = handle.tell()
            if end == 0:
                return None
            handle.seek(end - 1)
            if handle.read(1) == b"\n":
                end -= 1
            start = max(0, end - MAX_LINE_BYTES - 1)
            handle.seek(start)
            data = handle.read(end - start)
            newline = data.rfind(b"\n")
            if newline < 0 and start:
                return None
            return _parse_line(data[newline + 1:])
    except OSError:
        return None


def _file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


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


def _row_size(row):
    return len(json.dumps(
        row, allow_nan=False, separators=(",", ":")).encode("utf-8")) + 1


def _rows_within_bytes(rows, limit):
    kept = []
    size = 0
    for row in reversed(rows):
        row_size = _row_size(row)
        if size + row_size > limit:
            break
        kept.append(row)
        size += row_size
    return list(reversed(kept))


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
    path = paths.history_path()
    cap = max_bytes()
    oldest = _oldest_row(path)
    over_cap = _file_size(path) > cap
    prune_before = now - (retention_days() + 1) * 86400
    if over_cap or (oldest is not None and oldest["ts"] < prune_before):
        cutoff = now - retention_days() * 86400
        rows = [old for old in _read_rows(path) if old["ts"] >= cutoff]
        if over_cap and sum(_row_size(old) for old in rows) > cap:
            rows = _rows_within_bytes(rows, int(cap * .8))
        _write_rows_atomic(rows)
        newest = rows[-1] if rows else None
    else:
        newest = _tail_row(path)
    age = now - newest["ts"] if newest is not None else None
    if age is not None and 0 <= age < min_interval():
        return False
    row = project_snapshot(snapshot, ts=now)
    _append_row(row)
    return True


def remove_account(name):
    """Atomically remove one account from all history, never raising out."""
    try:
        path = paths.history_path()
        if not os.path.exists(path):
            return False
        rows = []
        changed = False
        for row in _read_rows(path):
            accounts = [account for account in row["accounts"]
                        if account["name"] != name]
            changed = changed or len(accounts) != len(row["accounts"])
            if accounts:
                rows.append({"ts": row["ts"], "accounts": accounts})
            else:
                changed = True
        _write_rows_atomic(rows)
        return changed
    except Exception:
        return False


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
