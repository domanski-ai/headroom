"""Private rolling history of public usage-window percentages.

Ordinary writes are O(1) appends. Retention rewrites are amortized by waiting
until the oldest row exceeds retention by a full day, while a configurable
``HEADROOM_HISTORY_MAX_BYTES`` cap (32 MiB by default, 1 MiB minimum) forces
an earlier prune and trims an oversized retained set to 80%. The history kill
switch stops background history access; explicit slot removal still attempts a
best-effort direct purge. Slot-generation IDs make registry membership
authoritative: removed rows may remain on disk, but are never served or merged
with a later slot that reuses the same display name.
"""
import errno
import fcntl
import json
import math
import os
import re
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
READ_DRAIN_BYTES = 64 * 1024
ID_RE = re.compile(r"^[0-9a-f]{12}$")


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


def _safe_label(value):
    return isinstance(value, str) and "@" not in value and len(value) <= 40


def _project_account(account):
    if not isinstance(account, dict):
        return None
    name = account.get("name")
    provider = account.get("provider")
    if not isinstance(name, str) or not isinstance(provider, str):
        return None
    slot_id = account.get("id")
    slot_id = slot_id if isinstance(slot_id, str) \
        and ID_RE.fullmatch(slot_id) else None
    plan = account.get("plan")
    plan = plan if _safe_label(plan) else None
    source_windows = account.get("windows")
    if source_windows is None:
        source_windows = {}
    if not isinstance(source_windows, dict):
        return None
    windows = {}
    for key, window in source_windows.items():
        if not _safe_label(key) or not isinstance(window, dict):
            continue
        used = _finite_number(window.get("used_percent"), 0, 100)
        reset = _finite_number(window.get("resets_at"))
        windows[key] = {
            "used_percent": used,
            "resets_at": int(reset) if reset is not None else None,
        }
    return {
        "id": slot_id,
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
        if projected is not None and projected["id"] is not None:
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
        if not _safe_label(normalized["name"]) \
                or not _safe_label(normalized["provider"]):
            continue
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


def _bounded_lines(handle):
    """Yield bounded physical lines without reading beyond the load budget."""
    budget = max_bytes() * 2
    file_size = os.fstat(handle.fileno()).st_size
    consumed = 0
    while consumed < budget:
        limit = min(MAX_LINE_BYTES + 1, budget - consumed)
        line = handle.readline(limit)
        if not line:
            break
        consumed += len(line)
        if line.endswith(b"\n"):
            yield line
            continue
        if len(line) < limit or handle.tell() >= file_size:
            if len(line) <= MAX_LINE_BYTES:
                yield line
            continue
        if limit < MAX_LINE_BYTES + 1:
            break
        del line
        while consumed < budget:
            chunk = handle.readline(min(READ_DRAIN_BYTES, budget - consumed))
            if not chunk:
                break
            consumed += len(chunk)
            ended = chunk.endswith(b"\n")
            del chunk
            if ended:
                break
    if handle.tell() < file_size:
        raise OSError(errno.EFBIG, "history read budget exceeded", handle.name)


def _read_rows(path):
    rows = []
    try:
        with open(path, "rb") as handle:
            for line in _bounded_lines(handle):
                row = _parse_line(line)
                if row is not None:
                    rows.append(row)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return []
        raise
    rows.sort(key=lambda row: row["ts"])
    return rows


def _oldest_row(path, now):
    try:
        with open(path, "rb") as handle:
            for line in _bounded_lines(handle):
                row = _parse_line(line)
                if row is not None and row["ts"] <= now + 300:
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
    return len(_encode_row(row)) + 1


def _encode_row(row):
    return json.dumps(
        row, allow_nan=False, separators=(",", ":")).encode("utf-8")


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


def _filter_live_rows(rows, live_ids):
    """Project rows to live slot generations; names are display labels only."""
    live_ids = set(live_ids)
    filtered = []
    for row in rows:
        accounts = [account for account in row["accounts"]
                    if account.get("id") in live_ids]
        if accounts:
            filtered.append({"ts": row["ts"], "accounts": accounts})
    return filtered


def _append_row(row):
    payload = _encode_row(row)
    if len(payload) > MAX_LINE_BYTES:
        raise ValueError("history row exceeds maximum line size")
    _ensure_storage()
    descriptor = os.open(
        paths.history_path(), os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "a+b") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            handle.seek(0, os.SEEK_END)
            end = handle.tell()
            prefix = b""
            if end:
                handle.seek(-1, os.SEEK_END)
                if handle.read(1) != b"\n":
                    prefix = b"\n"
            handle.write(prefix + payload + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def append_snapshot(snapshot, now=None, live_ids=None):
    """Append one public snapshot, returning False when disabled/throttled."""
    if not enabled():
        return False
    live_ids = None if live_ids is None else set(live_ids)
    now = int(time.time() if now is None else now)
    path = paths.history_path()
    cap = max_bytes()
    oldest = _oldest_row(path, now)
    over_cap = _file_size(path) > cap
    prune_before = now - (retention_days() + 1) * 86400
    if over_cap or (oldest is not None and oldest["ts"] < prune_before):
        cutoff = now - retention_days() * 86400
        try:
            loaded = _read_rows(path)
        except OSError as error:
            if over_cap:
                raise RuntimeError(
                    "history exceeds its byte cap; append skipped because "
                    f"pruning failed: {error}") from error
            loaded = None
        if loaded is not None:
            rows = [old for old in loaded
                    if cutoff <= old["ts"] <= now + 300]
            if live_ids is not None:
                # Physical cleanup is deliberately lazy. Correctness comes from
                # read-time allow-listing, so a failed prune cannot revive a slot.
                rows = _filter_live_rows(rows, live_ids)
            if over_cap and sum(_row_size(old) for old in rows) > cap:
                rows = _rows_within_bytes(rows, int(cap * .8))
            try:
                _write_rows_atomic(rows)
            except Exception as error:
                if over_cap:
                    raise RuntimeError(
                        "history exceeds its byte cap; append skipped because "
                        f"pruning failed: {error}") from error
                raise
            newest = rows[-1] if rows else None
        else:
            newest = _tail_row(path)
    else:
        newest = _tail_row(path)
    age = now - newest["ts"] if newest is not None else None
    if age is not None and 0 <= age < min_interval():
        return False
    row = project_snapshot(snapshot, ts=now)
    if live_ids is not None:
        filtered = _filter_live_rows([row], live_ids)
        row = filtered[0] if filtered else {"ts": now, "accounts": []}
    _append_row(row)
    return True


def remove_account(slot_id, legacy_name=None):
    """Best-effort hygiene purge for one ID and same-name legacy rows."""
    try:
        path = paths.history_path()
        try:
            os.stat(path)
        except OSError as error:
            if error.errno == errno.ENOENT:
                return False
            raise
        rows = []
        changed = False
        for row in _read_rows(path):
            accounts = [account for account in row["accounts"]
                        if not ((slot_id is not None
                                 and account.get("id") == slot_id)
                                or (account.get("id") is None
                                    and account["name"] == legacy_name))]
            changed = changed or len(accounts) != len(row["accounts"])
            if accounts:
                rows.append({"ts": row["ts"], "accounts": accounts})
            else:
                changed = True
        _write_rows_atomic(rows)
        return changed
    except Exception as error:
        raise RuntimeError(
            f"history purge failed for slot {slot_id!r}: {error}") from error


def load_series(days, live_ids):
    """Load trailing rows projected to the caller's live registry IDs."""
    if not enabled():
        return []
    try:
        days = max(1, int(days))
    except (TypeError, ValueError):
        days = 1
    now = int(time.time())
    cutoff = now - days * 86400
    rows = [row for row in _read_rows(paths.history_path())
            if cutoff <= row["ts"] <= now]
    return _filter_live_rows(rows, live_ids)


def _samples(rows):
    accounts = {}
    for row in sorted(rows, key=lambda value: value["ts"]):
        ts = row["ts"]
        for account in row["accounts"]:
            identity = account.get("id")
            if identity is None:
                continue
            target = accounts.setdefault(identity, {
                "id": identity, "name": account["name"],
                "provider": account["provider"],
                "plan": account["plan"], "windows": {}, "latest_ts": ts,
            })
            target["name"] = account["name"]
            target["provider"] = account["provider"]
            target["latest_ts"] = ts
            if not account["ok"] or account["stale"]:
                continue
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


def summarize(days, rows=None, generated=None, live_ids=None):
    rows = load_series(days, live_ids or set()) if rows is None else rows
    generated = int(time.time() if generated is None else generated)
    current_age_limit = 2 * min_interval() + 300
    result = []
    for account in _samples(rows).values():
        windows = {}
        for key, samples in account["windows"].items():
            peak_ts, peak_value = max(samples, key=lambda item: item[1])
            age = generated - samples[-1][0]
            current = samples[-1][1] \
                if samples[-1][0] == account["latest_ts"] \
                and 0 <= age <= current_age_limit else None
            windows[key] = {
                "current": current,
                "peak": {"value": peak_value, "ts": peak_ts},
                "average": round(
                    sum(value for _, value in samples) / len(samples), 2),
                "cap_hit_episodes": _episode_count(samples),
                "sample_count": len(samples),
                "first_ts": samples[0][0],
                "last_ts": samples[-1][0],
            }
        result.append({
            "id": account["id"], "name": account["name"],
            "provider": account["provider"],
            "plan": account["plan"], "windows": windows,
        })
    return sorted(result, key=lambda item: (
        item["name"], item["provider"], item["id"]))


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


def chart_series(days, rows=None, live_ids=None):
    rows = load_series(days, live_ids or set()) if rows is None else rows
    result = []
    for account in _samples(rows).values():
        result.append({
            "id": account["id"], "name": account["name"],
            "provider": account["provider"],
            "plan": account["plan"],
            "windows": {key: _bucket(samples)
                        for key, samples in account["windows"].items()},
        })
    return sorted(result, key=lambda item: (
        item["name"], item["provider"], item["id"]))


def leaderboard(days, rows=None, generated=None, live_ids=None):
    rows = load_series(days, live_ids or set()) if rows is None else rows
    ranked = []
    for account in summarize(days, rows=rows, generated=generated):
        weekly = account["windows"].get("7d")
        if weekly is None:
            continue
        ranked.append({
            "id": account["id"], "name": account["name"],
            "provider": account["provider"],
            "plan": account["plan"], "window": "7d",
            "average": weekly["average"],
            "cap_hit_episodes": weekly["cap_hit_episodes"],
            "current": weekly["current"], "peak": weekly["peak"],
            "sample_count": weekly["sample_count"],
        })
    ranked.sort(key=lambda item: (
        -item["average"], -item["cap_hit_episodes"],
        item["name"], item["provider"], item["id"]))
    for index, account in enumerate(ranked, 1):
        account["rank"] = index
    return ranked


def response(days, live_ids, rows=None, generated=None):
    rows = load_series(days, live_ids) if rows is None \
        else _filter_live_rows(rows, live_ids)
    generated = int(time.time() if generated is None else generated)
    return {
        "schema_version": SCHEMA_VERSION, "generated": generated,
        "days": int(days), "series": chart_series(days, rows=rows),
        "summary": summarize(days, rows=rows, generated=generated),
        "leaderboard": leaderboard(days, rows=rows, generated=generated),
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
                "id": account["id"], "name": account["name"],
                "provider": account["provider"],
                "plan": account["plan"], "ok": True, "stale": False,
                "windows": windows,
            })
        rows.append({"ts": ts, "accounts": accounts})
    return rows
