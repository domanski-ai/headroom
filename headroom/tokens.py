"""Opt-in, local-only token telemetry from Claude Code and Codex session logs.

Only timestamps and numeric usage counters survive parsing. Message content,
emails, and provider identities are never written to the token store. The
private incremental state necessarily records source paths plus byte offsets,
mtimes, per-file daily subtotals, and the minimum counter/dedupe metadata
needed to resume an append-only log.

``total`` is the dashboard headline: input + output + cache creation. Cache
reads are retained separately and can be added to ``total`` to obtain all
tokens processed. Codex reports cached input as a subset of input, so it is
split into uncached ``input`` and ``cache_read`` before aggregation.
"""
import datetime
import glob
import hashlib
import json
import math
import os
import re
import time

from . import paths, registry


SCHEMA_VERSION = 1
DEFAULT_SCAN_INTERVAL = 900
MAX_PAYLOAD_DAYS = 400
COUNT_KEYS = ("input", "output", "cache_read", "cache_creation", "total")
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def scan_interval():
    return max(0, paths.env_int(
        "HEADROOM_TOKEN_SCAN_INTERVAL", DEFAULT_SCAN_INTERVAL))


def _empty_counts():
    return {key: 0 for key in COUNT_KEYS}


def _count(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0 or int(value) != value:
        return None
    return int(value)


def _day(value):
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            parsed = datetime.datetime.fromtimestamp(
                value, datetime.timezone.utc)
        elif isinstance(value, str):
            parsed = datetime.datetime.fromisoformat(
                value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            parsed = parsed.astimezone(datetime.timezone.utc)
        else:
            return None
        return parsed.date().isoformat()
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def _record(line):
    try:
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        value = json.loads(line) if isinstance(line, str) else line
        return value if isinstance(value, dict) else None
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _usage_value(usage, key, default=0):
    if key not in usage:
        return default
    return _count(usage.get(key))


def parse_claude_record(line):
    """Return ``(UTC day, counts, message-identity hash)`` for one record."""
    value = _record(line)
    if value is None:
        return None
    message = value.get("message")
    if not isinstance(message, dict) or not (
            value.get("type") == "assistant"
            or message.get("role") == "assistant"):
        return None
    usage = message.get("usage")
    if not isinstance(usage, dict):
        return None
    source = {
        "input": _usage_value(usage, "input_tokens"),
        "output": _usage_value(usage, "output_tokens"),
        "cache_read": _usage_value(usage, "cache_read_input_tokens"),
        "cache_creation": _usage_value(
            usage, "cache_creation_input_tokens"),
    }
    if any(value is None for value in source.values()):
        return None
    source["total"] = (source["input"] + source["output"]
                       + source["cache_creation"])
    day = _day(value.get("timestamp"))
    if day is None or source["total"] + source["cache_read"] <= 0:
        return None
    identity = [value.get("requestId"), message.get("id")]
    if not any(isinstance(part, str) and part for part in identity):
        identity = [value.get("uuid")]
    signature = None
    if any(isinstance(part, str) and part for part in identity):
        raw = json.dumps(identity, separators=(",", ":"))
        signature = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return day, source, signature


def _codex_total_usage(value):
    payload = value.get("payload")
    payload = payload if isinstance(payload, dict) else {}
    if not (payload.get("type") == "token_count"
            or value.get("type") == "token_count"):
        return None
    info = payload.get("info")
    info = info if isinstance(info, dict) else {}
    candidates = (
        info.get("total_token_usage"),
        payload.get("total_token_usage"),
        value.get("total_token_usage"),
        payload.get("token_count"),
    )
    for candidate in candidates:
        if isinstance(candidate, dict):
            return candidate
    return None


def parse_codex_record(line):
    """Return ``(UTC day, absolute session counter)`` for a token event."""
    value = _record(line)
    if value is None:
        return None
    usage = _codex_total_usage(value)
    if usage is None:
        return None
    raw_input = _usage_value(usage, "input_tokens")
    output = _usage_value(usage, "output_tokens")
    cached = _usage_value(
        usage, "cached_input_tokens",
        _usage_value(usage, "cache_read_input_tokens"))
    if raw_input is None or output is None or cached is None \
            or cached > raw_input:
        return None
    counter = {
        "input": raw_input - cached,
        "output": output,
        "cache_read": cached,
        "cache_creation": 0,
    }
    counter["total"] = counter["input"] + counter["output"]
    day = _day(value.get("timestamp"))
    if day is None:
        return None
    return day, counter


def _normalized_counts(value):
    if not isinstance(value, dict):
        return None
    result = {}
    for key in COUNT_KEYS:
        count = _count(value.get(key))
        if count is None:
            return None
        result[key] = count
    if result["total"] != (result["input"] + result["output"]
                           + result["cache_creation"]):
        return None
    return result


def _normalized_days(value):
    result = {}
    if not isinstance(value, dict):
        return result
    for day, counts in value.items():
        normalized = _normalized_counts(counts)
        if isinstance(day, str) and DAY_RE.fullmatch(day) and normalized:
            try:
                datetime.date.fromisoformat(day)
            except ValueError:
                continue
            result[day] = normalized
    return result


def _add_counts(target, source):
    for key in COUNT_KEYS:
        target[key] += source[key]


def _add_day(days, day, counts):
    target = days.setdefault(day, _empty_counts())
    _add_counts(target, counts)


def _counter_delta(current, previous):
    previous = _normalized_counts(previous)
    if previous is None or any(current[key] < previous[key]
                               for key in COUNT_KEYS):
        return dict(current)
    delta = {key: current[key] - previous[key] for key in COUNT_KEYS}
    delta["total"] = (delta["input"] + delta["output"]
                      + delta["cache_creation"])
    return delta


def _message_delta(current, previous):
    """Return growth within one progressive Claude message usage record."""
    previous = _normalized_counts(previous)
    if previous is None:
        return dict(current), dict(current)
    maximum = {key: max(current[key], previous[key]) for key in COUNT_KEYS}
    maximum["total"] = (maximum["input"] + maximum["output"]
                        + maximum["cache_creation"])
    delta = {key: maximum[key] - previous[key] for key in COUNT_KEYS}
    delta["total"] = (delta["input"] + delta["output"]
                      + delta["cache_creation"])
    return delta, maximum


def _parse_stream(handle, provider, start=0, previous=None):
    previous = previous or {}
    days = _normalized_days(previous.get("days")) if start else {}
    last_claude = previous.get("last_claude") if start else None
    last_claude_counter = (_normalized_counts(
        previous.get("last_claude_counter")) if start else None)
    last_counter = (_normalized_counts(previous.get("last_counter"))
                    if start else None)
    seen = {}
    if last_claude and last_claude_counter is not None:
        seen[last_claude] = last_claude_counter
    handle.seek(start)
    while True:
        line = handle.readline()
        if not line:
            break
        if provider == "claude":
            parsed = parse_claude_record(line)
            if parsed is None:
                continue
            day, counts, signature = parsed
            if signature is not None:
                delta, maximum = _message_delta(counts, seen.get(signature))
                if delta["total"] + delta["cache_read"] > 0:
                    _add_day(days, day, delta)
                seen[signature] = maximum
                last_claude = signature
                last_claude_counter = maximum
            else:
                _add_day(days, day, counts)
        else:
            parsed = parse_codex_record(line)
            if parsed is None:
                continue
            day, counter = parsed
            delta = _counter_delta(counter, last_counter)
            if delta["total"] + delta["cache_read"] > 0:
                _add_day(days, day, delta)
            last_counter = counter
    result = {"days": days, "offset": handle.tell()}
    if provider == "claude" and last_claude:
        result["last_claude"] = last_claude
        result["last_claude_counter"] = last_claude_counter
    if provider == "codex" and last_counter is not None:
        result["last_counter"] = last_counter
    return result


def _scan_file(path, provider, previous, stat_result):
    previous = previous if isinstance(previous, dict) else {}
    previous_offset = previous.get("offset")
    append = (isinstance(previous_offset, int) and previous_offset >= 0
              and stat_result.st_size >= previous_offset
              and stat_result.st_size > previous.get("size", -1))
    start = previous_offset if append else 0
    with open(path, "rb") as handle:
        result = _parse_stream(
            handle, provider, start=start,
            previous=previous if append else None)
        final = os.fstat(handle.fileno())
    result.update({
        "size": final.st_size,
        "mtime_ns": final.st_mtime_ns,
        "provider": provider,
    })
    return result


def _patterns(account):
    home = account["home"]
    if account["provider"] == "claude":
        yield os.path.join(home, "projects", "**", "*.jsonl")
    else:
        yield os.path.join(home, "sessions", "**", "rollout-*.jsonl")


def _files(account):
    for pattern in _patterns(account):
        for path in glob.iglob(pattern, recursive=True):
            if os.path.isfile(path):
                yield os.path.realpath(path)


def _ensure_storage():
    paths.ensure_private(paths.base_dir())
    paths.ensure_private(paths.state_dir())
    return paths.ensure_private(paths.tokens_dir())


def _daily_from_files(files):
    accounts = {}
    for entry in files.values():
        if not isinstance(entry, dict):
            continue
        slot_id = entry.get("slot_id")
        if not isinstance(slot_id, str):
            continue
        target = accounts.setdefault(slot_id, {})
        for day, counts in _normalized_days(entry.get("days")).items():
            _add_day(target, day, counts)
    return accounts


def collect(accounts=None, config=None, now=None, force=False):
    """Incrementally scan live registry homes; return False when gated."""
    if not registry.token_stats_enabled(config):
        return False
    accounts = registry.accounts(config) if accounts is None else accounts
    now = int(time.time() if now is None else now)
    old_state = paths.load_json(paths.token_scan_state_path()) or {}
    if not isinstance(old_state, dict) \
            or old_state.get("schema_version") != SCHEMA_VERSION:
        old_state = {}
    last_scan = old_state.get("last_scan")
    if not force and isinstance(last_scan, int) \
            and 0 <= now - last_scan < scan_interval():
        return False
    old_files = old_state.get("files")
    old_files = old_files if isinstance(old_files, dict) else {}
    live = [account for account in accounts
            if isinstance(account, dict) and isinstance(account.get("id"), str)
            and account.get("provider") in registry.PROVIDERS
            and isinstance(account.get("home"), str)]
    live_ids = {account["id"] for account in live}
    files = {path: entry for path, entry in old_files.items()
             if isinstance(entry, dict)
             and entry.get("slot_id") not in live_ids}
    seen = set()
    for account in live:
        for path in _files(account):
            if path in seen:
                continue
            seen.add(path)
            previous = old_files.get(path)
            compatible = False
            try:
                stat_result = os.stat(path)
                compatible = (isinstance(previous, dict)
                              and previous.get("slot_id") == account["id"]
                              and previous.get("provider") == account["provider"])
                unchanged = (compatible
                             and previous.get("size") == stat_result.st_size
                             and previous.get("mtime_ns") == stat_result.st_mtime_ns)
                if unchanged:
                    files[path] = previous
                    continue
                scanned = _scan_file(
                    path, account["provider"],
                    previous if compatible else None, stat_result)
                scanned["slot_id"] = account["id"]
                files[path] = scanned
            except Exception:
                if compatible:
                    files[path] = previous
    daily = {
        "schema_version": SCHEMA_VERSION,
        "generated": now,
        "accounts": _daily_from_files(files),
    }
    state = {
        "schema_version": SCHEMA_VERSION,
        "last_scan": now,
        "files": files,
    }
    _ensure_storage()
    paths.write_json_atomic(paths.token_daily_path(), daily)
    paths.write_json_atomic(paths.token_scan_state_path(), state)
    return True


def _date(value):
    try:
        if not isinstance(value, str) or not DAY_RE.fullmatch(value):
            return None
        return datetime.date.fromisoformat(value)
    except ValueError:
        return None


def _peak(days):
    if not days:
        return {"date": None, "total": 0}
    day, counts = max(days.items(), key=lambda item: (
        item[1]["total"], item[0]))
    return {"date": day, "total": counts["total"]}


def _streaks(active_days, today):
    active = sorted({_date(day) for day in active_days if _date(day) is not None})
    if not active:
        return 0, 0
    longest = run = 1
    for index in range(1, len(active)):
        if active[index] == active[index - 1] + datetime.timedelta(days=1):
            run += 1
        else:
            run = 1
        longest = max(longest, run)
    end = today if today in active else today - datetime.timedelta(days=1)
    current = 0
    while end in active:
        current += 1
        end -= datetime.timedelta(days=1)
    return current, longest


def summarize(store, accounts, now=None):
    """Project private daily aggregates through the live slot allow-list."""
    if not isinstance(store, dict) or store.get("schema_version") != 1:
        return None
    raw_accounts = store.get("accounts")
    if not isinstance(raw_accounts, dict):
        return None
    now = int(time.time() if now is None else now)
    today = datetime.datetime.fromtimestamp(
        now, datetime.timezone.utc).date()
    generated = store.get("generated")
    generated = generated if isinstance(generated, int) else now
    fleet_days = {}
    account_rows = []
    for account in accounts:
        slot_id = account.get("id") if isinstance(account, dict) else None
        if not isinstance(slot_id, str):
            continue
        days = _normalized_days(raw_accounts.get(slot_id))
        days = {day: counts for day, counts in days.items()
                if _date(day) <= today}
        for day, counts in days.items():
            _add_day(fleet_days, day, counts)
        last7_cutoff = today - datetime.timedelta(days=6)
        account_rows.append({
            "id": slot_id,
            "name": account.get("name", ""),
            "provider": account.get("provider", ""),
            "lifetime": sum(counts["total"] for counts in days.values()),
            "last7d": sum(counts["total"] for day, counts in days.items()
                          if _date(day) >= last7_cutoff),
            "peak": _peak(days),
        })
    lifetime = sum(counts["total"] for counts in fleet_days.values())
    active = [day for day, counts in fleet_days.items()
              if counts["total"] + counts["cache_read"] > 0]
    current, longest = _streaks(active, today)
    cutoff = today - datetime.timedelta(days=MAX_PAYLOAD_DAYS - 1)
    payload_days = {day: fleet_days[day] for day in sorted(fleet_days)
                    if cutoff <= _date(day) <= today}
    return {
        "generated": generated,
        "days": payload_days,
        "accounts": account_rows,
        "summary": {
            "lifetime": lifetime,
            "peak": _peak(fleet_days),
            "current_streak": current,
            "longest_streak": longest,
        },
    }


def load_summary(accounts, now=None):
    store = paths.load_json(paths.token_daily_path())
    return summarize(store, accounts, now=now) if store is not None else None
