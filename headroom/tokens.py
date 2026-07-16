"""Opt-in, local-only token telemetry from Claude Code and Codex session logs.

Only timestamps and numeric usage counters survive parsing. Message content,
emails, and provider identities are never written to the token store. The
private incremental state necessarily records source paths plus byte offsets,
mtimes, per-file daily subtotals, and the minimum counter/dedupe metadata
needed to resume an append-only log.

``total`` preserves the original input + output + cache creation accounting;
``grand_total`` also includes cache reads and drives Codex-mirror headlines.
Codex reports cached input as a subset of input, so it is split into uncached
``input`` and ``cache_read`` before aggregation.
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


SCHEMA_VERSION = 2
DEFAULT_SCAN_INTERVAL = 900
MAX_PAYLOAD_DAYS = 400
MAX_SESSION_SECONDS = 48 * 60 * 60
COUNT_KEYS = ("input", "output", "cache_read", "cache_creation", "total",
              "grand_total")
FAMILY_LABELS = ("fable", "opus", "sonnet", "haiku", "other")
EFFORT_LABELS = ("none", "minimal", "low", "medium", "high", "xhigh")
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def scan_interval():
    return max(0, paths.env_int(
        "HEADROOM_TOKEN_SCAN_INTERVAL", DEFAULT_SCAN_INTERVAL))


def _empty_counts():
    return {key: 0 for key in COUNT_KEYS}


def _empty_day():
    result = _empty_counts()
    result.update({
        "session_count": 0,
        "longest_session_s": 0,
        "families": {},
        "efforts": {},
    })
    return result


def _count(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0 or int(value) != value:
        return None
    return int(value)


def _timestamp(value):
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return float(value) if math.isfinite(value) else None
        elif isinstance(value, str):
            parsed = datetime.datetime.fromisoformat(
                value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            parsed = parsed.astimezone(datetime.timezone.utc)
            return parsed.timestamp()
        else:
            return None
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def _day(value):
    timestamp = _timestamp(value)
    if timestamp is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(
            timestamp, datetime.timezone.utc).date().isoformat()
    except (OverflowError, OSError, ValueError):
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


def _model_family(model):
    if not isinstance(model, str) or not model.strip():
        return None
    lowered = model.lower()
    return next((label for label in FAMILY_LABELS[:-1]
                 if label in lowered), "other")


def _effort_label(effort):
    if not isinstance(effort, str):
        return None
    lowered = effort.strip().lower()
    return lowered if lowered in EFFORT_LABELS else None


def parse_claude_record(line):
    """Return day, counts, identity hash, and model family for a record."""
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
    source["grand_total"] = source["total"] + source["cache_read"]
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
    return day, source, signature, _model_family(message.get("model"))


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
    counter["grand_total"] = counter["total"] + counter["cache_read"]
    day = _day(value.get("timestamp"))
    if day is None:
        return None
    return day, counter


def _codex_context(value):
    payload = value.get("payload")
    payload = payload if isinstance(payload, dict) else {}
    kind = value.get("type") or payload.get("type")
    if kind != "turn_context":
        return None, None
    return (_model_family(payload.get("model")),
            _effort_label(payload.get("effort")
                          or payload.get("reasoning_effort")))


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
    if result["grand_total"] != result["total"] + result["cache_read"]:
        return None
    return result


def _normalized_mix(value, labels):
    if not isinstance(value, dict):
        return {}
    result = {}
    for label in labels:
        count = _count(value.get(label, 0))
        if count:
            result[label] = count
    return result


def _normalized_day(value):
    result = _normalized_counts(value)
    if result is None:
        return None
    result.update({
        "session_count": _count(value.get("session_count", 0)) or 0,
        "longest_session_s": _count(value.get("longest_session_s", 0)) or 0,
        "families": _normalized_mix(value.get("families"), FAMILY_LABELS),
        "efforts": _normalized_mix(value.get("efforts"), EFFORT_LABELS),
    })
    return result


def _normalized_days(value):
    result = {}
    if not isinstance(value, dict):
        return result
    for day, counts in value.items():
        normalized = _normalized_day(counts)
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


def _add_mix(target, source):
    for label, count in source.items():
        target[label] = target.get(label, 0) + count


def _add_day(days, day, counts, family=None, effort=None):
    target = days.setdefault(day, _empty_day())
    _add_counts(target, counts)
    if family in FAMILY_LABELS:
        target["families"][family] = (
            target["families"].get(family, 0) + counts["grand_total"])
    if effort in EFFORT_LABELS:
        target["efforts"][effort] = (
            target["efforts"].get(effort, 0) + counts["grand_total"])


def _add_day_record(days, day, source):
    target = days.setdefault(day, _empty_day())
    _add_counts(target, source)
    target["session_count"] += source["session_count"]
    target["longest_session_s"] = max(
        target["longest_session_s"], source["longest_session_s"])
    _add_mix(target["families"], source["families"])
    _add_mix(target["efforts"], source["efforts"])


def _counter_delta(current, previous):
    previous = _normalized_counts(previous)
    if previous is None or any(current[key] < previous[key]
                               for key in COUNT_KEYS):
        return dict(current)
    delta = {key: current[key] - previous[key] for key in COUNT_KEYS}
    delta["total"] = (delta["input"] + delta["output"]
                      + delta["cache_creation"])
    delta["grand_total"] = delta["total"] + delta["cache_read"]
    return delta


def _message_delta(current, previous):
    """Return growth within one progressive Claude message usage record."""
    previous = _normalized_counts(previous)
    if previous is None:
        return dict(current), dict(current)
    maximum = {key: max(current[key], previous[key]) for key in COUNT_KEYS}
    maximum["total"] = (maximum["input"] + maximum["output"]
                        + maximum["cache_creation"])
    maximum["grand_total"] = maximum["total"] + maximum["cache_read"]
    delta = {key: maximum[key] - previous[key] for key in COUNT_KEYS}
    delta["total"] = (delta["input"] + delta["output"]
                      + delta["cache_creation"])
    delta["grand_total"] = delta["total"] + delta["cache_read"]
    return delta, maximum


def _parse_stream(handle, provider, start=0, previous=None):
    previous = previous or {}
    days = _normalized_days(previous.get("days")) if start else {}
    last_claude = previous.get("last_claude") if start else None
    last_claude_counter = (_normalized_counts(
        previous.get("last_claude_counter")) if start else None)
    last_counter = (_normalized_counts(previous.get("last_counter"))
                    if start else None)
    first_event_ts = previous.get("first_event_ts") if start else None
    last_event_ts = previous.get("last_event_ts") if start else None
    current_family = previous.get("last_family") if start else None
    current_effort = previous.get("last_effort") if start else None
    seen = {}
    if last_claude and last_claude_counter is not None:
        seen[last_claude] = last_claude_counter
    handle.seek(start)
    while True:
        line = handle.readline()
        if not line:
            break
        record = _record(line)
        if record is None:
            continue
        event_ts = _timestamp(record.get("timestamp"))
        if event_ts is not None:
            if first_event_ts is None:
                first_event_ts = event_ts
            last_event_ts = event_ts
        if provider == "claude":
            parsed = parse_claude_record(record)
            if parsed is None:
                continue
            day, counts, signature, family = parsed
            if signature is not None:
                delta, maximum = _message_delta(counts, seen.get(signature))
                if delta["grand_total"] > 0:
                    _add_day(days, day, delta, family=family)
                seen[signature] = maximum
                last_claude = signature
                last_claude_counter = maximum
            else:
                _add_day(days, day, counts, family=family)
        else:
            family, effort = _codex_context(record)
            if family is not None:
                current_family = family
            if effort is not None:
                current_effort = effort
            parsed = parse_codex_record(record)
            if parsed is None:
                continue
            day, counter = parsed
            delta = _counter_delta(counter, last_counter)
            if delta["grand_total"] > 0:
                _add_day(days, day, delta, family=current_family,
                         effort=current_effort)
            last_counter = counter
    result = {"days": days, "offset": handle.tell()}
    if first_event_ts is not None:
        result["first_event_ts"] = first_event_ts
        result["last_event_ts"] = last_event_ts
    if provider == "claude" and last_claude:
        result["last_claude"] = last_claude
        result["last_claude_counter"] = last_claude_counter
    if provider == "codex" and last_counter is not None:
        result["last_counter"] = last_counter
        if current_family is not None:
            result["last_family"] = current_family
        if current_effort is not None:
            result["last_effort"] = current_effort
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
            _add_day_record(target, day, counts)
        first = _timestamp(entry.get("first_event_ts"))
        last = _timestamp(entry.get("last_event_ts"))
        day = _day(first)
        if day is not None and last is not None:
            duration = min(MAX_SESSION_SECONDS, max(0, int(last - first)))
            aggregate = target.setdefault(day, _empty_day())
            aggregate["session_count"] += 1
            aggregate["longest_session_s"] = max(
                aggregate["longest_session_s"], duration)
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
    active = {day: counts for day, counts in days.items()
              if counts["grand_total"] > 0}
    if not active:
        return {"date": None, "total": 0, "grand_total": 0}
    day, counts = max(active.items(), key=lambda item: (
        item[1]["grand_total"], item[0]))
    return {"date": day, "total": counts["total"],
            "grand_total": counts["grand_total"]}


def _breakdown(totals, labels):
    classified = sum(totals.values())
    return [{
        "label": label,
        "tokens": totals.get(label, 0),
        "share_pct": round(totals.get(label, 0) * 100 / classified, 1)
        if classified else 0,
    } for label in labels]


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
    if not isinstance(store, dict) \
            or store.get("schema_version") != SCHEMA_VERSION:
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
    family_totals = {label: 0 for label in FAMILY_LABELS}
    effort_totals = {label: 0 for label in EFFORT_LABELS}
    longest_session = {"seconds": 0, "date": None, "account": None}
    account_rows = []
    for account in accounts:
        slot_id = account.get("id") if isinstance(account, dict) else None
        if not isinstance(slot_id, str):
            continue
        days = _normalized_days(raw_accounts.get(slot_id))
        days = {day: counts for day, counts in days.items()
                if _date(day) <= today}
        for day, counts in days.items():
            _add_day_record(fleet_days, day, counts)
            _add_mix(family_totals, counts["families"])
            _add_mix(effort_totals, counts["efforts"])
            if counts["session_count"]:
                candidate = (counts["longest_session_s"], day,
                             account.get("name", ""))
                current = (longest_session["seconds"],
                           longest_session["date"] or "",
                           longest_session["account"] or "")
                if candidate > current:
                    longest_session = {
                        "seconds": counts["longest_session_s"],
                        "date": day,
                        "account": account.get("name", ""),
                    }
        last7_cutoff = today - datetime.timedelta(days=6)
        account_rows.append({
            "id": slot_id,
            "name": account.get("name", ""),
            "provider": account.get("provider", ""),
            "lifetime": sum(counts["total"] for counts in days.values()),
            "lifetime_grand_total": sum(
                counts["grand_total"] for counts in days.values()),
            "last7d": sum(counts["total"] for day, counts in days.items()
                          if _date(day) >= last7_cutoff),
            "last7d_grand_total": sum(
                counts["grand_total"] for day, counts in days.items()
                if _date(day) >= last7_cutoff),
            "peak": _peak(days),
        })
    lifetime = sum(counts["total"] for counts in fleet_days.values())
    grand_total = sum(counts["grand_total"] for counts in fleet_days.values())
    active = [day for day, counts in fleet_days.items()
              if counts["grand_total"] > 0]
    current, longest = _streaks(active, today)
    cutoff = today - datetime.timedelta(days=MAX_PAYLOAD_DAYS - 1)
    payload_days = {day: fleet_days[day] for day in sorted(fleet_days)
                    if cutoff <= _date(day) <= today}
    families = _breakdown(family_totals, FAMILY_LABELS)
    efforts = _breakdown(effort_totals, EFFORT_LABELS)
    most_used = max(families, key=lambda item: (
        item["tokens"], -FAMILY_LABELS.index(item["label"])))
    most_used_model = ({"label": most_used["label"],
                        "share_pct": most_used["share_pct"]}
                       if most_used["tokens"] else
                       {"label": None, "share_pct": 0})
    return {
        "generated": generated,
        "days": payload_days,
        "accounts": account_rows,
        "summary": {
            "lifetime": lifetime,
            "grand_total": grand_total,
            "peak": _peak(fleet_days),
            "current_streak": current,
            "longest_streak": longest,
            "total_sessions": sum(
                counts["session_count"] for counts in fleet_days.values()),
            "longest_session": longest_session,
            "active_days": len(active),
            "most_used_model": most_used_model,
            "families": families,
            "efforts": efforts,
        },
    }


def load_summary(accounts, now=None):
    store = paths.load_json(paths.token_daily_path())
    return summarize(store, accounts, now=now) if store is not None else None
