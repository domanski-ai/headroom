"""Opt-in, local-only token telemetry from Claude Code and Codex session logs.

Only timestamps and numeric usage counters survive parsing. Message content,
emails, and provider identities are never written to the token store. The
private incremental state necessarily records home-relative source paths,
byte offsets, mtimes, file identity/fingerprints, per-file daily subtotals,
and the bounded counter/dedupe metadata needed to resume an append-only log.

``total`` preserves the original input + output + cache creation accounting;
``grand_total`` also includes cache reads and drives Codex-mirror headlines.
Codex reports cached input as a subset of input, so it is split into uncached
``input`` and ``cache_read`` before aggregation.
"""
import collections
import contextlib
import datetime
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import time

from . import paths, registry


SCHEMA_VERSION = 3
DEFAULT_SCAN_INTERVAL = 900
MAX_PAYLOAD_DAYS = 400
MAX_SESSION_SECONDS = 48 * 60 * 60
MAX_LINE_BYTES = 1024 * 1024
READ_DRAIN_BYTES = 64 * 1024
DEDUPE_TAIL_RECORDS = 512
FINGERPRINT_BYTES = 4096
HANDOFF_MARKER_SCHEMA = "headroom_token_copy@1"
COUNT_KEYS = ("input", "output", "cache_read", "cache_creation", "total",
              "grand_total")
FAMILY_LABELS = ("fable", "opus", "sonnet", "haiku", "gpt", "other")
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


def handoff_marker_line():
    """One content-free JSONL boundary appended to every handoff target."""
    return (json.dumps({
        "type": "headroom_handoff",
        "headroom": {
            "schema": HANDOFF_MARKER_SCHEMA,
            "copied_prefix": True,
        },
    }, separators=(",", ":")) + "\n").encode("utf-8")


def _handoff_prefix_end(value):
    metadata = value.get("headroom") if isinstance(value, dict) else None
    return (value.get("type") == "headroom_handoff"
            and isinstance(metadata, dict)
            and metadata.get("schema") == HANDOFF_MARKER_SCHEMA
            and metadata.get("copied_prefix") is True)


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
    families = _normalized_mix(value.get("families"), FAMILY_LABELS)
    classified = sum(families.values())
    if classified > result["grand_total"]:
        return None
    if classified < result["grand_total"]:
        families["other"] = (families.get("other", 0)
                             + result["grand_total"] - classified)
    result.update({
        "session_count": _count(value.get("session_count", 0)) or 0,
        "longest_session_s": _count(value.get("longest_session_s", 0)) or 0,
        "families": families,
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
    family = family if family in FAMILY_LABELS else "other"
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


def _dedupe_tail(value):
    result = collections.OrderedDict()
    if not isinstance(value, list):
        return result
    for item in value[-DEDUPE_TAIL_RECORDS:]:
        if not isinstance(item, dict):
            continue
        signature = item.get("signature")
        maximum = _normalized_counts(item.get("maximum"))
        if not isinstance(signature, str) \
                or not re.fullmatch(r"[0-9a-f]{64}", signature) \
                or maximum is None:
            continue
        result.pop(signature, None)
        result[signature] = maximum
    return result


def _bounded_record_lines(handle, end):
    """Yield terminated, size-bounded physical records up to ``end``."""
    while handle.tell() < end:
        remaining = end - handle.tell()
        line = handle.readline(min(MAX_LINE_BYTES + 1, remaining))
        if not line:
            break
        if line.endswith(b"\n"):
            if len(line.rstrip(b"\r\n")) <= MAX_LINE_BYTES:
                yield handle.tell(), line
            continue
        if handle.tell() >= end:
            break  # final fragment: never parse or checkpoint it
        # The line exceeded the cap. Drain it in bounded chunks, then allow
        # later well-formed records to make progress without retaining it.
        while handle.tell() < end:
            chunk = handle.readline(min(READ_DRAIN_BYTES, end - handle.tell()))
            if not chunk:
                return
            terminated = chunk.endswith(b"\n")
            del chunk
            if terminated:
                break


def _parse_stream(handle, provider, start=0, previous=None, end=None):
    previous = previous or {}
    if end is None:
        position = handle.tell()
        handle.seek(0, os.SEEK_END)
        end = handle.tell()
        handle.seek(position)
    days = _normalized_days(previous.get("days")) if start else {}
    last_counter = (_normalized_counts(previous.get("last_counter"))
                    if start else None)
    first_event_ts = previous.get("first_event_ts") if start else None
    last_event_ts = previous.get("last_event_ts") if start else None
    current_family = previous.get("last_family") if start else None
    current_effort = previous.get("last_effort") if start else None
    seen = _dedupe_tail(previous.get("dedupe_tail")) if start else \
        collections.OrderedDict()
    valid_offset = start
    handle.seek(start)
    for record_end, line in _bounded_record_lines(handle, end):
        record = _record(line)
        if record is None:
            continue
        valid_offset = record_end
        if _handoff_prefix_end(record):
            # Everything through this boundary was already attributed to the
            # source slot. Retain counter/dedupe/model context only, so target
            # continuation records produce exact deltas.
            days = {}
            first_event_ts = None
            last_event_ts = None
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
                seen.pop(signature, None)
                seen[signature] = maximum
                while len(seen) > DEDUPE_TAIL_RECORDS:
                    seen.popitem(last=False)
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
    result = {"days": days, "offset": valid_offset}
    if first_event_ts is not None:
        result["first_event_ts"] = first_event_ts
        result["last_event_ts"] = last_event_ts
    if provider == "claude":
        result["dedupe_tail"] = [
            {"signature": signature, "maximum": maximum}
            for signature, maximum in seen.items()
        ]
    if provider == "codex":
        if last_counter is not None:
            result["last_counter"] = last_counter
        if current_family is not None:
            result["last_family"] = current_family
        if current_effort is not None:
            result["last_effort"] = current_effort
    return result


def _relative_parts(relative_path):
    parts = relative_path.split("/") if isinstance(relative_path, str) else []
    if not parts or any(part in ("", ".", "..") or os.sep in part
                        for part in parts):
        raise OSError("invalid token source path")
    return parts


def _inside_home(path, home):
    try:
        return os.path.commonpath((path, home)) == home and path != home
    except ValueError:
        return False


def _open_contained(home, relative_path):
    home = registry.expand(home)
    real_home = os.path.realpath(home)
    path = os.path.join(home, *_relative_parts(relative_path))
    if not _inside_home(os.path.realpath(path), real_home):
        raise OSError("token source escapes account home")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) \
                or not _inside_home(os.path.realpath(path), real_home):
            raise OSError("token source is not a contained regular file")
        current = os.stat(path, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("token source changed while opening")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _scan_file(home, relative_path, provider, previous=None):
    previous = previous if isinstance(previous, dict) else {}
    descriptor = _open_contained(home, relative_path)
    with os.fdopen(descriptor, "rb") as handle:
        bound = os.fstat(handle.fileno())  # size/mtime snapshot before reading
        fingerprint = hashlib.sha256(
            handle.read(min(FINGERPRINT_BYTES, bound.st_size))).hexdigest()
        same_file = (
            previous.get("st_dev") == bound.st_dev
            and previous.get("st_ino") == bound.st_ino
            and previous.get("fingerprint") == fingerprint
        )
        previous_offset = previous.get("offset")
        unchanged = (
            same_file
            and not previous.get("last_error")
            and isinstance(previous_offset, int)
            and previous_offset == previous.get("size") == bound.st_size
            and previous.get("mtime_ns") == bound.st_mtime_ns
        )
        if unchanged:
            return dict(previous)
        append = (same_file and isinstance(previous_offset, int)
                  and 0 <= previous_offset <= bound.st_size)
        result = _parse_stream(
            handle, provider, start=previous_offset if append else 0,
            previous=previous if append else None, end=bound.st_size)
    result.update({
        "size": bound.st_size,
        "mtime_ns": bound.st_mtime_ns,
        "st_dev": bound.st_dev,
        "st_ino": bound.st_ino,
        "fingerprint": fingerprint,
        "provider": provider,
    })
    return result


def _files(account):
    home = registry.expand(account["home"])
    root_name = "projects" if account["provider"] == "claude" else "sessions"
    root = os.path.join(home, root_name)
    for directory, subdirectories, filenames in os.walk(
            root, followlinks=False):
        subdirectories[:] = [name for name in subdirectories
                             if not os.path.islink(os.path.join(directory, name))]
        for name in filenames:
            if account["provider"] == "claude":
                matches = name.endswith(".jsonl")
            else:
                matches = name.startswith("rollout-") and name.endswith(".jsonl")
            path = os.path.join(directory, name)
            try:
                if not matches or not stat.S_ISREG(os.lstat(path).st_mode):
                    continue
            except OSError:
                continue
            yield os.path.relpath(path, home).replace(os.sep, "/")


def _ensure_storage():
    paths.ensure_private(paths.base_dir())
    paths.ensure_private(paths.state_dir())
    return paths.ensure_private(paths.tokens_dir())


@contextlib.contextmanager
def scan_lock(blocking=False):
    """Serialize token scans and slot purges independently of collection."""
    _ensure_storage()
    descriptor = os.open(
        paths.token_scan_lock_path(), os.O_RDWR | os.O_CREAT, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "a+") as lock:
        try:
            flags = fcntl.LOCK_EX
            if not blocking:
                flags |= fcntl.LOCK_NB
            fcntl.flock(lock, flags)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _daily_from_files(files):
    accounts = {}
    if not isinstance(files, dict):
        return accounts
    for slot_id, slot_files in files.items():
        if not isinstance(slot_id, str) or not isinstance(slot_files, dict):
            continue
        for entry in slot_files.values():
            if not isinstance(entry, dict):
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
    """Incrementally scan one exact registry view; return False when gated."""
    loaded_config = config is None
    config = registry.load() if loaded_config else config
    if not registry.token_stats_enabled(config):
        return False
    config_stamp = None
    if loaded_config:
        try:
            metadata = os.stat(paths.config_path())
            config_stamp = (metadata.st_dev, metadata.st_ino,
                            metadata.st_size, metadata.st_mtime_ns)
        except OSError:
            return False
    with scan_lock(blocking=False) as locked:
        if not locked:
            return False
        if loaded_config:
            try:
                metadata = os.stat(paths.config_path())
                if config_stamp != (metadata.st_dev, metadata.st_ino,
                                    metadata.st_size, metadata.st_mtime_ns):
                    return False
            except OSError:
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
                if isinstance(account, dict)
                and isinstance(account.get("id"), str)
                and account.get("provider") in registry.PROVIDERS
                and isinstance(account.get("home"), str)]
        files = {}
        failed_files = 0
        for account in live:
            slot_id = account["id"]
            provider = account["provider"]
            previous_files = old_files.get(slot_id)
            previous_files = previous_files \
                if isinstance(previous_files, dict) else {}
            slot_files = {}
            seen = set()
            for relative_path in _files(account):
                if relative_path in seen:
                    continue
                seen.add(relative_path)
                previous = previous_files.get(relative_path)
                compatible = (isinstance(previous, dict)
                              and previous.get("provider") == provider)
                try:
                    slot_files[relative_path] = _scan_file(
                        account["home"], relative_path, provider,
                        previous if compatible else None)
                except Exception as error:  # one bad file never hides the rest
                    failed_files += 1
                    retained = dict(previous) if compatible else {
                        "provider": provider, "days": {}, "offset": 0,
                    }
                    retained["last_error"] = type(error).__name__
                    retained["last_error_at"] = now
                    slot_files[relative_path] = retained
            files[slot_id] = slot_files
        daily = {
            "schema_version": SCHEMA_VERSION,
            "generated": now,
            "partial": failed_files > 0,
            "failed_file_count": failed_files,
            "accounts": _daily_from_files(files),
        }
        state = {
            "schema_version": SCHEMA_VERSION,
            "last_scan": now,
            "files": files,
        }
        paths.write_json_atomic(paths.token_daily_path(), daily, mode=0o600)
        paths.write_json_atomic(
            paths.token_scan_state_path(), state, mode=0o600)
        return True


def remove_account(slot_id):
    """Best-effort direct purge used even when token telemetry is disabled."""
    failures = []
    with scan_lock(blocking=True):
        state_path = paths.token_scan_state_path()
        state = paths.load_json(state_path)
        if state is None and os.path.exists(state_path):
            failures.append(f"unreadable {state_path}")
        state_files = state.get("files") if isinstance(state, dict) else None
        state_files = state_files if isinstance(state_files, dict) else {}
        if slot_id in state_files:
            del state_files[slot_id]
            paths.write_json_atomic(state_path, state, mode=0o600)
        failed_file_count = sum(
            1 for slot_files in (state_files or {}).values()
            if isinstance(slot_files, dict)
            for entry in slot_files.values()
            if isinstance(entry, dict) and entry.get("last_error")
        )

        daily_path = paths.token_daily_path()
        daily = paths.load_json(daily_path)
        if daily is None and os.path.exists(daily_path):
            failures.append(f"unreadable {daily_path}")
        daily_accounts = daily.get("accounts") \
            if isinstance(daily, dict) else None
        if isinstance(daily_accounts, dict):
            changed = daily_accounts.pop(slot_id, None) is not None
            partial_changed = (
                daily.get("failed_file_count") != failed_file_count
                or daily.get("partial") is not (failed_file_count > 0)
            )
            if changed or partial_changed:
                daily["failed_file_count"] = failed_file_count
                daily["partial"] = failed_file_count > 0
                paths.write_json_atomic(daily_path, daily, mode=0o600)
    if failures:
        raise RuntimeError("; ".join(failures))


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
    failed_file_count = _count(store.get("failed_file_count", 0)) or 0
    return {
        "generated": generated,
        "partial": store.get("partial") is True and failed_file_count > 0,
        "failed_file_count": failed_file_count,
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
