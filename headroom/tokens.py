"""Opt-in, local-only token telemetry from Claude Code and Codex session logs.

Only timestamps, numeric usage counters, sanitized one-segment project labels,
and registry slot names survive parsing. Message content, cwd paths, emails,
and provider identities are never written to the token store. The
private incremental state necessarily records home-relative source paths,
byte offsets, mtimes, file identity/fingerprints, per-file daily subtotals,
and the bounded counter/dedupe metadata needed to resume an append-only log.

Resource bounds are deliberately fixed: physical records are at most 1 MiB,
individual token counts are at most 10**12, only UTC days from 2020-01-01
through scan-time +2 days are accepted. One file retains at most 512 distinct days;
the daily store retains at most 3000 account/day entries. Scan state
tracks at most 50,000 files and 24 MiB of serialized data; cold files unchanged
for 30 days are compacted, then folded into per-file subtotal sentinels before
any last-resort entries are dropped. Crossing a cap after folding marks
telemetry partial.

``total`` preserves the original input + output + cache creation accounting;
``grand_total`` also includes cache reads and drives Codex-mirror headlines.
Codex reports cached input as a subset of input, so it is split into uncached
``input`` and ``cache_read`` before aggregation.
"""
import collections
import contextlib
import datetime
import hashlib
import json
import math
import ntpath
import os
import posixpath
import re
import stat
import time

from . import locks, paths, registry


SCHEMA_VERSION = 7
PREVIOUS_SCHEMA_VERSION = 6
DEFAULT_SCAN_INTERVAL = 900
MAX_PAYLOAD_DAYS = 400
MAX_SESSION_SECONDS = 48 * 60 * 60
MAX_LINE_BYTES = 1024 * 1024
READ_DRAIN_BYTES = 64 * 1024
MAX_TOKEN_COUNT = 10 ** 12
DEDUPE_TAIL_RECORDS = 512
FINGERPRINT_BYTES = 4096
MIN_TOKEN_DAY = datetime.date(2020, 1, 1)
MAX_FUTURE_DAYS = 2
MAX_FILE_DAYS = 512
MAX_GLOBAL_DAYS = 3000
MAX_TRACKED_FILES = 50_000
MAX_SERIALIZED_STATE_BYTES = 24 * 1024 * 1024
COMPACT_AFTER_SECONDS = 30 * 86400
WARM_FOLD_MEASURE_BATCH = 1024
HANDOFF_MARKER_SCHEMA = "headroom_token_copy@1"
COUNT_KEYS = ("input", "output", "cache_read", "cache_creation", "total",
              "grand_total")
FAMILY_LABELS = ("fable", "opus", "sonnet", "haiku", "gpt", "other")
EFFORT_LABELS = ("none", "minimal", "low", "medium", "high", "xhigh")
MAX_PROJECT_LABELS = 12
MAX_TOP_PROJECTS = 6
PROJECT_SCHEMA_VERSION = 1
EARLIER_ATTRIBUTION = "earlier"
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
        "projects": {},
        "attributed": {},
    })
    return result


def _safe_project_label(value):
    return (isinstance(value, str) and 1 <= len(value) <= 24
            and "@" not in value and "/" not in value and "\\" not in value
            and not any(ord(character) < 32 or ord(character) == 127
                        for character in value))


def _label_under_home(cwd, home, path_module):
    if not isinstance(home, str) or not path_module.isabs(home):
        return None
    cwd = path_module.normpath(cwd)
    home = path_module.normpath(home)
    try:
        common = path_module.commonpath((cwd, home))
    except (OSError, TypeError, ValueError):
        return None
    if path_module.normcase(common) != path_module.normcase(home):
        return None
    if path_module.normcase(cwd) == path_module.normcase(home):
        return "~"
    return path_module.relpath(cwd, home).split(path_module.sep, 1)[0]


def _recorded_home(cwd, path_module):
    """Infer the user-profile root from a path recorded on another host."""
    if path_module is posixpath:
        parts = cwd.split("/")
        if len(parts) >= 3 and parts[1] in ("home", "Users"):
            return "/".join(parts[:3])
        if len(parts) >= 2 and parts[1] == "root":
            return "/root"
        return None
    drive, tail = ntpath.splitdrive(cwd)
    parts = [part for part in tail.split("\\") if part]
    if parts and parts[0].casefold() in ("users", "documents and settings") \
            and len(parts) >= 2:
        return drive + "\\" + "\\".join(parts[:2])
    if drive.startswith("\\\\"):
        if ntpath.basename(drive).casefold() == "users" and parts:
            return drive + "\\" + parts[0]
        return drive + "\\"
    return None


def _project_label(cwd, home=None):
    """Reduce one cwd to a private, single-segment operator-home label."""
    if not isinstance(cwd, str) or not cwd:
        return None
    try:
        if "/" in cwd:
            path_module = posixpath
        elif re.match(r"^[A-Za-z]:\\", cwd) or cwd.startswith("\\\\"):
            path_module = ntpath
        else:
            return "other"
        if not path_module.isabs(cwd):
            return "other"
        cwd = path_module.normpath(cwd)
        homes = (home, os.environ.get("HOME"), os.environ.get("USERPROFILE"))
        label = next((candidate for candidate in (
            _label_under_home(cwd, value, path_module) for value in homes)
            if candidate is not None), None)
        if label is None:
            label = _label_under_home(
                cwd, _recorded_home(cwd, path_module), path_module)
        if label is None:
            return "other"
        return label if _safe_project_label(label) else "other"
    except (OSError, TypeError, ValueError):
        return "other"


def _safe_attribution_label(value):
    return (value == EARLIER_ATTRIBUTION
            or isinstance(value, str) and registry.NAME_RE.fullmatch(value))


def _is_extra_root(account):
    slot_id = account.get("id") if isinstance(account, dict) else None
    return isinstance(slot_id, str) and registry.VIRTUAL_ID_RE.fullmatch(slot_id)


def _current_extra_root_attribution(account, accounts):
    """Resolve a verified Claude extra-root email to one registry slot name."""
    if account.get("provider") != "claude" or not _is_extra_root(account):
        return None
    names_by_email = collections.defaultdict(set)
    for candidate in accounts:
        if _is_extra_root(candidate):
            continue
        email = candidate.get("expected_email")
        name = candidate.get("name")
        if isinstance(email, str) and isinstance(name, str):
            names_by_email[email.strip().casefold()].add(name)
    try:
        # Local import avoids collect.py -> tokens.py's module-load cycle. The
        # collector identity probe is read-only for the selected config home.
        from . import collect as usage_collect
        identity = usage_collect.claude_identity(account["home"])
        email = identity.get("email") if isinstance(identity, dict) else None
        if identity.get("verified") is not True or not isinstance(email, str):
            return None
        matches = names_by_email.get(email.strip().casefold(), set())
        return next(iter(matches)) if len(matches) == 1 else None
    except Exception:
        return None


def _sticky_attribution(previous, current):
    if isinstance(previous, dict):
        stamped = previous.get("attributed_slot")
        return stamped if _safe_attribution_label(stamped) \
            else EARLIER_ATTRIBUTION
    return current if _safe_attribution_label(current) \
        else EARLIER_ATTRIBUTION


def _count(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= MAX_TOKEN_COUNT else None
    if not math.isfinite(value) or value < 0 or value > MAX_TOKEN_COUNT \
            or int(value) != value:
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
    except RecursionError:
        return None
    except Exception:
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


def _model_family(model, provider=None):
    if not isinstance(model, str) or not model.strip():
        return None
    lowered = model.lower()
    if provider == "codex":
        return "gpt"
    return next((label for label in FAMILY_LABELS[:-1]
                 if label in lowered), "other")


def _effort_label(effort):
    if not isinstance(effort, str):
        return None
    lowered = effort.strip().lower()
    return lowered if lowered in EFFORT_LABELS else None


def parse_claude_record(line):
    """Return day, counts, identity hash, model family, and project label."""
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
    return (day, source, signature, _model_family(message.get("model")),
            _project_label(value.get("cwd")))


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
    return (_model_family(payload.get("model"), provider="codex"),
            _effort_label(payload.get("effort")
                          or payload.get("reasoning_effort")))


def _codex_project(value):
    payload = value.get("payload")
    payload = payload if isinstance(payload, dict) else {}
    kind = value.get("type") or payload.get("type")
    if kind != "session_meta":
        return None
    return _project_label(payload.get("cwd") or value.get("cwd"))


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


def _normalized_projects(value):
    if not isinstance(value, dict):
        return {}
    result = {}
    admitted = set()
    for raw_label, raw_count in value.items():
        count = _count(raw_count)
        if not count or not _safe_project_label(raw_label):
            continue
        label = raw_label
        if label != "other" and label not in admitted:
            if len(admitted) >= MAX_PROJECT_LABELS:
                label = "other"
            else:
                admitted.add(label)
        result[label] = result.get(label, 0) + count
    return result


def _normalized_attributed(value):
    if not isinstance(value, dict):
        return {}
    result = {}
    for label, raw_count in value.items():
        count = _count(raw_count)
        if count and _safe_attribution_label(label):
            result[label] = result.get(label, 0) + count
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
    projects = _normalized_projects(value.get("projects"))
    if sum(projects.values()) > result["grand_total"]:
        projects = {}
    attributed = _normalized_attributed(value.get("attributed"))
    if sum(attributed.values()) > result["grand_total"]:
        attributed = {}
    result.update({
        "session_count": _count(value.get("session_count", 0)) or 0,
        "longest_session_s": _count(value.get("longest_session_s", 0)) or 0,
        "families": families,
        "efforts": _normalized_mix(value.get("efforts"), EFFORT_LABELS),
        "projects": projects,
        "attributed": attributed,
    })
    return result


def _normalized_days(value, limit=None, partial=None):
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
            if limit is not None and day not in result and len(result) >= limit:
                if partial is not None:
                    partial[0] = True
                continue
            result[day] = normalized
    return result


def _add_counts(target, source):
    for key in COUNT_KEYS:
        target[key] += source[key]


def _add_mix(target, source):
    for label, count in source.items():
        target[label] = target.get(label, 0) + count


def _add_day(days, day, counts, family=None, effort=None, project=None,
             limit=None):
    if day not in days and limit is not None and len(days) >= limit:
        return False
    target = days.setdefault(day, _empty_day())
    _add_counts(target, counts)
    family = family if family in FAMILY_LABELS else "other"
    target["families"][family] = (
        target["families"].get(family, 0) + counts["grand_total"])
    if effort in EFFORT_LABELS:
        target["efforts"][effort] = (
            target["efforts"].get(effort, 0) + counts["grand_total"])
    if _safe_project_label(project):
        target["projects"][project] = (
            target["projects"].get(project, 0) + counts["grand_total"])
    return True


def _add_day_record(days, day, source):
    target = days.setdefault(day, _empty_day())
    _add_counts(target, source)
    target["session_count"] += source["session_count"]
    target["longest_session_s"] = max(
        target["longest_session_s"], source["longest_session_s"])
    _add_mix(target["families"], source["families"])
    _add_mix(target["efforts"], source["efforts"])
    _add_mix(target["projects"], source["projects"])
    _add_mix(target["attributed"], source["attributed"])


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
    """Yield every terminated physical record up to ``end``.

    Oversized records are represented by ``None`` after bounded draining so
    callers can checkpoint them without retaining their content. Only an
    unterminated EOF fragment is deliberately left before the checkpoint.
    """
    while handle.tell() < end:
        remaining = end - handle.tell()
        line = handle.readline(min(MAX_LINE_BYTES + 1, remaining))
        if not line:
            break
        if line.endswith(b"\n"):
            yield (handle.tell(), line
                   if len(line.rstrip(b"\r\n")) <= MAX_LINE_BYTES else None)
            continue
        if handle.tell() >= end:
            break  # final fragment: never parse or checkpoint it
        # The line exceeded the cap. Drain it in bounded chunks, then allow
        # later well-formed records to make progress without retaining it.
        record_end = None
        while handle.tell() < end:
            chunk = handle.readline(min(READ_DRAIN_BYTES, end - handle.tell()))
            if not chunk:
                return
            terminated = chunk.endswith(b"\n")
            del chunk
            if terminated:
                record_end = handle.tell()
                break
        if record_end is not None:
            yield record_end, None


def _parse_stream(handle, provider, start=0, previous=None, end=None, now=None):
    previous = previous or {}
    if end is None:
        position = handle.tell()
        handle.seek(0, os.SEEK_END)
        end = handle.tell()
        handle.seek(position)
    cap_reached = [False]
    days = _normalized_days(
        previous.get("days"), limit=MAX_FILE_DAYS,
        partial=cap_reached) if start else {}
    file_partial = previous.get("partial") is True or cap_reached[0]
    last_counter = (_normalized_counts(previous.get("last_counter"))
                    if start else None)
    first_event_ts = previous.get("first_event_ts") if start else None
    last_event_ts = previous.get("last_event_ts") if start else None
    current_family = previous.get("last_family") if start else None
    if provider == "codex" and current_family not in FAMILY_LABELS:
        current_family = "gpt"
    current_effort = previous.get("last_effort") if start else None
    current_project = previous.get("last_project") if start else None
    if not _safe_project_label(current_project):
        current_project = None
    seen = _dedupe_tail(previous.get("dedupe_tail")) if start else \
        collections.OrderedDict()
    valid_offset = start
    scan_day = datetime.datetime.fromtimestamp(
        time.time() if now is None else now, datetime.timezone.utc).date()
    latest_day = scan_day + datetime.timedelta(days=MAX_FUTURE_DAYS)

    def consume(line):
        nonlocal days, file_partial, last_counter, first_event_ts
        nonlocal last_event_ts, current_family, current_effort, current_project
        record = _record(line)
        if record is None:
            return
        if _handoff_prefix_end(record):
            # Everything through this boundary was already attributed to the
            # source slot. Retain counter/dedupe/model context only, so target
            # continuation records produce exact deltas.
            days = {}
            first_event_ts = None
            last_event_ts = None
            return
        event_ts = _timestamp(record.get("timestamp"))
        event_day = _day(event_ts)
        parsed_day = _date(event_day)
        event_allowed = (event_ts is not None and parsed_day is not None
                         and MIN_TOKEN_DAY <= parsed_day <= latest_day)
        if not event_allowed:
            if provider == "claude":
                parsed = parse_claude_record(record)
                if parsed is not None and parsed[2] is not None:
                    _delta, maximum = _message_delta(
                        parsed[1], seen.get(parsed[2]))
                    seen.pop(parsed[2], None)
                    seen[parsed[2]] = maximum
                    while len(seen) > DEDUPE_TAIL_RECORDS:
                        seen.popitem(last=False)
            else:
                parsed = parse_codex_record(record)
                if parsed is not None:
                    last_counter = parsed[1]
            return
        if first_event_ts is None:
            first_event_ts = event_ts
        last_event_ts = event_ts
        if provider == "claude":
            parsed = parse_claude_record(record)
            if parsed is None:
                return
            day, counts, signature, family, project = parsed
            if signature is not None:
                delta, maximum = _message_delta(counts, seen.get(signature))
                if delta["grand_total"] > 0:
                    if not _add_day(days, day, delta, family=family,
                                    project=project,
                                    limit=MAX_FILE_DAYS):
                        file_partial = True
                seen.pop(signature, None)
                seen[signature] = maximum
                while len(seen) > DEDUPE_TAIL_RECORDS:
                    seen.popitem(last=False)
            else:
                if not _add_day(days, day, counts, family=family,
                                project=project,
                                limit=MAX_FILE_DAYS):
                    file_partial = True
        else:
            project = _codex_project(record)
            if project is not None:
                current_project = project
            family, effort = _codex_context(record)
            if family is not None:
                current_family = family
            if effort is not None:
                current_effort = effort
            parsed = parse_codex_record(record)
            if parsed is None:
                return
            day, counter = parsed
            delta = _counter_delta(counter, last_counter)
            if delta["grand_total"] > 0:
                if not _add_day(days, day, delta, family=current_family,
                                effort=current_effort,
                                project=current_project,
                                limit=MAX_FILE_DAYS):
                    file_partial = True
            last_counter = counter

    handle.seek(start)
    for record_end, line in _bounded_record_lines(handle, end):
        valid_offset = record_end
        if line is None:
            continue
        try:
            consume(line)
        except RecursionError:
            continue
        except OverflowError:
            continue
        except Exception:
            continue
    result = {"days": days, "offset": valid_offset}
    if file_partial:
        result["partial"] = True
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
        if current_project is not None:
            result["last_project"] = current_project
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
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
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


def _stat_contained(home, relative_path):
    home = registry.expand(home)
    real_home = os.path.realpath(home)
    path = os.path.join(home, *_relative_parts(relative_path))
    if not _inside_home(os.path.realpath(path), real_home):
        raise OSError("token source escapes account home")
    current = os.lstat(path)
    if not stat.S_ISREG(current.st_mode):
        raise OSError("token source is not a contained regular file")
    return current


def _checkpoint_hash(handle, offset):
    start = max(0, offset - FINGERPRINT_BYTES)
    handle.seek(start)
    return hashlib.sha256(handle.read(offset - start)).hexdigest()


def _scan_file(home, relative_path, provider, previous=None, now=None):
    previous = previous if isinstance(previous, dict) else {}
    if previous.get("folded") is True:
        result = dict(previous)
        try:
            candidate = _stat_contained(home, relative_path)
        except OSError:
            result["_folded_changed"] = True
            return result
        if previous.get("size") != candidate.st_size \
                or previous.get("mtime_ns") != candidate.st_mtime_ns:
            result["_folded_changed"] = True
        return result
    candidate = _stat_contained(home, relative_path)
    previous_offset = previous.get("offset")
    unchanged = (
        not previous.get("last_error")
        and previous.get("st_dev") == candidate.st_dev
        and previous.get("st_ino") == candidate.st_ino
        and isinstance(previous_offset, int)
        and previous_offset == previous.get("size") == candidate.st_size
        and previous.get("mtime_ns") == candidate.st_mtime_ns
    )
    if unchanged:
        return dict(previous)
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
        append = (same_file and isinstance(previous_offset, int)
                  and 0 <= previous_offset <= bound.st_size
                  and isinstance(previous.get("checkpoint_hash"), str)
                  and previous["checkpoint_hash"] ==
                  _checkpoint_hash(handle, previous_offset))
        result = _parse_stream(
            handle, provider, start=previous_offset if append else 0,
            previous=previous if append else None, end=bound.st_size,
            now=now)
        result["checkpoint_hash"] = _checkpoint_hash(
            handle, result["offset"])
    result.update({
        "size": bound.st_size,
        "mtime_ns": bound.st_mtime_ns,
        "st_dev": bound.st_dev,
        "st_ino": bound.st_ino,
        "fingerprint": fingerprint,
        "provider": provider,
        "project_schema": PROJECT_SCHEMA_VERSION,
    })
    return result


def _files(account, errors=None):
    errors = [] if errors is None else errors
    home = registry.expand(account["home"])
    root_name = "projects" if account["provider"] == "claude" else "sessions"
    root = os.path.join(home, root_name)
    root_stat = os.lstat(root)
    real_home = os.path.realpath(home)
    if stat.S_ISLNK(root_stat.st_mode):
        raise OSError("symlinked token provider root")
    if not stat.S_ISDIR(root_stat.st_mode) \
            or not _inside_home(os.path.realpath(root), real_home):
        raise OSError("token provider root escapes account home")

    def walk_error(error):
        errors.append(error)

    for directory, subdirectories, filenames in os.walk(
            root, followlinks=False, onerror=walk_error):
        safe_subdirectories = []
        for name in subdirectories:
            try:
                if not stat.S_ISLNK(os.lstat(
                        os.path.join(directory, name)).st_mode):
                    safe_subdirectories.append(name)
            except OSError as error:
                errors.append(error)
        subdirectories[:] = safe_subdirectories
        for name in filenames:
            if account["provider"] == "claude":
                matches = name.endswith(".jsonl")
            else:
                matches = name.startswith("rollout-") and name.endswith(".jsonl")
            path = os.path.join(directory, name)
            try:
                if not matches or not stat.S_ISREG(os.lstat(path).st_mode):
                    continue
            except OSError as error:
                errors.append(error)
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
    paths.fchmod_private(descriptor, 0o600)
    with os.fdopen(descriptor, "a+") as lock:
        if not locks.exclusive(lock, blocking=blocking):
            yield False
            return
        try:
            yield True
        finally:
            locks.unlock(lock)


def _file_identity(entry):
    if not isinstance(entry, dict):
        return None
    device, inode = entry.get("st_dev"), entry.get("st_ino")
    if any(isinstance(value, bool) or not isinstance(value, int)
           for value in (device, inode)):
        return None
    return device, inode


def _serialized_state_size(state):
    return len(json.dumps(
        state, allow_nan=False, indent=2).encode("utf-8")) + 1


def _state_entries(files):
    entries = []
    for slot_id, slot_files in files.items():
        if not isinstance(slot_id, str) or not isinstance(slot_files, dict):
            continue
        for relative_path, entry in slot_files.items():
            if isinstance(relative_path, str) and isinstance(entry, dict):
                mtime = entry.get("mtime_ns")
                coldness = mtime if isinstance(mtime, int) else -1
                entries.append((coldness, slot_id, relative_path, entry))
    return sorted(entries, key=lambda item: item[:3])


def _entry_days(entry):
    capped = [False]
    days = _normalized_days(
        entry.get("days"), limit=MAX_FILE_DAYS, partial=capped)
    first = _timestamp(entry.get("first_event_ts"))
    last = _timestamp(entry.get("last_event_ts"))
    day = _day(first)
    if day is not None and last is not None:
        if day not in days and len(days) >= MAX_FILE_DAYS:
            capped[0] = True
        else:
            duration = min(MAX_SESSION_SECONDS, max(0, int(last - first)))
            aggregate = days.setdefault(day, _empty_day())
            aggregate["session_count"] += 1
            aggregate["longest_session_s"] = max(
                aggregate["longest_session_s"], duration)
    return days, capped[0]


def _fold_entry(state, slot_id, relative_path, entry):
    if entry.get("folded") is True or entry.get("partial") is True \
            or entry.get("last_error") \
            or entry.get("duplicate_identity") is True:
        return False
    sentinel_values = (entry.get("size"), entry.get("mtime_ns"))
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0
           for value in sentinel_values):
        return False
    entry_days, capped = _entry_days(entry)
    if capped:
        entry["partial"] = True
        return False
    state["files"][slot_id][relative_path] = {
        "size": entry.get("size"),
        "mtime_ns": entry.get("mtime_ns"),
        "st_dev": entry.get("st_dev"),
        "st_ino": entry.get("st_ino"),
        "days": entry_days,
        "folded": True,
    }
    if entry.get("project_schema") == PROJECT_SCHEMA_VERSION:
        state["files"][slot_id][relative_path]["project_schema"] = \
            PROJECT_SCHEMA_VERSION
    attributed_slot = entry.get("attributed_slot")
    if _safe_attribution_label(attributed_slot):
        state["files"][slot_id][relative_path]["attributed_slot"] = \
            attributed_slot
    return True


def _enforce_state_budgets(state, now):
    """Compact, fold, then last-resort drop until global budgets hold."""
    files = state["files"]
    entries = _state_entries(files)
    state["compacted_file_count"] = 0
    state["budget_dropped_files"] = {}
    state["budget_partial"] = False
    size = _serialized_state_size(state)
    if len(entries) <= MAX_TRACKED_FILES \
            and size <= MAX_SERIALIZED_STATE_BYTES:
        return 0, 0

    cutoff_ns = (now - COMPACT_AFTER_SECONDS) * 1_000_000_000
    compacted = 0
    for mtime, _slot_id, _relative_path, entry in entries:
        if mtime < 0:
            continue
        if mtime > cutoff_ns:
            break
        changed = False
        for key in ("dedupe_tail", "fingerprint", "checkpoint_hash"):
            if key in entry:
                del entry[key]
                changed = True
        if changed:
            compacted += 1
    state["compacted_file_count"] = compacted
    size = _serialized_state_size(state)
    if len(entries) <= MAX_TRACKED_FILES \
            and size <= MAX_SERIALIZED_STATE_BYTES:
        return compacted, 0

    measure_before_warm = len(entries) <= MAX_TRACKED_FILES
    folded_since_measure = 0
    in_warm_entries = False
    for mtime, slot_id, relative_path, entry in entries:
        warm = mtime > cutoff_ns
        if warm and not in_warm_entries:
            in_warm_entries = True
            if measure_before_warm and folded_since_measure:
                size = _serialized_state_size(state)
                folded_since_measure = 0
                if size <= MAX_SERIALIZED_STATE_BYTES:
                    break
        if _fold_entry(state, slot_id, relative_path, entry):
            folded_since_measure += 1
            if measure_before_warm and warm \
                    and folded_since_measure >= WARM_FOLD_MEASURE_BATCH:
                size = _serialized_state_size(state)
                folded_since_measure = 0
                if size <= MAX_SERIALIZED_STATE_BYTES:
                    break
    if folded_since_measure or not measure_before_warm:
        size = _serialized_state_size(state)

    if len(entries) <= MAX_TRACKED_FILES \
            and size <= MAX_SERIALIZED_STATE_BYTES:
        return compacted, 0

    dropped = collections.Counter()
    remaining = len(entries)
    drop_entries = sorted(
        _state_entries(files),
        key=lambda item: (item[3].get("folded") is True, item[:3]))
    next_index = 0
    while next_index < len(drop_entries) and (
            remaining > MAX_TRACKED_FILES
            or size > MAX_SERIALIZED_STATE_BYTES):
        _mtime, slot_id, relative_path, entry = drop_entries[next_index]
        next_index += 1
        slot_files = files.get(slot_id)
        if not isinstance(slot_files, dict) \
                or slot_files.get(relative_path) is not entry:
            continue
        member_size = (_serialized_state_size(relative_path)
                       + _serialized_state_size(entry) + 2)
        del slot_files[relative_path]
        dropped[slot_id] += 1
        remaining -= 1
        size = max(0, size - member_size)
    state["budget_dropped_files"] = dict(dropped)
    state["budget_partial"] = bool(dropped)
    size = _serialized_state_size(state)
    while next_index < len(drop_entries) \
            and size > MAX_SERIALIZED_STATE_BYTES:
        _mtime, slot_id, relative_path, entry = drop_entries[next_index]
        next_index += 1
        slot_files = files.get(slot_id)
        if not isinstance(slot_files, dict) \
                or slot_files.get(relative_path) is not entry:
            continue
        del slot_files[relative_path]
        dropped[slot_id] += 1
        remaining -= 1
        state["budget_dropped_files"] = dict(dropped)
        state["budget_partial"] = True
        size = _serialized_state_size(state)
    # Last-resort dropping only removes nested file entries. State that stays
    # over budget for any other reason (e.g. a pathological number of slot
    # mappings) must still be reported as partial rather than silently pass.
    if size > MAX_SERIALIZED_STATE_BYTES:
        state["budget_partial"] = True
    return compacted, sum(dropped.values())


def _daily_from_files(files, include_status=False):
    accounts = {}
    cardinality = 0
    partial = False
    seen_identities = set()
    if not isinstance(files, dict):
        return (accounts, partial) if include_status else accounts
    def merge_days(target, days, project_labels, owner=None,
                   attributed_slot=None):
        nonlocal cardinality, partial
        for day, counts in days.items():
            if day not in target and cardinality >= MAX_GLOBAL_DAYS:
                partial = True
                if owner is not None:
                    owner["partial"] = True
                continue
            if day not in target:
                cardinality += 1
            projects = {}
            for label, count in counts["projects"].items():
                if label != "other" and label not in project_labels:
                    if len(project_labels) >= MAX_PROJECT_LABELS:
                        label = "other"
                    else:
                        project_labels.add(label)
                projects[label] = projects.get(label, 0) + count
            source = dict(counts)
            source["projects"] = projects
            source["attributed"] = {}
            _add_day_record(target, day, source)
            if _safe_attribution_label(attributed_slot):
                aggregate = target[day]["attributed"]
                aggregate[attributed_slot] = (
                    aggregate.get(attributed_slot, 0)
                    + counts["grand_total"])

    for slot_id, slot_files in files.items():
        if not isinstance(slot_id, str) or not isinstance(slot_files, dict):
            continue
        project_labels = set()
        for entry in slot_files.values():
            if not isinstance(entry, dict):
                continue
            entry.pop("duplicate_identity", None)
            identity = _file_identity(entry)
            if identity is not None and identity in seen_identities:
                entry["duplicate_identity"] = True
                partial = True
                continue
            if identity is not None:
                seen_identities.add(identity)
            target = accounts.setdefault(slot_id, {})
            entry_days, capped = _entry_days(entry)
            partial = partial or capped or entry.get("partial") is True
            if capped:
                entry["partial"] = True
            merge_days(target, entry_days, project_labels, owner=entry,
                       attributed_slot=entry.get("attributed_slot"))
    return (accounts, partial) if include_status else accounts


def collect(accounts=None, config=None, now=None, force=False):
    """Incrementally scan authoritative registry and extra roots.

    ``accounts`` and ``config`` remain accepted for source compatibility but
    are intentionally ignored: opt-out and enumeration must come from one
    config view loaded under the config lock after the scan lock is held.
    """
    with scan_lock(blocking=False) as locked:
        if not locked:
            return False
        with registry.config_lock():
            authoritative_config = registry.load()
            if not registry.token_stats_enabled(authoritative_config):
                return False
            accounts, extra_roots_partial = registry.token_accounts(
                authoritative_config, include_status=True)
        now = int(time.time() if now is None else now)
        old_state = paths.load_json(paths.token_scan_state_path()) or {}
        state_version = old_state.get("schema_version") \
            if isinstance(old_state, dict) else None
        legacy_state = state_version == PREVIOUS_SCHEMA_VERSION
        if not isinstance(old_state, dict) or state_version not in (
                PREVIOUS_SCHEMA_VERSION, SCHEMA_VERSION):
            old_state = {}
            legacy_state = False
        last_scan = old_state.get("last_scan")
        if not force and not legacy_state and isinstance(last_scan, int) \
                and 0 <= now - last_scan < scan_interval():
            return False
        old_daily = paths.load_json(paths.token_daily_path())
        if not isinstance(old_daily, dict) \
                or old_daily.get("schema_version") not in (
                    PREVIOUS_SCHEMA_VERSION, SCHEMA_VERSION):
            old_daily = {
                "schema_version": SCHEMA_VERSION,
                "generated": 0,
                "partial": True,
                "failed_file_count": 0,
                "accounts": {},
            }
        last_success = old_daily.get("last_success")
        if not isinstance(last_success, int):
            generated = old_daily.get("generated")
            last_success = generated if isinstance(generated, int) \
                and generated > 0 else None
        attempted = dict(old_daily)
        attempted["schema_version"] = SCHEMA_VERSION
        attempted["last_attempt"] = now
        if last_success is not None:
            attempted["last_success"] = last_success
        paths.write_json_atomic(paths.token_daily_path(), attempted, mode=0o600)
        old_files = old_state.get("files")
        old_files = old_files if isinstance(old_files, dict) else {}
        live = [account for account in accounts
                if isinstance(account, dict)
                and isinstance(account.get("id"), str)
                and account.get("provider") in registry.PROVIDERS
                and isinstance(account.get("home"), str)]
        files = {}
        failed_files = 0
        failed_root_slot_ids = []
        folded_changed_files = collections.Counter()
        for account in live:
            slot_id = account["id"]
            provider = account["provider"]
            previous_files = old_files.get(slot_id)
            previous_files = previous_files \
                if isinstance(previous_files, dict) else {}
            previous_by_identity = {
                identity: entry for entry in previous_files.values()
                if (identity := _file_identity(entry)) is not None
            }
            current_attribution = _current_extra_root_attribution(
                account, live)
            stamps_sessions = (account.get("provider") == "claude"
                               and _is_extra_root(account))
            slot_files = {}
            seen = set()
            successful_identities = set()
            discovery_errors = []
            try:
                discovered = _files(account, errors=discovery_errors)
                for relative_path in discovered:
                    if relative_path in seen:
                        continue
                    seen.add(relative_path)
                    previous = previous_files.get(relative_path)
                    compatible = (isinstance(previous, dict)
                                  and (previous.get("provider") == provider
                                       or previous.get("folded") is True))
                    try:
                        scanned = _scan_file(
                            account["home"], relative_path, provider,
                            previous if compatible and not legacy_state else None,
                            now=now)
                        stamp_source = previous
                        if not isinstance(stamp_source, dict):
                            stamp_source = previous_by_identity.get(
                                _file_identity(scanned))
                        if stamps_sessions:
                            scanned["attributed_slot"] = _sticky_attribution(
                                stamp_source, current_attribution)
                        if scanned.pop("_folded_changed", False):
                            folded_changed_files[slot_id] += 1
                        slot_files[relative_path] = scanned
                        identity = _file_identity(scanned)
                        if identity is not None:
                            successful_identities.add(identity)
                    except Exception as error:  # one bad file never hides rest
                        failed_files += 1
                        retained = dict(previous) if compatible else {
                            "provider": provider, "days": {}, "offset": 0,
                        }
                        if stamps_sessions:
                            retained["attributed_slot"] = _sticky_attribution(
                                previous, current_attribution)
                        retained["last_error"] = type(error).__name__
                        retained["last_error_at"] = now
                        slot_files[relative_path] = retained
            except OSError as error:
                discovery_errors.append(error)
            if discovery_errors:
                failed_root_slot_ids.append(slot_id)
                for relative_path, previous in previous_files.items():
                    if relative_path not in seen and isinstance(previous, dict) \
                            and (previous.get("provider") == provider
                                 or previous.get("folded") is True):
                        if _file_identity(previous) in successful_identities:
                            continue
                        retained = dict(previous)
                        if stamps_sessions:
                            retained["attributed_slot"] = _sticky_attribution(
                                previous, current_attribution)
                        slot_files[relative_path] = retained
            else:
                for relative_path, previous in previous_files.items():
                    if relative_path not in seen and isinstance(previous, dict) \
                            and previous.get("folded") is True:
                        retained = dict(previous)
                        if stamps_sessions:
                            retained["attributed_slot"] = _sticky_attribution(
                                previous, current_attribution)
                        slot_files[relative_path] = retained
                        folded_changed_files[slot_id] += 1
            files[slot_id] = slot_files
        state = {
            "schema_version": SCHEMA_VERSION,
            "last_scan": now,
            "last_attempt": now,
            "last_success": now,
            "failed_root_count": len(failed_root_slot_ids),
            "failed_root_slot_ids": failed_root_slot_ids,
            "extra_roots_partial": extra_roots_partial,
            "folded_changed_files": dict(folded_changed_files),
            "files": files,
        }
        # Materialize aggregation-only markers before measuring serialized
        # state; the second pass below recomputes totals after any evictions.
        _daily_from_files(files)
        compacted_files, budget_dropped_files = _enforce_state_budgets(
            state, now)
        daily_accounts, aggregate_partial = _daily_from_files(
            files, include_status=True)
        partial_files = sum(
            1 for slot_files in files.values() if isinstance(slot_files, dict)
            for entry in slot_files.values()
            if isinstance(entry, dict) and entry.get("partial") is True)
        duplicate_files = sum(
            1 for slot_files in files.values() if isinstance(slot_files, dict)
            for entry in slot_files.values()
            if isinstance(entry, dict) and entry.get("duplicate_identity") is True)
        folded_changed_file_count = sum(folded_changed_files.values())
        partial = bool(extra_roots_partial or failed_files
                       or failed_root_slot_ids or partial_files
                       or duplicate_files or folded_changed_file_count
                       or budget_dropped_files
                       or aggregate_partial)
        daily = {
            "schema_version": SCHEMA_VERSION,
            "generated": now,
            "last_attempt": now,
            "last_success": now,
            "partial": partial,
            "failed_file_count": failed_files,
            "failed_root_count": len(failed_root_slot_ids),
            "failed_root_slot_ids": failed_root_slot_ids,
            "partial_file_count": partial_files,
            "duplicate_file_count": duplicate_files,
            "folded_changed_file_count": folded_changed_file_count,
            "compacted_file_count": compacted_files,
            "budget_dropped_file_count": budget_dropped_files,
            "accounts": daily_accounts,
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
        state_exists = os.path.exists(state_path)
        state_authoritative = (not state_exists or (
            isinstance(state, dict) and isinstance(state.get("files"), dict)))
        if not state_authoritative:
            failures.append(f"unreadable {state_path}")
        state_files = state.get("files") if isinstance(state, dict) else None
        state_files = state_files if isinstance(state_files, dict) else {}
        state_changed = False
        if slot_id in state_files:
            del state_files[slot_id]
            state_changed = True
        failed_root_slots = state.get("failed_root_slot_ids") \
            if isinstance(state, dict) else None
        if isinstance(failed_root_slots, list):
            remaining_failed_roots = sorted({
                value for value in failed_root_slots
                if isinstance(value, str) and value != slot_id
            })
            if remaining_failed_roots != failed_root_slots:
                state["failed_root_slot_ids"] = remaining_failed_roots
                state_changed = True
            if state.get("failed_root_count") != len(remaining_failed_roots):
                state["failed_root_count"] = len(remaining_failed_roots)
                state_changed = True
            failed_root_count = len(remaining_failed_roots)
        else:
            failed_root_count = None
        budget_dropped = state.get("budget_dropped_files") \
            if isinstance(state, dict) else None
        if isinstance(budget_dropped, dict):
            if slot_id in budget_dropped:
                del budget_dropped[slot_id]
                state_changed = True
            budget_dropped_file_count = sum(
                value for value in budget_dropped.values()
                if isinstance(value, int) and not isinstance(value, bool)
                and value > 0)
            budget_partial = bool(budget_dropped_file_count)
            if state.get("budget_partial") is not budget_partial:
                state["budget_partial"] = budget_partial
                state_changed = True
        else:
            budget_dropped_file_count = None
        folded_changed = state.get("folded_changed_files") \
            if isinstance(state, dict) else None
        if isinstance(folded_changed, dict):
            if slot_id in folded_changed:
                del folded_changed[slot_id]
                state_changed = True
            folded_changed_file_count = sum(
                value for value in folded_changed.values()
                if isinstance(value, int) and not isinstance(value, bool)
                and value > 0)
        else:
            folded_changed_file_count = 0
        if state_changed:
            paths.write_json_atomic(state_path, state, mode=0o600)
        failed_file_count = sum(
            1 for slot_files in (state_files or {}).values()
            if isinstance(slot_files, dict)
            for entry in slot_files.values()
            if isinstance(entry, dict) and entry.get("last_error")
        ) if state_authoritative else None
        partial_file_count = sum(
            1 for slot_files in (state_files or {}).values()
            if isinstance(slot_files, dict)
            for entry in slot_files.values()
            if isinstance(entry, dict) and entry.get("partial") is True
        ) if state_authoritative else None
        duplicate_file_count = sum(
            1 for slot_files in (state_files or {}).values()
            if isinstance(slot_files, dict)
            for entry in slot_files.values()
            if isinstance(entry, dict)
            and entry.get("duplicate_identity") is True
        ) if state_authoritative else None
        extra_roots_partial = state.get("extra_roots_partial") is True \
            if isinstance(state, dict) else False

        daily_path = paths.token_daily_path()
        daily = paths.load_json(daily_path)
        if daily is None and os.path.exists(daily_path):
            failures.append(f"unreadable {daily_path}")
        daily_accounts = daily.get("accounts") \
            if isinstance(daily, dict) else None
        if isinstance(daily_accounts, dict):
            changed = daily_accounts.pop(slot_id, None) is not None
            if failed_root_count is None:
                failed_root_count = _count(
                    daily.get("failed_root_count", 0)) or 0
            if budget_dropped_file_count is None:
                budget_dropped_file_count = _count(
                    daily.get("budget_dropped_file_count", 0)) or 0
            recalculated_partial = failed_file_count is not None and bool(
                extra_roots_partial or failed_file_count or failed_root_count
                or partial_file_count or duplicate_file_count
                or folded_changed_file_count
                or budget_dropped_file_count)
            partial_changed = failed_file_count is not None and any((
                daily.get("failed_file_count") != failed_file_count,
                daily.get("failed_root_count") != failed_root_count,
                isinstance(failed_root_slots, list)
                and daily.get("failed_root_slot_ids")
                != remaining_failed_roots,
                daily.get("partial_file_count") != partial_file_count,
                daily.get("duplicate_file_count", 0) != duplicate_file_count,
                daily.get("folded_changed_file_count", 0)
                != folded_changed_file_count,
                daily.get("budget_dropped_file_count", 0)
                != budget_dropped_file_count,
                daily.get("partial") is not recalculated_partial,
            ))
            if changed or partial_changed:
                if failed_file_count is not None:
                    daily["failed_file_count"] = failed_file_count
                    daily["failed_root_count"] = failed_root_count
                    if isinstance(failed_root_slots, list):
                        daily["failed_root_slot_ids"] = remaining_failed_roots
                    daily["partial_file_count"] = partial_file_count
                    daily["duplicate_file_count"] = duplicate_file_count
                    daily["folded_changed_file_count"] = \
                        folded_changed_file_count
                    daily["budget_dropped_file_count"] = \
                        budget_dropped_file_count
                    daily["partial"] = recalculated_partial
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


def _top_projects(totals, grand_total):
    ranked = sorted(
        ((label, count) for label, count in totals.items() if count > 0),
        key=lambda item: (-item[1], item[0]))[:MAX_TOP_PROJECTS]
    return [{
        "label": label,
        "grand_total": count,
        "share_pct": round(count * 100 / grand_total, 1)
        if grand_total else 0,
    } for label, count in ranked]


def _attributed_breakdown(totals):
    return [{"name": name, "grand_total": count}
            for name, count in sorted(
                totals.items(), key=lambda item: (-item[1], item[0]))
            if count > 0]


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


def summarize(store, accounts, now=None, partial=False):
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
    project_totals = {}
    longest_session = {"seconds": 0, "date": None, "account": None}
    account_rows = []
    for account in accounts:
        slot_id = account.get("id") if isinstance(account, dict) else None
        if not isinstance(slot_id, str):
            continue
        days = _normalized_days(raw_accounts.get(slot_id))
        days = {day: counts for day, counts in days.items()
                if _date(day) <= today}
        account_project_totals = {}
        attributed_totals = {}
        for day, counts in days.items():
            _add_day_record(fleet_days, day, counts)
            _add_mix(family_totals, counts["families"])
            _add_mix(effort_totals, counts["efforts"])
            _add_mix(project_totals, counts["projects"])
            _add_mix(account_project_totals, counts["projects"])
            _add_mix(attributed_totals, counts["attributed"])
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
        account_grand_total = sum(
            counts["grand_total"] for counts in days.values())
        row = {
            "id": slot_id,
            "name": account.get("name", ""),
            "provider": account.get("provider", ""),
            "lifetime": sum(counts["total"] for counts in days.values()),
            "lifetime_grand_total": account_grand_total,
            "last7d": sum(counts["total"] for day, counts in days.items()
                          if _date(day) >= last7_cutoff),
            "last7d_grand_total": sum(
                counts["grand_total"] for day, counts in days.items()
                if _date(day) >= last7_cutoff),
            "peak": _peak(days),
            "projects": _top_projects(
                account_project_totals, account_grand_total),
        }
        if _is_extra_root(account):
            row["attributed_breakdown"] = _attributed_breakdown(
                attributed_totals)
        account_rows.append(row)
    lifetime = sum(counts["total"] for counts in fleet_days.values())
    grand_total = sum(counts["grand_total"] for counts in fleet_days.values())
    active = [day for day, counts in fleet_days.items()
              if counts["grand_total"] > 0]
    current, longest = _streaks(active, today)
    generated_day = _date(_day(generated)) or today
    payload_end = min(generated_day, today)
    cutoff = payload_end - datetime.timedelta(days=MAX_PAYLOAD_DAYS - 1)
    payload_days = {
        day: {key: value for key, value in fleet_days[day].items()
              if key not in ("projects", "attributed")}
        for day in sorted(fleet_days)
        if cutoff <= _date(day) <= payload_end
    }
    families = _breakdown(family_totals, FAMILY_LABELS)
    efforts = _breakdown(effort_totals, EFFORT_LABELS)
    most_used = max(families, key=lambda item: (
        item["tokens"], -FAMILY_LABELS.index(item["label"])))
    most_used_model = ({"label": most_used["label"],
                        "share_pct": most_used["share_pct"]}
                       if most_used["tokens"] else
                       {"label": None, "share_pct": 0})
    failed_file_count = _count(store.get("failed_file_count", 0)) or 0
    failed_root_count = _count(store.get("failed_root_count", 0)) or 0
    partial_file_count = _count(store.get("partial_file_count", 0)) or 0
    duplicate_file_count = _count(store.get("duplicate_file_count", 0)) or 0
    folded_changed_file_count = _count(
        store.get("folded_changed_file_count", 0)) or 0
    compacted_file_count = _count(store.get("compacted_file_count", 0)) or 0
    budget_dropped_file_count = _count(
        store.get("budget_dropped_file_count", 0)) or 0
    return {
        "generated": generated,
        "partial": store.get("partial") is True or partial is True,
        "failed_file_count": failed_file_count,
        "failed_root_count": failed_root_count,
        "partial_file_count": partial_file_count,
        "duplicate_file_count": duplicate_file_count,
        "folded_changed_file_count": folded_changed_file_count,
        "compacted_file_count": compacted_file_count,
        "budget_dropped_file_count": budget_dropped_file_count,
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
            "projects": _top_projects(project_totals, grand_total),
        },
    }


def load_summary(accounts, now=None, partial=False):
    store = paths.load_json(paths.token_daily_path())
    return summarize(store, accounts, now=now, partial=partial) \
        if store is not None else None
