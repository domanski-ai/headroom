"""`headroom ops-status` — one read-only snapshot of every supervised session.

An operations layer sitting above this fleet needs to answer three questions
before it may touch anything: which supervised Claude sessions exist, is each
one MID-TURN or between turns, and does it still have context and battery to
finish. Every one of those answers already exists inside the supervisor — it
computes them on its own poll to decide whether a rotation is safe — but only
in-process, for the one child it owns.

This command is that same machinery, read from the OUTSIDE, for the whole
host. It deliberately calls the supervisor's own functions rather than
re-deriving anything: `_turn_is_complete`, `_agent_lifecycle`,
`_subagent_activity`, `_transcript_records`, `_context_used`. A second
implementation of "is this session busy" would drift from the first, and the
two would disagree exactly when it matters — the moment something is about to
restart a session that is still working.

Contract: read-only, no writes anywhere, no network, no LLM, sub-second, and
it degrades per session. One unreadable transcript costs that session's
fields, never the command. Exit 0 with valid JSON on stdout whenever ANY
source could be read; exit 1 only when none could.
"""
import json
import os
import subprocess
import sys
import time

from . import handoff, paths, registry, supervisor

SCHEMA = "headroom_ops_status@1"

PROC_ROOT = "/proc"
# the statusline republishes this file every render; older than this and the
# session is not rendering, so the number describes a window that has moved on
CTX_MAX_AGE = 15 * 60
# last few non-CwdChanged hook events, oldest first
RECENT_EVENTS = 5
# a status command may not hang on a wedged tmux server
TMUX_TIMEOUT = 2.0
# the journal is append-only and small; bound the read anyway (same discipline
# as _transcript_records — a status command's cost must not track history)
JOURNAL_TAIL_BYTES = 256 * 1024
# walking a pid's ancestry is bounded: a cycle in /proc would otherwise hang
MAX_ANCESTRY = 64
# the fleet's public battery feed, used only when headroom's own private
# snapshot cannot be read
FALLBACK_USAGE_PATH = "/var/lib/headroom/usage-fallback.json"

# `_turn_is_complete` answers "" or WHY the child may be mid-turn. Two of its
# reasons are not evidence of a turn at all — they say the transcript could
# not testify — and those must report unknown rather than a busy session that
# nothing may ever restart. Every other reason (including any added later)
# reads as in_flight: for an ops layer the fail-closed direction is "busy".
_TURN_UNKNOWN_PREFIXES = (
    "no completed assistant turn",
    "the transcript tail has an unreadable record",
)


# --- /proc ------------------------------------------------------------------

def _read_bytes(path, limit=None):
    try:
        with open(path, "rb") as handle:
            return handle.read() if limit is None else handle.read(limit)
    except OSError:
        return None


def _proc_environ(proc_root, pid):
    """The process's environment as a dict; {} when it cannot be read.

    A process owned by another user, or one that exited mid-scan, simply has
    no environment here — never an exception."""
    raw = _read_bytes(os.path.join(proc_root, str(pid), "environ"))
    if not raw:
        return {}
    environ = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        try:
            text = entry.decode("utf-8")
        except UnicodeError:
            continue
        key, separator, value = text.partition("=")
        if separator:
            environ[key] = value
    return environ


def _proc_cmdline(proc_root, pid):
    raw = _read_bytes(os.path.join(proc_root, str(pid), "cmdline"))
    if not raw:
        return []
    try:
        return [part for part in raw.decode("utf-8").split("\0") if part]
    except UnicodeError:
        return []


def _proc_stat_fields(proc_root, pid):
    """`(ppid, starttime_ticks)`, or `(None, None)`.

    The comm field is parenthesised and may itself contain spaces and
    parentheses, so the split starts after its LAST ')'."""
    raw = _read_bytes(os.path.join(proc_root, str(pid), "stat"))
    if not raw:
        return None, None
    try:
        text = raw.decode("utf-8", "replace")
    except UnicodeError:
        return None, None
    tail = text[text.rfind(")") + 1:].split()
    # tail[0] is state; fields 4 and 22 of stat are tail[1] and tail[19]
    try:
        return int(tail[1]), float(tail[19])
    except (IndexError, ValueError):
        return None, None


def _boot_time(proc_root):
    raw = _read_bytes(os.path.join(proc_root, "stat"), limit=1024 * 1024)
    if not raw:
        return None
    for line in raw.decode("utf-8", "replace").splitlines():
        if line.startswith("btime "):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def _clock_ticks():
    try:
        ticks = os.sysconf("SC_CLK_TCK")
    except (AttributeError, ValueError, OSError):
        return 100.0
    return float(ticks) if ticks and ticks > 0 else 100.0


def _pids(proc_root):
    """Every numeric entry under /proc, or None when /proc is unreadable."""
    try:
        return sorted(int(name) for name in os.listdir(proc_root)
                      if name.isdigit())
    except OSError:
        return None


def _is_supervised_child(argv, supervisor_id):
    """Whether this process looks like a supervised CLI rather than a shell.

    Every process a session spawns inherits HEADROOM_SUPERVISOR_ID, so the
    environment alone would report every shell and tool call as a session.
    Two independent discriminators, either of which is conclusive: the
    program IS `claude`, or it was handed the supervisor's own generated
    settings file (which only the supervisor writes, and only for its child).
    The second covers a claude installed behind a launcher argv[0]; the first
    covers a child launched without automation (no settings file at all).

    Necessary but NOT sufficient — see `_parent_holds_same_supervisor`."""
    if not argv:
        return False
    if os.path.basename(argv[0]) == "claude":
        return True
    marker = supervisor_id + "-"
    for index, arg in enumerate(argv):
        value = ""
        if arg == "--settings" and index + 1 < len(argv):
            value = argv[index + 1]
        elif arg.startswith("--settings="):
            value = arg.split("=", 1)[1]
        if not value:
            continue
        name = os.path.basename(value)
        if name.startswith(marker) and name.endswith(".settings.json"):
            return True
    return False


def _parent_holds_same_supervisor(proc_root, ppid, supervisor_id):
    """Whether this process is INSIDE a supervised session rather than being
    one.

    The supervisor injects HEADROOM_SUPERVISOR_ID *for the child it spawns*,
    so the supervised CLI is the unique process whose parent does not already
    carry that id. Everything a session then runs — a shell, a tool, and
    critically a headless `claude -p …` one-shot the session itself launched
    — inherits both the variable and, for that last one, the program name.
    Observed live on this fleet: four `claude -p` workers of the sales
    session, each reporting the SAME session id as their parent, which is
    precisely the duplicate-session shape an ops layer must never see.

    A NESTED supervisor is still reported: it generates a fresh id, so its
    child's parent carries a DIFFERENT one and the comparison passes."""
    if ppid is None or ppid <= 1:
        return False
    parent = _proc_environ(proc_root, ppid)
    return parent.get("HEADROOM_SUPERVISOR_ID", "") == supervisor_id


def supervised_children(proc_root=None):
    """Every live supervised Claude CLI process on this host.

    Returns None when the process table itself could not be read — the caller
    reports that as "nothing could be read", not as "no sessions"."""
    proc_root = PROC_ROOT if proc_root is None else proc_root
    pids = _pids(proc_root)
    if pids is None:
        return None
    boot = _boot_time(proc_root)
    ticks = _clock_ticks()
    found = []
    for pid in pids:
        environ = _proc_environ(proc_root, pid)
        supervisor_id = environ.get("HEADROOM_SUPERVISOR_ID", "")
        if not handoff._valid_uuid(supervisor_id):
            continue
        argv = _proc_cmdline(proc_root, pid)
        if not _is_supervised_child(argv, supervisor_id):
            continue
        ppid, starttime = _proc_stat_fields(proc_root, pid)
        if _parent_holds_same_supervisor(proc_root, ppid, supervisor_id):
            continue
        generation = environ.get("HEADROOM_CHILD_GENERATION", "")
        config_dir = environ.get("CLAUDE_CONFIG_DIR", "")
        if config_dir:
            try:
                config_dir = registry.expand(config_dir)
            except (OSError, ValueError):
                config_dir = ""
        found.append({
            "pid": pid,
            "supervisor_pid": ppid,
            "supervisor_id": supervisor_id,
            "generation": int(generation) if generation.isdigit() else None,
            "config_dir": config_dir,
            "argv": argv,
            # when the child started, in epoch seconds: `_subagent_activity`
            # uses it to discount sidechain transcripts a FORKED session
            # inherited from a process that has already exited
            "started_at": (boot + starttime / ticks
                           if boot is not None and starttime is not None
                           else None),
        })
    return found


# --- tmux -------------------------------------------------------------------

def tmux_panes(timeout=TMUX_TIMEOUT):
    """`{pane_pid: session_name}`, or None when tmux could not be consulted.

    None is not the same as {}: an empty map means tmux answered and nothing
    is running under it, so a session really is bare. None means we do not
    know, and the container is reported as unknown rather than as bare."""
    try:
        completed = subprocess.run(
            ["tmux", "list-panes", "-a", "-F", "#{session_name} #{pane_pid}"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    panes = {}
    for line in completed.stdout.decode("utf-8", "replace").splitlines():
        # a tmux session name may contain spaces; the pid is the last field
        name, _separator, pid = line.rstrip().rpartition(" ")
        if name and pid.isdigit():
            panes[int(pid)] = name
    return panes


def _container(proc_root, pid, panes):
    """The tmux session containing `pid`, "" when bare, None when unknown.

    A pane's pid is whatever the pane runs, which is rarely the CLI itself —
    a supervisor, or a wrapper waiting on a predecessor, sits between them.
    So walk the ancestry rather than matching the pid directly."""
    if panes is None or pid is None:
        return None
    seen = set()
    current = pid
    for _step in range(MAX_ANCESTRY):
        if current in panes:
            return panes[current]
        if current in seen or current <= 1:
            break
        seen.add(current)
        parent, _starttime = _proc_stat_fields(proc_root, current)
        if parent is None:
            return None
        current = parent
    return ""


# --- supervisor journal -----------------------------------------------------

def journal_records(supervisor_id):
    """Validated hook-event records for one supervisor, oldest first.

    Same envelope checks the supervisor's own reader applies: a record that
    is not shaped like a headroom hook event is dropped rather than trusted.
    Only the tail is parsed — a status command's cost must not grow with a
    session's history — and the partial record at the seek boundary is
    discarded the way `_transcript_records` discards it."""
    try:
        path = supervisor.event_path(supervisor_id)
    except (OSError, ValueError):
        return []
    try:
        with open(path, "rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            if size > JOURNAL_TAIL_BYTES:
                handle.seek(size - JOURNAL_TAIL_BYTES)
                handle.readline()
            data = handle.read()
    except OSError:
        return []
    records = []
    for line in data.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line.decode("utf-8"))
        except (UnicodeError, ValueError):
            continue
        if not isinstance(record, dict) \
                or record.get("schema") != "headroom_hook_event@1" \
                or not handoff._valid_uuid(record.get("supervisor_id")):
            continue
        payload = record.get("payload")
        received = record.get("received_at")
        if not isinstance(payload, dict) or not supervisor._number(received) \
                or payload.get("hook_event_name") \
                not in supervisor.HOOK_EVENTS:
            continue
        records.append(record)
    records.sort(key=lambda record: record["received_at"])
    return records


def _session_binding(records, generation):
    """`(session_id, transcript_path)` for the child of this generation.

    The journal, not the child's argv: a `--resume X --fork-session` launch
    runs as a NEW session id, so the argv names the conversation's ancestor
    and only the harness's own SessionStart names what is live."""
    for record in reversed(records):
        if generation is not None and record.get("generation") != generation:
            continue
        payload = record["payload"]
        session_id = payload.get("session_id")
        transcript = payload.get("transcript_path")
        if isinstance(session_id, str) and session_id:
            return session_id, (transcript if isinstance(transcript, str)
                                else "")
    return None, ""


def _recent_events(records):
    """The last few event names worth reporting, oldest first.

    CwdChanged is dropped: it fires on every directory move and would crowd
    out the transitions that actually describe a session's life."""
    names = [record["payload"]["hook_event_name"] for record in records
             if record["payload"].get("hook_event_name") != "CwdChanged"]
    return names[-RECENT_EVENTS:]


# --- context ----------------------------------------------------------------

def ctx_path(session_id):
    return os.path.join(paths.state_dir(), "ctx", session_id + ".json")


def _ctx_remaining(session_id, now):
    """The statusline's own published reading, or None when it cannot speak.

    This is the EXACT source: the session itself measured it against the
    window it is really running in. Stale means the session stopped
    rendering, so the number describes a window that has since moved."""
    if not session_id:
        return None
    try:
        payload = paths.load_json(ctx_path(session_id))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    timestamp = payload.get("ts")
    remaining = payload.get("remaining_percentage")
    if not supervisor._number(timestamp) or not supervisor._number(remaining):
        return None
    if now - timestamp > CTX_MAX_AGE:
        return None
    if not 0 <= remaining <= 100:
        return None
    return round(float(remaining), 1)


def _window_is_certain(used, model, environ=None):
    """Whether the context WINDOW for this reading is known rather than
    inferred from a coin-flip.

    ~200k tokens used is both "nearly dead" (standard window) and "barely
    started" (1M) — the estate's own §5 trap. A number is only reported when
    the window is pinned: an explicit override, a `[1m]` model on the child's
    own argv, or usage a standard window could not have served at all."""
    environ = os.environ if environ is None else environ
    override = str(environ.get("HEADROOM_CTX_WINDOW", "")).strip()
    if override:
        try:
            if int(override) > 0:
                return True
        except (TypeError, ValueError):
            pass
    if "[1m]" in str(model or "").lower():
        return True
    return bool(supervisor._number(used)
                and used > supervisor.CONTEXT_WINDOW_FIT_LIMIT)


def _context_remaining(session_id, transcript_path, model, now, environ=None):
    """Percent of context still free, or None.

    Primary source is the ctx file. Only when that is absent or stale does
    this fall back to the supervisor's OWN measurement of the transcript —
    and then only when the window it would be measured against is certain,
    so an unknown stays null instead of becoming a guess."""
    remaining = _ctx_remaining(session_id, now)
    if remaining is not None:
        return remaining
    if not transcript_path:
        return None
    used = supervisor._context_used(transcript_path)
    if used is None or not _window_is_certain(used, model, environ):
        return None
    window = supervisor._context_window(used, model, environ)
    remaining = supervisor._context_remaining(used, window)
    return None if remaining is None else round(float(remaining), 1)


# --- transcript activity ----------------------------------------------------

def _turn_state(reason):
    if reason == "":
        return "complete"
    for prefix in _TURN_UNKNOWN_PREFIXES:
        if reason.startswith(prefix):
            return "unknown"
    return "in_flight"


def _activity(transcript_path, now, since):
    """`(turn, subagents, last_write_epoch)` for one session.

    Every judgement here is the supervisor's own, called directly: the turn
    shape it trusts before a rotation, the parent ledger of background agents
    it started, and the bounded sidechain walk that proves none is working.
    Nothing about idleness is decided from mtime — recency can prove work,
    never completion."""
    if not transcript_path:
        return "unknown", "unknown", None
    try:
        mtime = os.stat(transcript_path).st_mtime
    except OSError:
        return "unknown", "unknown", None
    try:
        records, complete, malformed = supervisor._transcript_records(
            transcript_path)
        if malformed:
            return "unknown", "unknown", mtime
        turn = _turn_state(
            supervisor._turn_is_complete(transcript_path, records, complete))
        launched, finished = supervisor._agent_lifecycle(records)
        busy = supervisor._subagent_activity(
            transcript_path, now, supervisor.PREEMPT_IDLE_SECONDS,
            since=since or 0.0, launched=launched, finished=finished)
    except Exception:  # noqa: BLE001 — one session never breaks the report
        return "unknown", "unknown", mtime
    return turn, ("active" if busy else "idle"), mtime


# --- seats ------------------------------------------------------------------

def _window_used(windows, *names):
    """`used_percent` for the first window key that matches, else None.

    Key spellings differ between feeds — headroom writes `scoped:Fable`, the
    published fleet feed writes `fable` — so match case-insensitively on both
    the bare and the `scoped:` form."""
    if not isinstance(windows, dict):
        return None
    wanted = set()
    for name in names:
        wanted.add(name.lower())
        wanted.add("scoped:" + name.lower())
    for key, window in windows.items():
        if not isinstance(key, str) or key.lower() not in wanted:
            continue
        used = window.get("used_percent") if isinstance(window, dict) else None
        if supervisor._number(used):
            return round(float(used), 1)
    return None


def _seat_index():
    """`(by account name, by resolved home)` -> seat name.

    The seat name is the config home's BASENAME, because that is what a
    session's own CLAUDE_CONFIG_DIR reports — it is the only key on which the
    two halves of this report (sessions and batteries) can be joined. The
    by-home map exists so a session whose config dir reaches a home through a
    symlink still resolves to the same seat."""
    try:
        accounts = registry.accounts()
    except (registry.RegistryError, OSError, ValueError):
        return {}, {}
    by_name, by_home = {}, {}
    for account in accounts:
        home = account.get("home")
        name = account.get("name")
        if not isinstance(home, str) or not home:
            continue
        seat = os.path.basename(os.path.normpath(home))
        # a dotted home (~/.claude, ~/.codex) is the DEFAULT location, not a
        # seat identity — such an account names itself instead
        if seat.startswith(".") and name:
            seat = name
        if name:
            by_name[name] = seat
        try:
            by_home[registry.expand(home)] = seat
        except (OSError, ValueError):
            pass
    return by_name, by_home


def seats(fallback_path=None):
    """Per-seat batteries, or None when no usage snapshot could be read."""
    fallback_path = (FALLBACK_USAGE_PATH if fallback_path is None
                     else fallback_path)
    snapshot = None
    try:
        snapshot = paths.load_json(paths.private_snapshot_path())
    except (OSError, ValueError):
        snapshot = None
    if not isinstance(snapshot, dict):
        snapshot = paths.load_json(fallback_path)
    rows = snapshot.get("accounts") if isinstance(snapshot, dict) else None
    if not isinstance(rows, list):
        return None
    names = _seat_index()[0]
    out = []
    for row in rows:
        if not isinstance(row, dict) or not row.get("name"):
            continue
        windows = row.get("windows")
        out.append({
            "name": names.get(row["name"], row["name"]),
            "fable_used": _window_used(windows, "fable"),
            "five_h_used": _window_used(windows, "5h"),
            "seven_d_used": _window_used(windows, "7d"),
        })
    out.sort(key=lambda seat: seat["name"])
    return out


# --- report -----------------------------------------------------------------

def _iso(epoch):
    if not supervisor._number(epoch):
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _seat_of(config_dir, by_home):
    """The seat this session is running on, or None when it has no config
    home at all. Never invented: an unregistered home still names itself."""
    if not config_dir:
        return None
    seat = by_home.get(config_dir)
    return seat or os.path.basename(os.path.normpath(config_dir))


def _session_report(child, proc_root, panes, now, by_home=None, environ=None):
    """One session row. Every read inside is individually survivable: a
    failure costs that field, never the row and never the report."""
    supervisor_id = child["supervisor_id"]
    generation = child["generation"]
    try:
        records = journal_records(supervisor_id)
    except Exception:  # noqa: BLE001
        records = []
    session_id, transcript_path = _session_binding(records, generation)
    if session_id is None and generation is not None:
        # the child's generation left no record yet (a session that has only
        # just started): fall back to whatever this supervisor last bound
        session_id, transcript_path = _session_binding(records, None)
    seat = _seat_of(child["config_dir"], by_home or {})
    model = supervisor._model_flag(child["argv"][1:])
    turn, subagents, mtime = _activity(
        transcript_path, now, child.get("started_at"))
    return {
        "container": _container(proc_root, child["pid"], panes),
        "supervisor_id": supervisor_id,
        "session_id": session_id,
        "seat": seat,
        "pid": child["pid"],
        "turn": turn,
        "subagents": subagents,
        "context_remaining_percentage": _context_remaining(
            session_id, transcript_path, model, now, environ),
        "last_transcript_write": _iso(mtime),
        "generation": generation,
        "recent_events": _recent_events(records),
    }


def snapshot(now=None, proc_root=None, panes=None,
             fallback_path=None, environ=None):
    """`(report, read_something)`.

    `panes` may be pre-supplied (tests, or a caller that already asked tmux);
    None means consult tmux once for the whole report. The path defaults are
    resolved HERE rather than bound as argument defaults, so the module-level
    constants stay overridable at run time."""
    now = time.time() if now is None else now
    proc_root = PROC_ROOT if proc_root is None else proc_root
    fallback_path = (FALLBACK_USAGE_PATH if fallback_path is None
                     else fallback_path)
    children = supervised_children(proc_root)
    if panes is None:
        panes = tmux_panes()
    battery = seats(fallback_path)
    by_home = _seat_index()[1]
    sessions = []
    for child in (children or []):
        try:
            sessions.append(_session_report(
                child, proc_root, panes, now, by_home, environ))
        except Exception:  # noqa: BLE001 — a broken session is still a row
            sessions.append({
                "container": None, "supervisor_id": child.get("supervisor_id"),
                "session_id": None, "seat": None, "pid": child.get("pid"),
                "turn": "unknown", "subagents": "unknown",
                "context_remaining_percentage": None,
                "last_transcript_write": None, "generation": None,
                "recent_events": [],
            })
    sessions.sort(key=lambda row: (row["container"] or "",
                                   row["supervisor_id"] or ""))
    report = {
        "schema": SCHEMA,
        "generated_at": _iso(now),
        "sessions": sessions,
        "seats": battery or [],
    }
    return report, (children is not None or battery is not None)


def cmd_ops_status(args):
    if [arg for arg in args if arg not in ("--json",)]:
        print("usage: headroom ops-status [--json]", file=sys.stderr)
        return 2
    report, read_something = snapshot()
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0 if read_something else 1
