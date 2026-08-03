"""`headroom ps` — every live lane, and whether a pid may be killed.

On 2026-08-01 at 07:30:37Z an operator read

    claude --settings ~/.headroom/state/supervisors/<uuid>-1.settings.json

in `ps`, concluded "stale supervisor scaffolding", and killed two live
sessions; both panes then sat dark overnight. The conclusion was wrong but it
was not reckless: a dot-directory, a `state/` path, a UUID, a `-1` generation
suffix and `.settings.json` all read as a generated temp artefact, and there
was NO COMMAND ON THIS HOST that could answer "is this pid a live session?".
The answer had to be guessed. This command is that answer.

It is a CLI surface over machinery that already ships:
`ops_status.supervised_children()` enumerates every live supervised Claude
CLI from `/proc` alone, and nothing here re-derives any part of it. A second
opinion about liveness would drift from the first and the two would disagree
exactly when it matters — the moment something is about to kill a session
that is still working.

TWO PREDICATES, AND THE DIFFERENCE BETWEEN THEM IS THE WHOLE SAFETY ARGUMENT.
The natural shell idiom is

    headroom ps --is-lane "$p" || kill "$p"      # WRONG — FAILS OPEN

and a census failure is also non-zero, so a broken oracle would authorise
every kill on the box. `--killable` inverts it:

    headroom ps --killable "$p" && kill "$p"     # correct — refuses on doubt

`--killable` exits ZERO only when the census was READ and the pid was proven
absent from every lane cone. A broken census, a raising oracle, an unreadable
/proc entry, a pid that has already gone, a starttime that moved: every one
is non-zero, so every one refuses. The fail-safe direction is encoded in
WHICH PREDICATE YOU ASK, not in the caller's discipline.

IDENTITY IS pid+starttime, NEVER pid ALONE. The dangerous window is not the
pid_max wrap — it is the milliseconds between the check and the kill, in
which the pid can exit and be reassigned to a new lane's CLI. `PID:STARTTIME`
re-reads `/proc/<pid>/stat` field 22 and refuses distinctly when it moved.
The sentinel already keys its orphan receipts this way; this is the same
rule.

ARGV IS NEVER EVIDENCE. Any "is this a lane?" rule built on argv substrings
can be made to answer yes by a process whose command line merely QUOTES a
lane's identifying strings — during the design cycle one did, and it was the
grep that was writing the design. The oracle anchors on environment
(`HEADROOM_SUPERVISOR_ID`) plus PARENTAGE (the parent must be a headroom
launcher that does not already carry that id), which no argv can forge.
`tests/test_ps.py` pins it.

Read-only and bounded by construction: one `/proc` sweep, one optional tmux
query (decorative — the LANE column, never the liveness answer), ancestry
capped at `ops_status.MAX_ANCESTRY`. No daemon to be down, no lock to wedge,
no network. Measured on the live 7-lane estate: ~8 ms.
"""
import json
import os
import sys
import time

from . import ops_status

SCHEMA = "headroom_ps@1"
VERDICT_SCHEMA = "headroom_ps_verdict@1"

# --- verdicts ---------------------------------------------------------------
LANE = "lane"                        # the supervised CLI itself
LANE_SUPERVISOR = "lane-supervisor"  # the supervisor that owns a live CLI
LANE_BOOT = "lane-boot"              # sole ancestor of exactly ONE live CLI
SHARED_ANCESTOR = "shared-ancestor"  # ancestor of N >= 2 live CLIs
LANE_CHILD = "lane-child"            # descends from a live CLI
NOT_LANE = "not-lane"                # no live CLI above it or beneath it
NO_SUCH_PROCESS = "no-such-process"  # nothing at this pid
IDENTITY_MISMATCH = "identity-mismatch"  # the starttime moved
UNREADABLE = "unreadable"            # the entry exists, its ancestry does not
UNKNOWN = "unknown"                  # the census itself could not be read

# --- exit codes -------------------------------------------------------------
# 0  affirmative        --is-lane: yes        --killable: proven safe
# 1  negative           --is-lane: no         --killable: it is in a lane cone
# 2  shared ancestor (N >= 2 lanes), and the house usage-refusal code
# 3  the census could not be read at all — the oracle cannot answer
# 4  this pid could not be resolved: gone, unreadable, or a moved starttime
EXIT_YES = 0
EXIT_NO = 1
EXIT_SHARED = 2
EXIT_USAGE = 2
EXIT_CENSUS = 3
EXIT_IDENTITY = 4

_IS_LANE_EXIT = {
    LANE: EXIT_YES, LANE_SUPERVISOR: EXIT_YES, LANE_BOOT: EXIT_YES,
    LANE_CHILD: EXIT_YES, SHARED_ANCESTOR: EXIT_SHARED, NOT_LANE: EXIT_NO,
    NO_SUCH_PROCESS: EXIT_IDENTITY, IDENTITY_MISMATCH: EXIT_IDENTITY,
    UNREADABLE: EXIT_IDENTITY, UNKNOWN: EXIT_CENSUS,
}
_KILLABLE_EXIT = {
    LANE: EXIT_NO, LANE_SUPERVISOR: EXIT_NO, LANE_BOOT: EXIT_NO,
    LANE_CHILD: EXIT_NO, SHARED_ANCESTOR: EXIT_SHARED, NOT_LANE: EXIT_YES,
    NO_SUCH_PROCESS: EXIT_IDENTITY, IDENTITY_MISMATCH: EXIT_IDENTITY,
    UNREADABLE: EXIT_IDENTITY, UNKNOWN: EXIT_CENSUS,
}

#: the exact key set of a `--json` lane row
LANE_KEYS = {
    "lane", "container", "pid", "starttime_ticks", "supervisor_pid",
    "supervisor_starttime_ticks", "boot_pid", "boot_starttime_ticks",
    "seat", "generation", "model", "uptime_seconds", "started_at",
    "session_id", "supervisor_id",
}

TMUX_UNREACHABLE = ("tmux_unreachable: the LANE and container columns are "
                    "unknown; liveness is unaffected")


def is_lane_exit(verdict):
    """`--is-lane`'s exit code. A verdict this table does not know refuses:
    the informational predicate is still never allowed to invent a yes."""
    return _IS_LANE_EXIT.get(verdict, EXIT_CENSUS)


def killable_exit(verdict):
    """`--killable`'s exit code, and the one line that must never regress.

    The default is deliberate. A verdict added later without a mapping here
    is a verdict this build does not understand, and an unrecognised state
    must read as REFUSE — the same fail-closed default `_turn_state` applies
    when it cannot recognise a turn reason."""
    return _KILLABLE_EXIT.get(verdict, EXIT_CENSUS)


# --- /proc walking ----------------------------------------------------------

def ancestry(proc_root, pid, limit=None):
    """`[pid, parent, grandparent, …]`, self first, bounded and cycle-safe.

    The bound is `ops_status.MAX_ANCESTRY`, read at call time so the shipped
    constant stays the thing under test. A walk that cannot read a parent
    simply stops: an ancestry that could not be completed proves nothing, and
    the caller treats "proves nothing" as a refusal, never as a licence."""
    limit = ops_status.MAX_ANCESTRY if limit is None else limit
    chain, seen, current = [], set(), pid
    for _step in range(limit):
        chain.append(current)
        seen.add(current)
        parent, _starttime = ops_status._proc_stat_fields(proc_root, current)
        if parent is None or parent <= 1 or parent in seen:
            break
        current = parent
    return chain


def _exists(proc_root, pid):
    return os.path.isdir(os.path.join(proc_root, str(pid)))


def _starttime(proc_root, pid):
    return ops_status._proc_stat_fields(proc_root, pid)[1]


def blast_index(proc_root, children):
    """`{ancestor_pid: [live lane rows beneath it]}` — one pass, reused.

    Built once per census so a query is a dict lookup rather than a fresh
    walk per lane. Strictly BENEATH: a lane is not its own ancestor."""
    index = {}
    for child in children:
        for ancestor in ancestry(proc_root, child["pid"])[1:]:
            index.setdefault(ancestor, []).append(child)
    return index


def boot_pid(proc_root, child, index):
    """The outermost ancestor that belongs to THIS lane alone.

    Every pid from the CLI up to and including this one takes the lane down
    when it dies; the next one up holds something else too, so it is a
    shared-ancestor question rather than a lane question. Stopping at the
    first shared ancestor is what keeps the BOOT column an honest claim."""
    boot = None
    for ancestor in ancestry(proc_root, child["pid"])[1:]:
        beneath = index.get(ancestor, [])
        if len(beneath) != 1:
            break
        boot = ancestor
    return boot


# --- classification ---------------------------------------------------------

def classify(pid, children, proc_root=None, starttime=None, index=None):
    """One pid's verdict against a census that has ALREADY been read.

    `children` is `ops_status.supervised_children()`'s list — never None
    here: a failed census is the caller's `unknown`, decided before this is
    reached, because a classifier handed no census would happily report
    `not-lane` for every pid on the box."""
    proc_root = ops_status.PROC_ROOT if proc_root is None else proc_root
    live = {row["pid"]: row for row in children}
    index = blast_index(proc_root, children) if index is None else index

    def answer(verdict, reason, owner=None, beneath=()):
        return {
            "pid": pid, "verdict": verdict, "reason": reason,
            "starttime_ticks": _starttime(proc_root, pid),
            "owner_pid": owner["pid"] if owner else None,
            "supervisor_id": owner["supervisor_id"] if owner else None,
            "lanes_beneath": len(beneath),
            "lane_pids": [row["pid"] for row in beneath],
        }

    # 1. identity first: a starttime that moved means the caller is naming a
    #    process that no longer exists, whatever is at that pid now
    if starttime is not None:
        actual = _starttime(proc_root, pid)
        if actual is None:
            return answer(NO_SUCH_PROCESS,
                          f"pid {pid} is not running, so its starttime "
                          f"cannot be checked")
        if int(actual) != int(starttime):
            return answer(IDENTITY_MISMATCH,
                          f"pid {pid} has starttime {int(actual)}, not "
                          f"{int(starttime)} — this is a DIFFERENT process "
                          f"from the one you meant")

    # 2. census membership, before existence: a live lane is never described
    #    as gone just because it exited between the sweep and the query
    beneath = index.get(pid, [])
    if pid in live:
        return answer(LANE, f"pid {pid} IS a live supervised session",
                      live[pid], beneath)

    if not _exists(proc_root, pid):
        return answer(NO_SUCH_PROCESS, f"pid {pid} is not running")
    if ops_status._proc_stat_fields(proc_root, pid)[0] is None:
        return answer(UNREADABLE,
                      f"pid {pid} exists but its /proc entry cannot be read, "
                      f"so its ancestry cannot be walked")

    # 3. what dies with it — and HOW MANY. The count is not decoration.
    #    The naive rule takes the first live CLI beneath a pid and names the
    #    pid that lane's boot shell. On this estate that calls the TMUX
    #    SERVER, which holds six lanes, "lane domanski-ai's boot shell": it
    #    refuses correctly and explains wrongly, and an operator told that
    #    about a process holding six lanes has been misinformed by the very
    #    tool built to inform them. "Killing this takes six lanes down" is
    #    categorically different advice from "killing this takes one", so
    #    N >= 2 gets its own verdict and its own exit code.
    if len(beneath) >= 2:
        return answer(SHARED_ANCESTOR,
                      f"pid {pid} is an ancestor of {len(beneath)} live "
                      f"sessions", None, beneath)
    if beneath:
        owner = beneath[0]
        if pid == owner["supervisor_pid"]:
            return answer(LANE_SUPERVISOR,
                          f"pid {pid} is the SUPERVISOR of live session "
                          f"{owner['pid']}", owner, beneath)
        return answer(LANE_BOOT,
                      f"pid {pid} is the BOOT ancestor of live session "
                      f"{owner['pid']}", owner, beneath)

    # 4. what dies with the lane
    for ancestor in ancestry(proc_root, pid)[1:]:
        if ancestor in live:
            return answer(LANE_CHILD,
                          f"pid {pid} is running INSIDE live session "
                          f"{ancestor}", live[ancestor])

    return answer(NOT_LANE,
                  f"pid {pid} has no live supervised session above or "
                  f"beneath it")


# --- presentation -----------------------------------------------------------

def parse_target(text):
    """`PID` or `PID:STARTTIME` -> `(pid, starttime or None)`.

    Raises ValueError on anything else. Strict on purpose: a target this
    cannot read is a usage refusal, and a usage refusal is non-zero, so a
    typo can never reach a kill."""
    pid_text, separator, start_text = str(text).partition(":")
    if not pid_text.isdigit() or int(pid_text) <= 0:
        raise ValueError(f"not a pid: {text!r}")
    if separator and not start_text.isdigit():
        raise ValueError(f"not a starttime: {text!r}")
    return int(pid_text), (float(start_text) if separator else None)


def _uptime(seconds):
    if seconds is None or seconds < 0:
        return "?"
    seconds = int(seconds)
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days}d{hours:02d}h"
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m"
    return f"{seconds}s"


def _lane_name(container):
    """The LANE column: a tmux session name, `(bare)` when tmux answered and
    this lane is genuinely outside it, `(unknown)` when tmux could not say."""
    if container is None:
        return "(unknown)"
    return container or "(bare)"


def _describe(row):
    """The one line a refusal prints — it must NAME THE LANE, because the
    incident was a naming failure, not a warning that went unheeded."""
    parts = [_lane_name(row.get("container"))]
    if row.get("seat"):
        parts.append("seat " + row["seat"])
    parts.append("up " + _uptime(row.get("uptime_seconds")))
    if row.get("session_id"):
        parts.append("session " + row["session_id"].split("-")[0])
    if row.get("generation") is not None:
        parts.append("generation %s" % row["generation"])
    return ", ".join(parts)


def lane_rows(children, proc_root, panes, now=None):
    """One presentation row per live lane, widest-to-narrowest identity.

    The journal read (for the session id) happens HERE and not in
    `classify`, so the predicate path a pre-kill gate runs stays a /proc
    sweep plus a dict lookup."""
    from . import supervisor  # local: the predicate path must not pay for it

    now = time.time() if now is None else now
    index = blast_index(proc_root, children)
    by_home = ops_status._seat_index()[1]
    rows = []
    for child in children:
        try:
            records = ops_status.journal_records(child["supervisor_id"])
            session_id = ops_status._session_binding(
                records, child["generation"])[0]
        except Exception:  # noqa: BLE001 — a lane row survives its journal
            session_id = None
        boot = boot_pid(proc_root, child, index)
        started = child.get("started_at")
        container = ops_status._container(proc_root, child["pid"], panes)
        rows.append({
            "lane": _lane_name(container),
            "container": container,
            "pid": child["pid"],
            "starttime_ticks": _starttime(proc_root, child["pid"]),
            "supervisor_pid": child["supervisor_pid"],
            "supervisor_starttime_ticks": _starttime(
                proc_root, child["supervisor_pid"])
            if child["supervisor_pid"] else None,
            "boot_pid": boot,
            "boot_starttime_ticks": (_starttime(proc_root, boot)
                                     if boot else None),
            "seat": ops_status._seat_of(child["config_dir"], by_home),
            "generation": child["generation"],
            "model": supervisor._model_flag(child["argv"][1:]) or None,
            "uptime_seconds": (None if started is None
                               else round(now - started, 1)),
            "started_at": started,
            "session_id": session_id,
            "supervisor_id": child["supervisor_id"],
        })
    rows.sort(key=lambda row: (row["lane"], row["pid"]))
    return rows


_COLUMNS = (("LANE", "lane"), ("PID", "pid"), ("SUP", "sup"),
            ("BOOT", "boot"), ("SEAT", "seat"), ("GEN", "gen"),
            ("MODEL", "model"), ("UP", "up"), ("SESSION", "session"))


def _cells(row):
    return {
        "lane": row["lane"], "pid": row["pid"],
        "sup": row["supervisor_pid"] or "-",
        "boot": row["boot_pid"] or "-", "seat": row["seat"] or "-",
        "gen": "-" if row["generation"] is None else row["generation"],
        "model": row["model"] or "-",
        "up": _uptime(row["uptime_seconds"]),
        "session": (row["session_id"] or "-").split("-")[0],
    }


def render(rows, errors):
    """The human form. The trailing sentence is load-bearing: the incident
    was someone reading `ps` and drawing a conclusion, so the output that
    replaces `ps` states the conclusion rather than leaving it to be drawn.

    Widths are measured, never assumed. A fixed width silently truncates or
    runs columns together on the very values that vary most — seat names and
    model names — and a table whose columns have merged is a table an
    operator reads wrongly, which is the entire failure this command
    exists to end."""
    lines = []
    if rows:
        cells = [_cells(row) for row in rows]
        widths = {key: max([len(name)] + [len(str(cell[key]))
                                          for cell in cells]) + 2
                  for name, key in _COLUMNS}
        lines.append("".join(name.ljust(widths[key])
                             for name, key in _COLUMNS).rstrip())
        for cell in cells:
            lines.append("".join(str(cell[key]).ljust(widths[key])
                                 for _name, key in _COLUMNS).rstrip())
        lines.append("")
    lines.append(f"{len(rows)} lanes.")
    for error in errors:
        lines.append("note: " + error)
    if rows:
        lines.append(
            "KILLING ANY PID IN THE PID/SUP/BOOT COLUMNS TAKES THE LANE DOWN.")
    lines.append("Before killing anything:  headroom ps --killable <pid>   "
                 "(exit 0 = safe, anything else = refuse)")
    return "\n".join(lines)


USAGE = """\
usage: headroom ps [--json]
       headroom ps [--json] --killable PID[:STARTTIME]
       headroom ps [--json] --is-lane  PID[:STARTTIME]

Lists every live supervised Claude session on this host — the lane, its seat,
and every pid whose death takes it down — read from /proc alone. No tmux
dependency, no daemon, no lock.

  --killable PID   THE PRE-KILL GATE. Exit 0 ONLY when the census was read
                   and this pid was proven to be no part of any live lane.
                   Every other outcome is non-zero, so

                       headroom ps --killable "$p" && kill "$p"

                   refuses on any doubt: a broken census, a raising oracle,
                   an unreadable /proc entry, a pid that has already gone,
                   or a starttime that moved.

  --is-lane PID    The informational inverse: exit 0 when the pid IS part of
                   a lane. WARNING — THIS PREDICATE FAILS OPEN IN A SHELL
                   GATE. `headroom ps --is-lane "$p" || kill "$p"` kills on
                   a census failure too, because that is also non-zero, so a
                   broken oracle would authorise every kill on the box. Use
                   it to ASK, never to authorise. Use --killable to gate.

  PID:STARTTIME    Identity is the pid AND /proc/<pid>/stat field 22, never
                   the pid alone. A bare pid answers about the process that
                   was there when the census ran, and cannot close the window
                   between the check and the kill. `--json` reports each
                   lane's starttime_ticks so a caller can pass the tuple.

exit codes
  0  affirmative      --is-lane: yes          --killable: proven safe to kill
  1  negative         --is-lane: no           --killable: it is inside a lane
  2  the pid is an ancestor of TWO OR MORE live lanes (or a usage refusal)
  3  the census could not be read — the oracle cannot answer at all
  4  the pid could not be resolved: not running, unreadable, or its starttime
     moved (a different process now holds that number)

verdicts (--json)
  lane             the supervised CLI itself — the shape killed on 2026-08-01
  lane-supervisor  the supervisor process that owns a live CLI
  lane-boot        sole ancestor of exactly one live CLI
  shared-ancestor  ancestor of N >= 2 live CLIs; "lanes_beneath" reports N
  lane-child       something running inside a live session
  not-lane         no live session above or beneath it — the only killable one
"""


def _emit(payload, as_json, stream=None):
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False))
    elif stream is not None:
        print(payload, file=stream)


def _usage(message):
    print(f"headroom ps: {message}", file=sys.stderr)
    print(USAGE, file=sys.stderr)
    return EXIT_USAGE


def _predicate(target, predicate, as_json, proc_root):
    """One pid, one answer. EVERY path out of here that is not a proven
    `not-lane` must be non-zero when the predicate is `killable`."""
    try:
        pid, starttime = parse_target(target)
    except ValueError as error:
        return _usage(str(error))
    try:
        children, reason = ops_status.supervised_children(proc_root)
        if children is None:
            answer = {"pid": None, "verdict": UNKNOWN,
                      "reason": "census unreadable: " + (reason or "unknown"),
                      "starttime_ticks": None, "owner_pid": None,
                      "supervisor_id": None, "lanes_beneath": 0,
                      "lane_pids": []}
        else:
            answer = classify(pid, children, proc_root, starttime)
    except Exception as error:  # noqa: BLE001 — an oracle that raises REFUSES
        answer = {"pid": pid, "verdict": UNKNOWN,
                  "reason": f"census unreadable: {error}",
                  "starttime_ticks": None, "owner_pid": None,
                  "supervisor_id": None, "lanes_beneath": 0, "lane_pids": []}
    code = (killable_exit if predicate == "killable" else is_lane_exit)(
        answer["verdict"])
    reason = answer["reason"]
    # a refusal must name the LANE, not just the pid — the incident was a
    # naming failure. Only refusals pay for the journal read.
    if answer["verdict"] in (LANE, LANE_SUPERVISOR, LANE_BOOT, LANE_CHILD,
                             SHARED_ANCESTOR) and children:
        try:
            rows = {row["pid"]: row for row in lane_rows(
                children, proc_root, ops_status.tmux_panes())}
        except Exception:  # noqa: BLE001 — decoration never breaks the gate
            rows = {}
        if answer["verdict"] == SHARED_ANCESTOR:
            # the whole point of the verdict: name every lane that dies
            owners = answer["lane_pids"]
            described = [_describe(rows[owner]) for owner in owners
                         if owner in rows]
            reason = (f"pid {pid} is an ancestor of {answer['lanes_beneath']} "
                      f"LIVE LANES — killing it takes them ALL down:"
                      + "".join("\n           - " + text for text in
                                (described or [str(o) for o in owners])))
        else:
            # the lane this pid belongs to is owner_pid, NEVER lane_pids: a
            # nested supervisor makes a live CLI an ancestor of another live
            # CLI, and describing the pid by what hangs BENEATH it would name
            # the wrong lane in the one message that exists to name the right
            # one
            owner = answer["owner_pid"]
            if owner in rows:
                reason = f"{reason} — LIVE LANE ({_describe(rows[owner])})"
            # ONLY for `lane`. A supervisor's or boot shell's lanes_beneath
            # counts the very lane just named, so "and N further" would be
            # double-counting it; the CLI's own count excludes itself and so
            # is genuinely further. (Anything with two or more beneath it is
            # already shared-ancestor and never reaches here.)
            if answer["verdict"] == LANE and answer["lanes_beneath"]:
                reason += (f", and {answer['lanes_beneath']} further live "
                           f"lane(s) run inside it")
    answer = dict(answer, schema=VERDICT_SCHEMA, predicate=predicate,
                  exit=code, reason=reason)
    if as_json:
        _emit(answer, True)
    elif code != EXIT_YES:
        print("headroom ps: REFUSED: " + reason, file=sys.stderr)
    return code


def cmd_ps(args, proc_root=None, now=None):
    proc_root = ops_status.PROC_ROOT if proc_root is None else proc_root
    as_json = False
    predicate = target = None
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--json":
            as_json = True
        elif arg in ("-h", "--help"):
            print(USAGE, end="")
            return 0
        elif arg in ("--is-lane", "--killable"):
            if predicate is not None:
                return _usage("--is-lane and --killable are different "
                              "questions; ask one")
            if index + 1 >= len(args):
                return _usage(f"{arg} needs a PID[:STARTTIME]")
            predicate = "killable" if arg == "--killable" else "is-lane"
            target = args[index + 1]
            index += 1
        else:
            return _usage(f"unknown argument {arg!r}")
        index += 1

    if predicate is not None:
        return _predicate(target, predicate, as_json, proc_root)

    errors = []
    try:
        children, reason = ops_status.supervised_children(proc_root)
    except Exception as error:  # noqa: BLE001
        children, reason = None, str(error)
    if children is None:
        errors.append("session_discovery_failed: " + (reason or "unknown"))
        payload = {"schema": SCHEMA, "generated_at": ops_status._iso(
            time.time() if now is None else now), "lanes": None,
            "errors": errors}
        if as_json:
            _emit(payload, True)
        print("headroom ps: the process table is unreadable — this is NOT an "
              "empty host: " + (reason or "unknown"), file=sys.stderr)
        return EXIT_CENSUS
    panes = ops_status.tmux_panes()
    if panes is None:
        # §5.1's honest gap: `snapshot()` reports errors: [] here even though
        # every container degraded to null. Say it instead of inheriting the
        # silence.
        errors.append(TMUX_UNREACHABLE)
    rows = lane_rows(children, proc_root, panes, now)
    if as_json:
        _emit({"schema": SCHEMA,
               "generated_at": ops_status._iso(
                   time.time() if now is None else now),
               "lanes": rows, "errors": errors}, True)
    else:
        print(render(rows, errors))
    return 0
