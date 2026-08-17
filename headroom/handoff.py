"""Transactional Claude conversation handoff.

The service layer is deliberately split into a read-only plan and a locked
commit.  The manual CLI adapter may exec Claude after commit; resident callers
use :func:`resume_argv` and keep control of their own process lifecycle.
"""
import contextlib
import glob
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import stat
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass

from . import collect, locks, paths, registry, route, tokens

SCHEMA = "headroom_handoff@2"
MAX_SCAN_AGE = 48 * 3600
# Freshness tolerance for the manual handoff's target snapshot. Not zero:
# a running `headroom serve` holds the single-flight collect lock, so a
# zero-second demand made every manual handoff fail while the dashboard was
# up. The launch still re-verifies the target's live credential binding.
HANDOFF_SNAPSHOT_MAX_AGE = int(
    os.environ.get("HEADROOM_HANDOFF_SNAPSHOT_MAX_AGE", "60"))


class HandoffError(RuntimeError):
    """A user-actionable refusal; handoff guards intentionally fail closed."""


class NoHeadroomError(HandoffError):
    """No seat can be routed to right now.

    Its own class because it is the one refusal in this module that says
    nothing is WRONG — the request is well formed, the proof is intact, there
    is simply no capacity this second. A later snapshot resolves it without
    anyone doing anything, so a caller that would otherwise give up
    permanently (the supervisor disarming a capped child) can tell it apart
    from a refusal that no amount of waiting will change."""


@dataclass(frozen=True)
class SourceSession:
    session_id: str
    transcript_path: str
    account: dict
    model: str = ""
    seen_at: int = 0


@dataclass(frozen=True)
class HandoffPlan:
    handoff_id: str
    source: SourceSession
    family: str
    target: dict
    snapshot: dict
    cap_proof: dict
    cooldown_scope: dict
    cwd: str
    inspected: dict
    destination: str
    source_stat: tuple
    target_identity: dict
    target_home_stat: tuple
    automatic: bool = False
    child_generation: int = 0
    force: bool = False
    # True for a supervisor rotation taken BEFORE the wall (a threshold
    # crossing, not a proven cap). It only labels the ledger: a preemptive
    # plan carries no cooldown_scope, so it cools nothing, and it is planned
    # with allow_dangling off — a mid-tool-call session is never moved early.
    preemptive: bool = False
    # The family the SUCCESSOR launches on when it differs from `family`.
    # `family` stays the family this handoff is ABOUT — the pool that capped —
    # because it is what `commit_handoff` cools and what the ledger records;
    # cooling opus because a spent Fable week forced an opus successor would
    # leave the exhausted pool routable. Empty means "same as family", which
    # is every handoff that did not have to change model tier.
    resume_family: str = ""
    # The exact model the successor is launched with, stamped just before
    # commit (see Supervisor._post_stop_plan). `resume_family` alone is not
    # enough for the ledger's last-resort command: an over-limit transcript
    # needs `opus[1m]`, and `--model opus` cannot load it. Empty means the
    # successor takes the child's default, which is the pre-existing case.
    resume_model: str = ""
    # provider adapter fields: "claude" plans behave exactly as before; a
    # "codex" plan publishes to relative_destination (a validated
    # slash-separated path under the target home) instead of projects/<slug>.
    provider: str = "claude"
    relative_destination: str = ""

    @property
    def target_family(self):
        """The family the TARGET is gated on and the successor launches with.

        Identical to `family` for every handoff that kept its model tier.
        When a cap forced a downgrade they differ, and the distinction is
        load-bearing in both directions: `family` names the pool being moved
        AWAY from, so gating the destination on it would refuse the very seat
        the downgrade exists to reach, while gating the SOURCE cooldown on
        this one would cool a pool that never capped."""
        return self.resume_family or self.family


@dataclass(frozen=True)
class HandoffResult:
    plan: HandoffPlan
    destination: str
    record: dict


def _journal_path():
    return os.path.join(paths.state_dir(), "sessions.jsonl")


def _ledger_path():
    return os.path.join(paths.state_dir(), "handoffs.jsonl")


def _lock_path():
    return os.path.join(paths.state_dir(), "handoffs.lock")


def _valid_uuid(value):
    try:
        return str(uuid.UUID(value)) == value.lower()
    except (AttributeError, ValueError):
        return False


def _claude_slug(path):
    return re.sub(r"[^A-Za-z0-9-]", "-", path)


def guard_handoff_group(source_account, target_account):
    """Data-boundary gate: conversation content may only move between slots
    that share the same configured ``handoff_group``.  Enforced on the CODEX
    handoff paths only (plan, commit, publish, exec) — the Claude plan path
    deliberately does not call it, so pre-adapter Claude behaviour is
    byte-identical.  Neither side configured passes; exactly one side
    configured is an explicit boundary mismatch and refuses (fail closed)."""
    source_group = source_account.get("handoff_group")
    target_group = target_account.get("handoff_group")
    if source_group is None and target_group is None:
        return None
    if source_group is None or target_group is None:
        raise HandoffError(
            "handoff_group mismatch: %r has %s and %r has %s — conversation "
            "content only moves between accounts in the same handoff_group"
            % (source_account.get("name"),
               repr(source_group) if source_group is not None else "no group",
               target_account.get("name"),
               repr(target_group) if target_group is not None else "no group"))
    if source_group != target_group:
        raise HandoffError(
            "handoff_group mismatch: %r is in %r but %r is in %r — refusing "
            "to move conversation content across account data boundaries"
            % (source_account.get("name"), source_group,
               target_account.get("name"), target_group))
    return source_group


def _number(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def _timestamp(row):
    value = row.get("ts")
    return float(value) if _number(value) else 0.0


def _read_jsonl(path, label):
    if not os.path.exists(path):
        return []
    rows = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError
                rows.append(row)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise HandoffError(f"{label} is unreadable — inspect {path}") from error
    return rows


def _contained_transcript(path, session_id, account):
    """Return a canonical regular transcript owned by ``account``."""
    absolute = os.path.abspath(os.path.expanduser(path))
    if os.path.basename(absolute) != session_id + ".jsonl":
        raise HandoffError(
            f"session {session_id} transcript basename does not match its id")
    try:
        metadata = os.lstat(absolute)
    except FileNotFoundError as error:
        # ONLY a genuinely absent file says "no longer exists": the supervisor
        # treats that one phrase as "may still be being written" and waits a
        # bounded moment for it. A permission or ENOTDIR failure is a real,
        # unfixable identity failure and must keep saying so.
        raise HandoffError(
            f"session {session_id} transcript no longer exists") from error
    except OSError as error:
        raise HandoffError(
            f"session {session_id} transcript cannot be read "
            f"({error.strerror or error})") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise HandoffError("source transcript is a symlink — refusing to copy")
    canonical = os.path.realpath(absolute)
    try:
        if not stat.S_ISREG(os.stat(canonical).st_mode):
            raise HandoffError("source transcript is not a regular file")
    except OSError as error:
        raise HandoffError("cannot stat source transcript") from error
    for directory in account_directories(account):
        projects_path = os.path.join(directory, "projects")
        if os.path.islink(projects_path):
            raise HandoffError("source projects directory is a symlink")
        projects = os.path.realpath(projects_path)
        try:
            inside = os.path.commonpath((canonical, projects)) == projects
        except ValueError:
            inside = False
        if inside and canonical != projects:
            return canonical
    raise HandoffError(
        f"session {session_id} is not inside the account's projects directory")


def _account_for_path(path, accounts, config_dir=""):
    canonical = os.path.realpath(os.path.abspath(os.path.expanduser(path)))
    # RANK BY DIRECTORY, NOT BY ACCOUNT (2026-08-17 R4). One directory can be
    # named by two accounts at once: a rotated account resolves TO another
    # account's home, and that home's registered owner still names it too. The
    # account whose credential actually lives there has to win, or a lane is
    # attributed to the seat it borrowed rather than the one it spends. So
    # every account's resolved directory is tried before any account's
    # registry home. directory_owners is that ranking, and it is now the only
    # copy of it in this module (R5).
    for directory, account in directory_owners(accounts, config_dir).items():
        projects = os.path.realpath(os.path.join(directory, "projects"))
        try:
            if os.path.commonpath((canonical, projects)) == projects:
                return account
        except ValueError:
            continue
    return None


def _source(path, session_id, accounts, model="", seen_at=0, config_dir=""):
    account = _account_for_path(path, accounts, config_dir)
    if account is None:
        raise HandoffError(
            f"session {session_id} is not inside a configured Claude home")
    if account.get("provider") != "claude":
        raise HandoffError("handoff only supports same-provider Claude sessions")
    canonical = _contained_transcript(path, session_id, account)
    return SourceSession(session_id, canonical, account, model,
                         int(_timestamp({"ts": seen_at})))


def _age_text(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


def _ambiguity(rows, now):
    lines = []
    for row in sorted(rows, key=_timestamp, reverse=True):
        age = _age_text(now - _timestamp(row))
        lines.append(f"  {row.get('session_id')}  age={age}  "
                     f"model={row.get('model') or '?'}")
    return ("multiple sessions share this cwd; pass --session UUID:\n"
            + "\n".join(lines))


def _filesystem_matches(session_id, accounts):
    matches = []
    # ONE DIRECTORY, ONE OWNER, ONE HIT (2026-08-17 R5). Walking accounts and
    # then their directories reached a shared directory once per account, so
    # a single transcript under a rotated home returned twice and the caller
    # refused it as an ambiguity. `seen` keeps that property true of the
    # FILE as well, whatever nesting the directories have.
    seen = set()
    for directory, account in directory_owners(accounts).items():
        if account.get("provider") != "claude":
            continue
        pattern = os.path.join(directory, "projects", "**",
                               session_id + ".jsonl")
        for path in glob.glob(pattern, recursive=True):
            try:
                canonical = _contained_transcript(path, session_id, account)
            except HandoffError:
                continue
            if canonical in seen:
                continue
            seen.add(canonical)
            matches.append((canonical, account))
    return matches


def _ledger_source_slot(session_id):
    """The slot the handoff ledger says this session came FROM, or "".

    THE NEWEST ROW THAT NAMES A SLOT, NOT THE NEWEST ROW (2026-08-17, R5
    repair). One automatic handoff writes five rows under one handoff_id and
    the last of them, `resume_spawned`, carries target_slot and no
    source_slot at all. Reading `max(rows)` therefore answered None for every
    COMPLETED handoff, which is the shape almost every row on this estate is
    in, so the tie breaker below dead ended on the common case while looking
    like it worked. Measured on the live ledger: of 33 sessions with a second
    copy on disk, 11 refused for this reason alone.
    """
    rows = [row for row in _read_jsonl(_ledger_path(), "handoff ledger")
            if (row.get("old_session_id") or row.get("session_id")) == session_id
            and isinstance(row.get("source_slot"), str) and row["source_slot"]]
    return max(rows, key=_timestamp)["source_slot"] if rows else ""


def _ledger_claimed_match(session_id, matches, accounts):
    """The match the ledger's source slot claims on disk, or None.

    BY DIRECTORY, NOT BY OWNER NAME (2026-08-17, R5 repair). The ledger names
    a registry SLOT. R5 made one directory answer to one OWNER, the account
    whose credential is in it, so on a rotated estate the owner of a slot's
    own home is somebody else and `account["name"] == source_slot` can never
    match again: the manual rescue R5 opened for a single copy shut for every
    session that has two. What a slot identifies on disk is a set of
    DIRECTORIES, so the claim is matched there, best claim first, and
    `_source` re derives the owner exactly as it does on every other path.

    Measured on the live ledger and the live homes: five sessions whose
    source slot is `gmail`, whose chain is in the vault, resolved before R5
    and refused with "matched 2 configured transcripts" after it.

    AND WHEN NO CLAIM MATCHES, SAY WHY (2026-08-17, X2, R5 residual P1). A
    vaulted slot owns no directory, so when neither of its claims holds a copy
    this dead ended and `resolve_source` printed "matched N configured
    transcripts": a count, about the wrong thing, from which no operator can
    work out that the source account's chain is parked in the vault and that
    rotating it back into a home is the whole cure. The one sentence the
    estate already uses for exactly that condition
    (route.UNDISPATCHABLE_LOCATION, the same words `headroom env` and the
    handoff target check print) is raised here instead.

    IT RAISES ONLY WHERE IT USED TO ANSWER NOTHING. A vaulted slot whose
    registry home DOES hold a copy still resolves, to the account that owns
    that directory today, which is the case the R5 repair exists for and the
    class above pins. Refusing that too would trade this defect for the one
    it cured. And a resolver that cannot answer at all (no estate tree, a
    codex seat) yields no reason, so the caller keeps today's behaviour: a
    diagnostic never blocks a path it cannot judge.
    """
    slot = _ledger_source_slot(session_id)
    if not slot:
        return None
    account = next((item for item in accounts
                    if item.get("name") == slot), None)
    if account is None:
        return None
    for directory, _rank in account_directory_claims(account):
        projects = os.path.realpath(os.path.join(directory, "projects"))
        for path, _owner in matches:
            try:
                inside = os.path.commonpath((path, projects)) == projects
            except ValueError:
                continue
            if inside and path != projects:
                return _source(path, session_id, accounts)
    reason = route.credential_location_reason(account)
    if reason:
        raise HandoffError(
            f"session {session_id} matched {len(matches)} configured "
            f"transcripts and the handoff ledger says it came from {slot}, "
            f"whose {reason}")
    return None


def resolve_source(session_id=None, accounts=None, cwd=None, now=None):
    """Resolve explicit intent, then the statusline journal, then a narrow scan."""
    accounts = registry.accounts() if accounts is None else accounts
    cwd = os.path.realpath(os.getcwd() if cwd is None else cwd)
    now = time.time() if now is None else now
    if session_id is not None:
        if not _valid_uuid(session_id):
            raise HandoffError("--session must be a UUID")
        session_id = str(uuid.UUID(session_id))
        journal_error = None
        try:
            journal = _read_jsonl(_journal_path(), "session journal")
        except HandoffError as error:
            journal, journal_error = [], error
        hits = [row for row in journal
                if str(row.get("session_id", "")).lower() == session_id.lower()
                and isinstance(row.get("transcript_path"), str)]
        for row in sorted(hits, key=_timestamp, reverse=True):
            try:
                return _source(row["transcript_path"], session_id, accounts,
                               row.get("model", ""), row.get("ts", 0),
                               row.get("config_dir", ""))
            except HandoffError:
                continue
        matches = _filesystem_matches(session_id, accounts)
        if len(matches) == 1:
            return _source(matches[0][0], session_id, accounts)
        if len(matches) > 1:
            claimed = _ledger_claimed_match(session_id, matches, accounts)
            if claimed is not None:
                return claimed
            raise HandoffError(
                f"session {session_id} matched {len(matches)} configured transcripts")
        if journal_error is not None:
            raise journal_error
        raise HandoffError(f"session {session_id} matched none configured transcripts")

    journal = _read_jsonl(_journal_path(), "session journal")
    rows = []
    for row in journal:
        row_cwd = row.get("cwd")
        if not isinstance(row_cwd, str) or os.path.realpath(row_cwd) != cwd:
            continue
        session = row.get("session_id")
        if not isinstance(session, str) or not _valid_uuid(session):
            continue
        if _timestamp(row) >= next((_timestamp(item) for item in rows
                                    if item.get("session_id") == session), -1):
            rows = [item for item in rows if item.get("session_id") != session]
            rows.append(row)
    if len(rows) > 1:
        raise HandoffError(_ambiguity(rows, now))
    if len(rows) == 1:
        row = rows[0]
        return _source(row["transcript_path"], row["session_id"], accounts,
                       row.get("model", ""), row.get("ts", 0),
                       row.get("config_dir", ""))

    slug = _claude_slug(cwd)
    scanned = []
    # Same one map, same reason (R5): reached per account, a rotated home
    # listed the same session id twice under "pass --session UUID", and
    # passing it hit the second refusal in _filesystem_matches.
    seen = set()
    for directory, account in directory_owners(accounts).items():
        if account.get("provider") != "claude":
            continue
        pattern = os.path.join(directory, "projects", slug, "*.jsonl")
        for path in glob.glob(pattern):
            candidate = os.path.splitext(os.path.basename(path))[0]
            if not _valid_uuid(candidate):
                continue
            try:
                canonical = _contained_transcript(path, candidate, account)
                age = now - os.stat(canonical).st_mtime
            except (OSError, HandoffError):
                continue
            if canonical in seen:
                continue
            if 0 <= age < MAX_SCAN_AGE:
                seen.add(canonical)
                scanned.append((canonical, account, age))
    if len(scanned) != 1:
        report = [{"session_id": os.path.splitext(os.path.basename(path))[0],
                   "ts": now - age, "model": "?"}
                  for path, _, age in scanned]
        if report:
            raise HandoffError(_ambiguity(report, now))
        raise HandoffError("no recent session matches this cwd — pass --session UUID")
    path, account, _ = scanned[0]
    session_id = os.path.splitext(os.path.basename(path))[0]
    print(f"[headroom] found session {session_id} for the current cwd",
          file=sys.stderr)
    return _source(path, session_id, [account])


def guard_source_stable(path, now=None, sleep=None, quiet_seconds=5.0):
    """Require five quiet seconds and a stable follow-up stat."""
    try:
        first = os.stat(path)
    except OSError as error:
        raise HandoffError(f"cannot stat source transcript: {error}") from error
    now = time.time() if now is None else now
    if now - first.st_mtime < quiet_seconds:
        raise HandoffError(
            "source transcript changed recently — /exit the session first, "
            "wait 5 seconds, then hand off")
    (time.sleep if sleep is None else sleep)(1.0)
    try:
        second = os.stat(path)
    except OSError as error:
        raise HandoffError(f"cannot recheck source transcript: {error}") from error
    if second.st_size != first.st_size or second.st_mtime_ns != first.st_mtime_ns:
        raise HandoffError("source transcript is still changing — /exit first")


def _content_blocks(event):
    message = event.get("message") if isinstance(event, dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    return content if isinstance(content, list) else []


def unresolved_tool_ids(events):
    """Return tool-use ids without their exact tool_result partner."""
    uses = []
    results = set()
    for event in events:
        for block in _content_blocks(event):
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and isinstance(block.get("id"), str):
                uses.append(block["id"])
            elif block.get("type") == "tool_result" \
                    and isinstance(block.get("tool_use_id"), str):
                results.add(block["tool_use_id"])
    return tuple(dict.fromkeys(tool_id for tool_id in uses if tool_id not in results))


def _validate_tool_ids(events):
    uses = []
    results = []
    for event in events:
        for block in _content_blocks(event):
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                tool_id = block.get("id")
                if not isinstance(tool_id, str) or not tool_id:
                    raise HandoffError("transcript has a tool_use without a valid id")
                if tool_id in uses:
                    raise HandoffError(f"transcript repeats tool_use id {tool_id}")
                uses.append(tool_id)
            elif block.get("type") == "tool_result":
                tool_id = block.get("tool_use_id")
                if not isinstance(tool_id, str) or not tool_id:
                    raise HandoffError(
                        "transcript has a tool_result without a valid tool_use_id")
                results.append(tool_id)
    unknown = [tool_id for tool_id in results if tool_id not in uses]
    if unknown:
        raise HandoffError(
            "transcript has tool_result for unknown id: "
            + ", ".join(dict.fromkeys(unknown)))
    return tuple(tool_id for tool_id in uses if tool_id not in set(results))


def _guard_complete_turn(events):
    unresolved = unresolved_tool_ids(events)
    if unresolved:
        raise HandoffError(
            "session stopped mid-tool-call (unresolved: %s); resume it once on "
            "the source account, or use --force for a content-preserving fork"
            % ", ".join(unresolved))


def inspect_transcript(path, allow_dangling=False):
    """Validate every JSONL record and derive a content-addressed baton."""
    if os.path.islink(path):
        raise HandoffError("source transcript is a symlink — refusing to copy")
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        raise HandoffError(f"cannot read source transcript: {error}") from error
    events = []
    lines = data.splitlines()
    if not lines:
        raise HandoffError("transcript is empty — refusing to hand off")
    for index, raw in enumerate(lines):
        try:
            event = json.loads(raw.decode("utf-8"))
            if not isinstance(event, dict):
                raise ValueError
            events.append(event)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            if index == len(lines) - 1:
                raise HandoffError(
                    "transcript has an incomplete final line — is it still writing?") \
                    from error
            raise HandoffError(
                f"transcript contains invalid JSON at line {index + 1}") from error
    unresolved = _validate_tool_ids(events)
    if unresolved and not allow_dangling:
        _guard_complete_turn(events)
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "events": events, "unresolved_tool_ids": unresolved}


def resolve_model_family(source, override=None):
    """Resolve the actual Claude family; absent/unknown never falls back."""
    value = override if override is not None else source.model
    if not isinstance(value, str) or not value.strip():
        raise HandoffError("source model is unknown — pass --model FAMILY")
    try:
        family = registry.family(value)
    except registry.RegistryError as error:
        raise HandoffError(str(error) + "; pass --model FAMILY") from error
    if registry.family_provider(family) != "claude":
        raise HandoffError("handoff requires a Claude model family")
    if family == "claude":
        raise HandoffError(
            "handoff requires a scoped Claude family such as sonnet, opus, "
            "haiku, or fable; pass --model FAMILY")
    return family


def select_target(source_slot, snapshot, family="claude", requested=None):
    """Select and recheck a target with headroom for the actual family."""
    ranked = route.candidates(family, snapshot)
    if requested:
        match = next(((account, reason) for account, reason in ranked
                      if account.get("name") == requested), None)
        if match is None:
            raise HandoffError(f"no configured Claude account named {requested!r}")
        account, reason = match
        if account["name"] == source_slot:
            raise HandoffError("source and target slots must be different")
        if reason is not None:
            raise NoHeadroomError(
                f"target {requested} has no proven headroom: {reason}")
        return account
    target = next((account for account, reason in ranked
                   if reason is None and account["name"] != source_slot), None)
    if target is None:
        raise NoHeadroomError(
            f"no account has proven headroom for the {family} family")
    return target


def target_directory(target):
    """WHERE this handoff may stage and launch, never the registry home.

    THE FIFTH COPY (2026-08-17 R4, closing R3's P1-1 on both verifiers). R3
    taught route.py, __main__.py and supervisor._environment that the registry
    home is where an account BELONGS, not where its login lives, and missed
    this module, which is the one that performs the estate's wall time rescue.
    Two failures came out of that, both dated the same day.

    1. `headroom handoff --to <rotated account>` execs claude with
       CLAUDE_CONFIG_DIR set to a directory the refresher no longer touches,
       so the rescued lane strands at the next token expiry: the exact defect
       this build exists to end, on the path used to rescue a walled lane.
    2. The supervisor's automatic handoff staged the conversation under the
       registry home while R3's fixed launch started the child at the resolved
       one, so a `claude --resume` came up where its transcript was not. A
       lost conversation at a usage wall, which is the one moment the
       machinery exists for.

    Both are cured by asking ONE question in ONE place. A vault or a homeless
    account REFUSES here rather than falling back: a vault entry carries no
    settings.json, so a session launched there runs with no SessionStart hook,
    no guard and no fan out gate, and the registry home of a rotated account
    is the one directory known to hold somebody else's chain.

    Re-resolved rather than pinned on the plan, deliberately: a rotation that
    lands between plan and publish must be SEEN. It cannot be silently
    straddled, because plan.target_home_stat pins (dev, ino) at plan time and
    _target_dir_fd re-checks it at publish, so a directory that moved under a
    handoff fails closed with a stat refusal.
    """
    directory = route.dispatch_dir(target)
    if directory is None:
        raise HandoffError(
            "%s cannot receive a handoff: %s"
            % (target.get("name"), route.credential_location_reason(target)))
    return registry.expand(directory)


def account_directories(account):
    """Every directory that may hold this account's transcripts, best first.

    The resolved credential directory comes first, because that is where a
    session on this account runs today. The registry home comes second,
    because that is where it ran before it was rotated and where its older
    transcripts still sit. An account whose credential is in the vault, or
    nowhere, answers with its registry home alone: a vault entry is not a seat
    home and has no projects directory.

    WHY A LIST AND NOT A DIRECTORY (2026-08-17 R4, reproduce lens P2-2). After
    R3 a lane spending account A writes its transcripts under home B, so
    binding a session to an account through account["home"]/projects alone
    refused to hand off the very lanes R3 had just re-homed, and named every
    one of their transcripts after B's registered owner.
    """
    return [directory for directory, _rank
            in account_directory_claims(account)]


def account_directory_claims(account):
    """``[(directory, rank)]``: the same directories, each with its RANK.

    Rank 0 is the resolved credential directory, where a session on this
    account runs today. Rank 1 is the registry home, where it ran before it
    was rotated and where its older transcripts still sit.

    The rank is carried rather than inferred from the position (2026-08-17
    R5), because the two are not the same thing. An account whose credential
    is in the vault or nowhere has NO resolved directory, so its registry
    home is first in the list while being a rank 1 claim, and a positional
    reading would let it outrank the account whose chain actually lives in
    that directory. On this estate that is not a corner case: rotating one
    account's chain into another's home is what puts two accounts on one
    directory in the first place.
    """
    claims = []
    resolved = route.dispatch_dir(account)
    if resolved:
        claims.append((registry.expand(resolved), 0))
    home = account.get("home")
    if home:
        expanded = registry.expand(home)
        if all(expanded != directory for directory, _rank in claims):
            claims.append((expanded, 1))
    return claims


def directory_owners(accounts, config_dir=""):
    """The ONE directory to account map this module resolves paths with.

    Keyed by ``os.path.realpath``, so one directory on disk is one entry no
    matter how many accounts name it, and ordered best claim first, so
    iterating it visits every resolved credential directory before any
    registry home.

    WHY ONE MAP (2026-08-17 R5). R4 gave every account a LIST of directories
    and left the two scans consuming that list unranked and undeduplicated.
    Once a rotated account resolves INTO another account's registry home,
    both accounts reach the same file, and ONE transcript on disk is counted
    twice: `headroom handoff --session <id>` refuses with "matched 2
    configured transcripts" and the cwd scan prints the same session id twice
    under "pass --session UUID". Both doors of the MANUAL rescue shut, and
    each points at the other. `_account_for_path` had the ranked answer all
    along, so the module also held two disagreeing directory to account maps;
    this is the one map, and all three sites read it.

    TIE BREAKING, AND WHAT IS NEW IN IT (corrected 2026-08-17, R5 repair;
    the sentence here previously claimed the whole rule was preserved).
    `_account_for_path` sorted on ONE key before R5: the account whose
    directories include the caller's own CLAUDE_CONFIG_DIR first. That key is
    preserved and still ranks first. The second key, a Claude account ahead of
    a same rank non Claude one, is NEW here and changes behaviour: both scans
    skip a directory whose owner is not a Claude account, so without it one
    codex seat naming a directory could hide a real Claude transcript inside
    it from `--session` and from the cwd scan alike. Registry order breaks
    what is left, as before.
    """
    config_home = registry.expand(config_dir) if config_dir else ""
    claims = {}
    for account in accounts:
        name = account.get("name")
        if name:
            claims[name] = account_directory_claims(account)

    def preference(account):
        directories = [directory for directory, _rank
                       in claims.get(account.get("name"), [])]
        return (config_home not in directories,
                account.get("provider") != "claude")

    ordered = sorted(accounts, key=preference)
    owners = {}
    for rank in (0, 1):
        for account in ordered:
            for directory, claim_rank in claims.get(account.get("name"), []):
                if claim_rank == rank:
                    owners.setdefault(os.path.realpath(directory), account)
    return owners


def destination_path(target_home, source_transcript, session_id):
    slug = os.path.basename(os.path.dirname(source_transcript))
    return os.path.join(target_home, "projects", slug, session_id + ".jsonl")


def _preflight_destination(target, source, session_id):
    home = target_directory(target)
    if not os.path.isdir(home):
        raise HandoffError(f"target home is missing or not a directory: {home}")
    projects = os.path.join(home, "projects")
    if os.path.lexists(projects) and (os.path.islink(projects)
                                      or not os.path.isdir(projects)):
        raise HandoffError("target projects path is not a real directory")
    if not os.access(projects if os.path.isdir(projects) else home,
                     os.W_OK | os.X_OK):
        raise HandoffError("target directory is not writable")
    destination = destination_path(home, source, session_id)
    directory = os.path.dirname(destination)
    if os.path.lexists(directory) and (os.path.islink(directory)
                                       or not os.path.isdir(directory)):
        raise HandoffError("target session directory is not a real directory")
    projects_real = os.path.realpath(projects)
    directory_real = os.path.realpath(directory)
    try:
        inside = os.path.commonpath((directory_real, projects_real)) \
            == projects_real
    except ValueError:
        inside = False
    if not inside:
        raise HandoffError("target session directory escapes its account home")
    if os.path.lexists(destination):
        raise HandoffError(
            "target already has this session id; --force does not overwrite "
            "destination collisions — inspect the previous partial handoff")
    return destination


def _previous_handoff(session_id, digest):
    for row in _read_jsonl(_ledger_path(), "handoff ledger"):
        old_id = row.get("old_session_id") or row.get("session_id")
        if old_id == session_id and row.get("transcript_sha256") == digest \
                and row.get("action", "staged") == "staged":
            return row
    return None


def guard_not_duplicate(session_id, digest, force=False):
    previous = _previous_handoff(session_id, digest)
    if previous and not force:
        if not _number(previous.get("ts")) \
                or not isinstance(previous.get("target_slot"), str):
            raise HandoffError(f"handoff ledger is unreadable — inspect {_ledger_path()}")
        when = time.strftime("%Y-%m-%d %H:%M:%S UTC",
                             time.gmtime(previous.get("ts", 0)))
        raise HandoffError(
            f"already handed off to {previous.get('target_slot')} at {when} — "
            "re-run with --force and a different --to to create a second fork")


def _transcript_stat(path):
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise HandoffError(f"cannot stat source transcript: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise HandoffError("source transcript is not a regular file")
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns)


def _target_snapshot_identity(snapshot, target):
    row = _snapshot_rows(snapshot).get(target.get("name"))
    identity = row.get("identity") if isinstance(row, dict) else None
    if not isinstance(identity, dict):
        raise HandoffError("target snapshot has no bound identity — recollect")
    fingerprint = identity.get("account_fingerprint")
    digest = identity.get("credential_digest")
    if not isinstance(fingerprint, str) or not fingerprint \
            or not isinstance(digest, str) or not digest:
        raise HandoffError("target snapshot has no credential binding — recollect")
    return {"account_fingerprint": fingerprint, "credential_digest": digest}


def _target_home_stat(target):
    home = target_directory(target)
    try:
        metadata = os.stat(home, follow_symlinks=False)
    except OSError as error:
        raise HandoffError(f"cannot stat target home: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise HandoffError("target home is not a real directory")
    return (metadata.st_dev, metadata.st_ino)


def plan_handoff(source, family, target, snapshot, cap_proof, cwd, *,
                 cooldown_scope=None, resume_family=None,
                 automatic=False, child_generation=0, force=False,
                 require_executable=True, preemptive=False):
    """Build a complete, non-mutating handoff plan."""
    family = resolve_model_family(source, family)
    if resume_family:
        resume_family = resolve_model_family(source, resume_family)
    resume_family = "" if resume_family in (None, family) else resume_family
    if target.get("provider") != "claude":
        raise HandoffError("handoff target must be a Claude account")
    source = _source(source.transcript_path, source.session_id, [source.account],
                     source.model, source.seen_at, source.account["home"])
    cwd = os.path.realpath(cwd)
    if not os.path.isdir(cwd):
        raise HandoffError("current resume directory no longer exists")
    if require_executable and shutil.which("claude") is None:
        raise HandoffError("`claude` not found on PATH")
    destination = _preflight_destination(target, source.transcript_path,
                                         source.session_id)
    inspected = inspect_transcript(source.transcript_path,
                                   allow_dangling=(force or (
                                       automatic
                                       and cap_proof.get("authenticated") is True)))
    guard_not_duplicate(source.session_id, inspected["sha256"], force)
    return HandoffPlan(
        handoff_id=str(uuid.uuid4()), source=source, family=family,
        target=dict(target), snapshot=snapshot or {},
        cap_proof=dict(cap_proof or {}),
        cooldown_scope=dict(cooldown_scope or {}), cwd=cwd,
        inspected=inspected, destination=destination,
        source_stat=_transcript_stat(source.transcript_path),
        target_identity=_target_snapshot_identity(snapshot, target),
        target_home_stat=_target_home_stat(target), automatic=bool(automatic),
        child_generation=int(child_generation or 0), force=bool(force),
        preemptive=bool(preemptive), resume_family=resume_family)


@contextlib.contextmanager
def _handoff_lock():
    state = paths.ensure_private(paths.state_dir())
    handle = open(os.path.join(state, "handoffs.lock"), "a+")
    try:
        paths.chmod_private(handle.name, 0o600)
        locks.exclusive(handle)
        _reconcile_incomplete_unlocked()
        yield
    finally:
        locks.unlock(handle)
        handle.close()


def _fsync_directory(directory):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


_DIR_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
              | getattr(os, "O_NOFOLLOW", 0))
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_RECOVERY_SCHEMA = "headroom_handoff_recovery@1"
# schema@2 markers carry an explicit directory-component list so non-Claude
# adapters (codex: sessions/YYYY/MM/DD) reuse the same recovery machinery;
# Claude keeps writing schema@1 byte-identically.
_RECOVERY_SCHEMA_V2 = "headroom_handoff_recovery@2"
_AUTOMATIC_ACTIONS = {"cap_confirmed", "stop_sent", "stopped", "staged",
                      "resume_spawned", "resume_bound", "failure"}
TARGET_RESERVATION_SECONDS = 5 * 60.0


def _mkdir_open(parent_fd, name, create):
    if not name or name in (".", "..") or os.sep in name:
        raise HandoffError("target directory component is invalid")
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
    try:
        descriptor = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise HandoffError("target directory changed or is unsafe") from error
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise HandoffError("target path is not a directory")
    return descriptor


@contextlib.contextmanager
def _target_dir_fd(home, components, expected_home_stat, create):
    """Open home/<components...> descriptor-relative (O_NOFOLLOW throughout).
    Claude passes ("projects", slug); codex passes its sessions date path."""
    descriptors = []
    try:
        home_fd = os.open(home, _DIR_FLAGS)
        descriptors.append(home_fd)
        metadata = os.fstat(home_fd)
        if (metadata.st_dev, metadata.st_ino) != tuple(expected_home_stat):
            raise HandoffError("target home changed since planning")
        if not components:
            raise HandoffError("target directory components are missing")
        target_fd = home_fd
        for name in components:
            target_fd = _mkdir_open(target_fd, name, create)
            descriptors.append(target_fd)
        yield target_fd
    except HandoffError:
        raise
    except OSError as error:
        raise HandoffError(f"cannot open verified target directory: {error}") \
            from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _recovery_dir():
    return os.path.join(paths.state_dir(), "handoff-recovery")


def _marker_path(handoff_id):
    return os.path.join(_recovery_dir(), handoff_id + ".json")


def _write_marker_unlocked(plan, components, temporary, destination):
    directory = paths.ensure_private(_recovery_dir())
    if plan.provider == "codex":
        marker = {
            "schema": _RECOVERY_SCHEMA_V2, "handoff_id": plan.handoff_id,
            "target_home": target_directory(plan.target),
            "target_home_stat": list(plan.target_home_stat),
            "components": list(components),
            "temporary": temporary, "destination": destination,
            "transcript_sha256": plan.inspected["sha256"],
        }
    else:
        # Claude keeps the exact schema@1 marker it always wrote
        marker = {
            "schema": _RECOVERY_SCHEMA, "handoff_id": plan.handoff_id,
            "target_home": target_directory(plan.target),
            "target_home_stat": list(plan.target_home_stat),
            "slug": components[-1],
            "temporary": temporary, "destination": destination,
            "transcript_sha256": plan.inspected["sha256"],
        }
    paths.write_json_atomic(_marker_path(plan.handoff_id), marker, mode=0o600)
    _fsync_directory(directory)
    # normalize the in-memory copy only (never the on-disk schema@1 bytes)
    return dict(marker, components=list(components))


def _read_marker(path):
    try:
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            marker = json.load(handle)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise HandoffError("handoff recovery marker is unreadable") from error
    schema = marker.get("schema") if isinstance(marker, dict) else None
    required_strings = ["handoff_id", "target_home", "temporary",
                        "destination", "transcript_sha256"]
    if schema == _RECOVERY_SCHEMA:
        required_strings.append("slug")
        components = ["projects", marker.get("slug")] \
            if isinstance(marker, dict) else None
    elif schema == _RECOVERY_SCHEMA_V2:
        components = marker.get("components") \
            if isinstance(marker, dict) else None
    else:
        raise HandoffError("handoff recovery marker is malformed")
    home_stat = marker.get("target_home_stat") if isinstance(marker, dict) else None
    if (not isinstance(marker, dict)
            or any(not isinstance(marker.get(key), str) or not marker[key]
                   for key in required_strings)
            or not isinstance(home_stat, list) or len(home_stat) != 2
            or any(not isinstance(value, int) or isinstance(value, bool)
                   for value in home_stat)
            or not _valid_uuid(marker.get("handoff_id"))
            or not isinstance(components, list) or not components
            or any(not isinstance(value, str) or not value
                   or value in (".", "..") or os.sep in value
                   for value in components)
            or any(value in (".", "..") or os.sep in value
                   for value in (marker.get("temporary", ""),
                                 marker.get("destination", "")))):
        raise HandoffError("handoff recovery marker is malformed")
    return dict(marker, components=components)


def _name_stat(directory_fd, name):
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _finish_marker_unlocked(marker, committed):
    with _target_dir_fd(marker["target_home"], marker["components"],
                        marker["target_home_stat"], create=False) as directory_fd:
        temporary = _name_stat(directory_fd, marker["temporary"])
        destination = _name_stat(directory_fd, marker["destination"])
        if committed:
            if destination is None or not stat.S_ISREG(destination.st_mode):
                raise HandoffError("committed handoff destination is missing")
            if temporary is not None and (destination.st_dev, destination.st_ino) \
                    != (temporary.st_dev, temporary.st_ino):
                raise HandoffError("committed handoff marker does not match destination")
        elif destination is not None:
            if temporary is None or (destination.st_dev, destination.st_ino) != (
                    temporary.st_dev, temporary.st_ino):
                raise HandoffError(
                    "incomplete handoff destination cannot be safely reconciled")
            os.unlink(marker["destination"], dir_fd=directory_fd)
        if temporary is not None:
            os.unlink(marker["temporary"], dir_fd=directory_fd)
        os.fsync(directory_fd)
    os.unlink(_marker_path(marker["handoff_id"]))
    _fsync_directory(_recovery_dir())


def _reconcile_incomplete_unlocked():
    directory = _recovery_dir()
    if not os.path.exists(directory):
        return
    try:
        entries = list(os.scandir(directory))
    except OSError as error:
        raise HandoffError("handoff recovery directory is unreadable") from error
    markers = []
    for entry in entries:
        if not entry.name.endswith(".json"):
            raise HandoffError("handoff recovery directory contains unknown state")
        marker = _read_marker(entry.path)
        if entry.name != marker["handoff_id"] + ".json":
            raise HandoffError("handoff recovery marker name is malformed")
        markers.append(marker)
    rows = _recovery_ledger_rows(bool(markers))
    staged = {row.get("handoff_id") for row in rows
              if row.get("action") == "staged"
              and isinstance(row.get("handoff_id"), str)}
    for marker in markers:
        _finish_marker_unlocked(marker, marker["handoff_id"] in staged)


def _recovery_ledger_rows(has_markers):
    ledger = _ledger_path()
    if not os.path.exists(ledger):
        return []
    try:
        with open(ledger, "rb") as handle:
            data = handle.read()
    except OSError as error:
        raise HandoffError("handoff ledger is unreadable") from error
    if not data or data.endswith(b"\n"):
        return _read_jsonl(ledger, "handoff ledger")
    if not has_markers:
        raise HandoffError(f"handoff ledger is unreadable — inspect {ledger}")
    complete = data.rpartition(b"\n")[0]
    complete = complete + b"\n" if complete else b""
    try:
        for line in complete.splitlines():
            row = json.loads(line.decode("utf-8"))
            if not isinstance(row, dict):
                raise ValueError
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise HandoffError(f"handoff ledger is unreadable — inspect {ledger}") \
            from error
    descriptor = os.open(ledger, os.O_WRONLY | _NOFOLLOW)
    try:
        os.ftruncate(descriptor, len(complete))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return _read_jsonl(ledger, "handoff ledger")


def _publish_layout(plan):
    """(directory components under the target home, destination filename)."""
    if plan.provider == "codex":
        parts = [part for part in plan.relative_destination.split("/") if part]
        if len(parts) < 2 or any(part in (".", "..") or os.sep in part
                                 for part in parts):
            raise HandoffError("codex publish path is invalid")
        return parts[:-1], parts[-1]
    slug = os.path.basename(os.path.dirname(plan.source.transcript_path))
    return ["projects", slug], plan.source.session_id + ".jsonl"


def _copy_publish_pending(plan):
    components, destination = _publish_layout(plan)
    temporary = ".handoff-" + plan.handoff_id + ".tmp"
    with _target_dir_fd(target_directory(plan.target), components,
                        plan.target_home_stat, create=True):
        pass
    marker = _write_marker_unlocked(plan, components, temporary, destination)
    published = False
    try:
        with _target_dir_fd(marker["target_home"], components,
                            plan.target_home_stat,
                            create=True) as directory_fd:
            source_fd = os.open(plan.source.transcript_path,
                                os.O_RDONLY | _NOFOLLOW)
            target_fd = None
            try:
                source_stat = os.fstat(source_fd)
                if (source_stat.st_dev, source_stat.st_ino) \
                        != tuple(plan.source_stat[:2]):
                    raise HandoffError("source transcript changed before copy")
                target_fd = os.open(
                    temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600, dir_fd=directory_fd)
                digest = hashlib.sha256()
                last_byte = b""
                while True:
                    chunk = os.read(source_fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    last_byte = chunk[-1:]
                    view = memoryview(chunk)
                    while view:
                        written = os.write(target_fd, view)
                        if written <= 0:
                            raise HandoffError("target transcript write was incomplete")
                        view = view[written:]
                if digest.hexdigest() != plan.inspected["sha256"]:
                    raise HandoffError("source changed during copy — handoff aborted")
                copy_boundary = ((b"" if last_byte == b"\n" else b"\n")
                                 + tokens.handoff_marker_line())
                view = memoryview(copy_boundary)
                while view:
                    written = os.write(target_fd, view)
                    if written <= 0:
                        raise HandoffError("target transcript write was incomplete")
                    view = view[written:]
                os.fsync(target_fd)
            finally:
                os.close(source_fd)
                if target_fd is not None:
                    os.close(target_fd)
            def _link_destination():
                try:
                    os.link(temporary, destination, src_dir_fd=directory_fd,
                            dst_dir_fd=directory_fd, follow_symlinks=False)
                except FileExistsError as error:
                    raise HandoffError(
                        "target already has this session id; --force does not overwrite "
                        "destination collisions — inspect the previous partial handoff") \
                        from error
            if plan.provider == "codex":
                # P0-2: the COMPLETE target gate must be CURRENT immediately
                # before the hard-link publication — a target re-logged-in,
                # quarantined, capped, re-grouped, or re-configured while the
                # (potentially long) staging copy ran must abort here, while
                # the copy is still only an invisible temp file. We are under
                # the global handoff lock, and the gate performs the link
                # while STILL HOLDING the quarantine writers' lock, so a
                # quarantine cannot land between its read and the link. A
                # raise rolls the temp file back. (never runs for Claude)
                from . import handoff_codex
                handoff_codex.publish_within_gate(plan, _link_destination)
            else:
                _link_destination()
            published = True
            os.fsync(directory_fd)
        return marker
    except Exception:
        if not published:
            try:
                _finish_marker_unlocked(marker, committed=False)
            except (HandoffError, OSError):
                pass
        raise


def _stage_transcript(source, destination, expected_sha256):
    if os.path.islink(source):
        raise HandoffError("source transcript is a symlink — refusing to copy")
    directory = os.path.dirname(destination)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if os.path.islink(directory):
        raise HandoffError("target session directory is not a real directory")
    descriptor, temporary = tempfile.mkstemp(prefix=".handoff-", suffix=".tmp",
                                              dir=directory)
    try:
        paths.fchmod_private(descriptor, 0o600)
        digest = hashlib.sha256()
        with open(source, "rb") as incoming, os.fdopen(descriptor, "wb") as outgoing:
            descriptor = None
            last_byte = b""
            for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
                digest.update(chunk)
                outgoing.write(chunk)
                last_byte = chunk[-1:]
            if digest.hexdigest() != expected_sha256:
                raise HandoffError("source changed during copy — handoff aborted")
            if last_byte != b"\n":
                outgoing.write(b"\n")
            outgoing.write(tokens.handoff_marker_line())
            outgoing.flush()
            os.fsync(outgoing.fileno())
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError as error:
            raise HandoffError(
                "target already has this session id; --force does not overwrite "
                "destination collisions — inspect the previous partial handoff") \
                from error
        _fsync_directory(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def stage_transcript(source, destination, expected_sha256):
    try:
        _stage_transcript(source, destination, expected_sha256)
    except HandoffError:
        raise
    except OSError as error:
        raise HandoffError(f"could not stage transcript: {error}") from error


def _append_ledger_unlocked(record):
    state = paths.ensure_private(paths.state_dir())
    ledger = os.path.join(state, "handoffs.jsonl")
    descriptor = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        paths.fchmod_private(descriptor, 0o600)
        payload = (json.dumps(record, separators=(",", ":"),
                              allow_nan=False) + "\n").encode("utf-8")
        if os.write(descriptor, payload) != len(payload):
            raise HandoffError("handoff ledger append was incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def append_ledger(record):
    try:
        with _handoff_lock():
            _append_ledger_unlocked(record)
    except HandoffError:
        raise
    except OSError as error:
        raise HandoffError(f"could not append handoff ledger: {error}") from error


def append_action(handoff_id, action, *, automatic=False, **fields):
    allowed = {"cap_confirmed", "stop_sent", "stopped", "staged",
               "resume_spawned", "resume_bound", "failure"}
    if action not in allowed:
        raise HandoffError(f"invalid handoff ledger action: {action}")
    record = {"schema": SCHEMA, "ts": time.time(),
              "handoff_id": handoff_id, "action": action,
              "automatic": bool(automatic)}
    record.update(fields)
    append_ledger(record)
    return record


def _validated_automatic_rows(rows):
    for row in rows:
        safety_relevant = ("automatic" in row or row.get("action") \
                           == "cap_confirmed")
        if not safety_relevant:
            continue
        if (not isinstance(row.get("automatic"), bool)
                or row.get("action") not in _AUTOMATIC_ACTIONS
                or not _number(row.get("ts"))
                or not isinstance(row.get("handoff_id"), str)
                or not _valid_uuid(row.get("handoff_id"))):
            raise HandoffError(
                "handoff ledger has malformed automatic safety state — inspect "
                + _ledger_path())
    return rows


def verify_target_binding(plan):
    """Re-derive both pinned target identity components at the launch edge."""
    try:
        # THE SNAPSHOT AND THE RE-DERIVATION MUST READ ONE DIRECTORY.
        # plan.target_identity comes from the collector, which takes it at the
        # RESOLVED directory; re-deriving it at the registry home compares two
        # different chains and raises "target identity or credential changed
        # since planning" for a seat where nothing changed and no recollect
        # can help. That is the false diagnosis with the impossible cure that
        # R3 removed from route.block_reason, and it was alive here, in the
        # pre-spawn guard of the automatic rescue (2026-08-17 R4).
        current = collect.local_binding(
            plan.target["provider"], target_directory(plan.target))
        expected = (plan.target_identity["account_fingerprint"],
                    plan.target_identity["credential_digest"])
    except Exception as error:
        raise HandoffError(
            f"could not verify target identity or credential: {error}") from error
    if current != expected:
        raise HandoffError("target identity or credential changed since planning")


def _verify_target_unlocked(plan, now=None):
    verify_target_binding(plan)
    cool = route.preflight_cooldowns()
    row = _snapshot_rows(plan.snapshot).get(plan.target["name"])
    reason = route.block_reason(plan.target, plan.target_family, row, cool,
                                time.time() if now is None else now)
    if reason is not None:
        raise HandoffError(
            f"target {plan.target['name']} no longer has proven headroom: {reason}")


def _active_reservation(rows, plan, now):
    released = {row.get("handoff_id") for row in rows
                if row.get("action") in ("failure", "resume_bound")}
    for row in rows:
        if (row.get("handoff_id") == plan.handoff_id
                and row.get("action") == "cap_confirmed"
                and row.get("target_slot") == plan.target["name"]
                and row.get("handoff_id") not in released):
            until = row.get("reservation_until")
            until = until if _number(until) else \
                row["ts"] + TARGET_RESERVATION_SECONDS
            if until > now:
                return row
    return None


def reserve_automatic(plan, now=None, *, loop_window=600.0, loop_max=3):
    """Atomically admit one automatic cap and reserve its exact target."""
    if not plan.automatic:
        raise HandoffError("only automatic handoffs may reserve a target")
    now = time.time() if now is None else float(now)
    try:
        with _handoff_lock():
            rows = _validated_automatic_rows(
                _read_jsonl(_ledger_path(), "handoff ledger"))
            cutoff = now - loop_window
            confirmed = [row for row in rows
                         if row.get("automatic") is True
                         and row.get("action") == "cap_confirmed"
                         and row["ts"] >= cutoff]
            released = {row.get("handoff_id") for row in rows
                        if row.get("action") in ("failure", "resume_bound")}
            # The loop guard exists to stop a session being THRASHED between
            # accounts, so it counts admissions that actually touched a
            # session: one that reached `stop_sent`, or one still in flight.
            # An admission that was released by a failure WITHOUT ever
            # stopping the child moved nothing and must not consume the
            # budget — otherwise a few aborted (e.g. preemptive) attempts
            # exhaust the allowance and the next GENUINE cap is refused,
            # disabling supervision exactly when it is needed.
            #
            # `stop_cancelled` is the one case where a durable stop_sent row
            # exists but no signal was ever sent: the row must be written
            # before any signal (so a crash can never hide a stop), and the
            # caller then cancelled on a last-instant safety check. It never
            # touched the session either.
            cancelled = {row.get("handoff_id") for row in rows
                         if row.get("action") == "failure"
                         and row.get("stop_cancelled") is True}
            touched = {row.get("handoff_id") for row in rows
                       if row.get("action") == "stop_sent"} - cancelled
            effective = [row for row in confirmed
                         if row.get("handoff_id") in touched
                         or row.get("handoff_id") not in released]
            if len(effective) >= loop_max:
                raise HandoffError(
                    "automatic handoff loop guard: 3 handoffs in 10 minutes")
            for row in confirmed:
                until = row.get("reservation_until")
                until = until if _number(until) else \
                    row["ts"] + TARGET_RESERVATION_SECONDS
                if (row.get("target_slot") == plan.target["name"]
                        and row.get("handoff_id") not in released
                        and until > now):
                    raise HandoffError(
                        f"target {plan.target['name']} is reserved by another "
                        "automatic handoff")
            _verify_target_unlocked(plan, now)
            record = {
                "schema": SCHEMA, "ts": now, "handoff_id": plan.handoff_id,
                "action": "cap_confirmed", "automatic": True,
                "source_slot": plan.source.account["name"],
                "target_slot": plan.target["name"],
                "old_session_id": plan.source.session_id,
                "actual_model_family": plan.family,
                "cap_scope": plan.cooldown_scope.get("key"),
                "cap_used_percent": plan.cooldown_scope.get("used_percent"),
                "cap_reset": plan.cooldown_scope.get("reset"),
                "transcript_sha256": plan.inspected["sha256"],
                "child_generation": plan.child_generation,
                "reservation_until": now + TARGET_RESERVATION_SECONDS,
            }
            _append_ledger_unlocked(record)
            return record
    except HandoffError:
        raise
    except (OSError, RuntimeError, registry.RegistryError, ValueError) as error:
        raise HandoffError(f"could not reserve automatic handoff: {error}") \
            from error


def verify_automatic_reservation(plan):
    try:
        with _handoff_lock():
            rows = _validated_automatic_rows(
                _read_jsonl(_ledger_path(), "handoff ledger"))
            if _active_reservation(rows, plan, time.time()) is None:
                raise HandoffError("automatic target reservation is missing")
            _verify_target_unlocked(plan)
    except HandoffError:
        raise
    except (OSError, RuntimeError, registry.RegistryError, ValueError) as error:
        raise HandoffError(f"could not verify automatic reservation: {error}") \
            from error


def _snapshot_rows(snapshot):
    return {row.get("name"): row for row in (snapshot or {}).get("accounts", [])
            if isinstance(row, dict) and row.get("name")}


def resume_command(target_home, session_id, model=""):
    """The command that gets this conversation back BY HAND.

    `model` matters for exactly the cases the automatic argv already handles:
    a resume names no model, so a session that had to change tier (or that
    outgrew the standard window) would come back on the child's default —
    which is the model or the window it just proved it cannot use. The
    operator reading this line after a failed spawn has no other source of
    that fact, and the ledger row is the only record left if the process is
    gone, so both carry it."""
    model_flag = f" --model {shlex.quote(model)}" if model else ""
    return (f"CLAUDE_CONFIG_DIR={shlex.quote(target_home)} claude --resume "
            f"{shlex.quote(session_id)} --fork-session{model_flag}")


def resume_argv(result):
    return ["claude", "--resume", result.plan.source.session_id,
            "--fork-session"]


def commit_handoff(plan):
    """Cool, no-clobber publish, and ledger one handoff under one lock."""
    try:
        with _handoff_lock():
            rows = _validated_automatic_rows(
                _read_jsonl(_ledger_path(), "handoff ledger"))
            if plan.automatic and _active_reservation(
                    rows, plan, time.time()) is None:
                raise HandoffError("automatic target reservation is missing")
            _verify_target_unlocked(plan)
            if plan.provider == "codex":
                # provider-specific recheck under the SAME lock: refresh-token
                # lineage + handoff_group pins (never runs for Claude plans)
                from . import handoff_codex
                handoff_codex.verify_codex_commit(plan)
            guard_not_duplicate(plan.source.session_id,
                                plan.inspected["sha256"], plan.force)
            if os.path.lexists(plan.destination):
                raise HandoffError(
                    "target already has this session id; --force does not overwrite "
                    "destination collisions — inspect the previous partial handoff")
            scope = plan.cooldown_scope
            if scope:
                route.mark(
                    plan.source.account["name"], plan.family, scope.get("reset"),
                    account_wide=bool(scope.get("account_wide")),
                    window="5h" if scope.get("window") == "5h" else "7d")
            marker = _copy_publish_pending(plan)
            rows = _snapshot_rows(plan.snapshot)
            source_row = rows.get(plan.source.account["name"], {})
            source_email = (source_row.get("email")
                            or plan.source.account.get("expected_email") or "")
            record = {
                "schema": SCHEMA, "ts": time.time(),
                "handoff_id": plan.handoff_id, "action": "staged",
                "actions": ["staged"],
                "old_session_id": plan.source.session_id,
                "new_session_id": None,
                "session_id": plan.source.session_id,
                "source_slot": plan.source.account["name"],
                "source_email_redacted": collect.redact_email(source_email),
                "target_slot": plan.target["name"], "cwd": plan.cwd,
                "actual_model_family": plan.family,
                "cap_scope": scope.get("key") if scope else None,
                "cap_used_percent": scope.get("used_percent") if scope else None,
                "cap_reset": scope.get("reset") if scope else None,
                "transcript_sha256": plan.inspected["sha256"],
                "transcript_bytes": plan.inspected["bytes"],
                "automatic": plan.automatic,
                "child_generation": plan.child_generation,
                "source_5h_used": ((source_row.get("windows") or {}).get("5h")
                                   or {}).get("used_percent"),
                "reason": ("preemptive" if plan.preemptive
                           else "capped" if scope else "manual"),
            }
            if plan.provider == "codex":
                from . import handoff_codex
                record["provider"] = "codex"
                record["handoff_group"] = plan.target.get("handoff_group")
                record["resume_command"] = handoff_codex.codex_resume_command(
                    plan.target["home"], plan.source.session_id)
                record["resume_headless_command"] = \
                    handoff_codex.codex_exec_resume_command(
                        plan.target["home"], plan.source.session_id)
            else:
                record["resume_command"] = resume_command(
                    target_directory(plan.target), plan.source.session_id,
                    plan.resume_model or plan.resume_family)
            try:
                _append_ledger_unlocked(record)
            except Exception:
                _finish_marker_unlocked(marker, committed=False)
                raise
            _finish_marker_unlocked(marker, committed=True)
            return HandoffResult(plan, plan.destination, record)
    except HandoffError:
        raise
    except (OSError, RuntimeError, registry.RegistryError, ValueError) as error:
        raise HandoffError(f"could not commit handoff: {error}") from error


def _print_baton(record, unresolved=()):
    print("BATON — conversation history staged")
    print(f"session: {record['old_session_id']} ({record['transcript_bytes']} bytes)")
    print(f"cwd: {record['cwd']}")
    print(f"from -> to: {record['source_slot']} -> {record['target_slot']}")
    print("does not carry: background tasks / MCP connections / permission "
          "approvals / permission mode")
    if unresolved:
        print("note: the interrupted tool call may re-run on resume")
    print("NEXT COMMAND:")
    print(record["resume_command"])


def _parse_args(args):
    options = {"session": None, "to": None, "model": None, "provider": None,
               "from": None, "headless": None,
               "print": False, "force": False, "yes": False}
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("--print", "--force", "--yes"):
            options[arg[2:]] = True
        elif arg in ("--session", "--to", "--model", "--provider",
                     "--from", "--headless") \
                and index + 1 < len(args):
            index += 1
            options[arg[2:]] = args[index]
        else:
            raise HandoffError(
                "usage: headroom handoff [--session UUID] [--to SLOT] "
                "[--model FAMILY] [--provider claude|codex] "
                "[--from SLOT] [--headless BATON] "
                "[--print | --yes] [--force]")
        index += 1
    if options["yes"] and options["print"]:
        raise HandoffError("--yes and --print are mutually exclusive")
    if options["headless"] is not None and options["print"]:
        raise HandoffError("--headless and --print are mutually exclusive")
    if options["provider"] not in (None, "claude", "codex"):
        raise HandoffError("--provider must be claude or codex")
    return options


def _detect_provider(session_id, accounts):
    """Auto-detect the provider a --session UUID belongs to: a Claude projects
    transcript vs a Codex sessions rollout. Ambiguity fails closed."""
    if session_id is None:
        return "claude"
    if not _valid_uuid(session_id):
        raise HandoffError("--session must be a UUID")
    from . import handoff_codex
    codex_hits = handoff_codex.locate_rollouts(str(uuid.UUID(session_id)),
                                               accounts)
    claude_hits = _filesystem_matches(str(uuid.UUID(session_id)), accounts)
    if codex_hits and claude_hits:
        raise HandoffError(
            f"session {session_id} exists in both a Claude home and a Codex "
            "home — pass --provider claude|codex to disambiguate")
    return "codex" if codex_hits else "claude"


def cmd_handoff(args):
    """Manual adapter: confirm first, then commit, then optionally exec."""
    try:
        options = _parse_args(args)
        if not options["print"] and not options["yes"] and not sys.stdin.isatty():
            raise HandoffError(
                "non-interactive handoff requires --yes or --print")
        cwd = os.path.realpath(os.getcwd())
        if not os.path.isdir(cwd):
            raise HandoffError("current working directory no longer exists")
        accounts = registry.accounts()
        provider = options["provider"] or _detect_provider(options["session"],
                                                           accounts)
        if provider == "codex":
            from . import handoff_codex
            return handoff_codex.cmd_codex_handoff(options, accounts, cwd)
        if options["from"] is not None or options["headless"] is not None:
            raise HandoffError(
                "--from and --headless are codex handoff options — pass "
                "--provider codex")
        source = resolve_source(options["session"], accounts, cwd)
        family = resolve_model_family(source, options["model"])
        # A modest tolerance, NOT max_age=0: a running dashboard collects on
        # every poll and holds the single-flight collect lock, so demanding a
        # zero-second snapshot made the manual handoff fail with "no fresh
        # snapshot" whenever `headroom serve` was up. A reading this recent is
        # a sound basis for choosing the target — the target's bound identity
        # is re-verified from the snapshot here and the account's live
        # credential binding is re-checked again at the actual launch.
        snapshot = route.ensure_fresh_snapshot(max_age=HANDOFF_SNAPSHOT_MAX_AGE)
        if snapshot is None:
            raise HandoffError("no fresh usage snapshot — handoff held")
        target = select_target(source.account["name"], snapshot, family,
                               options["to"])
        guard_source_stable(source.transcript_path)
        scope = route.cap_scope(snapshot, source.account["name"], family,
                                "usage limit reached")
        plan = plan_handoff(
            source, family, target, snapshot, {}, cwd, cooldown_scope=scope,
            force=options["force"])
        rows = _snapshot_rows(snapshot)
        source_email = (rows.get(source.account["name"], {}).get("email")
                        or source.account.get("expected_email") or "")
        target_email = (rows.get(target["name"], {}).get("email")
                        or target.get("expected_email") or "")
        if source_email and target_email \
                and source_email.rpartition("@")[2].lower() \
                != target_email.rpartition("@")[2].lower():
            print("warning: conversation content is moving to the other "
                  "account's data boundary")
        if not options["print"] and not options["yes"]:
            answer = input(f"hand off {source.session_id} to {target['name']}? "
                           "This copies its conversation. [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                print("handoff cancelled; nothing copied or cooled")
                return 0
            refreshed = route.ensure_fresh_snapshot(max_age=0)
            if refreshed is None:
                raise HandoffError("post-confirmation collect failed — handoff held")
            refreshed_target = select_target(
                source.account["name"], refreshed, family, target["name"])
            refreshed_identity = _target_snapshot_identity(
                refreshed, refreshed_target)
            if refreshed_identity != plan.target_identity:
                raise HandoffError(
                    "target identity or credential changed during confirmation")
            guard_source_stable(source.transcript_path)
            refreshed_scope = route.cap_scope(
                refreshed, source.account["name"], family,
                "usage limit reached")
            plan = plan_handoff(
                source, family, refreshed_target, refreshed, {}, cwd,
                cooldown_scope=refreshed_scope, force=options["force"])
            target = refreshed_target
        result = commit_handoff(plan)
        _print_baton(result.record, plan.inspected["unresolved_tool_ids"])
        if options["print"]:
            return 0
        environment = collect.scrubbed_env()
        environment["CLAUDE_CONFIG_DIR"] = target_directory(target)
        try:
            argv = resume_argv(result)
            verify_target_binding(plan)
            os.execvpe(argv[0], argv, environment)
        except OSError as error:
            print(f"headroom: cannot exec claude: {error}", file=sys.stderr)
            return 127
    except HandoffError as error:
        print(f"headroom: {error}", file=sys.stderr)
        return 2
