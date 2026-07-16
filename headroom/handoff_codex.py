"""Codex provider adapter for the transactional conversation handoff.

Codex persists sessions as ``$CODEX_HOME/sessions/YYYY/MM/DD/
rollout-<timestamp>-<UUID>.jsonl``.  A handoff copies that one rollout plus a
content-free headroom boundary record — never ``auth.json``, ``config.toml``,
state databases, MCP credentials, memories, or shell state — to the SAME
relative path inside another configured Codex home in the same
``handoff_group``, then resumes it there with
``CODEX_HOME=<target> codex resume <UUID>`` (or headlessly with ``codex exec
resume``).  Every guard reuses the Claude handoff's transaction spine in
:mod:`headroom.handoff` and fails closed.

The target gate is enforced THREE times: at plan time, again under the global
handoff lock immediately before the hard-link publication (after the staging
copy), and again under the lock immediately before exec — so a target that is
re-logged-in, quarantined, capped, re-grouped, or re-configured DURING staging
aborts before any publication or launch.
"""
import contextlib
import fcntl
import glob
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import sys
import time
import uuid
from dataclasses import dataclass

from . import collect, paths, registry, route
from . import handoff
from .handoff import HandoffError, HandoffPlan, SourceSession

# rollout-2026-05-23T11-23-11-<uuid>.jsonl — strict, so an unexpected layout
# holds the handoff instead of guessing at a path we would then publish to.
_ROLLOUT_NAME = (r"rollout-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-%s\.jsonl")
_DATE_PARTS = (re.compile(r"^\d{4}$"), re.compile(r"^\d{2}$"),
               re.compile(r"^\d{2}$"))

# Local tool executions that MUST have a same-call_id output before the
# rollout may move: resuming mid-tool elsewhere could re-run the side effect.
# Server-side calls (web_search_call, tool_search_call) have no local pairing.
_TOOL_CALL_TYPES = ("function_call", "local_shell_call", "custom_tool_call")
_TOOL_OUTPUT_TYPES = ("function_call_output", "local_shell_call_output",
                      "custom_tool_call_output")
# A turn is only over at one of Codex's REAL persisted terminal boundaries
# (both abort spellings included). A generic `error` event is NOT a boundary
# — codex's own rollout reconstruction does not treat it as one, so neither
# may we.
_TURN_BOUNDARY_EVENTS = ("task_complete", "turn_complete", "turn_aborted",
                         "task_aborted")
_EPHEMERAL_PERSISTENCE = ("none", "ephemeral", "in-memory", "in_memory")

# A snapshot we JUST collected is stamped with an integer-second `generated`,
# so against a float `now` it is already up to ~1s "old" — max_age=0 would
# reject every genuine fresh collect. This is the small positive tolerance a
# force-collect accepts its own snapshot under (still far below any window
# in which capacity could silently change).
POST_COLLECT_TOLERANCE = 30.0


@dataclass(frozen=True)
class CodexSource:
    session_id: str
    rollout_path: str
    account: dict
    relative_parts: tuple  # ("sessions", "YYYY", "MM", "DD", basename)


def _canonical_uuid(session_id):
    if not handoff._valid_uuid(session_id):
        raise HandoffError("--session must be a UUID")
    return str(uuid.UUID(session_id))


def locate_rollouts(session_id, accounts):
    """Raw filename matches for a UUID across every configured Codex home.

    Used both by provider auto-detection and by :func:`resolve_codex_source`;
    containment/symlink validation happens at resolve time so a bad hit is a
    clear refusal, never a silent skip."""
    matches = []
    for account in accounts:
        if account.get("provider") != "codex":
            continue
        home = registry.expand(account["home"])
        pattern = os.path.join(home, "sessions", "*", "*", "*",
                               "rollout-*-" + session_id + ".jsonl")
        for path in sorted(glob.glob(pattern)):
            matches.append((path, account))
    return matches


def _contained_rollout(path, session_id, account):
    """Validate one rollout path: exact name, no symlinks, no escape.
    Returns (canonical_path, relative_parts)."""
    absolute = os.path.abspath(os.path.expanduser(path))
    name = os.path.basename(absolute)
    name_re = re.compile(_ROLLOUT_NAME % re.escape(session_id))
    if not name_re.fullmatch(name):
        raise HandoffError(
            f"rollout filename {name!r} does not match the expected "
            "sessions/YYYY/MM/DD/rollout-<timestamp>-<UUID>.jsonl layout")
    home = registry.expand(account["home"])
    sessions_root = os.path.join(home, "sessions")
    if os.path.islink(sessions_root):
        raise HandoffError("source sessions directory is a symlink")
    try:
        metadata = os.lstat(absolute)
    except OSError as error:
        raise HandoffError(
            f"session {session_id} rollout no longer exists") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise HandoffError("source rollout is a symlink — refusing to copy")
    if not stat.S_ISREG(metadata.st_mode):
        raise HandoffError("source rollout is not a regular file")
    relative = os.path.relpath(absolute, home)
    parts = relative.split(os.sep)
    if (len(parts) != 5 or parts[0] != "sessions" or parts[4] != name
            or any(not pattern.fullmatch(part)
                   for pattern, part in zip(_DATE_PARTS, parts[1:4]))):
        raise HandoffError(
            f"session {session_id} rollout is not inside the account's "
            "sessions/YYYY/MM/DD tree")
    canonical = os.path.realpath(absolute)
    expected = os.path.join(os.path.realpath(sessions_root), *parts[1:])
    if canonical != expected:
        raise HandoffError(
            f"session {session_id} rollout escapes the account's sessions "
            "directory — refusing to copy")
    return canonical, tuple(parts)


def resolve_codex_source(session_id, accounts, from_slot=None):
    """Exactly ONE rollout for this UUID.  Zero or several matches fail
    closed — there is deliberately NO ledger-based disambiguation (a stale
    ledger row would silently pick the pre-handoff copy and lose the resumed
    continuation).  ``--from SLOT`` narrows the search to one named codex
    home, and still requires exactly one match inside it."""
    session_id = _canonical_uuid(session_id)
    if from_slot is not None:
        named = [account for account in accounts
                 if account.get("name") == from_slot]
        if not named:
            raise HandoffError(
                f"--from: no configured account named {from_slot!r}")
        if named[0].get("provider") != "codex":
            raise HandoffError("--from must name a Codex account")
        accounts = named
    matches = locate_rollouts(session_id, accounts)
    if not matches:
        raise HandoffError(
            f"session {session_id} matched no rollout in "
            + (f"account {from_slot!r}" if from_slot
               else "any configured Codex home"))
    if len(matches) > 1:
        slots = ", ".join(sorted({account["name"] for _, account in matches}))
        raise HandoffError(
            f"session {session_id} matched {len(matches)} codex rollouts "
            f"(slots: {slots}) — refusing an ambiguous handoff; pass "
            "--from SLOT to name the source account")
    path, account = matches[0]
    canonical, parts = _contained_rollout(path, session_id, account)
    return CodexSource(session_id, canonical, dict(account), parts)


def _tool_call_id(payload):
    call_id = payload.get("call_id") or payload.get("id")
    if not isinstance(call_id, str) or not call_id:
        raise HandoffError("rollout has a tool call without a valid call id")
    return call_id


def _validate_tool_calls(records):
    """Unresolved local tool-call ids, mirroring the Claude mid-tool guard."""
    uses = []
    results = []
    for record in records:
        payload = record.get("payload")
        if record.get("type") != "response_item" or not isinstance(payload, dict):
            continue
        kind = payload.get("type")
        if kind in _TOOL_CALL_TYPES:
            call_id = _tool_call_id(payload)
            if call_id in uses:
                raise HandoffError(f"rollout repeats tool call id {call_id}")
            uses.append(call_id)
        elif kind in _TOOL_OUTPUT_TYPES:
            call_id = payload.get("call_id")
            if not isinstance(call_id, str) or not call_id:
                raise HandoffError(
                    "rollout has a tool output without a valid call_id")
            results.append(call_id)
    unknown = [call_id for call_id in results if call_id not in uses]
    if unknown:
        raise HandoffError("rollout has a tool output for unknown id: "
                           + ", ".join(dict.fromkeys(unknown)))
    return tuple(call_id for call_id in uses if call_id not in set(results))


def _turn_key(payload):
    """The turn/submission id a lifecycle event carries, when it carries one.

    ABSENT keys return None (legacy id-less layouts pair id-less boundaries);
    a key that is PRESENT but not a nonempty string is a malformed record and
    fails closed — it must never collapse into the legacy case, or a spliced
    rollout could dodge the id-matching guard with ``turn_id: 7`` or ``""``.
    """
    for key in ("turn_id", "submission_id", "id"):
        if key not in payload:
            continue
        value = payload[key]
        if isinstance(value, str) and value:
            return value
        raise HandoffError(
            "rollout lifecycle event carries a malformed %s — refusing to "
            "hand off" % key)
    return None


def _validate_lifecycle(records):
    """Turn-ID-aware lifecycle state machine matching Codex's own rollout
    reconstruction: every ``task_started`` opens a turn; only a REAL terminal
    boundary (``task_complete``/``turn_complete``/``turn_aborted``/
    ``task_aborted``) closes it, and when EITHER side carries a turn id the
    other must carry the SAME nonempty id — an id-less boundary cannot close
    an id-carrying turn (a truncated/spliced rollout could otherwise fake a
    clean close), and vice versa.  Only a rollout whose records carry no turn
    ids at all (legacy layouts) may pair id-less boundaries.  A generic
    ``error`` event is NOT a boundary.

    Hard failures (never --force-overridable): a rollout with no lifecycle
    events at all, a boundary with no open turn, mismatched or one-sided
    turn ids.  Returns (open_at_end, interior_dangling_turns) so the caller
    can apply the --force-overridable mid-turn guard."""
    open_turn = False
    open_id = None
    dangling = 0
    saw_lifecycle = False
    for record in records:
        payload = record.get("payload")
        if record.get("type") != "event_msg" or not isinstance(payload, dict):
            continue
        kind = payload.get("type")
        if kind == "task_started":
            saw_lifecycle = True
            if open_turn:
                dangling += 1  # interior turn that never reached a boundary
            open_turn, open_id = True, _turn_key(payload)
        elif kind in _TURN_BOUNDARY_EVENTS:
            saw_lifecycle = True
            if not open_turn:
                raise HandoffError(
                    f"rollout has a {kind} with no open turn — inconsistent "
                    "turn lifecycle; refusing to hand off")
            close_id = _turn_key(payload)
            if open_id != close_id:
                raise HandoffError(
                    "rollout closes turn %r while turn %r is open — "
                    "inconsistent turn ids; refusing to hand off"
                    % (close_id, open_id))
            open_turn, open_id = False, None
    if not saw_lifecycle:
        raise HandoffError(
            "rollout has no turn lifecycle events at all — not a resumable "
            "persisted codex conversation")
    return open_turn, dangling


def _check_meta_payload(payload, session_id, position):
    """One session_meta payload: matching UUID, persisted, openai provider."""
    meta_id = payload.get("id")
    if not isinstance(meta_id, str) \
            or meta_id.lower() != session_id.lower():
        raise HandoffError(
            f"rollout session_meta {position} id does not match the requested "
            "session — refusing to copy mismatched session metadata")
    persistence = str(payload.get("persistence") or "").lower()
    if payload.get("ephemeral") \
            or persistence in _EPHEMERAL_PERSISTENCE \
            or str(payload.get("source") or "").lower() == "ephemeral":
        raise HandoffError(
            "rollout is an ephemeral/in-memory codex session — it cannot be "
            "resumed on another account")
    provider = payload.get("model_provider")
    if provider != "openai":
        raise HandoffError(
            f"rollout session_meta {position} records model_provider "
            f"{provider!r} — only 'openai' rollouts can move between "
            "ChatGPT-subscription seats")


def _guard_session_meta(records, session_id):
    """Validate EVERY session_meta record consistently — a later session_meta
    with a different UUID or provider is a spliced/corrupt rollout."""
    meta = records[0]
    payload = meta.get("payload")
    if meta.get("type") != "session_meta" or not isinstance(payload, dict):
        raise HandoffError(
            "rollout has no session_meta header — not a resumable persisted "
            "codex session")
    _check_meta_payload(payload, session_id, "at line 1")
    for index, record in enumerate(records[1:], start=2):
        if record.get("type") != "session_meta":
            continue
        extra = record.get("payload")
        if not isinstance(extra, dict):
            raise HandoffError(
                f"rollout has a malformed session_meta record at line {index}")
        _check_meta_payload(extra, session_id, f"at line {index}")
    return payload


def inspect_rollout(path, session_id, allow_dangling=False):
    """Validate every JSONL record of a rollout and hash its exact bytes.

    Rejects symlinks, malformed JSONL, mismatched/ephemeral/incompatible
    session metadata (EVERY session_meta record), unresolved local tool
    calls, an inconsistent turn lifecycle, and a turn still open at the end
    (no real terminal boundary — a generic ``error`` is not one).
    ``allow_dangling`` (--force / a proven automatic cap in a later phase)
    permits ONLY the dangling-tool and open/interior-turn cases — never
    metadata, integrity, or lifecycle-consistency failures."""
    if os.path.islink(path):
        raise HandoffError("source rollout is a symlink — refusing to copy")
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        raise HandoffError(f"cannot read source rollout: {error}") from error
    lines = data.splitlines()
    if not lines:
        raise HandoffError("rollout is empty — refusing to hand off")
    records = []
    for index, raw in enumerate(lines):
        try:
            record = json.loads(raw.decode("utf-8"))
            if not isinstance(record, dict):
                raise ValueError
            records.append(record)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            if index == len(lines) - 1:
                raise HandoffError(
                    "rollout has an incomplete final line — is codex still "
                    "writing?") from error
            raise HandoffError(
                f"rollout contains invalid JSON at line {index + 1}") from error
    meta = _guard_session_meta(records, session_id)
    unresolved = _validate_tool_calls(records)
    if unresolved and not allow_dangling:
        raise HandoffError(
            "codex session stopped mid-tool-call (unresolved: %s); resume it "
            "once on the source account, or use --force for a manual "
            "content-preserving fork" % ", ".join(unresolved))
    open_turn, dangling = _validate_lifecycle(records)
    if (open_turn or dangling) and not allow_dangling:
        raise HandoffError(
            "codex session stopped mid-turn (task_started without a real "
            "terminal boundary — task_complete/turn_complete/turn_aborted); "
            "resume it once on the source account, or use --force for a "
            "manual content-preserving fork")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "records": len(records),
        "unresolved_tool_ids": unresolved,
        "meta": {
            "cwd": meta.get("cwd"),
            "source": meta.get("source"),
            "model_provider": meta.get("model_provider"),
        },
    }


# Every config layer codex may merge when constructing a resumed thread —
# not just $CODEX_HOME/config.toml: the system/managed layers, and any
# project `.codex/config.toml` on the walk from the resume cwd up to the
# filesystem root (codex applies project config for trusted projects; we
# gate it unconditionally — fail closed).
_SYSTEM_CONFIG_LAYERS = ("/etc/codex/config.toml",
                         "/etc/codex/managed_config.toml")


def _config_layer_paths(home, cwd):
    """(path, label) for every codex config layer relevant to a resume that
    will run in ``cwd`` against the target ``home``."""
    layers = [(path, "codex system config " + path)
              for path in _SYSTEM_CONFIG_LAYERS]
    layers.append((os.path.join(home, "config.toml"), "target config.toml"))
    directory = os.path.realpath(cwd)
    while True:
        candidate = os.path.join(directory, ".codex", "config.toml")
        layers.append((candidate, "project config " + candidate))
        parent = os.path.dirname(directory)
        if parent == directory:
            return layers
        directory = parent


def _layer_provider(config_path, label):
    """One codex config layer's whole provider SURFACE, fail-closed.

    Returns None when the layer file does not exist, else the set of
    provider ids the layer could contribute to the merged effective config:
    the top-level ``model_provider`` plus EVERY profile's ``model_provider``
    — another layer may select any profile this one defines, so all of them
    are reachable regardless of which layer carries the ``profile`` key.

    Refuses (fail closed): symlinked/unreadable/malformed layers, a
    ``profile`` selection this layer cannot resolve, any endpoint override
    for the built-in provider (top-level or in-profile ``openai_base_url``,
    a ``model_providers`` table redefining ``openai`` or nested in a
    profile), and unreadable profile tables."""
    if os.path.islink(config_path):
        raise HandoffError(f"{label} is a symlink — refusing to trust it")
    if not os.path.exists(config_path):
        return None
    try:
        with open(config_path, "rb") as handle:
            raw = handle.read()
    except OSError as error:
        raise HandoffError(f"cannot read {label}: {error}") from error
    try:
        import tomllib
    except ImportError as error:  # pragma: no cover — Python < 3.11
        raise HandoffError(
            "cannot parse codex config on this Python (tomllib needs 3.11+) "
            "— refusing to assume the effective model provider") from error
    try:
        config = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise HandoffError(
            f"{label} is unreadable — refusing to assume the effective "
            "model provider") from error
    if "openai_base_url" in config:
        raise HandoffError(
            f"{label} sets openai_base_url (a custom endpoint for the "
            "built-in provider) — the imported conversation would be sent "
            "to a non-standard endpoint; refusing")
    selectable = set()
    provider = config.get("model_provider")
    if provider is not None:
        if not isinstance(provider, str) or not provider:
            raise HandoffError(
                f"{label} model_provider is unreadable — refusing")
        selectable.add(provider)
    profiles = config.get("profiles")
    if profiles is not None and not isinstance(profiles, dict):
        raise HandoffError(f"{label} profiles table is unreadable — refusing")
    for name, entry in (profiles or {}).items():
        if not isinstance(entry, dict):
            raise HandoffError(
                f"{label} profile {name!r} is unreadable — refusing")
        if "openai_base_url" in entry or "model_providers" in entry:
            raise HandoffError(
                f"{label} profile {name!r} overrides the provider endpoint "
                "— refusing")
        candidate = entry.get("model_provider")
        if candidate is not None:
            if not isinstance(candidate, str) or not candidate:
                raise HandoffError(
                    f"{label} profile {name!r} model_provider is unreadable "
                    "— refusing")
            selectable.add(candidate)
    profile_name = config.get("profile")
    if profile_name is not None and (
            not isinstance(profile_name, str) or not profile_name
            or not isinstance(profiles, dict)
            or not isinstance(profiles.get(profile_name), dict)):
        # a non-string `profile` (e.g. a TOML array) must refuse, never
        # TypeError out of the gate as an unhandled traceback
        raise HandoffError(
            f"{label} selects a profile that is missing or unreadable — "
            "refusing to assume the effective model provider")
    overrides = config.get("model_providers")
    if overrides is not None and not isinstance(overrides, dict):
        raise HandoffError(f"{label} model_providers is unreadable — refusing")
    if isinstance(overrides, dict) and "openai" in overrides:
        raise HandoffError(
            f"{label} redefines model provider 'openai' (custom endpoint) — "
            "the imported conversation would be sent to a non-standard "
            "endpoint; refusing")
    return selectable


def _effective_model_provider(home, cwd):
    """The model provider the TARGET home's codex would actually construct a
    resumed thread against, across EVERY config layer codex merges (system/
    managed config, the home's config.toml, project `.codex/config.toml`
    from the resume cwd upward), defaulting to codex's built-in "openai"
    when no layer exists.  Layer precedence and profile merging are moving
    targets across codex versions, so the gate is order-independent over the
    whole provider SURFACE: it passes only when no existing layer could
    contribute any provider other than stock "openai" — via top-level
    selection, ANY profile (selected anywhere or not), an ``openai``
    redefinition, or an ``openai_base_url`` endpoint override.  (The exec
    environment is scrubbed separately: OPENAI_BASE_URL is stripped by
    collect.scrubbed_env.)"""
    for config_path, label in _config_layer_paths(home, cwd):
        selectable = _layer_provider(config_path, label)
        if not selectable:
            continue
        foreign = sorted(name for name in selectable if name != "openai")
        if foreign:
            raise HandoffError(
                f"{label} can activate model_provider {foreign[0]!r} — "
                "codex resume could send the imported conversation to that "
                "provider; only stock 'openai' ChatGPT-subscription targets "
                "may receive a handoff")
    return "openai"


def guard_target_effective_binding(target, cwd):
    """P0 gate: the TARGET's effective provider and auth mode — not just the
    source rollout header.  `codex resume` constructs the new thread from the
    target home's effective configuration (every layer, including a project
    `.codex/config.toml` at the resume cwd), so a layer that selects a proxy,
    Azure, or local provider would send the imported conversation there.
    Requires effective model_provider == "openai" AND a ChatGPT-subscription
    auth.json.  Called at plan time and re-derived under the handoff lock
    immediately before publish and before exec."""
    home = registry.expand(target["home"])
    provider = _effective_model_provider(home, cwd)
    if provider != "openai":
        raise HandoffError(
            f"target {target.get('name')!r} effective model_provider is "
            f"{provider!r} — codex resume would send the imported "
            "conversation to that provider; only 'openai' "
            "ChatGPT-subscription targets may receive a handoff")
    auth = paths.load_json(os.path.join(home, "auth.json"))
    if not auth:
        raise HandoffError(
            "target auth.json is missing or unreadable — cannot prove a "
            "ChatGPT-subscription login")
    if collect.codex_auth_mode(auth) != "chatgpt":
        raise HandoffError(
            "target is not a ChatGPT-subscription login (API-key or unknown "
            "auth mode) — refusing to hand a subscription conversation to it")
    return provider


def select_codex_target(source_slot, snapshot, requested=None):
    """Select/recheck a Codex target with proven headroom via the router."""
    ranked = route.candidates("codex", snapshot)
    if requested:
        match = next(((account, reason) for account, reason in ranked
                      if account.get("name") == requested), None)
        if match is None:
            raise HandoffError(f"no configured Codex account named {requested!r}")
        account, reason = match
        if account["name"] == source_slot:
            raise HandoffError("source and target slots must be different")
        if reason is not None:
            raise HandoffError(
                f"target {requested} has no proven headroom: {reason}")
        return account
    target = next((account for account, reason in ranked
                   if reason is None and account["name"] != source_slot), None)
    if target is None:
        raise HandoffError("no codex account has proven headroom")
    return target


def _codex_target_identity(snapshot, target):
    """Pin all three target identity components from the fresh snapshot:
    account fingerprint, credential digest, refresh-token lineage digest.
    Also requires the snapshot to name a ChatGPT-subscription login."""
    row = handoff._snapshot_rows(snapshot).get(target.get("name"))
    identity = row.get("identity") if isinstance(row, dict) else None
    if not isinstance(identity, dict):
        raise HandoffError("target snapshot has no bound identity — recollect")
    if identity.get("auth_mode") != "chatgpt":
        raise HandoffError(
            "target snapshot is not a ChatGPT-subscription login — refusing")
    pins = {}
    for key in ("account_fingerprint", "credential_digest", "lineage_digest"):
        value = identity.get(key)
        if not isinstance(value, str) or not value:
            raise HandoffError(
                "target snapshot has no %s binding — recollect"
                % key.replace("_", " "))
        pins[key] = value
    return pins


def _preflight_codex_destination(target, source):
    """Same relative sessions path inside the target home; no clobber."""
    home = registry.expand(target["home"])
    if not os.path.isdir(home):
        raise HandoffError(f"target home is missing or not a directory: {home}")
    probe = home
    for part in source.relative_parts[:-1]:
        candidate = os.path.join(probe, part)
        if os.path.lexists(candidate):
            if os.path.islink(candidate) or not os.path.isdir(candidate):
                raise HandoffError(
                    "target sessions directory is not a real directory")
            probe = candidate
        else:
            break
    if not os.access(probe, os.W_OK | os.X_OK):
        raise HandoffError("target directory is not writable")
    destination = os.path.join(home, *source.relative_parts)
    if os.path.lexists(destination):
        raise HandoffError(
            "target already has this rollout; --force does not overwrite "
            "destination collisions — inspect the previous partial handoff")
    return destination


def plan_codex_handoff(source, target, snapshot, cooldown_scope, cwd, *,
                       force=False, require_executable=True):
    """Build a complete, non-mutating codex handoff plan (fail-closed)."""
    if target.get("provider") != "codex":
        raise HandoffError("handoff target must be a Codex account")
    if source.account.get("provider") != "codex":
        raise HandoffError("handoff source must be a Codex account")
    handoff.guard_handoff_group(source.account, target)
    cwd = os.path.realpath(cwd)
    if not os.path.isdir(cwd):
        raise HandoffError("current resume directory no longer exists")
    guard_target_effective_binding(target, cwd)
    if require_executable and shutil.which("codex") is None:
        raise HandoffError("`codex` not found on PATH")
    canonical, parts = _contained_rollout(source.rollout_path,
                                          source.session_id, source.account)
    destination = _preflight_codex_destination(target, source)
    inspected = inspect_rollout(canonical, source.session_id,
                                allow_dangling=force)
    handoff.guard_not_duplicate(source.session_id, inspected["sha256"], force)
    return HandoffPlan(
        handoff_id=str(uuid.uuid4()),
        source=SourceSession(source.session_id, canonical,
                             dict(source.account)),
        family="codex", target=dict(target), snapshot=snapshot or {},
        cap_proof={}, cooldown_scope=dict(cooldown_scope or {}), cwd=cwd,
        inspected=inspected, destination=destination,
        source_stat=handoff._transcript_stat(canonical),
        target_identity=_codex_target_identity(snapshot, target),
        target_home_stat=handoff._target_home_stat(target),
        automatic=False, child_generation=0, force=bool(force),
        provider="codex", relative_destination="/".join(parts))


def fresh_codex_snapshot():
    """Explicit force-collect: run the collector NOW and accept the snapshot
    it returns.  ``ensure_fresh_snapshot(max_age=0)`` can never accept a real
    snapshot (integer-second ``generated`` vs float now), so the codex plan
    path collects explicitly and validates with a small positive tolerance.
    Raises (fail-closed) instead of returning None."""
    try:
        snapshot = collect.run_collect(quiet=True)
    except registry.RegistryError:
        raise
    except Exception as error:  # noqa: BLE001 — a failed collect must hold
        raise HandoffError(
            f"usage collect failed — handoff held ({error})") from error
    if not route._snapshot_fresh(snapshot, time.time(),
                                 POST_COLLECT_TOLERANCE):
        raise HandoffError(
            "collect did not produce a fresh usage snapshot — handoff held")
    return snapshot


def _current_registry_slots(plan):
    """Re-resolve BOTH slots against a freshly loaded registry (never the
    frozen plan dictionaries) — a slot removed, re-providered, re-homed, or
    re-grouped during staging must abort the handoff."""
    try:
        current = registry.accounts()
    except registry.RegistryError as error:
        raise HandoffError(
            f"cannot reload the account registry: {error}") from error
    by_name = {account["name"]: account for account in current}
    source = by_name.get(plan.source.account.get("name"))
    target = by_name.get(plan.target.get("name"))
    if source is None or target is None:
        raise HandoffError(
            "source or target slot vanished from the registry since planning")
    for slot, pinned in ((source, plan.source.account), (target, plan.target)):
        if slot.get("provider") != "codex":
            raise HandoffError(
                f"slot {slot['name']!r} is no longer a codex account")
        if registry.expand(slot["home"]) != registry.expand(pinned["home"]):
            raise HandoffError(
                f"slot {slot['name']!r} was re-pointed at a different home "
                "since planning")
    return source, target


@contextlib.contextmanager
def _quarantine_lock():
    """The SAME lock the quarantine writers use
    (``state/quarantine.json.lock``), HELD for the caller's whole block: a
    quarantine written during staging is fully flushed and seen (never a
    torn/raced read), and no NEW quarantine can land between the gate's read
    and the protected action (hard-link publication / exec) it guards."""
    lock_path = paths.quarantine_path() + ".lock"
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    with open(lock_path, "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _guard_reservation(plan, now):
    """Reservation currency: an automatic plan's own reservation must still
    be active, and no OTHER automatic handoff may hold an unexpired,
    unreleased reservation on this target."""
    rows = handoff._validated_automatic_rows(
        handoff._read_jsonl(handoff._ledger_path(), "handoff ledger"))
    if plan.automatic and handoff._active_reservation(rows, plan, now) is None:
        raise HandoffError("automatic target reservation is missing")
    released = {row.get("handoff_id") for row in rows
                if row.get("action") in ("failure", "resume_bound")}
    for row in rows:
        if (row.get("action") == "cap_confirmed"
                and row.get("target_slot") == plan.target["name"]
                and row.get("handoff_id") != plan.handoff_id
                and row.get("handoff_id") not in released):
            until = row.get("reservation_until")
            until = until if handoff._number(until) else \
                row["ts"] + handoff.TARGET_RESERVATION_SECONDS
            if until > now:
                raise HandoffError(
                    f"target {plan.target['name']} is reserved by another "
                    "automatic handoff")


def _live_target_row(target):
    """A TARGETED current capacity/identity read of just the target home via
    the codex app-server (collect.codex_live) — never the stale plan
    snapshot.  Shaped as a snapshot row so route.block_reason applies its
    full fail-closed gate to it."""
    try:
        identity, plan_type, windows = collect.codex_live(
            registry.expand(target["home"]), target.get("expected_email"))
    except collect.IdentityBindingError as error:
        raise HandoffError(
            f"live target capacity read failed ({error.code}) — handoff "
            "held") from error
    except (OSError, ValueError) as error:
        raise HandoffError(
            f"live target capacity read failed: {error}") from error
    return {
        "name": target["name"], "provider": "codex", "plan": plan_type,
        "ok": True, "stale": False, "routable": True,
        "identity_verified": True, "trust_state": "verified",
        "captured_at": time.time(), "source": "codex_app_server",
        "identity": identity, "windows": windows,
    }


def verify_codex_gate(plan):
    """The COMPLETE current target gate, against fresh state only:

    - both slots re-resolved from a freshly loaded registry;
    - handoff_group recheck on those fresh slots;
    - target effective model_provider + ChatGPT-subscription auth (P0-1);
    - account fingerprint + credential digest re-derived vs the plan pins;
    - refresh-token lineage re-derived vs the plan pin;
    - quarantine read under the quarantine writers' own lock (held by the
      caller ACROSS the protected action, not just this read);
    - reservation currency (own reservation live; no foreign reservation);
    - a TARGETED live capacity read of the target, passed through
      route.block_reason (windows, reserve, cooldowns, codex gate).

    The caller must hold the global handoff lock AND the quarantine writers'
    lock: `publish_within_gate` holds them across the hard-link publication
    (commit_handoff supplies the handoff lock there); `exec_within_gate`
    holds both across the exec itself."""
    source, target = _current_registry_slots(plan)
    handoff.guard_handoff_group(source, target)
    guard_target_effective_binding(target, plan.cwd)
    handoff.verify_target_binding(plan)
    pinned = plan.target_identity.get("lineage_digest")
    if not isinstance(pinned, str) or not pinned:
        raise HandoffError("plan has no pinned target lineage — recollect")
    current_lineage = collect.codex_lineage_digest(
        registry.expand(target["home"]))
    if current_lineage != pinned:
        raise HandoffError(
            "target refresh-token lineage changed since planning — a fresh "
            "login happened somewhere; recollect and re-plan")
    quarantine = route.quarantines()
    if quarantine is None:
        raise HandoffError(
            "quarantine ledger unreadable — inspect state/quarantine.json")
    entry = quarantine.get(target["name"])
    if entry is not None:
        detail = entry.get("reason") if isinstance(entry, dict) else None
        raise HandoffError(
            f"target {target['name']} is quarantined: "
            f"{detail or 'auth invalid'} — aborting before publication")
    now = time.time()
    _guard_reservation(plan, now)
    row = _live_target_row(target)
    live_identity = row["identity"]
    for key in ("account_fingerprint", "credential_digest", "lineage_digest"):
        if live_identity.get(key) != plan.target_identity.get(key):
            raise HandoffError(
                "target %s changed since planning — aborting"
                % key.replace("_", " "))
    if live_identity.get("auth_mode") != "chatgpt":
        raise HandoffError(
            "target is no longer a ChatGPT-subscription login — aborting")
    try:
        cool = route.preflight_cooldowns()
    except RuntimeError as error:
        raise HandoffError(str(error)) from error
    reason = route.block_reason(target, "codex", row, cool, now)
    if reason is not None:
        raise HandoffError(
            f"target {target['name']} no longer has proven headroom: {reason}")


@contextlib.contextmanager
def _protective_writer_locks():
    """Every lock headroom's own protective writers use, in one consistent
    order (registry config, then cooldowns, then quarantine — callers
    already hold the global handoff lock above all three): a registry
    mutation (re-group, re-home, re-provider via ``registry.mutate``), a
    cooldown mark (``route.mark`` on a freshly capped target), or a
    quarantine mark can no longer land between the gate's reads and the
    protected action.  External writers (a ``codex login`` rewriting the
    target home's auth.json or config.toml) have no lock protocol headroom
    could share; for those the gate's re-derivation under these locks
    immediately before the action is the strongest ordering available."""
    with registry.config_lock():
        with route._cooldown_lock():
            with _quarantine_lock():
                yield


def publish_within_gate(plan, publish):
    """P0-2 publish edge: runs INSIDE the global handoff lock, after the
    staging copy.  Takes the protective writers' locks (registry config +
    quarantine), re-runs the COMPLETE current target gate under them, then
    invokes ``publish`` (the hard-link publication) while they are STILL
    HELD — a quarantine or registry mutation landing after the gate's reads
    can no longer slip in before the link.  Any change during staging aborts
    while the copy is only an invisible temp file (rolled back by the
    caller)."""
    with _protective_writer_locks():
        verify_codex_gate(plan)
        return publish()


def exec_within_gate(plan, launch):
    """P0-2 exec edge: the same full gate under the global handoff lock AND
    the protective writers' locks, with ``launch`` (the codex exec) invoked
    while ALL are still held — nothing headroom-owned can land between the
    gate's reads and the launch.  The lock file descriptors are CLOEXEC
    (PEP 446), so a successful exec releases them exactly at the
    process-replacement boundary; a failed launch releases them on
    return/unwind."""
    with handoff._handoff_lock():
        with _protective_writer_locks():
            verify_codex_gate(plan)
            return launch()


def verify_codex_commit(plan):
    """Codex-only rechecks under the global handoff lock, immediately before
    the staging copy STARTS: the handoff_group pins still agree and the
    target's refresh-token lineage still matches the plan's pin.  This is the
    cheap early refusal; the FULL current gate (publish_within_gate)
    runs again after staging, immediately before publication."""
    handoff.guard_handoff_group(plan.source.account, plan.target)
    pinned = plan.target_identity.get("lineage_digest")
    if not isinstance(pinned, str) or not pinned:
        raise HandoffError("plan has no pinned target lineage — recollect")
    current = collect.codex_lineage_digest(registry.expand(plan.target["home"]))
    if current != pinned:
        raise HandoffError(
            "target refresh-token lineage changed since planning — a fresh "
            "login happened somewhere; recollect and re-plan")


def codex_resume_command(target_home, session_id):
    return (f"CODEX_HOME={shlex.quote(target_home)} codex resume "
            f"{shlex.quote(session_id)}")


def codex_exec_resume_command(target_home, session_id, baton=None):
    """Headless resume; ``baton`` is the continuation prompt (shown as a
    placeholder when the operator will type their own)."""
    prompt = shlex.quote(baton) if baton else '"<continuation prompt>"'
    return (f"CODEX_HOME={shlex.quote(target_home)} codex exec resume "
            f"{shlex.quote(session_id)} {prompt}")


def resume_argv(result):
    return ["codex", "resume", result.plan.source.session_id]


def exec_resume_argv(result, baton):
    if not isinstance(baton, str) or not baton.strip():
        raise HandoffError("headless codex resume requires a continuation baton")
    return ["codex", "exec", "resume", result.plan.source.session_id, baton]


def _print_baton(record, unresolved=()):
    print("BATON — codex conversation staged")
    print(f"session: {record['old_session_id']} "
          f"({record['transcript_bytes']} bytes)")
    print(f"from -> to: {record['source_slot']} -> {record['target_slot']}")
    print("does not carry: running shell processes / live MCP connections / "
          "pending approvals / ephemeral state")
    if unresolved:
        print("note: the interrupted tool call may re-run on resume")
    print("NEXT COMMAND:")
    print(record["resume_command"])
    print("headless alternative:")
    print(record["resume_headless_command"])


def _ledger_refusal(context, error):
    """P2-7: append a sanitized decision row for every refusal/failure —
    slot names, session id, stage, and the refusal message only; never
    rollout content, never credentials.  Best-effort: a ledger problem must
    never mask the original refusal."""
    try:
        handoff.append_action(
            context.get("handoff_id") or str(uuid.uuid4()), "failure",
            provider="codex", stage=context.get("stage") or "plan",
            old_session_id=context.get("session_id"),
            source_slot=context.get("source_slot"),
            target_slot=context.get("target_slot"),
            reason=str(error)[:500])
    except (HandoffError, OSError, RuntimeError):
        pass


def cmd_codex_handoff(options, accounts, cwd):
    """Manual codex adapter: confirm, commit under the shared spine, then
    optionally exec `codex resume` (or a headless `codex exec resume` with a
    baton) on the target home.  Raises HandoffError for every refusal (the
    shared cmd_handoff prints it and exits 2); every refusal is also
    ledgered, sanitized."""
    context = {"handoff_id": None, "session_id": options.get("session"),
               "source_slot": None, "target_slot": None, "stage": "plan"}
    try:
        return _cmd_codex_handoff(options, accounts, cwd, context)
    except HandoffError as error:
        _ledger_refusal(context, error)
        raise


def _cmd_codex_handoff(options, accounts, cwd, context):
    if options["session"] is None:
        raise HandoffError(
            "codex handoff requires --session UUID (cwd-based session "
            "discovery is Claude-only)")
    if options["model"]:
        family = registry.family(options["model"])
        if registry.family_provider(family) != "codex":
            raise HandoffError(
                "--model names a Claude family — codex handoffs always "
                "route the codex family")
    baton = options.get("headless")
    if baton is not None and options["print"]:
        raise HandoffError("--headless and --print are mutually exclusive")
    if baton is not None and not baton.strip():
        raise HandoffError(
            "headless codex resume requires a non-empty continuation baton")
    source = resolve_codex_source(options["session"], accounts,
                                  options.get("from"))
    context["session_id"] = source.session_id
    context["source_slot"] = source.account["name"]
    snapshot = fresh_codex_snapshot()
    target = select_codex_target(source.account["name"], snapshot,
                                 options["to"])
    context["target_slot"] = target["name"]
    handoff.guard_source_stable(source.rollout_path)
    scope = route.cap_scope(snapshot, source.account["name"], "codex",
                            "usage limit reached")
    plan = plan_codex_handoff(source, target, snapshot, scope, cwd,
                              force=options["force"])
    context["handoff_id"] = plan.handoff_id
    rows = handoff._snapshot_rows(snapshot)
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
        refreshed = fresh_codex_snapshot()
        refreshed_target = select_codex_target(
            source.account["name"], refreshed, target["name"])
        refreshed_identity = _codex_target_identity(refreshed,
                                                    refreshed_target)
        if refreshed_identity != plan.target_identity:
            raise HandoffError(
                "target identity or credential changed during confirmation")
        handoff.guard_source_stable(source.rollout_path)
        refreshed_scope = route.cap_scope(
            refreshed, source.account["name"], "codex", "usage limit reached")
        plan = plan_codex_handoff(source, refreshed_target, refreshed,
                                  refreshed_scope, cwd,
                                  force=options["force"])
        context["handoff_id"] = plan.handoff_id
        target = refreshed_target
        context["target_slot"] = target["name"]
    context["stage"] = "publish"
    result = handoff.commit_handoff(plan)
    _print_baton(result.record, plan.inspected["unresolved_tool_ids"])
    if options["print"]:
        return 0
    context["stage"] = "exec"
    environment = collect.scrubbed_env()
    environment["CODEX_HOME"] = target["home"]
    argv = exec_resume_argv(result, baton) if baton is not None \
        else resume_argv(result)

    def _launch():
        # replaces the process on success; the held handoff + quarantine
        # lock fds are CLOEXEC, so they release exactly at the exec boundary
        os.execvpe(argv[0], argv, environment)

    try:
        exec_within_gate(plan, _launch)
    except HandoffError as error:
        # published-then-failed: the copy in the target home stays (the
        # source rollout is untouched and recoverable); refuse the launch
        # and say so — the refusal is ledgered by the cmd wrapper.
        raise HandoffError(
            f"{error} — the conversation was already published to "
            f"{target['name']}; the source rollout is untouched. Resolve "
            "the target and resume manually with the printed command") \
            from error
    except OSError as error:
        print(f"headroom: cannot exec codex: {error}", file=sys.stderr)
        return 127
