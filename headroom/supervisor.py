"""Resident, fail-closed Claude auto-handoff supervisor.

One 250 ms loop owns hook ingestion and child lifecycle.  Hook evidence never
terminates a child by itself: it must be bound to the current child, match a
narrow subscription-cap phrase, and be corroborated by a fresh identity-bound
usage collect before every remaining pre-stop check succeeds.
"""
import contextlib
import fcntl
import json
import math
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import termios
import time
import uuid
from dataclasses import dataclass, field, replace

from . import collect, handoff, notify, paths, registry, route

POLL_SECONDS = 0.25
BIND_TIMEOUT = 30.0
TERM_TIMEOUT = 10.0
QUIET_SECONDS = 5.0
CAP_MODEL_TIMEOUT = QUIET_SECONDS + 1.0
LOOP_WINDOW = 10 * 60
LOOP_MAX = 3
MAX_HOOK_BYTES = 1024 * 1024

CAP_RE = re.compile(
    r"\b(?:(?:you(?:'|’)ve\s+)?hit your "
    r"(?:session|weekly|usage) limit|usage limit reached)\b", re.I)

HOOK_EVENTS = {"SessionStart", "StopFailure", "CwdChanged", "SessionEnd"}
INCOMPATIBLE_FLAGS = {
    "--bare", "--safe-mode", "--disable-all-hooks", "--print", "-p",
    "--output-format", "--input-format", "--no-session-persistence",
}
CLAUDE_VALUE_FLAGS = {
    "--model", "--settings", "--system-prompt", "--append-system-prompt",
    "--agents", "--allowedTools", "--disallowedTools", "--permission-mode",
    "--permission-prompt-tool", "--mcp-config", "--add-dir", "--ide",
    "--fallback-model", "--json-schema", "--max-budget-usd",
    "--input-format", "--output-format", "--debug-file", "--betas",
    "--plugin-dir", "--session-id", "--resume", "-r",
}
# Every other maintained Claude flag (including current flags such as --brief)
# is the boolean complement.  Unknown flags are boolean too; only this known
# value-taking list may consume the following argument.
HEADROOM_OVERRIDE_FLAGS = {
    "--headroom-auto-handoff", "--headroom-no-auto-handoff",
    "--headroom-launch-fallback"}


class SupervisorError(RuntimeError):
    """A fail-closed supervisor refusal."""


class PermanentSupervisorError(SupervisorError):
    """A child-local condition that cannot become safe on a later hook."""


class PendingCapTimeout(PermanentSupervisorError):
    """A payload-proven cap whose transcript model never became available."""


@dataclass(frozen=True)
class Binding:
    session_id: str
    transcript_path: str
    cwd: str
    model: str
    version: str
    config_dir: str
    epoch: int = 0
    received_at: float = 0.0


@dataclass(frozen=True)
class CapProof:
    event: dict
    message: str
    family: str
    session_id: str
    transcript_path: str
    epoch: int
    transcript_stat: tuple


@dataclass(frozen=True)
class PendingCap:
    event: dict
    session_id: str
    transcript_path: str
    epoch: int
    received_at: float
    deadline: float


@dataclass
class Child:
    process: subprocess.Popen
    account: dict
    generation: int
    event_path: str
    settings_path: str
    launched_at: float
    automation: bool
    binding: Binding = None
    session_ended: bool = False
    session_end_received_at: float = 0.0
    session_epoch: int = 0
    event_offset: int = 0
    hint_printed: bool = False
    resume_bound: bool = False
    dead_sessions: set = field(default_factory=set)
    session_epochs: dict = field(default_factory=dict)
    last_received_at: float = 0.0
    pending_cap: PendingCap = None
    supervision_loss_notified: bool = False


@dataclass(frozen=True)
class Relaunch:
    account: dict
    argv: list
    cwd: str
    automatic: bool
    handoff_id: str = ""
    plan: object = None


def _lose_supervision(child, reason):
    """Turn automation off for this child and (once per child) notify the
    loss. Post-spawn supervision loss is exactly what an external dispatcher
    cannot see on its own: the launch looked supervised, but auto-handoff
    will silently not fire. The notify is a no-op unless HEADROOM_NOTIFY_CMD
    is set; the stderr diagnostics at each call site are unchanged."""
    child.automation = False
    if not child.supervision_loss_notified:
        child.supervision_loss_notified = True
        notify.emit({"event": "supervision_lost",
                     "account": child.account.get("name", ""),
                     "reason": str(reason)})


def _supervisors_dir():
    return os.path.join(paths.state_dir(), "supervisors")


def event_path(supervisor_id):
    return os.path.join(_supervisors_dir(), supervisor_id + ".jsonl")


def _model_name(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("display_name", "displayName", "name", "model"):
            if isinstance(value.get(key), str):
                return value[key]
    return ""


def _hook_executable():
    override = os.environ.get("HEADROOM_EXECUTABLE")
    if override:
        return override
    installed = shutil.which("headroom")
    if installed:
        return installed
    return os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "bin", "headroom")


def _hook_command(matcher=""):
    command = shlex.quote(_hook_executable()) + " _hook-event"
    if matcher:
        command = "HEADROOM_HOOK_MATCHER=" + shlex.quote(matcher) + " " + command
    return command


def hook_settings():
    normal = {"type": "command", "command": _hook_command()}
    limited = {"type": "command", "command": _hook_command("rate_limit")}
    return {"hooks": {
        "SessionStart": [{"hooks": [normal]}],
        "StopFailure": [{"matcher": "rate_limit", "hooks": [limited]}],
        "CwdChanged": [{"hooks": [normal]}],
        "SessionEnd": [{"hooks": [normal]}],
    }}


def write_hook_event(stream=None, environ=None, now=None):
    """Hidden hook adapter: validate an envelope and append one private row."""
    stream = sys.stdin if stream is None else stream
    environ = os.environ if environ is None else environ
    try:
        raw = stream.read(MAX_HOOK_BYTES + 1)
        if len(raw.encode("utf-8")) > MAX_HOOK_BYTES:
            raise SupervisorError("hook payload too large")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise SupervisorError("hook payload must be an object")
        hook_name = payload.get("hook_event_name")
        if hook_name not in HOOK_EVENTS:
            raise SupervisorError("unknown hook event")
        supervisor_id = environ.get("HEADROOM_SUPERVISOR_ID", "")
        if not handoff._valid_uuid(supervisor_id):
            raise SupervisorError("invalid supervisor id")
        generation_raw = environ.get("HEADROOM_CHILD_GENERATION", "")
        if not generation_raw.isdigit():
            raise SupervisorError("invalid child generation")
        slot = environ.get("HEADROOM_SOURCE_SLOT", "")
        if not registry.NAME_RE.fullmatch(slot):
            raise SupervisorError("invalid source slot")
        config_dir = environ.get("CLAUDE_CONFIG_DIR", "")
        if not config_dir:
            raise SupervisorError("missing Claude config home")
        record = {
            "schema": "headroom_hook_event@1",
            "received_at": time.time() if now is None else float(now),
            "supervisor_id": supervisor_id,
            "generation": int(generation_raw),
            "source_slot": slot,
            "config_dir": registry.expand(config_dir),
            "matcher": environ.get("HEADROOM_HOOK_MATCHER", ""),
            "payload": payload,
        }
        directory = paths.ensure_private(_supervisors_dir())
        destination = os.path.join(directory, supervisor_id + ".jsonl")
        descriptor = os.open(destination,
                             os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            encoded = (json.dumps(record, separators=(",", ":"),
                                  allow_nan=False) + "\n").encode("utf-8")
            if os.write(descriptor, encoded) != len(encoded):
                raise SupervisorError("hook event append was incomplete")
            os.fsync(descriptor)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError,
            SupervisorError) as error:
        print(f"headroom: hook event refused: {error}", file=sys.stderr)
        return 2


def incompatible_args(args):
    for arg in args:
        if arg == "--":
            break
        if arg == "--settings" or arg.startswith("--settings="):
            return "user-supplied --settings"
    value_expected = False
    for arg in args:
        if value_expected:
            value_expected = False
            continue
        if arg == "--":
            break
        if arg in INCOMPATIBLE_FLAGS or any(
                arg.startswith(flag + "=")
                for flag in ("--output-format", "--input-format")):
            return arg
        if arg in CLAUDE_VALUE_FLAGS:
            value_expected = True
    return ""


def split_headroom_flags(args):
    """Remove every headroom-owned flag from Claude's option segment.

    Returns (cleaned_args, flags_found). Values of known value-taking Claude
    flags and everything after `--` pass through untouched, exactly like the
    original override stripping."""
    cleaned = []
    found = set()
    value_expected = False
    after_separator = False
    for arg in args:
        if after_separator:
            cleaned.append(arg)
            continue
        if value_expected:
            cleaned.append(arg)
            value_expected = False
            continue
        if arg == "--":
            cleaned.append(arg)
            after_separator = True
            continue
        if arg in HEADROOM_OVERRIDE_FLAGS:
            found.add(arg)
            continue
        cleaned.append(arg)
        if arg in CLAUDE_VALUE_FLAGS:
            value_expected = True
    return cleaned, found


def strip_headroom_overrides(args):
    """Remove only real headroom options from Claude's option segment."""
    cleaned, found = split_headroom_flags(args)
    return (cleaned, "--headroom-auto-handoff" in found,
            "--headroom-no-auto-handoff" in found)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _event_text(event):
    if not isinstance(event, dict):
        return ""
    message = event.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return content
    texts = []
    for item in content if isinstance(content, list) else []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            texts.append(item["text"])
    if texts:
        return "\n".join(texts)
    return "\n".join(_strings(event.get("text")))


SYNTHETIC_MODEL = "<synthetic>"


def _real_assistant_model(event):
    if (not isinstance(event, dict) or event.get("type") != "assistant"
            or event.get("isSidechain") is True):
        return ""
    message = event.get("message")
    if isinstance(message, dict) and message.get("isSidechain") is True:
        return ""
    model = message.get("model") if isinstance(message, dict) else None
    if not isinstance(model, str) or not model.strip() \
            or model.strip() == SYNTHETIC_MODEL:
        return ""
    return model.strip()


def _active_model(lines, cap_event):
    """The model the session was actually running at cap time.

    The API-error event itself carries model "<synthetic>" (observed live), so
    the authoritative source is the LAST preceding assistant event with a real
    model id — that reflects in-session /model switches, unlike SessionStart.
    """
    for raw in reversed(lines[:-1]):
        try:
            event = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError, json.JSONDecodeError):
            continue
        model = _real_assistant_model(event)
        if model:
            return model
    return ""


def _last_transcript_cap_evidence(path):
    """Locate the cap as the transcript's LATEST assistant activity.

    Observed live: Claude appends trailing non-assistant records (system
    turn_duration, last-prompt, file-history-snapshot, user, attachment)
    after the API-error event, so the cap is rarely the final line.  Scanning
    backward, the first assistant event must BE the cap — a successful
    assistant turn after it means the session is not capped (fail closed).
    """
    try:
        with open(path, "rb") as handle:
            lines = [line for line in handle.read().splitlines() if line.strip()]
        event = None
        cap_index = len(lines)
        for index in range(len(lines) - 1, -1, -1):
            candidate = json.loads(lines[index].decode("utf-8"))
            if not isinstance(candidate, dict) \
                    or candidate.get("type") != "assistant" \
                    or candidate.get("isSidechain") is True:
                continue
            message = candidate.get("message")
            if isinstance(message, dict) and message.get("isSidechain") is True:
                continue
            event, cap_index = candidate, index
            break
        lines = lines[:cap_index + 1]
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(event, dict) or event.get("type") != "assistant":
        return None
    is_api = event.get("isApiErrorMessage") is True
    if not is_api and isinstance(event.get("message"), dict):
        is_api = event["message"].get("isApiErrorMessage") is True
    text = _event_text(event)
    model = _active_model(lines, event)
    top_model = event.get("model")
    if (not is_api or not CAP_RE.search(text) or not model
            or (isinstance(top_model, str) and top_model.strip()
                and top_model.strip() not in (model, SYNTHETIC_MODEL))):
        return None
    try:
        signature = handoff._transcript_stat(path)
    except handoff.HandoffError:
        return None
    return {"message": text, "model": model, "stat": signature}


def _last_transcript_cap(path):
    evidence = _last_transcript_cap_evidence(path)
    return evidence["message"] if evidence else ""


def _namespace_matches(record, child):
    if not isinstance(record, dict):
        return False
    expected_id = os.path.splitext(os.path.basename(child.event_path))[0]
    return (record.get("supervisor_id") == expected_id
            and record.get("generation") == child.generation)


def _record_matches(record, child, binding=None):
    if not _namespace_matches(record, child):
        return False
    if record.get("source_slot") != child.account.get("name") \
            or not isinstance(record.get("config_dir"), str) \
            or registry.expand(record["config_dir"]) \
            != registry.expand(child.account["home"]):
        return False
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return False
    if binding is not None:
        if payload.get("session_id") != binding.session_id:
            return False
        transcript = payload.get("transcript_path")
        if transcript is not None and os.path.realpath(transcript) \
                != binding.transcript_path:
            return False
    return True


def _validated_event(record, child, binding=None):
    if not _namespace_matches(record, child):
        raise SupervisorError("hook event does not match this child")
    if record.get("source_slot") != child.account.get("name"):
        raise PermanentSupervisorError("hook event source slot is malformed")
    config_dir = record.get("config_dir")
    if not isinstance(config_dir, str) or not config_dir \
            or registry.expand(config_dir) \
            != registry.expand(child.account["home"]):
        raise PermanentSupervisorError("hook event config home is malformed")
    received = record.get("received_at")
    if (not isinstance(received, (int, float)) or isinstance(received, bool)
            or not math.isfinite(received) or received < child.launched_at
            or received > time.time() + route.CLOCK_SKEW):
        raise PermanentSupervisorError("hook event timestamp is not post-launch")
    payload = record.get("payload")
    if not isinstance(payload, dict):
        raise PermanentSupervisorError("hook event payload is malformed")
    session_id = payload.get("session_id")
    transcript = payload.get("transcript_path")
    cwd = payload.get("cwd")
    if not isinstance(session_id, str) or not handoff._valid_uuid(session_id):
        raise PermanentSupervisorError("hook event session id is malformed")
    if not isinstance(transcript, str) or not transcript \
            or os.path.abspath(os.path.expanduser(transcript)) != transcript:
        raise PermanentSupervisorError("hook event transcript path is not canonical")
    try:
        source = handoff._source(transcript, session_id, [child.account],
                                 config_dir=config_dir)
    except handoff.HandoffError as error:
        raise PermanentSupervisorError(str(error)) from error
    if source.transcript_path != transcript:
        raise PermanentSupervisorError("hook event transcript path is not canonical")
    if not isinstance(cwd, str) or not cwd \
            or not os.path.isdir(os.path.realpath(cwd)):
        raise PermanentSupervisorError("hook event cwd is missing or unreadable")
    if binding is not None and (session_id != binding.session_id
                                or transcript != binding.transcript_path):
        raise SupervisorError("hook event belongs to a different session epoch")
    return source, os.path.realpath(cwd)


def parse_session_start(record, child):
    source, cwd = _validated_event(record, child)
    payload = record["payload"]
    if payload.get("hook_event_name") != "SessionStart":
        raise SupervisorError("not a SessionStart event")
    return Binding(
        source.session_id, source.transcript_path, cwd,
        _model_name(payload.get("model")),
        payload.get("version", "") if isinstance(payload.get("version"), str)
        else "", record["config_dir"], child.session_epoch + 1,
        record["received_at"])


def cap_message(record, child):
    """Return the narrow cap message, or empty when any binding proof fails."""
    binding = child.binding
    if binding is None:
        return ""
    try:
        _validated_event(record, child, binding)
    except SupervisorError:
        return ""
    payload = record["payload"]
    if payload.get("hook_event_name") != "StopFailure":
        return ""
    if record.get("matcher") != "rate_limit":
        return ""
    error_type = payload.get("error") or payload.get("error_type")
    if error_type is not None and error_type != "rate_limit":
        return ""
    direct = payload.get("last_assistant_message")
    if direct is None:
        direct = payload.get("error_details")
    if direct is not None:
        text = "\n".join(_strings(direct))
        return text if CAP_RE.search(text) else ""
    return _last_transcript_cap(binding.transcript_path)


def _read_events(child):
    if not os.path.exists(child.event_path):
        return []
    try:
        with open(child.event_path, "rb") as handle:
            fcntl.flock(handle, fcntl.LOCK_SH)
            handle.seek(child.event_offset)
            data = handle.read()
            fcntl.flock(handle, fcntl.LOCK_UN)
        if not data:
            return []
        if not data.endswith(b"\n"):
            raise SupervisorError("hook event file has an incomplete record")
        events = []
        for line in data.splitlines():
            record = json.loads(line.decode("utf-8"))
            received = record.get("received_at") if isinstance(record, dict) else None
            payload = record.get("payload") if isinstance(record, dict) else None
            if (not isinstance(record, dict)
                    or record.get("schema") != "headroom_hook_event@1"
                    or not handoff._valid_uuid(record.get("supervisor_id"))
                    or not isinstance(record.get("generation"), int)
                    or isinstance(record.get("generation"), bool)
                    or not isinstance(record.get("source_slot"), str)
                    or not isinstance(record.get("config_dir"), str)
                    or not isinstance(record.get("matcher"), str)
                    or not isinstance(received, (int, float))
                    or isinstance(received, bool) or not math.isfinite(received)
                    or not isinstance(payload, dict)
                    or payload.get("hook_event_name") not in HOOK_EVENTS):
                raise ValueError
            events.append(record)
        child.event_offset += len(data)
        events.sort(key=lambda record: record["received_at"])
        return events
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise SupervisorError("hook event file is unreadable") from error


def _binding_key(binding):
    return (binding.session_id, binding.epoch) if binding is not None else None


def _remember_binding(child):
    binding = child.binding
    if binding is None:
        return
    child.session_epochs.setdefault(
        (binding.session_id, binding.transcript_path), binding.epoch)
    child.last_received_at = max(child.last_received_at, binding.received_at)


def _event_epoch(child, source):
    binding = child.binding
    if (binding is not None and source.session_id == binding.session_id
            and source.transcript_path == binding.transcript_path):
        return binding.epoch
    return child.session_epochs.get(
        (source.session_id, source.transcript_path))


def _accept_event_order(child, record):
    received = record["received_at"]
    if received <= child.last_received_at:
        raise PermanentSupervisorError(
            "hook event order is ambiguous for the current binding")
    child.last_received_at = received


@contextlib.contextmanager
def _event_stop_guard(child):
    """Prevent a session-transition hook from landing between check and TERM."""
    try:
        handle = open(child.event_path, "rb")
    except OSError as error:
        raise SupervisorError("cannot lock hook event journal before stop") \
            from error
    try:
        fcntl.flock(handle, fcntl.LOCK_SH)
        if os.fstat(handle.fileno()).st_size != child.event_offset:
            raise SupervisorError("cap proof expired after a newer hook event")
        yield
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


def _source_row_is_bound(account, family, snapshot, collect_started):
    if not isinstance(snapshot, dict):
        return "collect returned no snapshot"
    started = snapshot.get("run_started")
    generated = snapshot.get("generated")
    floor = int(collect_started)
    if not isinstance(started, (int, float)) or isinstance(started, bool) \
            or started < floor:
        return "collect did not start after the cap event"
    if not isinstance(generated, (int, float)) or isinstance(generated, bool) \
            or generated < floor:
        return "collect did not finish after the cap event"
    row = next((item for item in snapshot.get("accounts", [])
                if isinstance(item, dict) and item.get("name") == account["name"]),
               None)
    reason = route.block_reason(account, family, row, {}, time.time(), reserve=0)
    capacity_reasons = {"5h at 100%", "7d at 100%",
                        f"{family} weekly cap at 100%",
                        "5h critical", "7d critical"}
    if reason is not None and reason not in capacity_reasons:
        return reason
    captured = row.get("captured_at") if isinstance(row, dict) else None
    if not isinstance(captured, (int, float)) or isinstance(captured, bool) \
            or captured < floor:
        return "source observation predates the cap event"
    return ""


class _SignalGuard:
    def __init__(self, process=None):
        self.original = {}
        self.shutdown_signal = None
        self.forwarded = False
        # the child to forward a shutdown signal to; forwarding happens the
        # INSTANT the signal is latched (in _shutdown), not on a later poll,
        # so no notifier-bearing work can run between latch and forward (P1, r6)
        self._process = process

    def _forward(self, signum):
        # os.kill + int attribute reads only — async-signal-safe, so this is
        # correct to call directly from the signal handler
        if self.forwarded or self._process is None:
            return
        self.forwarded = True
        try:
            os.kill(self._process.pid, signum)
        except (ProcessLookupError, OSError):
            pass

    def _shutdown(self, signum, _frame):
        if self.shutdown_signal is None:
            self.shutdown_signal = signum
            self._forward(signum)  # forward immediately, before returning

    def attach(self, process):
        """Bind the live child to this already-installed guard (P1, r7).

        Called the instant Popen returns a child, BEFORE any post-spawn work.
        Idempotent. Set _process FIRST so a signal delivered during attach is
        forwarded by the handler; then forward any signal that was already
        latched while there was no child (e.g. during the Popen fork window)."""
        if self._process is not None:
            return
        self._process = process
        if self.shutdown_signal is not None and not self.forwarded:
            self._forward(self.shutdown_signal)

    def install(self):
        for signum in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
            self.original[signum] = signal.getsignal(signum)
        signal.signal(signal.SIGINT, lambda _s, _f: None)
        signal.signal(signal.SIGHUP, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def poll(self, process):
        # backstop only: forwarding is normally done in _shutdown. If a signal
        # was latched without a process handle, forward it here once.
        if self.shutdown_signal is None or process.poll() is not None:
            return
        if not self.forwarded:
            self.forwarded = True
            try:
                os.kill(process.pid, self.shutdown_signal)
            except (ProcessLookupError, OSError):
                pass

    def restore(self):
        for signum, handler in self.original.items():
            try:
                signal.signal(signum, handler)
            except OSError:
                # CPython raises "signal ignored due to race condition" if a
                # signal is delivered during this handler swap. Restoring the
                # remaining signals must still proceed, and _spawn samples our
                # latch AFTER restore() returns — so this best-effort restore
                # can never skip the requested-kill replay (r9/r10).
                pass


class Supervisor:
    def __init__(self, family, args, account, *, collect_fn=None,
                 popen=None, now=None, sleep=None, supervisor_id=None):
        self.family = family
        self.initial_args = list(args)
        self.account = account
        self.collect_fn = collect.run_collect if collect_fn is None else collect_fn
        self.popen = subprocess.Popen if popen is None else popen
        self.now = time.time if now is None else now
        self.sleep = time.sleep if sleep is None else sleep
        self.supervisor_id = supervisor_id or str(uuid.uuid4())
        self.generation = 0
        self.settings_files = []
        # True once ANY child CLI process has been successfully spawned —
        # the hard boundary for the opt-in launch fallback (see cmd_claude):
        # a failure after this point is normal supervision/exit, never a
        # "no CLI was ever started" condition
        self.spawned_any = False
        # True only inside the Popen window (P0-3): while set, the spawn
        # outcome is unknown and the launch fallback must be suppressed
        self.spawn_ambiguous = False
        # the account whose most recent spawn was left ambiguous — its lease
        # must NOT be released on unwind, since a live child may hold it (P0-1)
        self._ambiguous_account = None
        # the signal guard for the CURRENT spawn cycle: installed by _spawn
        # BEFORE the spawn window and reused by _monitor, so no instant after a
        # child exists is ever unguarded (P1, r7)
        self._signals = None

    def _settings_file(self, generation):
        directory = paths.ensure_private(_supervisors_dir())
        filename = f"{self.supervisor_id}-{generation}.settings.json"
        destination = os.path.join(directory, filename)
        paths.write_json_atomic(destination, hook_settings(), mode=0o600)
        self.settings_files.append(destination)
        return destination

    def _cleanup_files(self):
        for destination in self.settings_files + [event_path(self.supervisor_id)]:
            try:
                os.unlink(destination)
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _environment(self, account, generation, automatic):
        environment = collect.scrubbed_env()
        environment["CLAUDE_CONFIG_DIR"] = account["home"]
        if automatic:
            environment.update({
                "HEADROOM_SUPERVISOR_ID": self.supervisor_id,
                "HEADROOM_CHILD_GENERATION": str(generation),
                "HEADROOM_SOURCE_SLOT": account["name"],
            })
        else:
            for key in ("HEADROOM_SUPERVISOR_ID", "HEADROOM_CHILD_GENERATION",
                        "HEADROOM_SOURCE_SLOT", "HEADROOM_HOOK_MATCHER"):
                environment.pop(key, None)
        return environment

    def _spawn(self, account, args, cwd, automatic, plan=None):
        self.generation += 1
        settings = self._settings_file(self.generation) if automatic else ""
        argv = ["claude"]
        if settings:
            argv.extend(["--settings", settings])
        argv.extend(args)
        environment = self._environment(account, self.generation, automatic)
        launched_at = self.now()
        # Install the signal guard BEFORE the spawn window and reuse it in
        # _monitor, so no instant after a child could exist is ever unguarded
        # (P1, r7). A signal before any child attaches just latches with
        # nothing to forward; if a child then attaches it is forwarded then,
        # and if the spawn fails the guard is restored below with no orphan.
        guard = _SignalGuard()
        guard.install()
        self._signals = guard
        try:
            # ---- PRE-SPAWN validation (OUTSIDE the ambiguous window) ----
            # Everything that can POSITIVELY prove "no child will exist" is
            # checked here, synchronously, BEFORE spawn_ambiguous is set. A
            # failure here is an unambiguous pre-spawn failure: no fork has
            # happened, so run() may safely recover / the caller may fall back.
            try:
                if plan is not None:
                    handoff.verify_target_binding(plan)
            except handoff.HandoffError as error:
                raise SupervisorError(str(error)) from error
            # resolve the executable up-front so a missing binary is a POSITIVE
            # pre-spawn failure (preserving the missing-binary fallback nicety)
            # instead of being inferred from catching Popen's OSError inside the
            # window. (r5)
            if shutil.which(argv[0]) is None:
                raise SupervisorError(
                    f"`{argv[0]}` not found on PATH; nothing was started")
            # the wrapper handshake means "launch committed": it must be the
            # LAST fallible pre-spawn operation, AFTER every other pre-spawn
            # check (settings/argv/env, verify_target_binding, which) — so an
            # external marker-based wrapper sees a marker only when the spawn is
            # truly imminent (P2-a, r6). A marker with no child would suppress
            # the wrapper's bare-CLI fallback.
            if self.generation == 1:
                if not route.write_launch_marker("supervised", account):
                    raise SupervisorError(
                        "launch marker could not be written; nothing was "
                        "started")
            # hand the account's lease fd to the child so the flock rides on
            # the child (survives an ambiguous spawn / a supervisor exit);
            # no-op unless HEADROOM_SLOT_LEASE=1 (then held_lease_fd is None and
            # no pass_fds kwarg is added, so legacy-off Popen calls are
            # byte-identical) (P0-1)
            popen_kwargs = {}
            lease_fd = route.held_lease_fd(account.get("name"))
            if lease_fd is not None:
                popen_kwargs["pass_fds"] = (lease_fd,)
            # ---- the ambiguous window: ONLY the Popen call (r5) ----
            # Conservative by type-INDEPENDENCE: set spawn_ambiguous=True right
            # before Popen and, on ANY exception escaping Popen (OSError,
            # KeyboardInterrupt, a trace/profile hook raising, anything), LEAVE
            # it True — a child MAY be live, so the run() gate must suppress
            # fallback and source recovery and retain the lease. We do NOT
            # classify the exception; nothing inside this window ever clears the
            # flag. No signal masking, no preexec_fn — trace hooks and signals
            # are both moot.
            #
            # Accepted tiny trade: if the binary vanishes in the microsecond
            # between which() and Popen (TOCTOU), the launch exits 127 without
            # falling back. That is SAFE (never a double-brain), just a missed
            # fallback in an astronomically rare case — safety beats the nicety.
            self.spawn_ambiguous = True
            process = self.popen(argv, env=environment, cwd=cwd,
                                 **popen_kwargs)
        except BaseException:
            # No child was attached to this guard (a pre-spawn failure, or an
            # ambiguous Popen exception whose possible orphan we have no handle
            # for — the accepted r5 trade). Restore the handlers so run()'s
            # recovery / fallback / stop runs with normal signal disposition.
            guard.restore()
            # Sample the latch AFTER restore(): the guard's handler stays
            # installed until restore() reinstalls the originals, so a SIGTERM
            # arriving DURING restore still latches into the guard — reading
            # shutdown_signal before restore() would miss it (P1, r9). Once
            # restored, a further signal reaches the original disposition, not
            # the guard, so this read captures exactly what the guard latched.
            latched = guard.shutdown_signal
            self._signals = None
            # If a shutdown was requested DURING the pre-spawn window (which()
            # / marker write) and that op then failed, honour the kill with the
            # now-restored disposition instead of propagating into fallback /
            # source recovery — a requested kill must never result in a NEW
            # launch. Replay it before re-raising (P1, r8).
            if latched is not None:
                signal.raise_signal(latched)
            raise
        # Popen succeeded: a child IS live. ATTACH it to the already-installed
        # guard IMMEDIATELY, before ANY post-spawn work (the notify below, the
        # Child construction) — so from this instant a delivered signal is
        # forwarded to the child, closing the r6 attach gap (P1, r7).
        guard.attach(process)
        # Do NOT clear spawn_ambiguous or set spawned_any here — leave the
        # window OPEN across the ENTIRE successful return. run() closes it only
        # once it has safely received this Child and taken ownership, so any
        # failure between Popen-success and run()-holds-Child (e.g. Child
        # construction) keeps spawn_ambiguous True → the run() gate suppresses
        # source recovery and retains the lease. (P0-1)
        # launch notify only AFTER a real child exists, so a lost `fallback`
        # event can never leave a dispatcher believing "supervised and started"
        # when nothing did (P1-5)
        if self.generation == 1:
            notify.emit({"event": "launch", "mode": "supervised",
                         "account": account.get("name", ""),
                         "model": self.family, "note": ""})
        return Child(process, account, self.generation,
                     event_path(self.supervisor_id), settings, launched_at,
                     automatic)

    def _fresh_collect(self, event_time):
        # Provider snapshots use whole-second timestamps.  Crossing the next
        # second before starting removes the historical same-second ambiguity.
        boundary = math.floor(event_time) + 1
        while self.now() < boundary:
            self.sleep(min(POLL_SECONDS, boundary - self.now()))
        started = self.now()
        try:
            snapshot = self.collect_fn(quiet=True)
        except TypeError:
            snapshot = self.collect_fn()
        except Exception as error:  # noqa: BLE001 — a failed proof never stops
            raise SupervisorError(f"fresh usage collect failed: {error}") from error
        return snapshot, started

    def _prove_cap(self, child, record):
        message = cap_message(record, child)
        if not message:
            child.pending_cap = None
            return None
        binding = child.binding
        received_at = record["received_at"]
        pending = child.pending_cap
        if pending is None or (
                pending.session_id != binding.session_id
                or pending.transcript_path != binding.transcript_path
                or pending.epoch != binding.epoch
                or pending.received_at != received_at):
            pending = PendingCap(
                record, binding.session_id, binding.transcript_path,
                binding.epoch, received_at, received_at + CAP_MODEL_TIMEOUT)
            child.pending_cap = pending
        try:
            self._proof_current(child, pending)
        except SupervisorError:
            child.pending_cap = None
            raise
        try:
            evidence = _last_transcript_cap_evidence(
                binding.transcript_path)
            if evidence is None:
                if self.now() >= pending.deadline:
                    child.pending_cap = None
                    raise PendingCapTimeout(
                        "could not determine the cap-time model before "
                        f"{CAP_MODEL_TIMEOUT:g}s")
                return pending
            source = handoff.SourceSession(
                binding.session_id, binding.transcript_path,
                child.account, evidence["model"])
            family = handoff.resolve_model_family(source)
            proof = CapProof(record, evidence["message"], family,
                             binding.session_id, binding.transcript_path,
                             binding.epoch, evidence["stat"])
            child.pending_cap = None
            return proof
        except PermanentSupervisorError:
            raise
        except (handoff.HandoffError, registry.RegistryError) as error:
            raise PermanentSupervisorError(str(error)) from error

    def _attempt_cap(self, child, record, announce_non_cap=False):
        try:
            candidate = self._prove_cap(child, record)
            if isinstance(candidate, CapProof):
                return candidate
            if candidate is None and announce_non_cap:
                print("[headroom] rate-limit hook was not a subscription cap; "
                      "child continues", file=sys.stderr)
        except PendingCapTimeout as error:
            _lose_supervision(child, f"cap-time model unavailable: {error}")
            print(f"[headroom] {error}; automatic handoff disabled — /exit then "
                  "`headroom handoff` to move manually", file=sys.stderr)
        except PermanentSupervisorError as error:
            _lose_supervision(child, f"cap not corroborated: {error}")
            child.pending_cap = None
            print(f"[headroom] cap not corroborated ({error}); automatic "
                  "handoff disabled for this child", file=sys.stderr)
        except SupervisorError as error:
            print(f"[headroom] cap not corroborated ({error}); child continues",
                  file=sys.stderr)
        return None

    @staticmethod
    def _proof_current(child, proof):
        binding = child.binding
        if (binding is None or binding.session_id != proof.session_id
                or binding.transcript_path != proof.transcript_path
                or binding.epoch != proof.epoch
                or child.session_epoch != proof.epoch
                or (proof.session_id, proof.epoch) in child.dead_sessions):
            raise SupervisorError("cap proof expired after a session transition")

    @staticmethod
    def _events_pending(child):
        try:
            size = os.path.getsize(child.event_path)
        except FileNotFoundError:
            size = 0
        except OSError as error:
            raise SupervisorError("cannot recheck hook event journal") from error
        if size != child.event_offset:
            raise SupervisorError("cap proof expired after a newer hook event")

    def _preflight(self, child, proof):
        self._proof_current(child, proof)
        try:
            handoff.guard_source_stable(
                proof.transcript_path, now=self.now(),
                sleep=lambda _seconds: None, quiet_seconds=QUIET_SECONDS)
        except handoff.HandoffError as error:
            if "changed recently" in str(error):
                raise
            raise SupervisorError(str(error)) from error
        try:
            quiet_stat = handoff._transcript_stat(proof.transcript_path)
            if quiet_stat != proof.transcript_stat:
                raise SupervisorError(
                    "cap proof expired after the transcript changed")
            snapshot, started = self._fresh_collect(
                proof.event["received_at"])
            self._proof_current(child, proof)
            self._events_pending(child)
            if handoff._transcript_stat(proof.transcript_path) != quiet_stat:
                raise SupervisorError("source transcript changed during collect")
            reason = _source_row_is_bound(
                child.account, proof.family, snapshot, started)
            if reason:
                raise SupervisorError(reason)
            scope = route.cap_scope(snapshot, child.account["name"],
                                    proof.family, proof.message)
            if scope is None:
                raise SupervisorError(
                    "fresh usage is below 99% or the cap scope is ambiguous")
            reset = scope.get("reset")
            if (not isinstance(reset, (int, float)) or isinstance(reset, bool)
                    or not math.isfinite(reset) or reset <= self.now()):
                raise SupervisorError("fresh cap reset is missing or ambiguous")
            target = handoff.select_target(
                child.account["name"], snapshot, proof.family)
            binding = child.binding
            source = handoff.SourceSession(
                proof.session_id, proof.transcript_path, child.account,
                proof.family, int(self.now()))
            cap_proof = {
                "authenticated": True,
                "event_received_at": proof.event["received_at"],
                "session_id": proof.session_id, "epoch": proof.epoch,
            }
            plan = handoff.plan_handoff(
                source, proof.family, target, snapshot, cap_proof,
                binding.cwd, cooldown_scope=scope, automatic=True,
                child_generation=child.generation)
            route.preflight_cooldowns()
            handoff.select_target(
                child.account["name"], snapshot, proof.family,
                requested=target["name"])
            self._proof_current(child, proof)
            self._events_pending(child)
            if handoff._transcript_stat(proof.transcript_path) \
                    != plan.source_stat:
                raise SupervisorError("source transcript changed before admission")
            if reset <= self.now():
                raise SupervisorError("cap reset elapsed before admission")
            handoff.reserve_automatic(
                plan, self.now(), loop_window=LOOP_WINDOW, loop_max=LOOP_MAX)
            self._proof_current(child, proof)
            self._events_pending(child)
            if reset <= self.now():
                raise SupervisorError("cap reset elapsed before stop")
            return plan
        except SupervisorError:
            raise
        except (handoff.HandoffError, registry.RegistryError, RuntimeError,
                OSError, ValueError) as error:
            raise SupervisorError(str(error)) from error

    @staticmethod
    def _save_terminal():
        try:
            if sys.stdin.isatty():
                return termios.tcgetattr(sys.stdin.fileno())
        except (OSError, termios.error):
            pass
        return None

    @staticmethod
    def _restore_terminal(saved):
        if saved is None:
            return
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, saved)
        except (OSError, termios.error):
            pass

    def _wait_stopped(self, child, proof, stop_sent_at):
        deadline = self.now() + TERM_TIMEOUT
        while child.process.poll() is None and self.now() < deadline:
            self._consume_stop_events(child, proof, stop_sent_at)
            self.sleep(POLL_SECONDS)
        returncode = child.process.poll()
        self._consume_stop_events(child, proof, stop_sent_at)
        return returncode

    def _consume_stop_events(self, child, proof, stop_sent_at):
        _remember_binding(child)
        for record in _read_events(child):
            if not _namespace_matches(record, child):
                continue
            source, cwd = _validated_event(record, child)
            payload = record["payload"]
            hook_name = payload.get("hook_event_name")
            epoch = _event_epoch(child, source)
            session_key = ((source.session_id, epoch)
                           if epoch is not None else None)
            if hook_name == "StopFailure" \
                    and session_key in child.dead_sessions:
                continue
            _accept_event_order(child, record)
            if session_key in child.dead_sessions:
                if hook_name in ("SessionEnd", "StopFailure"):
                    continue
                raise SupervisorError(
                    "cap proof expired after its session ended")
            if hook_name == "CwdChanged" \
                    and source.session_id == proof.session_id \
                    and source.transcript_path == proof.transcript_path:
                binding = child.binding
                child.binding = replace(binding, cwd=cwd)
                continue
            if hook_name != "SessionEnd":
                raise SupervisorError(
                    "cap proof expired during the stop transition")
            if (record["received_at"] < stop_sent_at
                    or source.session_id != proof.session_id
                    or source.transcript_path != proof.transcript_path
                    or epoch != proof.epoch):
                raise SupervisorError(
                    "SessionEnd does not prove the stopped session epoch")
            self._proof_current(child, proof)
            child.dead_sessions.add(session_key)
            child.session_ended = True
            child.session_end_received_at = record["received_at"]

    def _post_stop_plan(self, plan):
        deadline = self.now() + QUIET_SECONDS + 1.0
        while True:
            signature = handoff._transcript_stat(plan.source.transcript_path)
            age = self.now() - (signature[3] / 1_000_000_000)
            if age >= QUIET_SECONDS:
                break
            if self.now() >= deadline:
                raise SupervisorError("final transcript did not become quiet")
            self.sleep(min(POLL_SECONDS, max(0.0, QUIET_SECONDS - age)))
        inspected = handoff.inspect_transcript(
            plan.source.transcript_path, allow_dangling=True)
        final_stat = handoff._transcript_stat(plan.source.transcript_path)
        if final_stat[:2] != plan.source_stat[:2] or final_stat != signature:
            raise SupervisorError("final transcript identity or stat changed")
        return replace(plan, inspected=inspected, source_stat=final_stat)

    def _failure(self, plan, reason):
        try:
            handoff.append_action(
                plan.handoff_id, "failure", automatic=True,
                source_slot=plan.source.account["name"],
                target_slot=plan.target["name"], reason=reason,
                old_session_id=plan.source.session_id,
                child_generation=plan.child_generation)
        except Exception:  # recovery must proceed even if the ledger is broken
            pass

    def _lease_target(self, plan):
        """Acquire the TARGET account's flock BEFORE stopping the source, so a
        concurrent launch can't double-book the account we're moving to. The
        source lease is deliberately kept until the target child spawns (run()
        reconciliation drops it), and on any failure here the handoff is held
        with the source still running AND still leased. No-op unless
        HEADROOM_SLOT_LEASE=1. (P0-2)"""
        try:
            if not route.acquire_slot_lease(plan.target, plan.family):
                raise SupervisorError(
                    "target slot is leased by another live launch")
        except route.LeaseError as error:
            raise SupervisorError(
                f"target slot lease unavailable: {error}") from error

    def _reconcile_leases(self, active_name):
        """Hold exactly the ACTIVE child's lease: release every other lease
        this supervisor took (the old source after a rotation, or a target we
        acquired for a handoff that then failed). No-op unless leasing is on."""
        for name in route.held_lease_names():
            if name != active_name:
                route.release_slot_lease(name)

    @staticmethod
    def _source_relaunch(plan):
        return Relaunch(plan.source.account,
                        ["--resume", plan.source.session_id], plan.cwd, False)

    @staticmethod
    def _print_manual_recovery(plan):
        print("headroom: automatic recovery could not start Claude; run one of:",
              file=sys.stderr)
        print(handoff.resume_command(
            plan.target["home"], plan.source.session_id), file=sys.stderr)
        source_argv = shlex.join(
            ["claude", "--resume", plan.source.session_id])
        print(f"CLAUDE_CONFIG_DIR={shlex.quote(plan.source.account['home'])} "
              f"{source_argv}", file=sys.stderr)

    def _stop_and_commit(self, child, plan, proof):
        self._proof_current(child, proof)
        self._events_pending(child)
        try:
            source_stat = handoff._transcript_stat(proof.transcript_path)
        except (handoff.HandoffError, OSError, RuntimeError) as error:
            raise SupervisorError(str(error)) from error
        if source_stat != plan.source_stat:
            raise SupervisorError("source transcript changed before stop")
        reset = plan.cooldown_scope.get("reset")
        if (not isinstance(reset, (int, float)) or isinstance(reset, bool)
                or not math.isfinite(reset) or reset <= self.now()):
            raise SupervisorError("cap reset elapsed before stop")
        try:
            handoff.verify_automatic_reservation(plan)
        except (handoff.HandoffError, registry.RegistryError, RuntimeError,
                OSError, ValueError) as error:
            raise SupervisorError(str(error)) from error
        self._proof_current(child, proof)
        self._events_pending(child)
        if handoff._transcript_stat(proof.transcript_path) != plan.source_stat:
            raise SupervisorError("source transcript changed before stop")
        if reset <= self.now():
            raise SupervisorError("cap reset elapsed before stop")
        print(f"[headroom] cap confirmed; {plan.source.account['name']} -> "
              f"{plan.target['name']}", file=sys.stderr)
        # take the target lease before we stop the source (P0-2); on failure
        # this raises SupervisorError and the caller keeps the source running
        # and leased
        self._lease_target(plan)
        saved = self._save_terminal()
        stop_error = None
        stop_sent_at = 0.0
        signal_sent = False
        child.session_ended = False
        child.session_end_received_at = 0.0
        try:
            with _event_stop_guard(child):
                self._proof_current(child, proof)
                if handoff._transcript_stat(proof.transcript_path) \
                        != plan.source_stat:
                    raise SupervisorError(
                        "source transcript changed before stop")
                if reset <= self.now():
                    raise SupervisorError("cap reset elapsed before stop")
                stop_sent_at = self.now()
                handoff.append_action(
                    plan.handoff_id, "stop_sent", automatic=True,
                    source_slot=plan.source.account["name"],
                    old_session_id=plan.source.session_id,
                    child_generation=plan.child_generation)
                os.kill(child.process.pid, signal.SIGTERM)
                signal_sent = True
            returncode = self._wait_stopped(child, proof, stop_sent_at)
        except Exception as error:  # post-signal failures recover if Claude exited
            if not signal_sent:
                raise SupervisorError(str(error)) from error
            stop_error = error
            returncode = child.process.poll()
        finally:
            self._restore_terminal(saved)
        if returncode is None:
            reason = "sigterm_timeout" if stop_error is None else str(stop_error)
            self._failure(plan, "stop_failed: " + reason)
            print("[headroom] Claude did not exit after one SIGTERM; automatic "
                  "handoff disabled for this child", file=sys.stderr)
            _lose_supervision(child, "Claude did not exit after one SIGTERM")
            return None
        try:
            if stop_error is not None:
                raise stop_error
            handoff.append_action(
                plan.handoff_id, "stopped", automatic=True,
                source_slot=plan.source.account["name"],
                old_session_id=plan.source.session_id,
                child_generation=plan.child_generation,
                child_exit_code=returncode,
                session_end=child.session_ended,
                session_end_received_at=child.session_end_received_at)
            if not child.session_ended \
                    or child.session_end_received_at < stop_sent_at:
                raise SupervisorError("SessionEnd proof is missing")
            plan = self._post_stop_plan(plan)
            result = handoff.commit_handoff(plan)
            if plan.inspected["unresolved_tool_ids"]:
                print("[headroom] note: the interrupted tool call may re-run on "
                      "resume", file=sys.stderr)
            return Relaunch(plan.target, handoff.resume_argv(result)[1:],
                            plan.cwd, True, plan.handoff_id, plan)
        except Exception as error:  # no post-stop failure may strand the user
            self._failure(plan, "post_stop_failed: " + str(error))
            print(f"[headroom] handoff failed after Claude exited ({error}); "
                  "relaunching the source with automation off", file=sys.stderr)
            # the source will be relaunched UNsupervised — notify the loss once
            # so an observer that saw the initial supervised launch knows (P1-5)
            _lose_supervision(
                child, f"handoff failed after Claude exited: {error}")
            return self._source_relaunch(plan)

    def _handle_events(self, child, pending_handoff_id, proof=None):
        try:
            records = _read_events(child)
        except SupervisorError as error:
            print(f"[headroom] {error}; automatic handoff disabled for this child",
                  file=sys.stderr)
            _lose_supervision(child, f"hook event journal unreadable: {error}")
            child.pending_cap = None
            return None
        _remember_binding(child)
        saw_stop_failure = False
        for record in records:
            if not _namespace_matches(record, child):
                continue
            try:
                source, cwd = _validated_event(record, child)
                payload = record["payload"]
                hook_name = payload["hook_event_name"]
                epoch = _event_epoch(child, source)
                session_key = ((source.session_id, epoch)
                               if epoch is not None else None)
                if hook_name == "StopFailure" and child.pending_cap is not None \
                        and record["received_at"] \
                        > child.pending_cap.received_at:
                    child.pending_cap = None
                if hook_name == "StopFailure" \
                        and session_key in child.dead_sessions:
                    proof = None
                    continue
                _accept_event_order(child, record)
            except SupervisorError as error:
                print(f"[headroom] malformed hook event ({error}); automatic "
                      "handoff disabled for this child", file=sys.stderr)
                _lose_supervision(child, f"malformed hook event: {error}")
                child.pending_cap = None
                return None
            if hook_name == "SessionStart":
                try:
                    child.pending_cap = None
                    child.binding = parse_session_start(record, child)
                    child.session_epoch = child.binding.epoch
                    child.session_epochs[
                        (child.binding.session_id,
                         child.binding.transcript_path)] = child.binding.epoch
                    child.session_ended = False
                    child.session_end_received_at = 0.0
                    proof = None
                    if pending_handoff_id and not child.resume_bound:
                        handoff.append_action(
                            pending_handoff_id, "resume_bound", automatic=True,
                            target_slot=child.account["name"],
                            new_session_id=child.binding.session_id,
                            transcript_path=child.binding.transcript_path,
                            child_generation=child.generation)
                        child.resume_bound = True
                except (SupervisorError, handoff.HandoffError, RuntimeError,
                        OSError) as error:
                    _lose_supervision(child, f"session binding failed: {error}")
                    print(f"[headroom] {error}; automatic handoff disabled for "
                          "this child", file=sys.stderr)
                    return None
                continue
            current = child.binding
            same_session = (current is not None
                            and source.session_id == current.session_id
                            and source.transcript_path == current.transcript_path)
            if hook_name == "SessionEnd":
                proof = None
                if child.pending_cap is not None and session_key == (
                        child.pending_cap.session_id, child.pending_cap.epoch):
                    child.pending_cap = None
                if epoch is None:
                    _lose_supervision(
                        child, "SessionEnd has no known session epoch")
                    print("[headroom] SessionEnd has no known session epoch; "
                          "automatic handoff disabled for this child",
                          file=sys.stderr)
                    return None
                child.dead_sessions.add(session_key)
                if same_session:
                    child.session_ended = True
                    child.session_end_received_at = record["received_at"]
                continue
            if hook_name == "CwdChanged":
                if same_session:
                    child.binding = replace(current, cwd=cwd)
                continue
            if hook_name == "StopFailure":
                saw_stop_failure = True
                proof = None
                if not same_session or not child.automation:
                    continue
                proof = self._attempt_cap(child, record, announce_non_cap=True)
        if not saw_stop_failure and child.pending_cap is not None \
                and child.automation:
            proof = self._attempt_cap(child, child.pending_cap.event)
        if _binding_key(child.binding) in child.dead_sessions:
            child.pending_cap = None
            print("[headroom] current session ended without a replacement "
                  "SessionStart; automatic handoff disabled for this child",
                  file=sys.stderr)
            _lose_supervision(
                child, "current session ended without a replacement "
                "SessionStart")
            return None
        return proof

    def _monitor(self, child, pending_handoff_id=""):
        # REUSE the guard _spawn installed+attached before/around the spawn
        # window, so there is no unguarded instant between spawn-success and
        # here (P1, r7). Fall back to constructing one only for a direct call
        # that did not go through _spawn (tests).
        signals = self._signals
        if signals is None:
            signals = _SignalGuard(child.process)
            signals.install()
            self._signals = signals
        proof = None
        try:
            while True:
                signals.poll(child.process)
                if signals.shutdown_signal is not None:
                    # A shutdown signal disarms auto-handoff immediately. But
                    # NO notifier-bearing work may run before the signal is
                    # forwarded to the child (forwarding happens on
                    # _SignalGuard's second poll) — a slow HEADROOM_NOTIFY_CMD,
                    # whether from the loss notice OR from _handle_events'
                    # own supervision_lost paths, must never delay forwarding
                    # (P1-4). So until forwarded, skip _handle_events entirely:
                    # just check for exit and keep polling.
                    child.automation = False
                    if not signals.forwarded:
                        returncode = child.process.poll()
                        if returncode is not None:
                            return returncode
                        self.sleep(POLL_SECONDS)
                        continue
                    # forwarded: safe to run notifiers now — record the loss once
                    _lose_supervision(child, "shutdown signal received")
                proof = self._handle_events(
                    child, pending_handoff_id, proof)
                returncode = child.process.poll()
                if returncode is not None:
                    return returncode
                if child.automation and child.binding is None \
                        and self.now() - child.launched_at >= BIND_TIMEOUT:
                    if not child.hint_printed:
                        print("[headroom] no SessionStart handshake within 30s; "
                              "automatic handoff disabled for this child",
                              file=sys.stderr)
                        child.hint_printed = True
                    _lose_supervision(
                        child, "SessionStart hook never bound within "
                        f"{BIND_TIMEOUT:g}s — auto-handoff is not armed")
                if proof is not None and child.automation:
                    try:
                        plan = self._preflight(child, proof)
                    except handoff.HandoffError as error:
                        # A recent mtime is expected just after StopFailure; keep
                        # polling until the required five quiet seconds pass.
                        if "changed recently" not in str(error):
                            print(f"[headroom] automatic handoff held: {error}; "
                                  "child continues", file=sys.stderr)
                            _lose_supervision(
                                child, f"automatic handoff held: {error}")
                            proof = None
                    except SupervisorError as error:
                        print(f"[headroom] automatic handoff held: {error}; child "
                              "continues", file=sys.stderr)
                        _lose_supervision(
                            child, f"automatic handoff held: {error}")
                        proof = None
                    else:
                        relaunch = None
                        try:
                            relaunch = self._stop_and_commit(child, plan, proof)
                        except Exception as error:
                            self._failure(plan, "pre_stop_failed: " + str(error))
                            print(f"[headroom] automatic handoff held: {error}; "
                                  "automatic handoff disabled for this child",
                                  file=sys.stderr)
                            _lose_supervision(
                                child, f"handoff stop failed: {error}")
                            proof = None
                        # P1-2: unless we are actually moving to the target
                        # (an automatic relaunch), the source keeps running and
                        # the target we leased in _lease_target was never
                        # spawned — release its unused lease so a third launcher
                        # isn't wrongly blocked. (release is a no-op if the
                        # target was never leased or the source is recovering.)
                        if not (relaunch is not None and relaunch.automatic):
                            route.release_slot_lease(plan.target["name"])
                        if relaunch is not None:
                            return relaunch
                        proof = None
                self.sleep(POLL_SECONDS)
        finally:
            signals.restore()
            self._signals = None

    def run(self):
        account = self.account
        args = self.initial_args
        cwd = os.path.realpath(os.getcwd())
        automatic = True
        pending_handoff_id = ""
        pending_plan = None
        recovery_plan = None
        last_exit = 0
        clean_exit = False
        try:
            while True:
                try:
                    child = self._spawn(
                        account, args, cwd, automatic, pending_plan)
                except Exception as error:  # every post-commit spawn must recover
                    if self.spawn_ambiguous:
                        # P0-1: the Popen window was interrupted, so a child
                        # MAY be live on `account`. We have no handle to
                        # monitor it, and starting ANOTHER process (source
                        # recovery) would double-run the session. Stop here and
                        # keep this account's lease bound to the possibly-live
                        # child — never release it, never spawn again.
                        self._ambiguous_account = account["name"]
                        if pending_plan is not None:
                            self._failure(
                                pending_plan,
                                "target_spawn_ambiguous: " + str(error))
                        print(f"headroom: spawn outcome for {account['name']} "
                              f"is ambiguous ({error}); a child may be running "
                              f"— not starting another process. If no claude "
                              f"is running, retry.", file=sys.stderr)
                        # the possibly-live child is unmonitored — notify the
                        # loss directly with the known account name (no Child
                        # handle exists on this path) so observers get more than
                        # stderr+exit127 (P2, r4)
                        notify.emit({
                            "event": "supervision_lost",
                            "account": account["name"],
                            "reason": f"spawn outcome ambiguous ({error}); a "
                            "child may be live but is unmonitored"})
                        return 127
                    if pending_plan is not None:
                        # positively no child (OSError cleared spawn_ambiguous):
                        # the target relaunch started nothing — recover source
                        failed_plan = pending_plan
                        self._failure(
                            failed_plan, "target_relaunch_failed: " + str(error))
                        print(f"[headroom] target relaunch failed ({error}); "
                              "relaunching the source with automation off",
                              file=sys.stderr)
                        # the recovered session is unsupervised — tell any
                        # observer, since it saw the initial supervised launch
                        # (P1-5)
                        notify.emit({
                            "event": "supervision_lost",
                            "account": failed_plan.source.account["name"],
                            "reason": f"target relaunch failed: {error}"})
                        # the target never started — release its unused lease
                        route.release_slot_lease(failed_plan.target["name"])
                        relaunch = self._source_relaunch(failed_plan)
                        account, args, cwd = (relaunch.account, relaunch.argv,
                                              relaunch.cwd)
                        automatic = False
                        pending_handoff_id = ""
                        pending_plan = None
                        recovery_plan = failed_plan
                        continue
                    print(f"headroom: {error}", file=sys.stderr)
                    if recovery_plan is not None:
                        self._print_manual_recovery(recovery_plan)
                    clean_exit = True
                    return 127
                # run() has now safely RECEIVED the child and taken ownership:
                # close the ambiguity window HERE (P0-1), outside the recovery
                # try/except above, so any failure between Popen-success and
                # this point kept spawn_ambiguous True and suppressed recovery.
                # spawned_any flips at the same safe point.
                self.spawned_any = True
                self.spawn_ambiguous = False
                pending_plan = None
                recovery_plan = None
                # the active child now exists on `child.account`: hold exactly
                # its lease. After a rotation this releases the OLD source
                # lease (kept until the target spawned, per _lease_target);
                # after a failed rotation it releases the unused target lease.
                # (P0-2)
                self._reconcile_leases(child.account["name"])
                if pending_handoff_id:
                    try:
                        handoff.append_action(
                            pending_handoff_id, "resume_spawned", automatic=True,
                            target_slot=account["name"],
                            old_session_id=args[1] if len(args) > 1 else "",
                            child_generation=child.generation)
                    except handoff.HandoffError as error:
                        print(f"[headroom] could not ledger resume spawn: {error}; "
                              "automatic handoff disabled", file=sys.stderr)
                        _lose_supervision(
                            child, f"resume spawn could not be ledgered: {error}")
                        automatic = False
                outcome = self._monitor(child, pending_handoff_id)
                if isinstance(outcome, Relaunch):
                    # the child has exited and the terminal is ours for a
                    # moment: this is the one place the user can actually see
                    # the handoff happen (anything printed earlier is hidden
                    # by Claude's alternate screen)
                    if outcome.automatic:
                        print(f"[headroom] {child.account['name']} hit its "
                              f"limit, continuing this conversation on "
                              f"{outcome.account['name']}",
                              file=sys.stderr)
                    else:
                        print(f"[headroom] recovering your session on "
                              f"{outcome.account['name']}", file=sys.stderr)
                    account, args, cwd = outcome.account, outcome.argv, outcome.cwd
                    automatic = outcome.automatic
                    pending_handoff_id = outcome.handoff_id
                    pending_plan = outcome.plan if outcome.automatic else None
                    continue
                last_exit = int(outcome)
                clean_exit = True
                return last_exit
        finally:
            # defensively restore signal handlers if a guard was installed by
            # _spawn but _monitor never got to restore it (P1, r7); normal
            # flow already restored it in _monitor's finally.
            if self._signals is not None:
                self._signals.restore()
                self._signals = None
            # the supervised launch is ending: release every lease this
            # supervisor holds so a waiting launch can take the account —
            # EXCEPT an account whose spawn was left ambiguous, whose lease
            # stays bound to the possibly-live child (P0-1). Crash exits rely
            # on the kernel dropping the flock instead.
            for name in route.held_lease_names():
                if name != self._ambiguous_account:
                    route.release_slot_lease(name)
            if clean_exit:
                self._cleanup_files()


def _initial_account(family):
    snapshot = route.ensure_fresh_snapshot()
    if snapshot is None:
        return None
    rows = route._snapshot_accounts(snapshot)
    # an explicitly exported CLAUDE_CONFIG_DIR that names a registered account
    # is the caller's routing decision — supervise THAT account instead of
    # re-routing, as long as it still has proven headroom (rotation off it on
    # a cap is unchanged)
    pinned = route.env_pinned_account(family)
    if pinned is not None:
        reason = route.block_reason(pinned, family, rows.get(pinned["name"]),
                                    route.cooldowns(), time.time())
        if reason is None:
            return pinned
        print(f"[headroom] env-selected account {pinned['name']} is not "
              f"routable ({reason}) — picking another", file=sys.stderr)
    account = next((candidate for candidate, reason in route.candidates(
        family, snapshot) if reason is None), None)
    if account is None:
        return None
    reason = route.block_reason(account, family, rows.get(account["name"]),
                                route.cooldowns(), time.time())
    return account if reason is None else None


def cmd_claude(family, args, fallback_argv=None):
    """Supervised launch. `fallback_argv` (opt-in, from
    --headroom-launch-fallback / HEADROOM_LAUNCH_FALLBACK=1) is the bare CLI
    argv to exec in-process when ANYTHING fails strictly BEFORE the first
    child CLI process was successfully spawned. Once a child has started
    (Supervisor.spawned_any) — or while the spawn outcome is even AMBIGUOUS
    (Supervisor.spawn_ambiguous, P0-3) — a later exit or crash is a normal
    supervision/exit path and NEVER triggers the fallback, so a live child is
    never duplicated by a bare relaunch."""
    # EVERYTHING after the fallback intent is established runs inside the
    # pre-spawn guard — account selection, lease commit, the diagnostic, and
    # Supervisor construction — so any pre-spawn failure (including a
    # constructor error) still bare-execs when the fallback was requested
    # (P1-4). The guard is only for BEFORE the first spawn; runner.run() owns
    # the after-spawn boundary via spawned_any/spawn_ambiguous.
    runner = None
    try:
        account = _initial_account(family)
        # commit: take the slot flock (no-op unless HEADROOM_SLOT_LEASE=1);
        # on the rare claim race, re-pick once — the lease check inside
        # block_reason now skips the account the other launch holds. A
        # LeaseError (infra failure) propagates to fail closed below.
        if account is not None \
                and not route.acquire_slot_lease(account, family):
            print(f"[headroom] {account['name']} is leased by another live "
                  f"launch — picking another", file=sys.stderr)
            account = _initial_account(family)
            if account is not None \
                    and not route.acquire_slot_lease(account, family):
                account = None
        if account is not None:
            print(f"[headroom] {family} -> {account['name']} "
                  f"({account['home']})", file=sys.stderr)
            # the wrapper handshake (route.write_launch_marker) is written
            # inside _spawn, immediately before the first Popen — after
            # settings/argv/env preparation, so a marker can never exist
            # without a child having been given its chance to start
            runner = Supervisor(family, args, account)
    except route.LeaseError as error:
        # HEADROOM_SLOT_LEASE=1 fails closed: refuse the routed launch. With
        # the explicit fallback opt-in, still degrade to a bare CLI (the
        # caller asked to always run something).
        print(f"[headroom] slot lease unavailable ({error}); refusing to "
              f"launch — HEADROOM_SLOT_LEASE=1 fails closed", file=sys.stderr)
        if fallback_argv is not None:
            return route.bare_fallback_exec(
                fallback_argv, f"slot lease unavailable: {error}")
        return 2
    except Exception as error:  # noqa: BLE001 — opt-in: pre-spawn failures fall back
        if fallback_argv is not None:
            return route.bare_fallback_exec(
                fallback_argv, f"launch preparation failed: {error}")
        raise
    if account is None:
        if fallback_argv is not None:
            return route.bare_fallback_exec(
                fallback_argv,
                f"no account for '{family}' has proven headroom")
        print(f"[headroom] no account for '{family}' has proven headroom; "
              f"try `headroom status {family}`", file=sys.stderr)
        return 2

    def _may_fall_back():
        # strictly before-first-spawn AND the spawn outcome is unambiguous:
        # a live-but-unacknowledged child (spawn_ambiguous) must NOT fall back
        return (fallback_argv is not None and not runner.spawned_any
                and not runner.spawn_ambiguous)

    try:
        result = runner.run()
    except Exception as error:  # noqa: BLE001 — opt-in: pre-spawn failures fall back
        if _may_fall_back():
            return route.bare_fallback_exec(
                fallback_argv, f"failed before Claude started: {error}")
        raise
    if _may_fall_back():
        # run() returned without ever spawning a child (e.g. the very first
        # spawn failed) — strictly before-first-spawn, so fall back
        return route.bare_fallback_exec(
            fallback_argv, "Claude never started (details on stderr)")
    return result
