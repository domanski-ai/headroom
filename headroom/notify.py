"""Bounded launch-event notifications for wrapper scripts.

When ``HEADROOM_NOTIFY_CMD`` names a command, headroom invokes it at launch
transitions with a single JSON argument describing the event:

    {"event": "launch", "mode": "supervised"|"exec",
     "account": ..., "model": ..., "note": ...}
    {"event": "downgrade", "account": ..., "reason": ...}
    {"event": "supervision_lost", "account": ..., "reason": ...}
    {"event": "fallback", "reason": ...}

Delivery is best-effort and bounded: the command has a hard timeout (default
10s, override with ``HEADROOM_NOTIFY_TIMEOUT``). Unix runs it in its own
process group and kills that whole group on timeout; Windows can only promise
to kill the direct observer process. A broken, missing, or hung notify command
is swallowed with a stderr line — it must never block, materially delay, or
kill the launch. This replaces external marker-polling with events; it
composes with, and is independent of, the
``HEADROOM_LAUNCH_MARKER`` handshake.

SECURITY: ``HEADROOM_NOTIFY_CMD`` is TRUSTED code — it runs as the invoking
user with that user's privileges and environment. The timeout bounds latency
and reaps runaways; it is NOT a sandbox. Only set this to a command you
control, exactly as you would any other command in your launch script.
"""
import json
import os
import shlex
import signal
import subprocess
import sys

NOTIFY_TIMEOUT = 10.0


def _timeout():
    raw = os.environ.get("HEADROOM_NOTIFY_TIMEOUT", "").strip()
    if not raw:
        return NOTIFY_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        return NOTIFY_TIMEOUT
    # a non-positive or absurd override falls back to the default: the bound
    # must stay a real bound, never "wait forever"
    return value if 0 < value <= 60 else NOTIFY_TIMEOUT


def emit(event):
    """Deliver one event to HEADROOM_NOTIFY_CMD; never raises, never unbounded.

    Returns True when the command ran to completion (its exit status is
    deliberately ignored — a failing observer must not fail the launch),
    False when no command is configured or delivery failed/timed out."""
    raw = os.environ.get("HEADROOM_NOTIFY_CMD", "").strip()
    if not raw:
        return False
    try:
        argv = shlex.split(raw)
        if not argv:
            return False
        payload = json.dumps(event, sort_keys=True, allow_nan=False)
        # Unix observers get a private process group. Windows has no killpg;
        # CREATE_NEW_PROCESS_GROUP isolates console signals, and timeout
        # cleanup honestly falls back to killing the direct observer process.
        platform_options = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                            if os.name == "nt" else {"start_new_session": True})
        process = subprocess.Popen(
            argv + [payload],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, **platform_options)
        try:
            process.wait(timeout=_timeout())
        except subprocess.TimeoutExpired:
            # Unix kills the WHOLE group so a shell that backgrounded workers
            # cannot leave descendants alive. Windows kills the direct process.
            # Then reap the leader so it does not remain a zombie.
            if os.name == "nt":
                process.kill()
            else:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    process.kill()  # group gone/unavailable — use the pid
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            target = "process" if os.name == "nt" else "process group"
            print(f"[headroom] notify command timed out; its {target} was "
                  "killed (launch continues)", file=sys.stderr)
            return False
        return True
    except Exception as error:  # noqa: BLE001 — an observer can never be fatal
        print(f"[headroom] notify failed: {error} (launch continues)",
              file=sys.stderr)
        return False
