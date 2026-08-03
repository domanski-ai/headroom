"""Bounded launch-event notifications for wrapper scripts.

When ``HEADROOM_NOTIFY_CMD`` names a command, headroom invokes it at launch
transitions with a single JSON argument describing the event:

    {"event": "launch", "mode": "supervised"|"exec",
     "account": ..., "model": ..., "note": ...}
    {"event": "downgrade", "account": ..., "reason": ...}
    {"event": "supervision_lost", "account": ..., "reason": ...,
     "supervisor_id": ..., "generation": ..., "session": ...,
     "transient": ...}
    {"event": "fallback", "reason": ...}
    {"event": "preemptive_scheduled", "account": ..., "family": ...,
     "window": ..., "used_percent": ...}
    {"event": "preemptive_handoff", "account": ..., "target": ...,
     "family": ..., "window": ..., "used_percent": ..., "handoff_id": ...}
    {"event": "preemptive_held", "account": ..., "reason": ...}
    {"event": "cap_held", "account": ..., "reason": ...}
    {"event": "cap_cleared", "account": ..., "reason": ...}
    {"event": "session_end_unknown_epoch", "account": ..., "session": ...,
     "armed": ..., "bound": ..., "classification": ..., "expected": ...,
     "resolution": ..., "supervisor_id": ..., "generation": ...,
     "reason": ...}
    {"event": "session_end_epoch_resolved", "account": ..., "session": ...,
     "epoch": ..., "moved_from": ..., "moved_to": ...,
     "supervisor_id": ..., "generation": ...}

``supervision_lost`` fires for EVERY path that disarms a supervised child's
automatic handoff, once per distinct reason — a dashboard should treat it as
"this session is no longer protected". ``transient`` is reserved vocabulary:
today every disarm is permanent and every row carries ``transient: false``.
A future heal cycle may add ``supervision_rearmed`` ("this session is
protected again"); THE CONTRACT, stated now so no consumer keys on counting:
per (``supervisor_id``, ``generation``), a child is unprotected iff the
LATEST of {``supervision_lost``, ``supervision_rearmed``} is
``supervision_lost``. Ordering, never counting — dedupe makes counts lie.
Any consumer that latches ``supervision_lost`` (the estate watchdog does)
must learn ``supervision_rearmed`` before that cycle lands.

``session_end_unknown_epoch`` is the deliberate counter-example: something
happened that is worth saying out loud, and supervision was NOT taken away
for it. ``classification`` says what the branch established before speaking
— ``never_bound`` (the session's SessionStart was journaled and never bound,
so it minted no epoch; the receipt-grade echo of a lost birth),
``expected_stop`` (unresolved during a stop this supervisor itself
requested; ``expected`` is true), or ``unknown_origin`` (nothing live or
journaled explains this end; ``resolution`` names exactly why not). The one
alert-grade shape is ``unknown_origin`` with ``armed: true``.

``session_end_epoch_resolved`` is receipt-grade: a SessionEnd named a moved
transcript path for a session that minted its epoch live, and lineage over
live state resolved it. Nothing is expired and supervision is unchanged.

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
                    # The group IS process.pid: start_new_session made this
                    # child a group leader. Re-deriving it with getpgid asks
                    # a different question — what group that pid is in NOW —
                    # and the answer can name a group we never created and are
                    # not entitled to SIGKILL, whether because the observer
                    # re-grouped itself or because the pid no longer means
                    # what it did. Kill the group we made.
                    os.killpg(process.pid, signal.SIGKILL)
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
