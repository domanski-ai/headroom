"""Claude Code status line: your live headroom at the bottom of every session.

Claude Code pipes a JSON payload on stdin (model, workspace, etc.) and renders
whatever this prints. We show the account the CURRENT session is running on
(matched via CLAUDE_CONFIG_DIR), its 5h/7d headroom color-coded, and — when
the current account is running low — who the rotator would pick next.

Wire it up in ~/.claude/settings.json:

    {"statusLine": {"type": "command", "command": "headroom statusline"}}
"""
import json
import os
import re
import sys
import time

from . import locks, paths, registry

GREEN, YELLOW, ORANGE, RED, DIM, RESET = (
    "\x1b[32m", "\x1b[33m", "\x1b[38;5;208m", "\x1b[31m", "\x1b[2m", "\x1b[0m")
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def journal_session(payload, now=None):
    """Leave a cheap breadcrumb so handoff can identify the current session.

    Status lines run frequently and sit on Claude Code's render path, so a
    per-session mtime makes the common throttled case one stat rather than a
    scan of an ever-growing journal. This public edge swallows every failure
    because capacity rendering is more important than handoff discovery.
    """
    try:
        return _journal_session(payload, now)
    except Exception:  # noqa: BLE001 — statusline output is load-bearing
        return False


def _journal_session(payload, now=None):
    if not isinstance(payload, dict):
        return False
    session_id = payload.get("session_id")
    transcript_path = payload.get("transcript_path")
    cwd = payload.get("cwd")
    if not cwd and isinstance(payload.get("workspace"), dict):
        cwd = payload["workspace"].get("current_dir")
    if (not isinstance(session_id, str) or not SESSION_ID_RE.fullmatch(session_id)
            or not isinstance(transcript_path, str) or not transcript_path
            or not isinstance(cwd, str) or not cwd):
        return False
    now = time.time() if now is None else now
    state = paths.ensure_private(paths.state_dir())
    markers = paths.ensure_private(os.path.join(state, "session-journal"))
    marker = os.path.join(markers, session_id)
    try:
        marker_fd = os.open(marker, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileNotFoundError:
        return False
    except FileExistsError:
        marker_fd = os.open(marker, os.O_RDWR)
        created = False
    try:
        locks.exclusive(marker_fd)
        if not created and now - os.fstat(marker_fd).st_mtime < 60:
            return False
        model = payload.get("model")
        model = model.get("display_name", "") if isinstance(model, dict) else ""
        model = model if isinstance(model, str) else ""
        version = payload.get("version", "")
        version = version if isinstance(version, str) else ""
        entry = {
            "ts": int(now), "session_id": session_id,
            "transcript_path": transcript_path, "cwd": cwd,
            "model": model, "version": version,
            "config_dir": os.environ.get("CLAUDE_CONFIG_DIR") or "",
        }
        journal_lock = open(os.path.join(state, "sessions.lock"), "a+")
        try:
            paths.chmod_private(journal_lock.name, 0o600)
            locks.exclusive(journal_lock)
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            descriptor = os.open(os.path.join(state, "sessions.jsonl"),
                                 flags, 0o600)
            try:
                paths.fchmod_private(descriptor, 0o600)
                encoded = (json.dumps(entry, separators=(",", ":"))
                           + "\n").encode()
                if os.write(descriptor, encoded) != len(encoded):
                    return False
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            locks.unlock(journal_lock)
            journal_lock.close()
        os.utime(marker, (now, now))
        return True
    finally:
        locks.unlock(marker_fd)
        os.close(marker_fd)


def color(used):
    if used is None:
        return DIM
    if used < 50:
        return GREEN
    if used < 75:
        return YELLOW
    if used < 90:
        return ORANGE
    return RED


def window_text(windows, key, label):
    window = (windows or {}).get(key) or {}
    used = window.get("used_percent")
    if used is None:
        return f"{DIM}{label} ?{RESET}"
    return f"{color(used)}{label} {round(used)}%{RESET}"


def main():
    payload = None
    try:
        payload = json.load(sys.stdin)
    except (ValueError, OSError):
        pass
    try:
        journal_session(payload)
    except Exception:  # noqa: BLE001 — statusline rendering must never fail
        pass
    snapshot = paths.load_json(paths.private_snapshot_path())
    if not snapshot:
        print(f"{DIM}headroom: no snapshot yet (run `headroom collect`){RESET}")
        return 0
    rows = {row["name"]: row for row in snapshot.get("accounts", [])
            if isinstance(row, dict) and row.get("name")}
    current_home = os.path.realpath(
        os.environ.get("CLAUDE_CONFIG_DIR", os.path.expanduser("~/.claude")))
    current = None
    try:
        for account in registry.accounts():
            if os.path.realpath(account["home"]) == current_home:
                current = account
                break
    except registry.RegistryError:
        pass
    parts = []
    if current and current["name"] in rows:
        row = rows[current["name"]]
        windows = row.get("windows") or {}
        parts.append(f"{current['name']}")
        parts.append(window_text(windows, "5h", "5h"))
        parts.append(window_text(windows, "7d", "7d"))
        used = (windows.get("5h") or {}).get("used_percent")
        if used is not None and used >= 99:
            if os.environ.get("HEADROOM_SUPERVISOR_ID"):
                parts.append(f"{DIM}capped · auto-handoff armed{RESET}")
            else:
                parts.append(
                    f"{DIM}capped -> /exit, then: headroom handoff{RESET}")
        elif used is not None and used >= 75:
            from . import route
            candidate = next(
                (account for account, reason in route.candidates(
                    "claude", snapshot)
                 if reason is None and account["name"] != current["name"]),
                None)
            if candidate:
                parts.append(f"{DIM}next: {candidate['name']}{RESET}")
    else:
        ok_rows = [row for row in rows.values()
                   if row.get("ok") and row.get("routable")
                   and not row.get("stale") and row.get("provider") == "claude"]
        if ok_rows:
            def used_5h(row):
                value = (row.get("windows", {}).get("5h") or {}).get("used_percent")
                return value if isinstance(value, (int, float)) else 101
            best = min(ok_rows, key=used_5h)
            windows = best.get("windows") or {}
            parts.append(f"{DIM}best:{RESET} {best['name']}")
            parts.append(window_text(windows, "5h", "5h"))
            parts.append(window_text(windows, "7d", "7d"))
        else:
            parts.append(f"{DIM}headroom: all accounts held{RESET}")
    print(" · ".join(parts))
    return 0
