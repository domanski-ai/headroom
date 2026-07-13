"""Model-aware routing with fail-closed cooldowns.

`pick` answers one question: which connected account has PROVEN headroom for
this model family right now? "Proven" means a fresh, identity-bound usage
reading — never a guess. An account is skipped when its reading is missing,
stale, out of range, at 100%, or inside a cooldown from a previous limit-hit.

`run` executes a command on the chosen account and watches its output for
limit errors; on a hit it cools that account down until the relevant window
resets and retries the next candidate.
"""
import contextlib
import datetime
try:
    import fcntl
except ImportError:
    fcntl = None  # Windows: no fcntl
import json
import math
import os
import re
import shlex
import subprocess
import sys
import time

from . import collect as collector
from . import paths, registry

SNAPSHOT_MAX_AGE = int(os.environ.get("HEADROOM_SNAPSHOT_MAX_AGE", "900"))
OBSERVATION_MAX_AGE = int(os.environ.get("HEADROOM_OBSERVATION_MAX_AGE", "1800"))
CLOCK_SKEW = int(os.environ.get("HEADROOM_CLOCK_SKEW", "300"))

LIMIT_RE = re.compile(
    r"(hit your (?:session|weekly|usage|5[- ]?hour|five[- ]?hour)[^.\n]*limit"
    r"|usage limit reached|rate_limit_error|\brate limit\b"
    r"|429 Too Many|status 429|overloaded_error)", re.I)
WEEKLY_RE = re.compile(r"week", re.I)


def _number(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def tfmt(epoch):
    try:
        return datetime.datetime.fromtimestamp(epoch).strftime("%a %H:%M")
    except (OSError, OverflowError, ValueError):
        return str(epoch)


def _read_cooldowns():
    """{} when no ledger exists; None when a ledger exists but is unreadable —
    corrupt protective state must HOLD routing, not silently clear it."""
    path = paths.cooldowns_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as handle:
            value = json.load(handle)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def cooldowns():
    return _read_cooldowns()


def save_cooldowns(value):
    paths.write_json_atomic(paths.cooldowns_path(), value)


@contextlib.contextmanager
def _cooldown_lock():
    """Exclusive lock so concurrent mark()/clear() can't clobber each other's
    limits (a lost cooldown routes an exhausted account = fail-open)."""
    if fcntl is None:
        yield  # Windows: no file locking
        return
    lock_path = paths.cooldowns_path() + ".lock"
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    handle = open(lock_path, "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


def _snapshot_fresh(snapshot, now, max_age):
    if not isinstance(snapshot, dict):
        return False
    generated = snapshot.get("generated")
    return (snapshot is not None and _number(generated)
            and now - generated <= max_age and generated <= now + CLOCK_SKEW)


def ensure_fresh_snapshot(max_age=None):
    """Return a fresh private snapshot, collecting inline when stale/absent.
    Returns None when no fresh snapshot can be proven — callers must hold."""
    max_age = SNAPSHOT_MAX_AGE if max_age is None else max_age
    snapshot = paths.load_json(paths.private_snapshot_path())
    now = time.time()
    if not _snapshot_fresh(snapshot, now, max_age):
        try:
            snapshot = collector.run_collect(quiet=True)
        except registry.RegistryError:
            # no/broken config is a single clean message from main(), not a
            # "collect failed" line followed by a second re-raise
            raise
        except Exception as error:  # noqa: BLE001 — stale must not be promoted
            print(f"[headroom] collect failed: {error}", file=sys.stderr)
            snapshot = None
        if not _snapshot_fresh(snapshot, time.time(), max_age):
            return None
    return snapshot


def _snapshot_accounts(snapshot):
    rows = snapshot.get("accounts") if isinstance(snapshot, dict) else None
    if not isinstance(rows, list):
        rows = []
    return {row["name"]: row for row in rows
            if isinstance(row, dict) and row.get("name")}


def scoped_window_for(fam, windows):
    for key, window in (windows or {}).items():
        if key.startswith("scoped:") and fam in key.lower():
            return window
    return None


# Codex usage is now read live and identity-bound via the codex app-server
# (account/rateLimits/read + account/read), so Codex is fully routed like
# Claude. Set HEADROOM_CODEX_ROUTING=0 to force dashboard-only (e.g. an older
# Codex without the app-server, where reads fall back to stale session logs
# and the router's freshness check already holds them).
CODEX_ROUTING_ENABLED = os.environ.get("HEADROOM_CODEX_ROUTING", "1") != "0"


def block_reason(account, fam, snapshot_row, cool, now):
    """None when the account has proven headroom; otherwise why not."""
    if account.get("provider") == "codex" and not CODEX_ROUTING_ENABLED:
        return "Codex is dashboard-only in this release (best-effort tracking)"
    if cool is None:
        return "cooldown ledger unreadable — inspect/delete state/cooldowns.json"
    if snapshot_row is None:
        return "no usage reading yet"
    if snapshot_row.get("ok") is not True:
        return "held: " + str(snapshot_row.get("error_code")
                              or snapshot_row.get("note") or "not ok")
    if snapshot_row.get("routable") is not True:
        return "trust unverified: " + str(snapshot_row.get("trust_state"))
    if snapshot_row.get("trust_state") not in ("verified", "verified_local"):
        # routable and trust_state must agree; a mismatch is corrupt state -> hold
        return "trust/routable mismatch: " + str(snapshot_row.get("trust_state"))
    # TOCTOU guard: the home may have been re-logged into a DIFFERENT account
    # since this snapshot was taken. Re-derive the identity currently bound in
    # the slot (local, no network) and hold if it no longer matches — otherwise
    # we'd launch the new identity on the old one's proven capacity.
    identity = snapshot_row.get("identity")
    identity = identity if isinstance(identity, dict) else {}
    snap_fp = identity.get("account_fingerprint")
    snap_digest = identity.get("credential_digest")
    if not snap_fp:
        # a routable snapshot with no bound identity can't be re-verified; hold
        return "snapshot has no bound identity — recollect"
    if not snap_digest:
        # require the credential binding too — a routable Claude row always has
        # one; its absence means stale/pre-binding state, so hold
        return "snapshot has no credential binding — recollect"
    current_fp, current_digest = collector.local_binding(account["provider"],
                                                         account["home"])
    if current_fp is None:
        return "cannot verify slot identity — recollect"
    if current_fp != snap_fp:
        return "slot identity changed since snapshot — recollect"
    if current_digest != snap_digest:
        # the actual credential token the CLI will use has changed
        return "slot credential changed since snapshot — recollect"
    if snapshot_row.get("stale"):
        return "reading stale"
    captured_at = snapshot_row.get("captured_at")
    if not _number(captured_at) or captured_at > now + CLOCK_SKEW:
        return "reading clock invalid"
    if now - captured_at > OBSERVATION_MAX_AGE:
        return "reading expired"
    windows = snapshot_row.get("windows")
    if not isinstance(windows, dict):
        return "windows invalid"
    for key in ("5h", "7d"):
        window = windows.get(key)
        if not isinstance(window, dict):
            return f"{key} window missing"
        percent = window.get("used_percent")
        if window.get("freshness") == "expired_observation":
            # an expired observation has NO current reading, so there is no
            # proof of capacity — always hold, never route on it
            return f"{key} reading expired — no current capacity proof"
        if not _number(percent) or not 0 <= percent <= 100:
            return f"{key} reading invalid"
        if percent >= 100:
            return f"{key} at 100%"
        if window.get("severity") == "critical" and window.get("is_active"):
            return f"{key} critical"
    # scoped weekly caps are per-MODEL (e.g. Opus); only gate on them for a
    # specific model family, never for the generic "claude" route — otherwise
    # an Opus cap would wrongly hold Sonnet/Haiku work.
    scoped = scoped_window_for(fam, windows) if fam in (
        "opus", "sonnet", "haiku", "fable") else None
    if scoped is not None:
        # fail CLOSED like 5h/7d: a scoped cap that is unreadable or expired
        # must hold, not silently route an exhausted model family
        if scoped.get("freshness") == "expired_observation":
            return f"{fam} weekly cap reading expired — no current proof"
        scoped_pct = scoped.get("used_percent")
        if not _number(scoped_pct) or not 0 <= scoped_pct <= 100:
            return f"{fam} weekly cap reading invalid"
        if scoped_pct >= 100:
            return f"{fam} weekly cap at 100%"
    for key in (f"{account['name']}:{fam}", f"{account['name']}:*"):
        if key not in cool:
            continue
        cooldown = cool.get(key)
        if not _number(cooldown):
            # a present-but-unreadable cooldown value is corrupt protective
            # state — hold, don't silently ignore it (fail-closed).
            return "cooldown entry unreadable — inspect state/cooldowns.json"
        if now < cooldown:
            return f"cooldown until {tfmt(cooldown)}"
    return None


_UNSET = object()


def candidates(fam, snapshot=_UNSET):
    """[(account, reason-or-None), ...] in preference order. Pass an explicit
    snapshot (possibly None, meaning 'already collected and it failed') to
    avoid re-triggering collection; omit it to collect once here."""
    if snapshot is _UNSET:
        snapshot = ensure_fresh_snapshot()
    rows = _snapshot_accounts(snapshot)
    cool = cooldowns()
    now = time.time()
    result = []
    for account in registry.ordered_for(fam):
        if snapshot is None:
            reason = "no fresh usage snapshot — `headroom collect` failing?"
        else:
            reason = block_reason(account, fam, rows.get(account["name"]),
                                  cool, now)
        result.append((account, reason))
    return result


def pick(fam):
    for account, reason in candidates(fam):
        if reason is None:
            return account
    return None


def env_key(account):
    return "CLAUDE_CONFIG_DIR" if account["provider"] == "claude" else "CODEX_HOME"


def mark(name, fam, epoch=None, account_wide=False, window="5h"):
    """Cool an account down. Session/weekly-all limits are account-wide
    (fam='*'); only genuine model-scoped caps cool a single family.
    A reset in the past is useless — clamp to a window-aware future floor
    (a weekly cap must never collapse to a session-length cooldown).
    Locked read-modify-write so a concurrent mark can't drop this limit."""
    now = time.time()
    floor = now + (6 * 3600 if window == "7d" else 15 * 60)
    epoch = (now + 5 * 3600) if epoch is None else max(float(epoch), floor)
    key = f"{name}:{'*' if account_wide else fam}"
    with _cooldown_lock():
        cool = _read_cooldowns()
        if cool is None:
            raise RuntimeError(
                "cooldown ledger unreadable — inspect/delete state/cooldowns.json")
        cool[key] = epoch
        save_cooldowns(cool)
    return epoch


def clear(key=None):
    """Return True if something was cleared, False if the key wasn't present."""
    with _cooldown_lock():
        if key is None:
            save_cooldowns({})  # explicit full reset is allowed
            return True
        cool = _read_cooldowns()
        if cool is None:
            # don't let a targeted clear silently wipe an unreadable ledger
            raise RuntimeError(
                "cooldown ledger unreadable — refusing to clear one key; "
                "inspect state/cooldowns.json (or `headroom clear` to reset all)")
        if key not in cool:
            return False
        cool.pop(key, None)
        save_cooldowns(cool)
        return True


def window_reset(snapshot, name, window_key):
    row = _snapshot_accounts(snapshot).get(name) or {}
    return ((row.get("windows") or {}).get(window_key) or {}).get("resets_at")


def cmd_status(fam):
    snapshot = ensure_fresh_snapshot()
    rows = _snapshot_accounts(snapshot)
    print(f"model family: {fam}")
    chosen = None
    for account, reason in candidates(fam, snapshot):
        windows = (rows.get(account["name"]) or {}).get("windows") or {}
        head = "5h=%s 7d=%s" % (
            collector.display_percent(windows.get("5h")),
            collector.display_percent(windows.get("7d")))
        scoped = scoped_window_for(fam, windows)
        if scoped is not None:
            head += " %s=%s" % (fam, collector.display_percent(scoped))
        marker = "AVAIL" if reason is None else "skip "
        note = "" if reason is None else f"({reason})"
        print(f"  {marker}  {account['name']:<18} {head:<28} {note}")
        if reason is None and chosen is None:
            chosen = account["name"]
    print(f"-> chosen: {chosen or 'NONE — no account has proven headroom'}")
    return 0 if chosen else 2


def cmd_run(fam, command):
    snapshot = ensure_fresh_snapshot()
    rows = _snapshot_accounts(snapshot)
    for account, reason in candidates(fam, snapshot):
        if reason:
            print(f"[headroom] skip {account['name']}: {reason}", file=sys.stderr)
            continue
        # re-check against the LATEST cooldown ledger immediately before launch:
        # another process may have cooled this account since candidates() ran.
        fresh_reason = block_reason(account, fam, rows.get(account["name"]),
                                    cooldowns(), time.time())
        if fresh_reason:
            print(f"[headroom] skip {account['name']}: {fresh_reason} (rechecked)",
                  file=sys.stderr)
            continue
        environment = collector.scrubbed_env()
        environment[env_key(account)] = account["home"]
        print(f"[headroom] running on {account['name']}", file=sys.stderr)
        try:
            process = subprocess.run(command, env=environment,
                                     capture_output=True, text=True)
        except OSError as error:
            print(f"[headroom] cannot run {command[0]}: {error}", file=sys.stderr)
            return 127
        # Rotation replays the command on the next account, so it is only
        # safe for idempotent commands (documented) and only fires on a
        # FAILED run whose stderr shows a provider limit — matching stdout
        # of a successful run must never trigger a replay.
        if process.returncode != 0 and LIMIT_RE.search(process.stderr or ""):
            sys.stdout.write(process.stdout or "")
            sys.stderr.write(process.stderr or "")
            window_key = "7d" if WEEKLY_RE.search(process.stderr or "") else "5h"
            reset = window_reset(snapshot, account["name"], window_key) \
                or time.time() + (7 * 86400 if window_key == "7d" else 5 * 3600)
            mark(account["name"], fam, reset, account_wide=True, window=window_key)
            print(f"[headroom] {account['name']} hit its {window_key} limit -> "
                  f"cooled until {tfmt(reset)}; rotating", file=sys.stderr)
            continue
        sys.stdout.write(process.stdout or "")
        sys.stderr.write(process.stderr or "")
        print(f"[headroom] completed on {account['name']} "
              f"(exit {process.returncode})", file=sys.stderr)
        return process.returncode
    print(f"[headroom] NO account for '{fam}' has proven headroom",
          file=sys.stderr)
    return 2


def cmd_exec(fam, command):
    """Interactive launch: pick once, exec with the account's env, no capture."""
    account = pick(fam)
    if account is None and registry.family_provider(fam) == "codex" \
            and not CODEX_ROUTING_ENABLED:
        # Codex isn't capacity-routed in this release; still launch on the
        # first configured Codex account so `headroom codex` works.
        ordered = registry.ordered_for(fam)
        account = ordered[0] if ordered else None
        if account:
            print(f"[headroom] Codex is tracked best-effort (not capacity-"
                  f"routed yet) — launching on {account['name']}", file=sys.stderr)
    if account is None:
        print(f"[headroom] no account for '{fam}' has proven headroom; "
              f"try `headroom status {fam}`", file=sys.stderr)
        return 2
    # final recheck against the latest cooldown ledger right before exec, in
    # case another process cooled this account since pick(). NEVER fall back to
    # a held account — re-pick, and refuse to launch if nothing is eligible.
    if registry.family_provider(fam) == "claude" or CODEX_ROUTING_ENABLED:
        snapshot = ensure_fresh_snapshot()
        row = _snapshot_accounts(snapshot).get(account["name"])
        if block_reason(account, fam, row, cooldowns(), time.time()):
            account = pick(fam)
            if account is None:
                print("[headroom] the chosen account was just held and no "
                      "other has proven headroom — try again in a moment",
                      file=sys.stderr)
                return 2
    for var in collector.AUTH_OVERRIDE_VARS:
        os.environ.pop(var, None)
    os.environ[env_key(account)] = account["home"]
    print(f"[headroom] {fam} -> {account['name']} ({account['home']})",
          file=sys.stderr)
    try:
        os.execvp(command[0], command)
    except FileNotFoundError:
        cli = "Claude Code" if command[0] == "claude" else "Codex"
        print(f"[headroom] `{command[0]}` not found on PATH — install the "
              f"{cli} CLI first", file=sys.stderr)
        return 127
    except OSError as error:
        print(f"[headroom] cannot exec {command[0]}: {error}", file=sys.stderr)
        return 127


def current_account(fam):
    """The registry account this process's environment actually points at."""
    provider = registry.family_provider(fam)
    var = "CLAUDE_CONFIG_DIR" if provider == "claude" else "CODEX_HOME"
    default = "~/.claude" if provider == "claude" else "~/.codex"
    home = os.path.realpath(os.path.expanduser(os.environ.get(var, default)))
    try:
        for account in registry.ordered_for(fam):
            if os.path.realpath(account["home"]) == home:
                return account
    except registry.RegistryError:
        pass
    return None


def cmd_rotate(fam):
    """Manual rotation: cool the account the CURRENT environment points at
    (falling back to the current best) and report the next one."""
    snapshot = ensure_fresh_snapshot()
    ranked = candidates(fam, snapshot)
    current = current_account(fam)
    if current is None:
        current = next((a for a, r in ranked if r is None), None)
        if current is not None:
            print(f"(current session's account not in the registry — "
                  f"rotating the first available: {current['name']})")
    if current is None:
        print(f"every account for '{fam}' is already limited or held")
        earliest = None
        for account, _ in ranked:
            reset = window_reset(snapshot, account["name"], "5h")
            if _number(reset) and (earliest is None or reset < earliest):
                earliest = reset
        if earliest:
            print(f"earliest 5h reset: {tfmt(earliest)}")
        return 2
    reset = window_reset(snapshot, current["name"], "5h") \
        or time.time() + 5 * 3600
    reset = mark(current["name"], fam, reset, account_wide=True)
    successor = pick(fam)
    if successor is None:
        print(f"rotated {current['name']} out (cools until {tfmt(reset)}) — "
              f"but no other account has headroom for '{fam}'")
        return 2
    print(f"rotated {current['name']} -> {successor['name']} ({fam}); "
          f"{current['name']} cools until {tfmt(reset)}")
    print(f"export {env_key(successor)}={shlex.quote(successor['home'])}")
    return 0
