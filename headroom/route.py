"""Model-aware routing with fail-closed cooldowns.

`pick` answers one question: which connected account has PROVEN headroom for
this model family right now? "Proven" means a fresh, identity-bound usage
reading — never a guess. An account is skipped when its reading is missing,
stale, out of range, at 100%, or inside a cooldown from a previous limit-hit.

`run` executes a command on the chosen account and watches its output for
limit errors; on a hit it cools that account down until the relevant window
resets and retries the next candidate.
"""
import atexit
import contextlib
import datetime
import errno
import json
import math
import os
import re
import shlex
import subprocess
import sys
import time

from . import collect as collector
from . import locks, notify, paths, registry


SNAPSHOT_MAX_AGE = paths.env_int("HEADROOM_SNAPSHOT_MAX_AGE", 900)
OBSERVATION_MAX_AGE = paths.env_int("HEADROOM_OBSERVATION_MAX_AGE", 1800)
CLOCK_SKEW = paths.env_int("HEADROOM_CLOCK_SKEW", 300)

LIMIT_RE = re.compile(
    r"(hit your (?:session|weekly|usage|5[- ]?hour|five[- ]?hour)[^.\n]*limit"
    r"|usage limit reached|rate_limit_error|\brate limit\b"
    r"|429 Too Many|status 429|overloaded_error)", re.I)
WEEKLY_RE = re.compile(r"week", re.I)

# Codex failure classification (provider-gated; never used for Claude).
# A stderr regex is a HINT — the classes drive different protective actions:
# a subscription cap cools the account; an invalidated token quarantines it
# WITHOUT a capacity cooldown; overload backs the provider off without
# touching the account; network ambiguity just holds. Auth is checked first
# so an auth error mentioning "limit" can never masquerade as a cap.
CODEX_AUTH_FAIL_RE = re.compile(
    r"(token_invalidated|refresh token|invalid_grant|unauthorized|\b401\b"
    r"|login required|not logged in|please (?:run )?`?codex login|re-?login)",
    re.I)
CODEX_CAP_RE = re.compile(
    r"(hit your [^.\n]*limit|usage[ _]limit|weekly limit|plan limit"
    r"|quota exceeded)", re.I)
CODEX_OVERLOAD_RE = re.compile(
    r"(\b429\b|too many requests|overload|throttl|temporarily unavailable"
    r"|\b503\b)", re.I)
CODEX_NETWORK_RE = re.compile(
    r"(network|connection (?:refused|reset|closed|error)|timed? ?out"
    r"|dns|unreachable|no route to host)", re.I)


def classify_codex_failure(stderr):
    """One of subscription_cap / auth_invalid / overload / network / none."""
    text = stderr or ""
    if CODEX_AUTH_FAIL_RE.search(text):
        return "auth_invalid"
    if CODEX_CAP_RE.search(text):
        return "subscription_cap"
    if CODEX_OVERLOAD_RE.search(text):
        return "overload"
    if CODEX_NETWORK_RE.search(text):
        return "network"
    return "none"


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


def preflight_cooldowns():
    """Return readable protective state or hold before a destructive action."""
    cool = _read_cooldowns()
    if cool is None:
        raise RuntimeError(
            "cooldown ledger unreadable — inspect/delete state/cooldowns.json")
    for key, reset in cool.items():
        if not isinstance(key, str) or not key or not _number(reset):
            raise RuntimeError(
                "cooldown entry unreadable — inspect state/cooldowns.json")
    return cool


def save_cooldowns(value):
    paths.write_json_atomic(paths.cooldowns_path(), value)


@contextlib.contextmanager
def _cooldown_lock():
    """Exclusive lock so concurrent mark()/clear() can't clobber each other's
    limits (a lost cooldown routes an exhausted account = fail-open)."""
    lock_path = paths.cooldowns_path() + ".lock"
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    handle = open(lock_path, "a+")
    try:
        locks.exclusive(handle)
        yield
    finally:
        locks.unlock(handle)
        handle.close()


def _read_quarantine():
    """{} when no ledger exists; None when a ledger exists but is unreadable —
    corrupt protective state must HOLD routing, not silently clear it."""
    path = paths.quarantine_path()
    if not os.path.exists(path):
        return {}
    value = paths.load_json(path)
    return value if isinstance(value, dict) else None


def quarantines():
    return _read_quarantine()


@contextlib.contextmanager
def _quarantine_lock():
    """Exclusive lock shared by all quarantine read-modify-write paths."""
    lock_path = paths.quarantine_path() + ".lock"
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    handle = open(lock_path, "a+")
    try:
        locks.exclusive(handle)
        yield
    finally:
        locks.unlock(handle)
        handle.close()


def quarantine_mark(name, reason):
    """Quarantine a seat after an explicit auth rejection: unroutable until
    re-login. Auth is NOT capacity, so no cooldown is written — the seat
    comes back via `headroom connect`, never via a timer. Locked
    read-modify-write; no secrets stored."""
    with _quarantine_lock():
        ledger = _read_quarantine()
        if ledger is None:
            raise RuntimeError(
                "quarantine ledger unreadable — inspect state/quarantine.json")
        ledger[name] = {"reason": str(reason), "ts": int(time.time())}
        paths.write_json_atomic(paths.quarantine_path(), ledger)
    return ledger[name]


def preflight_remove_slot_state():
    """Fail before a registry removal when protective state is unreadable."""
    with _cooldown_lock():
        if _read_cooldowns() is None:
            raise RuntimeError(
                "cooldown ledger unreadable — inspect state/cooldowns.json")
        with _quarantine_lock():
            if _read_quarantine() is None:
                raise RuntimeError(
                    "quarantine ledger unreadable — inspect state/quarantine.json")


def remove_slot_state(name):
    """Drop only one slot's cooldown and quarantine records.

    Callers that also change the registry must acquire the collection lock
    first. The state lock order stays cooldown, then quarantine, matching the
    handoff transaction's registry/cooldown/quarantine order.
    """
    with _cooldown_lock():
        cooldown = _read_cooldowns()
        if cooldown is None:
            raise RuntimeError(
                "cooldown ledger unreadable — inspect state/cooldowns.json")
        keys = [key for key in cooldown if key.startswith(name + ":")]
        for key in keys:
            cooldown.pop(key)
        if keys:
            paths.write_json_atomic(paths.cooldowns_path(), cooldown)
        with _quarantine_lock():
            quarantine = _read_quarantine()
            if quarantine is None:
                raise RuntimeError(
                    "quarantine ledger unreadable — inspect state/quarantine.json")
            if name in quarantine:
                quarantine.pop(name)
                paths.write_json_atomic(paths.quarantine_path(), quarantine)


# --- flock slot leases (opt-in: HEADROOM_SLOT_LEASE=1) ----------------------
#
# At the moment routing COMMITS to an account (just before spawn) the launcher
# takes an exclusive, non-blocking flock() on a per-account lock file and
# holds it for the LIFETIME of the launch. flock is race-free by construction
# (the kernel arbitrates; there is no read/decide/write TOCTOU and no stale
# file to delete) and is released automatically when the last holding process
# dies — so a crash frees the slot and there is no pid to reuse. On the exec
# path the locked fd is made inheritable and survives execvp, so the CLI holds
# the lease for its own lifetime; on the supervised path the resident
# supervisor holds it and MOVES it to the active account across an automatic
# handoff (acquire target before stopping source; release source after the
# target child spawns).
#
# A candidate account is unavailable iff a non-blocking flock probe fails
# (another live launch holds it). The flock is authoritative — acquire
# re-checks it atomically — so the probe in block_reason is only a hint: a
# probe error degrades to "not blocked" and can never crash routing.
# Acquisition, by contrast, FAILS CLOSED: when leasing is requested but the
# lock cannot be operated for an infrastructure reason, routing raises
# LeaseError and the launch refuses rather than double-booking one account.

_HELD_LEASES = {}       # account name -> open fd holding the exclusive flock
_RELEASE_REGISTERED = False

_LEASE_CONTENDED = (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES)


class LeaseError(RuntimeError):
    """The slot-lease layer could not operate. With HEADROOM_SLOT_LEASE=1 an
    opt-in coordination feature must FAIL CLOSED — never launch unleased."""


def _lease_enabled():
    return os.environ.get("HEADROOM_SLOT_LEASE", "") == "1"


def _leases_dir():
    return os.path.join(paths.state_dir(), "leases")


def _lease_path(name):
    # registry names match ^[a-z0-9][a-z0-9_-]{0,31}$, so they are safe
    # single-component filenames
    return os.path.join(_leases_dir(), f"{name}.lock")


def held_lease_names():
    """Account names whose flock THIS process currently holds."""
    return list(_HELD_LEASES)


def holds_slot_lease(name):
    return name in _HELD_LEASES


def _account_leased_by_other(name):
    """True iff a DIFFERENT live launch holds this account's flock.

    False for: leasing disabled, our own lease, no lock file, or any probe
    error (acquire is the authoritative gate, so a hint that fails open is
    corrected there). The probe is non-blocking, always releases what it
    opened, and never raises — it must never crash routing."""
    if not _lease_enabled() or not isinstance(name, str) or not name:
        return False
    if name in _HELD_LEASES:
        return False  # our own commitment never blocks us
    try:
        fd = os.open(_lease_path(name), os.O_RDWR)
    except FileNotFoundError:
        return False
    except OSError:
        return False
    try:
        if not locks.exclusive(fd, blocking=False):
            return True
        # nobody holds it — release the probe lock immediately
        locks.unlock(fd)
        return False
    except OSError as error:
        return error.errno in _LEASE_CONTENDED
    finally:
        os.close(fd)


def _write_lease_metadata(fd, name, fam):
    """Informational only (diagnostics/dashboards). Decisions use the flock,
    never these contents, so a failed write is non-fatal."""
    try:
        payload = json.dumps({"account": name, "pid": os.getpid(),
                              "family": fam, "written_at": time.time()},
                             allow_nan=False)
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        os.write(fd, (payload + "\n").encode("utf-8"))
    except OSError:
        pass


def acquire_slot_lease(account, fam):
    """Take (and keep) the exclusive flock for `account` at commit time.

    True  -> this process now holds the lease (or leasing is disabled: a
             no-op success, so legacy behaviour is byte-unchanged).
    False -> a DIFFERENT live launch holds the account; pick another.
    raises LeaseError -> leasing was requested but the lock could not be
             operated for an infrastructure reason; the launch must fail
             closed, never proceed unleased."""
    global _RELEASE_REGISTERED
    if not _lease_enabled():
        return True
    name = account.get("name") if isinstance(account, dict) else None
    if not isinstance(name, str) or not name:
        # requested leasing on a nameless account can't be honoured; fail
        # closed rather than silently launch unleased
        raise LeaseError("account has no name to lease")
    if name in _HELD_LEASES:
        return True  # already ours (e.g. a pre-launch recheck of our slot)
    try:
        paths.ensure_private(paths.state_dir())
        os.makedirs(_leases_dir(), exist_ok=True)
        fd = os.open(_lease_path(name), os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as error:
        raise LeaseError(
            f"cannot open slot lease for {name}: {error}") from error
    try:
        if not locks.exclusive(fd, blocking=False):
            os.close(fd)
            return False
    except OSError as error:
        os.close(fd)
        if error.errno in _LEASE_CONTENDED:
            return False
        raise LeaseError(
            f"cannot lock slot lease for {name}: {error}") from error
    # keep the lock across execvp so the exec'd CLI holds it for its lifetime
    # (and so a supervised child can inherit it via Popen pass_fds). If the fd
    # cannot be made inheritable, execvp would CLOSE it and silently free the
    # account — that is a fail-OPEN leak, so fail closed instead. (P1-3)
    try:
        os.set_inheritable(fd, True)
        if not os.get_inheritable(fd):
            raise OSError("slot lease fd did not become inheritable")
    except OSError as error:
        _close_lease_fd(fd)
        raise LeaseError(
            f"cannot make slot lease for {name} inheritable: {error}") \
            from error
    _write_lease_metadata(fd, name, fam)
    _HELD_LEASES[name] = fd
    if not _RELEASE_REGISTERED:
        atexit.register(release_slot_leases)
        _RELEASE_REGISTERED = True
    return True


def _close_lease_fd(fd):
    """Drop this process's lease via the backend's close discipline.

    Unix stays close-only because a supervised child may share the open file
    description. Windows supervision is gated off, and the backend explicitly
    unlocks its mandatory byte-range lock before closing the descriptor.
    """
    try:
        locks.close(fd)
    except OSError:
        pass


def held_lease_fd(name):
    """The open flock fd this process holds for `account`, or None. Used to
    hand the fd to a supervised child (Popen pass_fds) so the lease can ride
    on the child under an ambiguous spawn."""
    return _HELD_LEASES.get(name)


def release_slot_lease(name):
    """Release one held lease (used when a handoff moves to a new account, or
    before falling back to a bare CLI that uses no routed account). Close-only,
    so a lease a live child inherited stays held by that child."""
    fd = _HELD_LEASES.pop(name, None)
    if fd is None:
        return
    _close_lease_fd(fd)


def release_slot_leases():
    """Release every lease this process holds (normal-exit / fallback path).
    Crashes and exec'd CLIs are covered by the kernel dropping the flock."""
    for name in list(_HELD_LEASES):
        release_slot_lease(name)


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


def block_reason(account, fam, snapshot_row, cool, now, reserve=None):
    """None when the account has proven headroom; otherwise why not.

    `reserve` is the minimum % headroom an account must have left to route (see
    registry.reserve_percent); None self-looks it up from config so every
    caller honours the setting."""
    if reserve is None:
        reserve = registry.reserve_percent()
    if account.get("reserved") is True:
        # tracked but never routed to (config: reserved) — this must gate every
        # selection path, so it lives here rather than in the candidate listing
        return "reserved (config): tracked but never auto-routed"
    if account.get("provider") == "codex" and not CODEX_ROUTING_ENABLED:
        return ("Codex routing disabled (HEADROOM_CODEX_ROUTING=0) — "
                "headroom refuses to route Codex work")
    # opt-in slot lease (HEADROOM_SLOT_LEASE=1): an account whose flock is
    # held by another LIVE launch is unavailable, so concurrent launches
    # diverge; a lease held by THIS process never blocks (it is our own
    # commitment). The flock at acquire is authoritative; this is a hint.
    if _account_leased_by_other(account.get("name")):
        return "slot leased by another live launch"
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
    if account.get("provider") == "codex":
        # provider-gated: Codex needs stronger proof than Claude; nothing in
        # this branch can ever run for (or change the behaviour of) Claude
        codex_reason = _codex_gate(account, snapshot_row, identity)
        if codex_reason:
            return codex_reason
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
    # OpenAI lifted Codex's 5h (2026-07): a live codex seat reports only the
    # weekly window, so an absent 5h is a lifted limit, not a missing reading.
    # Skip it for codex; the weekly (7d) stays mandatory for every provider,
    # and a non-codex seat missing any standard window still holds (fail-closed).
    codex = account.get("provider") == "codex"
    for key in ("5h", "7d"):
        window = windows.get(key)
        if not isinstance(window, dict):
            # Only a genuinely ABSENT 5h is the lifted limit. A PRESENT but
            # malformed 5h ("5h": null / a string, i.e. a corrupt or partially
            # written snapshot) is not lifted — fail closed and hold.
            if key == "5h" and codex and key not in windows:
                continue
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
        if reserve > 0 and percent > 100 - reserve:
            return f"{key} below {reserve:g}% reserve ({100 - percent:g}% left)"
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
        if reserve > 0 and scoped_pct > 100 - reserve:
            return (f"{fam} weekly cap below {reserve:g}% reserve "
                    f"({100 - scoped_pct:g}% left)")
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


def _codex_gate(account, snapshot_row, identity):
    """Codex-only fail-closed eligibility (never touches the Claude path).

    Eligible only when the reading came from the live app-server, the identity
    is network-verified (verified_local is NOT routable for Codex — a local id
    token names an identity but proves no live capacity), the login is a
    ChatGPT subscription (API-key seats have no subscription windows), the
    refresh-token lineage is still the one the reading was taken under, and
    the seat is not quarantined. The pre-launch block_reason recheck re-derives
    the local binding + lineage, which is the mandatory targeted TOCTOU check;
    a full online (app-server) pre-launch recheck is a TODO hook — doing it on
    every candidate pass would over-spawn app-servers and trip the provider's
    transient throttle."""
    if snapshot_row.get("source") != "codex_app_server":
        return ("codex reading is not from the live app-server "
                "(display-only telemetry) — not routable")
    if snapshot_row.get("trust_state") != "verified":
        return "codex requires a network-verified reading — recollect"
    if identity.get("auth_mode") != "chatgpt":
        return ("codex seat is not a ChatGPT-subscription login — API-key "
                "seats have no subscription capacity to route")
    lineage = identity.get("lineage_digest")
    if not lineage:
        return "snapshot has no refresh-lineage binding — recollect"
    current_lineage = collector.codex_lineage_digest(account["home"])
    if current_lineage is None:
        return "cannot verify refresh-token lineage — recollect"
    if current_lineage != lineage:
        # a lineage change means a FRESH LOGIN happened somewhere (a normal
        # access refresh keeps the lineage) — for a seat shared with Paul's
        # Mac desktop that is the collision signature; either way, hold
        if account.get("shared_desktop"):
            return ("shared_desktop_identity — Mac re-login can invalidate "
                    "this seat")
        return "slot refresh-token lineage changed since snapshot — recollect"
    quarantine = _read_quarantine()
    if quarantine is None:
        return "quarantine ledger unreadable — inspect state/quarantine.json"
    entry = quarantine.get(account["name"])
    if entry is not None:
        detail = entry.get("reason") if isinstance(entry, dict) else None
        return ("quarantined: %s — run `headroom connect %s` to re-login"
                % (detail or "auth invalid", account["name"]))
    return None


_UNSET = object()


def _headroom_score(row):
    """min(100 - used_5h, 100 - used_7d): how much PROVEN room is left before
    the tightest window caps. Only meaningful for rows that already passed
    block_reason; anything unreadable scores worst (fail-closed ordering)."""
    windows = row.get("windows") if isinstance(row, dict) else None
    if not isinstance(windows, dict):
        return -1.0
    # 5h is optional for codex (OpenAI lifted it): score on whatever standard
    # windows are present. Reachable for codex now that block_reason no longer
    # blocks an absent 5h. 7d stays required — its absence, or any unreadable
    # percent, scores worst (fail-closed ordering).
    codex = row.get("provider") == "codex"
    values = []
    for key in ("5h", "7d"):
        window = windows.get(key)
        if not isinstance(window, dict):
            if key == "5h" and codex:
                continue
            return -1.0
        percent = window.get("used_percent")
        if not _number(percent):
            return -1.0
        values.append(100.0 - percent)
    return min(values) if values else -1.0


def candidates(fam, snapshot=_UNSET):
    """[(account, reason-or-None), ...] in preference order. Pass an explicit
    snapshot (possibly None, meaning 'already collected and it failed') to
    avoid re-triggering collection; omit it to collect once here."""
    if snapshot is _UNSET:
        snapshot = ensure_fresh_snapshot()
    rows = _snapshot_accounts(snapshot)
    cool = cooldowns()
    now = time.time()
    reserve = registry.reserve_percent()
    ranked = []
    for index, account in enumerate(registry.ordered_for(fam)):
        if snapshot is None:
            reason = "no fresh usage snapshot — `headroom collect` failing?"
        else:
            reason = block_reason(account, fam, rows.get(account["name"]),
                                  cool, now, reserve=reserve)
        # Greatest-headroom ordering is scoped to Codex for now (Paul 2026-07-14):
        # Claude keeps its established registry-order preference so daily Claude
        # routing is unchanged; Codex picks the account with the most proven room.
        greatest_headroom = registry.family_provider(fam) == "codex"
        score = _headroom_score(rows.get(account["name"])) \
            if (reason is None and greatest_headroom) else None
        ranked.append((account, reason, index, score))
    # Eligible before blocked; then (Codex only) greatest PROVEN headroom first
    # (min of 5h/7d room); registry order as the final tie-break/Claude order.
    # Ordering never overrides eligibility — block_reason already decided that.
    ranked.sort(key=lambda entry: (entry[1] is not None,
                                   -entry[3] if entry[3] is not None else 0.0,
                                   entry[2]))
    return [(account, reason) for account, reason, _, _ in ranked]


def pick(fam):
    for account, reason in candidates(fam):
        if reason is None:
            return account
    return None


def env_key(account):
    return "CLAUDE_CONFIG_DIR" if account["provider"] == "claude" else "CODEX_HOME"


def env_pinned_account(fam):
    """The registered account an explicitly exported CLAUDE_CONFIG_DIR /
    CODEX_HOME names, or None.

    When a caller has already routed (exported the config home) before
    invoking headroom, that choice is respected as the *initial* account
    instead of being silently overridden by a second routing decision —
    rotation off it still happens normally once it caps. Only an explicit
    environment value counts; the provider default home is not a pin."""
    try:
        provider = registry.family_provider(fam)
        value = os.environ.get(
            "CLAUDE_CONFIG_DIR" if provider == "claude" else "CODEX_HOME", "")
        value = value.strip()
        if not value:
            return None
        home = os.path.realpath(os.path.expanduser(value))
        for account in registry.ordered_for(fam):
            if os.path.realpath(account["home"]) == home:
                return account
    except registry.RegistryError:
        return None
    return None


def write_launch_marker(mode, account, note=""):
    """Launch handshake for wrapper scripts: when HEADROOM_LAUNCH_MARKER names
    an absolute path, write a small JSON there at the moment routing has
    COMMITTED to launching the CLI (account selected, spawn imminent — any
    failure past this point would equally afflict a bare launch).

    A wrapper that wants a bare-CLI fallback can therefore treat "headroom
    exited and no marker exists" as "the CLI was never started" and launch
    it directly, without racing a CLI that headroom did start.

    Returns True when no marker was requested or the write succeeded. When a
    marker WAS requested and cannot be written, returns False — the caller
    must abort the launch, because proceeding would leave the wrapper's
    handshake dangling and a fallback CLI could race the real one."""
    destination = os.environ.get("HEADROOM_LAUNCH_MARKER", "").strip()
    if not destination:
        return True
    if not os.path.isabs(destination):
        print("[headroom] HEADROOM_LAUNCH_MARKER must be an absolute path — "
              "refusing to launch without the requested handshake",
              file=sys.stderr)
        return False
    payload = {
        "mode": mode,  # "supervised" | "exec"
        "account": account["name"] if account else "",
        "home": account["home"] if account else "",
        "note": note,
        "pid": os.getpid(),
        "written_at": time.time(),
    }
    # No-clobber install: the marker destination must not exist (the wrapper
    # hands us a fresh path). An env-controlled path must never be able to
    # replace an existing file — write an O_EXCL|O_NOFOLLOW temp next to the
    # destination, then hard-link it in (link fails on an existing target),
    # so readers only ever observe a complete document and nothing existing
    # is ever overwritten.
    temporary = f"{destination}.{os.getpid()}.tmp"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "w") as handle:
                json.dump(payload, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, destination)
        finally:
            try:
                os.unlink(temporary)
            except OSError:
                pass
    except OSError as error:
        print(f"[headroom] cannot write HEADROOM_LAUNCH_MARKER "
              f"({destination}): {error} — refusing to launch without the "
              f"requested handshake (the marker path must be a fresh, "
              f"non-existent file)", file=sys.stderr)
        return False
    return True


def mark(name, fam, epoch=None, account_wide=False, window="5h"):
    """Cool an account down. Session/weekly-all limits are account-wide
    (fam='*'); only genuine model-scoped caps cool a single family.
    A reset in the past is useless — clamp to a window-aware future floor
    (a weekly cap must never collapse to a session-length cooldown).
    Locked read-modify-write so a concurrent mark can't drop this limit."""
    now = time.time()
    floor = now + (6 * 3600 if window == "7d" else 15 * 60)
    default = now + (7 * 86400 if window == "7d" else 5 * 3600)
    epoch = default if epoch is None else max(float(epoch), floor)
    key = f"{name}:{'*' if account_wide else fam}"
    with _cooldown_lock():
        cool = _read_cooldowns()
        if cool is None:
            raise RuntimeError(
                "cooldown ledger unreadable — inspect/delete state/cooldowns.json")
        previous = cool.get(key)
        if previous is not None and not _number(previous):
            raise RuntimeError(
                "cooldown entry unreadable — inspect state/cooldowns.json")
        cool[key] = max(epoch, previous) if previous is not None else epoch
        save_cooldowns(cool)
    return cool[key]


def cap_scope(snapshot, name, fam, message=""):
    """Return the unambiguous >=99% cap scope for one fresh account row.

    The hook phrase narrows which provider window may corroborate the event.
    Session wording only accepts 5h; weekly wording accepts the all-model 7d
    or the requested model's scoped weekly window.  A generic usage-limit
    phrase may use any single applicable scope.  Multiple account-wide caps
    are one scope and retain their latest reset.
    """
    row = _snapshot_accounts(snapshot).get(name)
    if not isinstance(row, dict):
        return None
    windows = row.get("windows")
    if not isinstance(windows, dict):
        return None
    lower = message.lower() if isinstance(message, str) else ""
    wants_weekly = "week" in lower
    wants_session = "session" in lower or "5-hour" in lower \
        or "5 hour" in lower or "five-hour" in lower
    account_hits = []
    scoped_hit = None
    if not wants_weekly:
        window = windows.get("5h")
        if isinstance(window, dict) and _number(window.get("used_percent")) \
                and window["used_percent"] >= 99:
            account_hits.append(("5h", window))
    if not wants_session:
        window = windows.get("7d")
        if isinstance(window, dict) and _number(window.get("used_percent")) \
                and window["used_percent"] >= 99:
            account_hits.append(("7d", window))
        scoped = scoped_window_for(fam, windows) if fam in (
            "opus", "sonnet", "haiku", "fable") else None
        if isinstance(scoped, dict) and _number(scoped.get("used_percent")) \
                and scoped["used_percent"] >= 99:
            scoped_hit = scoped
    if account_hits:
        resets = [window.get("resets_at") for _, window in account_hits
                  if _number(window.get("resets_at"))]
        used = max(window["used_percent"] for _, window in account_hits)
        return {
            "key": f"{name}:*", "account_wide": True,
            "family": fam, "window": "7d" if any(
                key == "7d" for key, _ in account_hits) else "5h",
            "used_percent": float(used),
            "reset": max(resets) if resets else None,
        }
    if scoped_hit is not None:
        return {
            "key": f"{name}:{fam}", "account_wide": False,
            "family": fam, "window": "scoped:" + fam,
            "used_percent": float(scoped_hit["used_percent"]),
            "reset": scoped_hit.get("resets_at")
            if _number(scoped_hit.get("resets_at")) else None,
        }
    return None


def earliest_reset(snapshot, fam=None, exclude=None):
    """Earliest readable future reset, for a useful fail-closed hint."""
    now = time.time()
    values = []
    for name, row in _snapshot_accounts(snapshot).items():
        if name == exclude:
            continue
        windows = row.get("windows") if isinstance(row, dict) else None
        if not isinstance(windows, dict):
            continue
        candidates_ = [windows.get("5h"), windows.get("7d")]
        if fam:
            candidates_.append(scoped_window_for(fam, windows))
        for window in candidates_:
            reset = window.get("resets_at") if isinstance(window, dict) else None
            if _number(reset) and reset > now:
                values.append(reset)
    return min(values) if values else None


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
        if process.returncode != 0 and account["provider"] == "codex":
            # Codex failures are classified, never blind-replayed: an
            # arbitrary command may have side effects, and rollout-resume
            # replay is a later phase. Cool/quarantine/back off as the class
            # demands and report — the caller re-runs to use the next seat.
            sys.stdout.write(process.stdout or "")
            sys.stderr.write(process.stderr or "")
            return _codex_run_failure(fam, account, snapshot, process)
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


def _codex_run_failure(fam, account, snapshot, process):
    """Classify a failed codex child and take the matching protective action.
    Never replays the command; always returns the child's exit code."""
    kind = classify_codex_failure(process.stderr or "")
    name = account["name"]
    if kind == "subscription_cap":
        window_key = "7d" if WEEKLY_RE.search(process.stderr or "") else "5h"
        reset = window_reset(snapshot, name, window_key) \
            or time.time() + (7 * 86400 if window_key == "7d" else 5 * 3600)
        reset = mark(name, fam, reset, account_wide=True, window=window_key)
        successor = pick(fam)
        follow_up = (f"next seat with proven headroom: {successor['name']} — "
                     f"re-run to use it (codex commands are never auto-replayed)"
                     if successor else
                     "no other codex seat has proven headroom")
        print(f"[headroom] {name} hit its {window_key} subscription cap -> "
              f"cooled until {tfmt(reset)}; {follow_up}", file=sys.stderr)
    elif kind == "auth_invalid":
        # auth is not capacity: quarantine (re-login required), NO cooldown
        quarantine_mark(name, "codex auth rejected "
                              "(token invalidated / login required)")
        print(f"[headroom] {name} auth was rejected -> quarantined (no "
              f"capacity cooldown); run `headroom connect {name}` to re-login",
              file=sys.stderr)
    elif kind == "overload":
        # provider-wide transient: back the provider off, cool NO account
        collector.persist_provider_backoff("codex_app_server",
                                           time.time() + 300)
        print(f"[headroom] provider overload/429 -> codex backoff set; "
              f"{name} NOT cooled, not rotating", file=sys.stderr)
    elif kind == "network":
        print(f"[headroom] network-ambiguous failure on {name} -> holding "
              f"(no cooldown, no rotation)", file=sys.stderr)
    else:
        # regex/classifier found no provider signal: an ordinary failed
        # command must never trigger rotation or protective state
        print(f"[headroom] completed on {name} (exit {process.returncode})",
              file=sys.stderr)
    return process.returncode


def bare_fallback_exec(command, reason, env=None):
    """Opt-in last resort (--headroom-launch-fallback / HEADROOM_LAUNCH_FALLBACK=1):
    exec the BARE CLI in this process after a failure that happened strictly
    BEFORE any child CLI was started, so a caller never needs an external
    fallback to guarantee "a CLI runs". `command` is the CLI argv with
    headroom's own flags already removed. This must never run once a CLI has
    been spawned — a later child exit, clean or capped, is a normal exit.

    Falling back means using NO routed account, so any lease this process
    committed is released (a concurrent launch may take that account) and the
    bare CLI is exec'd with the ORIGINAL environment (`env`) — never the
    routed env with its scrubbed auth vars and pinned CLAUDE_CONFIG_DIR."""
    release_slot_leases()
    notify.emit({"event": "fallback", "reason": str(reason)})
    print(f"[headroom] launch fallback: {reason} — running bare "
          f"`{command[0]}` without routing", file=sys.stderr)
    environment = os.environ if env is None else env
    try:
        os.execvpe(command[0], command, environment)
    except OSError as error:
        print(f"[headroom] fallback exec of {command[0]} failed: {error}",
              file=sys.stderr)
        return 127
    return 0  # unreachable outside tests: a successful exec never returns


def cmd_exec(fam, command, launch_note="", fallback=False):
    """Interactive launch: pick once, exec with the account's env, no capture.

    `launch_note` is recorded in the launch marker (see write_launch_marker)
    so a wrapper can see WHY this run is exec-only (e.g. an auto-handoff
    downgrade reason); it changes nothing else.

    `fallback` (opt-in) execs the bare CLI in-process when the launch fails
    strictly BEFORE the CLI was started. Reaching exec is the boundary: a
    successful exec replaces this process, so any return from the routed
    path (other than the test-only 0 sentinel) proves no CLI ever started.
    The bare fallback preserves the ORIGINAL environment captured here,
    before _exec_routed scrubs/pins anything."""
    if not fallback:
        return _exec_routed(fam, command, launch_note)
    # everything after the fallback intent is established runs inside the
    # guard — including the environment snapshot — so even an env-copy failure
    # still bare-execs when the fallback was requested (P1-4)
    original_env = None
    try:
        original_env = dict(os.environ)
        result = _exec_routed(fam, command, launch_note)
    except Exception as error:  # noqa: BLE001 — opt-in: pre-spawn failures fall back
        return bare_fallback_exec(command, f"launch failed: {error}",
                                  env=original_env)
    if result == 0:
        # only reachable when exec was stubbed under test — a real exec never
        # returns; the CLI is running, so there is nothing to fall back from
        return 0
    return bare_fallback_exec(
        command, f"headroom exited {result} before the CLI started",
        env=original_env)


def _exec_routed(fam, command, launch_note=""):
    if registry.family_provider(fam) == "codex" and not CODEX_ROUTING_ENABLED:
        # fail-closed: disabled routing means headroom REFUSES to launch a
        # Codex seat it cannot prove capacity for — never "just take the
        # first account". Run `CODEX_HOME=<home> codex` directly to bypass.
        print("[headroom] Codex routing is disabled (HEADROOM_CODEX_ROUTING=0)"
              " — refusing to launch without proven headroom; unset it, or "
              "run codex directly with CODEX_HOME=<home> to bypass headroom",
              file=sys.stderr)
        return 2
    # an explicitly exported config home that names a registered account is
    # the caller's routing decision — consume it instead of re-routing, as
    # long as it still has proven headroom
    account = None
    pinned = env_pinned_account(fam)
    if pinned is not None:
        snapshot = ensure_fresh_snapshot()
        reason = block_reason(pinned, fam,
                              _snapshot_accounts(snapshot).get(pinned["name"]),
                              cooldowns(), time.time())
        if reason is None:
            account = pinned
        else:
            print(f"[headroom] env-selected account {pinned['name']} is not "
                  f"routable ({reason}) — picking another", file=sys.stderr)
    if account is None:
        account = pick(fam)
        if account is None:
            print(f"[headroom] no account for '{fam}' has proven headroom; "
                  f"try `headroom status {fam}`", file=sys.stderr)
            return 2
        # final recheck against the latest cooldown ledger right before exec,
        # in case another process cooled this account since pick(). NEVER fall
        # back to a held account — re-pick, and refuse to launch if nothing is
        # eligible. (For codex this recheck also re-derives the local binding
        # + refresh lineage via block_reason's _codex_gate — the targeted
        # pre-launch check.)
        snapshot = ensure_fresh_snapshot()
        row = _snapshot_accounts(snapshot).get(account["name"])
        if block_reason(account, fam, row, cooldowns(), time.time()):
            account = pick(fam)
            if account is None:
                print("[headroom] the chosen account was just held and no "
                      "other has proven headroom — try again in a moment",
                      file=sys.stderr)
                return 2
    # commit: take the slot flock (no-op unless HEADROOM_SLOT_LEASE=1) so a
    # concurrent launch deterministically picks a different account; on the
    # rare claim race, re-pick once — block_reason now sees the foreign lease.
    # A LeaseError (infrastructure failure) FAILS CLOSED: refuse rather than
    # launch unleased. With --headroom-launch-fallback the cmd_exec wrapper
    # then turns that refusal into a bare-CLI last resort (the caller's
    # explicit opt-in to "run something over nothing").
    try:
        if not acquire_slot_lease(account, fam):
            print(f"[headroom] {account['name']} is leased by another live "
                  f"launch — picking another", file=sys.stderr)
            account = pick(fam)
            if account is None or not acquire_slot_lease(account, fam):
                print(f"[headroom] no unleased account for '{fam}' has proven "
                      f"headroom", file=sys.stderr)
                return 2
    except LeaseError as error:
        print(f"[headroom] slot lease unavailable ({error}); refusing to "
              f"launch — HEADROOM_SLOT_LEASE=1 fails closed", file=sys.stderr)
        return 2
    for var in collector.AUTH_OVERRIDE_VARS:
        os.environ.pop(var, None)
    os.environ[env_key(account)] = account["home"]
    print(f"[headroom] {fam} -> {account['name']} ({account['home']})",
          file=sys.stderr)
    if not write_launch_marker("exec", account, note=launch_note):
        return 2
    if launch_note:
        # supervision was requested/configured but this run is exec-only —
        # tell the observer WHY, bound to the account actually launched
        notify.emit({"event": "downgrade", "account": account["name"],
                     "reason": launch_note})
    notify.emit({"event": "launch", "mode": "exec",
                 "account": account["name"], "model": fam,
                 "note": launch_note})
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
    return 0  # unreachable outside tests: a successful exec never returns


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
