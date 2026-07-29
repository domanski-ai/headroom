"""Filesystem layout and atomic JSON I/O.

Everything headroom owns lives under one directory (default ``~/.headroom``,
override with ``HEADROOM_DIR``):

    config.json          account registry + dashboard preferences
    homes/<name>/        isolated CLI config home per connected account
    state/               snapshots, cooldowns, backoff ledgers (private)
    state/public/        the sanitized snapshot + dashboard build
"""
import json
import os
import stat
import tempfile


def env_int(name, default):
    """Tolerant module-level env int: a malformed value degrades to the
    default instead of raising at import time. Import-time strictness would
    make a stray env var (e.g. HEADROOM_IDENTITY_TIMEOUT=bad) crash the whole
    binary — including read-only commands like `headroom caps` — so every
    module-level HEADROOM_* numeric parse routes through here."""
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return int(default)


def base_dir():
    raw = os.environ.get("HEADROOM_DIR") or "~/.headroom"
    expanded = os.path.expanduser(raw)
    # A relative HEADROOM_DIR would resolve against the current directory, so
    # state/credentials would scatter per-cwd and the cooldown belt would be
    # silently forgotten from a new directory. Refuse it rather than normalize.
    if not os.path.isabs(expanded):
        raise ValueError(
            f"HEADROOM_DIR must be an absolute path (got {raw!r})")
    return os.path.abspath(expanded)


def ensure_private(directory):
    os.makedirs(directory, exist_ok=True)
    chmod_private(directory, 0o700)
    return directory


# A POSIX ACL keeps its MASK in the group bits, and chmod rewrites that mask
# from whatever group bits it is handed. So an unconditional `chmod 0700`
# silently strips every named grant on the path: getfacl still lists the entry
# and it grants nothing (`user:svc:r-x  #effective:---`). ensure_private runs
# on every supervisor tick, so a grant an operator applied and verified green
# decays minutes later with no error anywhere — observed 2026-07-27 on
# state/, granted to a read-only HTTP service under its own uid.
ACL_MASK_BITS = 0o070
# ONLY the access ACL. A DEFAULT ACL is a template for files created inside a
# directory — it grants nothing on the directory itself, its group bits are
# not a mask for anyone's access to it, and chmod does not touch it. Treating
# it as licence to keep group bits left a 0750 state directory at 0750 where
# the old code enforced 0700: a privacy regression, not a preserved grant.
ACL_XATTRS = ("system.posix_acl_access",)
# ...and the presence of an access ACL is not consent either. A directory
# created under a parent carrying a DEFAULT ACL is BORN with an access ACL its
# owner never asked for, so "there is an ACL here" cannot be read as "an
# operator granted this deliberately": under a parent with a default
# `u:nobody:rwx`, inferring consent published ~/.headroom and ~/.headroom/state
# at 0770 — a foreign uid able to read the state directory — where the plain
# chmod gives 0700. So the relaxation is stated, never inferred: the operator
# who set the grant sets this too, and everyone else keeps the old
# unconditional private mode.
PRESERVE_ACL_ENV = "HEADROOM_PRESERVE_ACL"


def preserve_acl(environ=None):
    """Whether the operator asked for POSIX ACL masks to survive chmod."""
    environ = os.environ if environ is None else environ
    return str(environ.get(PRESERVE_ACL_ENV, "")).strip() == "1"


def _extended_acl(target):
    """Whether ``target`` (a path or an open descriptor) carries a POSIX
    ACCESS ACL beyond its mode bits.

    Linux only, via the xattr the kernel stores the ACL in — there is no ACL
    in the stdlib. Everywhere else (macOS's NFSv4 ACLs included) this reports
    False and the mode is enforced exactly as it always was: this may only
    ever RELAX enforcement where an ACL is provably present."""
    lister = getattr(os, "listxattr", None)
    if lister is None:
        return False
    try:
        names = lister(target)
    except OSError:
        # no xattr support, or the mode cannot be read: enforce, don't guess
        return False
    return any(name in names for name in ACL_XATTRS)


def _apply_mode(target, mode, stat_fn, chmod_fn):
    """chmod ``target`` to ``mode`` only when that changes something.

    Two jobs. The cheap one: skip the syscall when the mode is already right,
    which is the overwhelmingly common case. The other one, and only with
    ``HEADROOM_PRESERVE_ACL=1``: when the path carries an access ACL, enforce
    the OWNER and OTHER bits and pass the current group bits straight back
    through, so the mask survives and a grant the operator made deliberately
    is not collateral damage.

    That opt-in DOES relax the mode headroom would otherwise enforce — group
    access is whatever the ACL's mask says, on every path this touches,
    credential homes included. Without it the mode is applied exactly as it
    always was."""
    try:
        current = stat.S_IMODE(stat_fn(target).st_mode)
    except OSError:
        # unreadable: fall through so the chmod raises what it always raised
        chmod_fn(target, mode)
        return
    if current == mode:
        return
    wanted = mode
    if preserve_acl() and _extended_acl(target):
        wanted = (mode & ~ACL_MASK_BITS) | (current & ACL_MASK_BITS)
        if wanted == current:
            return
    chmod_fn(target, wanted)


def chmod_private(path, mode):
    """Apply owner-only permissions where POSIX modes are meaningful."""
    if os.name != "nt":
        _apply_mode(path, mode, os.stat, os.chmod)


def fchmod_private(descriptor, mode):
    """Descriptor form of :func:`chmod_private`; a no-op on Windows."""
    if os.name != "nt":
        _apply_mode(descriptor, mode, os.fstat, os.fchmod)


def config_path():
    return os.path.join(base_dir(), "config.json")


def homes_dir():
    return os.path.join(base_dir(), "homes")


def state_dir():
    return os.path.join(base_dir(), "state")


def public_dir():
    return os.path.join(state_dir(), "public")


def history_dir():
    return os.path.join(state_dir(), "history")


def history_path():
    return os.path.join(history_dir(), "usage-history.jsonl")


def tokens_dir():
    return os.path.join(state_dir(), "tokens")


def token_scan_state_path():
    return os.path.join(tokens_dir(), "scan-state.json")


def token_daily_path():
    return os.path.join(tokens_dir(), "daily.json")


def token_scan_lock_path():
    return os.path.join(tokens_dir(), "scan.lock")


def private_snapshot_path():
    return os.path.join(state_dir(), "usage-private.json")


def public_snapshot_path():
    return os.path.join(public_dir(), "usage.json")


def cooldowns_path():
    return os.path.join(state_dir(), "cooldowns.json")


def backoff_path():
    return os.path.join(state_dir(), "provider-backoff.json")


def quarantine_path():
    return os.path.join(state_dir(), "quarantine.json")


def collect_lock_path():
    return os.path.join(state_dir(), "collect.lock")


def load_json(path):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def write_json_atomic(path, value, mode=0o600):
    """Write JSON so readers never observe a partial file.

    NOTE for operators: an ACL set on one of these FILES cannot survive this.
    The write lands on a fresh temp inode and `os.replace` swaps it in, so the
    old file's ACL goes with the old inode — no chmod involved and nothing
    here can preserve it. Grant on the containing DIRECTORY instead (that
    inode is stable, and with ``HEADROOM_PRESERVE_ACL=1`` set,
    :func:`chmod_private` leaves its mask alone)."""
    ensure_private(base_dir())
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".headroom-", suffix=".json.tmp", dir=directory
    )
    try:
        fchmod_private(descriptor, mode)
        # byte-exact output on every platform: UTF-8 and bare \n — Windows
        # text-mode CRLF translation and locale encodings would otherwise
        # shift the byte offsets and sizes the persistence math depends on
        with os.fdopen(descriptor, "w", encoding="utf-8",
                       newline="\n") as handle:
            json.dump(value, handle, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
