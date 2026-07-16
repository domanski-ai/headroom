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
    os.chmod(directory, 0o700)
    return directory


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


def purge_pending_path():
    return os.path.join(history_dir(), "purge-pending.json")


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
    """Write JSON so readers never observe a partial file."""
    ensure_private(base_dir())
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".headroom-", suffix=".json.tmp", dir=directory
    )
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w") as handle:
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
