"""Account registry: load, validate, and query config.json.

The registry is intentionally boring. Each account is a named *slot* bound to
one provider and one isolated CLI config home. Identity (email, plan) is
*discovered* from the provider at collect time, never trusted from config —
config only records what the operator expects, so a clobbered login can be
detected.

Config shape (schema_version 1)::

    {
      "schema_version": 1,
      "dashboard": {"theme": "midnight", "title": "AI Fleet",
                     "redact_emails": false, "port": 8377},
      "accounts": [
        {"name": "personal", "provider": "claude",
         "home": "~/.claude",  # or ~/.headroom/homes/personal
         "expected_email": "me@example.com"}   # optional but recommended
      ]
    }
"""
import contextlib
import fcntl
import os
import re

from . import paths

PROVIDERS = ("claude", "codex")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
DEFAULT_DASHBOARD = {
    "theme": "midnight",
    "title": "AI Fleet",
    "redact_emails": True,
    "port": 8377,
}

# Model-family -> provider. `pick`/`run` accept any model string; family()
# reduces it to one of these.
FAMILY_PROVIDER = {
    "opus": "claude",
    "sonnet": "claude",
    "haiku": "claude",
    "fable": "claude",
    "claude": "claude",
    "codex": "codex",
    "gpt": "codex",
}


class RegistryError(ValueError):
    pass


def family(model):
    model = (model or "").lower().strip()
    for name in ("fable", "opus", "sonnet", "haiku", "codex", "gpt"):
        if name in model:
            return "codex" if name == "gpt" else name
    if not model or "claude" in model:
        return "claude"
    # An unknown model must not silently route as generic Claude — a typo'd
    # scoped model would bypass its own weekly cap.
    raise RegistryError(
        f"unknown model family: {model!r} (use opus/sonnet/haiku/claude/codex)")


def family_provider(fam):
    return FAMILY_PROVIDER.get(fam, "claude")


def expand(path):
    # realpath so two paths that resolve to the same home (one via a symlink)
    # canonicalize identically for storage and duplicate detection
    return os.path.realpath(os.path.abspath(os.path.expanduser(path)))


def validate(config):
    if not isinstance(config, dict) or config.get("schema_version") != 1:
        raise RegistryError("config.json missing or wrong schema_version (expected 1)")
    accounts = config.get("accounts")
    if not isinstance(accounts, list) or not accounts:
        raise RegistryError("config.json has no accounts; run `headroom setup`")
    names, homes = set(), set()
    for account in accounts:
        if not isinstance(account, dict):
            raise RegistryError("account entries must be objects")
        name = account.get("name")
        provider = account.get("provider")
        home = account.get("home")
        if not isinstance(name, str) or not name or name in names:
            raise RegistryError(f"account name missing/duplicate: {name!r}")
        if not NAME_RE.fullmatch(name):
            raise RegistryError(
                f"account name {name!r} invalid: lowercase letters, digits, "
                f"- and _ only (max 32 chars)")
        if provider not in PROVIDERS:
            raise RegistryError(f"account {name}: provider must be one of {PROVIDERS}")
        if not isinstance(home, str) or not home:
            raise RegistryError(f"account {name}: home missing")
        resolved = expand(home)
        if resolved in homes:
            raise RegistryError(f"account {name}: home {resolved} already used by another account")
        names.add(name)
        homes.add(resolved)
    return config


def load():
    path = paths.config_path()
    if not os.path.exists(path):
        raise RegistryError(f"no config at {path}; run `headroom setup` first")
    config = paths.load_json(path)
    if config is None:
        raise RegistryError(
            f"config at {path} exists but is unreadable or not valid JSON; "
            f"fix or delete it, then run `headroom setup`")
    return validate(config)


def accounts(config=None):
    config = load() if config is None else config
    result = []
    for account in config["accounts"]:
        row = dict(account)
        row["home"] = expand(row["home"])
        result.append(row)
    return result


def dashboard_settings(config=None):
    config = load() if config is None else config
    settings = dict(DEFAULT_DASHBOARD)
    settings.update(config.get("dashboard") or {})
    # coerce a wrong-typed port so it can never reach the socket bind as a str
    try:
        port = int(settings.get("port", 8377))
        settings["port"] = port if 1 <= port <= 65535 else 8377
    except (TypeError, ValueError):
        settings["port"] = 8377
    return settings


def ordered_for(fam, config=None):
    """Accounts eligible for a model family, in registry (preference) order."""
    provider = family_provider(fam)
    return [account for account in accounts(config) if account["provider"] == provider]


def reserve_percent(config=None):
    """Minimum % of headroom an account must have LEFT to be routable.

    0 (default) = use every account down to its limit. Set e.g. 10 to skip any
    account with under 10% left so a session starts fresh instead of hitting a
    wall mid-task. Read from config['routing']['reserve_percent'], clamped to
    [0, 99]. Never raises — an unreadable/absent config yields 0.0 so routing
    degrades to the default behaviour."""
    try:
        config = load() if config is None else config
    except RegistryError:
        return 0.0
    routing = (config or {}).get("routing")
    if not isinstance(routing, dict):
        return 0.0
    try:
        value = float(routing.get("reserve_percent", 0))
    except (TypeError, ValueError):
        return 0.0
    return value if 0 <= value <= 99 else 0.0


def auto_handoff(config=None):
    """Whether the supervisor may hand a capped session off automatically.

    ON by default — uninterrupted continuation is the product.  Only an
    explicit ``routing.auto_handoff: false`` turns it off; every guard in the
    supervisor itself stays fail-closed, so ambiguity degrades to a plain
    launch rather than any destructive action.  A wrong-typed value (e.g. the
    string ``"false"``) keeps the default rather than guessing intent.
    """
    try:
        config = load() if config is None else config
    except RegistryError:
        return True
    routing = (config or {}).get("routing")
    if isinstance(routing, dict) and routing.get("auto_handoff") is False:
        return False
    return True


def save(config):
    validate(config)
    paths.write_json_atomic(paths.config_path(), config, mode=0o600)


@contextlib.contextmanager
def config_lock():
    lock_path = paths.config_path() + ".lock"
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    handle = open(lock_path, "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


def mutate(fn):
    """Locked reload-mutate-validate-save. Raises RegistryError if the config
    doesn't exist or is corrupt (never creates/overwrites here). Use for every
    non-interactive config write so concurrent writers can't lose each other."""
    with config_lock():
        config = load()
        fn(config)
        save(config)
        return config


def apply_pins(pins):
    """Record usage-org pins WITHOUT clobbering a concurrent account add:
    take the config lock, reload the latest config, merge pins by slot name,
    save. A collector that loaded a stale config can no longer delete an
    account that `connect` added in the meantime."""
    pins = {name: value for name, value in (pins or {}).items() if value}
    if not pins:
        return
    with config_lock():
        config = load()
        changed = False
        for entry in config["accounts"]:
            if entry["name"] in pins and not entry.get("pinned_usage_org"):
                entry["pinned_usage_org"] = pins[entry["name"]]
                changed = True
        if changed:
            save(config)
