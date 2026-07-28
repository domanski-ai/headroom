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
                     "redact_emails": false, "port": 8377,
                     "token_extra_roots": [
                       {"label": "server-cli", "provider": "claude",
                        "path": "/home/me/.claude"}
                     ]},
      "accounts": [
        {"id": "3f62ad91b7c4", "name": "personal", "provider": "claude",
         "home": "~/.claude",  # or ~/.headroom/homes/personal
         "expected_email": "me@example.com",  # optional but recommended
         "reserved": false}    # optional: true = tracked but never routed to
      ]
    }

A ``reserved: true`` account is still collected and shown on the dashboard,
but routing never selects it: not for `pick`/`env`, not as a launch account,
and never as a rotation/handoff target. Use it for a slot that belongs to
some other workflow and must not be consumed by automatic rotation.
"""
import contextlib
import hashlib
import os
import re
import uuid

from . import locks, paths

PROVIDERS = ("claude", "codex")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
ID_RE = re.compile(r"^[0-9a-f]{12,32}$")
VIRTUAL_ID_RE = re.compile(r"^x-[0-9a-f]{24}$")
DEFAULT_DASHBOARD = {
    "theme": "midnight",
    "title": "AI Fleet",
    "redact_emails": True,
    "port": 8377,
    "token_stats": False,
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


def virtual_slot_id(label, provider, home):
    """Return the stable, non-registry namespace ID for an extra token root."""
    identity = "\0".join((label, provider, expand(home)))
    return "x-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def _token_extra_root_entries(config):
    dashboard = config.get("dashboard")
    if not isinstance(dashboard, dict) \
            or "token_extra_roots" not in dashboard:
        return []
    entries = dashboard["token_extra_roots"]
    if not isinstance(entries, list):
        raise RegistryError("dashboard.token_extra_roots must be a list")
    labels = {account.get("name") for account in config.get("accounts", [])}
    roots = {expand(account["home"])
             for account in config.get("accounts", [])
             if isinstance(account, dict)
             and isinstance(account.get("home"), str)}
    derived_ids = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise RegistryError("dashboard.token_extra_roots entries must be objects")
        label = entry.get("label")
        if not isinstance(label, str) or not 1 <= len(label) <= 40 \
                or "@" in label:
            raise RegistryError(
                "token extra-root label must be 1-40 characters without @")
        if label in labels:
            raise RegistryError(f"token extra-root label duplicate: {label!r}")
        provider = entry.get("provider")
        if provider not in PROVIDERS:
            raise RegistryError(
                f"token extra-root {label}: provider must be one of {PROVIDERS}")
        home = entry.get("path")
        if isinstance(home, str):
            root = expand(home)
            if root in roots:
                raise RegistryError(
                    f"token extra-root {label}: canonical root already used")
            derived_id = virtual_slot_id(label, provider, root)
            if derived_id in derived_ids:
                raise RegistryError(
                    f"token extra-root {label}: duplicate derived id")
            roots.add(root)
            derived_ids.add(derived_id)
        labels.add(label)
    return entries


def validate(config):
    if not isinstance(config, dict) or config.get("schema_version") != 1:
        raise RegistryError("config.json missing or wrong schema_version (expected 1)")
    accounts = config.get("accounts")
    if not isinstance(accounts, list) or not accounts:
        raise RegistryError("config.json has no accounts; run `headroom setup`")
    names, homes, ids = set(), set(), set()
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
        slot_id = account.get("id")
        if slot_id is not None:
            if not isinstance(slot_id, str) or not ID_RE.fullmatch(slot_id):
                raise RegistryError(
                    f"account {name}: id must be 12-32 lowercase hex characters")
            if slot_id in ids:
                raise RegistryError(f"account {name}: duplicate id {slot_id!r}")
            ids.add(slot_id)
        # Optional fields, including generation IDs, remain load-compatible so
        # a collector can backfill legacy configs under the normal config lock.
        if "shared_desktop" in account \
                and not isinstance(account["shared_desktop"], bool):
            raise RegistryError(
                f"account {name}: shared_desktop must be true or false")
        if "reserved" in account \
                and not isinstance(account["reserved"], bool):
            raise RegistryError(
                f"account {name}: reserved must be true or false")
        if "handoff_group" in account:
            group = account["handoff_group"]
            if not isinstance(group, str) or not group.strip():
                raise RegistryError(
                    f"account {name}: handoff_group must be a non-empty string")
        resolved = expand(home)
        if resolved in homes:
            raise RegistryError(f"account {name}: home {resolved} already used by another account")
        names.add(name)
        homes.add(resolved)
    _token_extra_root_entries(config)
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


def token_extra_roots(config=None, include_status=False):
    """Project usable configured token roots as virtual account-shaped rows.

    A path can disappear after config validation, so unusable paths are skipped
    and reported as partial instead of making the whole registry unloadable.
    """
    config = load() if config is None else config
    result = []
    partial = False
    for entry in _token_extra_root_entries(config):
        path = entry.get("path")
        if not isinstance(path, str) or not os.path.isabs(path) \
                or not os.path.isdir(path):
            partial = True
            continue
        label = entry["label"]
        result.append({
            "id": virtual_slot_id(label, entry["provider"], path),
            "name": label,
            "provider": entry["provider"],
            "home": expand(path),
        })
    return (result, partial) if include_status else result


def token_accounts(config=None, include_status=False):
    """Registry slots plus virtual extra roots for token scanning and feeds."""
    config = load() if config is None else config
    extra, partial = token_extra_roots(config, include_status=True)
    result = accounts(config) + extra
    return (result, partial) if include_status else result


def new_slot_id(config):
    """Return a generation ID not already present in this registry view."""
    existing = {account.get("id") for account in config.get("accounts", [])}
    while True:
        candidate = uuid.uuid4().hex
        if candidate not in existing:
            return candidate


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


def token_stats_enabled(config=None):
    """True only for the explicit local-token telemetry opt-in."""
    if os.environ.get("HEADROOM_TOKEN_STATS") == "1":
        return True
    try:
        config = load() if config is None else config
    except RegistryError:
        return False
    dashboard = (config or {}).get("dashboard")
    return isinstance(dashboard, dict) and dashboard.get("token_stats") is True


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


PREEMPTIVE_SCOPED_PERCENT = 93.0
PREEMPTIVE_OVERALL_PERCENT = 95.0


def preemptive_handoff(config=None):
    """Whether the supervisor may rotate BEFORE a seat hits the wall.

    ON by default — the product promise is that the operator never has to
    watch a percentage.  ``HEADROOM_PREEMPTIVE=0`` is the operator kill
    switch (no config edit needed) and an explicit
    ``routing.preemptive_handoff: false`` turns it off permanently.  Like
    :func:`auto_handoff`, a wrong-typed value keeps the default rather than
    guessing intent, and every guard downstream stays fail-closed: a
    preemptive refusal only defers, it never disarms the cap-reactive path.
    """
    if os.environ.get("HEADROOM_PREEMPTIVE", "").strip() == "0":
        return False
    try:
        config = load() if config is None else config
    except RegistryError:
        return True
    routing = (config or {}).get("routing")
    if isinstance(routing, dict) and routing.get("preemptive_handoff") is False:
        return False
    return True


def _threshold(routing, key, default):
    try:
        value = float(routing.get(key, default))
    except (TypeError, ValueError):
        return default
    # a threshold outside (0, 100] can never describe a usable crossing —
    # keep the default rather than arming (or disarming) on nonsense
    return value if 0 < value <= 100 else default


def preemptive_thresholds(config=None):
    """``(scoped %, overall 7d %)`` at which a seat is rotated off early.

    Defaults 93 / 95: the model-family-scoped weekly window (e.g. fable) is
    the one that strands an interactive session first, so it trips earlier
    than the all-model 7d window.  Read from
    ``config['routing']['preemptive_scoped_percent']`` and
    ``...['preemptive_overall_percent']``.  Never raises — an unreadable or
    absent config yields the defaults."""
    try:
        config = load() if config is None else config
    except RegistryError:
        return PREEMPTIVE_SCOPED_PERCENT, PREEMPTIVE_OVERALL_PERCENT
    routing = (config or {}).get("routing")
    if not isinstance(routing, dict):
        return PREEMPTIVE_SCOPED_PERCENT, PREEMPTIVE_OVERALL_PERCENT
    return (_threshold(routing, "preemptive_scoped_percent",
                       PREEMPTIVE_SCOPED_PERCENT),
            _threshold(routing, "preemptive_overall_percent",
                       PREEMPTIVE_OVERALL_PERCENT))


# The 5-hour window is a DIFFERENT kind of wall from the weekly ones, so it
# gets its own, higher threshold rather than a share of theirs.  A weekly
# window that fills is gone for days — leaving early is nearly free.  A 5h
# window heals by itself within hours, so rotating off one costs a restart to
# buy back a few minutes unless the seat really is about to refuse.  97% is
# late enough that the wall is imminent and early enough to leave through the
# front door instead of mid-turn.
PREEMPTIVE_SESSION_PERCENT = 97.0


def preemptive_session(config=None):
    """Whether a 5-hour window may trigger an early rotation at all.

    ON by default: continuous autonomous work hits the 5h wall mid-task, and
    "the 5h heals on its own" is only true for a session that can afford to
    sit and wait.  ``HEADROOM_PREEMPTIVE_SESSION=0`` is the one-run kill
    switch for JUST this trigger (``HEADROOM_PREEMPTIVE=0`` still disables
    every preemptive rotation), and ``routing.preemptive_session_handoff:
    false`` turns it off permanently.  Turning it off never turns off the 5h
    TARGET rule: an exhausted seat is never a destination either way."""
    if os.environ.get("HEADROOM_PREEMPTIVE_SESSION", "").strip() == "0":
        return False
    try:
        config = load() if config is None else config
    except RegistryError:
        return True
    routing = (config or {}).get("routing")
    if isinstance(routing, dict) \
            and routing.get("preemptive_session_handoff") is False:
        return False
    return True


def preemptive_session_threshold(config=None):
    """The 5h % at which a session is moved off a seat, default 97.

    Read from ``config['routing']['preemptive_session_percent']``.  Never
    raises, and nonsense keeps the default — same contract as
    :func:`preemptive_thresholds`."""
    try:
        config = load() if config is None else config
    except RegistryError:
        return PREEMPTIVE_SESSION_PERCENT
    routing = (config or {}).get("routing")
    if not isinstance(routing, dict):
        return PREEMPTIVE_SESSION_PERCENT
    return _threshold(routing, "preemptive_session_percent",
                      PREEMPTIVE_SESSION_PERCENT)


CONTEXT_BACKSTOP_PERCENT = 10.0


def context_backstop(config=None):
    """Whether the supervisor may force a lossless rotation on a session that
    is nearly out of CONTEXT (not usage).

    ON by default, and independent of :func:`preemptive_handoff` — the two
    answer different questions (is this seat spent? is this conversation
    full?).  ``HEADROOM_CONTEXT_BACKSTOP=0`` is the operator kill switch and
    ``routing.context_backstop: false`` turns it off permanently.  Every guard
    downstream stays fail-closed and a refusal only defers."""
    if os.environ.get("HEADROOM_CONTEXT_BACKSTOP", "").strip() == "0":
        return False
    try:
        config = load() if config is None else config
    except RegistryError:
        return True
    routing = (config or {}).get("routing")
    if isinstance(routing, dict) and routing.get("context_backstop") is False:
        return False
    return True


def context_backstop_percent(config=None):
    """Remaining-context percent at which the backstop fires (default 10).

    Deliberately far below the cooperative handoff threshold: a session is
    expected to notice its own context and write a baton long before this, and
    a backstop that fired first would replace a considered handoff with a
    mechanical one.  Read from ``config['routing']['context_backstop_percent']``
    and never raises."""
    try:
        config = load() if config is None else config
    except RegistryError:
        return CONTEXT_BACKSTOP_PERCENT
    routing = (config or {}).get("routing")
    if not isinstance(routing, dict):
        return CONTEXT_BACKSTOP_PERCENT
    return _threshold(routing, "context_backstop_percent",
                      CONTEXT_BACKSTOP_PERCENT)


def save(config):
    validate(config)
    paths.write_json_atomic(paths.config_path(), config, mode=0o600)


@contextlib.contextmanager
def config_lock():
    lock_path = paths.config_path() + ".lock"
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    handle = open(lock_path, "a+")
    try:
        locks.exclusive(handle)
        yield
    finally:
        locks.unlock(handle)
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


def remove_account(name):
    """Atomically remove one non-final slot and return its former entry."""
    removed = []

    def _remove(config):
        accounts = config["accounts"]
        match = next((account for account in accounts
                      if account.get("name") == name), None)
        if match is None:
            raise RegistryError(f"no connected account named {name!r}")
        if len(accounts) == 1:
            raise RegistryError("refusing to remove the final connected account")
        config["accounts"] = [account for account in accounts
                              if account.get("name") != name]
        removed.append(dict(match))

    mutate(_remove)
    return removed[0]


def apply_pins(pins):
    """Merge pins and backfill slot IDs against the latest locked registry."""
    pins = {name: value for name, value in (pins or {}).items() if value}
    with config_lock():
        config = load()
        changed = False
        for entry in config["accounts"]:
            if not entry.get("id"):
                entry["id"] = new_slot_id(config)
                changed = True
            if entry["name"] in pins and not entry.get("pinned_usage_org"):
                entry["pinned_usage_org"] = pins[entry["name"]]
                changed = True
        if changed:
            save(config)
        return accounts(config)
