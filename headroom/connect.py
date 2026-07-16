"""Connect accounts smoothly — and never let a login clobber another slot.

Two paths:

* ``adopt``   — register a login that already exists on this machine
                (your current ``~/.claude`` or ``~/.codex``). Zero friction:
                headroom just reads it, it never moves or copies credentials.
* ``fresh``   — create an isolated config home under ``~/.headroom/homes/``
                and run the provider's own interactive login inside it
                (``claude auth login`` / ``codex login``).

Every fresh login is verified afterwards: if it bound the slot to an identity
that is already connected on another slot, the credentials are rolled back and
the connect is refused — duplicate logins silently eating each other's
headroom is the classic multi-account failure mode.
"""
import os
import shutil
import subprocess
import sys
import time

from . import collect as collector
from . import paths, registry

CREDENTIAL_FILES = {
    "claude": [".credentials.json", ".claude.json"],
    "codex": ["auth.json"],
}
DEFAULT_HOMES = {"claude": "~/.claude", "codex": "~/.codex"}


def provider_binary(provider):
    return shutil.which("claude" if provider == "claude" else "codex")


def login_argv(provider, binary):
    return [binary, "auth", "login"] if provider == "claude" else [binary, "login"]


def darwin_keychain_guard(config, provider, quiet=False, runner=None):
    """Protect existing macOS Claude slots from a login that could clobber them.

    Current Claude CLI builds namespace their Keychain item per config
    directory ("Claude Code-credentials-<hash(CLAUDE_CONFIG_DIR)>"), so
    multiple isolated accounts coexist safely. LEGACY builds keep one shared
    item, where a second `claude` login OVERWRITES the first login's token
    machine-wide. This gate checks capability instead of assuming either way:
    a fresh Claude login is allowed only when every existing Keychain-backed
    Claude slot resolves to its OWN namespaced item; any slot still on the
    shared legacy item (or unprobeable) refuses the login — fail closed,
    because refusing afterwards would be too late to undo the clobber.
    Returns True when the login may proceed."""
    if provider != "claude" or sys.platform != "darwin":
        return True
    kwargs = {"runner": runner} if runner is not None else {}
    at_risk = []
    for account in config.get("accounts") or []:
        if not isinstance(account, dict) or account.get("provider") != "claude":
            continue
        home = os.path.expanduser(str(account.get("home") or ""))
        if not home or os.path.exists(os.path.join(home, ".credentials.json")):
            continue  # file-isolated slot — a new login can't touch it
        if collector.claude_keychain_item_exists(home, **kwargs):
            continue  # namespaced item — isolated per config dir, safe
        at_risk.append(str(account.get("name") or "?"))
    if not at_risk:
        return True
    print(
        "REFUSED: this Claude CLI appears to keep logins in ONE shared macOS\n"
        f"Keychain item, and slot(s) {', '.join(sorted(at_risk))} depend on\n"
        "it — a new `claude` login would overwrite that token and break the\n"
        "slot. Update Claude Code to a current version (recent builds keep a\n"
        "separate Keychain item per account, which headroom supports), then\n"
        "re-run this connect. Otherwise: one Claude account per Mac (see\n"
        "docs/KNOWN-LIMITS.md); extra accounts belong on a Linux host, and\n"
        "Codex accounts are fully isolated everywhere.",
        file=sys.stderr)
    return False


def slot_identity(provider, home):
    """Best-effort identity read for a slot; None when nothing is bound."""
    try:
        if provider == "claude":
            identity = collector.claude_identity(home)
        else:
            identity = collector.codex_identity(home)
        return identity
    except Exception:  # noqa: BLE001 — absence of identity is a valid answer
        return None


def detect_existing():
    """Discover logins already on this machine, for the wizard/adopt flow."""
    found = []
    for provider, default in DEFAULT_HOMES.items():
        home = os.path.expanduser(
            os.environ.get(
                "CLAUDE_CONFIG_DIR" if provider == "claude" else "CODEX_HOME",
                default,
            )
        )
        if not os.path.isdir(home):
            continue
        identity = slot_identity(provider, home)
        if identity and identity.get("email"):
            found.append({"provider": provider, "home": home,
                          "email": identity["email"],
                          "fingerprint": identity.get("account_fingerprint")})
    return found


def backup_credentials(home, provider):
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    directory = os.path.join(home, ".headroom-login-backups", stamp)
    saved = []
    for filename in CREDENTIAL_FILES[provider]:
        source = os.path.join(home, filename)
        if os.path.exists(source):
            os.makedirs(directory, mode=0o700, exist_ok=True)
            os.chmod(os.path.dirname(directory), 0o700)
            shutil.copy2(source, os.path.join(directory, filename))
            saved.append(filename)
    return directory if saved else None, saved


def discard_backup(backup_dir):
    if backup_dir:
        shutil.rmtree(backup_dir, ignore_errors=True)


def restore_credentials(home, provider, backup_dir, saved):
    for filename in CREDENTIAL_FILES[provider]:
        target = os.path.join(home, filename)
        if filename in saved:
            shutil.copy2(os.path.join(backup_dir, filename), target)
        elif os.path.exists(target):
            os.remove(target)


def existing_fingerprints(config, provider, exclude_name=None):
    result = {}
    for account in registry.accounts(config):
        if account["provider"] != provider or account["name"] == exclude_name:
            continue
        identity = slot_identity(provider, account["home"])
        if identity and identity.get("account_fingerprint"):
            result[identity["account_fingerprint"]] = account["name"]
    return result


def add_account(config, name, provider, home, expected_email=None):
    # always store an absolute, canonical home — a relative path would resolve
    # against whatever directory a later command runs from
    entry = {"name": name, "provider": provider, "home": registry.expand(home)}
    if expected_email:
        entry["expected_email"] = expected_email

    added = False

    def _append(cfg):
        nonlocal added
        if not any(a.get("name") == name for a in cfg.get("accounts", [])):
            cfg.setdefault("accounts", []).append(dict(entry))
            added = True

    try:
        # locked reload-append against the latest on-disk config, so a
        # concurrent collector pin-write or connect can't drop this account
        registry.mutate(_append)
    except registry.RegistryError:
        # config doesn't exist yet (wizard building a fresh one) — create it
        config.setdefault("accounts", []).append(entry)
        registry.save(config)
        added = True
    else:
        # reflect into the caller's in-memory config too (the wizard keeps using it)
        if not any(a.get("name") == name for a in config.get("accounts", [])):
            config.setdefault("accounts", []).append(entry)
    if added:
        from . import route
        route.remove_slot_state(name)
    return entry


def _interactive_login(config, name, provider, home, expected_email=None,
                       exclude_name=None, quiet=False):
    """Run one provider-owned interactive login with rollback protections.

    Both fresh connects and an explicit Claude refresh use this path. Headroom
    never invokes it from collection or routing.
    """
    binary = provider_binary(provider)
    if not binary:
        print(f"cannot find the `{'claude' if provider == 'claude' else 'codex'}` "
              f"CLI on PATH — install it first", file=sys.stderr)
        return None
    # BEFORE the login runs: on macOS a new claude login clobbers the shared
    # Keychain token that an existing slot may depend on — refusing afterwards
    # would be too late to undo the damage.
    if not darwin_keychain_guard(config, provider, quiet=quiet):
        return None
    backup_dir, saved = backup_credentials(home, provider)
    duplicates = existing_fingerprints(config, provider, exclude_name=exclude_name)

    def rollback():
        if backup_dir:
            restore_credentials(home, provider, backup_dir, saved)
        else:
            for filename in CREDENTIAL_FILES[provider]:
                target = os.path.join(home, filename)
                if os.path.exists(target):
                    os.remove(target)

    env = collector.scrubbed_env()
    env["CLAUDE_CONFIG_DIR" if provider == "claude" else "CODEX_HOME"] = home
    if not quiet:
        print(f"\nStarting the {provider} login for slot '{name}'.")
        print("Complete the browser flow with the account you want on THIS slot.\n")
    completed = False
    try:
        code = subprocess.run(login_argv(provider, binary), env=env).returncode
        if code != 0:
            print(f"login exited {code}; credentials restored", file=sys.stderr)
            return None
        identity = slot_identity(provider, home)
        if not identity or not identity.get("email"):
            print("login completed but no identity could be read; rolled back",
                  file=sys.stderr)
            return None
        if expected_email and identity["email"].lower() != expected_email.lower():
            print(f"REFUSED: that login ({identity['email']}) does not match "
                  f"this slot's expected email ({expected_email}). Slot rolled "
                  "back.", file=sys.stderr)
            return None
        fingerprint = identity.get("account_fingerprint")
        if fingerprint and fingerprint in duplicates:
            print(f"REFUSED: that login ({identity['email']}) is already "
                  f"connected as slot '{duplicates[fingerprint]}'. Slot rolled "
                  f"back.\nLog in with a different account, or use the "
                  f"existing slot.", file=sys.stderr)
            return None
        completed = True
        return identity
    finally:
        if not completed:
            rollback()
        discard_backup(backup_dir)


def connect_fresh(config, name, provider, quiet=False):
    """Isolated home + interactive provider login + verify + rollback."""
    if not registry.NAME_RE.fullmatch(name):
        print(f"slot name {name!r} invalid: lowercase letters, digits, - and _ "
              f"only (max 32 chars)", file=sys.stderr)
        return None
    home = os.path.join(paths.homes_dir(), name)
    if os.path.realpath(home) != os.path.realpath(
            os.path.join(paths.homes_dir(), os.path.basename(name))):
        print("slot name resolves outside the homes directory; refused",
              file=sys.stderr)
        return None
    os.makedirs(home, mode=0o700, exist_ok=True)
    identity = _interactive_login(config, name, provider, home, quiet=quiet)
    if identity is None:
        # tidy the slot dir we created if the connect was refused and it's now
        # empty (credentials were rolled back)
        try:
            if os.path.isdir(home) and not os.listdir(home):
                os.rmdir(home)
        except OSError:
            pass
        return None
    entry = add_account(config, name, provider, home, identity["email"])
    if not quiet:
        print(f"connected: {name} -> {identity['email']} ({provider})")
        if provider == "claude" and sys.platform == "darwin" \
                and not os.path.exists(os.path.join(home, ".credentials.json")):
            print("note: this login is stored in the macOS Keychain (shared "
                  "machine-wide).\nheadroom reads it directly — but it is "
                  "the ONE Claude account this Mac\ncan hold; connecting a "
                  "second Claude account here is refused to protect it.")
    return entry


def connect_adopt(config, name, provider, home, quiet=False):
    home = os.path.expanduser(home)
    identity = slot_identity(provider, home)
    if not identity or not identity.get("email"):
        print(f"no {provider} login found in {home}", file=sys.stderr)
        return None
    duplicates = existing_fingerprints(config, provider)
    fingerprint = identity.get("account_fingerprint")
    if fingerprint in duplicates:
        print(f"that login ({identity['email']}) is already connected as slot "
              f"'{duplicates[fingerprint]}'", file=sys.stderr)
        return None
    entry = add_account(config, name, provider, home, identity["email"])
    if not quiet:
        print(f"connected: {name} -> {identity['email']} ({provider}, adopted {home})")
    return entry


def cmd_refresh(args):
    """CLI: `headroom auth refresh <slot>` for an owned Claude slot only."""
    if len(args) != 1:
        print("usage: headroom auth refresh <slot>", file=sys.stderr)
        return 2
    name = args[0]
    config = registry.load()
    account = next((item for item in registry.accounts(config)
                    if item["name"] == name), None)
    if account is None:
        print(f"headroom: no connected account named {name!r}", file=sys.stderr)
        return 2
    if account["provider"] != "claude":
        print(f"headroom: slot {name!r} is {account['provider']}; "
              "only owned Claude slots can be refreshed", file=sys.stderr)
        return 2
    # Resolve the homes root, but do not resolve the slot component again:
    # a symlink at homes/<slot> pointing outside must remain an external home,
    # not become eligible merely because both paths resolve to the same target.
    owned_home = os.path.join(registry.expand(paths.homes_dir()), name)
    if account["home"] != owned_home:
        print(f"headroom: slot {name!r} uses an adopted or external home; "
              "refusing to re-login outside Headroom-owned homes", file=sys.stderr)
        return 2
    credential_path = os.path.join(account["home"], ".credentials.json")
    if sys.platform == "darwin" and not os.path.isfile(credential_path):
        print(
            "headroom: refusing to refresh a Keychain-backed Claude slot: "
            "Headroom cannot safely roll back a failed or mismatched macOS "
            "Keychain login. Run `claude auth login` directly for this slot, "
            "then verify its identity before collecting.",
            file=sys.stderr,
        )
        return 2
    identity = _interactive_login(
        config, name, "claude", account["home"],
        expected_email=account.get("expected_email"), exclude_name=name,
    )
    if identity is None:
        return 1
    print(f"refreshed: {name} -> {identity['email']} (claude)")
    print("run `headroom collect` to update this slot's usage reading")
    return 0


def cmd_connect(args):
    """CLI: `headroom connect [name] [--provider claude|codex] [--adopt PATH]`."""
    try:
        config = registry.load()
    except registry.RegistryError:
        if os.path.exists(paths.config_path()):
            # a corrupt existing config must be repaired, never silently
            # replaced with an empty one that then overwrites every slot
            print(f"headroom: {paths.config_path()} exists but is unreadable; "
                  f"fix or delete it before connecting", file=sys.stderr)
            return 1
        config = {"schema_version": 1,
                  "dashboard": dict(registry.DEFAULT_DASHBOARD),
                  "accounts": []}
    name = None
    provider = None
    adopt_path = None
    rest = list(args)
    while rest:
        arg = rest.pop(0)
        if arg == "--provider" and rest:
            provider = rest.pop(0)
        elif arg == "--adopt" and rest:
            adopt_path = rest.pop(0)
        elif not arg.startswith("-") and name is None:
            name = arg
    if provider not in registry.PROVIDERS:
        provider = prompt_choice("Which provider is this account for?",
                                 ["claude", "codex"])
    if name is None:
        taken = {account["name"] for account in config.get("accounts", [])}
        default = next(
            candidate for candidate in
            [f"{provider}-{index}" for index in range(1, 100)]
            if candidate not in taken)
        name = input(f"Slot name for this account [{default}]: ").strip() or default
    if any(account.get("name") == name for account in config.get("accounts", [])):
        print(f"slot '{name}' already exists", file=sys.stderr)
        return 1
    entry = (connect_adopt(config, name, provider, adopt_path)
             if adopt_path else connect_fresh(config, name, provider))
    return 0 if entry else 1


def prompt_choice(question, options, default_index=0):
    print(question)
    for index, option in enumerate(options, 1):
        marker = " (default)" if index - 1 == default_index else ""
        print(f"  {index}. {option}{marker}")
    while True:
        raw = input("> ").strip()
        if not raw:
            return options[default_index]
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        if raw in options:
            return raw
        print("pick a number from the list")
