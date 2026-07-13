"""First-run setup: discover logins, connect accounts, style the dashboard.

The wizard is a conversation, not a config file. It:

1. finds logins already on this machine and offers to adopt them,
2. loops through connecting additional accounts (fresh isolated logins),
3. quizzes the user on how they want their tracker to look
   (theme, title, email privacy, port),
4. runs the first collect and builds the dashboard.
"""
import os
import sys

from . import collect as collector
from . import connect, dashboard, paths, registry

THEMES = [
    ("midnight", "Midnight — dark control-room: near-black, glowing meters"),
    ("minimal", "Minimal — white space, hairlines, quiet typography"),
    ("chrome", "Chrome — brushed metal, glossy gauges, instrument-panel feel"),
    ("paper", "Paper — warm parchment ledger with battery cells"),
    ("terminal", "Terminal — green-on-black CRT, pure operator nostalgia"),
]


def ask(question, default=None):
    suffix = f" [{default}]" if default is not None else ""
    answer = input(f"{question}{suffix}: ").strip()
    return answer or (default if default is not None else "")


def ask_yes_no(question, default=True):
    suffix = "[Y/n]" if default else "[y/N]"
    answer = input(f"{question} {suffix}: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def run_setup():
    print("headroom setup")
    print("=" * 40)
    config_file = paths.config_path()
    if os.path.exists(config_file):
        if not ask_yes_no(f"{config_file} already exists — reconfigure?", False):
            print("keeping the existing config. `headroom connect` adds accounts.")
            return 0
        config = paths.load_json(config_file)
        if config is None:
            # existing file is corrupt — don't silently discard it
            if not ask_yes_no("that config is unreadable/corrupt. Start over "
                              "and OVERWRITE it?", False):
                print("left the existing config untouched — fix or delete it, "
                      "then re-run setup.")
                return 1
            backup = config_file + ".corrupt.bak"
            try:
                os.replace(config_file, backup)
                print(f"backed the corrupt config up to {backup}")
            except OSError as error:
                print(f"could not back up the corrupt config ({error}); "
                      "aborting rather than risk losing it.")
                return 1
            config = {}
        config.setdefault("schema_version", 1)
        config.setdefault("accounts", [])
        config.setdefault("dashboard", dict(registry.DEFAULT_DASHBOARD))
    else:
        config = {"schema_version": 1,
                  "dashboard": dict(registry.DEFAULT_DASHBOARD),
                  "accounts": []}

    # -- 1. adopt what already exists -------------------------------------
    print("\nLooking for logins already on this machine...")
    existing_homes = {registry.expand(account["home"])
                      for account in config["accounts"]}
    found = [item for item in connect.detect_existing()
             if registry.expand(item["home"]) not in existing_homes]
    if found:
        for item in found:
            print(f"\n  found: {item['provider']} login {item['email']} "
                  f"({item['home']})")
            if ask_yes_no("  connect it?", True):
                taken = {account["name"] for account in config["accounts"]}
                default_name = item["provider"] if item["provider"] not in taken \
                    else f"{item['provider']}-main"
                name = ask("  slot name", default_name)
                connect.connect_adopt(config, name, item["provider"],
                                      item["home"], quiet=False)
    else:
        print("  none found (that's fine — connect fresh ones next).")

    # -- 2. connect more accounts ------------------------------------------
    while ask_yes_no("\nConnect another account (opens the provider's own "
                     "login flow)?", False):
        provider = connect.prompt_choice("Provider?", ["claude", "codex"])
        taken = {account["name"] for account in config["accounts"]}
        default_name = next(candidate for candidate in
                            [f"{provider}-{index}" for index in range(1, 100)]
                            if candidate not in taken)
        name = ask("Slot name", default_name)
        connect.connect_fresh(config, name, provider)

    if not config["accounts"]:
        print("\nNo accounts connected — nothing to track yet. "
              "Re-run `headroom setup` when ready.")
        return 1

    print("\nRotation preference: accounts are tried in the order listed.")
    for index, account in enumerate(config["accounts"], 1):
        print(f"  {index}. {account['name']} ({account['provider']}, "
              f"{account.get('expected_email', 'unknown')})")
    order = ask("Reorder? (e.g. `2,1,3`, empty keeps this order)", "")
    if order:
        try:
            indices = [int(part) - 1 for part in order.split(",")]
            if sorted(indices) == list(range(len(config["accounts"]))):
                config["accounts"] = [config["accounts"][i] for i in indices]
            else:
                print("  that wasn't a full ordering — keeping as-is")
        except ValueError:
            print("  couldn't parse — keeping as-is")

    # -- 3. the style quiz ---------------------------------------------------
    print("\nNow the fun part — how should your usage tracker look?")
    theme = connect.prompt_choice(
        "Pick a theme (you can switch live on the dashboard later):",
        [f"{name} — {label.split('— ', 1)[1]}" for name, label in THEMES])
    theme = theme.split(" — ", 1)[0]
    title = ask("Dashboard title", config["dashboard"].get("title", "AI Fleet"))
    redact = ask_yes_no(
        "Redact account emails on the dashboard (p***@domain)? "
        "Recommended if you might share or screenshot it", True)
    port = ask("Local dashboard port", str(config["dashboard"].get("port", 8377)))
    port = int(port) if port.isdigit() and 1 <= int(port) <= 65535 else 8377
    config["dashboard"].update({
        "theme": theme,
        "title": title,
        "redact_emails": redact,
        "port": port,
    })

    # -- routing preference: keep a reserve so sessions start fresh -----------
    routing = config.get("routing")
    if not isinstance(routing, dict):
        routing = {}
        config["routing"] = routing
    current_reserve = routing.get("reserve_percent", 0)
    reserve_raw = ask(
        "Skip an account once it drops below this % headroom left, so sessions "
        "start fresh instead of hitting a limit mid-task (0 = use every account "
        "to its limit)", str(current_reserve))
    try:
        reserve = float(reserve_raw)
        reserve = reserve if 0 <= reserve <= 99 else 0.0
    except ValueError:
        reserve = 0.0
    routing["reserve_percent"] = reserve

    auto_handoff = ask_yes_no(
        "Keep automatic Claude handoff on? When a `headroom claude` session "
        "hits its cap, headroom stops the proven-capped process, copies the "
        "conversation to a fresh account, and continues it in the same "
        "terminal (default: on)", True)
    routing["auto_handoff"] = auto_handoff

    registry.save(config)
    print(f"\nSaved {paths.config_path()}")

    # -- 4. first collect + dashboard build ----------------------------------
    print("\nReading usage for every connected account "
          "(no tokens are consumed)...")
    try:
        collector.run_collect()
    except Exception as error:  # noqa: BLE001 — setup must finish with guidance
        print(f"first collect hit a problem: {error}", file=sys.stderr)
        print("you can retry any time with `headroom collect`")
    dashboard.build()
    print("\nDone. Next steps:")
    print("  headroom serve --open     live dashboard in your browser")
    print("  headroom status sonnet    who has headroom right now")
    print("  headroom claude           launch Claude Code on the best account")
    print("  headroom rotate           switch accounts when you hit a limit")
    return 0
