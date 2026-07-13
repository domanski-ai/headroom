"""headroom — usage tracking, live dashboard, and account rotation
for Claude Code and Codex subscriptions.

usage:
  headroom setup                    first-run wizard (accounts + dashboard style)
  headroom connect [name] [--provider claude|codex] [--adopt PATH]
                                    add an account (fresh login or adopt existing)
  headroom collect                  read usage for every account (no tokens spent)
  headroom status [model]           who has headroom right now (default: claude)
  headroom pick <model>             print the best account name (exit 2 if none)
  headroom env <model>              print the export line for the best account
  headroom claude [args...]         launch Claude; supervise opted-in auto-handoff
    --headroom-auto-handoff / --headroom-no-auto-handoff   one-run override
  headroom codex [args...]          launch Codex on the best account
  headroom run <model> -- <cmd...>  headless run with auto-rotation on limit-hit
  headroom rotate [model]           cool the current account down, pick the next
  headroom handoff [--session UUID] [--to SLOT] [--model FAMILY]
                   [--print | --yes] [--force]
                                    hand a Claude conversation to another account
  headroom mark <name> <model> [epoch]   manual cooldown
  headroom clear [name:family]      clear cooldown(s)
  headroom repin <name>             re-bind a Claude slot's usage org
  headroom dashboard [--demo]       (re)build the static dashboard
  headroom serve [--open] [--port N] [--demo]   local live dashboard
  headroom widget-feed --swiftbar  render the last snapshot (never collects)
  headroom statusline               Claude Code status line output
  headroom accounts                 list connected accounts
  headroom doctor                   environment + config health check

Try it with no accounts:  headroom serve --demo   (bundled sample data)
"""
import sys

from . import __version__, registry


def main(argv=None):
    try:
        return _dispatch(sys.argv[1:] if argv is None else argv)
    except registry.RegistryError as error:
        print(f"headroom: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        # e.g. a relative HEADROOM_DIR — a config problem, not a crash
        print(f"headroom: {error}", file=sys.stderr)
        return 1
    except RuntimeError as error:
        # e.g. an unreadable cooldown ledger reached from a write path —
        # fail closed with the same clean message the read paths give
        print(f"headroom: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 130
    except EOFError:
        print("\nheadroom: this command needs an interactive terminal "
              "(no input available on stdin).", file=sys.stderr)
        return 1


def _dispatch(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    command, args = argv[0], argv[1:]

    if command == "_hook-event":
        from . import supervisor
        return supervisor.write_hook_event()

    if command in ("-V", "--version", "version"):
        print(f"headroom {__version__}")
        return 0
    if command == "setup":
        from . import wizard
        return wizard.run_setup()
    if command == "connect":
        from . import connect
        return connect.cmd_connect(args)
    if command == "collect":
        from . import collect
        collect.run_collect()
        return 0
    if command == "status":
        from . import route
        return route.cmd_status(registry.family(args[0] if args else "claude"))
    if command == "pick":
        from . import route
        account = route.pick(registry.family(args[0] if args else "claude"))
        print(account["name"] if account else "")
        return 0 if account else 2
    if command == "env":
        import shlex

        from . import route
        account = route.pick(registry.family(args[0] if args else "claude"))
        if not account:
            print("# no account with proven headroom", file=sys.stderr)
            return 2
        print(f"export {route.env_key(account)}={shlex.quote(account['home'])}"
              f"  # account={account['name']}")
        return 0
    if command in ("claude", "codex"):
        from . import route
        provider_cmd = "claude" if command == "claude" else "codex"
        auto_flag = no_auto_flag = False
        if command == "claude":
            from . import supervisor
            args, auto_flag, no_auto_flag = \
                supervisor.strip_headroom_overrides(args)
        # honour an explicit model flag (both `--model X` and `--model=X`) so a
        # scoped weekly cap (e.g. Opus) gates the routing decision
        model = None
        option_args = args[:args.index("--")] if "--" in args else args
        for index, arg in enumerate(option_args):
            if arg == "--model" and index + 1 < len(option_args):
                model = option_args[index + 1]
            elif arg.startswith("--model="):
                model = arg.split("=", 1)[1]
        fam = registry.family(model) if model else provider_cmd
        if registry.family_provider(fam) != provider_cmd:
            print(f"headroom: `headroom {command}` can't run a "
                  f"{registry.family_provider(fam)} model ({model}) — use "
                  f"`headroom {registry.family_provider(fam)}`", file=sys.stderr)
            return 2
        if command == "claude":
            if auto_flag and no_auto_flag:
                print("headroom: auto-handoff overrides are mutually exclusive",
                      file=sys.stderr)
                return 2
            configured = registry.auto_handoff()
            enabled = auto_flag or (configured and not no_auto_flag)
            if enabled:
                incompatible = supervisor.incompatible_args(args)
                all_tty = (sys.stdin.isatty() and sys.stdout.isatty()
                           and sys.stderr.isatty())
                if all_tty and not incompatible:
                    return supervisor.cmd_claude(fam, args)
                why = incompatible or "stdin/stdout/stderr are not all TTYs"
                print(f"[headroom] auto-handoff disabled for this run: {why}",
                      file=sys.stderr)
        return route.cmd_exec(fam, [command] + args)
    if command == "run":
        from . import route
        if not args or "--" not in args or args.index("--") == len(args) - 1:
            print("usage: headroom run <model> -- <command...>", file=sys.stderr)
            return 2
        separator = args.index("--")
        return route.cmd_run(registry.family(args[0]), args[separator + 1:])
    if command == "rotate":
        from . import route
        return route.cmd_rotate(registry.family(args[0] if args else "claude"))
    if command == "handoff":
        from . import handoff
        return handoff.cmd_handoff(args)
    if command == "mark":
        import time

        from . import route
        if len(args) < 2:
            print("usage: headroom mark <name> <model> [epoch-unix-timestamp]",
                  file=sys.stderr)
            return 2
        known = {account["name"] for account in registry.accounts()}
        if args[0] not in known:
            print(f"headroom: no connected account named {args[0]!r} "
                  f"(have: {', '.join(sorted(known)) or 'none'})", file=sys.stderr)
            return 2
        if len(args) > 2:
            try:
                epoch = float(args[2])
            except ValueError:
                print("usage: headroom mark <name> <model> "
                      "[epoch-unix-timestamp]", file=sys.stderr)
                return 2
        else:
            epoch = time.time() + 5 * 3600
        epoch = route.mark(args[0], registry.family(args[1]), epoch)
        print(f"cooled {args[0]}:{registry.family(args[1])} "
              f"until {route.tfmt(epoch)}")
        return 0
    if command == "clear":
        from . import route
        if not args:
            route.clear(None)
            print("cleared all cooldowns")
            return 0
        # cooldown keys are "<account>:<family>" or account-wide "<account>:*";
        # accept a bare account name by clearing every key for it
        cleared = route.clear(args[0])
        if not cleared and ":" not in args[0]:
            cool = route.cooldowns() or {}
            hit = [k for k in list(cool) if k.split(":")[0] == args[0]]
            for k in hit:
                route.clear(k)
            cleared = bool(hit)
        print(f"cleared {args[0]}" if cleared else f"no cooldown matching {args[0]!r}")
        return 0
    if command == "repin":
        # clear a Claude slot's remembered usage-org so it re-pins on the next
        # collect (use if a legitimate multi-org account started holding with
        # claude_usage_org_unverifiable/changed)
        if not args:
            print("usage: headroom repin <account>", file=sys.stderr)
            return 2
        hits = []

        def _repin(cfg):
            for account in cfg["accounts"]:
                if account.get("name") == args[0]:
                    account.pop("pinned_usage_org", None)
                    hits.append(account["name"])

        registry.mutate(_repin)  # locked reload-mutate-save
        if not hits:
            print(f"headroom: no account named {args[0]!r}", file=sys.stderr)
            return 2
        print(f"repinned {args[0]}: will re-bind its usage org on next collect")
        return 0
    if command == "dashboard":
        from . import collect, dashboard, paths
        if "--demo" in args:
            out = dashboard.build_demo()
            print(f"demo dashboard built: {out}/index.html")
        else:
            # re-derive the public feed from the private snapshot with the
            # CURRENT redaction setting, so a redaction change is reflected
            private = paths.load_json(paths.private_snapshot_path())
            if private:
                settings = registry.dashboard_settings()
                paths.write_json_atomic(
                    paths.public_snapshot_path(),
                    collect.public_snapshot(private,
                                            settings.get("redact_emails", True)),
                    mode=0o644)
            dashboard.build(snapshot_file=paths.public_snapshot_path())
        return 0
    if command == "serve":
        from . import dashboard
        port = None
        if "--port" in args:
            try:
                port = int(args[args.index("--port") + 1])
                if not 1 <= port <= 65535:
                    raise ValueError
            except (IndexError, ValueError):
                print("usage: headroom serve [--open] [--port 1-65535] [--demo]",
                      file=sys.stderr)
                return 2
        return dashboard.serve(open_browser="--open" in args, port=port,
                               demo="--demo" in args) or 0
    if command == "widget-feed":
        if args != ["--swiftbar"]:
            print("usage: headroom widget-feed --swiftbar", file=sys.stderr)
            return 2
        from . import paths, widget
        snapshot = paths.load_json(paths.public_snapshot_path())
        if snapshot is None:
            output = widget.render_swiftbar(None)
        else:
            try:
                output = widget.render_swiftbar(snapshot)
            except Exception:  # noqa: BLE001 — a display feed must fail closed
                output = widget.render_swiftbar(None)
        print(output, end="")
        return 0
    if command == "statusline":
        from . import statusline
        return statusline.main()
    if command == "doctor":
        import platform
        import shutil

        from . import paths
        print(f"headroom {__version__}")
        print(f"python     {platform.python_version()} ({platform.system()})")
        try:
            print(f"HEADROOM_DIR {paths.base_dir()}")
        except ValueError as error:
            print(f"HEADROOM_DIR INVALID: {error}")
        for cli in ("claude", "codex"):
            found = shutil.which(cli)
            print(f"{cli:<10} {found or 'not found on PATH'}")
        try:
            accts = registry.accounts()
            print(f"accounts   {len(accts)} configured: "
                  + ", ".join(a["name"] for a in accts))
        except registry.RegistryError as error:
            print(f"accounts   none ({error})")
        snap = paths.load_json(paths.private_snapshot_path())
        if snap and snap.get("generated"):
            import time
            age = int(time.time() - snap["generated"])
            print(f"snapshot   {age}s old, {len(snap.get('accounts', []))} accounts")
        else:
            print("snapshot   none yet (run `headroom collect`)")
        return 0
    if command == "accounts":
        try:
            for account in registry.accounts():
                print(f"  {account['name']:<16} {account['provider']:<7} "
                      f"{account.get('expected_email', '')}  {account['home']}")
            return 0
        except registry.RegistryError as error:
            print(str(error), file=sys.stderr)
            return 1
    print(f"unknown command: {command}\n", file=sys.stderr)
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
