"""headroom — usage tracking, live dashboard, and account rotation
for Claude Code and Codex subscriptions.

usage:
  headroom setup                    first-run wizard (accounts + dashboard style)
  headroom connect [name] [--provider claude|codex|grok] [--adopt PATH]
                                    add an account (fresh login or adopt existing;
                                    grok is adopt-only — log in with the grok CLI)
  headroom auth refresh <slot>     interactively re-login an owned Claude slot
                                    (then run `headroom collect`; never automatic)
  headroom remove <slot> [--yes]   unregister one non-final slot; keeps its home
  headroom collect                  read usage for every account (no tokens spent)
  headroom status [model]           who has headroom right now (default: claude)
  headroom pick <model>             print the best account name (exit 2 if none)
  headroom env <model>              print the export line for the best account
  headroom claude [args...]         launch Claude; supervise opted-in auto-handoff
    --headroom-auto-handoff / --headroom-no-auto-handoff   one-run override
    --headroom-launch-fallback      exec the bare CLI if the launch fails
                                    before the CLI ever started (opt-in)
  headroom codex [args...]          launch Codex on the best account
  headroom caps                     print scripting capability flags as JSON
  headroom run <model> -- <cmd...>  headless run with auto-rotation on limit-hit
  headroom rotate [model]           cool the current account down, pick the next
  headroom handoff [--session UUID] [--to SLOT] [--model FAMILY]
                   [--provider claude|codex] [--from SLOT]
                   [--headless BATON] [--print | --yes] [--force]
                                    hand a Claude or Codex conversation to
                                    another account (provider auto-detected
                                    from where the --session UUID resolves;
                                    --from names the codex source slot when a
                                    UUID exists in several homes; --headless
                                    runs `codex exec resume UUID BATON`)
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
import os
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


def _strip_launch_fallback(args):
    """Remove --headroom-launch-fallback from a codex option segment.

    Codex value-taking flags aren't modelled here (they're the codex CLI's
    business), so only exact pre-`--` matches are stripped — the flag is
    headroom's own and never a legitimate codex flag value."""
    separator = args.index("--") if "--" in args else len(args)
    head = [arg for arg in args[:separator]
            if arg != "--headroom-launch-fallback"]
    return head + args[separator:], len(head) != separator


# headroom-owned flags, needed to compute a "bare" fallback argv WITHOUT
# importing supervisor (whose import chain is exactly what can fail before the
# fallback boundary — P1-8a).
_OWNED_LAUNCH_FLAGS = frozenset({
    "--headroom-launch-fallback", "--headroom-auto-handoff",
    "--headroom-no-auto-handoff"})

# Claude value-taking options — a LOCAL mirror of supervisor.CLAUDE_VALUE_FLAGS
# kept here so the pre-import fallback can be value-aware WITHOUT importing
# supervisor (the very import that may have failed). Keep in sync with
# supervisor.CLAUDE_VALUE_FLAGS. Used only to avoid mistaking an option VALUE
# that happens to look like a headroom flag for the flag itself (P2-3).
_CLAUDE_VALUE_FLAGS = frozenset({
    "--model", "--settings", "--system-prompt", "--append-system-prompt",
    "--agents", "--allowedTools", "--disallowedTools", "--permission-mode",
    "--permission-prompt-tool", "--mcp-config", "--add-dir", "--ide",
    "--fallback-model", "--json-schema", "--max-budget-usd",
    "--input-format", "--output-format", "--debug-file", "--betas",
    "--plugin-dir", "--session-id", "--resume", "-r",
})


def _fallback_intent(args):
    """Whether the launch fallback is requested, decided WITHOUT importing
    route/supervisor so it survives an import/preprocessing failure."""
    if os.environ.get("HEADROOM_LAUNCH_FALLBACK", "") == "1":
        return True
    separator = args.index("--") if "--" in args else len(args)
    return "--headroom-launch-fallback" in args[:separator]


def _crude_bare_argv(command, args):
    """Best-effort bare CLI argv for the pre-import disaster fallback: strip
    headroom-owned flags before `--`, but value-aware — the argument that
    FOLLOWS a Claude value-taking option (e.g. `--system-prompt`) is that
    option's value and is preserved even if it happens to look like a headroom
    flag (P2-3). The normal path uses supervisor.split_headroom_flags; this is
    the reduced parser used only when supervisor could not be imported."""
    separator = args.index("--") if "--" in args else len(args)
    head = []
    value_expected = False
    for arg in args[:separator]:
        if value_expected:
            head.append(arg)  # an option value — never a headroom flag
            value_expected = False
            continue
        if arg in _OWNED_LAUNCH_FLAGS:
            continue
        head.append(arg)
        if arg in _CLAUDE_VALUE_FLAGS:
            value_expected = True
    return [command] + head + args[separator:]


def _bare_cli_fallback(bare_argv, reason):
    """Exec the bare CLI with the ORIGINAL (unmutated) environment when the
    launch aborts before headroom could route. Used only by the pre-import
    guard; the routed paths use route.bare_fallback_exec (which also releases
    committed leases). notify is best-effort and must not itself break the
    fallback."""
    try:
        from . import notify
        notify.emit({"event": "fallback", "reason": str(reason)})
    except Exception:  # noqa: BLE001 — the observer can never block the fallback
        pass
    print(f"[headroom] launch fallback: {reason} — running bare "
          f"`{bare_argv[0]}` without routing", file=sys.stderr)
    try:
        os.execvp(bare_argv[0], bare_argv)  # os.environ is still unmutated here
    except OSError as error:
        print(f"[headroom] fallback exec of {bare_argv[0]} failed: {error}",
              file=sys.stderr)
        return 127
    return 0  # unreachable outside tests: a successful exec never returns


def _launch(command, args):
    """Launch branch with a pre-import fallback boundary (P1-8a).

    Fallback INTENT is decided before any heavy import; the risky region —
    importing route/supervisor and preprocessing the args — is wrapped so that
    ANY failure there (e.g. a malformed HEADROOM_* env crashing a module
    import) still execs the bare CLI when the fallback was requested. Once
    preprocessing succeeds, the launch functions themselves own the
    before/after-spawn fallback decision (they alone can see whether a child
    started), so their exceptions are NOT re-wrapped here."""
    intent = _fallback_intent(args)
    try:
        prepared = _prepare_launch(command, args)
    except Exception as error:  # noqa: BLE001 — pre-boundary: bare-exec if asked
        if intent:
            return _bare_cli_fallback(
                _crude_bare_argv(command, args),
                f"launch preprocessing failed: {error}")
        raise
    if isinstance(prepared, int):
        return prepared  # a usage refusal (exit code), not a launch plan
    return _dispatch_launch(*prepared)


def _prepare_launch(command, args):
    """Import + preprocess. Returns either an int (usage refusal) or a launch
    plan tuple consumed by _dispatch_launch. Runs inside _launch's fallback
    guard, so it may freely raise on a broken environment."""
    from . import route  # noqa: F401 — imported so an import-time failure is
    #                                     caught by the fallback guard
    provider_cmd = "claude" if command == "claude" else "codex"
    auto_flag = no_auto_flag = fallback_flag = False
    supervisor = None
    if command == "claude":
        from . import supervisor
        args, headroom_flags = supervisor.split_headroom_flags(args)
        auto_flag = "--headroom-auto-handoff" in headroom_flags
        no_auto_flag = "--headroom-no-auto-handoff" in headroom_flags
        fallback_flag = "--headroom-launch-fallback" in headroom_flags
    else:
        args, fallback_flag = _strip_launch_fallback(args)
    fallback = fallback_flag or \
        os.environ.get("HEADROOM_LAUNCH_FALLBACK", "") == "1"
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
    use_supervisor = False
    launch_note = ""
    if command == "claude":
        if auto_flag and no_auto_flag:
            print("headroom: auto-handoff overrides are mutually exclusive",
                  file=sys.stderr)
            return 2
        if supervisor.termios is None:
            print(supervisor.UNSUPERVISED_MESSAGE, file=sys.stderr)
            launch_note = "supervision unavailable on this platform"
            return (command, args, fam, fallback, use_supervisor, launch_note,
                    supervisor)
        configured = registry.auto_handoff()
        enabled = auto_flag or (configured and not no_auto_flag)
        if enabled:
            incompatible = supervisor.incompatible_args(args)
            all_tty = (sys.stdin.isatty() and sys.stdout.isatty()
                       and sys.stderr.isatty())
            if all_tty and not incompatible:
                use_supervisor = True
            else:
                why = incompatible or "stdin/stdout/stderr are not all TTYs"
                print(f"[headroom] auto-handoff disabled for this run: {why}",
                      file=sys.stderr)
                launch_note = f"auto-handoff disabled: {why}"
        else:
            launch_note = "auto-handoff not enabled"
    return command, args, fam, fallback, use_supervisor, launch_note, supervisor


def _dispatch_launch(command, args, fam, fallback, use_supervisor,
                     launch_note, supervisor):
    """Call the launch function. The before/after-spawn fallback boundary is
    owned inside cmd_claude/cmd_exec, so exceptions here are NOT caught for a
    bare fallback (a post-spawn crash must never duplicate a live child)."""
    from . import route
    if command == "claude" and use_supervisor:
        if fallback:
            return supervisor.cmd_claude(
                fam, args, fallback_argv=["claude"] + args)
        return supervisor.cmd_claude(fam, args)
    if fallback:
        return route.cmd_exec(fam, [command] + args,
                              launch_note=launch_note, fallback=True)
    return route.cmd_exec(fam, [command] + args, launch_note=launch_note)


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
    if command == "caps":
        # capability probe for launchers: COMMAND-SCOPED, so a wrapper can see
        # which launch surface each feature is actually wired into and never
        # assume an operational guarantee a symbol's mere existence can't
        # prove. Each flag is confirmed against an implemented symbol; the
        # per-command map records where it is genuinely wired (e.g. `run` is
        # deliberately NOT covered by fallback/lease). (P2-10)
        #
        # caps must ALWAYS emit its JSON — a launcher relies on it to decide
        # whether this binary supports a feature. Module-level env parsing is
        # now tolerant (paths.env_int), so the heavy import no longer breaks on
        # a stray HEADROOM_* value; if introspection fails for any other
        # reason we still emit the declared capabilities of this build. (P2-6)
        import json

        has_marker = has_fallback = has_lease = has_notify = True
        try:
            from . import notify, route
            has_marker = callable(getattr(route, "write_launch_marker", None))
            has_fallback = callable(getattr(route, "bare_fallback_exec", None))
            has_lease = callable(getattr(route, "acquire_slot_lease", None))
            has_notify = callable(getattr(notify, "emit", None))
        except Exception:  # noqa: BLE001 — caps must never fail to emit
            pass
        capabilities = {
            "schema": 2,
            "launch_marker": {"claude": has_marker, "codex": has_marker},
            "launch_fallback": {"claude": has_fallback,
                                "codex": has_fallback, "run": False},
            "notify_cmd": has_notify,
            "slot_lease": {"claude": has_lease, "codex": has_lease,
                           "run": False,
                           # fail-closed acquisition (P1-9): with
                           # HEADROOM_SLOT_LEASE=1 headroom refuses rather than
                           # silently launching unleased
                           "fail_closed": has_lease},
        }
        print(json.dumps(capabilities, sort_keys=True))
        return 0
    if command == "setup":
        from . import wizard
        return wizard.run_setup()
    if command == "connect":
        from . import connect
        return connect.cmd_connect(args)
    if command == "auth":
        from . import connect
        if not args or args[0] != "refresh":
            print("usage: headroom auth refresh <slot>", file=sys.stderr)
            return 2
        return connect.cmd_refresh(args[1:])
    if command == "remove":
        from . import collect
        return collect.cmd_remove(args)
    if command == "collect":
        from . import collect
        collect.run_collect()
        collect._trigger_token_scan(synchronous=True)
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
        return _launch(command, args)
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
        family = registry.family(args[1])
        # cool against the window this provider resets on — no-5h providers
        # (codex/grok) reset weekly, so mark() must default to 7d, not +5h
        window = "7d" if registry.family_provider(family) \
            in registry.NO_5H_PROVIDERS else "5h"
        epoch = None  # None => mark() uses its window-aware default (7d vs 5h)
        if len(args) > 2:
            try:
                epoch = float(args[2])
            except ValueError:
                print("usage: headroom mark <name> <model> "
                      "[epoch-unix-timestamp]", file=sys.stderr)
                return 2
        epoch = route.mark(args[0], family, epoch, window=window)
        print(f"cooled {args[0]}:{family} until {route.tfmt(epoch)}")
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
            # Re-derive the public feed from the private snapshot with the
            # CURRENT redaction setting, so a redaction change is reflected.
            # Keep both reads and publications under the collection lifecycle
            # lock: otherwise a remove can prune a slot and this command can
            # republish its pre-removal snapshot afterwards.
            with collect.collection_lock():
                private = paths.load_json(paths.private_snapshot_path())
                if private:
                    settings = registry.dashboard_settings()
                    paths.write_json_atomic(
                        paths.public_snapshot_path(),
                        collect.public_snapshot(
                            private, settings.get("redact_emails", True)),
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
