# Contributing

Thanks for looking at headroom! It's intentionally small, dependency-free, and
stdlib-only — please keep it that way.

## Ground rules

- **No runtime dependencies.** Python 3.9+ standard library only. If you reach
  for a package, there's almost always a stdlib way.
- **Fail closed.** Anything touching routing or identity must default to
  HOLDING when state is missing, stale, corrupt, or unverifiable. When in
  doubt, don't route. New routing/identity logic needs a test proving the
  unhappy path holds.
- **Never widen the public feed.** `collect.public_snapshot()` has an explicit
  field whitelist. Don't add raw provider strings, paths, or identity material
  to it.
- **Match the house style.** Terse, commented only where a constraint isn't
  obvious from the code.

## Running the tests

```bash
python3 -m unittest discover -s tests
```

No pytest, no fixtures framework — plain `unittest`, no network.

Every file in `tests/` starts with this, after its imports and before it
touches `headroom` or `os.environ`:

```python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401 — hermetic bootstrap; see tests/__init__.py
```

That import is what unsets the ambient `HEADROOM_NOTIFY_CMD` and points
`HEADROOM_DIR` at a temp directory, so a test run cannot write launch events
into a live watchdog feed or read your real `~/.headroom`. It lives in the file
rather than in the runner because no runner hook fires under every form —
`discover -p <one file>` and `python3 tests/<file>.py` import no package at
all. `tests/test_ambient_channels.py` fails by name on any file that omits it.

## Handy while developing

```bash
headroom serve --demo     # dashboard on bundled sample data, no accounts
headroom doctor           # what headroom sees on this machine
python3 -m py_compile headroom/*.py
```

## Scope

headroom tracks and routes accounts you already hold. Features that create
accounts, share credentials, or work around provider limits are out of scope.
