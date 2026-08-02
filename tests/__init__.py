"""headroom's test package — hermetic before a test is collected.

An estate that runs headroom exports ``HEADROOM_NOTIFY_CMD`` into every pane
so launches report to a watchdog, and every process started in a pane
inherits it — this suite included, and everything this suite spawns. The suite
drives real launch paths, so with that variable set a test run writes
real-looking ``launch`` and ``supervision_lost`` events into a live watchdog
feed, where a ``launch`` clears a genuine disarm alert. A green suite and a
lying watchdog look identical from outside, so the channel has to be shut.

The scrub lives here because it is the one place that can serve every runner.
It also covers processes the suite forks, which a patched ``notify.emit``
never reaches — a child inherits the environment, not a monkeypatch.

WHAT MAKES IT RUN. Nothing in unittest guarantees this file executes. The
runner imports the package only when a module is named through it, so
``discover -s tests`` (top-level dir = ``tests/``) and ``python3 tests/x.py``
both reach a test without ever touching this module — measured, 113 events
into a live sink. The trigger therefore cannot be the runner and cannot be
collection order: every test file carries the two-line bootstrap in
``BOOTSTRAP`` below, immediately after its path setup and before it imports or
observes anything else. A test module is the one thing that runs under every
invocation form. ``tests/test_ambient_channels.py`` audits this directory for
that bootstrap, so a file that omits it turns the suite red instead of quietly
reopening the channel.

Popping rather than redirecting is what ``notify.emit`` itself documents as
off (notify.py:66): a redirected sink is still an exec per event. The tests
that exist to exercise notify point the variable at their own temp script per
test, and one of them asserts that an unset variable is a silent no-op, so
absence is the state they expect to start from.

The same reasoning covers ``HEADROOM_DIR``, the other channel that reaches
somewhere real: unset it and paths.py falls straight back to the live
``~/.headroom``, which the suite then opens and parses a couple of hundred
times a run. It has to be pointed at somewhere disposable rather than cleared.

The scrub is idempotent per PROCESS, not behind a module global. Eleven
bootstraps import this package, and a package can be reached under more than
one module name in one interpreter — a second module object with its own
globals, which a plain global would not survive. So the latch lives in the
environment, keyed to the pid that set it. A child process has a different pid
by definition and re-scrubs: the pin in ``tests/test_notify_hermetic.py``
measures a child's hermeticity, and a latch a child could inherit would
silently disarm it.
"""
import atexit
import os
import shutil
import tempfile

#: The bootstrap every ``tests/test_*.py`` must carry, immediately after its
#: docstring and imports. ``tests/test_ambient_channels.py`` enforces it and
#: pastes this text into the failure message.
BOOTSTRAP = """\
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401 — hermetic bootstrap; see tests/__init__.py
"""

#: Set to the pid that ran the scrub; re-read under the same pid to make a
#: second execution a no-op. Never matches in a child, which must re-scrub.
_LATCH = "_HEADROOM_TESTS_SCRUBBED_PID"

if os.environ.get(_LATCH) != str(os.getpid()):
    for _channel in ("HEADROOM_NOTIFY_CMD", "HEADROOM_NOTIFY_TIMEOUT"):
        os.environ.pop(_channel, None)

    _state = tempfile.mkdtemp(prefix="headroom-tests-")
    os.environ["HEADROOM_DIR"] = _state
    atexit.register(shutil.rmtree, _state, ignore_errors=True)

    os.environ[_LATCH] = str(os.getpid())
