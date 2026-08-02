"""A test run must not be able to reach a notify sink it inherited.

``HEADROOM_NOTIFY_CMD`` is an ambient environment variable: an estate exports it
(tmux global, supervisor-injected lane environment, CI) so that every process
launched in a lane reports launch transitions to a watchdog. Every process
INCLUDING this test suite, and including any child process the suite spawns,
because ``fork``/``execve`` hands ``os.environ`` straight down.

That is a production-safety defect, not a tidiness one. The watchdog latches a
``supervision_lost`` event so it cannot false-recover, and a later ``launch``
event on the same pane clears the latch. A suite run emits ``launch`` events.
So a test run can silently clear a real disarm alert on a live lane -- a green
suite and a lying watchdog look identical from the outside, which is why this
property needs a test and not only a fix.

WHAT THIS PINS, AND WHY IT IS SHAPED THIS WAY

The invariant is not "test_supervisor.py does not leak". Pinning today's
offenders lets test file number ten reintroduce the defect in silence. The
invariant is:

    running this suite cannot emit an event into a notify sink inherited from
    the ambient environment -- for any test file, including one whose author
    never heard of this bug, including processes the suite spawns, and under
    any way of starting it.

That last clause is the one that cost blood: a run's hermeticity used to depend
on some module importing the tests package, so narrowing the runner narrowed
the protection. Measured on the broken tree, from runs that reported OK:

    python3 -m unittest discover -s tests -p test_supervisor.py   112 events
    python3 tests/test_supervisor.py                              113 events

So every test here runs a REAL subprocess with ``HEADROOM_NOTIFY_CMD`` pointed
at a probe command of our own, and asserts the probe's sink stays empty. The
subprocess is what makes this meaningful: asserting
``os.environ.get("HEADROOM_NOTIFY_CMD") is None`` inside this process would pass
under a fix that cleans one file's environment, and it is blind to child
processes, which are a measured second source of leaked ``launch`` events.

No test here can pass by accident of our own hygiene: the variable is set
explicitly on the child's environment, so whatever this process did or did not
inherit is irrelevant.

The last three tests are the anti-rot half. Each copies the tests package to a
temp directory, drops in one new module, and starts it a different way:

  * dotted (``-m unittest tests.test_zz_notify_canary``) with a module that
    does nothing defensive at all -- the runner imports the package by name, so
    this arm pins the package-level scrub itself;
  * narrowed discovery (``discover -s tests -p ...``) and direct execution
    (``python3 tests/...``), which import no package on their own, with a
    module written to the house boilerplate. These two are the forms that used
    to leak, and they pass only because the boilerplate carries the bootstrap.

The boilerplate those two arms paste is ``tests.BOOTSTRAP`` -- the same string
``tests/test_ambient_channels.py`` requires of every file in the directory. So
this file measures what that file audits, and neither can drift alone.

Every test fails closed. The observation path is verified by a positive control
before any assertion runs, so "the sink is empty" can only mean "nothing was
emitted", never "the probe was broken".
"""
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401 — hermetic bootstrap; see tests/__init__.py

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.join(REPO_ROOT, "tests")

# A slice of the real suite, chosen because it is measured to reach
# headroom.notify.emit through production call sites (supervisor hook handling
# and route.cmd_exec) and because it runs in well under a second. It emits both
# leak classes that matter: `launch`, which CLEARS the watchdog's latch, and
# `supervision_lost`, which RAISES a false disarm alert.
LEAKY_SLICE = (
    "tests.test_supervisor.HookProof",
    "tests.test_headroom.LaunchMarker",
    "tests.test_headroom.EnvPinnedAccount",
)

# The observer headroom will exec once per event. It takes its sink path as
# argv[1] and the event payload as argv[-1] (notify appends the JSON as the
# final argv element). The sink path travels in the command string rather than
# in the environment, so a fix that scrubs the environment aggressively cannot
# accidentally disarm this probe and turn a leak into a false pass.
PROBE_SOURCE = (
    "import sys\n"
    "with open(sys.argv[1], 'a') as handle:\n"
    "    handle.write(sys.argv[-1] + '\\n')\n"
)

# Sorts last, so a canary planted in a copied package is never the file some
# other arm's discovery happens to reach first.
CANARY_NAME = "test_zz_notify_canary"

# The body of a new test file: it just calls the production emitter, in-process
# and from a child process. Nothing here defends itself.
CANARY_BODY = '''

CHILD = ("from headroom import notify; "
         "notify.emit({'event': 'launch', 'account': 'canary-child', "
         "'mode': 'exec', 'model': 'm', 'note': ''})")


class Canary(unittest.TestCase):
    def test_emits_in_process(self):
        notify.emit({"event": "launch", "account": "canary-parent",
                     "mode": "exec", "model": "m", "note": ""})

    def test_emits_from_a_child_process(self):
        subprocess.run([sys.executable, "-c", CHILD], check=True)


if __name__ == "__main__":
    unittest.main()
'''

# A file by someone who has never heard of this defect and wrote no boilerplate
# at all. Only reachable hermetically through a runner that imports the package
# by name, which is what the dotted arm exercises.
BARE_CANARY = ('import subprocess\n'
               'import sys\n'
               'import unittest\n'
               '\n'
               'from headroom import notify\n') + CANARY_BODY

# The same file written to the house boilerplate -- `tests.BOOTSTRAP` pasted
# verbatim, which is exactly what tests/test_ambient_channels.py requires of
# every file in the directory. This is what the narrowed-discovery and
# direct-execution arms run, because those two runners import no package of
# their own: the file has to carry its own protection or it leaks.
BOOTSTRAPPED_CANARY = ('import os\n'
                       'import subprocess\n'
                       'import sys\n'
                       'import unittest\n'
                       '\n'
                       + tests.BOOTSTRAP +
                       '\n'
                       'from headroom import notify  # noqa: E402\n') \
    + CANARY_BODY


@unittest.skipIf(os.name == "nt", "gated, not dropped: every arm here spawns "
                 "a runner and asserts on a process-group-killed observer, and "
                 "the channel being pinned is a POSIX estate's (tmux exports "
                 "HEADROOM_NOTIFY_CMD into every pane). Nobody has executed "
                 "these arms on Windows, and an unexecuted green is the exact "
                 "failure this file exists to prevent. tests/"
                 "test_ambient_channels.py audits the bootstrap on every "
                 "platform, so the anti-rot half is not gated.")
class NotifySinkIsUnreachableFromATestRun(unittest.TestCase):
    """The suite must not be able to write to an inherited notify sink."""

    maxDiff = None

    def setUp(self):
        workspace = tempfile.mkdtemp(prefix="headroom-notify-hermetic-")
        self.addCleanup(shutil.rmtree, workspace, ignore_errors=True)
        self.workspace = workspace

        self.probe = os.path.join(workspace, "probe_observer.py")
        with open(self.probe, "w") as handle:
            handle.write(PROBE_SOURCE)

        self.sink = os.path.join(workspace, "sink.jsonl")
        open(self.sink, "w").close()

        # Nothing in this test may touch the real ~/.headroom.
        self.state_dir = os.path.join(workspace, "headroom-dir")
        os.makedirs(self.state_dir)

        self._prove_the_probe_can_observe_an_emit()

    # -- machinery ---------------------------------------------------------

    def lane_environment(self, sink):
        """A child environment shaped like a supervised lane pane."""
        environment = dict(os.environ)
        # Set explicitly, never inherited: this test must measure the suite's
        # hermeticity, not ours.
        # notify.emit splits this with shlex, so quote every element: a temp
        # path with a space would otherwise disarm the probe and turn a leak
        # into a green.
        environment["HEADROOM_NOTIFY_CMD"] = " ".join(
            shlex.quote(part) for part in (sys.executable, self.probe, sink))
        environment.pop("HEADROOM_NOTIFY_TIMEOUT", None)
        # The package latch is pid-keyed, so a child re-scrubs on its own; drop
        # it anyway so this measures a pane's environment, not a descendant's.
        environment.pop(tests._LATCH, None)
        environment["HEADROOM_DIR"] = self.state_dir
        environment["PYTHONPATH"] = os.pathsep.join(
            [REPO_ROOT] + [p for p in [environment.get("PYTHONPATH")] if p])
        return environment

    def run_child(self, argv, cwd, sink):
        return subprocess.run(
            argv, cwd=cwd, env=self.lane_environment(sink),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600, text=True)

    def sink_lines(self, sink):
        with open(sink) as handle:
            return [line for line in handle.read().splitlines() if line.strip()]

    def _prove_the_probe_can_observe_an_emit(self):
        """Positive control: an unprotected emit DOES reach the sink.

        Without this, a broken probe path -- a bad interpreter, an unwritable
        sink, a subprocess that never started -- would look exactly like a
        hermetic suite, and this whole test would pass while the defect stood.
        """
        control_sink = os.path.join(self.workspace, "control.jsonl")
        open(control_sink, "w").close()
        emit = ("from headroom import notify\n"
                "raise SystemExit(0 if notify.emit("
                "{'event': 'launch', 'account': 'control', 'mode': 'exec',"
                " 'model': 'm', 'note': ''}) else 1)\n")
        control = subprocess.run(
            [sys.executable, "-c", emit], cwd=self.workspace,
            env=self.lane_environment(control_sink),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=120, text=True)
        observed = self.sink_lines(control_sink)
        self.assertEqual(
            (control.returncode, len(observed)), (0, 1),
            "positive control failed: an emit with HEADROOM_NOTIFY_CMD set did "
            "not reach the probe sink, so this test cannot observe a leak and "
            "its result would be meaningless.\n"
            "rc={}\noutput:\n{}\nsink:\n{}".format(
                control.returncode, control.stdout, observed))

    def assert_child_ran(self, result):
        self.assertEqual(
            result.returncode, 0,
            "the child test run did not complete cleanly, so it proves "
            "nothing about hermeticity (fix the child run, not this "
            "assertion).\nrc={}\noutput:\n{}".format(
                result.returncode, result.stdout))
        self.assertIn(
            "Ran ", result.stdout,
            "the child never reported a test count -- it probably never "
            "started.\noutput:\n{}".format(result.stdout))
        self.assertNotIn(
            "Ran 0 tests", result.stdout,
            "the child ran zero tests, so an empty sink means nothing.\n"
            "output:\n{}".format(result.stdout))

    def assert_sink_is_empty(self, sink, what, result):
        leaked = self.sink_lines(sink)
        self.assertEqual(
            len(leaked), 0,
            "{count} event(s) escaped from {what} into a notify sink inherited "
            "from the ambient environment. In this estate that sink is a live "
            "watchdog feed, and a leaked `launch` event clears a real "
            "supervision_lost latch.\nleaked:\n  {events}\nchild output:\n{out}"
            .format(count=len(leaked), what=what,
                    events="\n  ".join(leaked[:12]),
                    out=result.stdout[-2000:]))

    # -- the invariant -----------------------------------------------------

    def test_a_slice_of_the_real_suite_cannot_reach_an_inherited_sink(self):
        """Run real tests in a lane-shaped environment; the sink stays empty."""
        result = self.run_child(
            [sys.executable, "-m", "unittest"] + list(LEAKY_SLICE),
            cwd=REPO_ROOT, sink=self.sink)
        self.assert_child_ran(result)
        self.assert_sink_is_empty(self.sink, "a slice of the real test suite "
                                  "({})".format(", ".join(LEAKY_SLICE)), result)

    def plant_canary(self, source):
        """A throwaway copy of the tests package with one new file in it."""
        package_root = os.path.join(self.workspace, "package")
        if not os.path.isdir(package_root):
            os.makedirs(package_root)
            shutil.copytree(
                TESTS_DIR, os.path.join(package_root, "tests"),
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        canary = os.path.join(package_root, "tests", CANARY_NAME + ".py")
        with open(canary, "w") as handle:
            handle.write(source)
        return package_root, canary

    def test_a_new_test_file_cannot_leak_either(self):
        """The package scrub protects a file that does nothing for itself.

        Named through the package, so the runner imports ``tests`` before the
        module: this arm pins the scrub in ``tests/__init__.py``, and it is
        the only arm whose canary carries no boilerplate at all.
        """
        package_root, _ = self.plant_canary(BARE_CANARY)
        result = self.run_child(
            [sys.executable, "-m", "unittest", "tests." + CANARY_NAME],
            cwd=package_root, sink=self.sink)
        self.assert_child_ran(result)
        self.assert_sink_is_empty(
            self.sink, "a newly added test file that takes no precautions of "
            "its own", result)

    def test_a_narrowed_discovery_pattern_cannot_leak(self):
        """`discover -p <one file>` collects nothing that imports the package.

        This is the form that made collection order a false invariant: it
        filtered out whichever module happened to be importing ``tests`` for
        everybody, and 112 events went to a live sink under a run that
        reported OK. It passes now only because the canary carries the
        bootstrap itself -- delete that line from ``tests.BOOTSTRAP`` and this
        goes red.
        """
        package_root, _ = self.plant_canary(BOOTSTRAPPED_CANARY)
        result = self.run_child(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests",
             "-p", CANARY_NAME + ".py"],
            cwd=package_root, sink=self.sink)
        self.assert_child_ran(result)
        self.assert_sink_is_empty(
            self.sink, "a discovery run narrowed to a single file "
            "(-p {}.py)".format(CANARY_NAME), result)

    def test_running_a_test_file_directly_cannot_leak(self):
        """`python3 tests/<file>.py`, which every file in here invites.

        Each test module ends in ``unittest.main()``, so this is a form the
        repository offers, not an exotic one -- and it starts no package and
        no discovery. sys.path[0] is ``tests/``, so the bootstrap's path
        insert is what makes ``import tests`` resolvable at all; this arm is
        the one that proves that half of the boilerplate works.
        """
        _, canary = self.plant_canary(BOOTSTRAPPED_CANARY)
        result = self.run_child(
            [sys.executable, canary], cwd=self.workspace, sink=self.sink)
        self.assert_child_ran(result)
        self.assert_sink_is_empty(
            self.sink, "a test file executed directly (python3 {}.py)".format(
                CANARY_NAME), result)


if __name__ == "__main__":
    unittest.main()
