"""The supervisor must never paint on the terminal its child is drawing.

WHY (steward, 2026-08-22). A registry mismatch notice from collect.py printed
to stderr mid session and landed in the sales lane's composer row. It looked
exactly like text a person had typed, no keystroke could delete it, and the
sentinel raised stuck-composer-sales. That alert's own instruction for authored
text is PRESS ENTER, which would have submitted a fabricated instruction into a
live lane. A redraw cleared it, which is what proved it was never composer text.
"""
import contextlib
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401 hermetic bootstrap

from headroom import supervisor  # noqa: E402


ACCOUNT = {"name": "claude-gmail", "provider": "claude", "id": "gmail"}
SUPERVISOR_ID = "quiet-terminal-test"

NOTICE = ("[headroom] the estate registry puts ops in one home and this "
          "registry puts it in another; using this registry's home")


def _runner():
    return supervisor.Supervisor("opus", [], dict(ACCOUNT),
                                 supervisor_id=SUPERVISOR_ID)


class QuietTerminalTest(unittest.TestCase):

    def setUp(self):
        self.terminal = io.StringIO()          # stands in for the child's tty
        self.saved = sys.stderr
        sys.stderr = self.terminal
        self.addCleanup(self._restore)
        log = supervisor.diagnostics_path(SUPERVISOR_ID)
        if os.path.exists(log):
            os.unlink(log)
        self.log = log

    def _restore(self):
        sys.stderr = self.saved

    def _log_text(self):
        if not os.path.exists(self.log):
            return ""
        with open(self.log, encoding="utf-8") as handle:
            return handle.read()

    # ---------------- the behaviour ----------------

    def test_a_collect_notice_never_reaches_the_terminal(self):
        def noisy(quiet=False):
            print(NOTICE, file=sys.stderr)
            return {"accounts": []}

        runner = _runner()
        runner.collect_fn = noisy
        with contextlib.suppress(Exception):
            runner._collect_once(0)

        self.assertNotIn("headroom", self.terminal.getvalue())
        self.assertIn(NOTICE, self._log_text())

    def test_the_terminal_is_handed_back_even_when_collect_raises(self):
        def exploding(quiet=False):
            print(NOTICE, file=sys.stderr)
            raise RuntimeError("provider down")

        runner = _runner()
        runner.collect_fn = exploding
        with self.assertRaises(supervisor.CapacityHold):
            runner._collect_once(0)

        self.assertIs(sys.stderr, self.terminal)
        self.assertEqual(self.terminal.getvalue(), "")
        self.assertIn(NOTICE, self._log_text())

    # ---------------- controls on the surrounding behaviour ----------------

    def test_control_the_typeerror_fallback_still_runs(self):
        calls = []

        def old_style(*args, **kwargs):
            if kwargs.get("quiet") is not None or args:
                calls.append("quiet")
                raise TypeError("run_collect() takes no keyword 'quiet'")
            calls.append("plain")
            return {"accounts": []}

        runner = _runner()
        runner.collect_fn = old_style
        snapshot, _started = runner._collect_once(0)

        self.assertEqual(calls, ["quiet", "plain"])
        self.assertEqual(snapshot, {"accounts": []})

    def test_control_a_failed_collect_still_holds(self):
        def exploding(quiet=False):
            raise RuntimeError("provider down")

        runner = _runner()
        runner.collect_fn = exploding
        with self.assertRaises(supervisor.CapacityHold):
            runner._collect_once(0)

    # ---------------- the real control, one variable reverted ----------------

    def test_mutant_without_the_guard_the_notice_reaches_the_terminal(self):
        """The fixed file with ONE decision reverted.

        Everything else is byte identical: same call site, same collect_fn,
        same assertions. Only the guard becomes a passthrough. If this test
        does NOT see the notice on the terminal, then the test above is
        vacuous and proves nothing about the defect.
        """
        def noisy(quiet=False):
            print(NOTICE, file=sys.stderr)
            return {"accounts": []}

        runner = _runner()
        runner.collect_fn = noisy
        saved_guard = supervisor._quiet_terminal
        supervisor._quiet_terminal = lambda _id: contextlib.nullcontext()
        try:
            with contextlib.suppress(Exception):
                runner._collect_once(0)
        finally:
            supervisor._quiet_terminal = saved_guard

        self.assertIn(NOTICE, self.terminal.getvalue())


if __name__ == "__main__":
    unittest.main()
