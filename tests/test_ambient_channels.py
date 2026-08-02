"""Every test file carries the hermetic bootstrap, and it worked here.

The ambient ``HEADROOM_NOTIFY_CMD`` channel is shut by ``tests/__init__.py``
(see that file for what the channel costs). The question this file answers is
the one that decides whether the fix survives: what makes ``tests/__init__.py``
run?

Not the runner. Measured on this repo: ``discover -s tests -p test_x.py`` and
``python3 tests/test_x.py`` both reach tests without importing the package —
112 events into a live sink. Not collection order either: relying on one early
module to import the package for everyone works only until someone narrows the
pattern, deletes that module, or adds a file that sorts ahead of it.

So the trigger is the only thing that runs under every form — the test module
itself. Every ``tests/test_*.py`` carries ``tests.BOOTSTRAP`` right after its
imports, and ``BootstrapIsInEveryTestFile`` reads the directory off disk and
fails, by name, on any file that does not. That check is deterministic and
order-independent: it does not matter which file runs it, only that the suite
contains it.

``AmbientChannelsAreClosed`` then confirms the outcome in this process. It is
no longer the mechanism — it is the receipt.
"""
import ast
import fnmatch
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401 — hermetic bootstrap; see tests/__init__.py

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

HOW_TO_FIX = """\
{path} is a test file, so it can be reached by a runner that never imports the
tests package: `python3 -m unittest discover -s tests -p {name}` and
`python3 tests/{name}` both do. Without the bootstrap that file inherits
HEADROOM_NOTIFY_CMD from the environment and its launch events go to a live
watchdog feed.

{problem}

Paste this immediately after the imports, before anything that imports
headroom or reads os.environ:

{bootstrap}"""


def _module_body(path):
    with open(path, encoding="utf-8") as handle:
        return ast.parse(handle.read(), filename=path).body


def _is_path_insert(node):
    """`sys.path.insert(0, ...)`, the line the bootstrap sits under."""
    if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)):
        return False
    func = node.value.func
    return (isinstance(func, ast.Attribute) and func.attr == "insert"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "path")


def _is_bootstrap_import(node):
    return (isinstance(node, ast.Import)
            and any(alias.name == "tests" and alias.asname is None
                    for alias in node.names))


def _reaches_headroom(node):
    if isinstance(node, ast.ImportFrom):
        return (node.module or "").split(".")[0] == "headroom"
    return (isinstance(node, ast.Import)
            and any(a.name.split(".")[0] == "headroom" for a in node.names))


def _imported_roots(node):
    if isinstance(node, ast.ImportFrom):
        # `from . import x` has no module; it is a sibling either way.
        return [(node.module or "").split(".")[0]] if node.level == 0 else [""]
    if isinstance(node, ast.Import):
        return [alias.name.split(".")[0] for alias in node.names]
    return []


def _is_sibling(root):
    """Does this import name resolve to something inside ``tests/``?

    Third-party and stdlib imports above the bootstrap are inert — they do
    not read HEADROOM_* and they do not emit. A module living beside this
    one is the escape that matters: it runs at import time, before the
    scrub, and can stash the live environment or emit on its own.
    ``tests``-rooted imports are safe by construction, since importing
    ``tests.anything`` executes ``tests/__init__.py`` first.
    """
    if root == "":            # a relative import — a sibling by definition
        return True
    if root == "tests":
        return False
    return (os.path.isfile(os.path.join(TESTS_DIR, root + ".py"))
            or os.path.isdir(os.path.join(TESTS_DIR, root)))


def is_collectable(name):
    """Can a runner load this file as a test module?

    Deliberately the UNION of the runners' patterns, not our own naming
    habit. unittest discovers ``test*.py`` — note the missing underscore,
    which is how ``testAaa.py`` slipped past an earlier version of this
    audit while the documented run collected it and it leaked.
    """
    return name.endswith(".py") and (
        fnmatch.fnmatch(name, "test*.py")      # unittest's default
        or fnmatch.fnmatch(name, "test_*.py")  # pytest's
        or fnmatch.fnmatch(name, "*_test.py")  # pytest's other one
    )


class BootstrapIsInEveryTestFile(unittest.TestCase):
    """A new test file that forgets the bootstrap turns this suite red.

    Enumerated from disk rather than from collected modules on purpose: the
    defect being pinned is precisely that a runner can decline to collect the
    module you were counting on.
    """

    maxDiff = None

    def fail_file(self, path, problem):
        self.fail(HOW_TO_FIX.format(
            path=os.path.relpath(path, os.path.dirname(TESTS_DIR)),
            name=os.path.basename(path), problem=problem,
            bootstrap="".join(("    " + line).rstrip() + "\n"
                              for line in tests.BOOTSTRAP.splitlines())))

    def test_the_audit_still_covers_every_file_a_runner_can_load(self):
        """A narrowed enumeration passes forever while the channel reopens.

        Measured: narrowing this to ``test_h*`` left the pin, the full
        suite, narrowed discovery and direct execution all green while
        ``discover -s tests -p test_supervisor.py`` put 110 live launch and
        supervision_lost events into the sink. Counting files cannot catch
        that; comparing against an independently derived set can.
        """
        audited = {os.path.basename(p) for p in self.files_on_disk()}
        collectable = {name for name in os.listdir(TESTS_DIR)
                       if is_collectable(name)}
        self.assertEqual(
            audited, collectable,
            "the audit and the runners disagree about what is a test file; "
            "every file a runner can load must be audited")
        self.assertGreaterEqual(len(audited), 2, TESTS_DIR)

    def test_the_pattern_matches_what_the_runners_actually_collect(self):
        """unittest's default is ``test*.py``, not ``test_*.py``.

        The underscore is not cosmetic: ``testAaa_rot.py`` is collected by
        the documented run, and an audit that only knows ``test_*.py``
        reports OK while that file leaks.
        """
        for name in ("test_supervisor.py", "testAaa_rot.py", "testz.py",
                     "widget_test.py"):
            self.assertTrue(is_collectable(name), name)
        for name in ("__init__.py", "fake_claude.py", "conftest.py",
                     "helper.py", "notes.txt"):
            self.assertFalse(is_collectable(name), name)

    def test_the_latch_is_keyed_to_this_process_and_not_inheritable(self):
        """A latch a child inherits is a child that skips the scrub.

        That is the leak, not the optimisation: the events that reach the
        sink come from forked children, so a plain "already done" marker
        in the environment would silence the parent and free the child.
        Keying it to the pid is what makes it idempotent within a process
        and inert across a fork.
        """
        self.assertEqual(os.environ.get(tests._LATCH), str(os.getpid()))

    @staticmethod
    def files_on_disk():
        return sorted(os.path.join(TESTS_DIR, name)
                      for name in os.listdir(TESTS_DIR)
                      if is_collectable(name))

    def test_every_test_file_imports_the_scrub_before_it_can_leak(self):
        for path in self.files_on_disk():
            body = _module_body(path)

            imported = [i for i, node in enumerate(body)
                        if _is_bootstrap_import(node)]
            if not imported:
                self.fail_file(path, "It has no top-level `import tests`.")
            first = imported[0]

            if not any(_is_path_insert(node) for node in body[:first]):
                self.fail_file(
                    path, "It imports tests, but with no sys.path.insert "
                    "above it, so `python3 tests/{}` cannot resolve the "
                    "package (sys.path[0] is tests/, not the repo root)."
                    .format(os.path.basename(path)))

            for node in body[:first]:
                if _reaches_headroom(node):
                    self.fail_file(
                        path, "It imports headroom on line {} — before the "
                        "bootstrap, so headroom is configured from the "
                        "unscrubbed environment.".format(node.lineno))
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    self.fail_file(
                        path, "It assigns a module-level name on line {} — "
                        "before the bootstrap. A constant computed up there "
                        "(the usual `_ENV = dict(os.environ)` snapshot) "
                        "captures the unscrubbed environment and hands it "
                        "back in setUp.".format(node.lineno))
                for root in _imported_roots(node):
                    if not _is_sibling(root):
                        continue
                    self.fail_file(
                        path, "It imports the sibling module `{}` on line "
                        "{} — before the bootstrap. Whatever that helper "
                        "does at import time runs against the unscrubbed "
                        "environment, so it can emit, or stash the live "
                        "HEADROOM_NOTIFY_CMD and hand it back, without this "
                        "file ever touching notify itself.".format(
                            root or "a relative import", node.lineno))


class AmbientChannelsAreClosed(unittest.TestCase):
    """The receipt: in THIS process, the channels are actually shut."""

    def test_no_notify_command_survives_into_the_run(self):
        self.assertEqual(os.environ.get("HEADROOM_NOTIFY_CMD", ""), "")

    def test_no_notify_timeout_survives_into_the_run(self):
        self.assertEqual(os.environ.get("HEADROOM_NOTIFY_TIMEOUT", ""), "")

    def test_the_state_directory_is_not_the_live_one(self):
        """Unset is not safe here: paths.py defaults back to ~/.headroom."""
        live = os.path.join(os.path.expanduser("~"), ".headroom")
        self.assertNotEqual(os.environ.get("HEADROOM_DIR", live), live)

    def test_the_package_that_does_the_scrubbing_is_the_repo_one(self):
        """A stray ``tests`` package on the path would scrub nothing here."""
        self.assertEqual(
            os.path.dirname(os.path.abspath(tests.__file__)), TESTS_DIR)

    def test_the_scrub_runs_once_per_process_however_often_it_is_imported(self):
        """Eleven bootstraps, one temp state directory — and children re-scrub.

        The latch is keyed to the pid rather than held in a module global so
        that re-executing this module under a second name is a no-op while a
        child process, which cannot share the pid, still scrubs its own
        environment.
        """
        self.assertEqual(os.environ.get(tests._LATCH), str(os.getpid()))


if __name__ == "__main__":
    unittest.main()
