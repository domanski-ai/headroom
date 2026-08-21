"""The launcher and the hook-event validator must resolve a child's home the
SAME WAY, once, at construction.

WHY THIS FILE EXISTS. On 2026-08-21 six lanes lost automatic handoff. Each
raised "hook event config home is malformed" within seconds of its own launch.
The cause was that `_environment` resolved the credential directory through
`route.dispatch_dir` (obeying "THE RESOLVED CREDENTIAL DIRECTORY, NEVER THE
REGISTRY HOME", 2026-08-17 R3) while `_record_matches` and `_validated_event`
compared the child's reported config_dir against `account["home"]`, the
registry's answer. For a home whose name lies about what it holds, those two
answers differ, so the supervisor started a child in one place and then
refused that child's events for being there.

EVERY TEST HERE IS WRITTEN TO FAIL ON THE PRE-FIX FILE. A test that passes
both before and after a change measures nothing, and this estate has shipped
four such instruments in one day. Run them against
supervisor.py.bak-20260821T1330Z-prelaunchdir to see them fail.
"""

import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from headroom import supervisor, route            # noqa: E402


class LyingHomeCase(unittest.TestCase):
    """A registry home that names a folder holding a DIFFERENT account.

    This is not a hypothetical. On the day this was written,
    homes/claude-mzansiedge held claude-ops while the registry said ops lived
    in homes/claude-ops, and homes/claude-getdomanski held claude-system.
    """

    def setUp(self):
        import tempfile
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # the folder the REGISTRY names for this account
        self.registry_home = os.path.join(self.temp.name, "homes", "acct-a")
        # the folder the account's chain ACTUALLY lives in, which is what the
        # launcher resolves to and launches into
        self.real_home = os.path.join(self.temp.name, "homes", "somebody-else")
        os.makedirs(self.registry_home, exist_ok=True)
        os.makedirs(self.real_home, exist_ok=True)
        self.account = {"name": "acct-a", "provider": "claude",
                        "home": self.registry_home}

    def _child(self, launch_dir):
        """A Child as `_spawn` builds one: carrying the launcher's own answer."""
        return supervisor.Child(
            process=mock.Mock(), account=self.account, generation=1,
            event_path=os.path.join(self.temp.name, "ev.jsonl"),
            settings_path=os.path.join(self.temp.name, "s.json"),
            launched_at=time.time() - 60, automation=True,
            launch_dir=launch_dir)

    def _record(self, config_dir):
        return {"source_slot": "acct-a", "config_dir": config_dir,
                "received_at": time.time(),
                "payload": {"session_id": "s", "transcript_path": "t"}}

    # ---- THE DEFECT ITSELF -------------------------------------------------

    def test_a_child_in_the_folder_the_launcher_chose_is_NOT_malformed(self):
        """THE REGRESSION TEST FOR THE SIX LANES.

        The launcher resolved `real_home` and launched there. The child
        reports `real_home`. That child is exactly where it was put, so its
        event must validate, even though the registry names a different
        folder for its account.

        Pre-fix this raises PermanentSupervisorError and disarms the child."""
        child = self._child(self.real_home)
        record = self._record(self.real_home)
        with mock.patch.object(supervisor, "_namespace_matches",
                               return_value=True):
            try:
                supervisor._validated_event(record, child)
            except Exception as error:
                # This record deliberately carries no real session or
                # transcript, so it WILL be refused further down. The claim
                # under test is narrow and must stay narrow: it must not be
                # refused for its config HOME. Asserting on the specific
                # message is the difference between a test that polices this
                # defect and one that merely notices the function raised.
                self.assertNotIn(
                    "config home is malformed", str(error),
                    "a child in the directory the launcher chose was refused "
                    "for being in it")

    def test_a_child_reporting_the_REGISTRY_home_it_never_launched_into_IS_refused(self):
        """The guard must still bite. The launcher put this child in
        `real_home`; an event claiming `registry_home` did not come from it.

        Without this, the fix above could be 'accept everything', which would
        be worse than the defect."""
        child = self._child(self.real_home)
        record = self._record(self.registry_home)
        with mock.patch.object(supervisor, "_namespace_matches",
                               return_value=True):
            with self.assertRaises(supervisor.PermanentSupervisorError) as caught:
                supervisor._validated_event(record, child)
        self.assertIn("config home is malformed", str(caught.exception))

    def test_record_matches_uses_the_same_answer_as_validated_event(self):
        """The two sites must not disagree with each other either. They are
        separate copies of one question and only one of them was ever the
        subject of a bug report."""
        child = self._child(self.real_home)
        with mock.patch.object(supervisor, "_namespace_matches",
                               return_value=True):
            self.assertTrue(
                supervisor._record_matches(self._record(self.real_home), child))
            self.assertFalse(
                supervisor._record_matches(self._record(self.registry_home),
                                           child))

    # ---- dmux's design point, 2026-08-21 -----------------------------------

    def test_a_residency_swap_after_construction_does_not_flip_a_live_child(self):
        """RESOLVED ONCE, NEVER PER EVENT.

        At 11:47Z on 2026-08-21 a credential swap moved seven live lanes'
        residency in a single act. If the validator re-resolved per event,
        every one of those children would have flipped validity mid-run,
        which is the thing this file's own rule forbids: 'a config edit
        mid-session can never flip the policy under a live child.'

        So: build the child, THEN move the world, and the verdict must not
        move with it."""
        child = self._child(self.real_home)
        moved = os.path.join(self.temp.name, "homes", "moved-elsewhere")
        os.makedirs(moved, exist_ok=True)
        record = self._record(self.real_home)

        with mock.patch.object(route, "dispatch_dir", return_value=moved), \
                mock.patch.object(supervisor, "_namespace_matches",
                                  return_value=True):
            # still valid: the child has not moved, only the registry has
            self.assertTrue(supervisor._record_matches(record, child))
            # and the child that HAS been re-pointed is still refused
            self.assertFalse(
                supervisor._record_matches(self._record(moved), child))
        self.assertEqual(child.launch_dir, self.real_home,
                         "launch_dir was re-resolved after construction")

    def test_launcher_and_validator_resolve_identically_for_one_account(self):
        """The direct assertion dmux asked for, so that the NEXT R3-style
        sweep miss fails a test instead of silently disarming six lanes.

        A Child built without an explicit launch_dir must land on exactly what
        `route.dispatch_dir` would have given the launcher for that account."""
        with mock.patch.object(route, "dispatch_dir",
                               return_value=self.real_home) as resolver:
            child = supervisor.Child(
                process=mock.Mock(), account=self.account, generation=1,
                event_path=os.path.join(self.temp.name, "ev.jsonl"),
                settings_path=os.path.join(self.temp.name, "s.json"),
                launched_at=time.time(), automation=True)
        resolver.assert_called_once_with(self.account)
        self.assertEqual(child.launch_dir, self.real_home)
        self.assertNotEqual(child.launch_dir, self.account["home"],
                            "the test's own premise is broken: the registry "
                            "home and the resolved home are the same, so this "
                            "asserts nothing")


if __name__ == "__main__":
    unittest.main()
