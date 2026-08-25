"""Fixture tests for per lane Claude config directories."""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401

from headroom import handoff, ops_status, route, statusline, supervisor  # noqa: E402


class PerLaneConfigDirectory(unittest.TestCase):
    SUPERVISOR_ID = "11111111-2222-4333-8444-555555555555"
    SESSION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lane = os.path.join(self.temp.name, "lanes", "research")
        self.seat = os.path.join(self.temp.name, "seats", "alpha")
        self.target = os.path.join(self.temp.name, "seats", "beta")
        self.account = {
            "name": "alpha", "provider": "claude", "home": self.seat,
        }

    def _transcript(self, root):
        directory = os.path.join(root, "projects", "-fixture")
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, self.SESSION_ID + ".jsonl")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{}\n")
        return path

    def _child(self, launch_dir, lane_config_dir):
        return supervisor.Child(
            mock.Mock(pid=os.getpid()), self.account, 1, "", "", 0, True,
            launch_dir=launch_dir, lane_config_dir=lane_config_dir)

    def _hook_record(self, transcript, launch_dir, hook_name="SessionStart",
                     received_at=1):
        return {
            "source_slot": self.account["name"],
            "config_dir": launch_dir,
            "received_at": received_at,
            "payload": {
                "hook_event_name": hook_name,
                "session_id": self.SESSION_ID,
                "transcript_path": transcript,
                "cwd": self.temp.name,
            },
        }

    def _validate_hook(self, transcript, launch_dir, lane_config_dir):
        child = self._child(launch_dir, lane_config_dir)
        record = self._hook_record(transcript, launch_dir)
        with mock.patch.object(supervisor, "_namespace_matches",
                               return_value=True), \
                mock.patch.object(supervisor.time, "time", return_value=1):
            return supervisor._validated_event(record, child)

    def test_hook_event_under_lane_projects_maps_to_supervisor_account(self):
        source, _cwd = self._validate_hook(
            self._transcript(self.lane), self.lane, self.lane)
        self.assertIs(source.account, self.account)

    def test_hook_event_under_lane_projects_without_lane_is_rejected(self):
        with self.assertRaises(supervisor.PermanentSupervisorError) as caught:
            self._validate_hook(self._transcript(self.lane), self.seat, "")
        self.assertEqual(
            str(caught.exception),
            f"session {self.SESSION_ID} is not inside a configured Claude home")

    def test_hook_event_under_random_projects_is_rejected(self):
        random_root = os.path.join(self.temp.name, "random")
        with self.assertRaises(supervisor.PermanentSupervisorError) as caught:
            self._validate_hook(
                self._transcript(random_root), self.lane, self.lane)
        self.assertEqual(
            str(caught.exception),
            f"session {self.SESSION_ID} is not inside a configured Claude home")

    def test_unborn_lane_transcript_is_accepted_without_losing_supervision(self):
        transcript = os.path.join(
            self.lane, "projects", "-fixture", self.SESSION_ID + ".jsonl")
        child = self._child(self.lane, self.lane)
        record = self._hook_record(transcript, self.lane)
        runner = supervisor.Supervisor(
            "sonnet", [], self.account, popen=mock.Mock(), now=lambda: 1)
        with mock.patch.object(supervisor, "_read_events",
                               return_value=[record]), \
                mock.patch.object(supervisor, "_namespace_matches",
                                  return_value=True), \
                mock.patch.object(supervisor.time, "time", return_value=1), \
                mock.patch.object(supervisor.notify, "emit") as emit:
            runner._handle_events(child, "")

        self.assertTrue(child.automation)
        self.assertIsNotNone(child.binding)
        self.assertEqual(child.binding.transcript_path, transcript)
        self.assertFalse(any(call.args[0].get("event") == "supervision_lost"
                             for call in emit.call_args_list))

    def test_deleted_lane_transcript_keeps_the_existing_rejection(self):
        transcript = self._transcript(self.lane)
        child = self._child(self.lane, self.lane)
        child.binding = supervisor.Binding(
            self.SESSION_ID, transcript, self.temp.name, "", "", self.lane)
        child.session_epochs[(self.SESSION_ID, transcript)] = 1
        os.remove(transcript)

        with mock.patch.object(supervisor, "TRANSCRIPT_GRACE_SECONDS", 0.0), \
                mock.patch.object(supervisor, "_namespace_matches",
                                  return_value=True), \
                mock.patch.object(supervisor.time, "time", return_value=1):
            with self.assertRaises(supervisor.TransientSupervisorError) as caught:
                supervisor._validated_event(
                    self._hook_record(
                        transcript, self.lane, "CwdChanged", received_at=2),
                    child)

        self.assertEqual(
            str(caught.exception),
            f"session {self.SESSION_ID} transcript no longer exists")
        self.assertEqual(caught.exception.klass, "deletion")

    def test_lane_launch_uses_seat_credentials_and_census_names_seat(self):
        request_env = {
            "HEADROOM_DIR": os.path.join(self.temp.name, "headroom"),
            "HEADROOM_LANE_CONFIG_DIR": self.lane,
        }
        with mock.patch.dict(os.environ, request_env, clear=True), \
                mock.patch.object(route, "dispatch_dir", return_value=self.seat):
            runner = supervisor.Supervisor(
                "sonnet", [], self.account, supervisor_id=self.SUPERVISOR_ID)
            launched = runner._environment(self.account, 1, True)

        self.assertEqual(launched["CLAUDE_CONFIG_DIR"], self.lane)
        self.assertEqual(
            launched["CLAUDE_SECURESTORAGE_CONFIG_DIR"], self.seat)

        with mock.patch.object(ops_status, "_pids", return_value=([101], "")), \
                mock.patch.object(ops_status, "_boot_time", return_value=None), \
                mock.patch.object(ops_status, "_clock_ticks", return_value=100), \
                mock.patch.object(ops_status, "_proc_environ",
                                  return_value=launched), \
                mock.patch.object(ops_status, "_proc_cmdline",
                                  return_value=["claude"]), \
                mock.patch.object(ops_status, "_is_supervised_child",
                                  return_value=True), \
                mock.patch.object(ops_status, "_proc_stat_fields",
                                  return_value=(100, None)), \
                mock.patch.object(ops_status, "_parent_is_supervisor",
                                  return_value=True):
            children, reason = ops_status.supervised_children("/fixture/proc")

        self.assertEqual(reason, "")
        self.assertEqual(children[0]["config_dir"], os.path.realpath(self.seat))
        self.assertNotEqual(children[0]["config_dir"], os.path.realpath(self.lane))

    def test_statusline_names_secure_storage_seat(self):
        snapshot = {"accounts": [{
            "name": "alpha", "provider": "claude",
            "windows": {"5h": {"used_percent": 20},
                        "7d": {"used_percent": 30}},
        }]}
        environment = {
            "CLAUDE_CONFIG_DIR": self.lane,
            "CLAUDE_SECURESTORAGE_CONFIG_DIR": self.seat,
        }
        output = io.StringIO()
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(statusline.sys, "stdin", io.StringIO("{}")), \
                mock.patch.object(statusline.paths, "load_json",
                                  return_value=snapshot), \
                mock.patch.object(statusline.registry, "accounts",
                                  return_value=[self.account]), \
                redirect_stdout(output):
            self.assertEqual(statusline.main(), 0)
        self.assertIn("alpha", output.getvalue())

    def test_handoff_keeps_lane_and_moves_secure_storage_to_target(self):
        source_environment = {
            "CLAUDE_CONFIG_DIR": self.lane,
            "CLAUDE_SECURESTORAGE_CONFIG_DIR": self.seat,
        }
        resumed = handoff._claude_resume_environment(
            self.target, source_environment)
        self.assertEqual(resumed["CLAUDE_CONFIG_DIR"], self.lane)
        self.assertEqual(
            resumed["CLAUDE_SECURESTORAGE_CONFIG_DIR"], self.target)

        automatic = handoff._claude_resume_environment(self.target, {
            "HEADROOM_LANE_CONFIG_DIR": self.lane,
            "CLAUDE_CONFIG_DIR": self.seat,
        })
        self.assertEqual(automatic["CLAUDE_CONFIG_DIR"], self.lane)
        self.assertEqual(
            automatic["CLAUDE_SECURESTORAGE_CONFIG_DIR"], self.target)

        with mock.patch.dict(os.environ, source_environment, clear=True):
            command = handoff.resume_command(self.target, "session-id")
        self.assertEqual(
            command,
            f"CLAUDE_CONFIG_DIR={self.lane} "
            f"CLAUDE_SECURESTORAGE_CONFIG_DIR={self.target} "
            "claude --resume session-id --fork-session")

    def test_legacy_launch_strips_inherited_secure_storage(self):
        inherited = {
            "PATH": "/fixture/bin",
            "CLAUDE_SECURESTORAGE_CONFIG_DIR": self.target,
        }
        runner = supervisor.Supervisor.__new__(supervisor.Supervisor)
        runner.supervisor_id = self.SUPERVISOR_ID
        runner.lane_config_dir = ""
        with mock.patch.object(supervisor.collect, "scrubbed_env",
                               return_value=dict(inherited)), \
                mock.patch.object(route, "dispatch_dir", return_value=self.seat):
            launched = runner._environment(self.account, 1, False)
        self.assertEqual(launched, {
            "PATH": "/fixture/bin", "CLAUDE_CONFIG_DIR": self.seat,
        })

    def test_router_pin_uses_secure_storage_when_config_is_a_lane(self):
        environment = {
            "CLAUDE_CONFIG_DIR": self.lane,
            "CLAUDE_SECURESTORAGE_CONFIG_DIR": self.seat,
        }
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(route.registry, "family_provider",
                                  return_value="claude"), \
                mock.patch.object(route.registry, "ordered_for",
                                  return_value=[self.account]):
            pinned = route.env_pinned_account("sonnet")
            current = route.current_account("sonnet")
        self.assertEqual(pinned["name"], "alpha")
        self.assertEqual(current["name"], "alpha")


if __name__ == "__main__":
    unittest.main()
