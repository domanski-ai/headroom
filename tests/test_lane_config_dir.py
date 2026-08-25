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

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lane = os.path.join(self.temp.name, "lanes", "research")
        self.seat = os.path.join(self.temp.name, "seats", "alpha")
        self.target = os.path.join(self.temp.name, "seats", "beta")
        self.account = {
            "name": "alpha", "provider": "claude", "home": self.seat,
        }

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
