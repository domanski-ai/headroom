"""V2 supervision guarantees + Codex red-team fixes.

Covers the four features (in-process launch fallback, bounded notify hook,
flock slot lease, caps probe) and the adversarial fixes:

  P0-1  flock lease has no stale-cleanup delete race (no pid file to delete)
  P0-2  the lease follows the ACTIVE account across an automatic handoff
  P0-3  an ambiguous spawn window suppresses the fallback (no dup live child)
  P1-4  flock = fd death releases the lease (crash/reuse safe, tested via kill)
  P1-5  supervised `launch` notify fires only AFTER a child exists
  P1-6  session-end-without-replacement routes through _lose_supervision
  P1-7  notify timeout SIGKILLs the whole process group (reaps descendants)
  P1-8  fallback survives an import/preprocessing failure and stays bare
  P1-9  requested leasing FAILS CLOSED on an infrastructure error
  P2-10 caps is command-scoped and honest about `run`
"""
import contextlib
import dataclasses
import io
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from headroom import (  # noqa: E402
    __main__, collect, handoff, notify, paths, registry, route, supervisor,
)

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="resident supervision and handoff are Unix-gated in v1")

IDENTITY = {"account_fingerprint": "AAAA", "credential_digest": "BBBB"}


def usage_row(name, used5=10.0, used7=10.0, captured=None):
    captured = int(time.time()) if captured is None else captured
    return {"name": name, "provider": "claude", "ok": True,
            "routable": True, "trust_state": "verified", "stale": False,
            "captured_at": captured, "identity": dict(IDENTITY),
            "windows": {
                "5h": {"used_percent": used5, "resets_at": captured + 3600,
                       "window_minutes": 300},
                "7d": {"used_percent": used7,
                       "resets_at": captured + 7 * 86400,
                       "window_minutes": 10080},
            }}


def usage_record(total, iterations=2, sidechain=False,
                 model="claude-fable-5-20260701"):
    """An assistant record shaped like the real thing.

    `total` is split across the three input-side counters, and the nested
    `iterations` carry the SAME tokens again — a summer that walked them would
    report a multiple of the truth."""
    read = max(total - 1001, 0)
    usage = {
        "input_tokens": 1, "cache_creation_input_tokens": total - read - 1,
        "cache_read_input_tokens": read, "output_tokens": 405,
        "server_tool_use": {"web_search_requests": 0, "web_fetch_requests": 0},
        "service_tier": "standard",
        "cache_creation": {"ephemeral_1h_input_tokens": total - read - 1,
                           "ephemeral_5m_input_tokens": 0},
        "inference_geo": "not_available", "speed": "standard",
    }
    if iterations:
        usage["iterations"] = [
            {"input_tokens": 1, "output_tokens": 405,
             "cache_read_input_tokens": read, "type": "message",
             "cache_creation_input_tokens": total - read - 1}
            for _ in range(iterations)]
    record = {"type": "assistant", "sessionId": "s", "message": {
        "model": model, "usage": usage,
        "content": [{"type": "text", "text": "done"}]}}
    if sidechain:
        record["isSidechain"] = True
    return record


class TempDirCase(unittest.TestCase):
    """A fresh HEADROOM_DIR per test, with no launch/lease env leakage."""

    CLEAR_VARS = ("HEADROOM_LAUNCH_MARKER", "HEADROOM_LAUNCH_FALLBACK",
                  "HEADROOM_SLOT_LEASE", "HEADROOM_NOTIFY_CMD",
                  "HEADROOM_NOTIFY_TIMEOUT", "CLAUDE_CONFIG_DIR",
                  "CODEX_HOME", "HEADROOM_PREEMPTIVE", "HEADROOM_CTX_WINDOW",
                  "HEADROOM_CONTEXT_BACKSTOP", "HEADROOM_PREEMPTIVE_SESSION")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        environ = {key: value for key, value in os.environ.items()
                   if key not in self.CLEAR_VARS}
        environ["HEADROOM_DIR"] = os.path.join(self.temp.name, "headroom")
        patcher = mock.patch.dict(os.environ, environ, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        # never leak a held flock between tests
        self.addCleanup(route.release_slot_leases)
        # _spawn now installs the signal guard before the window and leaves it
        # for _monitor to restore; a direct _spawn call (no _monitor) would
        # otherwise leak the guard's handlers — snapshot and restore them.
        saved_handlers = {s: signal.getsignal(s)
                          for s in (signal.SIGINT, signal.SIGHUP,
                                    signal.SIGTERM)}

        def _restore_signals():
            for signum, handler in saved_handlers.items():
                signal.signal(signum, handler)
        self.addCleanup(_restore_signals)
        # _spawn now pre-validates the executable with shutil.which; make every
        # name resolve by default so these unit tests don't depend on the host
        # PATH. Tests that want a "missing binary" override this locally.
        which = mock.patch.object(
            supervisor.shutil, "which",
            side_effect=lambda name: "/usr/bin/" + name)
        which.start()
        self.addCleanup(which.stop)

    def account(self, name="acct-a"):
        return {"name": name, "provider": "claude",
                "home": os.path.join(self.temp.name, "homes", name)}


# --------------------------------------------------------------------------
# Feature 4 + P2-10: caps probe
# --------------------------------------------------------------------------
class CapsProbe(TempDirCase):
    def test_caps_is_command_scoped_and_honest_about_run(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(__main__._dispatch(["caps"]), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["schema"], 2)
        self.assertEqual(payload["launch_marker"],
                         {"claude": True, "codex": True})
        self.assertEqual(payload["launch_fallback"],
                         {"claude": True, "codex": True, "run": False})
        self.assertIs(payload["notify_cmd"], True)
        self.assertEqual(payload["slot_lease"], {
            "claude": True, "codex": True, "run": False, "fail_closed": True})


# --------------------------------------------------------------------------
# Feature 2 + P1-7: bounded notify hook
# --------------------------------------------------------------------------
class NotifyDelivery(TempDirCase):
    def notify_script(self):
        out = os.path.join(self.temp.name, "events.log")
        script = os.path.join(self.temp.name, "notify.sh")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\n"
                         f"printf '%s\\n' \"$#\" >> {shlex.quote(out)}\n"
                         f"printf '%s\\n' \"$1\" >> {shlex.quote(out)}\n")
        os.chmod(script, 0o755)
        return script, out

    def test_unset_env_is_a_silent_no_op(self):
        self.assertFalse(notify.emit({"event": "launch"}))

    def test_event_is_delivered_as_a_single_json_argument(self):
        script, out = self.notify_script()
        event = {"event": "launch", "mode": "exec", "account": "a",
                 "model": "sonnet", "note": ""}
        with mock.patch.dict(os.environ, {"HEADROOM_NOTIFY_CMD": script}):
            self.assertTrue(notify.emit(event))
        with open(out, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        self.assertEqual(lines[0], "1")  # exactly one argument
        self.assertEqual(json.loads(lines[1]), event)

    def test_command_with_its_own_args_still_gets_json_last(self):
        script, out = self.notify_script()
        with mock.patch.dict(os.environ,
                             {"HEADROOM_NOTIFY_CMD": f"/bin/sh {script}"}):
            self.assertTrue(notify.emit({"event": "fallback", "reason": "x"}))
        with open(out, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        self.assertEqual(json.loads(lines[1]),
                         {"event": "fallback", "reason": "x"})

    def test_hung_command_is_killed_within_the_bound(self):
        errors = io.StringIO()
        with mock.patch.dict(os.environ, {
                "HEADROOM_NOTIFY_CMD": "/bin/sh -c 'sleep 30'",
                "HEADROOM_NOTIFY_TIMEOUT": "0.2"}), \
                redirect_stderr(errors):
            started = time.monotonic()
            self.assertFalse(notify.emit({"event": "launch"}))
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 5.0)
        self.assertIn("killed", errors.getvalue())

    def test_timeout_kills_the_whole_process_group_not_just_the_shell(self):
        # P1-7: a shell that backgrounds a worker and waits must not leak the
        # worker. The worker writes its pid, then sleeps; after the timeout
        # kills the group, that pid must be gone.
        pidfile = os.path.join(self.temp.name, "worker.pid")
        readyfile = os.path.join(self.temp.name, "worker.ready")
        script = os.path.join(self.temp.name, "group.sh")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write(
                "#!/bin/sh\n"
                "( echo $$ > %s ; : > %s ; sleep 30 ) &\n"
                "wait\n" % (shlex.quote(pidfile), shlex.quote(readyfile)))
        os.chmod(script, 0o755)
        with mock.patch.dict(os.environ, {
                "HEADROOM_NOTIFY_CMD": f"/bin/sh {script}",
                "HEADROOM_NOTIFY_TIMEOUT": "0.3"}), \
                redirect_stderr(io.StringIO()):
            self.assertFalse(notify.emit({"event": "launch"}))
        deadline = time.monotonic() + 3.0
        with open(pidfile, encoding="utf-8") as handle:
            worker_pid = int(handle.read().strip())
        alive = True
        while time.monotonic() < deadline:
            try:
                os.kill(worker_pid, 0)
            except ProcessLookupError:
                alive = False
                break
            time.sleep(0.05)
        self.assertFalse(alive, "backgrounded worker survived the group kill")

    def test_missing_command_never_raises(self):
        errors = io.StringIO()
        with mock.patch.dict(os.environ, {
                "HEADROOM_NOTIFY_CMD": "/definitely/not/here/notify"}), \
                redirect_stderr(errors):
            self.assertFalse(notify.emit({"event": "launch"}))
        self.assertIn("notify failed", errors.getvalue())

    def test_malformed_command_string_never_raises(self):
        with mock.patch.dict(os.environ,
                             {"HEADROOM_NOTIFY_CMD": "'unclosed"}), \
                redirect_stderr(io.StringIO()):
            self.assertFalse(notify.emit({"event": "launch"}))

    def test_blank_command_is_a_no_op(self):
        with mock.patch.dict(os.environ, {"HEADROOM_NOTIFY_CMD": "   "}):
            self.assertFalse(notify.emit({"event": "launch"}))

    def test_unserializable_event_is_swallowed(self):
        script, _ = self.notify_script()
        with mock.patch.dict(os.environ, {"HEADROOM_NOTIFY_CMD": script}), \
                redirect_stderr(io.StringIO()):
            self.assertFalse(notify.emit({"bad": object()}))

    def test_bogus_timeout_override_keeps_the_default_bound(self):
        script, out = self.notify_script()
        with mock.patch.dict(os.environ, {
                "HEADROOM_NOTIFY_CMD": script,
                "HEADROOM_NOTIFY_TIMEOUT": "bogus"}):
            self.assertTrue(notify.emit({"event": "launch"}))
        self.assertTrue(os.path.exists(out))

    def test_nonzero_exit_of_the_observer_is_ignored(self):
        with mock.patch.dict(os.environ,
                             {"HEADROOM_NOTIFY_CMD": "/bin/sh -c 'exit 3'"}):
            self.assertTrue(notify.emit({"event": "launch"}))


# --------------------------------------------------------------------------
# Feature 1: in-process launch fallback (exec path)
# --------------------------------------------------------------------------
class LaunchFallbackExec(TempDirCase):
    def test_default_off_keeps_the_plain_refusal(self):
        with mock.patch.object(route, "pick", return_value=None), \
                mock.patch.object(route.os, "execvp") as execute, \
                redirect_stderr(io.StringIO()):
            code = route.cmd_exec("sonnet", ["claude"])
        self.assertEqual(code, 2)
        execute.assert_not_called()

    def test_no_account_falls_back_to_bare_cli(self):
        command = ["claude", "--model", "sonnet"]
        with mock.patch.object(route, "pick", return_value=None), \
                mock.patch.object(notify, "emit") as emit, \
                mock.patch.object(route.os, "execvpe") as execute, \
                redirect_stderr(io.StringIO()):
            code = route.cmd_exec("sonnet", command, fallback=True)
        self.assertEqual(code, 0)
        self.assertEqual(execute.call_args.args[:2], (command[0], command))
        events = [call.args[0]["event"] for call in emit.call_args_list]
        self.assertEqual(events, ["fallback"])

    def test_bare_fallback_preserves_the_original_environment(self):
        original = {"PATH": "/orig", "HOME": "/orig-home"}
        with mock.patch.object(route.os, "execvpe") as execute, \
                redirect_stderr(io.StringIO()):
            route.bare_fallback_exec(["claude"], "why", env=original)
        self.assertEqual(execute.call_args.args[2], original)

    def test_routing_exception_falls_back_with_original_env(self):
        marker_env = {"PATH": os.environ.get("PATH", ""), "SENTINEL": "1"}
        with mock.patch.dict(os.environ, marker_env, clear=True), \
                mock.patch.object(route, "pick",
                                  side_effect=RuntimeError("collect broke")), \
                mock.patch.object(route.os, "execvpe") as execute, \
                redirect_stderr(io.StringIO()) as errors:
            code = route.cmd_exec("sonnet", ["claude"], fallback=True)
        self.assertEqual(code, 0)
        self.assertEqual(execute.call_args.args[2].get("SENTINEL"), "1")
        self.assertIn("collect broke", errors.getvalue())

    def test_unwritable_marker_falls_back_before_any_routed_exec(self):
        account = self.account()
        snapshot = {"generated": time.time(), "accounts": []}
        with mock.patch.dict(os.environ,
                             {"HEADROOM_LAUNCH_MARKER": "relative/m.json"}), \
                mock.patch.object(route, "pick", return_value=account), \
                mock.patch.object(route, "ensure_fresh_snapshot",
                                  return_value=snapshot), \
                mock.patch.object(route, "block_reason", return_value=None), \
                mock.patch.object(route, "cooldowns", return_value={}), \
                mock.patch.object(notify, "emit") as emit, \
                mock.patch.object(route.os, "execvp") as routed, \
                mock.patch.object(route.os, "execvpe") as bare, \
                redirect_stderr(io.StringIO()):
            code = route.cmd_exec("sonnet", ["claude"], fallback=True)
        self.assertEqual(code, 0)
        routed.assert_not_called()   # the routed exec was never reached
        bare.assert_called_once()    # only the bare fallback ran
        events = [call.args[0]["event"] for call in emit.call_args_list]
        self.assertEqual(events, ["fallback"])

    def test_boundary_reaching_the_routed_exec_never_falls_back(self):
        account = self.account()
        snapshot = {"generated": time.time(), "accounts": []}
        with mock.patch.object(route, "pick", return_value=account), \
                mock.patch.object(route, "ensure_fresh_snapshot",
                                  return_value=snapshot), \
                mock.patch.object(route, "block_reason", return_value=None), \
                mock.patch.object(route, "cooldowns", return_value={}), \
                mock.patch.object(notify, "emit") as emit, \
                mock.patch.object(route.os, "execvp") as routed, \
                mock.patch.object(route.os, "execvpe") as bare, \
                redirect_stderr(io.StringIO()):
            code = route.cmd_exec("sonnet", ["claude"], fallback=True)
        self.assertEqual(code, 0)
        routed.assert_called_once()  # the routed exec ran
        bare.assert_not_called()     # and never the bare fallback
        events = [call.args[0]["event"] for call in emit.call_args_list]
        self.assertEqual(events, ["launch"])

    def test_fallback_exec_failure_reports_127(self):
        with mock.patch.object(route, "pick", return_value=None), \
                mock.patch.object(route.os, "execvpe",
                                  side_effect=FileNotFoundError("gone")), \
                redirect_stderr(io.StringIO()) as errors:
            code = route.cmd_exec("sonnet", ["claude"], fallback=True)
        self.assertEqual(code, 127)
        self.assertIn("fallback exec", errors.getvalue())

    def test_fallback_releases_a_committed_lease_before_baring_out(self):
        with mock.patch.dict(os.environ, {"HEADROOM_SLOT_LEASE": "1"}):
            self.assertTrue(route.acquire_slot_lease(self.account(), "sonnet"))
            self.assertEqual(route.held_lease_names(), ["acct-a"])
            with mock.patch.object(route.os, "execvpe"), \
                    redirect_stderr(io.StringIO()):
                route.bare_fallback_exec(["claude"], "why")
            self.assertEqual(route.held_lease_names(), [])


# --------------------------------------------------------------------------
# Feature 1 + P0-3: in-process launch fallback (supervised path + boundary)
# --------------------------------------------------------------------------
class LaunchFallbackSupervised(TempDirCase):
    def stub_supervisor(self, spawned_any, outcome, ambiguous=False):
        class Stub:
            def __init__(self, family, args, account):
                self.spawned_any = False
                self.spawn_ambiguous = False

            def run(self):
                self.spawned_any = spawned_any
                self.spawn_ambiguous = ambiguous
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome

        return Stub

    def test_no_account_falls_back(self):
        with mock.patch.object(supervisor, "_initial_account",
                               return_value=None), \
                mock.patch.object(notify, "emit") as emit, \
                mock.patch.object(route.os, "execvpe") as execute, \
                redirect_stderr(io.StringIO()):
            code = supervisor.cmd_claude("sonnet", [],
                                         fallback_argv=["claude"])
        self.assertEqual(code, 0)
        execute.assert_called_once()
        self.assertEqual(emit.call_args.args[0]["event"], "fallback")

    def test_no_account_without_fallback_keeps_exit_2(self):
        with mock.patch.object(supervisor, "_initial_account",
                               return_value=None), \
                mock.patch.object(route.os, "execvpe") as execute, \
                redirect_stderr(io.StringIO()):
            code = supervisor.cmd_claude("sonnet", [])
        self.assertEqual(code, 2)
        execute.assert_not_called()

    def test_preparation_exception_falls_back(self):
        with mock.patch.object(
                supervisor, "_initial_account",
                side_effect=registry.RegistryError("no config")), \
                mock.patch.object(route.os, "execvpe") as execute, \
                redirect_stderr(io.StringIO()) as errors:
            code = supervisor.cmd_claude("sonnet", [],
                                         fallback_argv=["claude"])
        self.assertEqual(code, 0)
        execute.assert_called_once()
        self.assertIn("no config", errors.getvalue())

    def test_preparation_exception_without_fallback_raises(self):
        with mock.patch.object(
                supervisor, "_initial_account",
                side_effect=registry.RegistryError("no config")):
            with self.assertRaises(registry.RegistryError):
                supervisor.cmd_claude("sonnet", [])

    def test_first_spawn_failure_falls_back(self):
        stub = self.stub_supervisor(spawned_any=False, outcome=127)
        with mock.patch.object(supervisor, "_initial_account",
                               return_value=self.account()), \
                mock.patch.object(supervisor, "Supervisor", stub), \
                mock.patch.object(route.os, "execvpe") as execute, \
                redirect_stderr(io.StringIO()):
            code = supervisor.cmd_claude("sonnet", [],
                                         fallback_argv=["claude"])
        self.assertEqual(code, 0)
        execute.assert_called_once()

    def test_boundary_spawned_child_exit_never_falls_back(self):
        # a capped/failed child AFTER a successful spawn is a normal exit
        stub = self.stub_supervisor(spawned_any=True, outcome=42)
        with mock.patch.object(supervisor, "_initial_account",
                               return_value=self.account()), \
                mock.patch.object(supervisor, "Supervisor", stub), \
                mock.patch.object(route.os, "execvpe") as execute, \
                redirect_stderr(io.StringIO()):
            code = supervisor.cmd_claude("sonnet", [],
                                         fallback_argv=["claude"])
        self.assertEqual(code, 42)
        execute.assert_not_called()

    def test_boundary_ambiguous_spawn_return_suppresses_fallback(self):
        # P0-3: run() returned with spawn_ambiguous True (a signal fired in
        # the Popen window) — a child MAY be live, so no bare relaunch
        stub = self.stub_supervisor(
            spawned_any=False, outcome=17, ambiguous=True)
        with mock.patch.object(supervisor, "_initial_account",
                               return_value=self.account()), \
                mock.patch.object(supervisor, "Supervisor", stub), \
                mock.patch.object(route.os, "execvpe") as execute, \
                redirect_stderr(io.StringIO()):
            code = supervisor.cmd_claude("sonnet", [],
                                         fallback_argv=["claude"])
        self.assertEqual(code, 17)
        execute.assert_not_called()

    def test_boundary_ambiguous_spawn_exception_suppresses_fallback(self):
        # P0-3: even a raised exception must not fall back while ambiguous
        stub = self.stub_supervisor(
            spawned_any=False, outcome=RuntimeError("async in window"),
            ambiguous=True)
        with mock.patch.object(supervisor, "_initial_account",
                               return_value=self.account()), \
                mock.patch.object(supervisor, "Supervisor", stub), \
                mock.patch.object(route.os, "execvpe") as execute, \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError):
                supervisor.cmd_claude("sonnet", [], fallback_argv=["claude"])
        execute.assert_not_called()

    def test_boundary_post_spawn_exception_still_raises(self):
        stub = self.stub_supervisor(
            spawned_any=True, outcome=RuntimeError("post-spawn crash"))
        with mock.patch.object(supervisor, "_initial_account",
                               return_value=self.account()), \
                mock.patch.object(supervisor, "Supervisor", stub), \
                mock.patch.object(route.os, "execvpe") as execute, \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError):
                supervisor.cmd_claude("sonnet", [], fallback_argv=["claude"])
        execute.assert_not_called()


# --------------------------------------------------------------------------
# P0-3 / P0-1(r3): the real _spawn keeps the ambiguity window OPEN across its
# entire successful return; run() closes it only once it owns the Child.
# --------------------------------------------------------------------------
class SpawnAmbiguityFlag(TempDirCase):
    def test_successful_popen_stays_ambiguous_until_run_owns_child(self):
        # P0-1(r3): _spawn must NOT clear the window after Popen — a failure
        # between Popen-success and run()-holds-Child must keep it ambiguous
        account = self.account()
        runner = supervisor.Supervisor(
            "sonnet", [], account, popen=mock.Mock(return_value=mock.Mock()))
        with mock.patch.object(runner, "_settings_file", return_value=""), \
                redirect_stderr(io.StringIO()):
            runner._spawn(account, [], self.temp.name, False)
        # the child is live but run() has not taken ownership yet
        self.assertTrue(runner.spawn_ambiguous)
        self.assertFalse(runner.spawned_any)

    def test_child_construction_failure_after_popen_stays_ambiguous(self):
        # P0-1(r3) exact repro: Popen succeeds, then Child(...) raises — the
        # window must remain OPEN so run() suppresses recovery
        account = self.account()
        runner = supervisor.Supervisor(
            "sonnet", [], account, popen=mock.Mock(return_value=mock.Mock()))
        with mock.patch.object(runner, "_settings_file", return_value=""), \
                mock.patch.object(supervisor, "Child",
                                  side_effect=RuntimeError("child ctor boom")), \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError):
                runner._spawn(account, [], self.temp.name, False)
        self.assertTrue(runner.spawn_ambiguous)
        self.assertFalse(runner.spawned_any)

    def test_run_closes_the_window_once_it_owns_the_child(self):
        # the window is closed in run(), not _spawn
        account = self.account()
        runner = supervisor.Supervisor("sonnet", [], account)
        child = mock.Mock()
        child.account = account

        def fake_spawn(*a, **k):
            runner.spawn_ambiguous = True  # real _spawn leaves it True
            return child

        with mock.patch.object(runner, "_spawn", side_effect=fake_spawn), \
                mock.patch.object(runner, "_reconcile_leases"), \
                mock.patch.object(runner, "_monitor", return_value=0), \
                redirect_stderr(io.StringIO()):
            code = runner.run()
        self.assertEqual(code, 0)
        self.assertTrue(runner.spawned_any)
        self.assertFalse(runner.spawn_ambiguous)

    def test_popen_oserror_now_stays_ambiguous(self):
        # r5: a Popen OSError is NO LONGER treated as "positively no child".
        # It is conservative-by-type-independence — a child MAY be live, so the
        # window stays ambiguous (never cleared inside the window).
        account = self.account()
        runner = supervisor.Supervisor(
            "sonnet", [], account,
            popen=mock.Mock(side_effect=OSError("boom")))
        with mock.patch.object(runner, "_settings_file", return_value=""), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(OSError):
                runner._spawn(account, [], self.temp.name, False)
        self.assertFalse(runner.spawned_any)
        self.assertTrue(runner.spawn_ambiguous)  # stays OPEN

    def test_missing_binary_is_a_positive_pre_spawn_failure(self):
        # r5: the ONLY thing that positively means "no child" is a pre-spawn
        # validation failure BEFORE the window — here, the binary not resolving.
        # spawn_ambiguous must NOT be set (safe to recover / fall back).
        account = self.account()
        popen = mock.Mock(return_value=mock.Mock())
        runner = supervisor.Supervisor("sonnet", [], account, popen=popen)
        with mock.patch.object(supervisor.shutil, "which", return_value=None), \
                mock.patch.object(runner, "_settings_file", return_value=""), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(supervisor.SupervisorError):
                runner._spawn(account, [], self.temp.name, False)
        popen.assert_not_called()          # never entered the spawn window
        self.assertFalse(runner.spawn_ambiguous)
        self.assertFalse(runner.spawned_any)

    def test_trace_hook_raising_in_popen_window_stays_ambiguous(self):
        # the exact P0 repro, with no masking machinery: a trace hook that
        # raises while inside the Popen call must leave the window ambiguous
        # (a child may be live) and never let run() double-spawn.
        account = self.account()

        def popen(argv, env=None, cwd=None, **kw):
            # emulate a trace/profile-induced exception escaping Popen
            raise RuntimeError("trace hook raised inside the Popen window")

        runner = supervisor.Supervisor("sonnet", [], account, popen=popen)
        with mock.patch.object(runner, "_settings_file", return_value=""), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError):
                runner._spawn(account, [], self.temp.name, False)
        self.assertTrue(runner.spawn_ambiguous)
        self.assertFalse(runner.spawned_any)

    def test_async_failure_in_the_popen_window_stays_ambiguous(self):
        # simulate a signal/trace handler firing the instant Popen returns
        account = self.account()

        def popen_then_raise(argv, env=None, cwd=None, **kw):
            raise KeyboardInterrupt("signal landed after the child was live")

        runner = supervisor.Supervisor(
            "sonnet", [], account, popen=popen_then_raise)
        with mock.patch.object(runner, "_settings_file", return_value=""), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                runner._spawn(account, [], self.temp.name, False)
        # KeyboardInterrupt is not the OSError handler, so ambiguity is NOT
        # cleared -> the fallback would be suppressed
        self.assertFalse(runner.spawned_any)
        self.assertTrue(runner.spawn_ambiguous)


# --------------------------------------------------------------------------
# Feature 2 wiring + P1-5: notify events at the right transitions
# --------------------------------------------------------------------------
class NotifyWiring(TempDirCase):
    def test_exec_launch_emits_downgrade_then_launch(self):
        account = self.account()
        snapshot = {"generated": time.time(), "accounts": []}
        with mock.patch.object(route, "pick", return_value=account), \
                mock.patch.object(route, "ensure_fresh_snapshot",
                                  return_value=snapshot), \
                mock.patch.object(route, "block_reason", return_value=None), \
                mock.patch.object(route, "cooldowns", return_value={}), \
                mock.patch.object(notify, "emit") as emit, \
                mock.patch.object(route.os, "execvp"), \
                redirect_stderr(io.StringIO()):
            route.cmd_exec("sonnet", ["claude"],
                           launch_note="auto-handoff disabled: --settings")
        payloads = [call.args[0] for call in emit.call_args_list]
        self.assertEqual([p["event"] for p in payloads],
                         ["downgrade", "launch"])
        self.assertEqual(payloads[0]["account"], "acct-a")
        self.assertEqual(payloads[0]["reason"],
                         "auto-handoff disabled: --settings")
        self.assertEqual(payloads[1]["mode"], "exec")

    def test_exec_launch_without_note_emits_launch_only(self):
        account = self.account()
        snapshot = {"generated": time.time(), "accounts": []}
        with mock.patch.object(route, "pick", return_value=account), \
                mock.patch.object(route, "ensure_fresh_snapshot",
                                  return_value=snapshot), \
                mock.patch.object(route, "block_reason", return_value=None), \
                mock.patch.object(route, "cooldowns", return_value={}), \
                mock.patch.object(notify, "emit") as emit, \
                mock.patch.object(route.os, "execvp"), \
                redirect_stderr(io.StringIO()):
            route.cmd_exec("sonnet", ["claude"])
        self.assertEqual([call.args[0]["event"]
                          for call in emit.call_args_list], ["launch"])

    def test_supervised_launch_emits_only_after_a_child_exists(self):
        # P1-5: the launch event must not precede a real Popen
        account = self.account()
        order = []

        def popen(argv, env=None, cwd=None, **kw):
            order.append("popen")
            return mock.Mock()

        runner = supervisor.Supervisor("sonnet", [], account, popen=popen)

        def record_emit(event):
            order.append(("emit", event["event"]))
            return True

        with mock.patch.object(notify, "emit", side_effect=record_emit), \
                mock.patch.object(runner, "_settings_file", return_value=""):
            runner._spawn(account, [], self.temp.name, False)
            runner._spawn(account, [], self.temp.name, False)
        self.assertEqual(order[0], "popen")             # child first
        self.assertEqual(order[1], ("emit", "launch"))  # THEN the launch event
        self.assertEqual(order.count(("emit", "launch")), 1)  # gen 1 only

    def test_spawn_refusal_emits_no_launch_event(self):
        account = self.account()
        popen = mock.Mock()
        runner = supervisor.Supervisor("sonnet", [], account, popen=popen)
        with mock.patch.object(route, "write_launch_marker",
                               return_value=False), \
                mock.patch.object(notify, "emit") as emit, \
                mock.patch.object(runner, "_settings_file", return_value=""), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(supervisor.SupervisorError):
                runner._spawn(account, [], self.temp.name, False)
        emit.assert_not_called()
        popen.assert_not_called()
        self.assertFalse(runner.spawned_any)

    def test_bind_timeout_emits_supervision_lost_once(self):
        account = self.account()
        polls = iter([None, None, 0])

        class FakeProcess:
            pid = os.getpid()

            @staticmethod
            def poll():
                return next(polls)

        clock = {"t": 1000.0}
        runner = supervisor.Supervisor(
            "sonnet", [], account,
            popen=lambda argv, env=None, cwd=None, **kw: FakeProcess(),
            now=lambda: clock["t"], sleep=lambda seconds: None)
        with mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            child = runner._spawn(account, [], self.temp.name, True)
            clock["t"] = 1000.0 + supervisor.BIND_TIMEOUT + 1
            outcome = runner._monitor(child)
        self.assertEqual(outcome, 0)
        events = [call.args[0] for call in emit.call_args_list]
        self.assertEqual([event["event"] for event in events],
                         ["launch", "supervision_lost"])
        self.assertIn("SessionStart hook never bound", events[1]["reason"])
        self.assertFalse(child.automation)


# --------------------------------------------------------------------------
# P1-6: the session-end-without-replacement disarm routes through the helper
# --------------------------------------------------------------------------
class SupervisionLostCoverage(TempDirCase):
    def test_session_end_without_replacement_emits_supervision_lost(self):
        account = self.account()
        runner = supervisor.Supervisor("sonnet", [], account,
                                       popen=mock.Mock())
        binding = supervisor.Binding(
            "11111111-1111-1111-1111-111111111111",
            "/t.jsonl", "/cwd", "sonnet", "1", account["home"], epoch=1)
        child = supervisor.Child(
            process=mock.Mock(), account=account, generation=1,
            event_path="/dev/null", settings_path="", launched_at=0.0,
            automation=True, binding=binding, session_epoch=1)
        child.dead_sessions.add((binding.session_id, binding.epoch))
        with mock.patch.object(supervisor, "_read_events", return_value=[]), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            result = runner._handle_events(child, "")
        self.assertIsNone(result)
        self.assertFalse(child.automation)
        self.assertTrue(child.supervision_loss_notified)
        events = [call.args[0] for call in emit.call_args_list]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "supervision_lost")
        self.assertIn("without a replacement", events[0]["reason"])


# --------------------------------------------------------------------------
# Feature 3 + P0-1/P1-4/P1-9: flock slot lease
# --------------------------------------------------------------------------
class SlotLease(TempDirCase):
    def lease_env(self):
        return mock.patch.dict(os.environ, {"HEADROOM_SLOT_LEASE": "1"})

    def hold_foreign_lease(self, name):
        """Spawn a subprocess that flock()s the account lock file and blocks,
        so THIS process sees a live foreign holder. Returns the Popen."""
        os.makedirs(route._leases_dir(), exist_ok=True)
        ready = os.path.join(self.temp.name, f"{name}.held")
        code = (
            "import fcntl, os, sys, time\n"
            "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "open(sys.argv[2], 'w').close()\n"
            "time.sleep(60)\n")
        process = subprocess.Popen(
            [sys.executable, "-c", code, route._lease_path(name), ready],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        deadline = time.monotonic() + 5.0
        while not os.path.exists(ready) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(os.path.exists(ready), "foreign holder never armed")
        return process

    def test_disabled_is_a_complete_no_op(self):
        account = self.account()
        self.assertTrue(route.acquire_slot_lease(account, "sonnet"))
        self.assertEqual(route.held_lease_names(), [])
        self.assertFalse(os.path.exists(route._lease_path("acct-a")))
        # feature off: even a live foreign holder is invisible to routing
        self.hold_foreign_lease("acct-a")
        self.assertFalse(route._account_leased_by_other("acct-a"))
        self.assertEqual(
            route.block_reason(account, "sonnet", None, {}, time.time()),
            "no usage reading yet")

    def test_acquire_holds_the_flock_and_records_the_name(self):
        with self.lease_env():
            self.assertTrue(route.acquire_slot_lease(self.account(), "sonnet"))
        self.assertEqual(route.held_lease_names(), ["acct-a"])
        self.assertTrue(route.holds_slot_lease("acct-a"))
        with open(route._lease_path("acct-a"), encoding="utf-8") as handle:
            meta = json.load(handle)
        self.assertEqual(meta["account"], "acct-a")
        self.assertEqual(meta["pid"], os.getpid())

    def test_own_lease_never_blocks_and_can_be_reacquired(self):
        account = self.account()
        with self.lease_env():
            self.assertTrue(route.acquire_slot_lease(account, "sonnet"))
            self.assertFalse(route._account_leased_by_other("acct-a"))
            self.assertTrue(route.acquire_slot_lease(account, "sonnet"))
            self.assertEqual(
                route.block_reason(account, "sonnet", None, {}, time.time()),
                "no usage reading yet")

    def test_live_foreign_lease_blocks_routing_and_acquire(self):
        account = self.account()
        with self.lease_env():
            self.hold_foreign_lease("acct-a")
            self.assertTrue(route._account_leased_by_other("acct-a"))
            reason = route.block_reason(account, "sonnet", None, {},
                                        time.time())
            self.assertEqual(reason, "slot leased by another live launch")
            self.assertFalse(route.acquire_slot_lease(account, "sonnet"))
            self.assertEqual(route.held_lease_names(), [])

    def test_dead_holder_releases_the_lease_via_fd_death(self):
        # P1-4: flock is dropped by the kernel when the holder dies — no pid
        # to reuse, no stale file to clean
        account = self.account()
        with self.lease_env():
            process = self.hold_foreign_lease("acct-a")
            self.assertTrue(route._account_leased_by_other("acct-a"))
            process.kill()
            process.wait()
            # the lock FILE still exists, but the flock is gone
            self.assertTrue(os.path.exists(route._lease_path("acct-a")))
            self.assertFalse(route._account_leased_by_other("acct-a"))
            self.assertTrue(route.acquire_slot_lease(account, "sonnet"))

    def test_no_stale_delete_race_a_probe_never_evicts_a_live_lease(self):
        # P0-1: with flock there is no read/liveness/delete/claim sequence, so
        # a would-be racer's probe/acquire attempt can neither delete nor
        # steal a lease another live launch holds. A foreign holder keeps the
        # lock; our probe returns "leased" and our acquire returns False, and
        # the lock file is never removed.
        account = self.account()
        with self.lease_env():
            self.hold_foreign_lease("acct-a")
            path = route._lease_path("acct-a")
            self.assertTrue(os.path.exists(path))
            self.assertTrue(route._account_leased_by_other("acct-a"))
            self.assertFalse(route.acquire_slot_lease(account, "sonnet"))
            self.assertTrue(os.path.exists(path))  # never deleted
            self.assertTrue(route._account_leased_by_other("acct-a"))

    def test_release_one_lease_frees_it_for_the_next_launch(self):
        account = self.account()
        with self.lease_env():
            self.assertTrue(route.acquire_slot_lease(account, "sonnet"))
            route.release_slot_lease("acct-a")
            self.assertEqual(route.held_lease_names(), [])
            # released -> a fresh acquire succeeds (flock is free)
            self.assertTrue(route.acquire_slot_lease(account, "sonnet"))

    def test_acquire_fails_closed_when_the_lease_dir_is_unusable(self):
        # P1-9: requested leasing must NOT silently launch unleased
        account = self.account()
        with self.lease_env():
            paths.ensure_private(paths.state_dir())
            # a FILE where the leases directory must be makes makedirs fail
            with open(route._leases_dir(), "w", encoding="utf-8") as handle:
                handle.write("blocker")
            with self.assertRaises(route.LeaseError):
                route.acquire_slot_lease(account, "sonnet")

    def test_nameless_account_under_leasing_fails_closed(self):
        with self.lease_env():
            with self.assertRaises(route.LeaseError):
                route.acquire_slot_lease({"provider": "claude"}, "sonnet")

    def test_probe_never_crashes_on_a_broken_lock_path(self):
        with self.lease_env():
            os.makedirs(route._leases_dir(), exist_ok=True)
            # a directory where the lock file would be: open may error — must
            # degrade to "not leased", never raise
            os.makedirs(route._lease_path("acct-a"))
            self.assertFalse(route._account_leased_by_other("acct-a"))

    def test_concurrent_initial_launches_pick_different_accounts(self):
        homes = {name: os.path.join(self.temp.name, "homes", name)
                 for name in ("acct-a", "acct-b")}
        registry.save({"schema_version": 1, "accounts": [
            {"name": name, "provider": "claude", "home": home}
            for name, home in homes.items()]})
        snapshot = {"generated": time.time(),
                    "accounts": [usage_row("acct-a"), usage_row("acct-b")]}
        with self.lease_env(), \
                mock.patch.object(route.collector, "local_binding",
                                  return_value=("AAAA", "BBBB")):
            ranked = route.candidates("sonnet", snapshot)
            self.assertEqual(
                [(a["name"], r) for a, r in ranked],
                [("acct-a", None), ("acct-b", None)])
            # a second launcher holds acct-a: this launcher must diverge
            self.hold_foreign_lease("acct-a")
            by_name = {a["name"]: r
                       for a, r in route.candidates("sonnet", snapshot)}
            self.assertIsNone(by_name["acct-b"])
            self.assertEqual(by_name["acct-a"],
                             "slot leased by another live launch")

    def test_cmd_exec_repicks_when_the_claim_race_is_lost(self):
        account_a, account_b = self.account("acct-a"), self.account("acct-b")
        snapshot = {"generated": time.time(), "accounts": []}
        with self.lease_env(), \
                mock.patch.object(route, "pick",
                                  side_effect=[account_a, account_b]), \
                mock.patch.object(route, "ensure_fresh_snapshot",
                                  return_value=snapshot), \
                mock.patch.object(route, "block_reason", return_value=None), \
                mock.patch.object(route, "cooldowns", return_value={}), \
                mock.patch.object(route.os, "execvp") as execute, \
                redirect_stderr(io.StringIO()):
            self.hold_foreign_lease("acct-a")
            route.cmd_exec("sonnet", ["claude"])
            selected = os.environ.get("CLAUDE_CONFIG_DIR")
        execute.assert_called_once()
        self.assertEqual(selected, account_b["home"])
        self.assertEqual(route.held_lease_names(), ["acct-b"])

    def test_cmd_exec_fails_closed_on_lease_infrastructure_error(self):
        # P1-9: LeaseError -> refuse (exit 2), never launch unleased
        account = self.account()
        snapshot = {"generated": time.time(), "accounts": []}
        with self.lease_env(), \
                mock.patch.object(route, "pick", return_value=account), \
                mock.patch.object(route, "ensure_fresh_snapshot",
                                  return_value=snapshot), \
                mock.patch.object(route, "block_reason", return_value=None), \
                mock.patch.object(route, "cooldowns", return_value={}), \
                mock.patch.object(route, "acquire_slot_lease",
                                  side_effect=route.LeaseError("disk full")), \
                mock.patch.object(route, "write_launch_marker") as marker, \
                mock.patch.object(route.os, "execvp") as execute, \
                redirect_stderr(io.StringIO()) as errors:
            code = route.cmd_exec("sonnet", ["claude"])
        self.assertEqual(code, 2)
        execute.assert_not_called()
        marker.assert_not_called()
        self.assertIn("fails closed", errors.getvalue())

    def test_cmd_claude_fails_closed_but_fallback_bares_out(self):
        # P1-9 + Feature 1: without fallback -> exit 2; with fallback -> bare
        account = self.account()
        with self.lease_env(), \
                mock.patch.object(supervisor, "_initial_account",
                                  return_value=account), \
                mock.patch.object(route, "acquire_slot_lease",
                                  side_effect=route.LeaseError("disk full")), \
                mock.patch.object(route.os, "execvpe") as bare, \
                redirect_stderr(io.StringIO()):
            self.assertEqual(supervisor.cmd_claude("sonnet", []), 2)
            bare.assert_not_called()
            code = supervisor.cmd_claude("sonnet", [],
                                         fallback_argv=["claude"])
        self.assertEqual(code, 0)
        bare.assert_called_once()


# --------------------------------------------------------------------------
# P0-2: the lease follows the ACTIVE account across an automatic handoff
# --------------------------------------------------------------------------
class LeaseFollowsActiveAccount(TempDirCase):
    def source(self):
        return {"name": "source", "provider": "claude",
                "home": os.path.join(self.temp.name, "source")}

    def target(self):
        return {"name": "target", "provider": "claude",
                "home": os.path.join(self.temp.name, "target")}

    def plan(self):
        source = mock.Mock()
        source.account = self.source()
        # target_family mirrors HandoffPlan's property: the family the TARGET
        # is gated on, which is `family` unless a cap forced a downgrade
        return type("P", (), {"target": self.target(), "family": "sonnet",
                              "target_family": "sonnet",
                              "resume_family": "", "source": source})()

    def test_lease_target_acquires_the_target_account(self):
        runner = supervisor.Supervisor("sonnet", [], self.source())
        with mock.patch.object(route, "acquire_slot_lease",
                               return_value=True) as acquire:
            runner._lease_target(self.plan())
        acquire.assert_called_once()
        self.assertEqual(acquire.call_args.args[0]["name"], "target")

    def test_lease_target_contended_holds_the_handoff(self):
        runner = supervisor.Supervisor("sonnet", [], self.source())
        with mock.patch.object(route, "acquire_slot_lease",
                               return_value=False):
            with self.assertRaises(supervisor.SupervisorError):
                runner._lease_target(self.plan())

    def test_lease_target_infra_error_holds_the_handoff(self):
        runner = supervisor.Supervisor("sonnet", [], self.source())
        with mock.patch.object(route, "acquire_slot_lease",
                               side_effect=route.LeaseError("nope")):
            with self.assertRaises(supervisor.SupervisorError):
                runner._lease_target(self.plan())

    def test_reconcile_releases_the_old_source_keeps_the_active_target(self):
        with mock.patch.dict(os.environ, {"HEADROOM_SLOT_LEASE": "1"}):
            self.assertTrue(route.acquire_slot_lease(self.source(), "sonnet"))
            self.assertTrue(route.acquire_slot_lease(self.target(), "sonnet"))
            self.assertEqual(sorted(route.held_lease_names()),
                             ["source", "target"])
            runner = supervisor.Supervisor("sonnet", [], self.source())
            runner._reconcile_leases("target")  # target is the active child
        self.assertEqual(route.held_lease_names(), ["target"])

    def test_reconcile_releases_an_unused_target_after_failed_rotation(self):
        with mock.patch.dict(os.environ, {"HEADROOM_SLOT_LEASE": "1"}):
            self.assertTrue(route.acquire_slot_lease(self.source(), "sonnet"))
            self.assertTrue(route.acquire_slot_lease(self.target(), "sonnet"))
            runner = supervisor.Supervisor("sonnet", [], self.source())
            # rotation failed -> the SOURCE is again the active child
            runner._reconcile_leases("source")
        self.assertEqual(route.held_lease_names(), ["source"])


# --------------------------------------------------------------------------
# CLI wiring (fallback flag threading, P1-8a pre-import guard)
# --------------------------------------------------------------------------
class CliWiringV2(TempDirCase):
    def test_claude_flag_is_stripped_and_enables_exec_fallback(self):
        with mock.patch.object(registry, "auto_handoff", return_value=False), \
                mock.patch("headroom.route.cmd_exec",
                           return_value=5) as execute:
            code = __main__._dispatch(
                ["claude", "--headroom-launch-fallback", "--model", "sonnet"])
        self.assertEqual(code, 5)
        execute.assert_called_once_with(
            "sonnet", ["claude", "--model", "sonnet"],
            launch_note="auto-handoff not enabled", fallback=True)

    def test_env_var_enables_fallback_without_the_flag(self):
        with mock.patch.dict(os.environ,
                             {"HEADROOM_LAUNCH_FALLBACK": "1"}), \
                mock.patch.object(registry, "auto_handoff",
                                  return_value=False), \
                mock.patch("headroom.route.cmd_exec",
                           return_value=5) as execute:
            __main__._dispatch(["claude", "--model", "sonnet"])
        execute.assert_called_once_with(
            "sonnet", ["claude", "--model", "sonnet"],
            launch_note="auto-handoff not enabled", fallback=True)

    def test_defaults_keep_the_exact_legacy_call_shape(self):
        with mock.patch.object(registry, "auto_handoff", return_value=False), \
                mock.patch("headroom.route.cmd_exec",
                           return_value=5) as execute:
            __main__._dispatch(["claude", "--model", "sonnet"])
        execute.assert_called_once_with(
            "sonnet", ["claude", "--model", "sonnet"],
            launch_note="auto-handoff not enabled")

    def test_codex_flag_is_stripped_and_enables_fallback(self):
        with mock.patch("headroom.route.cmd_exec", return_value=7) as execute:
            code = __main__._dispatch(["codex", "--headroom-launch-fallback"])
        self.assertEqual(code, 7)
        execute.assert_called_once_with("codex", ["codex"], launch_note="",
                                        fallback=True)

    def test_codex_flag_after_separator_passes_through(self):
        with mock.patch("headroom.route.cmd_exec", return_value=0) as execute:
            __main__._dispatch(["codex", "--", "--headroom-launch-fallback"])
        execute.assert_called_once_with(
            "codex", ["codex", "--", "--headroom-launch-fallback"],
            launch_note="")

    def test_supervised_launch_gets_the_bare_fallback_argv(self):
        tty = mock.Mock()
        tty.isatty.return_value = True
        with mock.patch.object(registry, "auto_handoff", return_value=True), \
                mock.patch.object(__main__.sys, "stdin", tty), \
                mock.patch.object(__main__.sys, "stdout", tty), \
                mock.patch.object(__main__.sys, "stderr", tty), \
                mock.patch("headroom.supervisor.cmd_claude",
                           return_value=9) as run:
            code = __main__._dispatch(
                ["claude", "--headroom-launch-fallback", "--model", "sonnet"])
        self.assertEqual(code, 9)
        run.assert_called_once_with(
            "sonnet", ["--model", "sonnet"],
            fallback_argv=["claude", "--model", "sonnet"])

    def test_usage_refusal_is_not_a_fallback(self):
        # a provider/model mismatch is a caller bug: refuse (exit 2), never
        # bare-exec, even with fallback requested
        with mock.patch.object(route.os, "execvp") as execute, \
                mock.patch.object(route.os, "execvpe") as bare, \
                redirect_stderr(io.StringIO()):
            code = __main__._dispatch(
                ["codex", "--headroom-launch-fallback", "--model", "sonnet"])
        self.assertEqual(code, 2)
        execute.assert_not_called()
        bare.assert_not_called()

    def test_import_preprocessing_failure_falls_back_to_bare_cli(self):
        # P1-8a: a failure while preparing the launch still bare-execs when
        # the fallback is requested
        with mock.patch.object(__main__, "_prepare_launch",
                               side_effect=RuntimeError("import blew up")), \
                mock.patch.object(__main__.os, "execvp") as execute, \
                redirect_stderr(io.StringIO()) as errors:
            code = __main__._dispatch(
                ["claude", "--headroom-launch-fallback", "--model", "sonnet"])
        self.assertEqual(code, 0)
        execute.assert_called_once()
        # the bare argv has headroom's own flag stripped
        self.assertEqual(execute.call_args.args[1],
                         ["claude", "--model", "sonnet"])
        self.assertIn("preprocessing failed", errors.getvalue())

    def test_import_failure_without_fallback_propagates(self):
        with mock.patch.object(__main__, "_prepare_launch",
                               side_effect=RuntimeError("import blew up")):
            with self.assertRaises(RuntimeError):
                __main__._dispatch(["claude", "--model", "sonnet"])

    def test_split_headroom_flags_respects_values_and_separator(self):
        cleaned, found = supervisor.split_headroom_flags([
            "--model", "--headroom-launch-fallback",
            "--headroom-launch-fallback", "--",
            "--headroom-launch-fallback"])
        self.assertEqual(cleaned, [
            "--model", "--headroom-launch-fallback", "--",
            "--headroom-launch-fallback"])
        self.assertEqual(found, {"--headroom-launch-fallback"})


class HeadlessSupervision(TempDirCase):
    """A headless (non-TTY) launch normally execs and cannot rotate on a cap.
    With --headroom-auto-handoff (every dispatched brief sends it) or
    HEADROOM_HEADLESS_SUPERVISION=1 the stateful supervisor runs headless too,
    so the baton/resume handoff still fires on a cap — never a command replay.
    incompatible_args still forces exec-only in every mode."""

    @staticmethod
    def _non_tty():
        stream = mock.Mock()
        stream.isatty.return_value = False
        return stream

    def _dispatch_non_tty(self, argv):
        pipe = self._non_tty()
        with mock.patch.object(__main__.sys, "stdin", pipe), \
                mock.patch.object(__main__.sys, "stdout", pipe), \
                mock.patch.object(__main__.sys, "stderr", pipe), \
                mock.patch("headroom.supervisor.cmd_claude",
                           return_value=41) as supervised, \
                mock.patch("headroom.route.cmd_exec",
                           return_value=42) as execed:
            code = __main__._dispatch(argv)
        return code, supervised, execed

    def test_explicit_flag_supervises_a_headless_run(self):
        # the exact dispatch shape: `claude --headroom-auto-handoff ...`, piped
        with mock.patch.object(registry, "auto_handoff", return_value=False):
            code, supervised, execed = self._dispatch_non_tty(
                ["claude", "--headroom-auto-handoff", "--model", "sonnet"])
        self.assertEqual(code, 41)
        supervised.assert_called_once_with("sonnet", ["--model", "sonnet"])
        execed.assert_not_called()

    def test_env_opt_in_supervises_headless_without_the_flag(self):
        # config-driven auto-handoff + the env switch, no explicit flag
        with mock.patch.dict(os.environ,
                             {"HEADROOM_HEADLESS_SUPERVISION": "1"}), \
                mock.patch.object(registry, "auto_handoff", return_value=True):
            code, supervised, execed = self._dispatch_non_tty(
                ["claude", "--model", "sonnet"])
        self.assertEqual(code, 41)
        supervised.assert_called_once_with("sonnet", ["--model", "sonnet"])
        execed.assert_not_called()

    def test_env_zero_forces_exec_even_with_the_flag(self):
        # explicit revert switch: HEADROOM_HEADLESS_SUPERVISION=0 keeps the old
        # exec-only headless behaviour even when the flag is present
        with mock.patch.dict(os.environ,
                             {"HEADROOM_HEADLESS_SUPERVISION": "0"}), \
                mock.patch.object(registry, "auto_handoff", return_value=False):
            code, supervised, execed = self._dispatch_non_tty(
                ["claude", "--headroom-auto-handoff", "--model", "sonnet"])
        self.assertEqual(code, 42)
        supervised.assert_not_called()
        execed.assert_called_once_with(
            "sonnet", ["claude", "--model", "sonnet"],
            launch_note="auto-handoff disabled: "
                        "stdin/stdout/stderr are not all TTYs")

    def test_incompatible_args_stay_exec_only_when_headless(self):
        # -p has no resumable session: supervise must never engage, flag or not
        with mock.patch.object(registry, "auto_handoff", return_value=False):
            code, supervised, execed = self._dispatch_non_tty(
                ["claude", "--headroom-auto-handoff", "-p", "hello"])
        self.assertEqual(code, 42)
        supervised.assert_not_called()
        execed.assert_called_once_with(
            "claude", ["claude", "-p", "hello"],
            launch_note="auto-handoff disabled: -p")

    def test_config_default_alone_does_not_supervise_headless(self):
        # a passive config default (no explicit flag, no env) must NOT silently
        # start supervising every piped `headroom claude` — headless is opt-in
        with mock.patch.object(registry, "auto_handoff", return_value=True):
            code, supervised, execed = self._dispatch_non_tty(
                ["claude", "--model", "sonnet"])
        self.assertEqual(code, 42)
        supervised.assert_not_called()
        execed.assert_called_once_with(
            "sonnet", ["claude", "--model", "sonnet"],
            launch_note="auto-handoff disabled: "
                        "stdin/stdout/stderr are not all TTYs")

    def test_tty_run_is_unchanged_by_the_headless_path(self):
        # the interactive TTY path still supervises with no env/flag gymnastics
        tty = mock.Mock()
        tty.isatty.return_value = True
        with mock.patch.object(registry, "auto_handoff", return_value=True), \
                mock.patch.object(__main__.sys, "stdin", tty), \
                mock.patch.object(__main__.sys, "stdout", tty), \
                mock.patch.object(__main__.sys, "stderr", tty), \
                mock.patch("headroom.supervisor.cmd_claude",
                           return_value=41) as supervised:
            code = __main__._dispatch(["claude", "--model", "sonnet"])
        self.assertEqual(code, 41)
        supervised.assert_called_once_with("sonnet", ["--model", "sonnet"])


class UserSettingsAreMergedNotObeyed(TempDirCase):
    """`--settings` used to disarm supervision for the whole run — silently,
    because the session still started: no cap rotation, no context backstop,
    no journal, and nothing in `ops-status`. The supervisor now takes the flag
    off the child's argv and merges the user's document UNDER its own, and a
    document it cannot merge refuses the launch instead of degrading it."""

    def user_settings(self, document, name="user.json"):
        path = os.path.join(self.temp.name, name)
        with open(path, "w") as handle:
            json.dump(document, handle)
        return path

    def _dispatch(self, argv, tty=True):
        # a stream that is BOTH readable text and a claimed terminal: the
        # dispatch decision reads isatty(), and the refusal has to be legible
        class Stream(io.StringIO):
            def isatty(self):
                return tty

        stream = Stream()
        with mock.patch.object(__main__.sys, "stdin", stream), \
                mock.patch.object(__main__.sys, "stdout", stream), \
                mock.patch.object(__main__.sys, "stderr", stream), \
                mock.patch.object(registry, "auto_handoff",
                                  return_value=True), \
                mock.patch("headroom.supervisor.cmd_claude",
                           return_value=41) as supervised, \
                mock.patch("headroom.route.cmd_exec",
                           return_value=42) as execed, \
                mock.patch.object(route, "bare_fallback_exec",
                                  return_value=0) as bare, \
                mock.patch.object(route.os, "execvp") as raw_exec, \
                mock.patch.object(route.os, "execvpe") as raw_exece:
            code = __main__._dispatch(argv)
        return code, supervised, execed, bare, (raw_exec, raw_exece), stream

    def test_a_settings_launch_is_supervised(self):
        path = self.user_settings({"ultracode": True})
        code, supervised, execed, _bare, _raw, _err = self._dispatch(
            ["claude", "--settings", path, "--model", "sonnet"])
        self.assertEqual(code, 41)
        supervised.assert_called_once_with(
            "sonnet", ["--settings", path, "--model", "sonnet"])
        execed.assert_not_called()

    def test_a_headless_settings_launch_is_supervised(self):
        path = self.user_settings({"ultracode": True})
        code, supervised, execed, _bare, _raw, _err = self._dispatch(
            ["claude", "--headroom-auto-handoff", "--settings", path],
            tty=False)
        self.assertEqual(code, 41)
        supervised.assert_called_once_with("claude", ["--settings", path])
        execed.assert_not_called()

    def test_malformed_settings_refuse_the_launch_and_never_exec(self):
        path = os.path.join(self.temp.name, "absent.json")
        code, supervised, execed, bare, raw, errors = self._dispatch(
            ["claude", "--settings", path, "--model", "sonnet"])
        self.assertEqual(code, 2)
        supervised.assert_not_called()
        execed.assert_not_called()        # NOT an unsupervised launch
        bare.assert_not_called()
        for call in raw:
            call.assert_not_called()
        self.assertIn(path, errors.getvalue())
        self.assertIn("refusing to launch", errors.getvalue())

    def test_an_unmergeable_key_is_refused_by_name(self):
        path = self.user_settings({"ultracode": True,
                                   "disableAllHooks": True})
        code, supervised, execed, _bare, _raw, errors = self._dispatch(
            ["claude", "--settings", path])
        self.assertEqual(code, 2)
        supervised.assert_not_called()
        execed.assert_not_called()
        self.assertIn("disableAllHooks", errors.getvalue())

    def test_a_settings_refusal_never_takes_the_bare_fallback(self):
        # the opt-in launch fallback exists for "the CLI never started" — it
        # must not be a back door to the unsupervised child we just closed
        path = self.user_settings({"disableAllHooks": True})
        code, supervised, execed, bare, raw, _err = self._dispatch(
            ["claude", "--headroom-launch-fallback", "--settings", path])
        self.assertEqual(code, 2)
        supervised.assert_not_called()
        execed.assert_not_called()
        bare.assert_not_called()
        for call in raw:
            call.assert_not_called()

    def test_cmd_claude_itself_refuses_rather_than_falling_back(self):
        # defence in depth: even reached directly, with a fallback argv armed
        path = self.user_settings({"disableAllHooks": True})
        with mock.patch.object(supervisor, "_initial_account",
                               return_value=self.account()), \
                mock.patch.object(route, "bare_fallback_exec") as bare, \
                mock.patch.object(route.os, "execvpe") as execute, \
                redirect_stderr(io.StringIO()) as errors:
            code = supervisor.cmd_claude(
                "sonnet", ["--settings", path],
                fallback_argv=["claude", "--settings", path])
        self.assertEqual(code, 2)
        bare.assert_not_called()
        execute.assert_not_called()
        self.assertIn("disableAllHooks", errors.getvalue())

    def test_the_child_is_launched_with_the_supervisors_file_alone(self):
        path = self.user_settings({"ultracode": True, "effortLevel": "high"})
        spawned = []
        runner = supervisor.Supervisor(
            "sonnet", ["--settings", path, "--model", "sonnet"],
            self.account(),
            popen=lambda argv, **kw: spawned.append(argv) or mock.Mock())
        child = runner._spawn(self.account(), runner.initial_args,
                              self.temp.name, True)
        argv = spawned[0]
        # exactly ONE --settings, and it is the supervisor's own file: a
        # second occurrence would REPLACE the injected hooks in Claude
        self.assertEqual(argv.count("--settings"), 1)
        self.assertNotIn(path, argv)
        self.assertEqual(argv[:2], ["claude", "--settings"])
        self.assertEqual(argv[2], child.settings_path)
        self.assertEqual(argv[3:], ["--model", "sonnet"])
        with open(child.settings_path, encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertTrue(document["ultracode"])        # the user's keys ride
        self.assertEqual(document["effortLevel"], "high")
        self.assertEqual(document["hooks"]["SessionStart"],   # supervision too
                         supervisor.hook_settings()["hooks"]["SessionStart"])

    def test_the_merge_rides_every_generation(self):
        # a rotation respawns as generation n+1 with a resume argv that carries
        # no user flags at all — the merged document must survive it
        path = self.user_settings({"ultracode": True})
        runner = supervisor.Supervisor(
            "sonnet", ["--settings", path], self.account())
        for generation in (1, 2, 3):
            with open(runner._settings_file(generation, self.account()),
                      encoding="utf-8") as handle:
                document = json.load(handle)
            self.assertTrue(document["ultracode"])
            self.assertIn("StopFailure", document["hooks"])

    def test_the_child_names_its_slot_in_its_own_argv(self):
        # On 2026-08-01 07:30:37Z an operator read
        # `claude --settings .../<uuid>-1.settings.json` in `ps`, concluded
        # "stale supervisor scaffolding", and killed two LIVE lanes. The
        # filename is the only thing a supervised lane says about itself in
        # the process table, so it says the seat.
        spawned = []
        account = self.account("domanski-ai")
        runner = supervisor.Supervisor(
            "sonnet", ["--model", "sonnet"], account,
            popen=lambda argv, **kw: spawned.append(argv) or mock.Mock())
        child = runner._spawn(account, runner.initial_args,
                              self.temp.name, True)
        argv = spawned[0]
        self.assertEqual(argv[:2], ["claude", "--settings"])
        settings = argv[2]
        self.assertEqual(settings, child.settings_path)
        name = os.path.basename(settings)
        self.assertIn("domanski-ai", name)
        self.assertEqual(
            name, f"{runner.supervisor_id}-1.domanski-ai.settings.json")
        # the slot is a filename INFIX, never a subdirectory: the estate glob
        # `supervisors/*.settings.json` must keep matching
        self.assertEqual(os.path.dirname(settings),
                         supervisor._supervisors_dir())
        self.assertTrue(name.endswith(".settings.json"))

    def test_the_spawned_slot_is_the_one_spawned_ONTO(self):
        # a handoff spawns onto the TARGET account, not the supervisor's own,
        # so the argv must name where the child actually runs
        spawned = []
        runner = supervisor.Supervisor(
            "sonnet", ["--model", "sonnet"], self.account("source"),
            popen=lambda argv, **kw: spawned.append(argv) or mock.Mock())
        runner._spawn(self.account("target"), runner.initial_args,
                      self.temp.name, True)
        self.assertIn("target", os.path.basename(spawned[0][2]))
        self.assertNotIn("source", os.path.basename(spawned[0][2]))

    def test_a_hostile_slot_name_cannot_escape_the_supervisors_directory(self):
        # the account name is CONFIG-controlled, so it is untrusted input to a
        # path: sanitise it rather than trusting the registry
        runner = supervisor.Supervisor("sonnet", [], self.account())
        for name, expected in (("../../etc/pwn", ".._.._etc_pwn"),
                               ("a b", "a_b"),
                               ("s/l", "s_l"),
                               ("", "lane")):
            account = dict(self.account(), name=name)
            path = runner._settings_file(1, account)
            self.assertEqual(os.path.dirname(path),
                             supervisor._supervisors_dir())
            self.assertEqual(os.path.basename(path),
                             f"{runner.supervisor_id}-1.{expected}"
                             ".settings.json")
            self.assertTrue(os.path.exists(path))

    def test_cleanup_removes_the_slot_named_file(self):
        # _cleanup_files iterates the paths it RECORDED and never globs, so
        # the rename must not strand a file — assert the name really moved
        runner = supervisor.Supervisor("sonnet", [], self.account())
        path = runner._settings_file(1, self.account("domanski-ai"))
        self.assertIn("domanski-ai", os.path.basename(path))
        self.assertTrue(os.path.exists(path))
        self.assertEqual(runner.settings_files, [path])
        runner._cleanup_files()
        self.assertFalse(os.path.exists(path))

    def test_a_boolean_or_optional_flag_never_hides_the_settings(self):
        # `--ide` (boolean) and `--resume` (optional value) used to consume
        # the next token, so `--settings` stayed on the child's argv beside
        # the supervisor's own and Claude honoured the LATER one
        path = self.user_settings({"ultracode": True})
        for prefix in (["--ide"], ["--resume"], ["-r"], ["--fork-session"]):
            spawned = []
            runner = supervisor.Supervisor(
                "sonnet", prefix + ["--settings", path], self.account(),
                popen=lambda argv, **kw: spawned.append(argv) or mock.Mock())
            child = runner._spawn(self.account(), runner.initial_args,
                                  self.temp.name, True)
            argv = spawned[0]
            self.assertEqual(argv.count("--settings"), 1, prefix)
            self.assertNotIn(path, argv)
            self.assertEqual(argv, ["claude", "--settings",
                                    child.settings_path] + prefix)
            with open(child.settings_path, encoding="utf-8") as handle:
                self.assertTrue(json.load(handle)["ultracode"])

    def test_an_unsupervised_recovery_still_carries_the_user_settings(self):
        # a rotation that could not start its target relaunches the source
        # with automation OFF; losing the rotation must not also lose the
        # settings the operator launched with
        path = self.user_settings({"ultracode": True})
        spawned = []
        runner = supervisor.Supervisor(
            "sonnet", ["--settings", path], self.account(),
            popen=lambda argv, **kw: spawned.append(argv) or mock.Mock())
        child = runner._spawn(self.account(), ["--resume", "SID"],
                              self.temp.name, False)
        argv = spawned[0]
        self.assertEqual(argv, ["claude", "--settings", child.settings_path,
                                "--resume", "SID"])
        with open(child.settings_path, encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertTrue(document["ultracode"])
        # …but NOT the hooks: this child carries no supervisor identity, so
        # every injected hook would be refused and printed at the operator
        self.assertNotIn("hooks", document)

    def test_an_unsupervised_child_without_user_settings_is_unchanged(self):
        spawned = []
        runner = supervisor.Supervisor(
            "sonnet", [], self.account(),
            popen=lambda argv, **kw: spawned.append(argv) or mock.Mock())
        runner._spawn(self.account(), ["--resume", "SID"], self.temp.name,
                      False)
        self.assertEqual(spawned[0], ["claude", "--resume", "SID"])
        self.assertEqual(runner.settings_files, [])

    def test_the_recovery_branch_in_run_reaches_that_spawn(self):
        # the same thing through run(): source -> failed target -> source
        # recovered unsupervised, with the user's document still on the argv
        path = self.user_settings({"ultracode": True})
        source, target = self.account("source"), self.account("target")
        spawned = []

        def popen(argv, **kw):
            # read the document exactly when the child would: run() deletes
            # its settings files on a clean exit
            document = None
            if "--settings" in argv:
                with open(argv[argv.index("--settings") + 1],
                          encoding="utf-8") as handle:
                    document = json.load(handle)
            spawned.append((argv, document))
            return mock.Mock()

        runner = supervisor.Supervisor(
            "sonnet", ["--settings", path], source, popen=popen)
        plan = mock.Mock(preemptive=False)
        plan.target, plan.source.account = target, source
        relaunch = supervisor.Relaunch(target, ["--resume", "SID"],
                                       self.temp.name, True, "hid", plan)
        recovery = supervisor.Relaunch(source, ["--resume", "SID"],
                                       self.temp.name, False)
        outcomes = iter([relaunch, 0])
        with mock.patch.object(
                handoff, "verify_target_binding",     # the TARGET spawn only
                side_effect=handoff.HandoffError("target changed")), \
                mock.patch.object(runner, "_monitor",
                                  side_effect=lambda child, pending="":
                                  next(outcomes)), \
                mock.patch.object(runner, "_source_relaunch",
                                  return_value=recovery), \
                mock.patch.object(runner, "_reconcile_leases"), \
                mock.patch.object(runner, "_failure"), \
                mock.patch.object(route, "release_slot_lease"), \
                mock.patch.object(handoff, "append_action"), \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            self.assertEqual(runner.run(), 0)
        self.assertEqual(len(spawned), 2)     # the target never started
        recovered, document = spawned[1]
        self.assertEqual(recovered[:2], ["claude", "--settings"])
        self.assertEqual(recovered[3:], ["--resume", "SID"])
        self.assertTrue(document["ultracode"])
        self.assertNotIn("hooks", document)
        # the first (supervised) child had both
        self.assertTrue(spawned[0][1]["ultracode"])
        self.assertIn("SessionStart", spawned[0][1]["hooks"])

    def _refused_fallback(self, argv, **patches):
        """cmd_claude with the fallback armed and a VALID settings file: the
        launch fails for a routing reason, and the bare argv still carries
        --settings, so the fallback must refuse rather than exec."""
        with mock.patch.object(route, "bare_fallback_exec") as bare, \
                mock.patch.object(route.os, "execvpe") as execute, \
                mock.patch.object(route.os, "execvp") as execute_p, \
                redirect_stderr(io.StringIO()) as errors:
            with contextlib.ExitStack() as stack:
                for target, patch in patches.items():
                    stack.enter_context(patch)
                code = supervisor.cmd_claude(
                    "sonnet", argv, fallback_argv=["claude"] + argv)
        self.assertEqual(code, 2)
        bare.assert_not_called()
        execute.assert_not_called()
        execute_p.assert_not_called()
        self.assertIn("refusing the bare fallback", errors.getvalue())
        return errors.getvalue()

    def test_no_account_refuses_rather_than_bare_execing_settings(self):
        path = self.user_settings({"ultracode": True})
        errors = self._refused_fallback(
            ["--settings", path],
            account=mock.patch.object(supervisor, "_initial_account",
                                      return_value=None))
        self.assertIn(path, errors)
        self.assertIn("proven headroom", errors)

    def test_a_lease_failure_refuses_rather_than_bare_execing_settings(self):
        path = self.user_settings({"ultracode": True})
        errors = self._refused_fallback(
            ["--settings", path],
            account=mock.patch.object(supervisor, "_initial_account",
                                      return_value=self.account()),
            lease=mock.patch.object(route, "acquire_slot_lease",
                                    side_effect=route.LeaseError("no lock")))
        self.assertIn("slot lease unavailable", errors)

    def test_a_preparation_failure_refuses_rather_than_bare_execing(self):
        path = self.user_settings({"ultracode": True})
        errors = self._refused_fallback(
            ["--settings", path],
            account=mock.patch.object(
                supervisor, "_initial_account",
                side_effect=registry.RegistryError("no config")))
        self.assertIn("launch preparation failed", errors)

    def test_a_first_spawn_failure_refuses_rather_than_bare_execing(self):
        path = self.user_settings({"ultracode": True})

        class Stub:
            def __init__(self, family, args, account):
                self.spawned_any = False
                self.spawn_ambiguous = False

            def run(self):
                return 127        # never spawned a child

        errors = self._refused_fallback(
            ["--settings", path],
            account=mock.patch.object(supervisor, "_initial_account",
                                      return_value=self.account()),
            runner=mock.patch.object(supervisor, "Supervisor", Stub))
        self.assertIn("Claude never started", errors)

    def test_a_run_that_raises_before_the_first_spawn_also_refuses(self):
        # the other side of the boundary: run() RAISING before any child
        # exists, not returning — a separate fallback call site
        path = self.user_settings({"ultracode": True})

        class Stub:
            def __init__(self, family, args, account):
                self.spawned_any = False
                self.spawn_ambiguous = False

            def run(self):
                raise supervisor.SupervisorError("nothing was started")

        errors = self._refused_fallback(
            ["--settings", path],
            account=mock.patch.object(supervisor, "_initial_account",
                                      return_value=self.account()),
            runner=mock.patch.object(supervisor, "Supervisor", Stub))
        self.assertIn("failed before Claude started", errors)

    def test_the_refusal_never_echoes_an_inline_settings_document(self):
        # inline settings legitimately carry credentials, and this diagnostic
        # goes to stderr — which is exactly what a launcher captures
        inline = '{"env": {"MY_API_KEY": "sk-super-secret"}}'
        errors = self._refused_fallback(
            ["--settings", inline],
            account=mock.patch.object(supervisor, "_initial_account",
                                      return_value=None))
        self.assertNotIn("sk-super-secret", errors)
        self.assertNotIn("MY_API_KEY", errors)
        self.assertIn("<inline JSON>", errors)

    def test_the_pre_import_refusal_never_echoes_one_either(self):
        inline = '{"env": {"MY_API_KEY": "sk-super-secret"}}'
        with mock.patch.object(__main__, "_prepare_launch",
                               side_effect=RuntimeError("import blew up")), \
                mock.patch.object(__main__, "_bare_cli_fallback") as bare, \
                redirect_stderr(io.StringIO()) as errors:
            code = __main__._dispatch(
                ["claude", "--headroom-launch-fallback", "--settings", inline])
        self.assertEqual(code, 2)
        bare.assert_not_called()
        self.assertNotIn("sk-super-secret", errors.getvalue())
        self.assertIn("<inline JSON>", errors.getvalue())

    def test_the_equals_form_is_redacted_on_the_supervised_surface(self):
        # `--settings={…}` is ONE token beginning with a dash: the whole
        # document rode into the rendered command behind the `=`
        inline = '{"env": {"MY_API_KEY": "sk-super-secret"}}'
        errors = self._refused_fallback(
            ["--settings=" + inline],
            account=mock.patch.object(supervisor, "_initial_account",
                                      return_value=None))
        self.assertNotIn("sk-super-secret", errors)
        self.assertNotIn("MY_API_KEY", errors)
        self.assertIn("<inline JSON>", errors)

    def test_the_equals_form_is_redacted_on_the_pre_import_surface(self):
        inline = '{"env": {"MY_API_KEY": "sk-super-secret"}}'
        with mock.patch.object(__main__, "_prepare_launch",
                               side_effect=RuntimeError("import blew up")), \
                mock.patch.object(__main__, "_bare_cli_fallback") as bare, \
                redirect_stderr(io.StringIO()) as errors:
            code = __main__._dispatch(
                ["claude", "--headroom-launch-fallback",
                 "--settings=" + inline])
        self.assertEqual(code, 2)
        bare.assert_not_called()
        self.assertNotIn("sk-super-secret", errors.getvalue())
        self.assertNotIn("MY_API_KEY", errors.getvalue())
        self.assertIn("<inline JSON>", errors.getvalue())

    def test_managed_settings_refuses_the_launch(self):
        # policy settings sit above the merged document and can turn the
        # injected hooks off; there is nothing to merge
        for argv in (["claude", "--managed-settings", "/tmp/policy.json"],
                     ["claude", "--managed-settings=/tmp/policy.json"],
                     ["claude", "--managed-settings", "/tmp/p.json",
                      "--settings", "/tmp/user.json"]):
            code, supervised, execed, bare, raw, errors = self._dispatch(argv)
            self.assertEqual(code, 2, argv)
            supervised.assert_not_called()
            execed.assert_not_called()
            bare.assert_not_called()
            for call in raw:
                call.assert_not_called()
            self.assertIn("--managed-settings", errors.getvalue())

    def test_every_hook_bypassing_env_shape_refuses_the_launch(self):
        for key in ("CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_CODE_SHELL",
                    "CLAUDE_CODE_PROCESS_WRAPPER", "CLAUDE_CODE_SIMPLE",
                    "HEADROOM_DIR", "HOME", "USERPROFILE",
                    "CLAUDE_CODE_A_KNOB_FROM_2027"):
            path = self.user_settings({"env": {key: "/bin/true"}},
                                      name=key + ".json")
            code, supervised, execed, bare, raw, errors = self._dispatch(
                ["claude", "--settings", path])
            self.assertEqual(code, 2, key)
            supervised.assert_not_called()
            execed.assert_not_called()
            bare.assert_not_called()
            for call in raw:
                call.assert_not_called()
            self.assertIn(key, errors.getvalue())

    def test_an_ordinary_env_block_still_reaches_the_child(self):
        path = self.user_settings(
            {"env": {"MY_TOKEN": "t", "AWS_PROFILE": "work"}})
        spawned = []
        runner = supervisor.Supervisor(
            "sonnet", ["--settings", path], self.account(),
            popen=lambda argv, **kw: spawned.append(argv) or mock.Mock())
        child = runner._spawn(self.account(), runner.initial_args,
                              self.temp.name, True)
        with open(child.settings_path, encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertEqual(document["env"],
                         {"MY_TOKEN": "t", "AWS_PROFILE": "work"})
        self.assertIn("SessionStart", document["hooks"])

    def test_a_fallback_without_settings_is_completely_unchanged(self):
        # the opt-in fallback still exists — only a --settings argv disarms it
        with mock.patch.object(supervisor, "_initial_account",
                               return_value=None), \
                mock.patch.object(route, "bare_fallback_exec",
                                  return_value=0) as bare, \
                redirect_stderr(io.StringIO()):
            code = supervisor.cmd_claude("sonnet", ["--model", "sonnet"],
                                         fallback_argv=["claude", "--model",
                                                        "sonnet"])
        self.assertEqual(code, 0)
        bare.assert_called_once()

    def test_preprocessing_failure_with_settings_never_bare_execs(self):
        # the PRE-IMPORT boundary: supervisor may not even be importable, so
        # this guard is duplicated there — and it must refuse the same way
        path = self.user_settings({"ultracode": True})
        with mock.patch.object(__main__, "_prepare_launch",
                               side_effect=RuntimeError("import blew up")), \
                mock.patch.object(__main__, "_bare_cli_fallback") as bare, \
                mock.patch.object(__main__.os, "execvp") as execute, \
                redirect_stderr(io.StringIO()) as errors:
            code = __main__._dispatch(
                ["claude", "--headroom-launch-fallback", "--settings", path])
        self.assertEqual(code, 2)
        bare.assert_not_called()
        execute.assert_not_called()
        self.assertIn(path, errors.getvalue())
        self.assertIn("refusing the bare fallback", errors.getvalue())

    def test_preprocessing_failure_without_settings_still_bare_execs(self):
        with mock.patch.object(__main__, "_prepare_launch",
                               side_effect=RuntimeError("import blew up")), \
                mock.patch.object(__main__, "_bare_cli_fallback",
                                  return_value=0) as bare, \
                redirect_stderr(io.StringIO()):
            code = __main__._dispatch(
                ["claude", "--headroom-launch-fallback", "--model", "sonnet"])
        self.assertEqual(code, 0)
        bare.assert_called_once()

    def test_an_empty_settings_value_refuses_the_launch(self):
        for argv in (["claude", "--settings="], ["claude", "--settings", ""]):
            code, supervised, execed, bare, raw, errors = self._dispatch(argv)
            self.assertEqual(code, 2, argv)
            supervised.assert_not_called()
            execed.assert_not_called()
            bare.assert_not_called()
            for call in raw:
                call.assert_not_called()
            self.assertIn("empty value", errors.getvalue())

    def test_a_document_too_deep_to_read_refuses_the_launch(self):
        deep = "{\"a\":" * 1400 + "1" + "}" * 1400
        code, supervised, execed, bare, raw, errors = self._dispatch(
            ["claude", "--headroom-launch-fallback", "--settings", deep])
        self.assertEqual(code, 2)
        supervised.assert_not_called()
        execed.assert_not_called()
        bare.assert_not_called()
        for call in raw:
            call.assert_not_called()
        self.assertIn("too deeply", errors.getvalue())

    def test_a_settings_edit_mid_run_cannot_change_a_live_child(self):
        path = self.user_settings({"ultracode": True})
        runner = supervisor.Supervisor(
            "sonnet", ["--settings", path], self.account())
        with open(path, "w") as handle:
            json.dump({"disableAllHooks": True}, handle)
        with open(runner._settings_file(2, self.account()),
                  encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertTrue(document["ultracode"])
        self.assertNotIn("disableAllHooks", document)


# ==========================================================================
# Round-2 red-team fixes
# ==========================================================================
class R2AmbiguousSpawnInRun(TempDirCase):
    """P0-1: spawn_ambiguous protects the rotation/recovery path in run(),
    not just cmd_claude's initial fallback — no second child, lease retained."""

    def test_initial_ambiguous_spawn_retains_lease_and_never_recovers(self):
        account = self.account("acct-a")
        with mock.patch.dict(os.environ, {"HEADROOM_SLOT_LEASE": "1"}):
            self.assertTrue(route.acquire_slot_lease(account, "sonnet"))
            runner = supervisor.Supervisor("sonnet", [], account)
            calls = []

            def fake_spawn(acct, args, cwd, automatic, plan=None):
                calls.append(acct["name"])
                runner.spawn_ambiguous = True
                raise supervisor.SupervisorError("async in the Popen window")

            with mock.patch.object(runner, "_spawn", side_effect=fake_spawn), \
                    redirect_stderr(io.StringIO()):
                code = runner.run()
            self.assertEqual(code, 127)
            self.assertEqual(calls, ["acct-a"])          # no recovery spawn
            self.assertEqual(runner._ambiguous_account, "acct-a")
            # the lease is RETAINED (a live child may hold it); run()'s finally
            # must not release the ambiguous account
            self.assertEqual(route.held_lease_names(), ["acct-a"])

    def test_ambiguous_target_rotation_does_not_recover_source(self):
        # Codex's isolated repro: the TARGET Popen creates a child, then a
        # post-Popen step (e.g. Child construction) raises before run() owns
        # it. run() must NOT start source recovery (which would double-run),
        # and the target lease must be retained (the live child may hold it).
        source = self.account("source")
        target = self.account("target")
        with mock.patch.dict(os.environ, {"HEADROOM_SLOT_LEASE": "1"}):
            # source held from the start; the target is acquired DURING the
            # handoff (as _lease_target really does), modelled in the _monitor
            # stub below — reconcile is kept REAL so retention is genuine
            self.assertTrue(route.acquire_slot_lease(source, "sonnet"))
            runner = supervisor.Supervisor("sonnet", [], source)
            child1 = mock.Mock()
            child1.account = source
            child1.generation = 1
            plan = mock.Mock()
            plan.target = target
            relaunch = supervisor.Relaunch(
                target, ["--resume", "sid"], "/cwd", True, "hid", plan)
            calls = []

            def fake_spawn(acct, args, cwd, automatic, plan=None):
                calls.append(acct["name"])
                if len(calls) == 1:
                    return child1
                # real _spawn leaves spawn_ambiguous True on a post-Popen fail
                runner.spawn_ambiguous = True
                raise RuntimeError("post-popen Child construction boom")

            def monitor_stub(child, pending_handoff_id=""):
                # the handoff takes the target lease before returning (P0-2)
                self.assertTrue(route.acquire_slot_lease(target, "sonnet"))
                return relaunch

            with mock.patch.object(runner, "_spawn", side_effect=fake_spawn), \
                    mock.patch.object(runner, "_monitor",
                                      side_effect=monitor_stub), \
                    mock.patch.object(runner, "_failure"), \
                    mock.patch.object(supervisor.handoff, "append_action"), \
                    redirect_stderr(io.StringIO()):
                code = runner.run()
            self.assertEqual(code, 127)
            # exactly two spawns: source, target — NEVER a third
            self.assertEqual(calls, ["source", "target"])
            self.assertEqual(runner._ambiguous_account, "target")
            # the target lease is RETAINED (the possibly-live child holds it);
            # the source lease was reconciled away when the target spawned
            self.assertEqual(route.held_lease_names(), ["target"])


class R2FailedRotationReleasesTarget(TempDirCase):
    """P1-2: a held/failed rotation releases the unused target lease so a
    third launcher isn't wrongly blocked."""

    def test_monitor_releases_target_when_stop_and_commit_returns_none(self):
        source = self.account("source")
        target = self.account("target")
        with mock.patch.dict(os.environ, {"HEADROOM_SLOT_LEASE": "1"}):
            self.assertTrue(route.acquire_slot_lease(source, "sonnet"))
            self.assertTrue(route.acquire_slot_lease(target, "sonnet"))
            runner = supervisor.Supervisor(
                "sonnet", [], source, now=lambda: 1000.0,
                sleep=lambda seconds: None)
            child = mock.Mock()
            child.account = source
            child.automation = True
            child.binding = object()          # not None -> no bind timeout
            child.launched_at = 0.0
            poll_seq = iter([None, 0])
            child.process.poll.side_effect = lambda: next(poll_seq)
            plan = mock.Mock()
            plan.target = target
            events = iter([object(), None])   # a proof, then nothing

            with mock.patch.object(
                    runner, "_handle_events",
                    side_effect=lambda c, p, pr=None: next(events)), \
                    mock.patch.object(runner, "_preflight",
                                      return_value=plan), \
                    mock.patch.object(runner, "_stop_and_commit",
                                      return_value=None), \
                    redirect_stderr(io.StringIO()):
                returncode = runner._monitor(child)
            self.assertEqual(returncode, 0)
            # the source keeps running (its lease held); the unused target is
            # released
            self.assertEqual(route.held_lease_names(), ["source"])


class R2LeaseFailClosed(TempDirCase):
    """P1-3: a non-inheritable lease fd would be closed by execvp and free the
    account — that is fail-OPEN, so acquisition must fail closed."""

    def lease_env(self):
        return mock.patch.dict(os.environ, {"HEADROOM_SLOT_LEASE": "1"})

    def test_set_inheritable_error_fails_closed(self):
        with self.lease_env(), \
                mock.patch.object(route.os, "set_inheritable",
                                  side_effect=OSError("nope")), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(route.LeaseError):
                route.acquire_slot_lease(self.account(), "sonnet")
        # no lease was recorded and the fd was not leaked into the held map
        self.assertEqual(route.held_lease_names(), [])

    def test_fd_that_does_not_become_inheritable_fails_closed(self):
        with self.lease_env(), \
                mock.patch.object(route.os, "get_inheritable",
                                  return_value=False), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(route.LeaseError):
                route.acquire_slot_lease(self.account(), "sonnet")
        self.assertEqual(route.held_lease_names(), [])


class R2SupervisedFallbackGuard(TempDirCase):
    """P1-4: everything after the fallback intent — including Supervisor
    construction — is inside the pre-spawn guard."""

    def test_supervisor_constructor_failure_falls_back(self):
        with mock.patch.object(supervisor, "_initial_account",
                               return_value=self.account()), \
                mock.patch.object(supervisor, "Supervisor",
                                  side_effect=RuntimeError("ctor boom")), \
                mock.patch.object(route.os, "execvpe") as bare, \
                redirect_stderr(io.StringIO()) as errors:
            code = supervisor.cmd_claude("sonnet", [],
                                         fallback_argv=["claude"])
        self.assertEqual(code, 0)
        bare.assert_called_once()
        self.assertIn("ctor boom", errors.getvalue())

    def test_supervisor_constructor_failure_without_fallback_raises(self):
        with mock.patch.object(supervisor, "_initial_account",
                               return_value=self.account()), \
                mock.patch.object(supervisor, "Supervisor",
                                  side_effect=RuntimeError("ctor boom")), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError):
                supervisor.cmd_claude("sonnet", [])


class R2RecoveryEmitsSupervisionLost(TempDirCase):
    """P1-5: a source recovery with automation off notifies the loss, since the
    observer already saw the initial supervised launch."""

    def test_positively_failed_target_relaunch_emits_supervision_lost(self):
        source = self.account("source")
        target = self.account("target")
        runner = supervisor.Supervisor("sonnet", [], source)
        child1 = mock.Mock()
        child1.account = source
        child1.generation = 1
        plan = mock.Mock()
        plan.target = target
        plan.source = mock.Mock()
        plan.source.account = source
        relaunch = supervisor.Relaunch(
            target, ["--resume", "sid"], "/cwd", True, "hid", plan)
        recovered = mock.Mock()
        recovered.account = source
        recovered.generation = 3
        spawn_calls = []

        def fake_spawn(acct, args, cwd, automatic, plan=None):
            spawn_calls.append(acct["name"])
            if len(spawn_calls) == 1:
                return child1
            if len(spawn_calls) == 2:
                runner.spawn_ambiguous = False  # positively no child
                raise supervisor.SupervisorError("exec failed: not found")
            return recovered

        monitor_seq = iter([relaunch, 0])
        with mock.patch.object(runner, "_spawn", side_effect=fake_spawn), \
                mock.patch.object(runner, "_monitor",
                                  side_effect=lambda *a, **k: next(monitor_seq)), \
                mock.patch.object(runner, "_reconcile_leases"), \
                mock.patch.object(runner, "_failure"), \
                mock.patch.object(supervisor.handoff, "append_action"), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            code = runner.run()
        self.assertEqual(code, 0)
        self.assertEqual(spawn_calls, ["source", "target", "source"])
        events = [call.args[0] for call in emit.call_args_list]
        lost = [event for event in events
                if event["event"] == "supervision_lost"]
        self.assertTrue(lost)
        self.assertEqual(lost[0]["account"], "source")


class R2PassFdsAndCaps(TempDirCase):
    """P0-1 (lease rides on the child via pass_fds) and P2-6 (caps + env_int)."""

    def test_spawn_passes_the_lease_fd_to_the_child(self):
        account = self.account("acct-a")
        with mock.patch.dict(os.environ, {"HEADROOM_SLOT_LEASE": "1"}):
            self.assertTrue(route.acquire_slot_lease(account, "sonnet"))
            fd = route.held_lease_fd("acct-a")
            popen = mock.Mock(return_value=mock.Mock())
            runner = supervisor.Supervisor("sonnet", [], account, popen=popen)
            with mock.patch.object(runner, "_settings_file",
                                   return_value=""), \
                    redirect_stderr(io.StringIO()):
                runner._spawn(account, [], self.temp.name, False)
            self.assertEqual(popen.call_args.kwargs.get("pass_fds"), (fd,))

    def test_lease_rides_on_the_child_and_frees_on_its_death(self):
        # P0-1 OS-level mechanism: with pass_fds the child shares the flock's
        # open file description, and release is CLOSE-ONLY (never LOCK_UN), so
        # the parent dropping its copy leaves the lease held by the live child
        # and it frees only when the last holder (the child) dies.
        account = self.account("acct-a")
        with mock.patch.dict(os.environ, {"HEADROOM_SLOT_LEASE": "1"}):
            self.assertTrue(route.acquire_slot_lease(account, "sonnet"))
            fd = route.held_lease_fd("acct-a")
            child = subprocess.Popen(["sleep", "30"], pass_fds=(fd,))
            self.addCleanup(child.wait)
            self.addCleanup(child.kill)
            # the parent drops its copy the way run()'s reconcile/finally does
            route.release_slot_lease("acct-a")
            self.assertTrue(route._account_leased_by_other("acct-a"),
                            "the live child should still hold the lease")
            child.kill()
            child.wait()
            deadline = time.monotonic() + 3.0
            while (route._account_leased_by_other("acct-a")
                   and time.monotonic() < deadline):
                time.sleep(0.02)
            self.assertFalse(route._account_leased_by_other("acct-a"),
                             "the lease should free when the child dies")

    def test_spawn_omits_pass_fds_when_leasing_is_off(self):
        # legacy-off: no pass_fds kwarg at all, so the Popen call is unchanged
        account = self.account("acct-a")
        popen = mock.Mock(return_value=mock.Mock())
        runner = supervisor.Supervisor("sonnet", [], account, popen=popen)
        with mock.patch.object(runner, "_settings_file", return_value=""), \
                redirect_stderr(io.StringIO()):
            runner._spawn(account, [], self.temp.name, False)
        self.assertNotIn("pass_fds", popen.call_args.kwargs)

    def test_env_int_tolerates_malformed_values(self):
        with mock.patch.dict(os.environ, {"HEADROOM_TEST_X": "bad"}):
            self.assertEqual(paths.env_int("HEADROOM_TEST_X", 7), 7)
        with mock.patch.dict(os.environ, {"HEADROOM_TEST_X": "42"}):
            self.assertEqual(paths.env_int("HEADROOM_TEST_X", 7), 42)
        self.assertEqual(paths.env_int("HEADROOM_TEST_UNSET_ZZZ", 5), 5)

    def test_caps_emits_json_despite_a_malformed_unrelated_env(self):
        # P2-6: a fresh process with a bad HEADROOM_* value must still emit the
        # caps JSON (module-level ints are now tolerant)
        env = dict(os.environ, HEADROOM_IDENTITY_TIMEOUT="bad",
                   HEADROOM_SNAPSHOT_MAX_AGE="nope",
                   HEADROOM_OBSERVATION_MAX_AGE="x")
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        result = subprocess.run(
            [sys.executable, "-m", "headroom", "caps"],
            cwd=repo, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema"], 2)


# ==========================================================================
# Round-3 red-team fixes
# ==========================================================================
class R3ShutdownSignalNotifiesLoss(TempDirCase):
    """P1-2(r3): a shutdown signal disarms auto-handoff via _lose_supervision,
    so supervision_lost fires once even if the child survives the signal."""

    def test_shutdown_signal_routes_through_lose_supervision(self):
        account = self.account()
        runner = supervisor.Supervisor(
            "sonnet", [], account, now=lambda: 1000.0,
            sleep=lambda seconds: None)
        child = mock.Mock()
        child.account = account
        child.automation = True
        child.binding = object()          # not None -> no bind-timeout path
        child.launched_at = 0.0
        child.supervision_loss_notified = False
        poll_seq = iter([None, 0])        # continue once, then the child exits
        child.process.poll.side_effect = lambda: next(poll_seq)

        class FakeGuard:
            shutdown_signal = 15          # SIGTERM already latched
            forwarded = True              # ...and already forwarded to child

            def __init__(self, process=None):
                pass

            def install(self):
                pass

            def restore(self):
                pass

            def poll(self, process):
                pass

        with mock.patch.object(supervisor, "_SignalGuard", FakeGuard), \
                mock.patch.object(runner, "_handle_events",
                                  return_value=None), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            returncode = runner._monitor(child)
        self.assertEqual(returncode, 0)
        self.assertFalse(child.automation)
        lost = [call.args[0] for call in emit.call_args_list
                if call.args[0]["event"] == "supervision_lost"]
        self.assertEqual(len(lost), 1)  # exactly once, not per poll
        self.assertEqual(lost[0]["reason"], "shutdown signal received")


class R3CrudeBareArgvValueAware(TempDirCase):
    """P2-3: the pre-import fallback argv is value-aware — an option value that
    merely looks like a headroom flag is preserved, not stripped."""

    def test_option_value_that_looks_like_a_headroom_flag_is_preserved(self):
        argv = __main__._crude_bare_argv(
            "claude",
            ["--system-prompt", "--headroom-auto-handoff", "-p", "hi"])
        self.assertEqual(
            argv,
            ["claude", "--system-prompt", "--headroom-auto-handoff",
             "-p", "hi"])

    def test_real_owned_flags_are_still_stripped(self):
        argv = __main__._crude_bare_argv(
            "claude", ["--headroom-launch-fallback", "--model", "sonnet"])
        self.assertEqual(argv, ["claude", "--model", "sonnet"])

    def test_owned_flag_as_a_value_after_equals_is_untouched(self):
        # --model=... is a single token; a following owned flag is a real flag
        argv = __main__._crude_bare_argv(
            "claude", ["--model=sonnet", "--headroom-launch-fallback"])
        self.assertEqual(argv, ["claude", "--model=sonnet"])

    def test_local_value_flags_mirror_supervisor(self):
        # keep the pre-import copy honest against the canonical lists — BOTH
        # of them: an optional-value flag mirrored as required is exactly the
        # misparse that let `--resume --settings x` past the merge
        self.assertEqual(set(__main__._CLAUDE_VALUE_FLAGS),
                         set(supervisor.CLAUDE_VALUE_FLAGS))
        self.assertEqual(set(__main__._CLAUDE_OPTIONAL_VALUE_FLAGS),
                         set(supervisor.CLAUDE_OPTIONAL_VALUE_FLAGS))
        # and the grammar itself agrees on every flag in both tables
        for flag in (supervisor.CLAUDE_VALUE_FLAGS
                     | supervisor.CLAUDE_OPTIONAL_VALUE_FLAGS
                     | {"--ide", "--brief", "--unknown-future"}):
            for following in ("value", "--settings", None):
                self.assertEqual(
                    __main__._takes_value(flag, following),
                    supervisor.takes_value(flag, following),
                    (flag, following))

    def test_local_redaction_mirrors_supervisor(self):
        # the same duplication, and the same obligation: a token the canonical
        # redactor elides must not be printed verbatim by the pre-import copy
        secret = '{"env": {"MY_API_KEY": "sk-super-secret"}}'
        for token in (secret, "--settings=" + secret, "--settings=/tmp/u.json",
                      "--agents=" + secret, "--model=sonnet", "--fork-session",
                      "/tmp/u.json", "", "-"):
            self.assertEqual(__main__._redacted(token),
                             supervisor.redacted_argument(token), token)

    def test_import_failure_preserves_option_value_that_looks_like_a_flag(self):
        # end-to-end: env-based fallback + import failure + a prompt value that
        # looks like a headroom flag -> the bare invocation keeps the value
        with mock.patch.dict(os.environ,
                             {"HEADROOM_LAUNCH_FALLBACK": "1"}), \
                mock.patch.object(__main__, "_prepare_launch",
                                  side_effect=RuntimeError("import blew up")), \
                mock.patch.object(__main__.os, "execvp") as execute, \
                redirect_stderr(io.StringIO()):
            code = __main__._dispatch(
                ["claude", "--system-prompt", "--headroom-auto-handoff"])
        self.assertEqual(code, 0)
        self.assertEqual(execute.call_args.args[1],
                         ["claude", "--system-prompt",
                          "--headroom-auto-handoff"])


# ==========================================================================
# Round-6: forward the shutdown signal the instant it is latched
# ==========================================================================
class R6SignalForwardOnLatch(TempDirCase):
    """P1(r6): _SignalGuard forwards the shutdown signal to the child inside
    _shutdown (the instant it latches), so no notifier-bearing work can run
    between latch and forward."""

    def test_guard_forwards_immediately_on_latch(self):
        process = mock.Mock()
        process.pid = 424242
        guard = supervisor._SignalGuard(process)
        kills = []
        with mock.patch.object(supervisor.os, "kill",
                               side_effect=lambda pid, sig: kills.append(
                                   (pid, sig))):
            # the OS would invoke this handler on delivery
            guard._shutdown(signal.SIGTERM, None)
        self.assertTrue(guard.forwarded)                 # forwarded in-handler
        self.assertEqual(kills, [(424242, signal.SIGTERM)])
        self.assertEqual(guard.shutdown_signal, signal.SIGTERM)

    def test_guard_forwards_only_once_across_repeat_signals(self):
        process = mock.Mock()
        process.pid = 111
        guard = supervisor._SignalGuard(process)
        kills = []
        with mock.patch.object(supervisor.os, "kill",
                               side_effect=lambda pid, sig: kills.append(sig)):
            guard._shutdown(signal.SIGTERM, None)
            guard._shutdown(signal.SIGHUP, None)  # second signal: ignored
        self.assertEqual(kills, [signal.SIGTERM])  # forwarded exactly once

    def test_attach_forwards_a_pre_latched_signal_once(self):
        # a signal latched BEFORE a child attaches (e.g. during the Popen fork
        # window, _process still None) is forwarded the instant attach binds
        # the child — and attach is idempotent.
        process = mock.Mock()
        process.pid = 333
        guard = supervisor._SignalGuard()  # no child yet
        kills = []
        with mock.patch.object(supervisor.os, "kill",
                               side_effect=lambda pid, sig: kills.append(
                                   (pid, sig))):
            guard._shutdown(signal.SIGTERM, None)   # latched, no child -> no kill
            self.assertEqual(kills, [])
            self.assertFalse(guard.forwarded)
            guard.attach(process)                    # now forward
            guard.attach(process)                    # idempotent
        self.assertTrue(guard.forwarded)
        self.assertEqual(kills, [(333, signal.SIGTERM)])  # exactly once

    def test_signal_in_attach_to_notify_window_forwards_no_orphan(self):
        # the r7 gap: a SIGTERM delivered AFTER Popen success but while the
        # launch notifier runs must be forwarded to the now-attached child.
        # Exactly one child signal, no orphan.
        account = self.account()
        process = mock.Mock()
        process.pid = 555555
        forwards = []
        captured = {}
        real_guard = supervisor._SignalGuard

        class CapturingGuard(real_guard):
            def __init__(self, proc=None):
                super().__init__(proc)
                captured["guard"] = self

            def install(self):        # don't touch the real process handlers
                pass

            def restore(self):
                pass

        def popen(argv, env=None, cwd=None, **kw):
            return process

        def emit(event):
            # SIGTERM delivered during the launch notify (post Popen + attach)
            if event.get("event") == "launch":
                captured["guard"]._shutdown(signal.SIGTERM, None)
            return True

        runner = supervisor.Supervisor("sonnet", [], account, popen=popen)
        with mock.patch.object(supervisor, "_SignalGuard", CapturingGuard), \
                mock.patch.object(
                    supervisor.os, "kill",
                    side_effect=lambda pid, sig: forwards.append((pid, sig))), \
                mock.patch.object(runner, "_settings_file", return_value=""), \
                mock.patch.object(notify, "emit", side_effect=emit), \
                redirect_stderr(io.StringIO()):
            runner._spawn(account, [], self.temp.name, False)
        # the child was attached before notify, so the mid-notify signal was
        # forwarded to it exactly once — no orphaned, unforwarded child
        self.assertEqual(forwards, [(555555, signal.SIGTERM)])
        self.assertTrue(captured["guard"].forwarded)

    def test_signal_before_attach_during_popen_forwards_at_attach(self):
        # a SIGTERM delivered WHILE Popen runs (child forked, not yet attached)
        # is latched and forwarded the instant the child attaches — no orphan.
        account = self.account()
        process = mock.Mock()
        process.pid = 888
        forwards = []
        captured = {}
        real_guard = supervisor._SignalGuard

        class CapturingGuard(real_guard):
            def __init__(self, proc=None):
                super().__init__(proc)
                captured["guard"] = self

            def install(self):
                pass

            def restore(self):
                pass

        def popen(argv, env=None, cwd=None, **kw):
            # signal arrives mid-Popen: latched, but no child attached yet
            captured["guard"]._shutdown(signal.SIGTERM, None)
            return process

        runner = supervisor.Supervisor("sonnet", [], account, popen=popen)
        with mock.patch.object(supervisor, "_SignalGuard", CapturingGuard), \
                mock.patch.object(
                    supervisor.os, "kill",
                    side_effect=lambda pid, sig: forwards.append((pid, sig))), \
                mock.patch.object(runner, "_settings_file", return_value=""), \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            runner._spawn(account, [], self.temp.name, False)
        self.assertEqual(forwards, [(888, signal.SIGTERM)])  # forwarded at attach

    def test_spawn_failure_restores_handlers_and_clears_guard(self):
        # a pre-spawn failure restores the installed handlers (no leak) and
        # clears self._signals so run()'s recovery runs with normal disposition
        account = self.account()
        popen = mock.Mock(return_value=mock.Mock())
        runner = supervisor.Supervisor("sonnet", [], account, popen=popen)
        restores = {"n": 0}
        real_guard = supervisor._SignalGuard

        class CountingGuard(real_guard):
            def install(self):
                pass

            def restore(self):
                restores["n"] += 1

        with mock.patch.object(supervisor, "_SignalGuard", CountingGuard), \
                mock.patch.object(supervisor.shutil, "which",
                                  return_value=None), \
                mock.patch.object(runner, "_settings_file", return_value=""), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(supervisor.SupervisorError):
                runner._spawn(account, [], self.temp.name, False)
        self.assertEqual(restores["n"], 1)     # handlers restored on failure
        self.assertIsNone(runner._signals)     # guard cleared
        popen.assert_not_called()

    def test_latched_shutdown_during_pre_spawn_failure_is_replayed(self):
        # a kill latched DURING the pre-spawn window (which() / marker) that
        # then fails must be honoured with the restored disposition, NOT
        # dropped into fallback/recovery — a requested kill never yields a new
        # launch (P1, r8). raise_signal is mocked so the test isn't killed.
        account = self.account()
        popen = mock.Mock(return_value=mock.Mock())
        runner = supervisor.Supervisor("sonnet", [], account, popen=popen)
        real_guard = supervisor._SignalGuard
        captured = {}

        class CapturingGuard(real_guard):
            def __init__(self, proc=None):
                super().__init__(proc)
                captured["guard"] = self

            def install(self):
                pass

            def restore(self):
                pass

        def latch_then_miss(_name):
            captured["guard"]._shutdown(signal.SIGTERM, None)
            return None  # which() reports the binary missing -> pre-spawn fail

        with mock.patch.object(supervisor, "_SignalGuard", CapturingGuard), \
                mock.patch.object(supervisor.shutil, "which",
                                  side_effect=latch_then_miss), \
                mock.patch.object(supervisor.signal, "raise_signal") as replay, \
                mock.patch.object(runner, "_settings_file", return_value=""), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(supervisor.SupervisorError):
                runner._spawn(account, [], self.temp.name, False)
        replay.assert_called_once_with(signal.SIGTERM)  # kill honoured
        popen.assert_not_called()                       # no child launched

    def test_shutdown_arriving_during_restore_is_still_replayed(self):
        # r9: the latch MUST be sampled AFTER guard.restore(). The guard's
        # handler stays live until restore() reinstalls the originals, so a
        # SIGTERM landing DURING restore still latches into the guard —
        # sampling before restore() would read None and let fallback/recovery
        # launch. Here which() fails WITHOUT pre-latching and the signal
        # arrives inside restore(); the replay must still fire.
        account = self.account()
        popen = mock.Mock(return_value=mock.Mock())
        runner = supervisor.Supervisor("sonnet", [], account, popen=popen)
        real_guard = supervisor._SignalGuard
        captured = {}

        class LatchOnRestoreGuard(real_guard):
            def __init__(self, proc=None):
                super().__init__(proc)
                captured["guard"] = self

            def install(self):
                pass

            def restore(self):
                # SIGTERM delivered while restore() runs, handler still live
                self._shutdown(signal.SIGTERM, None)

        with mock.patch.object(supervisor, "_SignalGuard", LatchOnRestoreGuard), \
                mock.patch.object(supervisor.shutil, "which",
                                  return_value=None), \
                mock.patch.object(supervisor.signal, "raise_signal") as replay, \
                mock.patch.object(runner, "_settings_file", return_value=""), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(supervisor.SupervisorError):
                runner._spawn(account, [], self.temp.name, False)
        replay.assert_called_once_with(signal.SIGTERM)  # sampled after restore
        popen.assert_not_called()

    def test_signal_during_handle_events_forwards_before_any_notify(self):
        # the real risk: a signal arrives WHILE _handle_events runs and calls
        # a (blocking) notifier. The forward must have already happened in the
        # signal handler, so it can never be delayed by the notify.
        account = self.account()
        runner = supervisor.Supervisor(
            "sonnet", [], account, now=lambda: 1000.0,
            sleep=lambda seconds: None)
        process = mock.Mock()
        process.pid = 777777
        poll_seq = iter([None, None, 0])
        process.poll.side_effect = lambda: next(poll_seq)
        child = mock.Mock()
        child.account = account
        child.process = process
        child.automation = True
        child.binding = object()
        child.launched_at = 0.0
        child.supervision_loss_notified = False
        order = []
        captured = {}
        real_guard = supervisor._SignalGuard

        class CapturingGuard(real_guard):
            def __init__(self, proc=None):
                super().__init__(proc)
                captured["guard"] = self

        def handle_events(c, phid, pr=None):
            if "signalled" not in captured:
                captured["signalled"] = True
                # a shutdown signal arrives mid-_handle_events (as the OS would
                # deliver it): the guard forwards synchronously here
                captured["guard"]._shutdown(signal.SIGTERM, None)
                # ...and _handle_events then does its own (blocking) notify
                notify.emit({"event": "supervision_lost",
                             "reason": "from _handle_events"})
            return None

        def record_kill(pid, sig):
            order.append("forward")

        def record_emit(event):
            order.append("notify")
            return True

        with mock.patch.object(supervisor, "_SignalGuard", CapturingGuard), \
                mock.patch.object(supervisor.os, "kill",
                                  side_effect=record_kill), \
                mock.patch.object(runner, "_handle_events",
                                  side_effect=handle_events), \
                mock.patch.object(notify, "emit", side_effect=record_emit), \
                redirect_stderr(io.StringIO()):
            returncode = runner._monitor(child)
        self.assertEqual(returncode, 0)
        self.assertIn("forward", order)
        self.assertIn("notify", order)
        # the forward happened BEFORE the first notify, despite the notify
        # being invoked from inside _handle_events
        self.assertLess(order.index("forward"), order.index("notify"))


# ==========================================================================
# Round-4 red-team fixes  (the r4 signal-masking + preexec_fn machinery was
# REMOVED in r5 in favour of pre-validate-then-conservative-ambiguity; the
# mask/preexec tests are gone. The notify-deferral and ambiguous-stop tests
# below remain valid.)
# ==========================================================================
class R4ShutdownNotifyDeferredUntilForwarded(TempDirCase):
    """P1(r4): the supervision_lost NOTIFY is deferred until the signal has
    been forwarded, so a slow notifier can't delay SIGTERM/SIGHUP forwarding."""

    def test_notify_only_after_forwarding_and_disarms_immediately(self):
        account = self.account()
        runner = supervisor.Supervisor(
            "sonnet", [], account, now=lambda: 1000.0,
            sleep=lambda seconds: None)
        child = mock.Mock()
        child.account = account
        child.automation = True
        child.binding = object()
        child.launched_at = 0.0
        child.supervision_loss_notified = False
        order = []
        counter = {"n": 0}

        def child_poll():
            counter["n"] += 1
            return None if counter["n"] < 6 else 0

        child.process.poll.side_effect = child_poll

        # a fake guard that mirrors the poll backstop forwarding (this test
        # pre-latches, then forwards on the poll — the r6 immediate-forward
        # path is covered by the _SignalGuard unit + mid-_handle_events tests)
        class Guard:
            shutdown_signal = signal.SIGTERM
            polls = 0
            forwarded = False

            def __init__(self, process=None):
                pass

            def install(self):
                pass

            def restore(self):
                pass

            def poll(self, process):
                if self.shutdown_signal is None or process.poll() is not None:
                    return
                self.polls += 1
                if self.polls >= 2 and not self.forwarded:
                    order.append("forward")
                    self.forwarded = True

        def record_emit(event):
            # the ACTUAL notification (emit), which _lose_supervision fires
            # once past its guard, is what must land after forwarding
            if event.get("event") == "supervision_lost":
                order.append("notify")
            return True

        with mock.patch.object(supervisor, "_SignalGuard", Guard), \
                mock.patch.object(runner, "_handle_events", return_value=None), \
                mock.patch.object(notify, "emit", side_effect=record_emit), \
                redirect_stderr(io.StringIO()):
            returncode = runner._monitor(child)
        self.assertEqual(returncode, 0)
        # automation is disarmed on the FIRST poll (before forwarding); the
        # notify is deferred until AFTER the forward
        self.assertFalse(child.automation)
        self.assertIn("forward", order)
        self.assertIn("notify", order)
        self.assertLess(order.index("forward"), order.index("notify"))
        # and the notification fires exactly once
        self.assertEqual(order.count("notify"), 1)


class R4AmbiguousStopEmitsSupervisionLost(TempDirCase):
    """P2(r4): the ambiguous-stop path emits supervision_lost directly (no
    Child handle), so observers learn the orphaned child is unmonitored."""

    def test_initial_ambiguous_stop_emits_supervision_lost(self):
        account = self.account("acct-a")
        runner = supervisor.Supervisor("sonnet", [], account)

        def fake_spawn(acct, args, cwd, automatic, plan=None):
            runner.spawn_ambiguous = True
            raise RuntimeError("post-popen boom")

        with mock.patch.object(runner, "_spawn", side_effect=fake_spawn), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            code = runner.run()
        self.assertEqual(code, 127)
        lost = [call.args[0] for call in emit.call_args_list
                if call.args[0]["event"] == "supervision_lost"]
        self.assertEqual(len(lost), 1)
        self.assertEqual(lost[0]["account"], "acct-a")
        self.assertIn("unmonitored", lost[0]["reason"])


# --------------------------------------------------------------------------
# Preemptive rotation: leave BEFORE the wall (incident 2026-07-26 — a seat at
# 97% with an idle session never rotated, because only a proven cap could
# trigger a handoff)
# --------------------------------------------------------------------------
class PreemptiveConfig(TempDirCase):
    BASE = {"schema_version": 1, "accounts": [
        {"name": "a", "provider": "claude", "home": "/tmp/a"}]}

    def test_defaults_on_with_93_and_95_thresholds(self):
        self.assertTrue(registry.preemptive_handoff(self.BASE))
        self.assertEqual(registry.preemptive_thresholds(self.BASE), (93.0, 95.0))
        self.assertEqual(registry.preemptive_thresholds(
            dict(self.BASE, routing="broken")), (93.0, 95.0))

    def test_the_five_hour_trigger_is_on_by_default_at_97(self):
        # its own switch and its own, higher threshold: a 5h window heals by
        # itself, so leaving one early has to be worth the restart
        self.assertTrue(registry.preemptive_session(self.BASE))
        self.assertEqual(registry.preemptive_session_threshold(self.BASE), 97.0)
        self.assertEqual(registry.preemptive_session_threshold(
            dict(self.BASE, routing="broken")), 97.0)
        self.assertEqual(registry.preemptive_session_threshold(
            dict(self.BASE, routing={"preemptive_session_percent": 88})), 88.0)
        for bad in ("x", None, [], 0, -1, 101):
            self.assertEqual(registry.preemptive_session_threshold(
                dict(self.BASE, routing={"preemptive_session_percent": bad})),
                97.0, bad)

    def test_the_five_hour_trigger_has_its_own_kill_switch(self):
        self.assertFalse(registry.preemptive_session(
            dict(self.BASE, routing={"preemptive_session_handoff": False})))
        with mock.patch.dict(os.environ, {"HEADROOM_PREEMPTIVE_SESSION": "0"}):
            self.assertFalse(registry.preemptive_session(self.BASE))
            # and it is JUST this trigger: everything else stays armed
            self.assertTrue(registry.preemptive_handoff(self.BASE))
        with mock.patch.dict(os.environ, {"HEADROOM_PREEMPTIVE_SESSION": "1"}):
            self.assertTrue(registry.preemptive_session(self.BASE))

    def test_only_explicit_false_or_the_env_kill_switch_disables(self):
        self.assertFalse(registry.preemptive_handoff(
            dict(self.BASE, routing={"preemptive_handoff": False})))
        for value in (True, "false", "true", 1, 0, None, [], {}):
            config = dict(self.BASE, routing={"preemptive_handoff": value})
            self.assertEqual(registry.preemptive_handoff(config),
                             value is not False, value)
        with mock.patch.dict(os.environ, {"HEADROOM_PREEMPTIVE": "0"}):
            self.assertFalse(registry.preemptive_handoff(self.BASE))
        with mock.patch.dict(os.environ, {"HEADROOM_PREEMPTIVE": "1"}):
            self.assertTrue(registry.preemptive_handoff(self.BASE))

    def test_configured_thresholds_are_used_and_nonsense_keeps_defaults(self):
        config = dict(self.BASE, routing={"preemptive_scoped_percent": 80,
                                          "preemptive_overall_percent": "88"})
        self.assertEqual(registry.preemptive_thresholds(config), (80.0, 88.0))
        for bad in ("x", None, [], 0, -1, 101, True):
            config = dict(self.BASE, routing={"preemptive_scoped_percent": bad})
            scoped, _ = registry.preemptive_thresholds(config)
            # True coerces to 1.0, which is a legal (if silly) threshold; every
            # other nonsense keeps the default rather than arming on garbage
            self.assertEqual(scoped, 1.0 if bad is True else 93.0, bad)


class _WindowCase(TempDirCase):
    """One usage row and a supervisor to read it with — shared by the two
    classes below (a mixin, not a base with tests: inheriting tests would run
    the whole crossing suite twice)."""

    def runner(self, account=None):
        return supervisor.Supervisor("fable", [], account or self.account())

    def windows(self, seven=10.0, scoped=None, five=10.0, **over):
        windows = {"5h": (five if isinstance(five, dict)
                          else {"used_percent": five}),
                   "7d": dict({"used_percent": seven}, **over)}
        if scoped is not None:
            windows["scoped:Fable"] = (scoped if isinstance(scoped, dict)
                                       else {"used_percent": scoped})
        return {"windows": windows}


class PreemptiveThresholds(_WindowCase):
    def test_scoped_family_window_trips_first(self):
        crossing = self.runner()._threshold_crossing(
            "fable", self.windows(seven=10.0, scoped=93.0))
        self.assertEqual(crossing, ("scoped:fable", 93.0))

    def test_a_weekly_crossing_is_reported_ahead_of_a_full_5h_one(self):
        # both have crossed; the weekly one is the one that does not heal, so
        # it names the rotation (and picks the stricter target rule)
        crossing = self.runner()._threshold_crossing(
            "fable", self.windows(seven=10.0, scoped=93.0, five=99.0))
        self.assertEqual(crossing, ("scoped:fable", 93.0))

    def test_overall_seven_day_window_trips_at_its_own_threshold(self):
        self.assertIsNone(self.runner()._threshold_crossing(
            "fable", self.windows(seven=94.9, scoped=10.0)))
        self.assertEqual(self.runner()._threshold_crossing(
            "fable", self.windows(seven=95.0, scoped=10.0)), ("7d", 95.0))

    def test_the_5h_window_triggers_at_its_own_higher_threshold(self):
        # SUPERSEDES test_a_full_5h_window_is_never_a_preemptive_trigger.
        # That test pinned "5h heals within hours and the cap path already
        # covers it", which holds for a session that can afford to sit and
        # wait and fails for the continuous autonomous work headroom is for:
        # the wall lands mid-task. So the 5h IS a trigger — later than the
        # weekly ones (97 vs 93/95), and only ever acted on when a seat with
        # real 5h headroom exists to move to (see TargetFitness).
        runner = self.runner()
        self.assertIsNone(runner._threshold_crossing(
            "fable", self.windows(seven=10.0, scoped=10.0, five=96.9)))
        self.assertEqual(runner._threshold_crossing(
            "fable", self.windows(seven=10.0, scoped=10.0, five=97.0)),
            ("5h", 97.0))
        self.assertEqual(runner._threshold_crossing(
            "fable", self.windows(seven=10.0, scoped=10.0, five=99.0)),
            ("5h", 99.0))

    def test_the_5h_trigger_can_be_switched_off_without_the_others(self):
        with mock.patch.dict(os.environ, {"HEADROOM_PREEMPTIVE_SESSION": "0"}):
            runner = self.runner()          # policy is read at construction
        self.assertIsNone(runner._threshold_crossing(
            "fable", self.windows(seven=10.0, scoped=10.0, five=99.0)))
        self.assertEqual(runner._threshold_crossing(
            "fable", self.windows(seven=95.0, scoped=10.0, five=99.0)),
            ("7d", 95.0))
        # ...and switching the TRIGGER off never makes a spent seat a target
        self.assertEqual(runner._target_unfit(
            "fable", self.windows(five=99.0)), "5h at 99%")

    def test_an_expired_or_unreadable_5h_reading_is_not_a_crossing(self):
        runner = self.runner()
        for five in (None, "97", 101.0, float("nan"),
                     {"used_percent": 99.0,
                      "freshness": "expired_observation"}):
            row = self.windows(seven=10.0, scoped=10.0, five=five)
            if five is None:
                row["windows"]["5h"] = None
            self.assertIsNone(runner._threshold_crossing("fable", row), five)

    def test_absence_of_proof_is_never_a_crossing(self):
        runner = self.runner()
        for row in (None, {}, {"windows": None}, {"windows": {}},
                    self.windows(seven="97"), self.windows(seven=101.0),
                    self.windows(seven=float("nan")),
                    self.windows(seven=97.0, freshness="expired_observation"),
                    self.windows(scoped={"used_percent": 99.0,
                                         "freshness": "expired_observation"})):
            self.assertIsNone(runner._threshold_crossing("fable", row), row)

    def test_thresholds_come_from_config(self):
        registry.save({"schema_version": 1, "routing": {
            "preemptive_scoped_percent": 70, "preemptive_overall_percent": 75},
            "accounts": [self.account()]})
        runner = self.runner()
        self.assertEqual((runner.preemptive_scoped, runner.preemptive_overall),
                         (70.0, 75.0))
        self.assertEqual(runner._threshold_crossing(
            "fable", self.windows(seven=10.0, scoped=71.0)),
            ("scoped:fable", 71.0))


class TargetFitness(_WindowCase):
    """Who is worth moving TO.

    Defect: preemptive rotation skipped a candidate only on the scoped and 7d
    thresholds, so a seat whose 5h window read 99% was a perfectly legal
    target — the rotation spent a handoff, a restart and the loop budget to
    land on a window that was about to refuse."""

    def test_a_spent_5h_seat_is_never_a_target_even_for_a_weekly_crossing(self):
        runner = self.runner()
        for window in ("7d", "scoped:fable", "5h", ""):
            self.assertEqual(
                runner._target_unfit("fable", self.windows(five=99.0), window),
                "5h at 99%", window)

    def test_a_weekly_crossing_accepts_a_busy_but_healing_5h_seat(self):
        # a spent WEEKLY window is gone for days; a target at 90% of a window
        # that resets within hours is still a much better place to be
        self.assertEqual(self.runner()._target_unfit(
            "fable", self.windows(five=90.0), "7d"), "")

    def test_a_5h_crossing_demands_a_margin_the_move_can_buy_time_with(self):
        # 97 → 96 is not a rotation, it is a restart with a short reprieve
        runner = self.runner()
        self.assertEqual(runner._target_unfit(
            "fable", self.windows(five=90.0), "5h"), "5h at 90%")
        self.assertEqual(runner._target_unfit(
            "fable", self.windows(five=86.9), "5h"), "")

    def test_a_seat_over_a_weekly_threshold_is_unfit_whatever_the_crossing(self):
        runner = self.runner()
        self.assertEqual(runner._target_unfit(
            "fable", self.windows(seven=96.0), "5h"), "7d at 96%")
        self.assertEqual(runner._target_unfit(
            "fable", self.windows(scoped=94.0), "7d"), "scoped:fable at 94%")

    def test_an_unreadable_5h_percentage_is_left_to_block_reason(self):
        # route.block_reason has already refused every candidate whose 5h is
        # missing, invalid, expired or at 100%; silence here is not consent
        runner = self.runner()
        for row in ({}, {"windows": {}}, self.windows(five="99"),
                    self.windows(five=101.0)):
            self.assertEqual(runner._target_unfit("fable", row, "5h"), "", row)

    def test_the_target_ceiling_follows_the_configured_threshold(self):
        registry.save({"schema_version": 1, "routing": {
            "preemptive_session_percent": 60}, "accounts": [self.account()]})
        runner = self.runner()
        self.assertEqual(runner._target_unfit(
            "fable", self.windows(five=60.0), "7d"), "5h at 60%")
        self.assertEqual(runner._target_unfit(
            "fable", self.windows(five=59.0), "7d"), "")
        # 5h crossing: 60 - 10 margin
        self.assertEqual(runner._target_unfit(
            "fable", self.windows(five=50.0), "5h"), "5h at 50%")
        self.assertEqual(runner._target_unfit(
            "fable", self.windows(five=49.0), "5h"), "")


class TurnCompleteness(TempDirCase):
    """Quiescence is not idleness: a turn can be silent for minutes while the
    model thinks, so the newest conversational record decides."""

    def write(self, *events):
        path = os.path.join(self.temp.name, "t.jsonl")
        with open(path, "w", encoding="utf-8") as out:
            for event in events:
                out.write(json.dumps(event) + "\n")
        return path

    ASSISTANT = {"type": "assistant", "message": {
        "model": "claude-fable-5", "content": [{"type": "text", "text": "hi"}]}}
    PROMPT = {"type": "user", "message": {
        "content": [{"type": "text", "text": "do the thing"}]}}
    TOOL_RESULT = {"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": "ok"}]}}

    def test_finished_assistant_turn_is_complete(self):
        self.assertEqual(
            supervisor._turn_is_complete(self.write(self.PROMPT, self.ASSISTANT)),
            "")

    def test_trailing_bookkeeping_records_do_not_hide_the_turn(self):
        path = self.write(self.PROMPT, self.ASSISTANT,
                          {"type": "system", "subtype": "turn_duration"},
                          {"type": "file-history-snapshot", "id": "x"},
                          {"type": "summary", "summary": "s"})
        self.assertEqual(supervisor._turn_is_complete(path), "")

    def test_a_prompt_awaiting_its_answer_is_mid_turn(self):
        # the reviewer's scenario: the model has been thinking for 70s and
        # has written nothing, so the transcript is quiet AND mid-turn
        path = self.write(self.ASSISTANT, self.PROMPT)
        self.assertIn("awaiting its answer", supervisor._turn_is_complete(path))

    def test_an_unanswered_tool_result_is_mid_turn(self):
        path = self.write(self.PROMPT, self.ASSISTANT, self.TOOL_RESULT)
        self.assertIn("awaiting its answer", supervisor._turn_is_complete(path))

    def test_a_live_sidechain_is_mid_turn(self):
        path = self.write(self.PROMPT, self.ASSISTANT,
                          dict(self.ASSISTANT, isSidechain=True))
        self.assertIn("subagent", supervisor._turn_is_complete(path))
        path = self.write(self.PROMPT, self.ASSISTANT,
                          {"type": "assistant", "message": dict(
                              self.ASSISTANT["message"], isSidechain=True)})
        self.assertIn("subagent", supervisor._turn_is_complete(path))

    def test_no_conversational_record_is_never_complete(self):
        self.assertIn("no completed assistant turn",
                      supervisor._turn_is_complete(self.write(
                          {"type": "system", "subtype": "init"})))
        self.assertIn("no completed assistant turn",
                      supervisor._turn_is_complete(
                          os.path.join(self.temp.name, "missing.jsonl")))


class BackgroundSubagents(TempDirCase):
    """Live layout: projects/<slug>/<session>.jsonl beside
    projects/<slug>/<session>/subagents/agent-<id>.jsonl. A backgrounded Agent
    hands its tool_result to the main thread at once and keeps working there,
    so the main transcript reads "finished turn" while work is in flight."""

    SID = "66666666-6666-4666-8666-666666666666"

    def setUp(self):
        super().setUp()
        self.project = os.path.join(self.temp.name, "projects", "slug")
        os.makedirs(self.project)
        self.transcript = os.path.join(self.project, self.SID + ".jsonl")
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "go"}]}}) + "\n")
            # the main turn genuinely ENDED: the Agent call was backgrounded
            out.write(json.dumps({"type": "assistant", "message": {
                "model": "claude-fable-5",
                "content": [{"type": "text", "text": "started it"}]}}) + "\n")
        old = time.time() - 3600
        os.utime(self.transcript, (old, old))

    # a finished agent's transcript ends with the assistant message that IS
    # its return value; a live one ends with input it has not answered, or a
    # tool_use whose result has not landed (real sidechain record shapes)
    FINISHED = {"type": "assistant", "isSidechain": True,
                "agentId": "a99d97898086ab524", "message": {
                    "model": "claude-fable-5",
                    "content": [{"type": "text", "text": "here is my report"}]}}
    IN_TOOL = {"type": "assistant", "isSidechain": True,
               "agentId": "a99d97898086ab524", "message": {
                   "model": "claude-fable-5", "content": [
                       {"type": "tool_use", "id": "toolu_slow", "name": "Bash",
                        "input": {"command": "make -j8"}}]}}
    AWAITING = {"type": "user", "isSidechain": True,
                "agentId": "a99d97898086ab524", "message": {"content": [
                    {"type": "tool_result", "tool_use_id": "toolu_slow",
                     "content": "build finished"}]}}

    def subagent(self, age, name="agent-a99d97898086ab524", records=None):
        directory = os.path.join(self.project, self.SID, "subagents")
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name + ".jsonl")
        with open(path, "w", encoding="utf-8") as out:
            for record in (records or [self.FINISHED]):
                out.write(json.dumps(record) + "\n")
        with open(os.path.join(directory, name + ".meta.json"), "w",
                  encoding="utf-8") as out:
            json.dump({"agentType": "general-purpose", "description": "work",
                       "toolUseId": "toolu_x", "spawnDepth": 1}, out)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def test_main_transcript_alone_reads_idle(self):
        # the exact trap: by the main transcript, this session looks finished
        self.assertEqual(supervisor._turn_is_complete(self.transcript), "")

    def test_a_live_background_subagent_is_not_idle(self):
        self.subagent(age=2)
        reason = supervisor._idle_refusal(self.transcript, time.time(), 60.0)
        self.assertIn("background subagent", reason)

    def test_a_finished_subagent_does_not_block_forever(self):
        self.subagent(age=3600)
        self.assertEqual(
            supervisor._idle_refusal(self.transcript, time.time(), 60.0), "")

    def test_the_newest_subagent_decides(self):
        self.subagent(age=3600, name="agent-aold")
        self.subagent(age=1, name="agent-anew")
        self.assertIn("background subagent", supervisor._idle_refusal(
            self.transcript, time.time(), 60.0))

    def test_nested_worker_transcripts_are_seen(self):
        directory = os.path.join(self.project, self.SID, "subagents",
                                 "workflows", "w1")
        os.makedirs(directory)
        path = os.path.join(directory, "agent-nested.jsonl")
        with open(path, "w", encoding="utf-8") as out:
            out.write("{}\n")
        self.assertIn("background subagent", supervisor._idle_refusal(
            self.transcript, time.time(), 60.0))

    def test_no_subagents_directory_is_idle(self):
        self.assertEqual(
            supervisor._idle_refusal(self.transcript, time.time(), 60.0), "")

    def test_a_future_dated_write_counts_as_active(self):
        path = self.subagent(age=0)
        later = time.time() + 600
        os.utime(path, (later, later))
        self.assertIn("background subagent", supervisor._idle_refusal(
            self.transcript, time.time(), 60.0))

    # --- liveness is SHAPE, never age -------------------------------------

    def test_a_silently_thinking_subagent_is_live_however_old(self):
        # blocked inside one long tool call for an hour: nothing written, so
        # "old" says finished and only the shape says the truth
        self.subagent(age=3600, records=[self.FINISHED, self.IN_TOOL])
        reason = supervisor._idle_refusal(self.transcript, time.time(), 60.0)
        self.assertIn("waiting on a tool call", reason)

    def test_a_subagent_with_unanswered_input_is_live_however_old(self):
        self.subagent(age=7200,
                      records=[self.IN_TOOL, self.AWAITING])
        reason = supervisor._idle_refusal(self.transcript, time.time(), 60.0)
        self.assertIn("answering its latest input", reason)

    def test_a_completed_return_value_does_not_block_however_old(self):
        self.subagent(age=7200,
                      records=[self.IN_TOOL, self.AWAITING, self.FINISHED])
        self.assertEqual(
            supervisor._idle_refusal(self.transcript, time.time(), 60.0), "")

    def test_an_unreadable_or_shapeless_sidechain_refuses(self):
        path = self.subagent(age=3600)
        with open(path, "w", encoding="utf-8") as out:
            out.write("not json at all\n")
        old = time.time() - 3600
        os.utime(path, (old, old))
        self.assertIn("unreadable record", supervisor._idle_refusal(
            self.transcript, time.time(), 60.0))
        with open(path, "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "system", "subtype": "init"}) + "\n")
        os.utime(path, (old, old))
        self.assertIn("no conversational record", supervisor._idle_refusal(
            self.transcript, time.time(), 60.0))

    # --- bounded by THIS child's lifetime ---------------------------------

    def main_with_launch(self, agent_id):
        """A finished main turn that started a background agent."""
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "go"}]}}) + "\n")
            out.write(json.dumps({"type": "user", "message": {"content": [{
                "type": "tool_result", "tool_use_id": "toolu_x", "content": [{
                    "type": "text",
                    "text": ("Async agent launched successfully.\n"
                             f"agentId: {agent_id} (internal ID)")}]}]}}) + "\n")
            out.write(json.dumps({"type": "assistant", "message": {
                "model": "claude-fable-5",
                "content": [{"type": "text",
                             "text": "started it"}]}}) + "\n")
        old = time.time() - 3600
        os.utime(self.transcript, (old, old))

    def test_a_launched_agent_with_no_transcript_yet_is_live(self):
        # the sidechain file may not exist at all in the instant after a spawn
        self.main_with_launch("anewagent123")
        now = time.time()
        self.assertIn("have not reported back", supervisor._idle_refusal(
            self.transcript, now, 60.0, since=now - 60))

    def test_a_mid_turn_sidechain_from_a_previous_run_never_blocks(self):
        self.subagent(age=7200, records=[self.IN_TOOL])
        now = time.time()
        # unbounded, it reads live — it really is mid-turn...
        self.assertIn("waiting on a tool call",
                      supervisor._idle_refusal(self.transcript, now, 60.0))
        # ...but it stopped writing before this child started, so its agent
        # died with the previous process and must not block forever
        self.assertEqual(supervisor._idle_refusal(
            self.transcript, now, 60.0, since=now - 60), "")

    def test_a_launch_from_a_previous_run_does_not_block(self):
        self.main_with_launch("aoldagent123")
        self.subagent(age=7200, name="agent-aoldagent123")
        now = time.time()
        self.assertEqual(supervisor._idle_refusal(
            self.transcript, now, 60.0, since=now - 60), "")

    def test_a_corrupt_newest_line_refuses_after_a_valid_turn(self):
        # a complete assistant turn followed by a broken line: the tail starts
        # at a record boundary, so that line is corruption or a record being
        # written right now — never "finished"
        self.subagent(age=3600, records=[self.FINISHED])
        path = os.path.join(self.project, self.SID, "subagents",
                            "agent-a99d97898086ab524.jsonl")
        with open(path, "a", encoding="utf-8") as out:
            out.write('{"type": "assistant", "mess')
        old = time.time() - 3600
        os.utime(path, (old, old))
        self.assertIn("unreadable record", supervisor._idle_refusal(
            self.transcript, time.time(), 60.0))

    def test_a_corrupt_newest_line_in_the_main_transcript_refuses(self):
        with open(self.transcript, "a", encoding="utf-8") as out:
            out.write('{"type": "user", "mes')
        old = time.time() - 3600
        os.utime(self.transcript, (old, old))
        self.assertIn("unreadable record", supervisor._idle_refusal(
            self.transcript, time.time(), 60.0))
        # and the same refusal reaches the turn check on its own
        self.assertIn("unreadable record",
                      supervisor._turn_is_complete(self.transcript))

    def test_the_scan_is_bounded(self):
        directory = os.path.join(self.project, self.SID, "subagents")
        os.makedirs(directory, exist_ok=True)
        old = time.time() - 3600
        for index in range(12):
            path = os.path.join(directory, f"agent-{index:03d}.jsonl")
            with open(path, "w", encoding="utf-8") as out:
                out.write(json.dumps(self.FINISHED) + "\n")   # each one done
            os.utime(path, (old, old))
        with mock.patch.object(supervisor, "MAX_SUBAGENT_SCAN", 5):
            # refusing to rotate is the fail-closed answer when the session is
            # too large to prove idle inside the poll
            self.assertIn("too many subagent transcripts",
                          supervisor._idle_refusal(self.transcript,
                                                   time.time(), 60.0))


class ASubagentsCapIsNotTheParentsCap(TempDirCase):
    """Replays the real 2026-07-27 disarm of session 82d739e6.

    27 of 35 StopFailure records in the live journals carry `agent_id` /
    `agent_type` ("workflow-subagent") while naming the PARENT session_id and
    transcript_path, with the cap text in `last_assistant_message`. Nothing
    in the cap path ever looked at those fields, so cap_message's
    direct-payload branch returned non-empty and _prove_cap opened a
    PendingCap against the parent.

    _prove_cap then resolves the cap-time model from the PARENT transcript,
    which skips sidechain records (deliberate, pinned elsewhere) and requires
    the newest MAIN-CHAIN assistant record to BE the cap. Background
    subagents write to <session>/subagents/agent-*.jsonl, so the refusal is
    simply absent from the parent file: evidence is None, the pending cap is
    re-driven every poll, and after CAP_MODEL_RETRIES+1 windows (~18s) it
    raises PendingCapTimeout — which _attempt_cap turns into a PERMANENT
    _lose_supervision. Measured on the real timeline: disarm at +39.5s, and
    the parent's OWN genuine cap arrived at +79.5s to find automation already
    gone and the announce-only path waiting for it.

    A subagent's refusal is real, but it is not evidence the parent session
    is walled. It must never open a proof against the parent transcript."""

    SID = "82d73900-0000-4000-8000-000000000001"
    # verbatim from a live record (agent_id 'addb74a7cd4302728')
    LIVE_CAP = "You've hit your session limit · resets 3pm (UTC)"

    def setUp(self):
        super().setUp()
        self.clock = {"t": 1_000_000.0}
        self.account_ = self.account("source")
        self.project = os.path.join(self.account_["home"], "projects", "slug")
        os.makedirs(self.project)
        self.transcript = os.path.join(self.project, self.SID + ".jsonl")
        self.healthy_parent()
        self.cwd = os.path.join(self.temp.name, "work")
        os.makedirs(self.cwd)
        self.binding = supervisor.Binding(
            self.SID, self.transcript, self.cwd, "Fable", "2.1",
            self.account_["home"], epoch=1)

    def healthy_parent(self):
        """The parent transcript as it really looks while a subagent caps:
        the newest main-chain assistant record is a perfectly healthy turn.
        The refusal is in <session>/subagents/, which this file never sees."""
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "go"}]}}) + "\n")
            out.write(json.dumps({"type": "assistant", "message": {
                "model": "claude-fable-5-20260701",
                "content": [{"type": "text", "text": "started it"}]}}) + "\n")
        old = self.clock["t"] - 3600
        os.utime(self.transcript, (old, old))

    def capped_parent(self):
        """...and the same transcript once the PARENT itself refuses."""
        with open(self.transcript, "a", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant", "isApiErrorMessage": True,
                "error": "rate_limit", "apiErrorStatus": 429,
                "message": {"model": "<synthetic>", "content": [
                    {"type": "text", "text": self.LIVE_CAP}]}}) + "\n")
        old = self.clock["t"] - 3600
        os.utime(self.transcript, (old, old))

    def child(self):
        return supervisor.Child(
            mock.Mock(pid=os.getpid()), self.account_, 1,
            os.path.join(self.temp.name, "no-events.jsonl"), "",
            0.0, True, binding=self.binding, session_epoch=1)

    def runner(self):
        return supervisor.Supervisor(
            "fable", [], self.account_, popen=mock.Mock(),
            now=lambda: self.clock["t"],
            sleep=lambda s: self.clock.__setitem__("t", self.clock["t"] + s))

    def record(self, when, agent=True, session_id=None):
        payload = {"hook_event_name": "StopFailure",
                   "session_id": session_id or self.SID,
                   "transcript_path": self.transcript, "cwd": self.cwd,
                   "error": "rate_limit",
                   "last_assistant_message": self.LIVE_CAP}
        if agent:
            # the live field pair, verbatim
            payload["agent_id"] = "addb74a7cd4302728"
            payload["agent_type"] = "workflow-subagent"
        return {"schema": "headroom_hook_event@1", "received_at": when,
                "supervisor_id": "no-events", "generation": 1,
                "source_slot": self.account_["name"],
                "config_dir": self.account_["home"], "matcher": "rate_limit",
                "payload": payload}

    @contextlib.contextmanager
    def wired(self):
        """_validated_event stubbed exactly as every other cap test does it;
        everything below it — _prove_cap, the transcript lookup, _attempt_cap
        and the disarm — is the real code."""
        with mock.patch.object(supervisor, "_validated_event",
                               return_value=(self.binding, self.cwd)), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()) as errors:
            yield emit, errors

    def replay(self, offsets, until=60.0, agent=True):
        """Drive the hooks at `offsets`, then poll the pending cap the way
        _monitor does (re-driving child.pending_cap.event every poll) across
        `until` seconds of simulated time."""
        runner, child = self.runner(), self.child()
        start, results = self.clock["t"], []
        pending = sorted(offsets)
        with self.wired() as (emit, errors):
            while self.clock["t"] - start <= until:
                if pending and self.clock["t"] - start >= pending[0]:
                    when = start + pending.pop(0)
                    results.append(runner._attempt_cap(
                        child, self.record(when, agent=agent),
                        announce_non_cap=True))
                elif child.pending_cap is not None and child.automation:
                    results.append(
                        runner._attempt_cap(child, child.pending_cap.event))
                self.clock["t"] += 1.0
            events = [call.args[0] for call in emit.call_args_list]
        return child, results, events, errors.getvalue()

    # -- the replay --------------------------------------------------------

    def test_the_2026_07_27_timeline_no_longer_disarms_the_parent(self):
        """(a) The real thing: subagent caps at t, +11.6s, +21.4s, then a
        22.3s quiet gap. HEAD disarms at +39.5s, permanently, on a seat the
        parent had not even refused on yet."""
        child, _results, events, errors = self.replay([0.0, 11.6, 21.4])
        self.assertTrue(child.automation,
                        "a background subagent's cap disarmed the parent")
        self.assertNotIn("supervision_lost", [e["event"] for e in events])
        unhandled = [e for e in events if e["event"] == "cap_unhandled"]
        self.assertTrue(unhandled)
        self.assertIn("background subagent", unhandled[0]["reason"])
        self.assertIn("background subagent", errors)
        # the refusal is named, never silently swallowed
        self.assertEqual(unhandled[0]["agent_id"], "addb74a7cd4302728")

    def test_the_2026_07_31_shape_still_does_not_disarm(self):
        """(e) The other live timeline — max gap 8.69s, which never reached
        the timeout even on HEAD. It must not start failing now."""
        child, _results, events, _errors = self.replay(
            [0.0, 4.2, 8.7, 13.0, 21.5], until=30.0)
        self.assertTrue(child.automation)
        self.assertNotIn("supervision_lost", [e["event"] for e in events])

    def test_a_subagent_cap_never_opens_a_pending_cap_at_all(self):
        """The mechanism, stated directly: no PendingCap, so no deadline, so
        no timeout, so no disarm. The old path could only ever end one way."""
        runner, child = self.runner(), self.child()
        with self.wired():
            with mock.patch.object(supervisor, "PendingCap",
                                   wraps=supervisor.PendingCap) as pending:
                self.assertIsNone(runner._prove_cap(
                    child, self.record(self.clock["t"])))
        self.assertEqual(pending.call_count, 0)
        self.assertIsNone(child.pending_cap)
        self.assertTrue(child.automation)

    # -- and it must not suppress anything real ----------------------------

    def test_the_parents_own_cap_still_proves_and_rotates(self):
        """(b) The +79.5s event in the real timeline: no agent attribution,
        the parent transcript's newest main-chain record IS the cap. This is
        the rotation the whole supervisor exists for and it is untouched."""
        self.capped_parent()
        runner, child = self.runner(), self.child()
        with self.wired():
            proof = runner._attempt_cap(
                child, self.record(self.clock["t"], agent=False))
        self.assertIsInstance(proof, supervisor.CapProof)
        self.assertEqual(proof.family, "fable")
        self.assertTrue(child.automation)

    def test_an_agent_tagged_cap_the_PARENT_transcript_corroborates_wins(self):
        """(d) THE fence on this patch, and the reason the suppression is
        conditional rather than absolute.

        Suppressing on the hook's agent attribution ALONE would mean that the
        day the harness starts tagging parent caps with an agent field, every
        genuine wall goes unrotated — trading a permanent disarm for a
        permanent refusal to act, which is no better. So the suppression asks
        the parent transcript first: if the parent itself refused, that is
        independent evidence this session is walled, and it rotates whatever
        the hook was tagged with. The suppression fires only in the case that
        used to time out and disarm — the parent transcript showing a
        perfectly healthy newest turn."""
        self.capped_parent()
        runner, child = self.runner(), self.child()
        with self.wired():
            proof = runner._attempt_cap(child, self.record(self.clock["t"]))
        self.assertIsInstance(proof, supervisor.CapProof)
        self.assertTrue(child.automation)

    def test_a_foreign_session_id_is_not_this_childs_business(self):
        """(c) Both conditions are required. A subagent record naming another
        session never matched this child anyway; cap_message's own binding
        check refuses it, exactly as before."""
        runner, child = self.runner(), self.child()
        other = "99999999-9999-4999-8999-999999999999"
        record = self.record(self.clock["t"], session_id=other)
        with mock.patch.object(
                supervisor, "_validated_event",
                side_effect=supervisor.SupervisorError(
                    "hook event belongs to a different session epoch")), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._prove_cap(child, record))
        self.assertEqual([call.args[0]["event"]
                          for call in emit.call_args_list], [])
        self.assertTrue(child.automation)

    def test_the_attribution_test_is_payload_only_and_reverts_safely(self):
        """(f) The field names are provider-controlled — the same fragility
        class as the scoped-pool key. Pinned against the observed shapes, and
        a rename reverts to the old behaviour rather than to something
        worse."""
        self.assertTrue(supervisor._subagent_attributed(
            self.record(0.0)))
        self.assertFalse(supervisor._subagent_attributed(
            self.record(0.0, agent=False)))
        for field in ("agent_id", "agent_type"):
            record = self.record(0.0, agent=False)
            record["payload"][field] = "addb74a7cd4302728"
            self.assertTrue(supervisor._subagent_attributed(record), field)
            # blank and whitespace are not an attribution
            record["payload"][field] = "  "
            self.assertFalse(supervisor._subagent_attributed(record), field)
        self.assertFalse(supervisor._subagent_attributed({}))


class BackgroundAgentLedger(TempDirCase):
    """The parent transcript's own record of what it started — the strongest
    signal, because it does not depend on the agent writing anything. Record
    shapes copied from live sessions."""

    AGENT = "a0fdfb291e702a98b"

    def launch(self, agent_id=None):
        return {"type": "user", "message": {"content": [{
            "type": "tool_result", "tool_use_id": "toolu_x", "content": [{
                "type": "text",
                "text": ("Async agent launched successfully. (This tool "
                         "result is internal metadata — never quote it.)\n"
                         f"agentId: {agent_id or self.AGENT} (internal ID - "
                         "do not mention to user. Use SendMessage with to: "
                         f"'{agent_id or self.AGENT}' to continue this "
                         "agent.)\nThe agent is working in the background.")}]}]}}

    def notification(self, status="completed", agent_id=None):
        # the harness-injected shape, verbatim from real transcripts
        return {"type": "user", "promptSource": "system",
                "origin": {"kind": "task-notification"},
                "message": {"content": (
            "<task-notification>\n"
            f"<task-id>{agent_id or self.AGENT}</task-id>\n"
            "<tool-use-id>toolu_x</tool-use-id>\n"
            f"<status>{status}</status>\n"
            "<summary>Agent \"work\" finished</summary>\n"
            "</task-notification>")}}

    def send_message(self, agent_id=None):
        return {"type": "assistant", "message": {"content": [{
            "type": "tool_use", "id": "toolu_y", "name": "SendMessage",
            "input": {"to": agent_id or self.AGENT, "summary": "more work",
                      "message": "keep going"}}]}}

    ANSWER = {"type": "assistant", "message": {
        "model": "claude-fable-5",
        "content": [{"type": "text", "text": "noted"}]}}

    def test_a_launched_agent_with_no_notification_is_live(self):
        self.assertEqual(supervisor._launched_background_agents(
            [self.launch(), self.ANSWER]), {self.AGENT})

    def test_a_terminal_notification_clears_it(self):
        for status in ("completed", "failed", "killed"):
            self.assertEqual(supervisor._launched_background_agents(
                [self.launch(), self.notification(status), self.ANSWER]),
                set(), status)

    def test_an_unknown_status_is_not_terminal(self):
        # fail closed: an outcome we do not recognise keeps the agent live
        self.assertEqual(supervisor._launched_background_agents(
            [self.launch(), self.notification("running"), self.ANSWER]),
            {self.AGENT})

    def test_a_resumed_agent_is_live_again(self):
        records = [self.launch(), self.notification(), self.send_message(),
                   self.ANSWER]
        self.assertEqual(supervisor._launched_background_agents(records),
                         {self.AGENT})
        records.append(self.notification())
        self.assertEqual(supervisor._launched_background_agents(records), set())

    def test_several_agents_are_tracked_independently(self):
        other = "abcdef1234567890a"
        records = [self.launch(), self.launch(other),
                   self.notification(agent_id=other)]
        self.assertEqual(supervisor._launched_background_agents(records),
                         {self.AGENT})

    def test_a_notification_without_its_launch_never_invents_an_agent(self):
        # a tail can truncate the launch; it must not create a live agent
        self.assertEqual(supervisor._launched_background_agents(
            [self.notification(), self.ANSWER]), set())

    def test_terminated_ids_skip_the_shape_check(self):
        self.assertEqual(
            supervisor._terminated_agents([self.launch(), self.notification()]),
            {self.AGENT})

    # --- only the authoritative record shape may retire an agent ----------

    def quoted_in_tool_result(self, status="completed", agent_id=None):
        """A notification envelope COPIED into another tool's result — the
        exact shape that exists in the fleet today (a Bash tool that cat'd a
        transcript) and the one Codex reproduced as a bypass."""
        return {"type": "user", "message": {"content": [{
            "type": "tool_result", "tool_use_id": "toolu_z", "content": (
                "=== transcript dump ===\n"
                "<task-notification>\n"
                f"<task-id>{agent_id or self.AGENT}</task-id>\n"
                f"<status>{status}</status>\n</task-notification>\n")}]}}

    def test_a_copied_notification_inside_a_tool_result_never_retires(self):
        records = [self.launch(), self.quoted_in_tool_result(), self.ANSWER]
        live, terminated = supervisor._agent_lifecycle(records)
        self.assertEqual(live, {self.AGENT})     # still running
        self.assertEqual(terminated, set())      # and never marked finished

    def test_a_notification_without_the_harness_marker_never_retires(self):
        # same string, same record type, no origin marker -> not authoritative
        forged = {"type": "user", "message": {"content": (
            "<task-notification>\n"
            f"<task-id>{self.AGENT}</task-id>\n"
            "<status>completed</status>\n</task-notification>")}}
        live, terminated = supervisor._agent_lifecycle(
            [self.launch(), forged, self.ANSWER])
        self.assertEqual(live, {self.AGENT})
        self.assertEqual(terminated, set())

    def test_a_wrong_origin_or_block_content_never_retires(self):
        real = self.notification()
        for forged in (
                dict(real, origin={"kind": "user-prompt"}),
                dict(real, type="attachment"),
                dict(real, message={"content": [
                    {"type": "text", "text": real["message"]["content"]}]}),
                dict(real, origin="task-notification")):
            live, _ = supervisor._agent_lifecycle(
                [self.launch(), forged, self.ANSWER])
            self.assertEqual(live, {self.AGENT}, forged.get("origin"))

    def test_assistant_prose_never_launches_or_retires(self):
        prose = {"type": "assistant", "message": {"content": [{
            "type": "text", "text": (
                "Async agent launched successfully — agentId: aprose1234 — "
                "and <task-notification><task-id>" + self.AGENT
                + "</task-id><status>completed</status></task-notification>")}]}}
        live, terminated = supervisor._agent_lifecycle(
            [self.launch(), prose, self.ANSWER])
        self.assertEqual(live, {self.AGENT})     # the prose neither adds...
        self.assertEqual(terminated, set())      # ...nor retires

    # --- the real status vocabulary ---------------------------------------

    def test_stopped_is_terminal_and_resumable(self):
        records = [self.launch(), self.notification("stopped"), self.ANSWER]
        live, terminated = supervisor._agent_lifecycle(records)
        self.assertEqual((live, terminated), (set(), {self.AGENT}))
        # ...and SendMessage puts it back to work, in BOTH sets
        records.append(self.send_message())
        live, terminated = supervisor._agent_lifecycle(records)
        self.assertEqual((live, terminated), ({self.AGENT}, set()))

    def test_unknown_status_is_not_terminal_in_either_helper(self):
        for status in ("running", "queued", "", "COMPLETED_MAYBE"):
            records = [self.launch(), self.notification(status), self.ANSWER]
            live, terminated = supervisor._agent_lifecycle(records)
            self.assertEqual(live, {self.AGENT}, status)
            self.assertEqual(terminated, set(), status)
            # the two helpers must agree — a looser _terminated_agents would
            # silently skip the sidechain shape check for a live agent
            self.assertEqual(supervisor._terminated_agents(records), set())
            self.assertEqual(supervisor._launched_background_agents(records),
                             {self.AGENT})

    def test_every_real_status_is_classified(self):
        # the complete vocabulary observed across the fleet
        self.assertEqual(supervisor.TERMINAL_TASK_STATUS,
                         {"completed", "failed", "killed", "stopped"})


class TranscriptTail(TempDirCase):
    """The poll must not re-parse a whole long session every minute."""

    MODEL = "claude-fable-5-20260701"

    def big(self, model_first=False):
        path = os.path.join(self.temp.name, "big.jsonl")
        assistant = json.dumps({"type": "assistant", "message": {
            "model": self.MODEL, "content": [{"type": "text", "text": "x"}]}})
        filler = json.dumps({"type": "user", "message": {"content": [
            {"type": "text", "text": "f" * 200}]}})
        with open(path, "w", encoding="utf-8") as out:
            if model_first:
                out.write(assistant + "\n")
            for _ in range(400):
                out.write(filler + "\n")
            if not model_first:
                out.write(assistant + "\n")
        return path

    def test_only_the_tail_is_read_and_parsed(self):
        path = self.big()
        with mock.patch.object(supervisor, "TRANSCRIPT_TAIL_BYTES", 4096):
            records, complete, bad = supervisor._transcript_records(path)
            self.assertFalse(complete)
            self.assertFalse(bad)
            self.assertLess(len(records), 401)
            # every parsed record is whole — the boundary record is dropped
            self.assertTrue(all(isinstance(row, dict) for row in records))
            self.assertEqual(supervisor._transcript_model(path), self.MODEL)

    def test_whole_file_fallback_only_when_the_tail_proves_nothing(self):
        path = self.big(model_first=True)
        with mock.patch.object(supervisor, "TRANSCRIPT_TAIL_BYTES", 4096):
            self.assertEqual(supervisor._transcript_model(path), self.MODEL)

    def test_short_transcripts_are_read_whole(self):
        path = self.big()
        records, complete, bad = supervisor._transcript_records(path)
        self.assertTrue(complete)
        self.assertFalse(bad)
        self.assertEqual(len(records), 401)


class CapWaitsForCapacity(TempDirCase):
    """A proven cap with nowhere to go.

    Every failure in the cap-proof chain used to end in _lose_supervision:
    automation off for good, on the capped seat, with the child still alive —
    the one state where it most needs the rotation it just gave up on. When
    the reason is "every seat is capped too", that answer is wrong twice
    over: nothing was disproven, and the condition fixes itself. So a
    capacity refusal HOLDS, bounded, and the session moves the moment a seat
    comes back.
    """

    SID = "44444444-4444-4444-8444-444444444444"
    CAP = "You've hit your 5-hour limit · resets 3pm (UTC)"

    def setUp(self):
        super().setUp()
        self.clock = {"t": time.time()}
        self.source = self.account("source")
        self.target = self.account("target")
        for account in (self.source, self.target):
            os.makedirs(os.path.join(account["home"], "projects"),
                        exist_ok=True)
        registry.save({"schema_version": 1,
                       "accounts": [self.source, self.target]})
        directory = os.path.join(self.source["home"], "projects", "p")
        os.makedirs(directory)
        self.transcript = os.path.join(directory, self.SID + ".jsonl")
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "hi"}]}}) + "\n")
            out.write(json.dumps({"type": "assistant", "message": {
                "model": "claude-fable-5-20260701",
                "content": [{"type": "text", "text": "done"}]}}) + "\n")
        when = time.time() - 600            # quiet: no turn in flight
        os.utime(self.transcript, (when, when))
        self.cwd = os.path.join(self.temp.name, "work")
        os.makedirs(self.cwd)
        self.binding = supervisor.Binding(
            self.SID, self.transcript, self.cwd, "Fable", "2.1",
            self.source["home"], epoch=1)
        for target, value in ((collect, ("AAAA", "BBBB")),):
            patch = mock.patch.object(target, "local_binding",
                                      return_value=value)
            patch.start()
            self.addCleanup(patch.stop)
        which = mock.patch.object(handoff.shutil, "which",
                                  side_effect=lambda name: "/usr/bin/" + name)
        which.start()
        self.addCleanup(which.stop)
        for constant, value in (("CAP_HOLD_SECONDS", 1.0),
                                ("CAP_HOLD_MAX", 3)):
            patch = mock.patch.object(supervisor, constant, value)
            patch.start()
            self.addCleanup(patch.stop)

    # -- fixture ------------------------------------------------------------

    def child(self):
        process = mock.Mock(pid=os.getpid())
        process.poll.return_value = None
        return supervisor.Child(
            process, self.source, 1,
            os.path.join(self.temp.name, "no-such-events.jsonl"), "",
            self.clock["t"] - 60, True, binding=self.binding, session_epoch=1)

    def snapshot(self, source5=100.0, target5=100.0, target7=10.0,
                 target_scoped=None, source_scoped=None, source7=None):
        """Built from the CURRENT clock, the way a real collect would be."""
        captured = int(self.clock["t"]) + 1
        source = usage_row("source", used5=0.0, captured=captured)
        # a dict source5 REPLACES the 5h window, so a test can make the very
        # window that corroborated the cap go expired or malformed mid-hold
        source["windows"]["5h"] = dict(
            source["windows"]["5h"],
            **(source5 if isinstance(source5, dict)
               else {"used_percent": source5}))
        # source7 the same way, so the OTHER account-wide window can cross
        # mid-hold — the shape that shares the recorded cooldown key
        if source7 is not None:
            source["windows"]["7d"] = dict(
                source["windows"]["7d"],
                **(source7 if isinstance(source7, dict)
                   else {"used_percent": source7}))
        target = usage_row("target", used5=target5, used7=target7,
                           captured=captured)
        for row, scoped in ((source, source_scoped), (target, target_scoped)):
            if scoped is not None:
                row["windows"]["scoped:Fable"] = {
                    "used_percent": scoped, "resets_at": captured + 6 * 86400,
                    "window_minutes": 10080}
        return {"run_started": captured, "generated": captured,
                "accounts": [source, target]}

    def runner(self, snapshots):
        """`snapshots` is a list of (source5, target5) the collects walk
        through, the last one repeating for every further attempt."""
        state = {"index": 0}

        def collect_fn(quiet=True):
            index = min(state["index"], len(snapshots) - 1)
            state["index"] += 1
            return self.snapshot(*snapshots[index])

        def sleep(seconds):
            self.clock["t"] += max(float(seconds), 0.0)

        return supervisor.Supervisor(
            "fable", [], self.source, collect_fn=collect_fn,
            now=lambda: self.clock["t"], sleep=sleep, popen=mock.Mock())

    CREDITS = ("You're out of usage credits. Run /usage-credits to keep "
               "using Fable 5")

    def proof(self, message=None):
        return supervisor.CapProof(
            {"received_at": self.clock["t"] - 30}, message or self.CAP,
            "fable", self.SID, self.transcript, 1,
            handoff._transcript_stat(self.transcript))

    def monitor(self, runner, child, proof, polls=2):
        """Drive _monitor for `polls` iterations, then let the child exit.

        _handle_events is modelled exactly as the real one behaves: the hook
        journal delivers the cap ONCE, and every later poll echoes back
        whatever proof it was handed (so a proof the loop discards stays
        discarded — nothing re-delivers it)."""
        codes = [None] * (polls - 1) + [0]
        child.process.poll.side_effect = lambda: codes.pop(0)
        delivered = {"done": False}

        def handle_events(_child, _pending_id, current=None):
            if delivered["done"]:
                return current
            delivered["done"] = True
            return proof

        with mock.patch.object(runner, "_handle_events",
                               side_effect=handle_events), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()) as err:
            outcome = runner._monitor(child)
        return outcome, [call.args[0] for call in emit.call_args_list], err

    def ledger(self):
        path = os.path.join(paths.state_dir(), "handoffs.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as source:
            return [json.loads(line) for line in source if line.strip()]

    # -- who a capped session may be moved ONTO ------------------------------

    def test_a_seat_at_99_percent_is_no_destination_for_a_real_cap(self):
        # The routing gate rejects 100%, critical, reserve and unreadable —
        # and nothing else — so this seat was a legal target for a proven
        # cap: a handoff, a restart and a third of the loop budget spent to
        # arrive at the same wall. The preemptive path had a fitness rule;
        # the cap-reactive path, which is the one that MUST move, did not.
        runner, child = self.runner([(100.0, 99.0)]), self.child()
        with self.assertRaises(supervisor.CapacityHold) as caught:
            runner._preflight(child, self.proof())
        self.assertIn("target (5h at 99%)", str(caught.exception))
        self.assertEqual(self.ledger(), [])          # nothing was admitted

    def test_a_capped_source_is_not_picky_about_a_merely_busy_seat(self):
        # and the rule must not overshoot: no margin here. The source is
        # already refusing, so 96% of a five-hour window beats nothing —
        # demanding the preemptive margin would strand a dead session.
        runner, child = self.runner([(100.0, 96.0)]), self.child()
        self.assertEqual(
            runner._preflight(child, self.proof()).target["name"], "target")

    def test_a_busy_weekly_seat_is_still_worth_moving_to(self):
        # 97% of a five-hour window is nine minutes; 97% of a week is most of
        # a working day, so the weekly ceiling is its own, later number
        runner, child = self.runner([(100.0, 10.0, 98.0)]), self.child()
        self.assertEqual(
            runner._preflight(child, self.proof()).target["name"], "target")

    def test_a_weekly_window_at_the_wall_is_not_a_destination(self):
        runner, child = self.runner([(100.0, 10.0, 99.5)]), self.child()
        with self.assertRaises(supervisor.CapacityHold) as caught:
            runner._preflight(child, self.proof())
        self.assertIn("target (7d at 99.5%)", str(caught.exception))

    def test_a_spent_scoped_weekly_seat_is_not_a_destination_either(self):
        # The ladder is off here so the FABLE gate is the only thing speaking:
        # a seat whose Fable pool is spent must never be picked to run Fable,
        # whatever the fallback later does with that refusal. What happens
        # with the ladder ON is CapFamilyDowngrade's subject, and it depends
        # on this refusal being real.
        runner, child = self.runner([(100.0, 10.0, 10.0, 99.5)]), self.child()
        with mock.patch.object(supervisor, "FAMILY_FALLBACK_ENABLED", False):
            with self.assertRaises(supervisor.CapacityHold) as caught:
                runner._preflight(child, self.proof())
        self.assertIn("target (scoped:fable at 99.5%)", str(caught.exception))

    def test_a_huge_transcript_is_gated_on_opus_through_the_REAL_preflight(self):
        """_preflight must hand _cap_target the transcript path.

        Every other test of the fit bound calls `_cap_target` directly, and
        every test that goes through `_preflight` uses a transcript small
        enough for the bound to be a no-op — so the one argument that carries
        the invariant across the seam (`proof.transcript_path`) was pinned by
        nothing. Drop it and this fleet gates a FABLE seat while the successor
        launches opus[1m] on it: one pool checked, another spent.

        Note the fleet here is HEALTHY for Fable — the target's Fable pool is
        fine. Fable is refused purely because a 500k conversation cannot live
        there, which is what makes this test discriminate."""
        with open(self.transcript, "a", encoding="utf-8") as out:
            out.write(json.dumps(usage_record(500_000)) + "\n")
        when = time.time() - 600          # quiet again after the append
        os.utime(self.transcript, (when, when))
        runner, child = self.runner([(100.0, 10.0)]), self.child()
        with redirect_stderr(io.StringIO()) as errors:
            plan = runner._preflight(child, self.proof())
        self.assertEqual(plan.target["name"], "target")
        self.assertEqual((plan.family, plan.resume_family), ("fable", "opus"))
        self.assertIn("only fits the 1M window", errors.getvalue())
        # and the successor really is launched on that gated family
        argv, forced = supervisor._resume_argv_for(plan, "")
        self.assertEqual(forced, "opus[1m]")
        self.assertEqual(supervisor._family_or_blank(
            supervisor._model_flag(argv)), plan.resume_family)

    def test_a_spent_scoped_seat_is_still_a_destination_for_another_family(self):
        # the same fleet with the ladder ON: Fable is walled on the only other
        # seat, so the session moves there on OPUS rather than sitting still
        runner, child = self.runner([(100.0, 10.0, 10.0, 99.5)]), self.child()
        with redirect_stderr(io.StringIO()) as errors:
            plan = runner._preflight(child, self.proof())
        self.assertEqual(plan.target["name"], "target")
        self.assertEqual((plan.family, plan.resume_family), ("fable", "opus"))
        # the cooldown still cools the pool that CAPPED, not the one it moved to
        self.assertEqual(plan.cooldown_scope.get("key"), "source:*")
        self.assertIn("moving this session to opus", errors.getvalue())

    # -- the hold itself ----------------------------------------------------

    def test_no_seat_anywhere_raises_capacity_not_a_generic_refusal(self):
        runner, child = self.runner([(100.0, 100.0)]), self.child()
        with self.assertRaises(supervisor.CapacityHold) as caught:
            runner._preflight(child, self.proof())
        self.assertIn("no seat has headroom worth moving to",
                      str(caught.exception))
        # and it names each seat and why — this text is the cap_held reason
        self.assertIn("target (5h at 100%)", str(caught.exception))
        # and it is a SupervisorError, so nothing that catches the base class
        # (a caller that has not been taught about holds) changes behaviour
        self.assertIsInstance(caught.exception, supervisor.SupervisorError)

    def test_a_capped_fleet_holds_the_child_instead_of_disarming_it(self):
        runner, child = self.runner([(100.0, 100.0)]), self.child()
        outcome, events, err = self.monitor(runner, child, self.proof())
        self.assertEqual(outcome, 0)
        self.assertTrue(child.automation)
        self.assertEqual(child.cap_hold_attempts, 1)
        self.assertEqual([event["event"] for event in events], ["cap_held"])
        self.assertIn("waiting for capacity", err.getvalue())
        self.assertEqual(self.ledger(), [])

    def test_the_session_moves_the_moment_a_seat_comes_back(self):
        # the whole point of holding: nobody is watching a percentage at 3am
        runner, child = self.runner([(100.0, 100.0), (100.0, 5.0)]), self.child()
        relaunch = {}

        def stop(child, plan, proof):
            relaunch["plan"] = plan
            return supervisor.Relaunch(plan.target, [], plan.cwd, True,
                                       plan.handoff_id, plan)

        with mock.patch.object(runner, "_stop_and_commit", side_effect=stop):
            outcome, events, _err = self.monitor(
                runner, child, self.proof(), polls=8)
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.account["name"], "target")
        self.assertEqual(relaunch["plan"].target["name"], "target")
        self.assertEqual([event["event"] for event in events], ["cap_held"])
        self.assertEqual(child.cap_hold_attempts, 0)   # cleared on admission

    def test_the_hold_is_bounded_and_ends_in_the_same_disarm(self):
        runner, child = self.runner([(100.0, 100.0)]), self.child()
        outcome, events, err = self.monitor(
            runner, child, self.proof(), polls=40)
        self.assertEqual(outcome, 0)
        self.assertFalse(child.automation)
        self.assertEqual([event["event"] for event in events],
                         ["cap_held", "supervision_lost"])
        self.assertIn("no seat came free", err.getvalue())
        self.assertIn("automatic handoff disabled", err.getvalue())

    def test_zero_budget_restores_the_old_immediate_disarm(self):
        with mock.patch.object(supervisor, "CAP_HOLD_MAX", 0):
            runner, child = self.runner([(100.0, 100.0)]), self.child()
            outcome, events, _err = self.monitor(runner, child, self.proof())
        self.assertEqual(outcome, 0)
        self.assertFalse(child.automation)
        self.assertEqual([event["event"] for event in events],
                         ["supervision_lost"])

    def test_a_window_that_heals_first_ends_the_hold_still_armed(self):
        # every seat capped, then the SOURCE's own window resets: there is
        # nothing left to rotate away from and no reason to disarm
        runner, child = self.runner(
            [(100.0, 100.0), (4.0, 100.0)]), self.child()
        outcome, events, err = self.monitor(
            runner, child, self.proof(), polls=8)
        self.assertEqual(outcome, 0)
        self.assertTrue(child.automation)
        self.assertEqual([event["event"] for event in events],
                         ["cap_held", "cap_cleared"])
        self.assertIn("the seat is usable again", err.getvalue())
        self.assertEqual(child.cap_hold_attempts, 0)

    def test_a_failed_collect_holds_rather_than_costing_the_automation(self):
        # one network blip on the single collect after a cap used to disarm a
        # live session permanently; it is "no information", not a refutation
        runner, child = self.runner([(100.0, 5.0)]), self.child()
        runner.collect_fn = mock.Mock(side_effect=OSError("network down"))
        outcome, events, err = self.monitor(runner, child, self.proof())
        self.assertEqual(outcome, 0)
        self.assertTrue(child.automation)
        self.assertEqual([event["event"] for event in events], ["cap_held"])
        self.assertIn("fresh usage collect failed", err.getvalue())

    # -- only the window that corroborated it may declare it over ------------

    def scoped_hold(self, second):
        """A held SCOPED weekly cap, then one more snapshot. Returns the
        second attempt's outcome.

        The first snapshot walls the target ACCOUNT-WIDE (5h at 100%), not
        just its Fable pool: these tests are about the hold-and-recheck
        reasoning, and a target with only its Fable pool spent is no longer a
        hold at all — the ladder downgrades to it (CapFamilyDowngrade). An
        account-wide wall is the fleet state that genuinely has nowhere to
        go, which is the state each of these tests means to start from."""
        runner = self.runner([(10.0, 100.0, 10.0, 100.0, 100.0), second])
        child, proof = self.child(), self.proof(self.CREDITS)
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(supervisor.CapacityHold):
                runner._preflight(child, proof)
            self.assertEqual(child.cap_scope_window, "scoped:fable")
            try:
                return runner._preflight(
                    child, proof, held=child.cap_scope_window), child
            except supervisor.SupervisorError as error:
                return error, child

    def test_a_window_that_merely_vanished_is_not_a_reset(self):
        # the hold remembered only THAT something corroborated the cap, so a
        # snapshot that simply omitted the scoped window read as "it reset":
        # a good proof discarded on no evidence, with a healthy seat unused
        outcome, child = self.scoped_hold((10.0, 10.0, 10.0, 5.0, None))
        self.assertIsInstance(outcome, supervisor.CapacityHold)
        self.assertIn("scoped:fable window is not readable",
                      str(outcome))
        self.assertTrue(child.automation)
        self.assertEqual(child.cap_scope_window, "scoped:fable")

    def test_an_unreadable_window_mid_hold_holds_and_stays_armed(self):
        # THE case the wait was built for, and it was defeated by ordering:
        # the source-binding gate runs before any of the cap-scope reasoning,
        # so an expired or malformed corroborating window raised a plain
        # SupervisorError and disarmed the child — on the dead seat, exactly
        # like the bug the wait replaced. Driven through _monitor, because
        # that is where the disarm lived.
        for bad in ({"used_percent": 100.0, "freshness": "expired_observation"},
                    {"used_percent": "?"},
                    {"used_percent": 100.0, "resets_at": None}):
            runner = self.runner([(100.0, 100.0), (bad, 5.0)])
            child = self.child()
            outcome, events, err = self.monitor(
                runner, child, self.proof(), polls=8)
            self.assertEqual(outcome, 0, bad)
            self.assertTrue(child.automation, bad)
            self.assertNotIn("supervision_lost",
                             [event["event"] for event in events], bad)
            self.assertEqual({event["event"] for event in events},
                             {"cap_held"}, bad)
            self.assertIn("holding the proof rather than", err.getvalue())
            # and the proof it is holding is untouched
            self.assertEqual(child.cap_scope_window, "5h", bad)

    UNREADABLE_5H = {"used_percent": 100.0, "freshness": "expired_observation"}

    def test_the_same_unreadable_window_still_disarms_on_a_first_look(self):
        # the hold is for a cap already corroborated once; with nothing
        # corroborated there is nothing to wait on, and the fail-closed
        # first look is unchanged
        runner = self.runner(
            [({"used_percent": 100.0, "freshness": "expired_observation"},
              5.0)])
        child = self.child()
        outcome, events, _err = self.monitor(runner, child, self.proof())
        self.assertEqual(outcome, 0)
        self.assertFalse(child.automation)
        self.assertEqual([event["event"] for event in events],
                         ["supervision_lost"])

    def test_zero_budget_restores_the_immediate_first_look_disarm(self):
        # and the documented kill switch still means what it says: with no
        # budget to spend there is no hold to take, unreadable or not
        with mock.patch.object(supervisor, "CAP_HOLD_MAX", 0):
            runner = self.runner([(self.UNREADABLE_5H, 5.0)])
            child = self.child()
            outcome, events, _err = self.monitor(runner, child, self.proof())
        self.assertEqual(outcome, 0)
        self.assertFalse(child.automation)
        self.assertEqual([event["event"] for event in events],
                         ["supervision_lost"])

    def test_the_corroborating_window_reading_low_does_clear_it(self):
        outcome, _child = self.scoped_hold((10.0, 10.0, 10.0, 5.0, 4.0))
        self.assertIsInstance(outcome, supervisor.CapCleared)
        self.assertIn("scoped:fable window is back to 4%", str(outcome))

    def test_a_held_scoped_cap_moves_once_a_seat_frees(self):
        outcome, _child = self.scoped_hold((10.0, 10.0, 10.0, 5.0, 100.0))
        self.assertEqual(outcome.target["name"], "target")

    GENERIC = "You've hit your usage limit"

    def wall_hold(self, second, message=None):
        """A held cap recorded on the SCOPED pool under a generic phrase, so
        a later snapshot can legitimately resolve to a different key."""
        runner = self.runner([(10.0, 100.0, 10.0, None, 100.0), second])
        child, proof = self.child(), self.proof(message or self.GENERIC)
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(supervisor.CapacityHold):
                runner._preflight(child, proof)
            self.assertEqual((child.cap_scope_key, child.cap_scope_window),
                             ("source:fable", "scoped:fable"))
            try:
                return runner._preflight(
                    child, proof, held=child.cap_scope_window), child
            except supervisor.SupervisorError as error:
                return error, child

    def test_a_recorded_window_still_at_the_wall_rotates(self):
        """The recorded scope had two outcomes and needed three.

        Below 99 cleared it; ANYTHING else was reported as "not readable" and
        held. So a recorded window sitting at a legitimate, perfectly
        readable 100% could never proceed — the session waited out the whole
        hold budget with a fit seat in front of it and then disarmed on the
        capped account, which is the exact failure the hold was built to
        prevent.

        Here the Fable pool the hold recorded is still at 100% and the 5h
        window has filled behind it, so fresh usage resolves to `source:*`
        while the recorded key is `source:fable`. The recorded window is
        still provably spent and a seat is free: move."""
        outcome, child = self.wall_hold((100.0, 5.0, 10.0, None, 100.0))
        self.assertNotIsInstance(outcome, supervisor.SupervisorError)
        self.assertEqual(outcome.target["name"], "target")
        # ...on the scope it CORROBORATED, never the one it just read: the
        # immutability of the recorded scope is what stops a hold quietly
        # turning into a 5h account-wide handoff nobody proved.
        self.assertEqual((child.cap_scope_key, child.cap_scope_window),
                         ("source:fable", "scoped:fable"))
        self.assertEqual(outcome.cooldown_scope["key"], "source:fable")
        self.assertEqual(outcome.cooldown_scope["window"], "scoped:fable")
        self.assertIs(outcome.cooldown_scope["account_wide"], False)
        self.assertEqual(outcome.cooldown_scope["used_percent"], 100.0)
        self.assertGreater(outcome.cooldown_scope["reset"], self.clock["t"])

    def test_a_recorded_wall_with_no_seat_still_holds(self):
        """Rotating needs a destination as much as it ever did."""
        outcome, _child = self.wall_hold((100.0, 100.0, 10.0, None, 100.0))
        self.assertIsInstance(outcome, supervisor.CapacityHold)

    def test_a_recorded_wall_that_went_unreadable_still_holds(self):
        """Only a window that can be READ at the wall may rotate. An expired
        observation of it proves nothing and keeps the proof."""
        outcome, _child = self.wall_hold((100.0, 5.0, 10.0, None, None))
        self.assertIsInstance(outcome, supervisor.CapacityHold)
        self.assertIn("not readable in fresh usage", str(outcome))

    def test_the_wall_rotation_has_a_kill_switch(self):
        with mock.patch.object(supervisor, "CAP_ROTATE_AT_WALL", False):
            outcome, _child = self.wall_hold((100.0, 5.0, 10.0, None, 100.0))
        self.assertIsInstance(outcome, supervisor.CapacityHold)
        # and the hold says WHY: the window read fine, rotation is off — it
        # used to claim "not readable" about a reading it had just made
        self.assertIn("rotation at the wall is disabled", str(outcome))

    def test_a_proof_may_only_ever_admit_the_cap_it_recorded(self):
        # the scoped pool it was holding for resets to 4% while the 5h window
        # fills. That is a DIFFERENT cap: reading it as this one cooled a
        # window nobody corroborated and quietly rewrote what the hold was
        # for. Only the recorded scope may speak, and it says it is over.
        outcome, child = self.scoped_hold((100.0, 10.0, 10.0, 5.0, 4.0))
        self.assertIsInstance(outcome, supervisor.CapCleared)
        self.assertIn("scoped:fable window is back to 4%", str(outcome))
        self.assertEqual((child.cap_scope_key, child.cap_scope_window),
                         ("source:fable", "scoped:fable"))

    def account_hold(self, second):
        """A held ACCOUNT-WIDE cap recorded on the 5h window under a generic
        phrase, so a later snapshot can resolve to the 7d window behind the
        SAME `source:*` cooldown key. Returns the second attempt's outcome."""
        runner = self.runner([(100.0, 100.0), second])
        child, proof = self.child(), self.proof(self.GENERIC)
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(supervisor.CapacityHold):
                runner._preflight(child, proof)
            self.assertEqual((child.cap_scope_key, child.cap_scope_window),
                             ("source:*", "5h"))
            try:
                return runner._preflight(
                    child, proof, held=child.cap_scope_window), child
            except supervisor.SupervisorError as error:
                return error, child

    def test_a_shared_key_does_not_relabel_a_recorded_window_that_reset(self):
        """Both account-wide windows share `source:*`, so a matching key is
        not a matching cap. The recorded 5h window reset to 4% while the 7d
        filled behind it: the retry resolved the same key, took the relabel
        path, and produced a live handoff cooling seven days nobody
        corroborated — instead of the CapCleared the reading proves."""
        outcome, child = self.account_hold(
            (4.0, 5.0, 10.0, None, None, 100.0))
        self.assertIsInstance(outcome, supervisor.CapCleared)
        self.assertIn("5h window is back to 4%", str(outcome))
        self.assertEqual((child.cap_scope_key, child.cap_scope_window),
                         ("source:*", "5h"))
        self.assertEqual(self.ledger(), [])          # no handoff was admitted

    def test_the_shared_key_reset_clears_with_rotation_disabled_too(self):
        """The relabel path predates the wall-rotation switch and was never
        gated by it — so neither is the correction. A recorded window that
        provably reset is CapCleared with the switch in every position."""
        with mock.patch.object(supervisor, "CAP_ROTATE_AT_WALL", False):
            outcome, _child = self.account_hold(
                (4.0, 5.0, 10.0, None, None, 100.0))
        self.assertIsInstance(outcome, supervisor.CapCleared)

    def test_the_switch_pins_the_shared_key_relabel_too(self):
        """Round 5: the switch's contract is the README's, not the branch
        history's — a recorded window still readable and still at the wall
        KEEPS WAITING under HEADROOM_CAP_ROTATE_AT_WALL=0, whichever key
        fresh usage now prefers. The first fix exempted the same-key relabel
        because it predated the switch, and a session the operator asked to
        pin moved anyway."""
        with mock.patch.object(supervisor, "CAP_ROTATE_AT_WALL", False):
            outcome, child = self.account_hold(
                (100.0, 5.0, 10.0, None, None, 100.0))
        self.assertIsInstance(outcome, supervisor.CapacityHold)
        self.assertIn("rotation at the wall is disabled", str(outcome))
        self.assertEqual((child.cap_scope_key, child.cap_scope_window),
                         ("source:*", "5h"))
        self.assertEqual(self.ledger(), [])

    def test_a_shared_key_relabel_still_stands_when_both_windows_hold(self):
        """The round-2 agreement is untouched: when the recorded 5h window is
        STILL at the wall and the 7d crossed too, the account-wide scope
        legitimately relabels onto the window that now binds — that is not a
        scope change, and the recorded proof does not move."""
        outcome, child = self.account_hold(
            (100.0, 5.0, 10.0, None, None, 100.0))
        self.assertNotIsInstance(outcome, supervisor.SupervisorError)
        self.assertEqual(outcome.target["name"], "target")
        self.assertEqual(outcome.cooldown_scope["key"], "source:*")
        self.assertEqual(outcome.cooldown_scope["window"], "7d")
        self.assertIs(outcome.cooldown_scope["account_wide"], True)
        # the RECORD stays what was corroborated at the first look
        self.assertEqual((child.cap_scope_key, child.cap_scope_window),
                         ("source:*", "5h"))

    def test_a_shared_key_with_the_recorded_window_unreadable_holds(self):
        """Same key, the 7d provably at the wall, and the recorded 5h window
        unreadable: that proves nothing about the cap we held for, so the
        proof is kept — no relabel proceeds on the other window's reading
        alone, and no disarm. (The source-binding gate raises this hold for
        an account-wide window, since 5h is mandatory in every bound row; the
        scope interrogation's own unreadable arm answers the same way for a
        recorded window the row can be bound without, like a vanished scoped
        pool — test_a_window_that_merely_vanished_is_not_a_reset.)"""
        outcome, child = self.account_hold(
            ({"used_percent": 100.0, "freshness": "expired_observation"},
             5.0, 10.0, None, None, 100.0))
        self.assertIsInstance(outcome, supervisor.CapacityHold)
        self.assertEqual((child.cap_scope_key, child.cap_scope_window),
                         ("source:*", "5h"))

    def test_an_uncorroborated_cap_still_disarms_on_the_first_look(self):
        # NOT a hold: the hook says capped and fresh usage says otherwise, on
        # the first look. That contradiction is exactly what fail-closed is
        # for, and it disarms today as it always has.
        runner, child = self.runner([(4.0, 4.0)]), self.child()
        outcome, events, err = self.monitor(runner, child, self.proof())
        self.assertEqual(outcome, 0)
        self.assertFalse(child.automation)
        self.assertEqual([event["event"] for event in events],
                         ["supervision_lost"])
        self.assertIn("below 99%", err.getvalue())

    def test_a_deliberate_human_stop_is_never_revived(self):
        runner, child = self.runner([(100.0, 100.0)]), self.child()
        child.automation = False              # e.g. a shutdown signal
        outcome, events, _err = self.monitor(runner, child, self.proof())
        self.assertEqual(outcome, 0)
        self.assertEqual(child.cap_hold_attempts, 0)
        self.assertEqual(events, [])
        self.assertEqual(self.ledger(), [])

    def test_a_second_cap_gets_its_own_budget_and_no_inherited_trust(self):
        runner, child = self.runner([(100.0, 100.0)]), self.child()
        first = self.proof()
        with mock.patch.object(runner, "_handle_events", return_value=first), \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            child.process.poll.side_effect = [None, 0]
            runner._monitor(child)
        self.assertEqual(child.cap_hold_attempts, 1)
        self.assertEqual(child.cap_scope_window, "5h")
        later = dataclasses.replace(
            first, event={"received_at": self.clock["t"]})
        runner._cap_hold_sync(child, later)
        self.assertEqual(child.cap_hold_attempts, 0)
        self.assertEqual(child.cap_scope_window, "")

    # -- a collector that never RAN is not a collector that refuted us -------
    #
    # collect.run_collect takes the collection lock nonblocking and, on
    # contention, prints "collector already running; skipped" and returns the
    # PREVIOUS snapshot from disk — no exception, no sentinel. _fresh_collect
    # only ever caught exceptions, so a skip read as success, the stale
    # run_started produced "collect did not start after the cap event", and
    # that walked into _lose_supervision: automation off, permanently, on a
    # capped seat, because a second collector happened to be mid-run. Three
    # serve daemons and ~7 supervisors drive run_collect on this box, so the
    # window is open several seconds out of every minute.

    def hold_collect_lock(self):
        """Hold `collect.lock` the way a second, live collector does."""
        path = paths.collect_lock_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        handle = open(path, "a+")
        self.addCleanup(handle.close)
        self.assertTrue(collect.locks.exclusive(handle, blocking=False))
        self.addCleanup(collect.locks.unlock, handle)
        return handle

    def stale_on_disk(self):
        """The previous run's snapshot, which is exactly what a skipped
        run_collect hands back."""
        old = int(self.clock["t"]) - 3600
        snapshot = self.snapshot(100.0, 5.0)
        snapshot["run_started"] = snapshot["generated"] = old
        paths.write_json_atomic(paths.private_snapshot_path(), snapshot)
        return snapshot

    def test_a_contended_collect_holds_the_proof_instead_of_disarming(self):
        """(a) The live case, through the REAL collector.

        A healthy seat is sitting right there (target at 5%), so the only
        thing between this session and its rotation is a lock another
        collector holds."""
        self.hold_collect_lock()
        self.stale_on_disk()
        runner, child = self.runner([(100.0, 5.0)]), self.child()
        runner.collect_fn = collect.run_collect       # the real one
        with self.assertRaises(supervisor.CapacityHold) as caught:
            runner._preflight(child, self.proof(), held=False)
        self.assertIn("skipped", str(caught.exception))
        self.assertTrue(child.automation)

    def test_a_contended_collect_keeps_the_child_armed_through_monitor(self):
        """...and the disarm this closes lived in _monitor, so drive it."""
        self.hold_collect_lock()
        self.stale_on_disk()
        runner, child = self.runner([(100.0, 5.0)]), self.child()
        runner.collect_fn = collect.run_collect
        outcome, events, err = self.monitor(runner, child, self.proof())
        self.assertEqual(outcome, 0)
        self.assertTrue(child.automation)
        self.assertEqual([event["event"] for event in events], ["cap_held"])
        self.assertNotIn("collect did not start", err.getvalue())

    def test_a_skipped_collect_is_retried_and_the_fresh_one_wins(self):
        """(b) The skip is INFERRED from run_started — run_collect has no
        sentinel and changing its return contract would touch every caller.
        So pin the inference at both ends: N stale reads then a fresh one
        must cost N+1 calls and return the FRESH snapshot."""
        stale = self.snapshot(100.0, 5.0)
        stale["run_started"] = stale["generated"] = int(self.clock["t"]) - 3600
        calls = {"n": 0}

        def collect_fn(quiet=True):
            calls["n"] += 1
            return stale if calls["n"] <= 2 else self.snapshot(100.0, 5.0)

        runner = self.runner([(100.0, 5.0)])
        runner.collect_fn = collect_fn
        snapshot, started = runner._fresh_collect(self.clock["t"] - 30)
        self.assertEqual(calls["n"], 3)
        self.assertGreaterEqual(snapshot["run_started"], int(started))

    def test_a_collector_that_never_frees_the_lock_holds_after_its_budget(self):
        """(b) continued: the retries are bounded, and what they end in is a
        HOLD — the child keeps running and keeps its automation."""
        stale = self.snapshot(100.0, 5.0)
        stale["run_started"] = stale["generated"] = int(self.clock["t"]) - 3600
        calls = {"n": 0}

        def collect_fn(quiet=True):
            calls["n"] += 1
            return stale

        runner = self.runner([(100.0, 5.0)])
        runner.collect_fn = collect_fn
        with self.assertRaises(supervisor.CapacityHold) as caught:
            runner._fresh_collect(self.clock["t"] - 30)
        self.assertIn("skipped", str(caught.exception))
        self.assertEqual(calls["n"],
                         supervisor.COLLECT_CONTENTION_RETRIES + 1)

    def test_a_readable_snapshot_below_99_still_disarms_on_a_first_look(self):
        """(c) THE regression. Ungating the hold escape from `held` must move
        the UNREADABLE class and nothing else: a fresh, readable snapshot
        that says 4% is a contradiction of the hook, not an absence of
        evidence, and a proof nobody can corroborate still disarms."""
        runner, child = self.runner([(4.0, 4.0)]), self.child()
        with self.assertRaises(supervisor.SupervisorError) as caught:
            runner._preflight(child, self.proof(), held=False)
        self.assertNotIsInstance(caught.exception, supervisor.CapacityHold)
        self.assertIn("below 99%", str(caught.exception))

    def test_a_trust_refusal_still_disarms_on_a_first_look(self):
        """(d) An identity that moved under us is not something waiting
        fixes, and it is deliberately outside _source_reading_unavailable.
        Ungating the escape must not widen that list by accident."""
        runner, child = self.runner([(100.0, 5.0)]), self.child()
        base = runner.collect_fn

        def moved_identity(quiet=True):
            snapshot = base(quiet=quiet)
            snapshot["accounts"][0]["identity"] = dict(
                IDENTITY, account_fingerprint="MOVED")
            return snapshot

        runner.collect_fn = moved_identity
        with self.assertRaises(supervisor.SupervisorError) as caught:
            runner._preflight(child, self.proof(), held=False)
        self.assertNotIsInstance(caught.exception, supervisor.CapacityHold)
        self.assertEqual(str(caught.exception),
                         "slot identity changed since snapshot — recollect")

    def test_a_pool_renamed_mid_hold_holds_instead_of_disarming(self):
        """P4 case (c) — the disarm that patch closes, at this end.

        A held cap whose scoped pool comes back under a name nothing maps
        used to reach `route.cap_scope() is None` and, before that, a
        block_reason of None that let the row look perfectly healthy. Now the
        row itself says "not recognised", which is missing evidence, so the
        proof holds and the child keeps its automation."""
        runner, child = self.runner([(10.0, 100.0, 10.0, 100.0, 100.0)]), \
            self.child()
        base = runner.collect_fn

        def renamed(quiet=True):
            snapshot = base(quiet=quiet)
            for row in snapshot["accounts"]:
                windows = row["windows"]
                if "scoped:Fable" in windows:
                    windows["scoped:Frontier"] = windows.pop("scoped:Fable")
            return snapshot

        proof = self.proof(self.CREDITS)
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(supervisor.CapacityHold):
                runner._preflight(child, proof)
            self.assertEqual(child.cap_scope_window, "scoped:fable")
            runner.collect_fn = renamed
            with self.assertRaises(supervisor.CapacityHold) as caught:
                runner._preflight(child, proof, held=child.cap_scope_window)
        self.assertIn("not recognised", str(caught.exception))
        self.assertTrue(child.automation)

    def test_the_hold_announcement_fires_once_per_distinct_reason(self):
        """(e) A hold that now fires on the FIRST look must not turn into a
        per-poll siren: one voice per distinct reason, and a new reason is a
        new voice."""
        runner, child = self.runner([(100.0, 5.0)]), self.child()
        with mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()) as err:
            for _ in range(3):
                self.assertTrue(runner._cap_hold(
                    child, supervisor.CapacityHold("lock is held")))
        self.assertEqual([call.args[0]["event"] for call in emit.call_args_list],
                         ["cap_held"])
        self.assertEqual(err.getvalue().count("waiting for capacity"), 1)
        child.cap_hold_attempts = 0
        with mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            runner._cap_hold(child, supervisor.CapacityHold("no seat at all"))
        self.assertEqual(len(emit.call_args_list), 1)


class PreemptiveRotation(TempDirCase):
    """The whole preemptive path against real transcripts, a real registry and
    the real handoff ledger — only the child process and the stop are faked."""

    SID = "33333333-3333-4333-8333-333333333333"

    def setUp(self):
        super().setUp()
        self.clock = {"t": time.time()}
        self.source = self.account("source")
        self.target = self.account("target")
        for account in (self.source, self.target):
            os.makedirs(os.path.join(account["home"], "projects"),
                        exist_ok=True)
        registry.save({"schema_version": 1,
                       "accounts": [self.source, self.target]})
        directory = os.path.join(self.source["home"], "projects", "p")
        os.makedirs(directory)
        self.transcript = os.path.join(directory, self.SID + ".jsonl")
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "hi"}]}}) + "\n")
            out.write(json.dumps({"type": "assistant", "message": {
                "model": "claude-fable-5-20260701",
                "content": [{"type": "text", "text": "done"}]}}) + "\n")
        self.idle(seconds=600)
        self.cwd = os.path.join(self.temp.name, "work")
        os.makedirs(self.cwd)
        binding = supervisor.Binding(self.SID, self.transcript, self.cwd,
                                     "Fable", "2.1", self.source["home"],
                                     epoch=1)
        process = mock.Mock(pid=os.getpid())
        process.poll.return_value = None
        self.child = supervisor.Child(
            process, self.source, 1,
            os.path.join(self.temp.name, "no-such-events.jsonl"), "",
            self.clock["t"] - 60, True, binding=binding, session_epoch=1)
        patcher = mock.patch.object(collect, "local_binding",
                                    return_value=("AAAA", "BBBB"))
        patcher.start()
        self.addCleanup(patcher.stop)
        which = mock.patch.object(handoff.shutil, "which",
                                  side_effect=lambda name: "/usr/bin/" + name)
        which.start()
        self.addCleanup(which.stop)
        for constant, value in (("PREEMPT_IDLE_SECONDS", 5.0),
                                ("PREEMPT_POLL_SECONDS", 60.0),
                                ("PREEMPT_BACKOFF_SECONDS", 300.0),
                                ("PREEMPT_DECISION_TTL", 120.0)):
            patch = mock.patch.object(supervisor, constant, value)
            patch.start()
            self.addCleanup(patch.stop)

    def idle(self, seconds=600):
        """Age the transcript so it reads as an idle (no active turn) child."""
        when = time.time() - seconds
        os.utime(self.transcript, (when, when))

    def usage(self, scoped=94.0, seven=20.0, target_ok=True, five=10.0,
              target_five=10.0):
        captured = int(self.clock["t"])
        source = usage_row("source", used5=five, used7=seven, captured=captured)
        source["windows"]["scoped:Fable"] = {
            "used_percent": scoped, "resets_at": captured + 6 * 86400,
            "window_minutes": 10080}
        target = usage_row("target", used5=target_five, captured=captured)
        if not target_ok:
            target["ok"] = False
            target["error_code"] = "collect_failed"
        return {"run_started": captured, "generated": captured,
                "accounts": [source, target]}

    def runner(self, snapshot=None):
        snapshot = self.usage() if snapshot is None else snapshot
        return supervisor.Supervisor(
            "fable", [], self.source, collect_fn=lambda quiet=True: snapshot,
            now=lambda: self.clock["t"], sleep=lambda seconds: None,
            popen=mock.Mock())

    def events(self, emit):
        return [call.args[0] for call in emit.call_args_list]

    def ledger(self):
        path = os.path.join(paths.state_dir(), "handoffs.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as source:
            return [json.loads(line) for line in source if line.strip()]

    # -- the crossing itself ------------------------------------------------

    def test_threshold_crossing_schedules_and_commits_a_handoff(self):
        runner = self.runner()
        captured = {}

        def stop(child, plan, proof):
            captured["plan"], captured["proof"] = plan, proof
            return supervisor.Relaunch(plan.target, [], plan.cwd, True,
                                       plan.handoff_id, plan,
                                       reason="preemptive")

        with mock.patch.object(runner, "_stop_and_commit", side_effect=stop), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            outcome = runner._preemptive_cycle(self.child)
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.account["name"], "target")
        plan, proof = captured["plan"], captured["proof"]
        self.assertTrue(plan.preemptive)
        self.assertTrue(plan.automatic)
        self.assertEqual(plan.family, "fable")
        self.assertEqual(plan.target["name"], "target")
        # a preemptive plan carries NO cap scope, so it cools nothing
        self.assertEqual(plan.cooldown_scope, {})
        self.assertEqual((proof.window, proof.used_percent),
                         ("scoped:fable", 94.0))
        # NOT an authenticated cap: a mid-tool-call transcript is refused
        self.assertIs(plan.cap_proof["authenticated"], False)
        self.assertIs(plan.cap_proof["preemptive"], True)
        # the shared ledger admission ran: the target is reserved
        reserved = [row for row in self.ledger()
                    if row.get("action") == "cap_confirmed"]
        self.assertEqual(len(reserved), 1)
        self.assertEqual(reserved[0]["target_slot"], "target")
        self.assertEqual([event["event"] for event in self.events(emit)],
                         ["preemptive_scheduled", "preemptive_handoff"])
        self.assertEqual(self.events(emit)[0]["used_percent"], 94.0)
        self.assertTrue(self.child.automation)

    def test_overall_weekly_crossing_also_rotates(self):
        runner = self.runner(self.usage(scoped=10.0, seven=96.0))
        with mock.patch.object(runner, "_stop_and_commit",
                               return_value=None) as stop, \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            runner._preemptive_cycle(self.child)
        self.assertEqual(stop.call_args.args[2].window, "7d")

    def test_a_five_hour_crossing_rotates_before_the_wall(self):
        # the whole point: a session doing continuous work does not get to
        # "wait a few hours for the 5h to heal", so it leaves at 97% through
        # the front door instead of being refused mid-task
        runner = self.runner(self.usage(scoped=10.0, seven=20.0, five=97.0))
        with mock.patch.object(runner, "_stop_and_commit",
                               return_value=None) as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            runner._preemptive_cycle(self.child)
        plan, proof = stop.call_args.args[1], stop.call_args.args[2]
        self.assertEqual((proof.window, proof.used_percent), ("5h", 97.0))
        self.assertEqual(plan.target["name"], "target")
        # nothing is cooled: the seat is not capped, it is nearly spent
        self.assertEqual(plan.cooldown_scope, {})
        scheduled = [event for event in self.events(emit)
                     if event["event"] == "preemptive_scheduled"]
        self.assertEqual(scheduled[0]["window"], "5h")

    def test_a_five_hour_crossing_holds_when_no_seat_has_5h_headroom(self):
        # rotating would not help: the only other seat is nearly at the same
        # wall, so staying put and letting the window heal is strictly better
        # than spending a seat, a restart and the loop budget to arrive there
        runner = self.runner(self.usage(scoped=10.0, seven=20.0, five=99.0,
                                        target_five=95.0))
        with mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        held = [event for event in self.events(emit)
                if event["event"] == "preemptive_held"]
        self.assertIn("no seat has real 5h headroom", held[0]["reason"])
        self.assertIn("5h at 95%", held[0]["reason"])
        self.assertIn("heals on its own", held[0]["reason"])
        self.assertEqual(self.ledger(), [])
        self.assertTrue(self.child.automation)

    def test_that_same_seat_is_still_a_target_for_a_weekly_crossing(self):
        # the 5h margin is a rule about 5h rotations, not a general embargo:
        # a weekly window is gone for days, a 95% 5h heals within hours
        runner = self.runner(self.usage(scoped=94.0, seven=20.0,
                                        target_five=95.0))
        with mock.patch.object(runner, "_stop_and_commit",
                               return_value=None) as stop, \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            runner._preemptive_cycle(self.child)
        self.assertEqual(stop.call_args.args[1].target["name"], "target")
        self.assertEqual(stop.call_args.args[2].window, "scoped:fable")

    def test_a_spent_5h_seat_is_never_a_weekly_crossings_target_either(self):
        runner = self.runner(self.usage(scoped=94.0, seven=20.0,
                                        target_five=99.0))
        with mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        held = [event for event in self.events(emit)
                if event["event"] == "preemptive_held"]
        self.assertIn("itself near its limit: target (5h at 99%)",
                      held[0]["reason"])
        self.assertTrue(self.child.automation)

    def test_below_threshold_never_rotates_and_clears_the_announcement(self):
        runner = self.runner(self.usage(scoped=10.0, seven=20.0))
        self.child.preemptive_announced = True
        with mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        emit.assert_not_called()
        self.assertFalse(self.child.preemptive_announced)
        self.assertTrue(self.child.automation)

    # -- safe boundary ------------------------------------------------------

    def test_mid_turn_child_defers_without_interrupting_or_disarming(self):
        self.idle(seconds=0)          # transcript is being written right now
        runner = self.runner()
        with mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        self.assertTrue(self.child.automation)
        self.assertFalse(self.child.supervision_loss_notified)
        held = [event for event in self.events(emit)
                if event["event"] == "preemptive_held"]
        self.assertEqual(len(held), 1)
        self.assertIn("changed recently", held[0]["reason"])
        # a busy child is the common case: retry on the normal cadence, not
        # the long backoff
        self.assertEqual(self.child.preemptive_next_check,
                         self.clock["t"] + supervisor.PREEMPT_POLL_SECONDS)
        # nothing was staged or reserved
        self.assertEqual(self.ledger(), [])

    def test_mid_tool_call_transcript_is_never_moved_early(self):
        with open(self.transcript, "a", encoding="utf-8") as out:
            out.write(json.dumps({"type": "assistant", "message": {
                "model": "claude-fable-5-20260701",
                "content": [{"type": "tool_use", "id": "t1",
                             "name": "Bash", "input": {}}]}}) + "\n")
        self.idle(seconds=600)
        runner = self.runner()
        with mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        held = [event for event in self.events(emit)
                if event["event"] == "preemptive_held"]
        self.assertIn("mid-tool-call", held[0]["reason"])
        self.assertTrue(self.child.automation)

    def test_unread_hook_event_defers_the_rotation(self):
        runner = self.runner()
        with open(self.child.event_path, "w", encoding="utf-8") as out:
            out.write("{}\n")
        with mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        self.assertTrue(self.child.automation)

    # -- no target / guard refusal -----------------------------------------

    def test_no_healthy_target_defers_with_backoff_and_does_not_thrash(self):
        runner = self.runner(self.usage(target_ok=False))
        with mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
            first = self.child.preemptive_next_check
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        self.assertEqual(first, self.clock["t"]
                         + supervisor.PREEMPT_BACKOFF_SECONDS)
        held = [event for event in self.events(emit)
                if event["event"] == "preemptive_held"]
        self.assertEqual(len(held), 1)           # repeat holds do not re-notify
        self.assertIn("no target with proven headroom", held[0]["reason"])
        # nothing was announced: there was never an actionable rotation
        self.assertEqual([event["event"] for event in self.events(emit)],
                         ["preemptive_held"])
        self.assertTrue(self.child.automation)

    def test_long_quiet_mid_turn_child_is_never_stopped(self):
        # the transcript has been silent far longer than the idle window, but
        # its newest record is an unanswered prompt: the model is thinking
        with open(self.transcript, "a", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "think hard"}]}}) + "\n")
        self.idle(seconds=3600)
        runner = self.runner()
        with mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        held = [event for event in self.events(emit)
                if event["event"] == "preemptive_held"]
        self.assertIn("still working", held[0]["reason"])
        self.assertIn("awaiting its answer", held[0]["reason"])
        self.assertEqual(self.ledger(), [])
        self.assertTrue(self.child.automation)

    def sidechain(self, records, age):
        directory = os.path.join(os.path.dirname(self.transcript), self.SID,
                                 "subagents")
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "agent-a99d9789808.jsonl")
        with open(path, "w", encoding="utf-8") as out:
            for record in records:
                out.write(json.dumps(record) + "\n")
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def test_a_live_background_subagent_defers_the_rotation(self):
        # the desk's normal mode: the main turn ended, but a backgrounded
        # Agent is still working — and it has been SILENT for far longer than
        # the idle window, blocked in one long tool call. Only its shape says
        # so; its mtime says "finished".
        self.sidechain([{"type": "assistant", "isSidechain": True,
                         "agentId": "a99d9789808", "message": {
                             "model": "claude-fable-5", "content": [
                                 {"type": "tool_use", "id": "toolu_slow",
                                  "name": "Bash",
                                  "input": {"command": "make"}}]}}], age=30)
        runner = self.runner()
        with mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        held = [event for event in self.events(emit)
                if event["event"] == "preemptive_held"]
        self.assertIn("waiting on a tool call", held[0]["reason"])
        self.assertEqual(self.ledger(), [])
        self.assertTrue(self.child.automation)

    def test_a_copied_notification_cannot_unlock_the_sigterm(self):
        # end to end: a live background agent, and a transcript dump quoting
        # its own completion envelope inside a Bash tool_result. Only the
        # harness-marked record retires an agent, so the rotation must hold.
        agent = "a0fdfb291e702a98b"
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "go"}]}}) + "\n")
            out.write(json.dumps({"type": "user", "message": {"content": [{
                "type": "tool_result", "tool_use_id": "toolu_a", "content": [{
                    "type": "text",
                    "text": ("Async agent launched successfully.\n"
                             f"agentId: {agent} (internal ID)")}]}]}}) + "\n")
            out.write(json.dumps({"type": "user", "message": {"content": [{
                "type": "tool_result", "tool_use_id": "toolu_b", "content": (
                    "=== dump ===\n<task-notification>\n"
                    f"<task-id>{agent}</task-id>\n<status>completed</status>\n"
                    "</task-notification>")}]}}) + "\n")
            out.write(json.dumps({"type": "assistant", "message": {
                "model": "claude-fable-5-20260701",
                "content": [{"type": "text", "text": "done"}]}}) + "\n")
        self.idle(seconds=600)
        runner = self.runner()
        with mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        held = [event for event in self.events(emit)
                if event["event"] == "preemptive_held"]
        self.assertIn("have not reported back", held[0]["reason"])
        self.assertEqual(self.ledger(), [])
        self.assertTrue(self.child.automation)

    def test_a_finished_background_subagent_does_not_block_the_rotation(self):
        # same age, same silence — but its transcript ends with the assistant
        # message that IS its return value, so the rotation proceeds
        self.sidechain([{"type": "assistant", "isSidechain": True,
                         "agentId": "a99d9789808", "message": {
                             "model": "claude-fable-5", "content": [
                                 {"type": "text",
                                  "text": "report delivered"}]}}], age=30)
        runner = self.runner()
        with mock.patch.object(runner, "_stop_and_commit",
                               return_value=None) as stop, \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            runner._preemptive_cycle(self.child)
        stop.assert_called_once()

    def test_target_relaunch_failure_recovers_the_source_supervised(self):
        # the handoff COMMITTED (the conversation is staged on the target) and
        # only then did the target spawn fail deterministically. An elective
        # rotation must not turn that into a disarmed session.
        runner = self.runner()
        plan = mock.Mock(preemptive=True)
        plan.target = self.target
        plan.source.account = self.source
        relaunch = supervisor.Relaunch(self.target, ["--resume", self.SID],
                                       self.cwd, True, "hid", plan,
                                       reason="preemptive")
        spawns = []

        def spawn(account, args, cwd, automatic, plan=None):
            spawns.append((account["name"], automatic))
            if len(spawns) == 2:
                runner.spawn_ambiguous = False   # positively no child started
                raise supervisor.SupervisorError(
                    "`claude` not found on PATH; nothing was started")
            child = mock.Mock()
            child.account = account
            child.generation = len(spawns)
            return child

        outcomes = iter([relaunch, 0])
        with mock.patch.object(runner, "_spawn", side_effect=spawn), \
                mock.patch.object(
                    runner, "_monitor",
                    side_effect=lambda child, pending="": next(outcomes)), \
                mock.patch.object(runner, "_reconcile_leases"), \
                mock.patch.object(runner, "_failure") as failure, \
                mock.patch.object(handoff, "append_action"), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertEqual(runner.run(), 0)
        self.assertEqual([name for name, _ in spawns],
                         ["source", "target", "source"])
        # the recovered source is SUPERVISED — the guarantee survives
        self.assertTrue(spawns[2][1])
        events = [event["event"] for event in self.events(emit)]
        self.assertNotIn("supervision_lost", events)
        self.assertIn("preemptive_held", events)
        self.assertIn("target_relaunch_failed", failure.call_args.args[1])
        self.assertEqual(runner.preemptive_hold_until,
                         self.clock["t"] + supervisor.PREEMPT_BACKOFF_SECONDS)

    def test_cap_origin_target_relaunch_failure_is_unchanged(self):
        runner = self.runner()
        plan = mock.Mock(preemptive=False)
        plan.target = self.target
        plan.source.account = self.source
        relaunch = supervisor.Relaunch(self.target, ["--resume", self.SID],
                                       self.cwd, True, "hid", plan)
        spawns = []

        def spawn(account, args, cwd, automatic, plan=None):
            spawns.append((account["name"], automatic))
            if len(spawns) == 2:
                runner.spawn_ambiguous = False
                raise supervisor.SupervisorError("nothing was started")
            child = mock.Mock()
            child.account = account
            child.generation = len(spawns)
            return child

        outcomes = iter([relaunch, 0])
        with mock.patch.object(runner, "_spawn", side_effect=spawn), \
                mock.patch.object(
                    runner, "_monitor",
                    side_effect=lambda child, pending="": next(outcomes)), \
                mock.patch.object(runner, "_reconcile_leases"), \
                mock.patch.object(runner, "_failure"), \
                mock.patch.object(handoff, "append_action"), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertEqual(runner.run(), 0)
        self.assertFalse(spawns[2][1])          # still recovered unsupervised
        self.assertIn("supervision_lost",
                      [event["event"] for event in self.events(emit)])
        self.assertEqual(runner.preemptive_hold_until, 0.0)

    def stopped_plan(self, runner):
        """A fully admitted preemptive plan, ready to stop the child."""
        with mock.patch.object(notify, "emit"), redirect_stderr(io.StringIO()):
            proof, snapshot = runner._preemptive_observation(self.child)
            plan = runner._preemptive_preflight(self.child, proof, snapshot)
        with open(self.child.event_path, "w", encoding="utf-8"):
            pass          # the stop guard needs a real (empty) journal
        return plan, proof

    def test_a_turn_starting_during_the_stop_write_aborts_the_kill(self):
        runner = self.runner()
        plan, proof = self.stopped_plan(runner)
        real_append = handoff.append_action

        def append(handoff_id, action, **fields):
            record = real_append(handoff_id, action, **fields)
            if action == "stop_sent":
                # the user hit enter while the durable stop_sent write was in
                # flight — the exact TOCTOU window before SIGTERM
                with open(self.transcript, "a", encoding="utf-8") as out:
                    out.write(json.dumps({"type": "user", "message": {
                        "content": [{"type": "text", "text": "one more"}]}})
                        + "\n")
            return record

        kills = []
        with mock.patch.object(handoff, "append_action", side_effect=append), \
                mock.patch.object(supervisor.os, "kill",
                                  side_effect=lambda pid, sig: kills.append(sig)), \
                mock.patch.object(runner, "_wait_stopped", return_value=0), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                runner._stop_and_commit(self.child, plan, proof)
        self.assertEqual(kills, [])          # the child was never signalled
        self.assertIn("edge of a preemptive stop", str(caught.exception))
        self.assertTrue(self.child.automation)
        # the durable stop_sent row is marked cancelled, so the shared loop
        # budget is not charged for a stop that never happened
        rows = self.ledger()
        self.assertEqual([row["action"] for row in rows],
                         ["cap_confirmed", "stop_sent", "failure"])
        self.assertIs(rows[-1]["stop_cancelled"], True)

    def test_stop_edge_refuses_a_transcript_that_became_mid_turn(self):
        runner = self.runner()
        _, proof = self.stopped_plan(runner)
        with open(self.transcript, "a", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "one more"}]}}) + "\n")
        # stat matches (as it would if the record landed before the stat) but
        # the conversation is now mid-turn
        plan = mock.Mock(source_stat=handoff._transcript_stat(self.transcript))
        with self.assertRaisesRegex(supervisor.SupervisorError,
                                    "became busy"):
            runner._preemptive_stop_edge(self.child, plan, proof)

    def test_a_committed_rotation_fits_the_window_it_resumes_into(self):
        # the whole real pipeline — admission, stop, staging, commit — for a
        # conversation that has outgrown the standard context window
        with open(self.transcript, "a", encoding="utf-8") as out:
            out.write(json.dumps(usage_record(500_000)) + "\n")
        self.idle(seconds=600)
        runner = self.runner()
        plan, proof = self.stopped_plan(runner)

        def wait(child, _proof, stop_sent_at):
            child.session_ended = True
            child.session_end_received_at = stop_sent_at + 0.1
            return 0

        with mock.patch.object(supervisor.os, "kill"), \
                mock.patch.object(runner, "_wait_stopped", side_effect=wait), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            outcome = runner._stop_and_commit(self.child, plan, proof)
        self.assertEqual(outcome.account["name"], "target")
        self.assertEqual(outcome.argv, ["--resume", self.SID, "--fork-session",
                                        "--model", "opus[1m]"])
        fit = [event for event in self.events(emit)
               if event["event"] == "context_window_fit"]
        self.assertEqual(len(fit), 1)
        self.assertEqual(fit[0]["model"], "opus[1m]")
        self.assertEqual(fit[0]["account"], "target")
        # and the LEDGER carries the same model. If the supervisor dies
        # between commit and spawn, this row is the only thing left telling
        # the operator how to get the conversation back — and `--model opus`
        # cannot load a transcript that needs opus[1m].
        with open(handoff._ledger_path(), encoding="utf-8") as source:
            rows = [json.loads(line) for line in source if line.strip()]
        staged = [row for row in rows if row.get("action") == "staged"]
        self.assertTrue(staged)
        self.assertIn("--model 'opus[1m]'", staged[-1]["resume_command"])

    def test_a_normal_rotation_resumes_exactly_as_before(self):
        runner = self.runner()
        plan, proof = self.stopped_plan(runner)

        def wait(child, _proof, stop_sent_at):
            child.session_ended = True
            child.session_end_received_at = stop_sent_at + 0.1
            return 0

        with mock.patch.object(supervisor.os, "kill"), \
                mock.patch.object(runner, "_wait_stopped", side_effect=wait), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            outcome = runner._stop_and_commit(self.child, plan, proof)
        self.assertEqual(outcome.argv, ["--resume", self.SID, "--fork-session"])
        self.assertNotIn("context_window_fit",
                         [event["event"] for event in self.events(emit)])

    def test_aborted_rotation_recovers_the_source_with_supervision_on(self):
        runner = self.runner()
        plan, proof = self.stopped_plan(runner)

        def wait(child, _proof, stop_sent_at):
            child.session_ended = True
            child.session_end_received_at = stop_sent_at + 0.1
            return 0

        with mock.patch.object(supervisor.os, "kill"), \
                mock.patch.object(runner, "_wait_stopped", side_effect=wait), \
                mock.patch.object(
                    runner, "_post_stop_plan",
                    side_effect=handoff.HandoffError(
                        "session stopped mid-tool-call (unresolved: t1)")), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            outcome = runner._stop_and_commit(self.child, plan, proof)
        self.assertEqual(outcome.account["name"], "source")
        self.assertEqual(outcome.reason, "preemptive_aborted")
        self.assertFalse(outcome.automatic)
        self.assertTrue(outcome.supervised)     # recovered SUPERVISED
        self.assertTrue(self.child.automation)
        self.assertFalse(self.child.supervision_loss_notified)
        self.assertNotIn("supervision_lost",
                         [event["event"] for event in self.events(emit)])
        # and the recovered child is not immediately re-targeted
        self.assertEqual(runner.preemptive_hold_until,
                         self.clock["t"] + supervisor.PREEMPT_BACKOFF_SECONDS)
        self.assertFalse(runner._preemptive_due(self.child, None))

    def test_post_stop_dangling_transcript_is_refused_only_when_preemptive(self):
        runner = self.runner()
        plan, _ = self.stopped_plan(runner)
        # the stop caught a tool call after all
        with open(self.transcript, "a", encoding="utf-8") as out:
            out.write(json.dumps({"type": "assistant", "message": {
                "model": "claude-fable-5-20260701",
                "content": [{"type": "tool_use", "id": "t1", "name": "Bash",
                             "input": {}}]}}) + "\n")
        self.idle(seconds=600)
        with self.assertRaisesRegex(handoff.HandoffError, "mid-tool-call"):
            runner._post_stop_plan(plan)
        # a CAP stop had no alternative, so it still publishes (with the
        # "may re-run on resume" notice) — that behaviour is unchanged
        cap_plan = dataclasses.replace(plan, preemptive=False)
        self.assertEqual(
            runner._post_stop_plan(cap_plan).inspected["unresolved_tool_ids"],
            ("t1",))

    def test_run_relaunches_an_aborted_rotation_supervised(self):
        runner = self.runner()
        spawned = []

        def spawn(account, args, cwd, automatic, plan=None):
            spawned.append(automatic)
            child = mock.Mock()
            child.account = account
            child.generation = len(spawned)
            return child

        for supervised, expected in ((True, [True, True]),
                                     (None, [True, False])):
            spawned.clear()
            outcomes = iter([supervisor.Relaunch(
                self.source, ["--resume", self.SID], self.cwd, False,
                reason="preemptive_aborted", supervised=supervised), 0])
            with mock.patch.object(runner, "_spawn", side_effect=spawn), \
                    mock.patch.object(
                        runner, "_monitor",
                        side_effect=lambda child, pending="": next(outcomes)), \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(runner.run(), 0)
            self.assertEqual(spawned, expected, supervised)

    def test_cap_hook_during_the_stop_transition_is_absorbed(self):
        runner = self.runner()
        _, proof = self.stopped_plan(runner)
        record = {"schema": "headroom_hook_event@1",
                  "supervisor_id": os.path.splitext(
                      os.path.basename(self.child.event_path))[0],
                  "generation": 1, "source_slot": "source",
                  "config_dir": self.source["home"], "matcher": "rate_limit",
                  "received_at": self.clock["t"] + 1,
                  "payload": {"hook_event_name": "StopFailure",
                              "session_id": self.SID,
                              "transcript_path": self.transcript,
                              "cwd": self.cwd, "error": "rate_limit"}}
        self.child.pending_cap = supervisor.PendingCap(
            {}, self.SID, self.transcript, 1, self.clock["t"], self.clock["t"])
        with mock.patch.object(supervisor, "_read_events",
                               return_value=[record]), \
                redirect_stderr(io.StringIO()):
            # must NOT raise "cap proof expired during the stop transition"
            runner._consume_stop_events(self.child, proof, self.clock["t"])
        self.assertIsNone(self.child.pending_cap)
        self.assertTrue(self.child.automation)

    def test_target_that_is_itself_near_its_limit_is_never_moved_onto(self):
        snapshot = self.usage()
        target = snapshot["accounts"][1]
        target["windows"]["7d"]["used_percent"] = 97.0
        runner = self.runner(snapshot)
        with mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        held = [event for event in self.events(emit)
                if event["event"] == "preemptive_held"]
        self.assertIn("itself near its limit", held[0]["reason"])
        self.assertEqual(self.ledger(), [])
        self.assertTrue(self.child.automation)

    def test_near_limit_top_candidate_is_skipped_for_a_healthy_lower_one(self):
        # Claude ranking is Fable-headroom-primary, so the FIRST candidate can
        # be the one over the 7d threshold while a healthy seat sits below it
        # in the ranking. Walk the list instead of backing off on the leader.
        seats = [self.source]
        for name in ("target-a", "target-b"):
            account = self.account(name)
            os.makedirs(os.path.join(account["home"], "projects"),
                        exist_ok=True)
            seats.append(account)
        registry.save({"schema_version": 1, "accounts": seats})
        captured = int(self.clock["t"])
        snapshot = self.usage()
        snapshot["accounts"].pop()            # drop the fixture's "target"
        for name, scoped, seven in (("target-a", 5.0, 97.0),
                                    ("target-b", 60.0, 20.0)):
            row = usage_row(name, used7=seven, captured=captured)
            row["windows"]["scoped:Fable"] = {
                "used_percent": scoped, "resets_at": captured + 6 * 86400,
                "window_minutes": 10080}
            snapshot["accounts"].append(row)
        runner = self.runner(snapshot)
        # the leader really is the near-limit seat
        ranked = [account["name"] for account, reason
                  in route.candidates("fable", snapshot) if reason is None]
        self.assertEqual(ranked[0], "target-a")
        self.assertIn("target-b", ranked)
        with mock.patch.object(notify, "emit"), redirect_stderr(io.StringIO()):
            proof, snap = runner._preemptive_observation(self.child)
            plan = runner._preemptive_preflight(self.child, proof, snap)
        self.assertEqual(plan.target["name"], "target-b")

    def test_every_target_near_its_limit_backs_off_with_a_named_reason(self):
        snapshot = self.usage()
        snapshot["accounts"][1]["windows"]["7d"]["used_percent"] = 97.0
        runner = self.runner(snapshot)
        with mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        held = [event for event in self.events(emit)
                if event["event"] == "preemptive_held"]
        self.assertIn("itself near its limit: target", held[0]["reason"])
        self.assertEqual(self.child.preemptive_next_check,
                         self.clock["t"] + supervisor.PREEMPT_BACKOFF_SECONDS)
        self.assertTrue(self.child.automation)

    def test_guard_refusal_falls_back_cleanly_to_cap_reactive(self):
        runner = self.runner()
        with mock.patch.object(
                handoff, "reserve_automatic",
                side_effect=handoff.HandoffError(
                    "automatic handoff loop guard: 3 handoffs in 10 minutes")), \
                mock.patch.object(runner, "_stop_and_commit") as stop, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        stop.assert_not_called()
        # the cap-reactive guarantee is untouched: still armed, never disarmed
        self.assertTrue(self.child.automation)
        self.assertFalse(self.child.supervision_loss_notified)
        held = [event for event in self.events(emit)
                if event["event"] == "preemptive_held"]
        self.assertIn("loop guard", held[0]["reason"])
        self.assertEqual(self.child.preemptive_next_check,
                         self.clock["t"] + supervisor.PREEMPT_BACKOFF_SECONDS)

    def test_pre_stop_failure_releases_the_reservation_without_disarming(self):
        runner = self.runner()
        with mock.patch.object(
                runner, "_stop_and_commit",
                side_effect=supervisor.SupervisorError("target slot is leased")), \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        actions = [row.get("action") for row in self.ledger()]
        self.assertEqual(actions, ["cap_confirmed", "failure"])
        self.assertIn("preemptive_pre_stop_failed",
                      self.ledger()[-1]["reason"])
        self.assertTrue(self.child.automation)
        self.assertFalse(self.child.supervision_loss_notified)

    def test_unreadable_usage_holds_quietly_without_a_fleet_event(self):
        def boom(quiet=True):
            raise RuntimeError("provider unreachable")

        runner = supervisor.Supervisor(
            "fable", [], self.source, collect_fn=boom,
            now=lambda: self.clock["t"], sleep=lambda seconds: None)
        with mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertIsNone(runner._preemptive_cycle(self.child))
        emit.assert_not_called()        # no crossing is known — not an event
        self.assertTrue(self.child.automation)
        self.assertEqual(self.child.preemptive_next_check,
                         self.clock["t"] + supervisor.PREEMPT_BACKOFF_SECONDS)

    # -- the monitor gate ---------------------------------------------------

    def test_monitor_polls_only_when_due_and_returns_the_relaunch(self):
        runner = self.runner()
        relaunch = supervisor.Relaunch(self.target, [], self.cwd, True,
                                       reason="preemptive")
        self.child.preemptive_next_check = self.clock["t"] + 3600
        self.assertFalse(runner._preemptive_due(self.child, None))
        self.child.preemptive_next_check = self.clock["t"]
        self.assertTrue(runner._preemptive_due(self.child, None))
        polls = iter([None, 0])
        self.child.process.poll.side_effect = lambda: next(polls)
        with mock.patch.object(runner, "_handle_events", return_value=None), \
                mock.patch.object(runner, "_preemptive_cycle",
                                  return_value=relaunch) as cycle, \
                redirect_stderr(io.StringIO()):
            outcome = runner._monitor(self.child)
        self.assertIs(outcome, relaunch)
        cycle.assert_called_once()

    def test_disabled_preemptive_never_polls(self):
        registry.save({"schema_version": 1,
                       "routing": {"preemptive_handoff": False},
                       "accounts": [self.source, self.target]})
        runner = self.runner()
        self.assertFalse(runner.preemptive)
        self.assertFalse(runner._preemptive_due(self.child, None))
        polls = iter([None, 0])
        self.child.process.poll.side_effect = lambda: next(polls)
        with mock.patch.object(runner, "_handle_events", return_value=None), \
                mock.patch.object(runner, "_preemptive_cycle") as cycle, \
                redirect_stderr(io.StringIO()):
            self.assertEqual(runner._monitor(self.child), 0)
        cycle.assert_not_called()

    def test_a_cap_proof_always_wins_over_a_preemptive_poll(self):
        runner = self.runner()
        self.assertTrue(runner._preemptive_due(self.child, None))
        # a cap proof in flight, a pending cap, or an ended session all skip
        self.assertFalse(runner._preemptive_due(self.child, object()))
        self.child.pending_cap = supervisor.PendingCap(
            {}, self.SID, self.transcript, 1, self.clock["t"], self.clock["t"])
        self.assertFalse(runner._preemptive_due(self.child, None))
        self.child.pending_cap = None
        self.child.session_ended = True
        self.assertFalse(runner._preemptive_due(self.child, None))

    # -- the ledger label ---------------------------------------------------

    def test_committed_preemptive_handoff_is_labelled_in_the_ledger(self):
        runner = self.runner()
        with mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            proof, snapshot = runner._preemptive_observation(self.child)
            plan = runner._preemptive_preflight(self.child, proof, snapshot)
            result = handoff.commit_handoff(plan)
        self.assertEqual(result.record["reason"], "preemptive")
        self.assertIsNone(result.record["cap_scope"])
        self.assertTrue(os.path.exists(plan.destination))
        # a preemptive rotation cools nothing — the seat is not capped
        self.assertEqual(route.cooldowns(), {})


# --------------------------------------------------------------------------
# Loud disarms: every path that turns automatic handoff off for a child emits
# a structured supervision_lost event, not just a stderr line
# --------------------------------------------------------------------------
class LoudDisarms(TempDirCase):
    SUPERVISOR = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    SID = "44444444-4444-4444-8444-444444444444"

    def setUp(self):
        super().setUp()
        self.home = self.account("source")["home"]
        directory = os.path.join(self.home, "projects", "p")
        os.makedirs(directory)
        self.transcript = os.path.join(directory, self.SID + ".jsonl")
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "hi"}]}}) + "\n")
        self.cwd = os.path.join(self.temp.name, "work")
        os.makedirs(self.cwd)
        self.account_row = {"name": "source", "provider": "claude",
                            "home": self.home}
        self.child = supervisor.Child(
            mock.Mock(pid=os.getpid()), self.account_row, 1,
            os.path.join(self.temp.name, self.SUPERVISOR + ".jsonl"), "",
            1.0, True,
            binding=supervisor.Binding(self.SID, self.transcript, self.cwd,
                                       "Sonnet", "2.1", self.home, epoch=1),
            session_epoch=1)
        self.runner = supervisor.Supervisor(
            "sonnet", [], self.account_row, popen=mock.Mock())

    def record(self, **over):
        payload = {"hook_event_name": "SessionEnd", "session_id": self.SID,
                   "transcript_path": self.transcript, "cwd": self.cwd}
        payload.update(over.pop("payload", {}))
        record = {"schema": "headroom_hook_event@1",
                  "supervisor_id": self.SUPERVISOR, "generation": 1,
                  "source_slot": "source", "config_dir": self.home,
                  "matcher": "", "received_at": time.time(),
                  "payload": payload}
        record.update(over)
        return record

    def disarm(self, records):
        with mock.patch.object(supervisor, "_read_events",
                               return_value=records), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()) as err:
            self.runner._handle_events(self.child, "")
        return [call.args[0] for call in emit.call_args_list], err.getvalue()

    def test_malformed_hook_event_emits_supervision_lost(self):
        events, err = self.disarm([self.record(source_slot="impostor")])
        self.assertIn("automatic handoff disabled", err)
        self.assertEqual([event["event"] for event in events],
                         ["supervision_lost"])
        self.assertIn("malformed hook event", events[0]["reason"])
        self.assertFalse(self.child.automation)

    def test_session_end_without_a_known_epoch_emits_supervision_lost(self):
        other = "55555555-5555-4555-8555-555555555555"
        path = os.path.join(os.path.dirname(self.transcript), other + ".jsonl")
        with open(path, "w", encoding="utf-8") as out:
            out.write("{}\n")
        events, err = self.disarm([self.record(payload={
            "session_id": other, "transcript_path": path})])
        self.assertIn("SessionEnd has no known session epoch", err)
        self.assertEqual([event["event"] for event in events],
                         ["supervision_lost"])
        self.assertIn("no known session epoch", events[0]["reason"])
        self.assertFalse(self.child.automation)

    def test_unreadable_hook_journal_emits_supervision_lost(self):
        with mock.patch.object(
                supervisor, "_read_events",
                side_effect=supervisor.SupervisorError("journal is unreadable")), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()) as err:
            self.runner._handle_events(self.child, "")
        self.assertIn("automatic handoff disabled", err.getvalue())
        events = [call.args[0] for call in emit.call_args_list]
        self.assertIn("journal unreadable", events[0]["reason"])
        self.assertFalse(self.child.automation)

    def test_a_repeating_reason_notifies_once_a_new_one_is_never_silent(self):
        with mock.patch.object(notify, "emit") as emit:
            supervisor._lose_supervision(self.child, "same reason")
            supervisor._lose_supervision(self.child, "same reason")
            supervisor._lose_supervision(self.child, "a different failure")
        reasons = [call.args[0]["reason"] for call in emit.call_args_list]
        self.assertEqual(reasons, ["same reason", "a different failure"])

    def test_shutdown_after_the_child_exited_is_not_a_silent_disarm(self):
        # the child is already gone, so signal forwarding is moot: the disarm
        # must still be reported rather than exiting quietly
        class FakeGuard:
            shutdown_signal = 15
            forwarded = False

            def __init__(self, process=None):
                pass

            def install(self):
                pass

            def restore(self):
                pass

            def poll(self, process):
                pass

        self.child.process.poll.return_value = 0
        with mock.patch.object(supervisor, "_SignalGuard", FakeGuard), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            self.assertEqual(self.runner._monitor(self.child), 0)
        lost = [call.args[0] for call in emit.call_args_list
                if call.args[0]["event"] == "supervision_lost"]
        self.assertEqual(len(lost), 1)
        self.assertEqual(lost[0]["reason"], "shutdown signal received")


class AnAbandonedBatchStillSpeaksItsCaps(LoudDisarms):
    """_read_events advances the cursor for the WHOLE batch and then sorts by
    received_at; _handle_events has four early `return None` paths that
    abandon every record after the one that tripped them. Those bytes are
    already consumed from the journal and are never re-read, so a cap sharing
    a batch with one racy or malformed record is DESTROYED — the exact "the
    cap fired and nothing happened" shape this supervisor exists to prevent.

    Making the cursor per-record is not the fix: _events_pending and
    _event_stop_guard both prove "no newer hook event arrived" by comparing
    the journal's on-disk size against event_offset, so an unconsumed tail
    would make every later cap preflight fail with "cap proof expired after a
    newer hook event". So drain the tail for the one thing that must never be
    lost, and disarm exactly as before.

    ANNOUNCE-ONLY, deliberately. The child is being disarmed on these paths
    for reasons that are still valid, and ACTING on a cap found after a
    malformed event in the same batch would be acting on a journal we just
    declared untrustworthy."""

    CAP = ("You're out of usage credits. Run /usage-credits to keep using "
           "Fable 5 or /model to switch models.")
    ABANDONED = "the hook batch was abandoned after an earlier malformed event"

    def cap_record(self, when):
        return self.record(
            matcher="rate_limit", received_at=when,
            payload={"hook_event_name": "StopFailure", "error": "rate_limit",
                     "last_assistant_message": self.CAP})

    def unhandled(self, events):
        return [event for event in events if event["event"] == "cap_unhandled"]

    def test_a_cap_behind_a_malformed_event_is_announced_not_destroyed(self):
        """(a) The live shape: one impostor record in the batch and the cap
        that followed it is gone forever."""
        now = time.time()
        events, err = self.disarm([
            self.record(source_slot="impostor", received_at=now),
            self.cap_record(now + 1)])
        # the disarm itself is completely unchanged
        self.assertFalse(self.child.automation)
        self.assertIn("malformed hook event", err)
        self.assertIn("supervision_lost", [e["event"] for e in events])
        # ...and the cap in the abandoned tail now has a voice
        self.assertIn("hit a subscription cap", err)
        self.assertIn(self.ABANDONED, err)
        self.assertIn("/model opus", err)
        unhandled = self.unhandled(events)
        self.assertEqual(len(unhandled), 1)
        self.assertEqual(unhandled[0]["reason"], self.ABANDONED)
        self.assertIs(unhandled[0]["bound"], True)

    def test_a_cap_behind_an_unknown_epoch_session_end_is_announced_too(self):
        """(b) The same loss through a different early return."""
        now = time.time()
        other = "55555555-5555-4555-8555-555555555555"
        path = os.path.join(os.path.dirname(self.transcript), other + ".jsonl")
        with open(path, "w", encoding="utf-8") as out:
            out.write("{}\n")
        events, err = self.disarm([
            self.record(received_at=now, payload={
                "session_id": other, "transcript_path": path}),
            self.cap_record(now + 1)])
        self.assertFalse(self.child.automation)
        self.assertIn("SessionEnd has no known session epoch", err)
        self.assertEqual([e["reason"] for e in self.unhandled(events)],
                         [self.ABANDONED])

    def test_a_cap_that_sorts_BEFORE_the_bad_record_is_not_double_announced(self):
        """(c) ORDERING. `records[index + 1:]` is the tail in received_at
        order, which is the order the loop would have processed — NOT file
        order. A cap ahead of the malformed record was already handled on its
        own terms and must not be announced a second time with the wrong
        reason."""
        now = time.time()
        self.child.automation = False        # so the cap takes the announce path
        events, err = self.disarm([
            self.cap_record(now),
            self.record(source_slot="impostor", received_at=now + 1)])
        unhandled = self.unhandled(events)
        self.assertEqual(len(unhandled), 1)
        self.assertEqual(unhandled[0]["reason"],
                         "supervision is off for this child")
        self.assertNotIn(self.ABANDONED, err)

    def test_a_tail_with_no_cap_in_it_adds_nothing(self):
        """(d) The drain speaks only for caps."""
        now = time.time()
        events, err = self.disarm([
            self.record(source_slot="impostor", received_at=now),
            self.record(matcher="rate_limit", received_at=now + 1, payload={
                "hook_event_name": "StopFailure", "error": "rate_limit",
                "last_assistant_message": "429 rate_limit_error: try later"})])
        self.assertEqual(self.unhandled(events), [])
        self.assertNotIn("hit a subscription cap", err)

    def test_one_cap_repeated_in_the_tail_is_announced_once(self):
        """Volume on a badly corrupted journal is bounded by the batch, and
        the same event redelivered is still one wall."""
        now = time.time()
        events, _err = self.disarm([
            self.record(source_slot="impostor", received_at=now),
            self.cap_record(now + 1), self.cap_record(now + 1)])
        self.assertEqual(len(self.unhandled(events)), 1)

    def test_the_unreadable_journal_path_drains_nothing(self):
        """(e) Unchanged, and deliberately so: _read_events raised, so no
        bytes were parsed and the cursor never advanced. There is no tail to
        drain — the records are all still in the journal."""
        with mock.patch.object(
                supervisor, "_read_events",
                side_effect=supervisor.SupervisorError("journal is unreadable")), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()) as err:
            self.runner._handle_events(self.child, "")
        events = [call.args[0] for call in emit.call_args_list]
        self.assertEqual(self.unhandled(events), [])
        self.assertNotIn("hit a subscription cap", err.getvalue())
        self.assertFalse(self.child.automation)


# --------------------------------------------------------------------------
# Context backstop: measurement, window fit, and the forced rotation
# --------------------------------------------------------------------------
class ContextMeasurement(TempDirCase):
    """What the supervisor believes about a session's remaining context.

    The cooperative hook and this backstop must agree exactly — a disagreement
    means one of them fires at the wrong moment."""

    def transcript(self, records, name="c.jsonl"):
        path = os.path.join(self.temp.name, name)
        with open(path, "w", encoding="utf-8") as out:
            for record in records:
                out.write(json.dumps(record) + "\n")
        return path

    def test_the_newest_main_loop_record_decides_and_iterations_never_double(self):
        path = self.transcript([
            {"type": "user", "message": {"content": "hi"}},
            usage_record(120_000),
            {"type": "user", "message": {"content": "again"}},
            usage_record(180_000),
        ])
        # each request carries the whole conversation, so the newest record IS
        # the occupancy: not a sum of turns, and not multiplied by iterations
        self.assertEqual(supervisor._context_used(path), 180_000)

    def test_a_sidechain_never_counts_as_the_parents_context(self):
        path = self.transcript([
            usage_record(180_000),
            usage_record(950_000, sidechain=True),
        ])
        self.assertEqual(supervisor._context_used(path), 180_000)

    def test_a_nested_sidechain_marker_is_honoured_too(self):
        # some records carry the marker on the message, not the record — the
        # idleness machinery already reads both, and so must this
        nested = usage_record(950_000)
        nested["message"]["isSidechain"] = True
        path = self.transcript([usage_record(180_000), nested])
        self.assertEqual(supervisor._context_used(path), 180_000)
        self.assertEqual(supervisor._assistant_usage(nested), 0)

    def test_records_without_usage_never_read_as_an_empty_window(self):
        path = self.transcript([
            usage_record(180_000),
            {"type": "assistant", "message": {
                "model": "<synthetic>",
                "content": [{"type": "text", "text": "interrupted"}]}},
            {"type": "system", "subtype": "turn_duration", "durationMs": 12},
            {"type": "user", "message": {"content": "next"}},
        ])
        self.assertEqual(supervisor._context_used(path), 180_000)

    def test_an_unmeasurable_transcript_is_unknown_not_zero(self):
        self.assertIsNone(supervisor._context_used(
            os.path.join(self.temp.name, "missing.jsonl")))
        self.assertIsNone(supervisor._context_used(self.temp.name))
        self.assertIsNone(supervisor._context_used(mock.Mock()))
        self.assertIsNone(supervisor._context_used(self.transcript([
            {"type": "user", "message": {"content": "hi"}}])))
        broken = os.path.join(self.temp.name, "broken.jsonl")
        with open(broken, "w", encoding="utf-8") as out:
            out.write("{not json\n")
        self.assertIsNone(supervisor._context_used(broken))

    def test_usage_counters_that_are_not_numbers_are_ignored(self):
        record = usage_record(180_000)
        record["message"]["usage"]["input_tokens"] = True   # bool is not a count
        record["message"]["usage"]["cache_creation_input_tokens"] = "1000"
        path = self.transcript([record])
        self.assertEqual(supervisor._context_used(path),
                         record["message"]["usage"]["cache_read_input_tokens"])

    def test_window_inference_boundaries(self):
        # a transcript can only be over the ceiling if the 1M window served it
        self.assertEqual(supervisor._context_window(190_000), 200_000)
        self.assertEqual(supervisor._context_window(205_000), 200_000)
        self.assertEqual(supervisor._context_window(205_001), 1_000_000)
        self.assertEqual(supervisor._context_window(210_000), 1_000_000)

    def test_an_explicit_1m_model_is_knowledge_that_beats_inference(self):
        for args in (["--model", "opus[1m]", "--resume", "x"],
                     ["--model=claude-opus-5[1m]"],
                     ["--resume", "x", "--model", "OPUS[1M]"]):
            self.assertEqual(
                supervisor._context_window(1_000,
                                           supervisor._model_flag(args)),
                1_000_000, args)
        # ...and a normal model infers exactly as before
        self.assertEqual(
            supervisor._context_window(
                1_000, supervisor._model_flag(["--model", "fable"])), 200_000)

    def test_the_hooks_env_override_wins(self):
        with mock.patch.dict(os.environ, {"HEADROOM_CTX_WINDOW": "500000"}):
            self.assertEqual(supervisor._context_window(190_000), 500_000)
        for bad in ("", "abc", "0", "-5"):
            with mock.patch.dict(os.environ, {"HEADROOM_CTX_WINDOW": bad}):
                self.assertEqual(supervisor._context_window(190_000), 200_000)

    def test_remaining_percent_is_fail_closed(self):
        self.assertEqual(supervisor._context_remaining(180_000, 200_000), 10.0)
        self.assertEqual(supervisor._context_remaining(190_000, 200_000), 5.0)
        self.assertEqual(supervisor._context_remaining(190_000, 1_000_000), 81.0)
        self.assertEqual(supervisor._context_remaining(250_000, 200_000), 0.0)
        for used, window in ((None, 200_000), (100, 0), (100, None),
                             (-1, 200_000), (float("nan"), 200_000)):
            self.assertIsNone(supervisor._context_remaining(used, window))

    def test_model_flags_respect_the_argument_separator(self):
        self.assertEqual(
            supervisor._model_flag(["--resume", "x", "--", "--model", "no"]),
            "")
        self.assertEqual(
            supervisor._with_model(["--resume", "x", "--", "payload"], "m"),
            ["--resume", "x", "--model", "m", "--", "payload"])
        for args in (["--model", "fable", "--resume", "x"],
                     ["--model=fable", "--resume", "x"],
                     ["--resume", "x"]):
            self.assertEqual(supervisor._with_model(args, "opus[1m]"),
                             ["--resume", "x", "--model", "opus[1m]"])


class WindowFitOnResume(TempDirCase):
    """Every automatic resume must fit the window it resumes into (production
    lesson, 2026-07-27: a 500k-token transcript resumed under a 200k window
    died on its first prompt, twice)."""

    def transcript(self, total):
        path = os.path.join(self.temp.name, "t.jsonl")
        with open(path, "w", encoding="utf-8") as out:
            out.write(json.dumps(usage_record(total)) + "\n")
        return path

    def test_a_transcript_past_the_limit_forces_the_1m_model(self):
        path = self.transcript(500_000)
        argv, forced = supervisor._window_fit_argv(
            ["--resume", "sid", "--fork-session"], path)
        self.assertEqual(argv, ["--resume", "sid", "--fork-session",
                                "--model", "opus[1m]"])
        self.assertEqual(forced, "opus[1m]")

    def test_a_fitting_transcript_is_resumed_exactly_as_before(self):
        for total in (1_000, 190_000, 205_000):
            argv, forced = supervisor._window_fit_argv(
                ["--resume", "sid"], self.transcript(total))
            self.assertEqual((argv, forced), (["--resume", "sid"], ""))

    def test_a_wrong_model_on_an_over_limit_resume_is_replaced(self):
        argv, _ = supervisor._window_fit_argv(
            ["--resume", "sid", "--model", "fable"], self.transcript(500_000))
        self.assertEqual(argv, ["--resume", "sid", "--model", "opus[1m]"])
        # already fitted: nothing to say and nothing to change
        self.assertEqual(supervisor._window_fit_argv(
            argv, self.transcript(500_000)), (argv, ""))

    def test_a_large_conversation_keeps_the_1m_model_it_was_running(self):
        # a resume argv names only --resume/--fork-session, so without this a
        # rotation would silently shrink a 1M session back to 200k
        argv, forced = supervisor._window_fit_argv(
            ["--resume", "sid", "--fork-session"], self.transcript(150_000),
            model="opus[1m]")
        self.assertEqual(argv, ["--resume", "sid", "--fork-session",
                                "--model", "opus[1m]"])
        self.assertEqual(forced, "opus[1m]")
        # the child's OWN 1M model is kept, not swapped for the default one
        argv, forced = supervisor._window_fit_argv(
            ["--resume", "sid"], self.transcript(500_000),
            model="claude-sonnet-5[1m]")
        self.assertEqual(forced, "claude-sonnet-5[1m]")
        self.assertEqual(argv[-1], "claude-sonnet-5[1m]")

    def test_a_downgrade_does_not_carry_a_foreign_1m_model_across(self):
        # a capped Fable session routed to an Opus seat: keeping its own
        # `fable[1m]` would re-cap it on the very pool that just walled it,
        # and the seat was never checked for Fable in the first place
        argv, forced = supervisor._window_fit_argv(
            ["--resume", "sid", "--model", "opus"], self.transcript(500_000),
            model="fable[1m]", family="opus")
        self.assertEqual(forced, "opus[1m]")
        self.assertEqual(argv, ["--resume", "sid", "--model", "opus[1m]"])

    def test_a_downgrade_keeps_a_1m_model_that_is_its_own_family(self):
        argv, forced = supervisor._window_fit_argv(
            ["--resume", "sid"], self.transcript(150_000),
            model="claude-opus-5[1m]", family="opus")
        self.assertEqual(forced, "claude-opus-5[1m]")
        self.assertEqual(argv[-1], "claude-opus-5[1m]")

    def test_an_unroutable_model_name_does_not_raise_here(self):
        # model naming is the registry's problem; a fit decision must never
        # crash the one path that is saving a capped conversation
        argv, forced = supervisor._window_fit_argv(
            ["--resume", "sid"], self.transcript(500_000),
            model="wat-9000[1m]", family="opus")
        self.assertEqual((argv[-1], forced), ("opus[1m]", "opus[1m]"))

    def plan(self, total, resume_family=""):
        plan = mock.Mock(cwd="/work", resume_family=resume_family)
        plan.source.session_id = "sid"
        plan.source.transcript_path = self.transcript(total)
        plan.source.account = {"name": "source", "home": "/h/source"}
        plan.target = {"name": "target", "home": "/h/target"}
        return plan

    def test_the_manual_recovery_command_is_the_command_headroom_would_run(self):
        # the LAST thing between the user and a lost conversation: a bare
        # --resume here sends them back to the model that just capped (after a
        # downgrade) or to a window the transcript no longer fits
        for total, family, expected in (
                (50_000, "opus", ["--model", "opus"]),
                (500_000, "opus", ["--model", "opus[1m]"]),
                (500_000, "", ["--model", "opus[1m]"]),
                (50_000, "", [])):
            plan = self.plan(total, family)
            argv, _forced = supervisor._resume_argv_for(plan)
            self.assertEqual(
                argv, ["--resume", "sid", "--fork-session"] + expected,
                (total, family))
            with redirect_stderr(io.StringIO()) as errors:
                supervisor.Supervisor._print_manual_recovery(plan)
            self.assertIn(shlex.join(["claude"] + argv), errors.getvalue())
            # and the source line is the same command _source_relaunch builds
            self.assertIn(shlex.join(
                ["claude"] + supervisor.Supervisor._source_relaunch(plan).argv),
                errors.getvalue())

    def test_the_ledger_command_carries_the_model_not_just_the_family(self):
        # after a crash between commit and spawn, this row is all the operator
        # has. `--model opus` cannot load a transcript that needs `opus[1m]`,
        # so _post_stop_plan stamps the EXACT model the launch will use and
        # the row renders that.
        stamped = supervisor._model_flag(
            supervisor._resume_argv_for(self.plan(500_000, "opus"))[0])
        self.assertEqual(stamped, "opus[1m]")
        self.assertEqual(
            handoff.resume_command("/h/target", "sid", stamped),
            "CLAUDE_CONFIG_DIR=/h/target claude --resume sid --fork-session "
            "--model 'opus[1m]'")
        # and the family alone — what the row used to get — would not load it
        self.assertNotIn("[1m]", handoff.resume_command(
            "/h/target", "sid", "opus"))

    def test_a_downgrade_is_not_announced_as_a_window_fit(self):
        # `forced` drives the "no longer fits a 200k window" message; a tier
        # change is a routing fact and has its own announcement
        _argv, forced = supervisor._resume_argv_for(self.plan(50_000, "opus"))
        self.assertEqual(forced, "")

    def test_a_plan_without_a_family_field_is_treated_as_unset(self):
        # plans reach here from several vintages; a Mock's auto-attribute and
        # a legacy plan with no field at all must both read as "no family",
        # never as a truthy one that lands in the argv
        for plan in (mock.Mock(cwd="/w"), type("Old", (), {})()):
            plan.source = mock.Mock()
            plan.source.session_id = "sid"
            plan.source.transcript_path = self.transcript(50_000)
            argv, forced = supervisor._resume_argv_for(plan)
            self.assertEqual(argv, ["--resume", "sid", "--fork-session"])
            self.assertEqual(forced, "")

    def test_the_seats_gated_family_bounds_the_fit_even_without_a_downgrade(self):
        # a child spawned `--model sonnet[1m]` whose session had since moved
        # to Opus: no downgrade, but carrying sonnet[1m] onto the Opus-gated
        # seat checks one pool and spends another
        plan = self.plan(500_000)
        plan.target_family = "opus"
        argv, forced = supervisor._resume_argv_for(plan, "sonnet[1m]")
        self.assertEqual(forced, "opus[1m]")
        self.assertEqual(argv[-1], "opus[1m]")
        # and the same child on a SONNET-gated seat keeps its own model
        plan.target_family = "sonnet"
        _argv, forced = supervisor._resume_argv_for(plan, "sonnet[1m]")
        self.assertEqual(forced, "sonnet[1m]")

    def test_a_small_conversation_on_a_big_model_still_routes_normally(self):
        for total in (1_000, 100_000, 139_000):
            self.assertEqual(
                supervisor._window_fit_argv(["--resume", "sid"],
                                            self.transcript(total),
                                            model="opus[1m]"),
                (["--resume", "sid"], ""))

    def test_an_unmeasurable_transcript_changes_nothing(self):
        for path in (mock.Mock(), os.path.join(self.temp.name, "gone.jsonl")):
            self.assertEqual(
                supervisor._window_fit_argv(["--resume", "sid"], path),
                (["--resume", "sid"], ""))

    def test_source_recovery_is_fitted_too(self):
        plan = mock.Mock(cwd="/work")
        plan.source.session_id = "sid"
        plan.source.transcript_path = self.transcript(500_000)
        plan.source.account = {"name": "source"}
        relaunch = supervisor.Supervisor._source_relaunch(plan)
        self.assertEqual(relaunch.argv,
                         ["--resume", "sid", "--model", "opus[1m]"])
        self.assertFalse(relaunch.automatic)

    def test_source_recovery_of_an_unmeasurable_plan_is_unchanged(self):
        plan = mock.Mock(cwd="/work")
        plan.source.session_id = "sid"
        plan.source.account = {"name": "source"}
        self.assertEqual(supervisor.Supervisor._source_relaunch(plan).argv,
                         ["--resume", "sid"])

    def test_source_recovery_keeps_the_stopped_childs_own_1m_model(self):
        # recovering a sonnet[1m] session without its model shrinks it into a
        # 200k window (at 190k that is a 5%-remaining crisis on arrival) or
        # swaps its family for the default fit model for no reason at all
        plan = mock.Mock(cwd="/work")
        plan.source.session_id = "sid"
        plan.source.account = {"name": "source"}
        for total in (190_000, 500_000):
            plan.source.transcript_path = self.transcript(total)
            relaunch = supervisor.Supervisor._source_relaunch(
                plan, model="claude-sonnet-5[1m]")
            self.assertEqual(
                relaunch.argv,
                ["--resume", "sid", "--model", "claude-sonnet-5[1m]"], total)

    def test_source_recovery_of_a_small_session_still_routes_normally(self):
        plan = mock.Mock(cwd="/work")
        plan.source.session_id = "sid"
        plan.source.account = {"name": "source"}
        plan.source.transcript_path = self.transcript(50_000)
        self.assertEqual(
            supervisor.Supervisor._source_relaunch(
                plan, model="claude-sonnet-5[1m]").argv,
            ["--resume", "sid"])


class ContextBackstop(TempDirCase):
    """The fail-safe under the cooperative baton handoff: a real transcript, a
    real registry, the real idleness machinery; only the child process and the
    signal are faked."""

    SID = "44444444-4444-4444-8444-444444444444"

    def setUp(self):
        super().setUp()
        self.clock = {"t": time.time()}
        self.source = self.account("source")
        os.makedirs(os.path.join(self.source["home"], "projects"))
        registry.save({"schema_version": 1, "accounts": [self.source]})
        directory = os.path.join(self.source["home"], "projects", "p")
        os.makedirs(directory)
        self.transcript = os.path.join(directory, self.SID + ".jsonl")
        self.write(190_000)
        self.cwd = os.path.join(self.temp.name, "work")
        os.makedirs(self.cwd)
        self.events_path = os.path.join(self.temp.name, "events.jsonl")
        with open(self.events_path, "w", encoding="utf-8"):
            pass
        binding = supervisor.Binding(self.SID, self.transcript, self.cwd,
                                     "Fable", "2.1", self.source["home"],
                                     epoch=1)
        process = mock.Mock(pid=os.getpid())
        process.poll.return_value = None
        self.child = supervisor.Child(
            process, self.source, 1, self.events_path, "",
            self.clock["t"] - 600, True, binding=binding, session_epoch=1)
        for constant, value in (("PREEMPT_IDLE_SECONDS", 5.0),
                                ("PREEMPT_POLL_SECONDS", 60.0),
                                ("PREEMPT_BACKOFF_SECONDS", 300.0),
                                ("PREEMPT_DECISION_TTL", 120.0)):
            patch = mock.patch.object(supervisor, constant, value)
            patch.start()
            self.addCleanup(patch.stop)

    def write(self, used, trailing=None, idle=600):
        """A transcript whose newest turn is finished at `used` tokens."""
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "hi"}]}}) + "\n")
            out.write(json.dumps(usage_record(used)) + "\n")
            for record in trailing or ():
                out.write(json.dumps(record) + "\n")
        when = time.time() - idle
        os.utime(self.transcript, (when, when))

    def runner(self):
        return supervisor.Supervisor(
            "fable", [], self.source, collect_fn=lambda quiet=True: {},
            now=lambda: self.clock["t"], sleep=lambda seconds: None,
            popen=mock.Mock())

    def events(self, emit):
        return [call.args[0] for call in emit.call_args_list]

    def stopping(self, runner, exits=True):
        """Patch the kill + wait so a rotation completes without a real child."""
        def wait(child, _proof, stop_sent_at):
            if not exits:
                return None
            child.session_ended = True
            child.session_end_received_at = stop_sent_at + 0.1
            return 0
        return (mock.patch.object(supervisor.os, "kill"),
                mock.patch.object(runner, "_wait_stopped", side_effect=wait))

    def cycle(self, runner):
        kill, wait = self.stopping(runner)
        with kill as killed, wait, mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            outcome = runner._context_backstop_cycle(self.child)
        return outcome, killed, self.events(emit)

    # -- the crossing -------------------------------------------------------

    def test_a_nearly_full_idle_session_is_forked_onto_a_bigger_window(self):
        runner = self.runner()
        outcome, killed, events = self.cycle(runner)
        self.assertIsNotNone(outcome)
        killed.assert_called_once()
        self.assertEqual(killed.call_args.args[1], signal.SIGTERM)
        # the SAME seat, the SAME conversation, a window it fits in
        self.assertEqual(outcome.account["name"], "source")
        self.assertEqual(outcome.argv, ["--resume", self.SID, "--fork-session",
                                        "--model", "opus[1m]"])
        self.assertEqual(outcome.reason, "context_backstop")
        self.assertEqual(outcome.cwd, self.cwd)
        self.assertTrue(outcome.automatic)
        self.assertTrue(outcome.supervised)
        # it carries its OWN recovery: there is no handoff plan behind a
        # same-seat rotation, so this is all run() has if the replacement
        # cannot be spawned onto an already-stopped session
        self.assertIsNotNone(outcome.recovery)
        self.assertEqual(outcome.recovery.argv, ["--resume", self.SID])
        self.assertEqual(outcome.recovery.account["name"], "source")
        self.assertEqual(outcome.recovery.session_id, self.SID)
        self.assertEqual(outcome.recovery.cwd, self.cwd)
        self.assertEqual([event["event"] for event in events],
                         ["context_backstop_scheduled",
                          "context_backstop_rotation"])
        self.assertEqual(events[1]["used"], 190_000)
        self.assertEqual(events[1]["window"], 200_000)
        self.assertEqual(events[1]["model"], "opus[1m]")
        self.assertIs(events[1]["forked"], True)
        # nothing was disarmed and nothing was reserved or cooled. The ledger
        # now carries the ATTRIBUTION pair and nothing else — no cap_confirmed,
        # no reservation: a same-seat rotation still spends none of the cap
        # path's budget (pinned by
        # ..._rows_do_not_consume_the_automatic_budget in test_supervisor).
        self.assertTrue(self.child.automation)
        self.assertFalse(self.child.supervision_loss_notified)
        self.assertEqual([row["action"] for row in self.ledger()],
                         ["context_stop_sent", "context_stopped"])
        # the successor is not immediately rotated again
        self.assertEqual(runner.context_hold_until,
                         self.clock["t"] + supervisor.PREEMPT_BACKOFF_SECONDS)
        self.assertFalse(runner._context_backstop_due(self.child, None))

    def test_the_cooperative_zone_is_never_preempted(self):
        # 30% -> 10% belongs to the session's own baton handoff
        runner = self.runner()
        for used in (100_000, 140_000, 179_000, 179_999):
            self.write(used)
            self.assertIsNone(runner._context_observation(self.child), used)
            outcome, killed, events = self.cycle(runner)
            self.assertIsNone(outcome, used)
            killed.assert_not_called()
            self.assertEqual(events, [])
        self.assertTrue(self.child.automation)

    def test_the_threshold_itself_fires(self):
        runner = self.runner()
        self.write(180_000)                       # exactly 10% remaining
        proof = runner._context_observation(self.child)
        self.assertIsNotNone(proof)
        self.assertEqual(proof.remaining_percent, 10.0)
        self.assertIn("context at 10% remaining", proof.message)

    def test_the_threshold_is_configurable(self):
        registry.save({"schema_version": 1, "accounts": [self.source],
                       "routing": {"context_backstop_percent": 25}})
        runner = self.runner()
        self.write(160_000)                       # 20% remaining
        self.assertIsNotNone(runner._context_observation(self.child))

    def test_an_unmeasurable_transcript_never_rotates(self):
        runner = self.runner()
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user",
                                  "message": {"content": "hi"}}) + "\n")
        outcome, killed, events = self.cycle(runner)
        self.assertIsNone(outcome)
        killed.assert_not_called()
        self.assertEqual(events, [])

    # -- the safe boundary --------------------------------------------------

    def test_a_child_mid_turn_is_never_interrupted(self):
        runner = self.runner()
        self.write(190_000, trailing=[{"type": "user", "message": {
            "content": [{"type": "text", "text": "one more"}]}}])
        outcome, killed, events = self.cycle(runner)
        self.assertIsNone(outcome)
        killed.assert_not_called()
        held = [event for event in events
                if event["event"] == "context_backstop_held"]
        self.assertEqual(len(held), 1)
        # refused by the PREFLIGHT, long before the stop edge that backs it up
        self.assertEqual(held[0]["reason"],
                         "child is still working: a prompt is still awaiting "
                         "its answer")
        self.assertTrue(self.child.automation)
        self.assertFalse(self.child.supervision_loss_notified)

    def test_the_preflight_itself_refuses_a_busy_child(self):
        runner = self.runner()
        proof = runner._context_observation(self.child)
        self.write(190_000, trailing=[{"type": "user", "message": {
            "content": [{"type": "text", "text": "one more"}]}}])
        with self.assertRaisesRegex(supervisor.SupervisorError,
                                    "child is still working: a prompt is "
                                    "still awaiting its answer"):
            runner._context_backstop_preflight(self.child, proof)

    def test_a_transcript_still_being_written_defers_on_the_short_cadence(self):
        runner = self.runner()
        self.write(190_000, idle=0)
        outcome, killed, events = self.cycle(runner)
        self.assertIsNone(outcome)
        killed.assert_not_called()
        self.assertIn("changed recently",
                      [event.get("reason", "") for event in events][-1])
        self.assertEqual(self.child.context_next_check,
                         self.clock["t"] + supervisor.PREEMPT_POLL_SECONDS)

    def test_a_live_background_subagent_holds_the_rotation(self):
        runner = self.runner()
        directory = os.path.join(os.path.dirname(self.transcript), self.SID,
                                 "subagents")
        os.makedirs(directory)
        path = os.path.join(directory, "agent-a99d9789808.jsonl")
        with open(path, "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "isSidechain": True,
                                  "message": {"content": "go"}}) + "\n")
        when = time.time() - 600
        os.utime(path, (when, when))
        outcome, killed, events = self.cycle(runner)
        self.assertIsNone(outcome)
        killed.assert_not_called()
        self.assertEqual(
            events[-1]["reason"],
            "child is still working: a background subagent is answering its "
            "latest input")
        # and the preflight is the layer that says so
        proof = runner._context_observation(self.child)
        with self.assertRaisesRegex(supervisor.SupervisorError,
                                    "child is still working: a background "
                                    "subagent"):
            runner._context_backstop_preflight(self.child, proof)

    def test_a_cap_proof_in_flight_always_wins(self):
        runner = self.runner()
        self.assertTrue(runner._context_backstop_due(self.child, None))
        self.assertFalse(runner._context_backstop_due(self.child, object()))
        self.child.pending_cap = mock.Mock()
        self.assertFalse(runner._context_backstop_due(self.child, None))

    def test_the_operator_can_turn_it_off(self):
        with mock.patch.dict(os.environ, {"HEADROOM_CONTEXT_BACKSTOP": "0"}):
            runner = self.runner()
        self.assertFalse(runner._context_backstop_due(self.child, None))
        registry.save({"schema_version": 1, "accounts": [self.source],
                       "routing": {"context_backstop": False}})
        self.assertFalse(self.runner()._context_backstop_due(self.child, None))

    def test_a_disarmed_or_unbound_child_is_left_alone(self):
        runner = self.runner()
        self.child.automation = False
        self.assertFalse(runner._context_backstop_due(self.child, None))
        self.child.automation = True
        self.child.binding = None
        self.assertFalse(runner._context_backstop_due(self.child, None))

    # -- the limits of a same-seat rotation ---------------------------------

    def test_a_session_on_the_largest_window_is_not_restarted_for_nothing(self):
        self.child.spawn_args = ("--model", "opus[1m]", "--resume", self.SID)
        self.write(950_000)
        runner = self.runner()
        outcome, killed, events = self.cycle(runner)
        self.assertIsNone(outcome)
        killed.assert_not_called()
        self.assertEqual([event["event"] for event in events],
                         ["context_backstop_held"])
        self.assertIn("already on the largest context window",
                      events[0]["reason"])
        # ...unless the operator insists
        with mock.patch.object(supervisor, "CONTEXT_BACKSTOP_ALWAYS", True):
            outcome, killed, _events = self.cycle(runner)
        self.assertIsNotNone(outcome)
        # the fork gains no headroom, but the resume still has to NAME the
        # only window that can hold 950k tokens
        self.assertEqual(outcome.argv, ["--resume", self.SID, "--fork-session",
                                        "--model", "opus[1m]"])

    def test_the_budget_bounds_forced_rotations(self):
        runner = self.runner()
        runner.context_rotations = [self.clock["t"] - 60] \
            * supervisor.CONTEXT_BACKSTOP_MAX
        outcome, killed, events = self.cycle(runner)
        self.assertIsNone(outcome)
        killed.assert_not_called()
        self.assertIn("budget spent", events[0]["reason"])
        # an old rotation falls out of the window and the budget returns
        runner.context_rotations = [self.clock["t"] - supervisor.LOOP_WINDOW - 1] \
            * supervisor.CONTEXT_BACKSTOP_MAX
        self.child.context_last_hold = ""
        outcome, _killed, _events = self.cycle(runner)
        self.assertIsNotNone(outcome)

    # -- the stop itself ----------------------------------------------------

    def test_a_child_that_ignores_sigterm_disarms_instead_of_forking(self):
        runner = self.runner()
        kill, wait = self.stopping(runner, exits=False)
        with kill, wait, mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            outcome = runner._context_backstop_cycle(self.child)
        self.assertIsNone(outcome)
        self.assertFalse(self.child.automation)
        self.assertIn("supervision_lost",
                      [event["event"] for event in self.events(emit)])
        self.assertEqual(self.child.context_next_check,
                         self.clock["t"] + supervisor.PREEMPT_BACKOFF_SECONDS)

    def test_a_conversation_that_cannot_be_proven_clean_is_resumed_in_place(self):
        runner = self.runner()
        kill, wait = self.stopping(runner)
        with kill, wait, mock.patch.object(
                handoff, "inspect_transcript",
                side_effect=handoff.HandoffError(
                    "session stopped mid-tool-call (unresolved: t1)")), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            outcome = runner._context_backstop_cycle(self.child)
        self.assertIsNotNone(outcome)
        # no fork of a conversation we could not prove finished — but the
        # session still comes back, and still on a window it fits
        self.assertEqual(outcome.argv,
                         ["--resume", self.SID, "--model", "opus[1m]"])
        self.assertEqual(outcome.reason, "context_backstop_recovered")
        self.assertFalse(outcome.automatic)
        self.assertTrue(outcome.supervised)
        self.assertIn("forked resume degraded",
                      [event.get("reason", "")
                       for event in self.events(emit)][-2])

    def test_a_missing_session_end_degrades_the_resume_but_never_drops_it(self):
        runner = self.runner()
        with mock.patch.object(supervisor.os, "kill"), \
                mock.patch.object(runner, "_wait_stopped", return_value=0), \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            outcome = runner._context_backstop_cycle(self.child)
        self.assertEqual(outcome.reason, "context_backstop_recovered")
        self.assertEqual(outcome.argv,
                         ["--resume", self.SID, "--model", "opus[1m]"])

    def test_a_turn_starting_on_the_edge_cancels_the_kill(self):
        runner = self.runner()
        proof = runner._context_observation(self.child)
        with open(self.transcript, "a", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "one more"}]}}) + "\n")
        stat = handoff._transcript_stat(self.transcript)
        with self.assertRaisesRegex(supervisor.SupervisorError,
                                    "became busy before the context backstop"):
            runner._idle_stop_edge(self.child, proof, stat,
                                   label="context backstop")
        with self.assertRaisesRegex(
                supervisor.SupervisorError,
                "edge of a context backstop stop"):
            runner._idle_stop_edge(self.child, proof, proof.transcript_stat,
                                   label="context backstop")

    def test_a_turn_that_lands_between_the_proof_and_the_kill_is_spared(self):
        # the user hit enter after the preflight passed. The stat check cannot
        # see it (it landed before the stat was taken, as the identical
        # preemptive race shows), so ONLY the last-instant edge stands between
        # a live turn and a SIGTERM.
        runner = self.runner()
        proof = runner._context_observation(self.child)
        with open(self.transcript, "a", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "one more"}]}}) + "\n")
        with mock.patch.object(handoff, "_transcript_stat",
                               return_value=proof.transcript_stat), \
                mock.patch.object(supervisor.os, "kill") as killed, \
                mock.patch.object(runner, "_wait_stopped", return_value=0), \
                redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(
                    supervisor.SupervisorError,
                    "became busy before the context backstop stop"):
                runner._context_backstop_stop(self.child, proof)
        killed.assert_not_called()
        self.assertTrue(self.child.automation)

    def test_an_expired_decision_window_never_reaches_the_signal(self):
        runner = self.runner()
        proof = runner._context_observation(self.child)
        self.clock["t"] += supervisor.PREEMPT_DECISION_TTL + 1
        with mock.patch.object(supervisor.os, "kill") as killed, \
                redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(supervisor.SupervisorError,
                                        "decision window elapsed"):
                runner._context_backstop_stop(self.child, proof)
        killed.assert_not_called()

    def test_an_unread_hook_event_holds_the_rotation(self):
        runner = self.runner()
        with open(self.events_path, "a", encoding="utf-8") as out:
            out.write("{}\n")
        outcome, killed, events = self.cycle(runner)
        self.assertIsNone(outcome)
        killed.assert_not_called()
        self.assertIn("newer hook event",
                      [event.get("reason", "") for event in events][-1])

    # -- attribution: headroom's own kills are never anonymous --------------

    def ledger(self):
        path = os.path.join(paths.state_dir(), "handoffs.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as source:
            return [json.loads(line) for line in source if line.strip()]

    def test_the_stop_row_is_durable_BEFORE_the_signal(self):
        # The discipline _stop_and_commit's stop_sent already has: a crash can
        # never hide a stop, and an external kill must never be
        # indistinguishable from ours. Read the ledger AT THE MOMENT OF THE
        # SIGNAL rather than after — writing the row afterwards would satisfy
        # every other assertion here and still leave the 07:30Z signature.
        runner = self.runner()
        at_signal = []

        def kill(_pid, _signum):
            at_signal.extend(self.ledger())

        wait = self.stopping(runner)[1]
        with mock.patch.object(supervisor.os, "kill", side_effect=kill), wait, \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            outcome = runner._context_backstop_cycle(self.child)
        self.assertIsNotNone(outcome)
        self.assertEqual([row["action"] for row in at_signal],
                         ["context_stop_sent"])
        row = at_signal[0]
        self.assertEqual(row["schema"], handoff.SCHEMA)
        self.assertEqual(row["source_slot"], "source")
        self.assertEqual(row["old_session_id"], self.SID)
        self.assertEqual(row["child_generation"], 1)
        self.assertEqual(row["used"], 190_000)
        self.assertEqual(row["window"], 200_000)
        self.assertEqual(row["remaining_percent"], 5.0)
        self.assertTrue(handoff._valid_uuid(row["handoff_id"]))
        # the mixed-version contract: no `automatic` key, so an OLDER headroom
        # skips the row entirely instead of refusing the whole ledger
        self.assertNotIn("automatic", row)

    def test_a_stopped_row_records_the_exit_code_and_the_fork(self):
        runner = self.runner()
        outcome, _killed, _events = self.cycle(runner)
        self.assertIsNotNone(outcome)
        rows = self.ledger()
        self.assertEqual([row["action"] for row in rows],
                         ["context_stop_sent", "context_stopped"])
        # one rotation, one id, so the pair is joinable
        self.assertEqual(rows[0]["handoff_id"], rows[1]["handoff_id"])
        self.assertEqual(rows[1]["source_slot"], "source")
        self.assertEqual(rows[1]["old_session_id"], self.SID)
        self.assertEqual(rows[1]["child_generation"], 1)
        self.assertEqual(rows[1]["child_exit_code"], 0)
        self.assertIs(rows[1]["session_end"], True)
        self.assertEqual(rows[1]["degraded"], "")
        self.assertIs(rows[1]["forked"], True)
        self.assertNotIn("automatic", rows[1])

    def test_a_degraded_rotation_is_recorded_as_degraded(self):
        # the flags must match the branch actually taken, not the intent
        runner = self.runner()
        with mock.patch.object(supervisor.os, "kill"), \
                mock.patch.object(runner, "_wait_stopped", return_value=0), \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            outcome = runner._context_backstop_cycle(self.child)
        self.assertEqual(outcome.reason, "context_backstop_recovered")
        row = self.ledger()[-1]
        self.assertEqual(row["action"], "context_stopped")
        self.assertEqual(row["degraded"], "SessionEnd proof is missing")
        self.assertIs(row["forked"], False)

    def test_a_ledger_failure_before_the_signal_defers_instead_of_killing(self):
        # the row is on the ABORT side of the kill: a ledger it cannot write
        # can only cost a rotation, never orphan a session
        runner = self.runner()
        wait = self.stopping(runner)[1]
        with mock.patch.object(supervisor.os, "kill") as killed, wait, \
                mock.patch.object(
                    handoff, "append_ledger",
                    side_effect=handoff.HandoffError("disk full")), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            outcome = runner._context_backstop_cycle(self.child)
        self.assertIsNone(outcome)
        killed.assert_not_called()
        self.assertTrue(self.child.automation)
        self.assertFalse(self.child.supervision_loss_notified)
        self.assertIn("disk full", [event.get("reason", "")
                                    for event in self.events(emit)][-1])
        self.assertEqual(self.child.context_next_check,
                         self.clock["t"] + supervisor.PREEMPT_BACKOFF_SECONDS)

    def test_a_ledger_failure_after_the_signal_still_returns_the_relaunch(self):
        # after the signal there is no "refuse" left — the session MUST come
        # back, so the second row's failure is printed and swallowed
        runner = self.runner()
        real = handoff.append_ledger

        def append(record):
            if record.get("action") == "context_stopped":
                raise handoff.HandoffError("disk full")
            return real(record)

        kill, wait = self.stopping(runner)
        with kill as killed, wait, \
                mock.patch.object(handoff, "append_ledger", side_effect=append), \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()) as err:
            outcome = runner._context_backstop_cycle(self.child)
        killed.assert_called_once()
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.reason, "context_backstop")
        self.assertIn("could not record the context stop", err.getvalue())

    def test_the_backstop_rows_are_inert_to_every_automatic_reader(self):
        runner = self.runner()
        self.assertIsNotNone(self.cycle(runner)[0])
        rows = handoff._read_jsonl(handoff._ledger_path(), "handoff ledger")
        self.assertEqual(len(rows), 2)
        # _validated_automatic_rows (handoff.py:1117): no `automatic` key and
        # not cap_confirmed, so never safety-relevant. This is the assertion an
        # OLDER headroom's read of a NEWER ledger reduces to — widening
        # _AUTOMATIC_ACTIONS instead would have made that read RAISE and
        # disabled every automatic handoff on the fleet.
        self.assertEqual(handoff._validated_automatic_rows(rows), rows)
        # _previous_handoff (588) filters action == 'staged'
        self.assertIsNone(handoff._previous_handoff(self.SID, "sha"))
        handoff.guard_not_duplicate(self.SID, "sha")

    # -- the session must survive the rotation itself -----------------------

    def relaunched(self, runner, relaunch, fail_on=2):
        """Drive run() so the `fail_on`-th spawn fails unambiguously."""
        spawns = []

        def spawn(account, args, cwd, automatic, plan=None):
            spawns.append((account["name"], list(args), automatic))
            if len(spawns) == fail_on:
                runner.spawn_ambiguous = False   # positively no child started
                raise supervisor.SupervisorError(
                    "`claude` not found on PATH; nothing was started")
            child = mock.Mock()
            child.account = account
            child.generation = len(spawns)
            return child

        outcomes = iter([relaunch, 0])
        with mock.patch.object(runner, "_spawn", side_effect=spawn), \
                mock.patch.object(
                    runner, "_monitor",
                    side_effect=lambda child, pending="": next(outcomes)), \
                mock.patch.object(runner, "_reconcile_leases"), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()) as err:
            exit_code = runner.run()
        return exit_code, spawns, self.events(emit), err.getvalue()

    def rotation(self, recovery=True):
        """The Relaunch a successful backstop rotation hands back."""
        return supervisor.Relaunch(
            self.source,
            ["--resume", self.SID, "--fork-session", "--model", "opus[1m]"],
            self.cwd, True, reason="context_backstop", supervised=True,
            recovery=supervisor.Recovery(
                self.source, ["--resume", self.SID], self.cwd, self.SID)
            if recovery else None)

    def test_a_replacement_that_cannot_be_spawned_never_strands_the_session(self):
        # the child was ALREADY STOPPED by an elective rotation: exiting here
        # kills exactly the conversation the rotation exists to save. End to
        # end from the REAL rotation, so the recovery it carries is the one
        # under test, not a hand-built stand-in.
        runner = self.runner()
        outcome, _killed, _events = self.cycle(runner)
        exit_code, spawns, events, _err = self.relaunched(runner, outcome)
        self.assertEqual(exit_code, 0)
        self.assertEqual([name for name, _a, _s in spawns],
                         ["source", "source", "source"])
        # recovered on its own seat with the SIMPLER command, and SUPERVISED
        self.assertEqual(spawns[2][1], ["--resume", self.SID])
        self.assertTrue(spawns[2][2])
        self.assertNotIn("supervision_lost",
                         [event["event"] for event in events])
        held = [event for event in events
                if event["event"] == "context_backstop_held"]
        self.assertEqual(len(held), 1)
        self.assertIn("replacement spawn failed", held[0]["reason"])
        # and the recovered child is not immediately targeted again
        self.assertEqual(runner.context_hold_until,
                         self.clock["t"] + supervisor.PREEMPT_BACKOFF_SECONDS)

    def everything_fails(self, runner, relaunch):
        """run() where the replacement AND its recovery both refuse to start."""
        spawns = []

        def spawn(account, args, cwd, automatic, plan=None):
            spawns.append(list(args))
            runner.spawn_ambiguous = False
            if len(spawns) == 1:
                child = mock.Mock()
                child.account = account
                child.generation = 1
                return child
            raise supervisor.SupervisorError("nothing was started")

        with mock.patch.object(runner, "_spawn", side_effect=spawn), \
                mock.patch.object(
                    runner, "_monitor",
                    side_effect=lambda child, pending="": relaunch), \
                mock.patch.object(runner, "_reconcile_leases"), \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()) as err:
            exit_code = runner.run()
        return exit_code, spawns, err.getvalue()

    def degraded_rotation(self, runner):
        """A rotation whose stop could not be proven clean (no SessionEnd)."""
        with mock.patch.object(supervisor.os, "kill"), \
                mock.patch.object(runner, "_wait_stopped", return_value=0), \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            return runner._context_backstop_cycle(self.child)

    def test_a_recovery_identical_to_the_replacement_is_still_attached(self):
        # HEADROOM_CTX_WINDOW=500000 + a 480k transcript + a degraded stop:
        # the fallback command comes out IDENTICAL to the one that just
        # failed, and skipping it there left an already-stopped session with
        # no recovery at all and an exit 127
        with mock.patch.dict(os.environ, {"HEADROOM_CTX_WINDOW": "500000"}):
            self.write(480_000)
            runner = self.runner()
            outcome = self.degraded_rotation(runner)
            self.assertEqual(outcome.reason, "context_backstop_recovered")
            self.assertIsNotNone(outcome.recovery)
            self.assertEqual(outcome.recovery.argv, outcome.argv)
            self.assertIn("--model", outcome.recovery.argv)
            exit_code, spawns, events, _err = self.relaunched(runner, outcome)
        # a plain retry of the same command IS a recovery — spawn failures are
        # not always about the argv
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(spawns), 3)
        self.assertEqual(spawns[2][1], outcome.recovery.argv)
        self.assertTrue(spawns[2][2])          # SUPERVISED
        self.assertNotIn("supervision_lost",
                         [event["event"] for event in events])

    def test_every_rotation_shape_carries_a_recovery(self):
        for degraded in (False, True):
            self.write(190_000)
            runner = self.runner()
            outcome = (self.degraded_rotation(runner) if degraded
                       else self.cycle(runner)[0])
            self.assertIsNotNone(outcome.recovery, degraded)
            self.assertEqual(outcome.recovery.session_id, self.SID)
            self.assertEqual(outcome.recovery.account["name"], "source")

    def test_a_recovery_that_also_fails_leaves_a_usable_resume_command(self):
        # both the replacement AND its recovery refuse to start: the user gets
        # the one command that brings the conversation back by hand
        runner = self.runner()
        exit_code, spawns, err = self.everything_fails(runner, self.rotation())
        self.assertEqual(exit_code, 127)
        self.assertEqual(len(spawns), 3)
        self.assertIn("--resume " + self.SID, err)
        self.assertIn(self.source["home"], err)

    def test_the_manual_command_is_the_stored_argv_not_a_reconstruction(self):
        # a rebuilt resume command drops the model a large transcript REQUIRES
        # and re-adds a fork that a degraded stop already ruled unsafe
        runner = self.runner()
        recovery = supervisor.Recovery(
            self.source,
            ["--resume", self.SID, "--model", "claude-sonnet-5[1m]"],
            self.cwd, self.SID)
        relaunch = supervisor.Relaunch(
            self.source, list(recovery.argv), self.cwd, False,
            reason="context_backstop_recovered", supervised=True,
            recovery=recovery)
        _exit, _spawns, err = self.everything_fails(runner, relaunch)
        printed = [line for line in err.splitlines()
                   if line.startswith("CLAUDE_CONFIG_DIR=")]
        self.assertEqual(len(printed), 1)
        self.assertEqual(
            printed[0],
            f"CLAUDE_CONFIG_DIR={self.source['home']} claude --resume "
            f"{self.SID} --model 'claude-sonnet-5[1m]'")
        self.assertNotIn("--fork-session", printed[0])

    def stop_failure(self):
        """A valid StopFailure hook row bound to this child's session."""
        return {"schema": "headroom_hook_event@1",
                "supervisor_id": os.path.splitext(
                    os.path.basename(self.child.event_path))[0],
                "generation": 1, "source_slot": "source",
                "config_dir": self.source["home"], "matcher": "rate_limit",
                "received_at": self.clock["t"] + 1,
                "payload": {"hook_event_name": "StopFailure",
                            "session_id": self.SID,
                            "transcript_path": self.transcript,
                            "cwd": self.cwd, "error": "rate_limit"}}

    def test_a_child_that_exits_a_moment_after_the_race_still_comes_back(self):
        # the racing event lands while the child is still dying. Sampling
        # poll() once would read that as "ignored SIGTERM", disarm, and hand
        # back NO relaunch — stranding a session that was already stopped.
        runner = self.runner()
        proof = runner._context_observation(self.child)
        alive = iter([None, None])
        self.child.process.poll.side_effect = lambda: next(alive, 0)
        with mock.patch.object(supervisor, "_read_events",
                               return_value=[self.stop_failure()]), \
                mock.patch.object(supervisor.os, "kill"), \
                mock.patch.object(notify, "emit"), \
                redirect_stderr(io.StringIO()):
            outcome = runner._context_backstop_stop(self.child, proof)
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.reason, "context_backstop_recovered")
        self.assertTrue(self.child.automation)
        self.assertFalse(self.child.supervision_loss_notified)

    def test_a_cap_landing_during_the_context_stop_is_never_swallowed(self):
        # absorbing it would resume the conversation on a seat that has just
        # been refused; the fork is abandoned and the cap path takes over
        runner = self.runner()
        proof = runner._context_observation(self.child)
        record = self.stop_failure()
        self.child.process.poll.return_value = 0
        with mock.patch.object(supervisor, "_read_events",
                               return_value=[record]), \
                mock.patch.object(supervisor.os, "kill"), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()):
            outcome = runner._context_backstop_stop(self.child, proof)
        self.assertIsNotNone(outcome)          # the session still comes back
        self.assertNotIn("--fork-session", outcome.argv)
        self.assertEqual(outcome.reason, "context_backstop_recovered")
        self.assertTrue(outcome.supervised)    # cap handoff stays armed
        self.assertTrue(self.child.automation)
        reasons = [event.get("reason", "") for event in self.events(emit)]
        self.assertIn("a subscription cap landed during the context stop",
                      reasons[-1])

    def test_the_same_race_is_still_absorbed_for_a_seat_rotation(self):
        # the preemptive/cap contract is unchanged: those stops DO have a
        # reserved target on another seat, so a racing cap is corroboration
        runner = self.runner()
        proof = runner._context_observation(self.child)
        seat_proof = supervisor.PreemptiveProof(
            event={"received_at": self.clock["t"]}, message="7d at 96%",
            family="fable", session_id=proof.session_id,
            transcript_path=proof.transcript_path, epoch=proof.epoch,
            transcript_stat=proof.transcript_stat, window="7d",
            used_percent=96.0, deadline=self.clock["t"] + 120)
        with mock.patch.object(supervisor, "_read_events",
                               return_value=[self.stop_failure()]), \
                redirect_stderr(io.StringIO()):
            runner._consume_stop_events(self.child, seat_proof,
                                        self.clock["t"])
        self.assertTrue(self.child.automation)

    def test_the_monitor_loop_returns_the_forced_rotation(self):
        runner = self.runner()
        relaunch = supervisor.Relaunch(self.source, ["--resume", self.SID],
                                       self.cwd, True,
                                       reason="context_backstop")
        with mock.patch.object(runner, "_handle_events", return_value=None), \
                mock.patch.object(runner, "_preemptive_cycle",
                                  return_value=None), \
                mock.patch.object(runner, "_context_backstop_cycle",
                                  return_value=relaunch) as cycle, \
                redirect_stderr(io.StringIO()):
            self.assertIs(runner._monitor(self.child), relaunch)
        cycle.assert_called_once()



# --------------------------------------------------------------------------
# A cap that lands while supervision is off must be LOUD, never swallowed
# --------------------------------------------------------------------------
class UnhandledCapIsAnnounced(TempDirCase):
    """Live failure, 2026-07-31: the Fable weekly pool ran out mid-session.
    The StopFailure hook fired and journaled with the account's own "out of
    usage credits" wording, the binding was correct — and nothing happened,
    because automation had already been turned off earlier in the run. No
    rotation, and worse, no reason: the operator learned about the wall from
    the model's reply, not from headroom. Acting is still wrong here (an
    unsupervised child is not ours to rotate), so the contract is to SAY so."""

    SID = "11111111-1111-1111-1111-111111111111"

    def _child(self, account, automation):
        binding = supervisor.Binding(self.SID, "/t.jsonl", "/cwd", "fable",
                                     "1", account["home"], epoch=1)
        return supervisor.Child(
            process=mock.Mock(), account=account, generation=1,
            event_path="/dev/null", settings_path="", launched_at=0.0,
            automation=automation, binding=binding, session_epoch=1)

    def _event(self, message):
        return {
            "schema": "headroom_hook_event@1", "received_at": 1000.0,
            "supervisor_id": "22222222-2222-2222-2222-222222222222",
            "generation": 1, "source_slot": "a", "config_dir": "/home/a",
            "matcher": "rate_limit",
            "payload": {"hook_event_name": "StopFailure", "session_id": self.SID,
                        "transcript_path": "/t.jsonl", "cwd": "/cwd",
                        "error": "rate_limit", "last_assistant_message": message},
        }

    def _run(self, message, automation=False):
        account = self.account()
        runner = supervisor.Supervisor("fable", [], account, popen=mock.Mock())
        child = self._child(account, automation)
        with mock.patch.object(supervisor, "_read_events",
                               return_value=[self._event(message)]), \
                mock.patch.object(supervisor, "_namespace_matches",
                                  return_value=True), \
                mock.patch.object(supervisor, "_validated_event",
                                  return_value=(supervisor.Binding(
                                      self.SID, "/t.jsonl", "/cwd", "fable",
                                      "1", account["home"], epoch=1), "/cwd")), \
                mock.patch.object(supervisor, "_event_epoch", return_value=1), \
                mock.patch.object(supervisor, "_accept_event_order"), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()) as errors:
            runner._handle_events(child, "")
        return errors.getvalue(), [call.args[0] for call in emit.call_args_list]

    def test_credits_cap_with_automation_off_is_announced(self):
        errors, events = self._run(
            "You're out of usage credits. Run /usage-credits to keep using "
            "Fable 5 or /model to switch models.")
        self.assertIn("hit a subscription cap", errors)
        self.assertIn("NO automatic handoff", errors)
        self.assertIn("supervision is off", errors)
        self.assertIn("/model opus", errors)      # the manual remedy, in place
        self.assertEqual([event["event"] for event in events],
                         ["cap_unhandled"])

    def test_a_non_cap_stop_failure_stays_quiet(self):
        # a transient 429 is NOT a cap; announcing it would train the operator
        # to ignore the message that matters
        errors, events = self._run(
            "429 rate_limit_error: please try again later")
        self.assertEqual(errors, "")
        self.assertEqual(events, [])

    def test_armed_children_still_take_the_normal_cap_path(self):
        # the announcement must not shadow the real handler
        account = self.account()
        runner = supervisor.Supervisor("fable", [], account, popen=mock.Mock())
        child = self._child(account, automation=True)
        with mock.patch.object(supervisor, "_read_events",
                               return_value=[self._event("out of usage credits")]), \
                mock.patch.object(supervisor, "_namespace_matches",
                                  return_value=True), \
                mock.patch.object(supervisor, "_validated_event",
                                  return_value=(child.binding, "/cwd")), \
                mock.patch.object(supervisor, "_event_epoch", return_value=1), \
                mock.patch.object(supervisor, "_accept_event_order"), \
                mock.patch.object(runner, "_attempt_cap") as attempt, \
                redirect_stderr(io.StringIO()) as errors:
            runner._handle_events(child, "")
        attempt.assert_called_once()
        self.assertNotIn("NO automatic handoff", errors.getvalue())

    # -- the child that never bound a session ------------------------------
    #
    # cap_message returns "" on its BINDING gate before it ever looks at the
    # record, so for an unbound child the announce branch found nothing to
    # say and hit its bare `continue`: no stderr, no notify, no record of the
    # decision anywhere. _binding_key(None) is None, so the post-loop "session
    # ended without a replacement SessionStart" line does not fire either.
    # Totally dark — and BIND_TIMEOUT is 30s, so a SessionStart that fails to
    # bind leaves a live child in exactly this state.

    def _unbound_run(self, message, automation=False, matcher="rate_limit",
                     error="rate_limit"):
        """The same drive as _run, but with NO binding on the child — so
        nothing here may be routed through _validated_event, which needs one."""
        account = self.account()
        runner = supervisor.Supervisor("fable", [], account, popen=mock.Mock())
        child = supervisor.Child(
            process=mock.Mock(), account=account, generation=1,
            event_path="/dev/null", settings_path="", launched_at=0.0,
            automation=automation, binding=None, session_epoch=1)
        event = self._event(message)
        event["matcher"] = matcher
        event["payload"]["error"] = error
        if message is None:
            event["payload"].pop("last_assistant_message")
        with mock.patch.object(supervisor, "_read_events",
                               return_value=[event]), \
                mock.patch.object(supervisor, "_namespace_matches",
                                  return_value=True), \
                mock.patch.object(supervisor, "_validated_event",
                                  return_value=(supervisor.Binding(
                                      self.SID, "/t.jsonl", "/cwd", "fable",
                                      "1", account["home"], epoch=1), "/cwd")), \
                mock.patch.object(supervisor, "_event_epoch", return_value=1), \
                mock.patch.object(supervisor, "_accept_event_order"), \
                mock.patch.object(runner, "_attempt_cap") as attempt, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()) as errors:
            runner._handle_events(child, "")
        return (errors.getvalue(),
                [call.args[0] for call in emit.call_args_list],
                attempt, child)

    def test_an_unbound_childs_cap_is_announced_not_swallowed(self):
        """(a) The dark case. 27 of 35 real StopFailure records carry the cap
        text in their own payload, so the announcement does not need a
        binding — only ACTING does."""
        errors, events, attempt, child = self._unbound_run(
            "You're out of usage credits. Run /usage-credits to keep using "
            "Fable 5 or /model to switch models.")
        self.assertIn("hit a subscription cap", errors)
        self.assertIn("never bound a session", errors)
        self.assertIn("/model opus", errors)
        self.assertEqual([event["event"] for event in events],
                         ["cap_unhandled"])
        self.assertIs(events[0]["bound"], False)
        # SAYING is not ACTING: an unbound child is not ours to rotate
        attempt.assert_not_called()
        self.assertTrue(child.automation is False)

    def test_the_bound_child_still_reports_bound_true(self):
        """(4) The two dark shapes must be tellable apart by an observer."""
        _errors, events = self._run(
            "You're out of usage credits. Run /usage-credits to keep using "
            "Fable 5.")
        self.assertIs(events[0]["bound"], True)

    def test_a_foreign_session_finally_reaches_its_own_reason(self):
        """(c) The branch d24a613 shipped DEAD.

        "the event is from another session" needed automation True and
        same_session False — but _validated_event raises "hook event belongs
        to a different session epoch" for exactly that pair, before
        cap_message could return any text, so the branch could never run.
        Reached now via the payload-only path, which never validates."""
        account = self.account()
        runner = supervisor.Supervisor("fable", [], account, popen=mock.Mock())
        child = self._child(account, automation=True)
        foreign = "99999999-9999-4999-8999-999999999999"
        event = self._event("You're out of usage credits, Fable 5")
        event["payload"]["session_id"] = foreign

        def validated(_record, _child, binding=None):
            # Modelled exactly as the real one behaves for this record: the
            # LOOP's binding-free call succeeds (namespace, slot, paths are
            # all fine), and cap_message's BINDING-scoped call is the one that
            # raises. That raise is precisely why the third `why` branch could
            # never run — cap_message returned "" before it could be reached.
            if binding is not None:
                raise supervisor.SupervisorError(
                    "hook event belongs to a different session epoch")
            return (supervisor.Binding(foreign, "/t.jsonl", "/cwd", "fable",
                                       "1", account["home"], epoch=1), "/cwd")

        with mock.patch.object(supervisor, "_read_events",
                               return_value=[event]), \
                mock.patch.object(supervisor, "_namespace_matches",
                                  return_value=True), \
                mock.patch.object(supervisor, "_validated_event",
                                  side_effect=validated), \
                mock.patch.object(supervisor, "_event_epoch", return_value=1), \
                mock.patch.object(supervisor, "_accept_event_order"), \
                mock.patch.object(runner, "_attempt_cap") as attempt, \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()) as errors:
            runner._handle_events(child, "")
        self.assertIn("does not match this child's live session",
                      errors.getvalue())
        self.assertEqual([call.args[0]["event"]
                          for call in emit.call_args_list], ["cap_unhandled"])
        attempt.assert_not_called()

    def test_an_unbound_non_cap_stop_failure_is_still_quiet(self):
        """(d) The new path must not become chatty. A transient 429 is not a
        cap, and announcing it trains the operator to ignore the one that
        matters."""
        errors, events, _attempt, _child = self._unbound_run(
            "429 rate_limit_error: please try again later")
        self.assertEqual(errors, "")
        self.assertEqual(events, [])

    def test_an_unbound_child_with_nothing_to_read_stays_silent(self):
        """...and a payload that says nothing about itself has no transcript
        to fall back on — there is no binding to read one through. Stated in
        the docstring rather than papered over."""
        errors, events, _attempt, _child = self._unbound_run(None)
        self.assertEqual(errors, "")
        self.assertEqual(events, [])

    def test_cap_message_still_falls_back_to_the_transcript(self):
        """(e) One direction of the sentinel. A record that IS an in-class
        rate-limit StopFailure but describes nothing about itself is the ONE
        empty answer that may reach the transcript. If `absent=None` is ever
        dropped at the call site, this is what fails — and it fails toward a
        MISSED cap, never a fabricated one."""
        account = self.account()
        child = self._child(account, automation=True)
        event = self._event(None)
        event["payload"].pop("last_assistant_message")
        with mock.patch.object(supervisor, "_validated_event",
                               return_value=(child.binding, "/cwd")), \
                mock.patch.object(supervisor, "_last_transcript_cap",
                                  return_value="You've hit your weekly limit"
                                  ) as fallback:
            self.assertEqual(supervisor.cap_message(event, child),
                             "You've hit your weekly limit")
        fallback.assert_called_once_with("/t.jsonl")

    def test_a_payload_that_says_NOT_a_cap_never_opens_the_transcript(self):
        """(e) The other direction, and the one that matters: a record that
        speaks for itself and is not a cap is a DECISION, not an absence. The
        transcript gets no second vote — asserted on the read count, not just
        on the return value."""
        account = self.account()
        child = self._child(account, automation=True)
        event = self._event("429 rate_limit_error: please try again later")
        with mock.patch.object(supervisor, "_validated_event",
                               return_value=(child.binding, "/cwd")), \
                mock.patch.object(supervisor, "_last_transcript_cap",
                                  return_value="You've hit your weekly limit"
                                  ) as fallback:
            self.assertEqual(supervisor.cap_message(event, child), "")
        fallback.assert_not_called()


class CapClassIsNotDelegatedToTheTranscript(TempDirCase):
    """(g) THE DISCRIMINATING TEST for the P5 extraction, on the ACTING path.

    `cap_message` produces "" for five distinct reasons and they are NOT
    interchangeable. Three are cap-CLASS gates — not a StopFailure, not the
    `rate_limit` matcher, an error type that is not `rate_limit` — and each
    means THIS RECORD IS NOT A RATE-LIMIT REFUSAL AT ALL. HEAD answers all
    three without ever opening the transcript. The other two are about what
    an in-class record SAID, and only one of those (payload silent) may fall
    through to `_last_transcript_cap`.

    A refactor that collapses the five into one falsy answer and then
    reconstructs which one happened by re-reading the payload can only tell
    "self-described" from "said nothing". So a record that failed the MATCHER
    or ERROR-TYPE gate and carries no payload text becomes indistinguishable
    from an in-class silent one: it reads the transcript, finds a cap left
    there earlier in the session still sitting as the newest main-chain
    assistant record, and returns a STALE CAP.

    That is on the live acting path, not a hypothetical. `_read_events` only
    requires `matcher` to be a str; the hook writes
    `environ.get("HEADROOM_HOOK_MATCHER", "")`, so `matcher == ""` is routine,
    and `error == "api_error"` is another ordinary shape. `_handle_events`
    hands exactly such a record to `_attempt_cap`, which reaches `cap_message`
    through `_prove_cap` — and a non-empty return there opens a PendingCap and
    can drive a ROTATION OFF A NON-CAP.

    This test passes on HEAD and on the sentinel form, and fails on the
    collapsed form. The rest of the suite does not discriminate between them
    at all, which is the entire reason it exists."""

    SID = "33333333-3333-4333-8333-333333333333"

    def setUp(self):
        super().setUp()
        self.account_ = self.account()
        directory = os.path.join(self.account_["home"], "projects", "p")
        os.makedirs(directory, exist_ok=True)
        self.transcript = os.path.join(directory, self.SID + ".jsonl")
        # A REAL transcript whose newest main-chain assistant record IS a cap
        # — exactly what _last_transcript_cap is built to return. Nothing
        # below may be allowed to reach it.
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant", "message": {
                    "model": "claude-fable-5-20260701",
                    "content": [{"type": "text", "text": "real turn"}]}}) + "\n")
            out.write(json.dumps({
                "type": "assistant", "isApiErrorMessage": True,
                "error": "rate_limit", "apiErrorStatus": 429,
                "message": {"model": "<synthetic>", "content": [
                    {"type": "text",
                     "text": "You've hit your weekly limit · resets 3pm"}]}
            }) + "\n")
        when = time.time() - 600
        os.utime(self.transcript, (when, when))
        self.binding = supervisor.Binding(
            self.SID, self.transcript, "/cwd", "Fable", "1",
            self.account_["home"], epoch=1)

    def child(self):
        return supervisor.Child(
            process=mock.Mock(), account=self.account_, generation=1,
            event_path=os.path.join(self.temp.name, "no-events.jsonl"),
            settings_path="", launched_at=0.0, automation=True,
            binding=self.binding, session_epoch=1)

    def record(self, matcher="rate_limit", error="rate_limit"):
        """An in-session StopFailure that says NOTHING about itself: no
        last_assistant_message, no error_details."""
        return {
            "schema": "headroom_hook_event@1", "received_at": 1000.0,
            "supervisor_id": "no-events", "generation": 1,
            "source_slot": self.account_["name"],
            "config_dir": self.account_["home"], "matcher": matcher,
            "payload": {"hook_event_name": "StopFailure",
                        "session_id": self.SID,
                        "transcript_path": self.transcript,
                        "cwd": "/cwd", "error": error},
        }

    def drive(self, record):
        """The real acting path: same_session true, automation on, so
        _handle_events reaches _attempt_cap -> _prove_cap -> cap_message."""
        runner = supervisor.Supervisor(
            "fable", [], self.account_, popen=mock.Mock())
        child = self.child()
        reads = {"n": 0}
        real_last = supervisor._last_transcript_cap

        def counting(path):
            reads["n"] += 1
            return real_last(path)

        with mock.patch.object(supervisor, "_read_events",
                               return_value=[record]), \
                mock.patch.object(supervisor, "_namespace_matches",
                                  return_value=True), \
                mock.patch.object(supervisor, "_validated_event",
                                  return_value=(self.binding, "/cwd")), \
                mock.patch.object(supervisor, "_event_epoch", return_value=1), \
                mock.patch.object(supervisor, "_accept_event_order"), \
                mock.patch.object(supervisor, "_last_transcript_cap",
                                  side_effect=counting), \
                mock.patch.object(supervisor, "PendingCap",
                                  wraps=supervisor.PendingCap) as pending, \
                redirect_stderr(io.StringIO()) as errors:
            proof = runner._handle_events(child, "")
            direct = supervisor.cap_message(record, child)
        return proof, direct, reads["n"], pending.call_count, errors.getvalue()

    def test_an_empty_matcher_is_out_of_class_not_merely_silent(self):
        """(g1) `matcher == ""` — the shape the hook writes whenever no
        matcher was supplied. Out of class: the transcript may not speak."""
        proof, direct, reads, pendings, errors = self.drive(
            self.record(matcher=""))
        self.assertEqual(direct, "")
        self.assertEqual(reads, 0, "the transcript got a vote it must not have")
        self.assertEqual(pendings, 0, "a non-cap opened a PendingCap")
        self.assertIsNone(proof, "a non-cap produced a CapProof")
        self.assertIn("was not a subscription cap", errors)

    def test_an_api_error_type_is_out_of_class_not_merely_silent(self):
        """(g2) `payload["error"] == "api_error"` — an ordinary non-cap
        failure shape. Same rule."""
        proof, direct, reads, pendings, errors = self.drive(
            self.record(error="api_error"))
        self.assertEqual(direct, "")
        self.assertEqual(reads, 0, "the transcript got a vote it must not have")
        self.assertEqual(pendings, 0, "a non-cap opened a PendingCap")
        self.assertIsNone(proof, "a non-cap produced a CapProof")
        self.assertIn("was not a subscription cap", errors)

    def test_the_control_an_IN_CLASS_silent_record_DOES_read_it(self):
        """The control, without which the two above prove nothing: the same
        fixture, in class, still falls through to the transcript and still
        finds the cap. If only the two above pass, the fallback is simply
        dead and the extraction broke something else."""
        proof, direct, reads, _pendings, _errors = self.drive(self.record())
        self.assertIn("You've hit your weekly limit", direct)
        self.assertGreaterEqual(reads, 1)
        self.assertIsNotNone(proof)


# --------------------------------------------------------------------------
# THE TRAIN KEEPS MOVING: birth race must not disarm, caps must downgrade
# --------------------------------------------------------------------------
class TranscriptBirthRace(TempDirCase):
    """Live failure, 2026-07-31: Claude fires SessionStart BEFORE writing the
    transcript. The identity check reads that file, so every lane on the
    estate booted with 'malformed hook event (transcript no longer exists);
    automatic handoff disabled'. Disarmed lanes cannot rotate, so each one
    later died at its first cap with capacity sitting unused on other seats."""

    SID = "11111111-1111-1111-1111-111111111111"

    def test_a_transcript_being_born_is_waited_for_not_rejected(self):
        path = os.path.join(self.temp.name, self.SID + ".jsonl")
        account = self.account()
        child = mock.Mock(account=account)
        calls = {"n": 0}

        def fake_source(transcript, session_id, accounts, **kw):
            calls["n"] += 1
            if calls["n"] < 3:      # the file lands on the third look
                raise handoff.HandoffError(
                    f"session {session_id} transcript no longer exists")
            return "SOURCE"

        with mock.patch.object(handoff, "_source", side_effect=fake_source), \
                mock.patch.object(supervisor, "TRANSCRIPT_GRACE_SECONDS", 5.0):
            result = supervisor._source_once_written(
                path, self.SID, child, account["home"], sleep=lambda s: None,
                now=lambda: 0.0)
        self.assertEqual(result, "SOURCE")
        self.assertEqual(calls["n"], 3)

    def test_a_transcript_that_never_arrives_still_fails_closed(self):
        account = self.account()
        child = mock.Mock(account=account)
        clock = {"t": 0.0}

        def fake_source(*a, **kw):
            clock["t"] += 1.0
            raise handoff.HandoffError("session X transcript no longer exists")

        with mock.patch.object(handoff, "_source", side_effect=fake_source), \
                mock.patch.object(supervisor, "TRANSCRIPT_GRACE_SECONDS", 2.0):
            with self.assertRaises(handoff.HandoffError):
                supervisor._source_once_written(
                    "/x.jsonl", "X", child, account["home"],
                    sleep=lambda s: None, now=lambda: clock["t"])

    def test_a_real_identity_failure_is_not_retried(self):
        # a symlinked/foreign transcript must fail on the FIRST look — the
        # grace window exists for birth, never for a forged event
        account = self.account()
        child = mock.Mock(account=account)
        calls = {"n": 0}
        # The clock ADVANCES even though this case must not loop at all. A
        # frozen clock makes the regression this test exists to catch (losing
        # the substring guard) spin forever instead of failing: mock's
        # call_args_list grows until the runner is OOM-killed, which on this
        # box means eating memory next to live lanes. A test that catches a
        # mutation must catch it as an assertion, in milliseconds.
        clock = {"t": 0.0}

        def fake_source(*a, **kw):
            calls["n"] += 1
            clock["t"] += 1.0
            raise handoff.HandoffError("source transcript is a symlink")

        with mock.patch.object(handoff, "_source", side_effect=fake_source):
            with self.assertRaises(handoff.HandoffError):
                supervisor._source_once_written(
                    "/x.jsonl", "X", child, account["home"],
                    sleep=lambda s: None, now=lambda: clock["t"])
        self.assertEqual(calls["n"], 1)

    def test_an_unreadable_transcript_is_not_a_missing_one(self):
        # _contained_transcript used to fold EVERY lstat error into "no longer
        # exists", which would put a permission or ENOTDIR failure — neither
        # of which heals — into the birth-race retry.
        directory = os.path.join(self.temp.name, "projects", "p")
        os.makedirs(directory, exist_ok=True)
        not_a_dir = os.path.join(directory, "file")
        with open(not_a_dir, "w", encoding="utf-8"):
            pass
        with self.assertRaises(handoff.HandoffError) as caught:
            handoff._contained_transcript(
                os.path.join(not_a_dir, self.SID + ".jsonl"), self.SID,
                self.account())
        self.assertNotIn("no longer exists", str(caught.exception))
        self.assertIn("cannot be read", str(caught.exception))

    def test_the_grace_is_actually_WIRED_INTO_the_identity_check(self):
        """The three tests above prove `_source_once_written` waits. None of
        them prove `_validated_event` CALLS it — and that one line is the
        whole first half of this fix. Reverted, a SessionStart that beats its
        own transcript to disk raises PermanentSupervisorError, _handle_events
        disarms the child, and the estate-wide 2026-07-31 failure is back,
        with the suite still green."""
        account = self.account()
        os.makedirs(os.path.join(account["home"], "projects", "p"),
                    exist_ok=True)
        path = os.path.join(account["home"], "projects", "p",
                            self.SID + ".jsonl")
        with open(path, "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "hi"}]}}) + "\n")
        cwd = os.path.join(self.temp.name, "work")
        os.makedirs(cwd, exist_ok=True)
        child = mock.Mock(account=account, binding=None,
                          launched_at=time.time() - 60)
        record = {"source_slot": account["name"],
                  "config_dir": account["home"],
                  "received_at": time.time(),
                  "payload": {"session_id": self.SID,
                              "transcript_path": path, "cwd": cwd}}
        real = handoff._source
        calls = {"n": 0}

        def born_late(*a, **kw):
            calls["n"] += 1
            if calls["n"] == 1:        # the hook won the race, as it does live
                raise handoff.HandoffError(
                    f"session {self.SID} transcript no longer exists")
            return real(*a, **kw)

        with mock.patch.object(supervisor, "_namespace_matches",
                               return_value=True), \
                mock.patch.object(handoff, "_source", side_effect=born_late), \
                mock.patch.object(supervisor, "TRANSCRIPT_GRACE_STEP", 0.0):
            validated = supervisor._validated_event(record, child)
        source = validated[0] if isinstance(validated, tuple) else validated
        self.assertEqual(source.session_id, self.SID)
        self.assertGreater(calls["n"], 1)   # it really did retry, not luck

    def test_the_grace_window_is_tolerant_and_finite(self):
        # the project's numeric-env convention: junk must not crash import,
        # and `inf` must not turn a bounded wait into a permanent one — this
        # poll also drives cap detection and exit handling
        for raw in (None, "", "bad", "inf", "nan", "-inf"):
            self.assertEqual(supervisor._grace_seconds(raw), 3.0, raw)
        self.assertEqual(supervisor._grace_seconds("0"), 0.0)
        self.assertEqual(supervisor._grace_seconds("1.5"), 1.5)
        self.assertEqual(supervisor._grace_seconds("-5"), 0.0)
        self.assertEqual(supervisor._grace_seconds("9999"), 30.0)


class CapFamilyDowngrade(TempDirCase):
    """Paul's rule: a spent weekly pool costs a session its model tier, not
    its life. When no seat can serve the capped family, the cap handoff walks
    DOWN the ladder rather than holding the conversation until reset."""

    def runner(self):
        return supervisor.Supervisor("fable", [], self.account(),
                                     popen=mock.Mock())

    def test_downgrades_to_the_next_family_a_seat_can_serve(self):
        run = self.runner()
        child = mock.Mock(account={"name": "a"})
        served = {"opus": {"name": "b"}}

        def in_family(_child, family, _snapshot):
            if family in served:
                return served[family]
            raise supervisor.CapacityHold(f"no seat for {family}")

        with mock.patch.object(supervisor.Supervisor, "_cap_target_in_family",
                               side_effect=in_family), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()) as errors:
            target, family = run._cap_target(child, "fable", {})
        self.assertEqual((target["name"], family), ("b", "opus"))
        self.assertIn("moving this session to opus", errors.getvalue())
        self.assertEqual([e["event"] for e in
                          [call.args[0] for call in emit.call_args_list]],
                         ["family_downgrade"])

    def test_never_promotes_above_the_capped_family(self):
        # capped on sonnet: fable/opus are ABOVE it and must never be tried,
        # or a cap would hand the session more capacity than it just spent
        run = self.runner()
        tried = []

        def in_family(_child, family, _snapshot):
            tried.append(family)
            raise supervisor.CapacityHold("none")

        with mock.patch.object(supervisor.Supervisor, "_cap_target_in_family",
                               side_effect=in_family):
            with self.assertRaises(supervisor.CapacityHold):
                run._cap_target(mock.Mock(account={"name": "a"}), "sonnet", {})
        self.assertEqual(tried, ["sonnet", "haiku"])

    def test_same_family_still_wins_when_a_seat_has_room(self):
        run = self.runner()
        with mock.patch.object(supervisor.Supervisor, "_cap_target_in_family",
                               return_value={"name": "b"}), \
                mock.patch.object(notify, "emit") as emit, \
                redirect_stderr(io.StringIO()) as errors:
            target, family = run._cap_target(
                mock.Mock(account={"name": "a"}), "fable", {})
        self.assertEqual((target["name"], family), ("b", "fable"))
        self.assertEqual(errors.getvalue(), "")   # no downgrade announcement
        emit.assert_not_called()

    def test_a_fleet_with_no_room_anywhere_still_holds(self):
        run = self.runner()
        with mock.patch.object(supervisor.Supervisor, "_cap_target_in_family",
                               side_effect=supervisor.CapacityHold("walled")):
            with self.assertRaises(supervisor.CapacityHold):
                run._cap_target(mock.Mock(account={"name": "a"}), "fable", {})

    def test_the_hold_names_the_family_that_capped_not_the_last_one_tried(self):
        # the hold reason reaches the operator's terminal and the cap_held
        # ledger reason. `first_hold or hold` keeps the FIRST refusal; taking
        # the last would report "for the haiku family" on a Fable cap — a 3am
        # diagnostic pointing at a model the session never ran.
        run = self.runner()
        child = mock.Mock(account={"name": "a"}, spawn_args=[])

        def per_family(_child, family, _snapshot):
            raise supervisor.CapacityHold(f"nothing free for {family}")

        with mock.patch.object(supervisor.Supervisor, "_cap_target_in_family",
                               side_effect=per_family):
            with self.assertRaises(supervisor.CapacityHold) as caught:
                run._cap_target(child, "fable", {})
        self.assertIn("fable", str(caught.exception))
        self.assertNotIn("haiku", str(caught.exception))

    # -- the ladder is bounded by where a huge conversation can LOAD --------

    def transcript(self, total):
        path = os.path.join(self.temp.name, "big.jsonl")
        with open(path, "w", encoding="utf-8") as out:
            out.write(json.dumps(usage_record(total)) + "\n")
        return path

    def walk(self, total, spawn_args=(), fit=None, family="fable",
             serves=None, fallback=True):
        """`(families tried, chosen family, model the successor launches)`.

        `serves` is the family whose seat has room — set it so the walk
        SUCCEEDS, because a walk where every attempt fails cannot show which
        family was gated against which model actually starts. That gap is the
        whole defect class this bounding exists for. Anything the walk says on
        stderr lands in `self.errors` for the announcement tests."""
        self.errors = io.StringIO()
        run, tried = self.runner(), []
        child = mock.Mock(account={"name": "a"}, spawn_args=list(spawn_args))
        path = (self.transcript(total) if total
                else os.path.join(self.temp.name, "gone.jsonl"))

        def in_family(_child, attempt, _snapshot):
            tried.append(attempt)
            if serves is not None and attempt == serves:
                return {"name": "b"}
            raise supervisor.CapacityHold("walled")

        with mock.patch.object(supervisor.Supervisor, "_cap_target_in_family",
                               side_effect=in_family), \
                mock.patch.object(supervisor, "FAMILY_FALLBACK_ENABLED",
                                  fallback), \
                mock.patch.object(supervisor, "CONTEXT_FIT_MODEL",
                                  fit or supervisor.CONTEXT_FIT_MODEL), \
                redirect_stderr(self.errors):
            if serves is None:
                with self.assertRaises(supervisor.CapacityHold) as caught:
                    run._cap_target(child, family, {}, path)
                return tried, caught.exception, ""
            _target, chosen = run._cap_target(child, family, {}, path)
        # exactly what _preflight would build from that decision
        plan = mock.Mock(resume_family="" if chosen == family else chosen)
        plan.source.session_id = "sid"
        plan.source.transcript_path = path
        with mock.patch.object(supervisor, "CONTEXT_FIT_MODEL",
                               fit or supervisor.CONTEXT_FIT_MODEL):
            argv, _forced = supervisor._resume_argv_for(
                plan, supervisor._model_flag(list(spawn_args)))
        return tried, chosen, supervisor._model_flag(argv)

    def assert_gate_matches_launch(self, *args, **kw):
        """THE invariant: the family the seat was CHECKED for is the family
        the successor SPENDS. Every mismatch review found was a rotation that
        gated one pool and started another, and re-capped on its first prompt.

        An argv with no `--model` is not a free pass — it means the child
        keeps its default, so the gate must have stayed on the capped family.
        """
        capped = kw.get("family", args[2] if len(args) > 2 else "fable")
        tried, chosen, model = self.walk(*args, **kw)
        if model:
            self.assertEqual(supervisor._family_or_blank(model), chosen,
                             (tried, chosen, model))
        else:
            self.assertEqual(chosen, capped, (tried, chosen, model))
        return tried, chosen, model

    def test_an_over_limit_transcript_is_gated_on_the_family_it_will_run(self):
        # A 500k transcript WILL be re-modelled onto opus[1m] — it cannot load
        # otherwise. So Opus is the only honest destination: gating the seat
        # on Fable and then starting Opus on it checks one pool and spends
        # another.
        tried, chosen, model = self.assert_gate_matches_launch(
            500_000, serves="opus")
        self.assertEqual((tried, chosen, model), (["opus"], "opus", "opus[1m]"))

    def test_a_transcript_that_fits_still_walks_the_whole_ladder(self):
        tried, chosen, model = self.walk(50_000, serves="haiku")
        self.assertEqual(tried, ["fable", "opus", "sonnet", "haiku"])
        self.assertEqual((chosen, model), ("haiku", "haiku"))

    def test_an_unmeasurable_transcript_does_not_bound_the_ladder(self):
        # measurement failure must cost a session options, not create them
        tried, chosen, _model = self.walk(None, serves="haiku")
        self.assertEqual((tried, chosen),
                         (["fable", "opus", "sonnet", "haiku"], "haiku"))

    def test_a_child_on_its_own_1m_model_may_stay_on_that_family(self):
        # keeping `fable[1m]` is the existing doctrine, so Fable stays a
        # destination — with Opus behind it, because opus[1m] holds it too
        self.assertEqual(
            self.assert_gate_matches_launch(
                500_000, ["--model", "fable[1m]"], serves="fable"),
            (["fable"], "fable", "fable[1m]"))
        self.assertEqual(
            self.assert_gate_matches_launch(
                500_000, ["--model", "fable[1m]"], serves="opus"),
            (["fable", "opus"], "opus", "opus[1m]"))

    def test_an_overridden_fit_model_gates_the_family_it_names(self):
        # the override decides what the successor RUNS, so it has to decide
        # what the seat is checked for; anything else gates Opus and starts
        # Sonnet
        self.assertEqual(
            self.assert_gate_matches_launch(
                500_000, fit="sonnet[1m]", serves="sonnet"),
            (["sonnet"], "sonnet", "sonnet[1m]"))

    def test_a_fit_family_above_the_capped_one_is_still_gated_honestly(self):
        # capped Sonnet, 500k transcript: opus[1m] is the only model that can
        # load it, so Opus is what gets checked. This is not the ladder
        # promoting — it is the gate naming the pool the window fit already
        # chose. Gating Sonnet here spends Opus unchecked.
        self.assertEqual(
            self.assert_gate_matches_launch(
                500_000, family="sonnet", serves="opus"),
            (["opus"], "opus", "opus[1m]"))

    def test_the_fit_bound_applies_even_with_the_ladder_switched_off(self):
        # HEADROOM_FAMILY_FALLBACK governs VOLUNTARY tier changes; it cannot
        # license gating one pool and spending another. Fable is not a home
        # for a 500k transcript at all, so Opus is the only honest gate.
        self.assertEqual(
            self.assert_gate_matches_launch(
                500_000, serves="opus", fallback=False),
            (["opus"], "opus", "opus[1m]"))

    def test_the_ladder_off_still_refuses_a_VOLUNTARY_tier_change(self):
        # the other side of the same switch: here Fable IS a home (the child
        # runs fable[1m]), so moving to Opus would be a choice, not a
        # necessity — and the switch forbids choices
        tried, error, _ = self.walk(
            500_000, ["--model", "fable[1m]"], fallback=False)
        self.assertEqual(tried, ["fable"])
        self.assertIsInstance(error, supervisor.CapacityHold)

    def announcement(self, **kw):
        """The reason `_cap_target` actually emits, from the real site."""
        with mock.patch.object(notify, "emit") as emit:
            self.walk(**kw)
        events = [call.args[0] for call in emit.call_args_list]
        return (events[0] if events else {}), self.errors.getvalue()

    def test_a_capacity_move_is_not_blamed_on_the_transcript(self):
        # the capped family was a perfectly good home for this conversation —
        # it just had no seat. Reporting that as a window fit tells the
        # operator the transcript outgrew a model it did not.
        event, err = self.announcement(
            total=500_000, spawn_args=["--model", "fable[1m]"], serves="opus")
        self.assertEqual((event.get("event"), event.get("reason")),
                         ("family_downgrade", "capacity"))
        self.assertIn("no seat can serve fable", err)
        self.assertNotIn("only fits the 1M window", err)

    def test_a_window_fit_move_says_so(self):
        # here Fable genuinely cannot hold the conversation
        event, err = self.announcement(total=500_000, serves="opus")
        self.assertEqual((event.get("event"), event.get("reason")),
                         ("family_downgrade", "window_fit"))
        self.assertIn("only fits the 1M window", err)

    def test_an_unreasonable_fit_model_holds_instead_of_routing_blind(self):
        # An override is only a home when it is BOTH a 1M model and a family a
        # seat can be gated on. `sonnet` is the subtle one: perfectly routable,
        # and it resumes a 500k transcript into a 200k window that kills it.
        # `serves` is None because the hold lands BEFORE any seat is tried —
        # assert exactly that, so this cannot pass by every target failing.
        for fit in ("claude[1m]", "mystery[1m]", "[1m]", "sonnet", "opus"):
            tried, error, _ = self.walk(500_000, fit=fit, serves=None)
            self.assertEqual(tried, [], fit)
            self.assertIn("not a 1M model on a routable family",
                          str(error), fit)


if __name__ == "__main__":
    unittest.main()
