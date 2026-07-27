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
                  "HEADROOM_CONTEXT_BACKSTOP")

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
        return type("P", (), {"target": self.target(), "family": "sonnet",
                              "source": source})()

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
        # keep the pre-import copy honest against the canonical list
        self.assertEqual(set(__main__._CLAUDE_VALUE_FLAGS),
                         set(supervisor.CLAUDE_VALUE_FLAGS))

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


class PreemptiveThresholds(TempDirCase):
    def runner(self, account=None):
        return supervisor.Supervisor("fable", [], account or self.account())

    def windows(self, seven=10.0, scoped=None, **over):
        windows = {"5h": {"used_percent": 99.0},
                   "7d": dict({"used_percent": seven}, **over)}
        if scoped is not None:
            windows["scoped:Fable"] = (scoped if isinstance(scoped, dict)
                                       else {"used_percent": scoped})
        return {"windows": windows}

    def test_scoped_family_window_trips_first(self):
        crossing = self.runner()._threshold_crossing(
            "fable", self.windows(seven=10.0, scoped=93.0))
        self.assertEqual(crossing, ("scoped:fable", 93.0))

    def test_overall_seven_day_window_trips_at_its_own_threshold(self):
        self.assertIsNone(self.runner()._threshold_crossing(
            "fable", self.windows(seven=94.9, scoped=10.0)))
        self.assertEqual(self.runner()._threshold_crossing(
            "fable", self.windows(seven=95.0, scoped=10.0)), ("7d", 95.0))

    def test_a_full_5h_window_is_never_a_preemptive_trigger(self):
        # 5h heals within hours and the cap path already covers it
        self.assertIsNone(self.runner()._threshold_crossing(
            "fable", self.windows(seven=10.0, scoped=10.0)))

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

    def usage(self, scoped=94.0, seven=20.0, target_ok=True):
        captured = int(self.clock["t"])
        source = usage_row("source", used7=seven, captured=captured)
        source["windows"]["scoped:Fable"] = {
            "used_percent": scoped, "resets_at": captured + 6 * 86400,
            "window_minutes": 10080}
        target = usage_row("target", captured=captured)
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
        self.assertEqual([event["event"] for event in events],
                         ["context_backstop_scheduled",
                          "context_backstop_rotation"])
        self.assertEqual(events[1]["used"], 190_000)
        self.assertEqual(events[1]["window"], 200_000)
        self.assertEqual(events[1]["model"], "opus[1m]")
        self.assertIs(events[1]["forked"], True)
        # nothing was disarmed and nothing was reserved or cooled
        self.assertTrue(self.child.automation)
        self.assertFalse(self.child.supervision_loss_notified)
        self.assertFalse(os.path.exists(
            os.path.join(paths.state_dir(), "handoffs.jsonl")))
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


if __name__ == "__main__":
    unittest.main()
