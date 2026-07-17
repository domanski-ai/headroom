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
    __main__, notify, paths, registry, route, supervisor,
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


class TempDirCase(unittest.TestCase):
    """A fresh HEADROOM_DIR per test, with no launch/lease env leakage."""

    CLEAR_VARS = ("HEADROOM_LAUNCH_MARKER", "HEADROOM_LAUNCH_FALLBACK",
                  "HEADROOM_SLOT_LEASE", "HEADROOM_NOTIFY_CMD",
                  "HEADROOM_NOTIFY_TIMEOUT", "CLAUDE_CONFIG_DIR",
                  "CODEX_HOME")

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


if __name__ == "__main__":
    unittest.main()
