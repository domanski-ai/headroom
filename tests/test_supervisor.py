"""v0.2 transactional handoff and resident supervisor tests."""
import errno
import hashlib
import io
import json
import multiprocessing
import os
import pty
import select
import signal
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from headroom import (  # noqa: E402
    __main__, collect, handoff, registry, route, statusline, supervisor,
)


IDENTITY = {"account_fingerprint": "AAAA", "credential_digest": "BBBB"}


def usage_row(name, used5=10.0, used7=10.0, captured=None, scoped=None):
    captured = int(time.time()) if captured is None else captured
    windows = {
        "5h": {"used_percent": used5, "resets_at": captured + 3600,
               "window_minutes": 300},
        "7d": {"used_percent": used7, "resets_at": captured + 7 * 86400,
               "window_minutes": 10080},
    }
    if scoped is not None:
        windows["scoped:Sonnet"] = {
            "used_percent": scoped, "resets_at": captured + 6 * 86400,
            "window_minutes": 10080}
    return {"name": name, "provider": "claude", "ok": True,
            "routable": True, "trust_state": "verified", "stale": False,
            "captured_at": captured, "identity": dict(IDENTITY),
            "windows": windows}


def commit_worker(plan, queue):
    try:
        result = handoff.commit_handoff(plan)
        queue.put(("ok", result.record["transcript_sha256"]))
    except Exception as error:  # noqa: BLE001 — child reports exact refusal
        queue.put(("error", str(error)))


class ConfigAndScope(unittest.TestCase):
    def test_auto_handoff_is_strict_opt_in(self):
        base = {"schema_version": 1, "accounts": [
            {"name": "a", "provider": "claude", "home": "/tmp/a"}]}
        self.assertFalse(registry.auto_handoff(base))
        for value in (False, "true", 1, None, [], {}):
            cfg = dict(base, routing={"auto_handoff": value})
            self.assertFalse(registry.auto_handoff(cfg), value)
        self.assertTrue(registry.auto_handoff(
            dict(base, routing={"auto_handoff": True})))
        self.assertFalse(registry.auto_handoff(dict(base, routing="broken")))
        self.assertEqual(registry.reserve_percent(
            dict(base, routing="broken")), 0.0)

    def test_fable_display_name_and_unknown_model(self):
        source = handoff.SourceSession("x", "/tmp/x", {}, "Claude Fable 5")
        self.assertEqual(handoff.resolve_model_family(source), "fable")
        source = handoff.SourceSession("x", "/tmp/x", {}, "mystery")
        with self.assertRaises(handoff.HandoffError):
            handoff.resolve_model_family(source)

    def test_exact_5h_7d_and_scoped_cap_scope(self):
        now = int(time.time())
        snap = {"accounts": [usage_row("a", used5=99, captured=now)]}
        scope = route.cap_scope(snap, "a", "sonnet", "hit your session limit")
        self.assertEqual(scope["key"], "a:*")
        self.assertEqual(scope["window"], "5h")
        snap = {"accounts": [usage_row("a", used7=100, captured=now)]}
        scope = route.cap_scope(snap, "a", "sonnet", "hit your weekly limit")
        self.assertEqual(scope["key"], "a:*")
        self.assertEqual(scope["window"], "7d")
        snap = {"accounts": [usage_row("a", captured=now, scoped=100)]}
        scope = route.cap_scope(snap, "a", "sonnet", "hit your weekly limit")
        self.assertEqual(scope["key"], "a:sonnet")
        self.assertFalse(scope["account_wide"])

    def test_monotonic_cooldown_retains_later_reset(self):
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.dict(os.environ, {"HEADROOM_DIR": root}):
            later = time.time() + 20_000
            route.mark("a", "sonnet", later)
            result = route.mark("a", "sonnet", time.time() + 10_000)
            self.assertEqual(result, later)
            self.assertEqual(route.cooldowns()["a:sonnet"], later)


class TranscriptAndTransaction(unittest.TestCase):
    SID = "11111111-1111-4111-8111-111111111111"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(
            os.environ, {"HEADROOM_DIR": os.path.join(self.temp.name, "state")})
        self.env.start()
        self.cwd = os.path.join(self.temp.name, "work")
        self.source_home = os.path.join(self.temp.name, "source")
        self.target_home = os.path.join(self.temp.name, "target")
        os.makedirs(self.cwd)
        os.makedirs(self.target_home)
        directory = os.path.join(self.source_home, "projects", "project")
        os.makedirs(directory)
        self.transcript = os.path.join(directory, self.SID + ".jsonl")
        self.source_account = {"name": "source", "provider": "claude",
                               "home": self.source_home}
        self.target_account = {"name": "target", "provider": "claude",
                               "home": self.target_home}

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def write(self, events):
        with open(self.transcript, "w", encoding="utf-8") as out:
            for event in events:
                out.write(json.dumps(event) + "\n")
        old = time.time() - 20
        os.utime(self.transcript, (old, old))

    def test_tool_results_are_paired_by_exact_id(self):
        self.write([
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "one"},
                {"type": "tool_use", "id": "two"}]}},
            {"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "one"}]}},
            {"type": "user", "message": {"content": [
                {"type": "text", "text": "later"}]}},
        ])
        with self.assertRaisesRegex(handoff.HandoffError, "two"):
            handoff.inspect_transcript(self.transcript)
        inspected = handoff.inspect_transcript(
            self.transcript, allow_dangling=True)
        self.assertEqual(inspected["unresolved_tool_ids"], ("two",))

    def test_forged_config_dir_does_not_bypass_containment(self):
        outside = os.path.join(self.temp.name, self.SID + ".jsonl")
        with open(outside, "w", encoding="utf-8") as out:
            out.write("{}\n")
        with self.assertRaisesRegex(handoff.HandoffError, "configured Claude home"):
            handoff._source(outside, self.SID, [self.source_account],
                            config_dir=self.source_home)

    def test_basename_must_match_session_id(self):
        wrong = os.path.join(os.path.dirname(self.transcript), "wrong.jsonl")
        with open(wrong, "w", encoding="utf-8") as out:
            out.write("{}\n")
        with self.assertRaisesRegex(handoff.HandoffError, "basename"):
            handoff._source(wrong, self.SID, [self.source_account])

    def test_yes_and_print_are_mutually_exclusive(self):
        with self.assertRaisesRegex(handoff.HandoffError, "mutually exclusive"):
            handoff._parse_args(["--yes", "--print"])
        self.assertTrue(handoff._parse_args(["--yes"])["yes"])

    def test_concurrent_commits_publish_once_without_replacement(self):
        self.write([{"type": "user", "message": {"content": []}}])
        source = handoff.SourceSession(
            self.SID, self.transcript, self.source_account, "Sonnet")
        plan = handoff.plan_handoff(
            source, "sonnet", self.target_account, {"accounts": []}, None,
            self.cwd, require_executable=False)
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        workers = [context.Process(target=commit_worker, args=(plan, queue))
                   for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(5)
            self.assertEqual(worker.exitcode, 0)
        outcomes = [queue.get(timeout=1) for _ in workers]
        self.assertEqual(sum(item[0] == "ok" for item in outcomes), 1)
        destination = handoff.destination_path(
            self.target_home, self.transcript, self.SID)
        with open(destination, "rb") as copied, open(self.transcript, "rb") as source_f:
            self.assertEqual(copied.read(), source_f.read())

    def test_manual_dangling_requires_force_unless_source_is_capped(self):
        self.write([{"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "danger", "name": "Write"}]}}])
        source = handoff.SourceSession(
            self.SID, self.transcript, self.source_account, "Sonnet")
        with self.assertRaisesRegex(handoff.HandoffError, "mid-tool-call"):
            handoff.plan_handoff(
                source, "sonnet", self.target_account, {"accounts": []}, None,
                self.cwd, require_executable=False)
        forced = handoff.plan_handoff(
            source, "sonnet", self.target_account, {"accounts": []}, None,
            self.cwd, force=True, require_executable=False)
        self.assertEqual(forced.inspected["unresolved_tool_ids"], ("danger",))
        capped = handoff.plan_handoff(
            source, "sonnet", self.target_account, {"accounts": []},
            {"key": "source:*", "account_wide": True, "window": "5h",
             "used_percent": 100, "reset": time.time() + 3600},
            self.cwd, require_executable=False)
        self.assertEqual(capped.inspected["unresolved_tool_ids"], ("danger",))


class HookProof(unittest.TestCase):
    SUPERVISOR = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    SID = "11111111-1111-4111-8111-111111111111"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self.temp.name, "home")
        self.cwd = os.path.join(self.temp.name, "work")
        os.makedirs(self.cwd)
        directory = os.path.join(self.home, "projects", "p")
        os.makedirs(directory)
        self.transcript = os.path.join(directory, self.SID + ".jsonl")
        event = {"type": "assistant", "isApiErrorMessage": True,
                 "message": {"content": [{"type": "text", "text":
                 "You've hit your session limit · resets 12:20pm (UTC)"}]}}
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps(event) + "\n")
        account = {"name": "source", "provider": "claude", "home": self.home}
        process = mock.Mock(pid=999)
        process.poll.return_value = None
        self.child = supervisor.Child(
            process, account, 1,
            os.path.join(self.temp.name, self.SUPERVISOR + ".jsonl"), "", 1, True,
            binding=supervisor.Binding(self.SID, self.transcript, self.cwd,
                                       "Sonnet", "2.1", self.home))

    def tearDown(self):
        self.temp.cleanup()

    def record(self, text=None, **over):
        payload = {"hook_event_name": "StopFailure", "session_id": self.SID,
                   "transcript_path": self.transcript, "cwd": self.cwd,
                   "error": "rate_limit"}
        if text is not None:
            payload["last_assistant_message"] = text
        payload.update(over.pop("payload", {}))
        record = {"supervisor_id": self.SUPERVISOR, "generation": 1,
                  "source_slot": "source", "config_dir": self.home,
                  "matcher": "rate_limit", "received_at": time.time(),
                  "payload": payload}
        record.update(over)
        return record

    def test_narrow_parser_accepts_cap_and_fallback(self):
        direct = self.record("You've hit your weekly limit · resets Friday")
        self.assertIn("weekly", supervisor.cap_message(direct, self.child))
        self.assertIn("session", supervisor.cap_message(self.record(), self.child))

    def test_rejects_overload_429_wrong_nonce_generation_and_session(self):
        for record in (
            self.record("overloaded_error", payload={"error": "overloaded"}),
            self.record("429 Too Many Requests"),
            self.record("You've hit your session limit", supervisor_id="bad"),
            self.record("You've hit your session limit", generation=2),
            self.record("You've hit your session limit",
                        payload={"session_id":
                                 "22222222-2222-4222-8222-222222222222"}),
        ):
            self.assertEqual(supervisor.cap_message(record, self.child), "")

    def test_hook_writer_is_private_and_silent(self):
        root = os.path.join(self.temp.name, "state")
        payload = {"hook_event_name": "SessionStart", "session_id": self.SID,
                   "transcript_path": self.transcript, "cwd": self.cwd}
        env = {"HEADROOM_DIR": root, "HEADROOM_SUPERVISOR_ID": self.SUPERVISOR,
               "HEADROOM_CHILD_GENERATION": "1",
               "HEADROOM_SOURCE_SLOT": "source", "CLAUDE_CONFIG_DIR": self.home}
        output = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False), redirect_stdout(output):
            self.assertEqual(supervisor.write_hook_event(
                io.StringIO(json.dumps(payload)), env), 0)
        self.assertEqual(output.getvalue(), "")
        destination = os.path.join(root, "state", "supervisors",
                                   self.SUPERVISOR + ".jsonl")
        self.assertEqual(os.stat(destination).st_mode & 0o777, 0o600)
        with open(destination, encoding="utf-8") as source:
            self.assertEqual(json.loads(source.readline())["payload"], payload)

    def test_snapshot_only_and_hook_only_do_not_make_cap_proof(self):
        self.assertIsNone(route.cap_scope(
            {"accounts": [usage_row("source", used5=10)]},
            "source", "sonnet", "hit your session limit"))
        self.assertEqual(supervisor.cap_message(
            self.record("rate limit"), self.child), "")


class CliWiring(unittest.TestCase):
    def test_plain_claude_with_auto_off_keeps_exec_path(self):
        with mock.patch.object(registry, "auto_handoff", return_value=False), \
                mock.patch("headroom.route.cmd_exec", return_value=17) as execute:
            result = __main__._dispatch(["claude", "--model", "sonnet"])
        self.assertEqual(result, 17)
        execute.assert_called_once_with("sonnet", ["claude", "--model", "sonnet"])

    def test_override_is_stripped_and_selects_supervisor(self):
        tty = mock.Mock()
        tty.isatty.return_value = True
        with mock.patch.object(registry, "auto_handoff", return_value=False), \
                mock.patch.object(__main__.sys, "stdin", tty), \
                mock.patch.object(__main__.sys, "stdout", tty), \
                mock.patch.object(__main__.sys, "stderr", tty), \
                mock.patch("headroom.supervisor.cmd_claude", return_value=23) as run:
            result = __main__._dispatch(
                ["claude", "--headroom-auto-handoff", "--model", "sonnet"])
        self.assertEqual(result, 23)
        run.assert_called_once_with("sonnet", ["--model", "sonnet"])

    def test_no_auto_override_strips_flag_and_uses_plain_exec(self):
        with mock.patch.object(registry, "auto_handoff", return_value=True), \
                mock.patch("headroom.route.cmd_exec", return_value=19) as execute:
            result = __main__._dispatch(
                ["claude", "--headroom-no-auto-handoff", "--model", "sonnet"])
        self.assertEqual(result, 19)
        execute.assert_called_once_with("sonnet", ["claude", "--model", "sonnet"])

    def test_statusline_distinguishes_armed_supervisor(self):
        snapshot = {"accounts": [{"name": "source", "provider": "claude",
                                   "windows": {"5h": {"used_percent": 100},
                                               "7d": {"used_percent": 10}}}]}
        account = {"name": "source", "provider": "claude", "home": "/tmp/source"}
        output = io.StringIO()
        with mock.patch.object(statusline.sys, "stdin", io.StringIO("{}")), \
                mock.patch.object(statusline.paths, "load_json", return_value=snapshot), \
                mock.patch.object(statusline.registry, "accounts",
                                  return_value=[account]), \
                mock.patch.dict(os.environ, {
                    "CLAUDE_CONFIG_DIR": "/tmp/source",
                    "HEADROOM_SUPERVISOR_ID": "armed"}), \
                redirect_stdout(output):
            self.assertEqual(statusline.main(), 0)
        self.assertIn("auto-handoff armed", output.getvalue())


class SupervisorIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.temp.name, "headroom")
        self.fake_state = os.path.join(self.temp.name, "fake-state")
        self.bin_dir = os.path.join(self.temp.name, "bin")
        os.makedirs(self.bin_dir)
        fake = os.path.join(os.path.dirname(__file__), "fake_claude.py")
        os.chmod(fake, 0o755)
        os.symlink(fake, os.path.join(self.bin_dir, "claude"))
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.env = mock.patch.dict(os.environ, {
            "HEADROOM_DIR": self.root,
            "HEADROOM_EXECUTABLE": os.path.join(repo, "bin", "headroom"),
            "PATH": self.bin_dir + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_CLAUDE_STATE": self.fake_state,
            "FAKE_CLAUDE_SCENARIO": "handoff",
            "FAKE_CAP_SLOTS": "source",
        })
        self.env.start()
        self.binding = mock.patch.object(
            collect, "local_binding", return_value=("AAAA", "BBBB"))
        self.binding.start()
        self.cwd_before = os.getcwd()
        self.cwd = os.path.join(self.temp.name, "work")
        os.makedirs(self.cwd)
        os.chdir(self.cwd)
        self.accounts = self.make_accounts("source", "target")

    def tearDown(self):
        os.chdir(self.cwd_before)
        self.binding.stop()
        self.env.stop()
        self.temp.cleanup()

    def make_accounts(self, *names):
        accounts = []
        for name in names:
            home = os.path.join(self.temp.name, name)
            os.makedirs(home, exist_ok=True)
            accounts.append({"name": name, "provider": "claude", "home": home})
        registry.save({"schema_version": 1, "accounts": accounts,
                       "routing": {"auto_handoff": True}})
        return accounts

    def snapshot(self, quiet=True):
        del quiet
        active_path = os.path.join(self.fake_state, "active-slot")
        active = "source"
        try:
            with open(active_path, encoding="utf-8") as source:
                active = source.read().strip()
        except OSError:
            pass
        now = int(time.time())
        return {"run_started": now, "generated": now,
                "accounts": [usage_row(
                    account["name"], used5=100 if account["name"] == active else 10,
                    captured=now) for account in self.accounts]}

    def ledger_actions(self):
        with open(handoff._ledger_path(), encoding="utf-8") as source:
            return [json.loads(line) for line in source if line.strip()]

    def test_fake_child_handoffs_and_rebinds_target(self):
        changed = os.path.join(self.temp.name, "changed-cwd")
        os.makedirs(changed)
        os.environ["FAKE_CHANGED_CWD"] = changed
        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        source_sid = str(__import__("uuid").uuid5(
            __import__("uuid").NAMESPACE_DNS, "headroom-fake-source-1"))
        destination = os.path.join(self.accounts[1]["home"], "projects",
                                   "fake-project", source_sid + ".jsonl")
        self.assertTrue(os.path.exists(destination))
        actions = [row.get("action") for row in self.ledger_actions()]
        for action in ("cap_confirmed", "stop_sent", "stopped", "staged",
                       "resume_spawned", "resume_bound"):
            self.assertIn(action, actions)
        with open(os.path.join(self.fake_state, "launches.jsonl"),
                  encoding="utf-8") as source:
            launches = [json.loads(line) for line in source]
        self.assertEqual(launches[1]["args"],
                         ["--resume", source_sid, "--fork-session"])
        self.assertEqual(launches[1]["config_dir"], self.accounts[1]["home"])
        self.assertEqual(launches[1]["cwd"], changed)
        bound = [row for row in self.ledger_actions()
                 if row.get("action") == "resume_bound"][-1]
        self.assertTrue(handoff._valid_uuid(bound["new_session_id"]))

    def test_banner_alone_never_terminates(self):
        os.environ["FAKE_CLAUDE_SCENARIO"] = "banner"
        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))

    def test_transient_hook_below_proof_does_not_terminate(self):
        os.environ["FAKE_CLAUDE_SCENARIO"] = "transient"
        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))

    def test_cap_hook_with_source_below_99_does_not_terminate(self):
        os.environ["FAKE_CLAUDE_SCENARIO"] = "below"

        def below_snapshot(quiet=True):
            del quiet
            now = int(time.time())
            return {"run_started": now, "generated": now,
                    "accounts": [usage_row(account["name"], used5=10,
                                                   captured=now)
                                 for account in self.accounts]}

        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=below_snapshot).run()
        self.assertEqual(result, 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))

    def test_no_target_leaves_capped_child_alive(self):
        self.accounts = self.make_accounts("source")
        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))

    def test_corrupt_transcript_never_receives_sigterm(self):
        os.environ["FAKE_CLAUDE_SCENARIO"] = "corrupt"
        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))

    def test_sigterm_timeout_never_escalates(self):
        os.environ["FAKE_CLAUDE_SCENARIO"] = "ignore-term"
        with mock.patch.object(supervisor, "TERM_TIMEOUT", 0.25):
            result = supervisor.Supervisor(
                "sonnet", [], self.accounts[0], collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        marker = os.path.join(self.fake_state, "sigterm-source")
        with open(marker, encoding="utf-8") as source:
            self.assertEqual(len(source.readlines()), 1)

    def test_missing_session_end_recovers_source_with_auto_off(self):
        os.environ["FAKE_CLAUDE_SCENARIO"] = "missing-end"
        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        with open(os.path.join(self.fake_state, "recovered"),
                  encoding="utf-8") as source:
            self.assertIn("--resume", source.read())

    def test_three_handoffs_then_fourth_is_held(self):
        self.accounts = self.make_accounts("a", "b", "c", "d", "e")
        os.environ["FAKE_CLAUDE_SCENARIO"] = "loop"
        os.environ["FAKE_CAP_SLOTS"] = "a,b,c,d"
        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        for name in ("a", "b", "c"):
            self.assertTrue(os.path.exists(
                os.path.join(self.fake_state, "sigterm-" + name)))
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-d")))
        confirmed = [row for row in self.ledger_actions()
                     if row.get("action") == "cap_confirmed"]
        self.assertEqual(len(confirmed), 3)

    def test_child_inherits_foreground_process_group_under_pty(self):
        os.environ["FAKE_CLAUDE_SCENARIO"] = "foreground"
        account = self.accounts[0]
        code = (
            "from headroom.supervisor import Supervisor; "
            f"raise SystemExit(Supervisor('sonnet', [], {account!r}).run())")
        pid, descriptor = pty.fork()
        if pid == 0:
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))
            os.execve(sys.executable, [sys.executable, "-c", code], environment)
        output = b""
        deadline = time.time() + 5
        while time.time() < deadline:
            ready, _, _ = select.select([descriptor], [], [], 0.25)
            if ready:
                try:
                    output += os.read(descriptor, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                self.assertTrue(os.WIFEXITED(status))
                break
        else:
            os.kill(pid, signal.SIGKILL)
            self.fail("pty supervisor did not exit")
        os.close(descriptor)
        self.assertIn(b"PGRP_OK", output)


if __name__ == "__main__":
    unittest.main()
