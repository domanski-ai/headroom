"""v0.2 transactional handoff and resident supervisor tests."""
import errno
import fcntl
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
    __main__, collect, handoff, paths, registry, route, statusline, supervisor,
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


def reserve_worker(plan, now, queue):
    try:
        handoff.reserve_automatic(plan, now)
        queue.put(("ok", plan.handoff_id))
    except Exception as error:  # noqa: BLE001 — child reports exact refusal
        queue.put(("error", str(error)))


class ConfigAndScope(unittest.TestCase):
    def test_auto_handoff_defaults_on_and_only_explicit_false_disables(self):
        base = {"schema_version": 1, "accounts": [
            {"name": "a", "provider": "claude", "home": "/tmp/a"}]}
        self.assertTrue(registry.auto_handoff(base))
        self.assertFalse(registry.auto_handoff(
            dict(base, routing={"auto_handoff": False})))
        for value in (True, "false", "true", 1, 0, None, [], {}):
            cfg = dict(base, routing={"auto_handoff": value})
            expected = value is not False
            self.assertEqual(registry.auto_handoff(cfg), expected, value)
        self.assertTrue(registry.auto_handoff(dict(base, routing="broken")))
        self.assertEqual(registry.reserve_percent(
            dict(base, routing="broken")), 0.0)

    def test_fable_display_name_and_unknown_model(self):
        source = handoff.SourceSession("x", "/tmp/x", {}, "Claude Fable 5")
        self.assertEqual(handoff.resolve_model_family(source), "fable")
        source = handoff.SourceSession("x", "/tmp/x", {}, "mystery")
        with self.assertRaises(handoff.HandoffError):
            handoff.resolve_model_family(source)
        generic = handoff.SourceSession("x", "/tmp/x", {}, "claude")
        with self.assertRaisesRegex(handoff.HandoffError, "scoped Claude family"):
            handoff.resolve_model_family(generic, "claude")

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


class RealCollectorBinding(unittest.TestCase):
    def test_real_local_identity_and_collect_lock_fixture(self):
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.dict(os.environ, {"HEADROOM_DIR": root}):
            home = os.path.join(root, "claude-home")
            os.makedirs(home)
            with open(os.path.join(home, ".claude.json"), "w") as out:
                json.dump({"oauthAccount": {
                    "emailAddress": "seat@example.test",
                    "organizationUuid": "fixture-org"}}, out)
            with open(os.path.join(home, ".credentials.json"), "w") as out:
                json.dump({"claudeAiOauth": {
                    "accessToken": "fixture-token",
                    "subscriptionType": "max"}}, out)
            account = {"name": "seat", "provider": "claude", "home": home}
            registry.save({"schema_version": 1, "accounts": [account]})
            now = int(time.time())
            limits = {
                "source": "fixture", "captured_at": now, "stale": False,
                "source_identity_fingerprint": collect.fingerprint("fixture-org"),
                "windows": {
                    "5h": {"used_percent": 10, "resets_at": now + 3600},
                    "7d": {"used_percent": 20, "resets_at": now + 86400},
                },
            }
            with mock.patch.object(collect, "claude_bin", return_value=None), \
                    mock.patch.object(collect, "claude_limits",
                                      return_value=limits):
                snapshot = collect.run_collect(quiet=True)
                expected = collect.local_binding("claude", home)
                identity = snapshot["accounts"][0]["identity"]
                self.assertEqual((identity["account_fingerprint"],
                                  identity["credential_digest"]), expected)
                with open(paths.collect_lock_path(), "w") as held:
                    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked_snapshot = collect.run_collect(quiet=True)
                    fcntl.flock(held, fcntl.LOCK_UN)
                self.assertEqual(locked_snapshot["run_id"], snapshot["run_id"])


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
        self.binding = mock.patch.object(
            collect, "local_binding", return_value=("AAAA", "BBBB"))
        self.local_binding = self.binding.start()
        registry.save({"schema_version": 1,
                       "accounts": [self.source_account, self.target_account]})

    def tearDown(self):
        self.binding.stop()
        self.env.stop()
        self.temp.cleanup()

    def snapshot(self):
        now = int(time.time())
        return {"generated": now, "accounts": [
            usage_row("source", captured=now),
            usage_row("target", captured=now)]}

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
            source, "sonnet", self.target_account, self.snapshot(), None,
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

    def test_manual_dangling_requires_force_even_when_snapshot_is_capped(self):
        self.write([{"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "danger", "name": "Write"}]}}])
        source = handoff.SourceSession(
            self.SID, self.transcript, self.source_account, "Sonnet")
        with self.assertRaisesRegex(handoff.HandoffError, "mid-tool-call"):
            handoff.plan_handoff(
                source, "sonnet", self.target_account, {"accounts": []}, None,
                self.cwd, require_executable=False)
        forced = handoff.plan_handoff(
            source, "sonnet", self.target_account, self.snapshot(), None,
            self.cwd, force=True, require_executable=False)
        self.assertEqual(forced.inspected["unresolved_tool_ids"], ("danger",))
        scope = {"key": "source:*", "account_wide": True, "window": "5h",
                 "used_percent": 100, "reset": time.time() + 3600}
        with self.assertRaisesRegex(handoff.HandoffError, "mid-tool-call"):
            handoff.plan_handoff(
                source, "sonnet", self.target_account, self.snapshot(), {},
                self.cwd, cooldown_scope=scope, require_executable=False)
        automatic = handoff.plan_handoff(
            source, "sonnet", self.target_account, self.snapshot(),
            {"authenticated": True}, self.cwd, cooldown_scope=scope,
            automatic=True, require_executable=False)
        self.assertEqual(automatic.inspected["unresolved_tool_ids"], ("danger",))

    def automatic_plan(self):
        self.write([{"type": "user", "message": {"content": []}}])
        snapshot = self.snapshot()
        snapshot["accounts"][0]["windows"]["5h"]["used_percent"] = 100
        source = handoff.SourceSession(
            self.SID, self.transcript, self.source_account, "Sonnet")
        scope = {"key": "source:*", "account_wide": True, "window": "5h",
                 "used_percent": 100, "reset": time.time() + 3600}
        return handoff.plan_handoff(
            source, "sonnet", self.target_account, snapshot,
            {"authenticated": True}, self.cwd, cooldown_scope=scope,
            automatic=True, require_executable=False)

    def test_loop_guard_count_and_admission_are_atomic(self):
        now = time.time()
        for _ in range(2):
            handoff.append_action(
                str(__import__("uuid").uuid4()), "cap_confirmed",
                automatic=True, source_slot="source", target_slot="old",
                old_session_id=self.SID)
        plans = [self.automatic_plan(), self.automatic_plan()]
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        workers = [context.Process(
            target=reserve_worker, args=(plan, now, queue)) for plan in plans]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(5)
            self.assertEqual(worker.exitcode, 0)
        outcomes = [queue.get(timeout=1) for _ in workers]
        self.assertEqual(sum(outcome[0] == "ok" for outcome in outcomes), 1)
        self.assertIn("loop guard", next(
            outcome[1] for outcome in outcomes if outcome[0] == "error"))

    def test_malformed_automatic_ledger_row_holds_admission(self):
        handoff.append_ledger({
            "ts": "recent", "handoff_id": str(__import__("uuid").uuid4()),
            "automatic": "yes", "action": "cap_confirmed"})
        with self.assertRaisesRegex(handoff.HandoffError, "malformed"):
            handoff.reserve_automatic(self.automatic_plan())

    def test_target_credential_change_or_cooldown_blocks_commit(self):
        plan = self.automatic_plan()
        handoff.reserve_automatic(plan)
        self.local_binding.return_value = ("AAAA", "CHANGED")
        with self.assertRaisesRegex(handoff.HandoffError, "identity or credential"):
            handoff.commit_handoff(plan)
        self.local_binding.return_value = ("AAAA", "BBBB")
        route.mark("target", "sonnet", time.time() + 3600)
        with self.assertRaisesRegex(handoff.HandoffError, "no longer"):
            handoff.commit_handoff(plan)

    def test_target_reservation_is_held_through_spawn_until_bind(self):
        first = self.automatic_plan()
        second = self.automatic_plan()
        handoff.reserve_automatic(first)
        handoff.append_action(
            first.handoff_id, "resume_spawned", automatic=True,
            target_slot=first.target["name"])
        with self.assertRaisesRegex(handoff.HandoffError, "reserved"):
            handoff.reserve_automatic(second)
        handoff.append_action(
            first.handoff_id, "resume_bound", automatic=True,
            target_slot=first.target["name"], new_session_id=self.SID)
        handoff.reserve_automatic(second)

    def test_incomplete_publication_is_reconciled_on_next_lock(self):
        plan = self.automatic_plan()
        with handoff._handoff_lock():
            marker = handoff._copy_publish_pending(plan)
        self.assertTrue(os.path.exists(plan.destination))
        self.assertTrue(os.path.exists(handoff._marker_path(plan.handoff_id)))
        with open(handoff._ledger_path(), "wb") as ledger:
            ledger.write(b'{"schema":')
            ledger.flush()
            os.fsync(ledger.fileno())
        handoff.append_ledger({"session_id": "reconcile-sentinel"})
        self.assertFalse(os.path.exists(plan.destination))
        self.assertFalse(os.path.exists(handoff._marker_path(plan.handoff_id)))
        self.assertFalse(os.path.exists(os.path.join(
            os.path.dirname(plan.destination), marker["temporary"])))

    def test_durable_publication_marker_finishes_without_rollback(self):
        plan = self.automatic_plan()
        with handoff._handoff_lock():
            marker = handoff._copy_publish_pending(plan)
            handoff._append_ledger_unlocked({
                "handoff_id": plan.handoff_id, "action": "staged",
                "ts": time.time()})
        handoff.append_ledger({"session_id": "reconcile-sentinel"})
        self.assertTrue(os.path.exists(plan.destination))
        self.assertFalse(os.path.exists(handoff._marker_path(plan.handoff_id)))
        self.assertFalse(os.path.exists(os.path.join(
            os.path.dirname(plan.destination), marker["temporary"])))

    def test_target_directory_swap_cannot_redirect_publication(self):
        plan = self.automatic_plan()
        handoff.reserve_automatic(plan)
        outside = os.path.join(self.temp.name, "outside")
        original = self.target_home + "-original"
        os.makedirs(outside)
        os.rename(self.target_home, original)
        os.symlink(outside, self.target_home)
        with self.assertRaisesRegex(handoff.HandoffError, "unsafe|changed"):
            handoff.commit_handoff(plan)
        self.assertFalse(os.path.exists(os.path.join(
            outside, "projects", "project", self.SID + ".jsonl")))


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
                 "error": "rate_limit", "apiErrorStatus": 429,
                 "message": {"model": "<synthetic>",
                 "content": [{"type": "text", "text":
                 "You've hit your session limit · resets 12:20pm (UTC)"}]}}
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant", "message": {
                    "model": "claude-sonnet-4-5-20250929",
                    "content": [{"type": "text", "text": "real turn"}]}
            }) + "\n")
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
        record = {"schema": "headroom_hook_event@1",
                  "supervisor_id": self.SUPERVISOR, "generation": 1,
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

    def test_cap_event_model_is_never_used(self):
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant", "message": {
                    "model": "claude-opus-4-8",
                    "content": [{"type": "text", "text": "real turn"}]}
            }) + "\n")
            out.write(json.dumps({
                "type": "assistant", "isApiErrorMessage": True,
                "message": {"model": "claude-fable-5-20260701", "content": [{
                    "type": "text", "text": "You've hit your weekly limit"}]}
            }) + "\n")
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, supervisor_id=self.SUPERVISOR)
        proof = runner._prove_cap(
            self.child, self.record("You've hit your weekly limit"))
        self.assertEqual(proof.family, "opus")
        self.assertEqual(self.child.binding.model, "Sonnet")

    def test_cap_family_survives_synthetic_model_on_the_cap_event(self):
        # Observed live: the API-error event's own model is "<synthetic>"; the
        # active model is the LAST preceding real assistant model (reflecting
        # an in-session /model switch away from the launch model).
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant",
                "message": {"model": "claude-opus-4-8", "content": [
                    {"type": "text", "text": "earlier turn"}]}}) + "\n")
            out.write(json.dumps({
                "type": "assistant",
                "message": {"model": "claude-fable-5", "content": [
                    {"type": "text", "text": "later turn"}]}}) + "\n")
            out.write(json.dumps({
                "type": "user", "message": {"content": "more"}}) + "\n")
            out.write(json.dumps({
                "type": "assistant", "isApiErrorMessage": True,
                "error": "rate_limit", "apiErrorStatus": 429,
                "message": {"model": "<synthetic>", "content": [{
                    "type": "text",
                    "text": "You've hit your session limit · resets 12:20pm"
                }]}}) + "\n")
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, supervisor_id=self.SUPERVISOR)
        proof = runner._prove_cap(
            self.child, self.record("You've hit your session limit"))
        self.assertEqual(proof.family, "fable")

    def test_cap_evidence_tolerates_trailing_non_assistant_records(self):
        # Observed live: Claude appends system/turn_duration, last-prompt,
        # file-history-snapshot, user, and attachment records AFTER the
        # API-error event, so the cap is rarely the transcript's final line.
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant",
                "message": {"model": "claude-haiku-4-5-20251001", "content": [
                    {"type": "text", "text": "earlier turn"}]}}) + "\n")
            out.write(json.dumps({
                "type": "user", "message": {"content": "prompt"}}) + "\n")
            out.write(json.dumps({"type": "attachment"}) + "\n")
            out.write(json.dumps({
                "type": "assistant", "isApiErrorMessage": True,
                "error": "rate_limit",
                "message": {"model": "<synthetic>", "content": [{
                    "type": "text",
                    "text": "You've hit your session limit · resets 3pm"
                }]}}) + "\n")
            out.write(json.dumps({
                "type": "system", "subtype": "turn_duration"}) + "\n")
            out.write(json.dumps({
                "type": "last-prompt", "lastPrompt": "x"}) + "\n")
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, supervisor_id=self.SUPERVISOR)
        proof = runner._prove_cap(
            self.child, self.record("You've hit your session limit"))
        self.assertEqual(proof.family, "haiku")

    def test_stopfailure_before_transcript_flush_is_transient_then_proves(self):
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant", "message": {
                    "model": "claude-fable-5", "content": "real turn"}
            }) + "\n")
            out.write(json.dumps({"type": "attachment"}) + "\n")
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, supervisor_id=self.SUPERVISOR)
        record = self.record("You've hit your session limit · resets 3pm (UTC)")

        hold = runner._prove_cap(self.child, record)
        self.assertIsInstance(hold, supervisor.PendingCap)
        self.assertTrue(self.child.automation)
        self.assertIs(self.child.pending_cap, hold)

        with open(self.transcript, "a", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant", "isApiErrorMessage": True,
                "error": "rate_limit", "message": {
                    "model": "<synthetic>", "content": [{
                        "type": "text", "text":
                        "You've hit your session limit · resets 3pm (UTC)"}]}
            }) + "\n")
        proof = runner._prove_cap(self.child, record)
        self.assertIsInstance(proof, supervisor.CapProof)
        self.assertEqual(proof.family, "fable")
        self.assertIsNone(self.child.pending_cap)

    def test_message_level_sidechain_cap_candidate_is_skipped(self):
        # A sidechain assistant API-error (message.isSidechain) after a
        # successful main-chain turn must not be selected as the cap: the
        # main session is not capped, so evidence is refused entirely.
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant",
                "message": {"model": "claude-opus-4-8", "content": [
                    {"type": "text", "text": "successful main turn"}]}}) + "\n")
            out.write(json.dumps({
                "type": "assistant", "isApiErrorMessage": True,
                "message": {"isSidechain": True, "model": "<synthetic>",
                            "content": [{
                                "type": "text",
                                "text": "You've hit your session limit"}]}})
                + "\n")
        self.assertIsNone(
            supervisor._last_transcript_cap_evidence(self.transcript))

    def test_successful_assistant_turn_after_cap_refuses_evidence(self):
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant", "isApiErrorMessage": True,
                "message": {"model": "<synthetic>", "content": [{
                    "type": "text", "text": "You've hit your session limit"
                }]}}) + "\n")
            out.write(json.dumps({
                "type": "assistant",
                "message": {"model": "claude-haiku-4-5-20251001", "content": [
                    {"type": "text", "text": "a later successful turn"}]}})
                + "\n")
        self.assertIsNone(
            supervisor._last_transcript_cap_evidence(self.transcript))

    def test_cap_with_only_synthetic_models_waits_then_refuses(self):
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant", "isApiErrorMessage": True,
                "message": {"model": "<synthetic>", "content": [{
                    "type": "text", "text": "You've hit your session limit"
                }]}}) + "\n")
        record = self.record("You've hit your session limit")
        clock = [record["received_at"]]
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, now=lambda: clock[0],
            supervisor_id=self.SUPERVISOR)
        hold = runner._prove_cap(self.child, record)
        self.assertIsInstance(hold, supervisor.PendingCap)
        clock[0] += supervisor.CAP_MODEL_TIMEOUT
        with self.assertRaises(supervisor.PendingCapTimeout):
            runner._prove_cap(
                self.child, hold.event)

    def test_pending_cap_deadline_disables_without_model(self):
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant", "message": {
                    "model": "claude-sonnet-4-5-20250929",
                    "content": "real turn"}}) + "\n")
            out.write(json.dumps({"type": "attachment"}) + "\n")
        received = time.time()
        clock = [received]
        record = self.record(
            "You've hit your session limit · resets 3pm (UTC)",
            received_at=received)
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, now=lambda: clock[0],
            supervisor_id=self.SUPERVISOR)
        output = io.StringIO()
        with mock.patch.object(supervisor, "_read_events",
                               side_effect=[[record], []]), \
                mock.patch("headroom.supervisor.os.kill") as kill, \
                redirect_stderr(output):
            self.assertIsNone(runner._handle_events(self.child, ""))
            self.assertTrue(self.child.automation)
            clock[0] += supervisor.CAP_MODEL_TIMEOUT
            self.assertIsNone(runner._handle_events(self.child, ""))
        self.assertFalse(self.child.automation)
        self.assertIsNone(self.child.pending_cap)
        kill.assert_not_called()
        self.assertIn(
            f"could not determine the cap-time model before "
            f"{supervisor.CAP_MODEL_TIMEOUT:g}s", output.getvalue())
        self.assertIn("/exit then `headroom handoff` to move manually",
                      output.getvalue())

    def test_pending_cap_discarded_on_session_transition(self):
        with open(self.transcript, "w", encoding="utf-8") as out:
            out.write(json.dumps({
                "type": "assistant", "message": {
                    "model": "claude-sonnet-4-5-20250929",
                    "content": "real turn"}}) + "\n")
            out.write(json.dumps({"type": "attachment"}) + "\n")
        other_sid = "22222222-2222-4222-8222-222222222222"
        other_path = os.path.join(
            os.path.dirname(self.transcript), other_sid + ".jsonl")
        with open(other_path, "w", encoding="utf-8") as out:
            out.write("{}\n")
        base = time.time() - 3
        stop = self.record(
            "You've hit your session limit · resets 3pm (UTC)",
            received_at=base)
        end = self.record(payload={"hook_event_name": "SessionEnd"},
                          received_at=base + 1)
        start = self.record(payload={
            "hook_event_name": "SessionStart", "session_id": other_sid,
            "transcript_path": other_path,
            "model": {"display_name": "Sonnet"}}, received_at=base + 2)
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, supervisor_id=self.SUPERVISOR)
        with mock.patch.object(supervisor, "_read_events",
                               side_effect=[[stop], [end, start], []]), \
                mock.patch("headroom.supervisor.os.kill") as kill:
            self.assertIsNone(runner._handle_events(self.child, ""))
            self.assertIsNotNone(self.child.pending_cap)
            self.assertIsNone(runner._handle_events(self.child, ""))
            self.assertIsNone(self.child.pending_cap)
            with open(self.transcript, "a", encoding="utf-8") as out:
                out.write(json.dumps({
                    "type": "assistant", "isApiErrorMessage": True,
                    "message": {"model": "<synthetic>", "content": [{
                        "type": "text", "text":
                        "You've hit your session limit"}]}}) + "\n")
            self.assertIsNone(runner._handle_events(self.child, ""))
        self.assertEqual(self.child.binding.session_id, other_sid)
        self.assertTrue(self.child.automation)
        kill.assert_not_called()

    def test_sidechain_assistant_models_cannot_poison_cap_family(self):
        with open(self.transcript, "w", encoding="utf-8") as out:
            for event in (
                {"type": "assistant", "message": {
                    "model": "claude-fable-5", "content": "main"}},
                {"type": "assistant", "isSidechain": True, "message": {
                    "model": "claude-sonnet-4-5", "content": "poison"}},
                {"type": "assistant", "message": {
                    "model": "claude-opus-4-8", "isSidechain": True,
                    "content": "nested poison"}},
                {"type": "assistant", "isApiErrorMessage": True,
                 "message": {"model": "<synthetic>", "content": [{
                     "type": "text",
                     "text": "You've hit your session limit"}]}},
            ):
                out.write(json.dumps(event) + "\n")
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, supervisor_id=self.SUPERVISOR)
        proof = runner._prove_cap(
            self.child, self.record("You've hit your session limit"))
        self.assertEqual(proof.family, "fable")

    def test_transcript_quiet_gate_runs_before_fresh_collect(self):
        collect_fn = mock.Mock()
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, collect_fn=collect_fn,
            supervisor_id=self.SUPERVISOR)
        proof = runner._prove_cap(
            self.child, self.record("You've hit your session limit"))
        with mock.patch.object(
                handoff, "guard_source_stable",
                side_effect=handoff.HandoffError(
                    "source transcript changed recently")):
            with self.assertRaisesRegex(handoff.HandoffError, "changed recently"):
                runner._preflight(self.child, proof)
        collect_fn.assert_not_called()

    def test_transcript_change_expires_proof_before_collect(self):
        collect_fn = mock.Mock()
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, collect_fn=collect_fn,
            supervisor_id=self.SUPERVISOR)
        proof = runner._prove_cap(
            self.child, self.record("You've hit your session limit"))
        with open(self.transcript, "a", encoding="utf-8") as out:
            out.write("{}\n")
        old = time.time() - 20
        os.utime(self.transcript, (old, old))
        with self.assertRaisesRegex(supervisor.SupervisorError,
                                   "transcript changed"):
            runner._preflight(self.child, proof)
        collect_fn.assert_not_called()

    def test_session_transition_rebinds_and_expires_old_proof(self):
        other_sid = "22222222-2222-4222-8222-222222222222"
        other_path = os.path.join(os.path.dirname(self.transcript),
                                  other_sid + ".jsonl")
        with open(other_path, "w", encoding="utf-8") as out:
            out.write("{}\n")
        old_proof = supervisor.CapProof(
            self.record("You've hit your session limit"), "cap", "sonnet",
            self.SID, self.transcript, 0,
            handoff._transcript_stat(self.transcript))
        end = self.record(payload={"hook_event_name": "SessionEnd"})
        start = self.record(payload={
            "hook_event_name": "SessionStart", "session_id": other_sid,
            "transcript_path": other_path,
            "model": {"display_name": "Sonnet"}})
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, supervisor_id=self.SUPERVISOR)
        with mock.patch.object(supervisor, "_read_events",
                               return_value=[end, start]):
            proof = runner._handle_events(self.child, "", old_proof)
        self.assertIsNone(proof)
        self.assertEqual(self.child.binding.session_id, other_sid)
        self.assertEqual(self.child.session_epoch, 1)
        self.assertFalse(self.child.session_ended)

    def test_session_end_then_delayed_stop_failure_cannot_rearm_proof(self):
        base = time.time() - 2
        end = self.record(
            payload={"hook_event_name": "SessionEnd"},
            received_at=base + 1)
        delayed = self.record(
            "You've hit your session limit", received_at=base)
        with open(self.child.event_path, "w", encoding="utf-8") as out:
            for record in (end, delayed):
                out.write(json.dumps(record) + "\n")
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, supervisor_id=self.SUPERVISOR)
        proof = runner._handle_events(self.child, "")
        self.assertIsNone(proof)
        self.assertFalse(self.child.automation)
        self.assertIn((self.SID, 0), self.child.dead_sessions)

    def test_late_old_session_start_never_rolls_binding_backward(self):
        other_sid = "22222222-2222-4222-8222-222222222222"
        other_path = os.path.join(
            os.path.dirname(self.transcript), other_sid + ".jsonl")
        with open(other_path, "w", encoding="utf-8") as out:
            out.write("{}\n")
        base = time.time() - 2
        replacement = self.record(payload={
            "hook_event_name": "SessionStart", "session_id": other_sid,
            "transcript_path": other_path}, received_at=base + 1)
        old_start = self.record(payload={
            "hook_event_name": "SessionStart"}, received_at=base)
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, supervisor_id=self.SUPERVISOR)
        with mock.patch.object(supervisor, "_read_events",
                               side_effect=[[replacement], [old_start]]):
            runner._handle_events(self.child, "")
            runner._handle_events(self.child, "")
        self.assertEqual(self.child.binding.session_id, other_sid)
        self.assertFalse(self.child.automation)

    def test_lost_replacement_session_start_permanently_disables(self):
        end = self.record(payload={"hook_event_name": "SessionEnd"})
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, supervisor_id=self.SUPERVISOR)
        with mock.patch.object(supervisor, "_read_events", return_value=[end]):
            self.assertIsNone(runner._handle_events(self.child, ""))
        self.assertTrue(self.child.session_ended)
        self.assertFalse(self.child.automation)

    def test_malformed_matching_control_events_permanently_disable(self):
        runner = supervisor.Supervisor(
            "sonnet", [], self.child.account, supervisor_id=self.SUPERVISOR)
        for malformed in (
            self.record(payload={"hook_event_name": "CwdChanged", "cwd": None}),
            self.record(payload={"transcript_path": None}),
            self.record(received_at=0),
        ):
            self.child.automation = True
            with mock.patch.object(supervisor, "_read_events",
                                   return_value=[malformed]):
                self.assertIsNone(runner._handle_events(self.child, ""))
            self.assertFalse(self.child.automation)


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

    def test_equals_format_flags_are_incompatible_with_supervision(self):
        self.assertEqual(supervisor.incompatible_args(
            ["--output-format=json"]), "--output-format=json")
        self.assertEqual(supervisor.incompatible_args(
            ["--input-format=stream-json"]), "--input-format=stream-json")

    def test_override_stripping_respects_values_and_bare_separator(self):
        cleaned, auto, no_auto = supervisor.strip_headroom_overrides([
            "--model", "--headroom-auto-handoff",
            "--headroom-no-auto-handoff", "--",
            "--headroom-auto-handoff"])
        self.assertEqual(cleaned, [
            "--model", "--headroom-auto-handoff", "--",
            "--headroom-auto-handoff"])
        self.assertFalse(auto)
        self.assertTrue(no_auto)

    def test_brief_style_boolean_flags_do_not_swallow_overrides_or_settings(self):
        cleaned, auto, no_auto = supervisor.strip_headroom_overrides([
            "--brief", "--headroom-no-auto-handoff", "--future-boolean",
            "--headroom-auto-handoff"])
        self.assertEqual(cleaned, ["--brief", "--future-boolean"])
        self.assertTrue(auto)
        self.assertTrue(no_auto)
        self.assertEqual(supervisor.incompatible_args(
            ["--brief", "--settings", "custom.json"]),
            "user-supplied --settings")

    def test_settings_detection_scans_every_pre_separator_position(self):
        self.assertEqual(supervisor.incompatible_args(
            ["--model", "--settings", "--", "--settings=after.json"]),
            "user-supplied --settings")
        self.assertEqual(supervisor.incompatible_args(
            ["--brief", "--settings=custom.json"]),
            "user-supplied --settings")
        self.assertEqual(supervisor.incompatible_args(
            ["--brief", "--", "--settings=prompt-text"]), "")

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
        self.local_binding = self.binding.start()
        self.quiet = mock.patch.object(supervisor, "QUIET_SECONDS", 0.1)
        self.quiet.start()
        self.cwd_before = os.getcwd()
        self.cwd = os.path.join(self.temp.name, "work")
        os.makedirs(self.cwd)
        os.chdir(self.cwd)
        self.accounts = self.make_accounts("source", "target")

    def tearDown(self):
        os.chdir(self.cwd_before)
        self.quiet.stop()
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
        runner = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot)
        result = runner.run()
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
        self.assertEqual(bound["target_slot"], "target")
        self.assertNotIn("source_slot", bound)
        with open(destination, encoding="utf-8") as copied:
            self.assertIn("sigterm_flush", copied.read())
        self.assertTrue(all(not os.path.exists(path)
                            for path in runner.settings_files))
        self.assertFalse(os.path.exists(supervisor.event_path(
            runner.supervisor_id)))

    def test_fake_child_handoffs_after_delayed_cap_transcript_flush(self):
        os.environ["FAKE_CLAUDE_SCENARIO"] = "delayed-flush"
        runner = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot)
        self.assertEqual(runner.run(), 0)
        self.assertTrue(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))
        actions = [row.get("action") for row in self.ledger_actions()]
        self.assertIn("cap_confirmed", actions)
        self.assertIn("stop_sent", actions)

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

    def test_cap_proof_expires_when_reset_elapses_before_preflight(self):
        def expired_snapshot(quiet=True):
            snapshot = self.snapshot(quiet)
            source = next(row for row in snapshot["accounts"]
                          if row["name"] == "source")
            source["windows"]["5h"]["resets_at"] = time.time() - 1
            return snapshot

        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=expired_snapshot).run()
        self.assertEqual(result, 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))

    def test_cap_time_fable_model_refuses_fable_capped_target(self):
        os.environ["FAKE_CAP_MODEL"] = "claude-fable-5-20260701"

        def fable_snapshot(quiet=True):
            snapshot = self.snapshot(quiet)
            target = next(row for row in snapshot["accounts"]
                          if row["name"] == "target")
            target["windows"]["scoped:Fable"] = {
                "used_percent": 100, "resets_at": time.time() + 86400}
            return snapshot

        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=fable_snapshot).run()
        self.assertEqual(result, 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))

    def test_clear_and_resume_transitions_never_use_stale_cap_proof(self):
        for scenario in ("clear", "resume-transition"):
            with self.subTest(scenario=scenario):
                os.environ["FAKE_CLAUDE_SCENARIO"] = scenario
                result = supervisor.Supervisor(
                    "sonnet", [], self.accounts[0],
                    collect_fn=self.snapshot).run()
                self.assertEqual(result, 0)
                self.assertFalse(os.path.exists(
                    os.path.join(self.fake_state, "sigterm-source")))

    def test_pre_stop_runtime_error_disables_automation_without_crashing(self):
        with mock.patch.object(handoff, "select_target",
                               side_effect=RuntimeError("registry changed")):
            result = supervisor.Supervisor(
                "sonnet", [], self.accounts[0],
                collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))

    def test_unreadable_cooldown_state_is_held_before_sigterm(self):
        os.makedirs(os.path.dirname(paths.cooldowns_path()), exist_ok=True)
        with open(paths.cooldowns_path(), "w") as out:
            out.write("{broken")
        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))

    def test_post_stop_runtime_error_always_recovers_source(self):
        with mock.patch.object(handoff, "commit_handoff",
                               side_effect=RuntimeError("commit exploded")):
            result = supervisor.Supervisor(
                "sonnet", [], self.accounts[0],
                collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        with open(os.path.join(self.fake_state, "recovered"),
                  encoding="utf-8") as source:
            self.assertIn("--resume", source.read())

    def test_post_commit_target_spawn_failure_recovers_source(self):
        real_popen = supervisor.subprocess.Popen
        attempts = {"count": 0}

        def fail_target(argv, **kwargs):
            attempts["count"] += 1
            if attempts["count"] == 2:
                raise OSError("target spawn exploded")
            return real_popen(argv, **kwargs)

        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot,
            popen=fail_target).run()
        self.assertEqual(result, 0)
        self.assertEqual(attempts["count"], 3)
        with open(os.path.join(self.fake_state, "recovered"),
                  encoding="utf-8") as source:
            self.assertIn("--resume", source.read())

    def test_spawn_time_target_identity_swap_recovers_source(self):
        source_sid = str(__import__("uuid").uuid5(
            __import__("uuid").NAMESPACE_DNS, "headroom-fake-source-1"))
        destination = os.path.join(
            self.accounts[1]["home"], "projects", "fake-project",
            source_sid + ".jsonl")

        def swap_after_commit(_provider, home):
            if home == self.accounts[1]["home"] and os.path.exists(destination):
                return "OTHER", "CHANGED"
            return "AAAA", "BBBB"

        self.local_binding.side_effect = swap_after_commit
        result = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        with open(os.path.join(self.fake_state, "launches.jsonl"),
                  encoding="utf-8") as source:
            launches = [json.loads(line) for line in source]
        self.assertEqual(len(launches), 2)
        self.assertEqual(launches[1]["config_dir"], self.accounts[0]["home"])
        with open(os.path.join(self.fake_state, "recovered"),
                  encoding="utf-8") as source:
            self.assertIn("--resume", source.read())

    def test_failed_source_recovery_prints_both_manual_resume_commands(self):
        real_popen = supervisor.subprocess.Popen
        attempts = {"count": 0}

        def fail_target_and_recovery(argv, **kwargs):
            attempts["count"] += 1
            if attempts["count"] in (2, 3):
                raise OSError(f"spawn {attempts['count']} exploded")
            return real_popen(argv, **kwargs)

        errors = io.StringIO()
        with redirect_stderr(errors):
            result = supervisor.Supervisor(
                "sonnet", [], self.accounts[0], collect_fn=self.snapshot,
                popen=fail_target_and_recovery).run()
        self.assertEqual(result, 127)
        source_sid = str(__import__("uuid").uuid5(
            __import__("uuid").NAMESPACE_DNS, "headroom-fake-source-1"))
        self.assertIn(handoff.resume_command(
            self.accounts[1]["home"], source_sid), errors.getvalue())
        self.assertIn(
            f"CLAUDE_CONFIG_DIR={self.accounts[0]['home']} claude --resume "
            f"{source_sid}", errors.getvalue())

    def test_target_relogin_after_stop_recovers_source_without_publication(self):
        original_commit = handoff.commit_handoff

        def relog_then_commit(plan):
            self.local_binding.return_value = ("OTHER", "CHANGED")
            return original_commit(plan)

        with mock.patch.object(handoff, "commit_handoff",
                               side_effect=relog_then_commit):
            result = supervisor.Supervisor(
                "sonnet", [], self.accounts[0],
                collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        with open(os.path.join(self.fake_state, "recovered"),
                  encoding="utf-8") as source:
            self.assertIn("--resume", source.read())
        source_sid = str(__import__("uuid").uuid5(
            __import__("uuid").NAMESPACE_DNS, "headroom-fake-source-1"))
        self.assertFalse(os.path.exists(os.path.join(
            self.accounts[1]["home"], "projects", "fake-project",
            source_sid + ".jsonl")))

    def test_post_stop_cooldown_runtime_error_always_recovers_source(self):
        with mock.patch.object(route, "mark",
                               side_effect=RuntimeError("cooldown corrupt")):
            result = supervisor.Supervisor(
                "sonnet", [], self.accounts[0],
                collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        with open(os.path.join(self.fake_state, "recovered"),
                  encoding="utf-8") as source:
            self.assertIn("--resume", source.read())

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

    def test_fast_session_end_after_sigterm_is_accepted(self):
        runner = supervisor.Supervisor(
            "sonnet", [], self.accounts[0], collect_fn=self.snapshot)
        real_kill = supervisor.os.kill
        observed = {"ledger_before_kill": False}
        source_sid = str(__import__("uuid").uuid5(
            __import__("uuid").NAMESPACE_DNS, "headroom-fake-source-1"))
        transcript = os.path.join(
            self.accounts[0]["home"], "projects", "fake-project",
            source_sid + ".jsonl")

        def emit_end_before_kill_returns(pid, sig):
            observed["ledger_before_kill"] = any(
                row.get("action") == "stop_sent"
                for row in self.ledger_actions())
            record = {
                "schema": "headroom_hook_event@1",
                "received_at": time.time(),
                "supervisor_id": runner.supervisor_id,
                "generation": runner.generation,
                "source_slot": "source",
                "config_dir": self.accounts[0]["home"],
                "matcher": "",
                "payload": {
                    "hook_event_name": "SessionEnd",
                    "session_id": source_sid,
                    "transcript_path": transcript,
                    "cwd": self.cwd,
                    "reason": "other",
                },
            }
            with open(supervisor.event_path(runner.supervisor_id), "a",
                      encoding="utf-8") as out:
                out.write(json.dumps(record) + "\n")
                out.flush()
                os.fsync(out.fileno())
            return real_kill(pid, sig)

        with mock.patch.object(supervisor.os, "kill",
                               side_effect=emit_end_before_kill_returns):
            result = runner.run()
        self.assertEqual(result, 0)
        self.assertTrue(observed["ledger_before_kill"])
        actions = [row.get("action") for row in self.ledger_actions()]
        self.assertIn("staged", actions)

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

    def test_child_inherits_foreground_group_and_receives_ctrl_c_and_term(self):
        os.environ["FAKE_CLAUDE_SCENARIO"] = "foreground"
        account = self.accounts[0]
        code = (
            "from headroom.supervisor import Supervisor; "
            f"raise SystemExit(Supervisor('sonnet', [], {account!r}).run())")

        def exercise(kind):
            pid, descriptor = pty.fork()
            if pid == 0:
                environment = os.environ.copy()
                environment["PYTHONPATH"] = os.path.dirname(
                    os.path.dirname(os.path.abspath(__file__)))
                os.execve(sys.executable,
                          [sys.executable, "-c", code], environment)
            output = b""
            sent = False
            deadline = time.time() + 5
            while time.time() < deadline:
                ready, _, _ = select.select([descriptor], [], [], 0.1)
                if ready:
                    try:
                        output += os.read(descriptor, 4096)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                if not sent and b"PGRP_OK" in output:
                    if kind == "ctrl-c":
                        os.write(descriptor, b"\x03")
                    else:
                        os.kill(pid, signal.SIGTERM)
                    sent = True
                done, status = os.waitpid(pid, os.WNOHANG)
                if done:
                    self.assertTrue(os.WIFEXITED(status))
                    break
            else:
                os.kill(pid, signal.SIGKILL)
                self.fail("pty supervisor did not exit")
            os.close(descriptor)
            self.assertTrue(sent)
            self.assertIn(b"PGRP_OK", output)
            self.assertIn(
                b"SIGINT_OK" if kind == "ctrl-c" else b"SIGTERM_OK", output)

        exercise("ctrl-c")
        exercise("term")


if __name__ == "__main__":
    unittest.main()
