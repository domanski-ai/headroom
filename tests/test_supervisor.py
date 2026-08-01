"""v0.2 transactional handoff and resident supervisor tests."""
import errno
import hashlib
import io
import json
import multiprocessing
import os
if os.name != "nt":
    import pty
import select
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
    __main__, collect, handoff, locks, notify, paths, registry, route,
    statusline, supervisor,
)

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="resident supervision is Unix-gated in v1")


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


class CapVocabulary(unittest.TestCase):
    """One cap vocabulary, shared by route and the supervisor.

    It was two copies and they drifted twice: `out of usage credits` reached
    only the supervisor (after a Fable cap slipped past on 2026-07-23), and
    every 5-hour wording reached only route — so a session refused with "hit
    your 5-hour limit" was invisible to the cap-reactive path.
    """

    CAPS = (
        "You've hit your session limit",
        "You’ve hit your weekly limit · resets Friday",
        "hit your usage limit",
        "You've hit your weekly limit for Claude Opus 5",
        "You've hit your 5-hour limit",
        "You've hit your 5 hour limit",
        "You've hit your 5hour limit",
        "you've hit your five-hour limit",
        "You've hit your five hour limit",
        "Usage limit reached",
        "You're out of usage credits. Run /usage-credits to keep using Fable 5",
    )
    TRANSIENT = (
        "rate_limit_error",
        "API Error: hit the rate limit, retrying",
        "429 Too Many Requests",
        "status 429",
        "overloaded_error",
    )

    def test_the_supervisor_reads_the_same_object_route_does(self):
        self.assertIs(supervisor.CAP_RE, route.CAP_RE)

    def test_every_cap_wording_either_side_knows_is_a_cap_on_both(self):
        for text in self.CAPS:
            self.assertTrue(route.CAP_RE.search(text), text)
            self.assertTrue(supervisor.CAP_RE.search(text), text)
            # a cap is also a limit: `route.run` must end the attempt too
            self.assertTrue(route.LIMIT_RE.search(text), text)

    def test_transient_refusals_are_limits_but_never_caps(self):
        # they heal on their own — retried on the same seat, never rotated
        for text in self.TRANSIENT:
            self.assertTrue(route.LIMIT_RE.search(text), text)
            self.assertIsNone(route.CAP_RE.search(text), text)
            self.assertIsNone(supervisor.CAP_RE.search(text), text)

    def test_every_five_hour_spelling_scopes_to_the_5h_window(self):
        # a "five hour" cap corroborated by the 7d window would cool the seat
        # for a week over a window that heals in hours (the old inline check
        # knew "5 hour" and "five-hour" but not "five hour" or "5hour")
        now = int(time.time())
        capped_weekly = {"accounts": [usage_row("a", used5=10, used7=100,
                                                captured=now)]}
        capped_session = {"accounts": [usage_row("a", used5=99, used7=10,
                                                 captured=now)]}
        for text in self.CAPS:
            if not route.SESSION_RE.search(text):
                continue
            self.assertIsNone(
                route.cap_scope(capped_weekly, "a", "sonnet", text), text)
            scope = route.cap_scope(capped_session, "a", "sonnet", text)
            self.assertEqual((scope or {}).get("window"), "5h", text)


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


class CooldownCeiling(unittest.TestCase):
    """`route.mark` clamps UP to a floor and stores `max(epoch, previous)`, so
    a cooldown could only ever GROW. A millisecond-valued reset therefore
    parked a seat ~56,000 years out and nothing said so.

    The subtlety that decides the shape of the fix: the ledger key
    (`name:*` / `name:<fam>`) does NOT record which window wrote it — BOTH key
    shapes take both a 7d write and a 5h write. So a ceiling derived from the
    CURRENT call's window may bound only the value that call carries; a value
    already in the ledger can only be judged against the largest ceiling any
    window can produce. Getting that wrong collapses a live 7-day wall to 12
    hours and reopens a provider-walled seat about six days early."""

    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        env = mock.patch.dict(os.environ, {"HEADROOM_DIR": self.root.name})
        env.start()
        self.addCleanup(env.stop)
        self.now = time.time()

    def seed(self, ledger):
        path = paths.cooldowns_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as out:
            json.dump(ledger, out)

    def mark(self, *args, **kwargs):
        """`route.mark`, returning (result, stderr)."""
        err = io.StringIO()
        with redirect_stderr(err):
            result = route.mark(*args, **kwargs)
        return result, err.getvalue()

    # ---- the key does not record the window -------------------------------

    def test_a_5h_mark_may_not_collapse_a_7d_wall_account_wide(self):
        """The `route.py:1292` writer (window="7d") and the `route.py:1516`
        writer (no window= argument at all) share the key `a:*`."""
        seven = self.now + 7 * 86400
        route.mark("a", "fable", seven, account_wide=True, window="7d")
        route.mark("a", "fable", self.now + 5 * 3600, account_wide=True)
        self.assertEqual(route.cooldowns()["a:*"], seven,
                         "a 5h mark collapsed a live 7-day wall")

    def test_a_5h_mark_may_not_collapse_a_7d_wall_on_the_scoped_key(self):
        """The same collision on the other key shape: `handoff.py` writes
        `a:fable` with window="7d", `__main__.py mark` writes it with 5h."""
        seven = self.now + 7 * 86400
        route.mark("a", "fable", seven, window="7d")
        route.mark("a", "fable", self.now + 3600)
        self.assertEqual(route.cooldowns()["a:fable"], seven)

    # ---- the incoming value ------------------------------------------------

    def test_an_incoming_millisecond_reset_is_bounded_by_its_own_window(self):
        result, _ = self.mark("a", "sonnet", self.now * 1000)
        self.assertAlmostEqual(result, self.now + 12 * 3600, delta=5)
        self.assertGreater(result, self.now)
        route.clear()
        result, _ = self.mark("a", "sonnet", self.now * 1000, window="7d")
        self.assertAlmostEqual(result, self.now + 9 * 86400, delta=5)
        self.assertGreater(result, self.now)

    def test_narrowing_an_incoming_value_is_never_silent(self):
        """`headroom mark <name> <model> <epoch>` always uses the default 5h
        window, so an operator-supplied epoch days out is now clamped. A
        user-visible narrowing that happens quietly is a trap."""
        result, err = self.mark("a", "fable", self.now + 3 * 86400)
        self.assertAlmostEqual(result, self.now + 12 * 3600, delta=5)
        self.assertIn("clamped", err)
        self.assertIn("a:fable", err)
        route.clear()
        result, err = self.mark("a", "fable", self.now + 3 * 86400,
                                window="7d")
        self.assertAlmostEqual(result, self.now + 3 * 86400, delta=5)
        self.assertEqual(err, "", "a 7d value inside the 7d ceiling is not "
                                  "narrowed and must say nothing")

    # ---- the value already in the ledger -----------------------------------

    def test_a_poisoned_stored_value_is_clamped_announced_and_decays(self):
        self.seed({"a:*": self.now * 1000})
        emitted = []
        with mock.patch.object(notify, "emit", emitted.append):
            result, err = self.mark("a", "fable", self.now + 5 * 3600,
                                    account_wide=True)
        self.assertAlmostEqual(result, self.now + 9 * 86400, delta=5)
        # the discriminating assertion: repaired, NOT replaced by this call
        self.assertNotAlmostEqual(result, self.now + 5 * 3600, delta=60)
        self.assertIn("headroom clear a:*", err)
        self.assertEqual([event["event"] for event in emitted],
                         ["cooldown_corrupt_repaired"])
        self.assertEqual(emitted[0]["was"], self.now * 1000)
        self.assertAlmostEqual(emitted[0]["now"], self.now + 9 * 86400,
                               delta=5)
        # ...and it DECAYS: an hour later the repaired value is not re-clamped
        repaired = result
        emitted.clear()
        later = self.now + 3600
        with mock.patch.object(time, "time", lambda: later), \
                mock.patch.object(notify, "emit", emitted.append):
            second, err = self.mark("a", "fable", later + 5 * 3600,
                                    account_wide=True)
        self.assertEqual(second, repaired)
        self.assertEqual(emitted, [])
        self.assertEqual(err, "")

    def test_a_legitimate_long_entry_is_never_touched_by_a_short_mark(self):
        """Eight days out — inside MAX, far outside the 5h ceiling. This is
        the value the rejected per-call-window ceiling would have destroyed."""
        eight = self.now + 8 * 86400
        self.seed({"a:*": eight})
        emitted = []
        with mock.patch.object(notify, "emit", emitted.append):
            result, err = self.mark("a", "fable", self.now + 5 * 3600,
                                    account_wide=True)
        self.assertEqual(result, eight)
        self.assertEqual(err, "")
        self.assertEqual(emitted, [])

    def test_a_poisoned_key_does_not_reopen_a_seat_inside_its_real_wall(self):
        """The fail-open guard, and the reason the repair CLAMPS rather than
        discards. A millisecond mark does not sit BESIDE the legitimate wall
        it landed on — the store is max(), so it OVERWROTE it and the real
        reset is unrecoverable from this file. Replacing the poison with the
        current call's epoch would reopen the seat ~6.75 days early."""
        route.mark("a", "fable", self.now + 6.958 * 86400,
                   account_wide=True, window="7d")
        self.seed({"a:*": self.now * 1000})       # the poison overwrites it
        with mock.patch.object(notify, "emit", lambda event: None):
            result, _ = self.mark("a", "fable", self.now + 5 * 3600,
                                  account_wide=True)
        self.assertGreaterEqual(result, self.now + 7 * 86400,
                                "the seat was reopened inside its 7d wall")

    # ---- the invariant the table has to keep -------------------------------

    def test_no_window_ceiling_may_exceed_the_absolute_bound(self):
        """MAX is DERIVED from the table, so a future window with a longer
        ceiling widens the absolute bound automatically instead of silently
        falling outside it. A ceiling below its own floor, or a table whose
        max is not MAX, fails here rather than shipping."""
        table = route.WINDOW_COOLDOWN_CEILING
        self.assertEqual(route.MAX_COOLDOWN_SECONDS, max(table.values()))
        for window, ceiling in table.items():
            floor = 6 * 3600 if window == "7d" else 15 * 60
            self.assertLess(floor, ceiling, window)
            self.assertLessEqual(ceiling, route.MAX_COOLDOWN_SECONDS, window)


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
                    locks.exclusive(held, blocking=False)
                    locked_snapshot = collect.run_collect(quiet=True)
                    locks.unlock(held)
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
            copied_bytes = copied.read()
            source_bytes = source_f.read()
        self.assertTrue(copied_bytes.startswith(source_bytes))
        self.assertEqual(copied_bytes.count(b'"type":"headroom_handoff"'), 1)

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

    def aborted_admission(self, target="old"):
        """A reservation released by a failure that never stopped a child."""
        handoff_id = str(__import__("uuid").uuid4())
        handoff.append_action(handoff_id, "cap_confirmed", automatic=True,
                              source_slot="source", target_slot=target,
                              old_session_id=self.SID)
        handoff.append_action(handoff_id, "failure", automatic=True,
                              source_slot="source", target_slot=target,
                              reason="preemptive_pre_stop_failed: raced",
                              old_session_id=self.SID)
        return handoff_id

    def test_aborted_admissions_do_not_consume_the_loop_budget(self):
        # the composition that matters: several preemptive attempts reserve a
        # target and are released without ever stopping a child, then a REAL
        # cap arrives inside the same ten minutes. It must still hand off —
        # otherwise aborted optimisations disable supervision.
        for _ in range(3):
            self.aborted_admission()
        record = handoff.reserve_automatic(self.automatic_plan())
        self.assertEqual(record["action"], "cap_confirmed")

    def test_admissions_that_stopped_a_child_still_trip_the_loop_guard(self):
        for _ in range(3):
            handoff_id = self.aborted_admission()
            # this one really did stop a session before failing
            handoff.append_action(handoff_id, "stop_sent", automatic=True,
                                  source_slot="source",
                                  old_session_id=self.SID)
        with self.assertRaisesRegex(handoff.HandoffError, "loop guard"):
            handoff.reserve_automatic(self.automatic_plan())

    def test_edge_cancelled_stops_do_not_consume_the_loop_budget(self):
        # a stop_sent row is durable BEFORE any signal, so a last-instant
        # idleness cancellation leaves one behind having touched nothing
        for _ in range(3):
            handoff_id = str(__import__("uuid").uuid4())
            handoff.append_action(handoff_id, "cap_confirmed", automatic=True,
                                  source_slot="source", target_slot="old",
                                  old_session_id=self.SID)
            handoff.append_action(handoff_id, "stop_sent", automatic=True,
                                  source_slot="source",
                                  old_session_id=self.SID)
            handoff.append_action(
                handoff_id, "failure", automatic=True, source_slot="source",
                target_slot="old", old_session_id=self.SID,
                reason="preemptive_stop_cancelled_on_edge",
                stop_cancelled=True)
        record = handoff.reserve_automatic(self.automatic_plan())
        self.assertEqual(record["action"], "cap_confirmed")

    def test_in_flight_admissions_still_count(self):
        for _ in range(3):
            handoff.append_action(
                str(__import__("uuid").uuid4()), "cap_confirmed",
                automatic=True, source_slot="source", target_slot="old",
                old_session_id=self.SID)
        with self.assertRaisesRegex(handoff.HandoffError, "loop guard"):
            handoff.reserve_automatic(self.automatic_plan())

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

    def test_parser_accepts_scoped_model_out_of_credits_cap(self):
        # a Fable-scoped weekly cap surfaces as "out of usage credits", not
        # "hit your … limit"; it must still be recognised so the seat hands off
        # (regression: this wording slipped past CAP_RE, so a seat that had
        # capped on Fable sat there and never rotated).
        rec = self.record("You're out of usage credits. Run /usage-credits to "
                          "keep using Fable 5 or /model to switch models.")
        self.assertIn("out of usage credits",
                      supervisor.cap_message(rec, self.child))

    def test_parser_accepts_every_five_hour_wording(self):
        # route has always matched these; the supervisor's copy did not, so a
        # 5-hour refusal worded this way never reached the cap-reactive path
        for text in ("You've hit your 5-hour limit · resets 12:20pm (UTC)",
                     "You've hit your 5 hour limit",
                     "you've hit your five-hour limit",
                     "You've hit your five hour limit"):
            self.assertEqual(supervisor.cap_message(self.record(text),
                                                    self.child), text, text)

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
        # Each timeout buys another window, bounded by CAP_MODEL_RETRIES. A
        # transcript that has not been flushed yet is an ABSENCE of evidence,
        # not a contradicted proof, and 6s is a short window to bet a live
        # session's automation on.
        for extension in range(1, supervisor.CAP_MODEL_RETRIES + 1):
            clock[0] += supervisor.CAP_MODEL_TIMEOUT
            hold = runner._prove_cap(self.child, hold.event)
            self.assertIsInstance(hold, supervisor.PendingCap)
            self.assertEqual(hold.extensions, extension)
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
        windows = supervisor.CAP_MODEL_RETRIES + 1
        with mock.patch.object(supervisor, "_read_events",
                               side_effect=[[record]] + [[]] * windows), \
                mock.patch("headroom.supervisor.os.kill") as kill, \
                redirect_stderr(output):
            self.assertIsNone(runner._handle_events(self.child, ""))
            self.assertTrue(self.child.automation)
            for _ in range(supervisor.CAP_MODEL_RETRIES):
                clock[0] += supervisor.CAP_MODEL_TIMEOUT
                self.assertIsNone(runner._handle_events(self.child, ""))
                # one 6-second window no longer costs a live session its
                # automation — the lookup gets a bounded number of them
                self.assertTrue(self.child.automation)
            clock[0] += supervisor.CAP_MODEL_TIMEOUT
            self.assertIsNone(runner._handle_events(self.child, ""))
        self.assertFalse(self.child.automation)
        self.assertIsNone(self.child.pending_cap)
        kill.assert_not_called()
        self.assertIn(
            f"could not determine the cap-time model before "
            f"{supervisor.CAP_MODEL_TIMEOUT * windows:g}s", output.getvalue())
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
    def setUp(self):
        # a direct _spawn call installs the signal guard and leaves it for
        # _monitor; with no _monitor here, restore handlers after each test
        saved = {s: signal.getsignal(s)
                 for s in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)}
        self.addCleanup(
            lambda: [signal.signal(s, h) for s, h in saved.items()])

    def test_plain_claude_with_auto_off_keeps_exec_path(self):
        with mock.patch.object(registry, "auto_handoff", return_value=False), \
                mock.patch("headroom.route.cmd_exec", return_value=17) as execute:
            result = __main__._dispatch(["claude", "--model", "sonnet"])
        self.assertEqual(result, 17)
        execute.assert_called_once_with("sonnet", ["claude", "--model", "sonnet"],
                                        launch_note="auto-handoff not enabled")

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
        execute.assert_called_once_with("sonnet", ["claude", "--model", "sonnet"],
                                        launch_note="auto-handoff not enabled")

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
        # a user --settings is merged, never a reason to drop supervision
        self.assertEqual(supervisor.incompatible_args(
            ["--brief", "--settings", "custom.json"]), "")

    def test_settings_is_never_an_incompatible_flag(self):
        # the old behaviour returned "user-supplied --settings" here and the
        # whole run went unsupervised — silently, since it still started
        for argv in (["--brief", "--settings", "custom.json"],
                     ["--brief", "--settings=custom.json"],
                     ["--model", "--settings", "--", "--settings=after.json"],
                     ["--brief", "--", "--settings=prompt-text"]):
            self.assertEqual(supervisor.incompatible_args(argv), "", argv)

    def test_settings_split_is_value_aware_and_last_wins(self):
        self.assertEqual(
            supervisor.split_user_settings(["--brief", "--settings=one.json"]),
            (["--brief"], "one.json"))
        # a second --settings replaces the first exactly as Claude's does
        self.assertEqual(
            supervisor.split_user_settings(
                ["--settings", "one.json", "--model", "sonnet",
                 "--settings=two.json"]),
            (["--model", "sonnet"], "two.json"))
        # --settings as ANOTHER option's value is that option's value
        self.assertEqual(
            supervisor.split_user_settings(
                ["--model", "--settings", "--", "--settings=after.json"]),
            (["--model", "--settings", "--", "--settings=after.json"], None))
        # and after `--` it is prompt text, never an option
        self.assertEqual(
            supervisor.split_user_settings(
                ["--brief", "--", "--settings=prompt-text"]),
            (["--brief", "--", "--settings=prompt-text"], None))

    def test_settings_with_no_value_refuses_instead_of_guessing(self):
        with self.assertRaises(supervisor.UserSettingsError):
            supervisor.split_user_settings(["--brief", "--settings"])

    def test_option_classes_match_the_cli_and_never_swallow_settings(self):
        # `--ide` is BOOLEAN and `--resume`/`-r` take an OPTIONAL value; both
        # sat in the required table, so these argv shapes walked straight past
        # the user's settings and left it on the child's argv
        for prefix in (["--ide"], ["--resume"], ["-r"], ["--fork-session"],
                       ["--brief"], ["--tmux"], ["--worktree"], ["-d"]):
            self.assertEqual(
                supervisor.split_user_settings(
                    prefix + ["--settings", "u.json"]),
                (prefix, "u.json"), prefix)
            self.assertEqual(
                supervisor.split_user_settings(prefix + ["--settings=u.json"]),
                (prefix, "u.json"), prefix)
        # an optional value that is NOT option-shaped is still consumed
        self.assertEqual(
            supervisor.split_user_settings(
                ["--resume", "abc123", "--settings", "u.json"]),
            (["--resume", "abc123"], "u.json"))
        # and the opposite misparse: a REQUIRED option's value stays its value
        for required in ("--agent", "--effort", "--name", "-n",
                         "--managed-settings", "--setting-sources"):
            self.assertEqual(
                supervisor.split_user_settings([required, "--settings"]),
                ([required, "--settings"], None), required)

    def test_takes_value_is_the_one_grammar_every_walker_shares(self):
        self.assertTrue(supervisor.takes_value("--model", "sonnet"))
        self.assertTrue(supervisor.takes_value("--agent", "--settings"))
        self.assertFalse(supervisor.takes_value("--ide", "--settings"))
        self.assertFalse(supervisor.takes_value("--brief", "anything"))
        # commander's optional-value rule, both directions
        self.assertTrue(supervisor.takes_value("--resume", "abc123"))
        self.assertFalse(supervisor.takes_value("--resume", "--settings"))
        self.assertFalse(supervisor.takes_value("--resume", None))
        self.assertTrue(supervisor.takes_value("--resume", "-"))   # not option

    def test_the_grammar_fix_reaches_the_other_walkers_too(self):
        # `--ide` used to eat the next token, so a -p run looked supervisable
        self.assertEqual(supervisor.incompatible_args(["--ide", "-p"]), "-p")
        self.assertEqual(
            supervisor.incompatible_args(["--resume", "--print"]), "--print")
        # and it used to eat a headroom override instead of stripping it
        cleaned, _auto, no_auto = supervisor.strip_headroom_overrides(
            ["--resume", "--headroom-no-auto-handoff"])
        self.assertEqual(cleaned, ["--resume"])
        self.assertTrue(no_auto)

    def test_settings_merge_keeps_supervision_and_the_user_document(self):
        merged = supervisor.merge_user_settings({
            "ultracode": True, "effortLevel": "high", "model": "opus",
            "statusLine": {"type": "command", "command": "mine"},
            "hooks": {"SessionStart": [{"hooks": [{"type": "command",
                                                   "command": "mine"}]}],
                      "PreToolUse": [{"matcher": "Bash", "hooks": []}]},
        }, "/tmp/user.json")
        # user keys pass through untouched
        self.assertTrue(merged["ultracode"])
        self.assertEqual(merged["effortLevel"], "high")
        self.assertEqual(merged["model"], "opus")
        self.assertEqual(merged["statusLine"]["command"], "mine")
        self.assertEqual(merged["hooks"]["PreToolUse"],
                         [{"matcher": "Bash", "hooks": []}])
        # every supervised event carries the supervisor's group FIRST, and
        # the user's own SessionStart hook still runs after it
        injected = supervisor.hook_settings()["hooks"]
        for event, groups in injected.items():
            self.assertEqual(merged["hooks"][event][:len(groups)], groups)
        self.assertEqual(merged["hooks"]["SessionStart"][1],
                         {"hooks": [{"type": "command", "command": "mine"}]})

    def test_settings_merge_without_a_user_document_is_unchanged(self):
        # the no-settings launch must stay byte-identical to before merging
        self.assertEqual(supervisor.merge_user_settings(),
                         supervisor.hook_settings())
        self.assertEqual(supervisor.merge_user_settings({}),
                         supervisor.hook_settings())

    def test_settings_merge_never_mutates_the_user_document(self):
        document = {"hooks": {"SessionStart": []}}
        supervisor.merge_user_settings(document, "/tmp/user.json")
        self.assertEqual(document, {"hooks": {"SessionStart": []}})

    def test_settings_that_cannot_be_merged_are_refused_by_name(self):
        for document, offender in (
                ({"disableAllHooks": True}, "disableAllHooks"),
                ({"allowManagedHooksOnly": True}, "allowManagedHooksOnly"),
                ({"env": {"CLAUDE_CONFIG_DIR": "/elsewhere"}},
                 "CLAUDE_CONFIG_DIR"),
                ({"env": {"HEADROOM_SUPERVISOR_ID": "x"}},
                 "HEADROOM_SUPERVISOR_ID"),
                ({"env": {"CLAUDE_CODE_SAFE_MODE": "1"}},
                 "CLAUDE_CODE_SAFE_MODE"),
                # what --bare sets; 2.1.220's own help: "skip hooks … Sets
                # CLAUDE_CODE_SIMPLE=1"
                ({"env": {"CLAUDE_CODE_SIMPLE": "1"}}, "CLAUDE_CODE_SIMPLE"),
                ({"env": ["nope"]}, "env"),
                ({"hooks": ["nope"]}, "hooks"),
                ({"hooks": {"SessionStart": "mine"}}, "hooks.SessionStart")):
            with self.assertRaises(supervisor.UserSettingsError) as caught:
                supervisor.merge_user_settings(document, "/tmp/user.json")
            self.assertIn(offender, str(caught.exception))
            self.assertIn("/tmp/user.json", str(caught.exception))

    def test_managed_settings_cannot_be_merged_and_is_refused_by_name(self):
        # policy settings sit ABOVE the merged document: an
        # allowManagedHooksOnly / strictPluginOnlyCustomization in there turns
        # the injected hooks off and no merge can answer for it
        for argv in (["--managed-settings", "policy.json"],
                     ["--managed-settings=policy.json"],
                     ["--model", "sonnet", "--managed-settings", "p.json"]):
            with self.assertRaises(supervisor.UserSettingsError) as caught:
                supervisor.validate_user_settings(argv)
            self.assertIn("--managed-settings", str(caught.exception))
        # …but only when it IS an option: as another option's value, or as
        # prompt text, it is not one
        self.assertEqual(supervisor.hook_suppressing_flag(
            ["--model", "--managed-settings"]), "")
        self.assertEqual(
            supervisor.hook_suppressing_flag(["--", "--managed-settings"]), "")

    def test_the_reserved_env_rule_is_a_namespace_not_a_list(self):
        # round 1 enumerated names and missed two; the rule is now the two
        # control surfaces themselves, so a knob added by a later CLI release
        # is covered before it exists
        for key in ("CLAUDE_CODE_SHELL_PREFIX",     # replaces the command
                    "CLAUDE_CODE_SHELL",            # replaces the shell
                    "CLAUDE_CODE_PROCESS_WRAPPER",  # wraps the process
                    "CLAUDE_CODE_FORCE_SANDBOX",
                    "CLAUDE_CODE_SIMPLE", "CLAUDE_CODE_SAFE_MODE",
                    "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_A_KNOB_FROM_2027",
                    "HEADROOM_DIR",                 # moves the state tree
                    "HEADROOM_SUPERVISOR_ID", "HEADROOM_ANYTHING",
                    "HOME", "USERPROFILE"):         # relocate ~/.headroom
            with self.assertRaises(supervisor.UserSettingsError) as caught:
                supervisor.merge_user_settings({"env": {key: "1"}},
                                               "/tmp/user.json")
            self.assertIn(key, str(caught.exception), key)
        # the operator's own variables are exactly what merging is for
        merged = supervisor.merge_user_settings(
            {"env": {"ANTHROPIC_API_KEY": "sk-x", "AWS_PROFILE": "work",
                     "NODE_ENV": "test", "MY_CLAUDE_TOKEN": "t"}},
            "/tmp/user.json")
        self.assertEqual(merged["env"]["AWS_PROFILE"], "work")
        self.assertEqual(merged["env"]["MY_CLAUDE_TOKEN"], "t")

    def test_the_injected_hook_command_pins_the_state_tree(self):
        # the event path may not depend on the env check being complete
        expected = "HEADROOM_DIR=" + shlex.quote(paths.base_dir())
        for groups in supervisor.hook_settings()["hooks"].values():
            for group in groups:
                for entry in group["hooks"]:
                    self.assertTrue(entry["command"].startswith(expected),
                                    entry["command"])

    def test_an_inline_settings_document_is_never_echoed(self):
        secret = '{"env": {"MY_API_KEY": "sk-super-secret"}}'
        self.assertEqual(supervisor.redacted_settings_value(secret),
                         "<inline JSON>")
        self.assertEqual(supervisor.redacted_settings_value("/tmp/user.json"),
                         "/tmp/user.json")
        rendered = supervisor.redacted_command(
            ["claude", "--settings", secret, "--model", "sonnet"])
        self.assertNotIn("sk-super-secret", rendered)
        self.assertIn("<inline JSON>", rendered)
        self.assertIn("--model sonnet", rendered)

    def test_the_equals_form_hides_the_document_behind_a_dash(self):
        # a first-character test only ever sees `--settings {…}`, never
        # `--settings={…}` — which is how the equals form kept leaking
        secret = '{"env": {"MY_API_KEY": "sk-super-secret"}}'
        self.assertEqual(supervisor.redacted_argument("--settings=" + secret),
                         "--settings=<inline JSON>")
        for token, expected in (
                ("--agents=" + secret, "--agents=<inline JSON>"),
                ("--json-schema=" + secret, "--json-schema=<inline JSON>"),
                ("--managed-settings=" + secret,
                 "--managed-settings=<inline JSON>"),
                (secret, "<inline JSON>"),
                ("--settings=/tmp/user.json", "--settings=/tmp/user.json"),
                ("--model=sonnet", "--model=sonnet"),
                ("--fork-session", "--fork-session"),
                ("/tmp/user.json", "/tmp/user.json")):
            self.assertEqual(supervisor.redacted_argument(token), expected)
        rendered = supervisor.redacted_command(
            ["claude", "--settings=" + secret, "--model", "sonnet"])
        self.assertNotIn("sk-super-secret", rendered)
        self.assertNotIn("MY_API_KEY", rendered)
        self.assertIn("<inline JSON>", rendered)

    def test_every_argv_headroom_prints_goes_through_the_redactor(self):
        # the property is per-renderer, not per-call-site: a resume argv
        # carries no document today, and still cannot start reproducing one
        secret = '{"env": {"MY_API_KEY": "sk-super-secret"}}'
        recovery = supervisor.Recovery(
            {"name": "seat", "home": "/tmp/home"},
            ["--resume", "SID", "--fork-session", "--settings=" + secret],
            "/tmp/work", "SID")
        self.assertNotIn("sk-super-secret", recovery.command())
        self.assertIn("<inline JSON>", recovery.command())
        # …and an ordinary resume command is rendered exactly as before
        plain = supervisor.Recovery(
            {"name": "seat", "home": "/tmp/home"},
            ["--resume", "SID", "--fork-session"], "/tmp/work", "SID")
        self.assertEqual(
            plain.command(),
            "CLAUDE_CONFIG_DIR=/tmp/home claude --resume SID --fork-session")

    def test_a_hook_restricting_key_that_is_off_still_merges(self):
        merged = supervisor.merge_user_settings({"disableAllHooks": False},
                                                "/tmp/user.json")
        self.assertFalse(merged["disableAllHooks"])
        self.assertIn("SessionStart", merged["hooks"])

    def test_an_explicit_null_hooks_block_still_takes_the_injection(self):
        merged = supervisor.merge_user_settings({"hooks": None},
                                                "/tmp/user.json")
        self.assertEqual(merged["hooks"], supervisor.hook_settings()["hooks"])

    def test_settings_are_loaded_from_a_file_or_inline_json(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "user.json")
            with open(path, "w") as handle:
                json.dump({"ultracode": True}, handle)
            document, source = supervisor.load_user_settings(path)
            self.assertEqual(document, {"ultracode": True})
            self.assertEqual(source, path)
        document, source = supervisor.load_user_settings('{"ultracode": true}')
        self.assertEqual(document, {"ultracode": True})
        self.assertEqual(source, "the inline --settings JSON")

    def test_unreadable_settings_refuse_and_name_the_file(self):
        with tempfile.TemporaryDirectory() as root:
            missing = os.path.join(root, "absent.json")
            with self.assertRaises(supervisor.UserSettingsError) as caught:
                supervisor.load_user_settings(missing)
            self.assertIn(missing, str(caught.exception))
            self.assertIn("does not exist", str(caught.exception))

            broken = os.path.join(root, "broken.json")
            with open(broken, "w") as handle:
                handle.write('{"ultracode": ')
            with self.assertRaises(supervisor.UserSettingsError) as caught:
                supervisor.load_user_settings(broken)
            self.assertIn(broken, str(caught.exception))
            self.assertIn("not valid JSON", str(caught.exception))

            listy = os.path.join(root, "list.json")
            with open(listy, "w") as handle:
                handle.write("[1, 2]")
            with self.assertRaises(supervisor.UserSettingsError) as caught:
                supervisor.load_user_settings(listy)
            self.assertIn("must be a JSON object", str(caught.exception))

            # NaN parses but cannot be written back out — catch it at the
            # gate, not at spawn time with the launch already committed
            nan = os.path.join(root, "nan.json")
            with open(nan, "w") as handle:
                handle.write('{"budget": NaN}')
            with self.assertRaises(supervisor.UserSettingsError) as caught:
                supervisor.load_user_settings(nan)
            self.assertIn("portable JSON", str(caught.exception))

        for empty in ("", "   "):
            with self.assertRaises(supervisor.UserSettingsError):
                supervisor.load_user_settings(empty)
        with self.assertRaises(supervisor.UserSettingsError) as caught:
            supervisor.load_user_settings('{"ultracode": ')
        self.assertIn("inline --settings JSON", str(caught.exception))

    def test_an_empty_settings_value_is_given_not_absent(self):
        # `--settings=` and `--settings ""` used to collapse into the same
        # "no settings" sentinel and were silently discarded
        self.assertEqual(supervisor.split_user_settings(["--settings="]),
                         ([], ""))
        self.assertEqual(supervisor.split_user_settings(["--settings", ""]),
                         ([], ""))
        for argv in (["--settings="], ["--settings", ""],
                     ["--settings", "   "]):
            with self.assertRaises(supervisor.UserSettingsError) as caught:
                supervisor.validate_user_settings(argv)
            self.assertIn("empty value", str(caught.exception))

    def test_a_document_too_deep_to_read_is_refused_not_crashed(self):
        # RecursionError is a RuntimeError, and the launch guard bare-execs on
        # broad exceptions — but whether the interpreter raises AT ALL depends
        # on how deep the stack already was (this exact 1,400-level object
        # parses fine from a shallow stack), so the refusal is by measured
        # depth, not by catching the crash
        deep = "{\"a\":" * 1400 + "1" + "}" * 1400
        with self.assertRaises(supervisor.UserSettingsError) as caught:
            supervisor.load_user_settings(deep)
        self.assertIn("too deeply", str(caught.exception))
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "deep.json")
            with open(path, "w") as handle:
                handle.write(deep)
            with self.assertRaises(supervisor.UserSettingsError) as caught:
                supervisor.load_user_settings(path)
            self.assertIn("too deeply", str(caught.exception))
        # the merge refuses on its own account too — it is public and runs
        # once per generation, so it may not trust its caller
        document = inner = {}
        for _ in range(supervisor.MAX_SETTINGS_DEPTH + 5):
            inner["a"] = {}
            inner = inner["a"]
        with self.assertRaises(supervisor.UserSettingsError) as caught:
            supervisor.merge_user_settings(document, "/tmp/user.json")
        self.assertIn("too deeply", str(caught.exception))
        # and an ordinary settings document is nowhere near the limit
        self.assertFalse(supervisor._nested_too_deeply(
            supervisor.merge_user_settings({
                "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                    {"type": "command", "command": "x"}]}]},
                "permissions": {"allow": ["Bash(git *)"]}})))

    def test_validate_user_settings_is_the_pre_launch_gate(self):
        self.assertEqual(supervisor.validate_user_settings(["--model", "x"]),
                         {})
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "user.json")
            with open(path, "w") as handle:
                json.dump({"disableAllHooks": True}, handle)
            with self.assertRaises(supervisor.UserSettingsError):
                supervisor.validate_user_settings(["--settings", path])
            with open(path, "w") as handle:
                json.dump({"ultracode": True}, handle)
            merged = supervisor.validate_user_settings(["--settings", path])
        self.assertTrue(merged["ultracode"])
        self.assertIn("SessionStart", merged["hooks"])

    def test_initial_account_prefers_env_pinned_slot(self):
        pinned = {"name": "pinned", "provider": "claude", "home": "/tmp/p"}
        other = {"name": "other", "provider": "claude", "home": "/tmp/o"}
        snapshot = {"generated": time.time(), "accounts": []}
        with mock.patch.object(route, "ensure_fresh_snapshot",
                               return_value=snapshot), \
                mock.patch.object(route, "env_pinned_account",
                                  return_value=pinned), \
                mock.patch.object(route, "block_reason", return_value=None), \
                mock.patch.object(route, "cooldowns", return_value={}), \
                mock.patch.object(route, "candidates",
                                  return_value=[(other, None)]) as ranked:
            chosen = supervisor._initial_account("sonnet")
        self.assertEqual(chosen["name"], "pinned")
        ranked.assert_not_called()  # the caller's routing was consumed

    def test_initial_account_repicks_when_pinned_slot_is_blocked(self):
        pinned = {"name": "pinned", "provider": "claude", "home": "/tmp/p"}
        other = {"name": "other", "provider": "claude", "home": "/tmp/o"}
        snapshot = {"generated": time.time(), "accounts": []}
        errors = io.StringIO()
        with mock.patch.object(route, "ensure_fresh_snapshot",
                               return_value=snapshot), \
                mock.patch.object(route, "env_pinned_account",
                                  return_value=pinned), \
                mock.patch.object(route, "block_reason",
                                  side_effect=["at limit", None]), \
                mock.patch.object(route, "cooldowns", return_value={}), \
                mock.patch.object(route, "candidates",
                                  return_value=[(other, None)]), \
                redirect_stderr(errors):
            chosen = supervisor._initial_account("sonnet")
        self.assertEqual(chosen["name"], "other")
        self.assertIn("not routable", errors.getvalue())

    def test_spawn_aborts_when_marker_unwritable_and_marker_is_last(self):
        # the marker means "launch committed": it is written after every
        # piece of spawn preparation, immediately before Popen — and a
        # marker that cannot be written aborts with nothing started
        account = {"name": "a", "provider": "claude", "home": "/tmp/a"}
        popen = mock.Mock()
        supervisor_under_test = supervisor.Supervisor(
            "sonnet", [], account, popen=popen)
        with mock.patch.object(route, "write_launch_marker",
                               return_value=False) as marker, \
                mock.patch.object(supervisor.shutil, "which",
                                  return_value="/x/claude"), \
                mock.patch.object(supervisor_under_test, "_settings_file",
                                  return_value=""), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor_under_test._spawn(account, [], "/tmp", False)
        marker.assert_called_once_with("supervised", account)
        popen.assert_not_called()  # nothing started before the refusal

    def test_spawn_writes_marker_only_for_the_first_generation(self):
        account = {"name": "a", "provider": "claude", "home": "/tmp/a"}
        popen = mock.Mock(return_value=mock.Mock())
        supervisor_under_test = supervisor.Supervisor(
            "sonnet", [], account, popen=popen)
        with mock.patch.object(route, "write_launch_marker",
                               return_value=True) as marker, \
                mock.patch.object(supervisor.shutil, "which",
                                  return_value="/x/claude"), \
                mock.patch.object(supervisor_under_test, "_settings_file",
                                  return_value=""):
            supervisor_under_test._spawn(account, [], "/tmp", False)
            supervisor_under_test._spawn(account, [], "/tmp", False)
        marker.assert_called_once_with("supervised", account)
        self.assertEqual(popen.call_count, 2)

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


class InjectedHooksActuallyRun(unittest.TestCase):
    """Round-2 P2: every settings test so far asserted on the REFUSAL path,
    and that is how three hook bypasses survived a whole round. These run the
    injected hook command for real — the same string, through the same shell,
    that `tests/fake_claude.py` (and Claude) executes — and look at where the
    event landed."""

    SUP = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tree = os.path.join(self.temp.name, "headroom")     # the real one
        self.elsewhere = os.path.join(self.temp.name, "elsewhere")
        environ = dict(os.environ)
        environ.update({
            "HEADROOM_DIR": self.tree,
            # hermetic: never fire an installed headroom that is not this tree
            "HEADROOM_EXECUTABLE": os.path.join(self.REPO, "bin", "headroom"),
        })
        patcher = mock.patch.dict(os.environ, environ, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def child_env(self, **adversarial):
        """The environment Claude hands a hook: the supervisor's own
        variables, plus whatever a settings `env` block put there."""
        environ = dict(os.environ)
        environ.update({
            "HEADROOM_SUPERVISOR_ID": self.SUP,
            "HEADROOM_CHILD_GENERATION": "1",
            "HEADROOM_SOURCE_SLOT": "seat",
            "CLAUDE_CONFIG_DIR": os.path.join(self.temp.name, "home"),
        })
        environ.update(adversarial)
        return environ

    @staticmethod
    def fire(command, environ):
        payload = {"hook_event_name": "SessionStart",
                   "session_id": "11111111-1111-4111-8111-111111111111",
                   "transcript_path": "/tmp/t.jsonl", "cwd": "/tmp"}
        return subprocess.run(command, shell=True, env=environ, text=True,
                              input=json.dumps(payload), capture_output=True)

    @staticmethod
    def events(tree, supervisor_id):
        path = os.path.join(tree, "state", "supervisors",
                            supervisor_id + ".jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def session_start_command(self, document=None):
        """Exactly what fake_claude executes: the FIRST group's command."""
        settings = supervisor.merge_user_settings(document, "/tmp/user.json")
        return settings["hooks"]["SessionStart"][0]["hooks"][0]["command"]

    def test_the_handshake_lands_even_when_the_child_env_redirects_it(self):
        # the bypass shape: a settings `env` that moved HEADROOM_DIR (or HOME,
        # where the default tree lives) so hooks run perfectly into a state
        # tree the supervisor is not reading
        command = self.session_start_command()
        result = self.fire(command, self.child_env(
            HEADROOM_DIR=self.elsewhere, HOME=self.elsewhere))
        self.assertEqual(result.returncode, 0, result.stderr)
        landed = self.events(self.tree, self.SUP)
        self.assertEqual(len(landed), 1, result.stderr)
        self.assertEqual(landed[0]["supervisor_id"], self.SUP)
        self.assertEqual(landed[0]["payload"]["hook_event_name"],
                         "SessionStart")
        self.assertEqual(self.events(self.elsewhere, self.SUP), [])

    def test_without_the_pin_the_same_env_captures_the_event(self):
        # the control that proves the bypass was real: drop the pinned
        # assignment and the identical hook writes into the other tree
        command = self.session_start_command()
        unpinned = command.split(" ", 1)[1]
        self.assertTrue(command.startswith("HEADROOM_DIR="))
        result = self.fire(unpinned, self.child_env(
            HEADROOM_DIR=self.elsewhere, HOME=self.elsewhere))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events(self.tree, self.SUP), [])
        self.assertEqual(len(self.events(self.elsewhere, self.SUP)), 1)

    def test_a_merged_document_still_fires_both_hooks(self):
        # the supervisor's group runs FIRST and the operator's own SessionStart
        # hook still runs — proven by running both, not by reading the JSON
        witness = os.path.join(self.temp.name, "user-hook-ran")
        merged = supervisor.merge_user_settings({
            "env": {"MY_TOKEN": "t"},
            "hooks": {"SessionStart": [{"hooks": [{
                "type": "command",
                "command": "touch " + shlex.quote(witness)}]}]},
        }, "/tmp/user.json")
        groups = merged["hooks"]["SessionStart"]
        self.assertEqual(len(groups), 2)
        environ = self.child_env()
        for group in groups:
            result = self.fire(group["hooks"][0]["command"], environ)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.events(self.tree, self.SUP)), 1)
        self.assertTrue(os.path.exists(witness))

    def test_a_hook_that_cannot_run_at_all_fails_closed(self):
        # the residual class headroom cannot defend against inside the child
        # (a shell prefix, a broken interpreter): the adapter never writes, so
        # the supervisor's handshake simply never arrives — which is the
        # 30-second loud disarm, never a silent unsupervised session
        command = self.session_start_command()
        result = self.fire("/bin/true " + shlex.quote(command),
                           self.child_env())
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.events(self.tree, self.SUP), [])

    def test_a_forged_supervisor_id_is_refused_by_the_adapter(self):
        command = self.session_start_command()
        result = self.fire(command,
                           self.child_env(HEADROOM_SUPERVISOR_ID="not-a-uuid"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("refused", result.stderr)
        self.assertEqual(self.events(self.tree, self.SUP), [])


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

        # ladder off: this pins the FABLE gate itself — a seat with no Fable
        # left is not a Fable destination. What the ladder then does with that
        # refusal is the next test's subject.
        with mock.patch.object(supervisor, "FAMILY_FALLBACK_ENABLED", False):
            result = supervisor.Supervisor(
                "sonnet", [], self.accounts[0], collect_fn=fable_snapshot).run()
        self.assertEqual(result, 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))

    def test_cap_time_fable_capped_target_still_takes_the_session_on_opus(self):
        """Paul's rule, end to end: a spent Fable week costs the session its
        model tier, not its life. Same fleet as the test above — the only
        other seat has no Fable left — but with the ladder on, the session
        stops and moves rather than sitting on the capped account."""
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
        self.assertTrue(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))
        with open(os.path.join(self.fake_state, "launches.jsonl"),
                  encoding="utf-8") as source:
            launches = [json.loads(line) for line in source]
        # THE point of the downgrade, and the part a mocked test cannot see:
        # a resume argv names no model, so without this the successor comes
        # back on its default (Fable) — on the seat that has no Fable left —
        # and re-caps on its first prompt. It has to SAY opus.
        self.assertEqual(launches[1]["config_dir"], self.accounts[1]["home"])
        self.assertIn("--model", launches[1]["args"])
        self.assertEqual(
            launches[1]["args"][launches[1]["args"].index("--model") + 1],
            "opus")
        # and the ledger's last-resort command names the same model, because
        # after a crash between commit and spawn that row is all there is
        with open(handoff._ledger_path(), encoding="utf-8") as source:
            rows = [json.loads(line) for line in source if line.strip()]
        staged = [row for row in rows if row.get("action") == "staged"]
        self.assertTrue(staged)
        self.assertIn("--model opus", staged[-1]["resume_command"])

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
        # r5: source recovery fires on a POSITIVE pre-spawn failure of the
        # target (a SupervisorError raised BEFORE the spawn window, e.g. the
        # binary not resolving), NOT on a raising Popen (which is now ambiguous
        # — see test_ambiguous_target_spawn_does_not_recover).
        real_spawn = supervisor.Supervisor._spawn
        calls = {"n": 0}

        def spawn(runner, account, args, cwd, automatic, plan=None):
            calls["n"] += 1
            if calls["n"] == 2:  # the target spawn: positive pre-spawn failure
                raise supervisor.SupervisorError(
                    "`claude` not found on PATH; nothing was started")
            return real_spawn(runner, account, args, cwd, automatic, plan)

        with mock.patch.object(supervisor.Supervisor, "_spawn", spawn):
            result = supervisor.Supervisor(
                "sonnet", [], self.accounts[0],
                collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        self.assertEqual(calls["n"], 3)  # source, target, recovery
        with open(os.path.join(self.fake_state, "recovered"),
                  encoding="utf-8") as source:
            self.assertIn("--resume", source.read())

    def test_ambiguous_target_spawn_does_not_recover(self):
        # r5: a raising Popen on the target is AMBIGUOUS (a child may be live),
        # so the supervisor must NOT recover the source (never double-spawn) —
        # it stops with 127 and writes no recovery.
        real_popen = supervisor.subprocess.Popen
        attempts = {"count": 0}

        def raising_target(argv, **kwargs):
            attempts["count"] += 1
            if attempts["count"] == 2:
                raise RuntimeError("async/trace failure in the Popen window")
            return real_popen(argv, **kwargs)

        with redirect_stderr(io.StringIO()):
            result = supervisor.Supervisor(
                "sonnet", [], self.accounts[0], collect_fn=self.snapshot,
                popen=raising_target).run()
        self.assertEqual(result, 127)
        self.assertEqual(attempts["count"], 2)  # NO third spawn (no recovery)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "recovered")))

    def test_real_which_target_missing_recovers_source(self):
        # r6 P2-b: phase-aware, REAL shutil.which (not a stubbed _spawn).
        # Planning sees claude present; the TARGET _spawn's real which()
        # returns None (positive pre-spawn failure -> recover source);
        # recovery sees it present again. Keyed on the target transcript that
        # commit_handoff writes just before the target spawn, so planning
        # (before commit) sees present and only the first post-commit which
        # (the target spawn) fails.
        source_sid = str(__import__("uuid").uuid5(
            __import__("uuid").NAMESPACE_DNS, "headroom-fake-source-1"))
        target_transcript = os.path.join(
            self.accounts[1]["home"], "projects", "fake-project",
            source_sid + ".jsonl")
        real_which = supervisor.shutil.which
        state = {"target_failed": False}

        def which(name):
            if (name == "claude" and os.path.exists(target_transcript)
                    and not state["target_failed"]):
                state["target_failed"] = True  # only the target spawn fails
                return None
            return real_which(name)

        with mock.patch.object(supervisor.shutil, "which", side_effect=which):
            result = supervisor.Supervisor(
                "sonnet", [], self.accounts[0],
                collect_fn=self.snapshot).run()
        self.assertEqual(result, 0)
        self.assertTrue(state["target_failed"])  # the real target which failed
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
        # r5: both the target spawn AND the source recovery spawn fail their
        # POSITIVE pre-spawn validation, so the recovery-failed path prints the
        # two manual resume commands.
        real_spawn = supervisor.Supervisor._spawn
        calls = {"n": 0}

        def spawn(runner, account, args, cwd, automatic, plan=None):
            calls["n"] += 1
            if calls["n"] in (2, 3):  # target + source recovery both fail
                raise supervisor.SupervisorError(
                    "`claude` not found on PATH; nothing was started")
            return real_spawn(runner, account, args, cwd, automatic, plan)

        errors = io.StringIO()
        with redirect_stderr(errors), \
                mock.patch.object(supervisor.Supervisor, "_spawn", spawn):
            result = supervisor.Supervisor(
                "sonnet", [], self.accounts[0],
                collect_fn=self.snapshot).run()
        self.assertEqual(result, 127)
        source_sid = str(__import__("uuid").uuid5(
            __import__("uuid").NAMESPACE_DNS, "headroom-fake-source-1"))
        self.assertIn(handoff.resume_command(
            self.accounts[1]["home"], source_sid), errors.getvalue())
        self.assertIn(
            f"CLAUDE_CONFIG_DIR={self.accounts[0]['home']} claude --resume "
            f"{source_sid}", errors.getvalue())

    def test_failed_recovery_of_a_huge_session_prints_a_model_that_can_load_it(self):
        """The same branch, but with a conversation that outgrew the standard
        window. Both printed lines must name a 1M model — a bare `--resume`
        here hands the operator a command that dies on its first prompt, and
        this is the path that runs when BOTH spawns have already failed.

        The two `model=` arguments feeding these lines were threaded in but
        pinned by nothing: the original fixture's child has no `--model` and
        its transcript carries no usage records, so the window-fit code was
        unreachable from the integration layer entirely."""
        os.environ["FAKE_CONTEXT_TOKENS"] = "500000"
        self.addCleanup(os.environ.pop, "FAKE_CONTEXT_TOKENS", None)
        real_spawn = supervisor.Supervisor._spawn
        calls = {"n": 0}

        def spawn(runner, account, args, cwd, automatic, plan=None):
            calls["n"] += 1
            if calls["n"] in (2, 3):    # target + source recovery both fail
                raise supervisor.SupervisorError(
                    "`claude` not found on PATH; nothing was started")
            return real_spawn(runner, account, args, cwd, automatic, plan)

        errors = io.StringIO()
        with redirect_stderr(errors), \
                mock.patch.object(supervisor.Supervisor, "_spawn", spawn):
            result = supervisor.Supervisor(
                "sonnet", ["--model", "sonnet[1m]"], self.accounts[0],
                collect_fn=self.snapshot).run()
        self.assertEqual(result, 127)
        printed = [line for line in errors.getvalue().splitlines()
                   if line.startswith("CLAUDE_CONFIG_DIR=")]
        self.assertEqual(len(printed), 2, errors.getvalue())
        for line in printed:
            # sonnet[1m] SPECIFICALLY, not merely "some 1M model": the whole
            # job of the threaded `model=` is to keep the conversation on the
            # family it was already running. Asserting only "[1m]" passes even
            # when the model is dropped, because an over-limit transcript then
            # falls back to opus[1m) — a family this seat was never gated on.
            self.assertIn("sonnet[1m]", line, line)

    def test_source_recovery_of_a_huge_session_keeps_its_own_1m_model(self):
        """The sibling of the test above on the path where recovery SUCCEEDS.

        Only the TARGET spawn fails, so the source is recovered for real and
        the fake records the argv it was started with. Without the threaded
        `model=` at this call site the recovered session is re-modelled onto
        the default fit model — a different family, on the seat it never
        left."""
        os.environ["FAKE_CONTEXT_TOKENS"] = "500000"
        self.addCleanup(os.environ.pop, "FAKE_CONTEXT_TOKENS", None)
        real_spawn = supervisor.Supervisor._spawn
        calls = {"n": 0}

        def spawn(runner, account, args, cwd, automatic, plan=None):
            calls["n"] += 1
            if calls["n"] == 2:         # only the TARGET spawn fails
                raise supervisor.SupervisorError(
                    "`claude` not found on PATH; nothing was started")
            return real_spawn(runner, account, args, cwd, automatic, plan)

        with redirect_stderr(io.StringIO()), \
                mock.patch.object(supervisor.Supervisor, "_spawn", spawn):
            supervisor.Supervisor(
                "sonnet", ["--model", "sonnet[1m]"], self.accounts[0],
                collect_fn=self.snapshot).run()
        with open(os.path.join(self.fake_state, "recovered"),
                  encoding="utf-8") as source:
            recovered = source.read()
        self.assertIn("--resume", recovered)
        self.assertIn("sonnet[1m]", recovered)

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


class PreemptiveIntegration(unittest.TestCase):
    """End to end with a REAL child process: an idle session on a seat that
    has crossed its threshold rotates before it ever hits the wall, through
    the same staging/reservation/resume pipeline the cap path uses."""

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
            "FAKE_CLAUDE_SCENARIO": "idle",
        })
        self.env.start()
        self.binding = mock.patch.object(
            collect, "local_binding", return_value=("AAAA", "BBBB"))
        self.binding.start()
        # collapse the cadences: the real ones are minutes, the fake child
        # lives for a second and a half
        self.patched = [mock.patch.object(supervisor, name, value)
                        for name, value in (("QUIET_SECONDS", 0.1),
                                            ("PREEMPT_IDLE_SECONDS", 0.1),
                                            ("PREEMPT_POLL_SECONDS", 0.05),
                                            ("PREEMPT_BACKOFF_SECONDS", 0.2),
                                            ("PREEMPT_DECISION_TTL", 60.0))]
        for patch in self.patched:
            patch.start()
        self.cwd_before = os.getcwd()
        self.cwd = os.path.join(self.temp.name, "work")
        os.makedirs(self.cwd)
        os.chdir(self.cwd)
        self.accounts = []
        for name in ("source", "target"):
            home = os.path.join(self.temp.name, name)
            os.makedirs(home, exist_ok=True)
            self.accounts.append({"name": name, "provider": "claude",
                                  "home": home})
        registry.save({"schema_version": 1, "accounts": self.accounts,
                       "routing": {"auto_handoff": True}})

    def tearDown(self):
        os.chdir(self.cwd_before)
        for patch in reversed(self.patched):
            patch.stop()
        self.binding.stop()
        self.env.stop()
        self.temp.cleanup()

    def usage(self, source7):
        def snapshot(quiet=True):
            del quiet
            now = int(time.time())
            return {"run_started": now, "generated": now, "accounts": [
                usage_row("source", used5=10, used7=source7, captured=now),
                usage_row("target", used5=10, used7=10, captured=now)]}
        return snapshot

    def ledger_rows(self):
        path = handoff._ledger_path()
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as source:
            return [json.loads(line) for line in source if line.strip()]

    def source_session_id(self):
        return str(__import__("uuid").uuid5(
            __import__("uuid").NAMESPACE_DNS, "headroom-fake-source-1"))

    def test_idle_child_over_threshold_rotates_before_the_wall(self):
        runner = supervisor.Supervisor("sonnet", [], self.accounts[0],
                                       collect_fn=self.usage(96.0))
        with mock.patch.object(notify, "emit") as emit:
            self.assertEqual(runner.run(), 0)
        session = self.source_session_id()
        destination = os.path.join(self.accounts[1]["home"], "projects",
                                   "fake-project", session + ".jsonl")
        self.assertTrue(os.path.exists(destination))
        self.assertTrue(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))
        rows = self.ledger_rows()
        actions = [row.get("action") for row in rows]
        for action in ("cap_confirmed", "stop_sent", "stopped", "staged",
                       "resume_spawned", "resume_bound"):
            self.assertIn(action, actions)
        staged = next(row for row in rows if row.get("action") == "staged")
        self.assertEqual(staged["reason"], "preemptive")
        self.assertIsNone(staged["cap_scope"])
        self.assertTrue(staged["automatic"])
        # the seat was NOT capped, so nothing was cooled
        self.assertEqual(route.cooldowns(), {})
        with open(os.path.join(self.fake_state, "launches.jsonl"),
                  encoding="utf-8") as source:
            launches = [json.loads(line) for line in source]
        self.assertEqual(launches[1]["args"],
                         ["--resume", session, "--fork-session"])
        self.assertEqual(launches[1]["config_dir"], self.accounts[1]["home"])
        events = [call.args[0]["event"] for call in emit.call_args_list]
        self.assertIn("preemptive_scheduled", events)
        self.assertIn("preemptive_handoff", events)
        self.assertNotIn("supervision_lost", events)

    def test_seat_below_threshold_is_left_alone(self):
        runner = supervisor.Supervisor("sonnet", [], self.accounts[0],
                                       collect_fn=self.usage(50.0))
        with mock.patch.object(notify, "emit") as emit:
            self.assertEqual(runner.run(), 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))
        self.assertEqual(self.ledger_rows(), [])
        events = [call.args[0]["event"] for call in emit.call_args_list]
        self.assertEqual(events, ["launch"])

    def test_cap_landing_during_the_preemptive_stop_is_absorbed(self):
        # the race the rotation was trying to beat: the seat caps AFTER the
        # SIGTERM and BEFORE SessionEnd. The in-flight handoff is already
        # doing what the cap demands, so it must complete — never abort into
        # an unsupervised source.
        os.environ["FAKE_CLAUDE_SCENARIO"] = "idle-cap-on-stop"
        runner = supervisor.Supervisor("sonnet", [], self.accounts[0],
                                       collect_fn=self.usage(96.0))
        with mock.patch.object(notify, "emit") as emit:
            self.assertEqual(runner.run(), 0)
        session = self.source_session_id()
        self.assertTrue(os.path.exists(os.path.join(
            self.accounts[1]["home"], "projects", "fake-project",
            session + ".jsonl")))
        actions = [row.get("action") for row in self.ledger_rows()]
        self.assertIn("staged", actions)
        self.assertIn("resume_bound", actions)
        events = [call.args[0]["event"] for call in emit.call_args_list]
        self.assertIn("preemptive_handoff", events)
        self.assertNotIn("supervision_lost", events)
        with open(os.path.join(self.fake_state, "launches.jsonl"),
                  encoding="utf-8") as source:
            launches = [json.loads(line) for line in source]
        # the session resumed on the TARGET, supervised (a settings file is
        # only passed to a supervised child)
        self.assertEqual(launches[1]["config_dir"], self.accounts[1]["home"])
        self.assertEqual(launches[1]["args"],
                         ["--resume", session, "--fork-session"])

    def test_no_healthy_target_leaves_the_idle_child_running(self):
        def snapshot(quiet=True):
            del quiet
            now = int(time.time())
            target = usage_row("target", captured=now)
            target["routable"] = False
            target["trust_state"] = "unverified"
            return {"run_started": now, "generated": now, "accounts": [
                usage_row("source", used5=10, used7=96.0, captured=now),
                target]}

        runner = supervisor.Supervisor("sonnet", [], self.accounts[0],
                                       collect_fn=snapshot)
        with mock.patch.object(notify, "emit") as emit:
            self.assertEqual(runner.run(), 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.fake_state, "sigterm-source")))
        self.assertEqual(self.ledger_rows(), [])
        held = [call.args[0] for call in emit.call_args_list
                if call.args[0]["event"] == "preemptive_held"]
        self.assertTrue(held)
        self.assertIn("no target with proven headroom", held[0]["reason"])
        # backoff, not a retry every tick: one hold notice for the whole run
        self.assertEqual(len(held), 1)


if __name__ == "__main__":
    unittest.main()
