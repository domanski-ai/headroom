"""Codex conversation handoff test suite — stdlib unittest only, no network.

Covers the Codex provider adapter: rollout location and containment (fail-
closed ambiguity, --from), the turn-ID-aware lifecycle validator, session_meta
consistency, the target's EFFECTIVE model_provider/auth gate, the shared
transaction spine publishing rollout-only (never auth.json), the full target
gate re-run under the handoff lock immediately before publication and before
exec (relogin/group-change/quarantine/capacity races DURING staging), the
force-collect freshness path, the headless CLI path, and sanitized refusal
ledgering.  Tests use a REAL on-disk registry and mutate it between plan and
publish; only the process/network boundaries (codex app-server via
collect.codex_live, collect.run_collect, local token reads) are stubbed.
"""
import copy
import fcntl
import hashlib
import inspect
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from headroom import collect, handoff, handoff_codex, paths, route, tokens  # noqa: E402

SID = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0001"
OTHER_SID = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0002"
THIRD_SID = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0003"
ROLLOUT_NAME = "rollout-2026-07-13T10-00-00-%s.jsonl"
AUTH_BYTES = json.dumps({"tokens": {"access_token": "SECRET-ACCESS",
                                    "refresh_token": "SECRET-REFRESH",
                                    "id_token": "SECRET-ID"}}).encode()


def _record(kind, payload):
    return {"timestamp": "2026-07-13T10:00:00.000Z", "type": kind,
            "payload": payload}


def _rollout_records(session_id, *, provider="openai", source="cli",
                     dangling_call=False, open_task=False, ephemeral=False,
                     meta_id=None):
    """Realistic lifecycle: a turn opened by task_started (with a turn id)
    and closed by a REAL terminal boundary carrying the same turn id."""
    meta = {"id": meta_id or session_id,
            "timestamp": "2026-07-13T10:00:00.000Z", "cwd": "/tmp",
            "originator": "codex_cli_rs", "cli_version": "0.144.0",
            "source": source, "model_provider": provider}
    if ephemeral:
        meta["ephemeral"] = True
    records = [
        _record("session_meta", meta),
        _record("event_msg", {"type": "task_started", "turn_id": "turn-1"}),
        _record("response_item", {"type": "message", "role": "user",
                                  "content": [{"type": "input_text",
                                               "text": "hello"}]}),
        _record("response_item", {"type": "function_call", "call_id": "c1",
                                  "name": "shell", "arguments": "{}"}),
    ]
    if not dangling_call:
        records.append(_record("response_item",
                               {"type": "function_call_output",
                                "call_id": "c1", "output": "ok"}))
    if not open_task:
        records.append(_record("event_msg", {"type": "task_complete",
                                             "turn_id": "turn-1"}))
    return records


def _rollout_bytes(session_id, **kwargs):
    return "".join(json.dumps(record) + "\n"
                   for record in _rollout_records(session_id, **kwargs)).encode()


def _records_bytes(records):
    return "".join(json.dumps(record) + "\n" for record in records).encode()


def _codex_row(name, used5h=10.0, used7d=20.0, **over):
    now = int(time.time())
    row = {
        "name": name, "provider": "codex", "plan": "ChatGPT Pro", "ok": True,
        "stale": False, "routable": True, "identity_verified": True,
        "identity": {"verified": True, "account_fingerprint": "AAAA",
                     "credential_digest": "BBBB", "lineage_digest": "LLLL",
                     "auth_mode": "chatgpt"},
        "trust_state": "verified", "captured_at": now - 10,
        "source": "codex_app_server",
        "windows": {
            "5h": {"used_percent": used5h, "resets_at": now + 3600,
                   "window_minutes": 300},
            "7d": {"used_percent": used7d, "resets_at": now + 8 * 86400,
                   "window_minutes": 10080},
        },
    }
    row.update(over)
    return row


class CodexHandoffBase(unittest.TestCase):
    """Two codex homes in one handoff_group, one persisted rollout on cxa.
    A REAL registry config is written to HEADROOM_DIR so every gate that
    reloads the registry reads genuine, mutable on-disk state."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_headroom = os.environ.get("HEADROOM_DIR")
        os.environ["HEADROOM_DIR"] = os.path.join(self.temp.name, "headroom")
        self.old_cwd = os.getcwd()
        self.cwd = os.path.join(self.temp.name, "work")
        os.makedirs(self.cwd)
        os.chdir(self.cwd)
        self.source_home = os.path.join(self.temp.name, "cxa")
        self.target_home = os.path.join(self.temp.name, "cxb")
        os.makedirs(self.target_home)
        self.accounts = [
            {"name": "cxa", "provider": "codex", "home": self.source_home,
             "expected_email": "one@example.com",
             "handoff_group": "domanski-server"},
            {"name": "cxb", "provider": "codex", "home": self.target_home,
             "expected_email": "two@example.com",
             "handoff_group": "domanski-server"},
        ]
        self.rollout = self._rollout(self.source_home, SID)
        for home in (self.source_home, self.target_home):
            with open(os.path.join(home, "auth.json"), "wb") as handle:
                handle.write(AUTH_BYTES)
        self.write_config(self.accounts)
        # process/network boundaries only — the gate logic itself runs real.
        self.binding_value = ("AAAA", "BBBB")
        self.lineage_value = "LLLL"
        self.live_identity = {
            "verified": True, "email": "two@example.com",
            "account_fingerprint": "AAAA", "credential_digest": "BBBB",
            "lineage_digest": "LLLL", "auth_mode": "chatgpt",
            "method": "codex_app_server", "plan_type": "ChatGPT Pro",
        }
        self.live_windows = self._fresh_windows()
        self.binding = mock.patch.object(
            collect, "local_binding",
            side_effect=lambda provider, home: self.binding_value)
        self.binding.start()
        self.lineage = mock.patch.object(
            collect, "codex_lineage_digest",
            side_effect=lambda home: self.lineage_value)
        self.lineage.start()
        self.live = mock.patch.object(
            collect, "codex_live", side_effect=self._fake_codex_live)
        self.live.start()

    def tearDown(self):
        self.live.stop()
        self.lineage.stop()
        self.binding.stop()
        os.chdir(self.old_cwd)
        if self.old_headroom is None:
            os.environ.pop("HEADROOM_DIR", None)
        else:
            os.environ["HEADROOM_DIR"] = self.old_headroom
        self.temp.cleanup()

    @staticmethod
    def _fresh_windows():
        now = int(time.time())
        return {
            "5h": {"used_percent": 10.0, "resets_at": now + 3600,
                   "window_minutes": 300, "observed_at": now,
                   "freshness": "fresh"},
            "7d": {"used_percent": 20.0, "resets_at": now + 8 * 86400,
                   "window_minutes": 10080, "observed_at": now,
                   "freshness": "fresh"},
        }

    def _fake_codex_live(self, home, expected_email=None, now=None):
        return (dict(self.live_identity), "ChatGPT Pro",
                copy.deepcopy(self.live_windows))

    def write_config(self, accounts):
        config = {"schema_version": 1,
                  "accounts": [dict(account) for account in accounts]}
        os.makedirs(os.path.dirname(paths.config_path()), exist_ok=True)
        with open(paths.config_path(), "w", encoding="utf-8") as handle:
            json.dump(config, handle)

    def _rollout(self, home, session_id, data=None, name=None):
        directory = os.path.join(home, "sessions", "2026", "07", "13")
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name or ROLLOUT_NAME % session_id)
        with open(path, "wb") as handle:
            handle.write(_rollout_bytes(session_id) if data is None else data)
        old = time.time() - 20
        os.utime(path, (old, old))
        return path

    def snapshot(self, **target_over):
        return {"generated": int(time.time()), "accounts": [
            _codex_row("cxa", used5h=100.0), _codex_row("cxb", **target_over)]}

    def source(self):
        return handoff_codex.resolve_codex_source(SID, self.accounts)

    def plan(self, snapshot=None, scope=None, force=False, target=None):
        return handoff_codex.plan_codex_handoff(
            self.source(), target or self.accounts[1],
            self.snapshot() if snapshot is None else snapshot, scope,
            self.cwd, force=force, require_executable=False)

    def commit_with_staging_mutation(self, plan, mutate):
        """Run commit_handoff but apply ``mutate`` DURING staging — after the
        plan-time and commit-entry gates have passed, before the copy is
        hard-linked into the target home (the plan→publish transition)."""
        original = handoff._write_marker_unlocked

        def hooked(plan_, components, temporary, destination):
            marker = original(plan_, components, temporary, destination)
            mutate()
            return marker

        with mock.patch.object(handoff, "_write_marker_unlocked",
                               side_effect=hooked):
            return handoff.commit_handoff(plan)

    def assert_nothing_published(self):
        sessions = os.path.join(self.target_home, "sessions")
        leaked = []
        for base, _, names in os.walk(sessions):
            leaked.extend(os.path.join(base, name) for name in names)
        self.assertEqual(leaked, [])


class RolloutLocation(CodexHandoffBase):
    def test_single_rollout_resolves_with_relative_parts(self):
        source = self.source()
        self.assertEqual(source.session_id, SID)
        self.assertEqual(source.account["name"], "cxa")
        self.assertEqual(source.rollout_path, os.path.realpath(self.rollout))
        self.assertEqual(source.relative_parts,
                         ("sessions", "2026", "07", "13", ROLLOUT_NAME % SID))

    def test_unknown_uuid_fails_closed(self):
        with self.assertRaisesRegex(handoff.HandoffError, "matched no rollout"):
            handoff_codex.resolve_codex_source(OTHER_SID, self.accounts)

    def test_ambiguous_uuid_across_homes_fails_closed(self):
        self._rollout(self.target_home, SID)
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "matched 2 codex rollouts"):
            handoff_codex.resolve_codex_source(SID, self.accounts)

    def test_from_slot_disambiguates_and_stays_exact(self):
        self._rollout(self.target_home, SID)
        source = handoff_codex.resolve_codex_source(SID, self.accounts,
                                                    from_slot="cxa")
        self.assertEqual(source.account["name"], "cxa")
        self.assertEqual(source.rollout_path, os.path.realpath(self.rollout))
        source = handoff_codex.resolve_codex_source(SID, self.accounts,
                                                    from_slot="cxb")
        self.assertEqual(source.account["name"], "cxb")

    def test_from_slot_unknown_or_wrong_provider_refused(self):
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "no configured account named"):
            handoff_codex.resolve_codex_source(SID, self.accounts,
                                               from_slot="ghost")
        accounts = self.accounts + [{"name": "cl", "provider": "claude",
                                     "home": os.path.join(self.temp.name, "cl")}]
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "must name a Codex account"):
            handoff_codex.resolve_codex_source(SID, accounts, from_slot="cl")

    def test_from_slot_requires_exactly_one_match_inside_home(self):
        # a second rollout file for the SAME UUID inside the named home is
        # still ambiguous — --from narrows the search, never guesses
        self._rollout(self.source_home, SID,
                      name="rollout-2026-07-13T11-00-00-%s.jsonl" % SID)
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "matched 2 codex rollouts"):
            handoff_codex.resolve_codex_source(SID, self.accounts,
                                               from_slot="cxa")

    def test_non_uuid_session_refused(self):
        with self.assertRaisesRegex(handoff.HandoffError, "must be a UUID"):
            handoff_codex.resolve_codex_source("not-a-uuid", self.accounts)

    def test_symlinked_rollout_refused(self):
        real = self._rollout(self.source_home, OTHER_SID)
        link = os.path.join(os.path.dirname(self.rollout),
                            ROLLOUT_NAME % OTHER_SID)
        os.unlink(real)
        outside = os.path.join(self.temp.name, "outside.jsonl")
        with open(outside, "wb") as handle:
            handle.write(_rollout_bytes(OTHER_SID))
        os.symlink(outside, link)
        with self.assertRaisesRegex(handoff.HandoffError, "symlink"):
            handoff_codex.resolve_codex_source(OTHER_SID, self.accounts)

    def test_symlinked_date_directory_escape_refused(self):
        outside = os.path.join(self.temp.name, "outside-day")
        os.makedirs(outside)
        with open(os.path.join(outside, ROLLOUT_NAME % OTHER_SID), "wb") as fh:
            fh.write(_rollout_bytes(OTHER_SID))
        os.symlink(outside, os.path.join(self.source_home, "sessions",
                                         "2026", "07", "14"))
        with self.assertRaisesRegex(handoff.HandoffError, "escapes"):
            handoff_codex.resolve_codex_source(OTHER_SID, self.accounts)

    def test_symlinked_sessions_root_refused(self):
        home = os.path.join(self.temp.name, "cxc")
        os.makedirs(home)
        outside = os.path.join(self.temp.name, "outside-sessions")
        os.makedirs(os.path.join(outside, "2026", "07", "13"))
        with open(os.path.join(outside, "2026", "07", "13",
                               ROLLOUT_NAME % OTHER_SID), "wb") as fh:
            fh.write(_rollout_bytes(OTHER_SID))
        os.symlink(outside, os.path.join(home, "sessions"))
        accounts = [{"name": "cxc", "provider": "codex", "home": home,
                     "handoff_group": "domanski-server"}]
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "sessions directory is a symlink"):
            handoff_codex.resolve_codex_source(OTHER_SID, accounts)


class RolloutInspection(CodexHandoffBase):
    def test_valid_rollout_inspects_with_hash_and_meta(self):
        data = _rollout_bytes(SID)
        inspected = handoff_codex.inspect_rollout(self.rollout, SID)
        self.assertEqual(inspected["sha256"],
                         hashlib.sha256(data).hexdigest())
        self.assertEqual(inspected["bytes"], len(data))
        self.assertEqual(inspected["unresolved_tool_ids"], ())
        self.assertEqual(inspected["meta"]["model_provider"], "openai")

    def test_malformed_middle_line_refused(self):
        with open(self.rollout, "rb") as handle:
            lines = handle.read().splitlines(keepends=True)
        lines.insert(2, b"not json\n")
        with open(self.rollout, "wb") as handle:
            handle.writelines(lines)
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "invalid JSON at line 3"):
            handoff_codex.inspect_rollout(self.rollout, SID)

    def test_incomplete_final_line_refused(self):
        with open(self.rollout, "ab") as handle:
            handle.write(b'{"type":')
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "incomplete final line"):
            handoff_codex.inspect_rollout(self.rollout, SID)

    def test_wrong_meta_uuid_refused(self):
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_rollout_bytes(OTHER_SID, meta_id=SID))
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "does not match the requested session"):
            handoff_codex.inspect_rollout(path, OTHER_SID)

    def test_missing_session_meta_refused(self):
        records = _rollout_records(SID)[1:]
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        with self.assertRaisesRegex(handoff.HandoffError, "session_meta"):
            handoff_codex.inspect_rollout(path, OTHER_SID)

    def test_second_session_meta_different_uuid_refused(self):
        records = _rollout_records(OTHER_SID)
        rogue = {"id": THIRD_SID, "model_provider": "openai",
                 "cwd": "/tmp", "source": "cli"}
        records.insert(3, _record("session_meta", rogue))
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "does not match the requested session"):
            handoff_codex.inspect_rollout(path, OTHER_SID)
        # --force must NOT override metadata consistency
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "does not match the requested session"):
            handoff_codex.inspect_rollout(path, OTHER_SID, allow_dangling=True)

    def test_second_session_meta_different_provider_refused(self):
        records = _rollout_records(OTHER_SID)
        rogue = {"id": OTHER_SID, "model_provider": "azure",
                 "cwd": "/tmp", "source": "cli"}
        records.insert(3, _record("session_meta", rogue))
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        with self.assertRaisesRegex(handoff.HandoffError, "model_provider"):
            handoff_codex.inspect_rollout(path, OTHER_SID)

    def test_second_session_meta_consistent_accepted(self):
        records = _rollout_records(OTHER_SID)
        twin = {"id": OTHER_SID, "model_provider": "openai",
                "cwd": "/tmp", "source": "cli"}
        records.insert(3, _record("session_meta", twin))
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        handoff_codex.inspect_rollout(path, OTHER_SID)

    def test_ephemeral_session_refused(self):
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_rollout_bytes(OTHER_SID, ephemeral=True))
        with self.assertRaisesRegex(handoff.HandoffError, "ephemeral"):
            handoff_codex.inspect_rollout(path, OTHER_SID)

    def test_incompatible_model_provider_refused(self):
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_rollout_bytes(OTHER_SID, provider="oss"))
        with self.assertRaisesRegex(handoff.HandoffError, "model_provider"):
            handoff_codex.inspect_rollout(path, OTHER_SID)

    def test_dangling_tool_call_refused_and_force_allows(self):
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_rollout_bytes(OTHER_SID, dangling_call=True))
        with self.assertRaisesRegex(handoff.HandoffError, "mid-tool-call"):
            handoff_codex.inspect_rollout(path, OTHER_SID)
        inspected = handoff_codex.inspect_rollout(path, OTHER_SID,
                                                  allow_dangling=True)
        self.assertEqual(inspected["unresolved_tool_ids"], ("c1",))

    def test_task_in_flight_refused_and_force_allows(self):
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_rollout_bytes(OTHER_SID, open_task=True))
        with self.assertRaisesRegex(handoff.HandoffError, "mid-turn"):
            handoff_codex.inspect_rollout(path, OTHER_SID)
        handoff_codex.inspect_rollout(path, OTHER_SID, allow_dangling=True)

    def test_task_started_followed_by_generic_error_refused(self):
        # a generic `error` event is NOT a terminal boundary — this rollout
        # is mid-turn (the reviewer's probe case), overridable only by --force
        records = [
            _record("session_meta", {"id": OTHER_SID, "cwd": "/tmp",
                                     "source": "cli",
                                     "model_provider": "openai"}),
            _record("event_msg", {"type": "task_started", "turn_id": "t1"}),
            _record("event_msg", {"type": "error",
                                  "message": "stream disconnected"}),
        ]
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        with self.assertRaisesRegex(handoff.HandoffError, "mid-turn"):
            handoff_codex.inspect_rollout(path, OTHER_SID)
        handoff_codex.inspect_rollout(path, OTHER_SID, allow_dangling=True)

    def test_no_lifecycle_events_refused_even_with_force(self):
        records = [
            _record("session_meta", {"id": OTHER_SID, "cwd": "/tmp",
                                     "source": "cli",
                                     "model_provider": "openai"}),
            _record("response_item", {"type": "message", "role": "user",
                                      "content": [{"type": "input_text",
                                                   "text": "hi"}]}),
        ]
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "no turn lifecycle events"):
            handoff_codex.inspect_rollout(path, OTHER_SID)
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "no turn lifecycle events"):
            handoff_codex.inspect_rollout(path, OTHER_SID, allow_dangling=True)

    def test_turn_complete_and_turn_aborted_are_boundaries(self):
        for boundary in ("turn_complete", "turn_aborted", "task_aborted"):
            records = [
                _record("session_meta", {"id": OTHER_SID, "cwd": "/tmp",
                                         "source": "cli",
                                         "model_provider": "openai"}),
                _record("event_msg", {"type": "task_started",
                                      "turn_id": "t1"}),
                _record("event_msg", {"type": boundary, "turn_id": "t1"}),
            ]
            path = self._rollout(self.source_home, OTHER_SID,
                                 data=_records_bytes(records))
            handoff_codex.inspect_rollout(path, OTHER_SID)

    def test_boundary_without_open_turn_refused_even_with_force(self):
        records = [
            _record("session_meta", {"id": OTHER_SID, "cwd": "/tmp",
                                     "source": "cli",
                                     "model_provider": "openai"}),
            _record("event_msg", {"type": "task_complete", "turn_id": "t1"}),
        ]
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        with self.assertRaisesRegex(handoff.HandoffError, "no open turn"):
            handoff_codex.inspect_rollout(path, OTHER_SID)
        with self.assertRaisesRegex(handoff.HandoffError, "no open turn"):
            handoff_codex.inspect_rollout(path, OTHER_SID, allow_dangling=True)

    def test_turn_id_mismatch_refused_even_with_force(self):
        records = [
            _record("session_meta", {"id": OTHER_SID, "cwd": "/tmp",
                                     "source": "cli",
                                     "model_provider": "openai"}),
            _record("event_msg", {"type": "task_started", "turn_id": "t1"}),
            _record("event_msg", {"type": "task_complete", "turn_id": "t2"}),
        ]
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "inconsistent turn ids"):
            handoff_codex.inspect_rollout(path, OTHER_SID)
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "inconsistent turn ids"):
            handoff_codex.inspect_rollout(path, OTHER_SID, allow_dangling=True)

    def test_idless_boundary_cannot_close_id_turn(self):
        # P1: task_started(turn_id) + an ID-LESS task_complete could fake a
        # clean close on a truncated/spliced rollout — refused, even forced
        records = [
            _record("session_meta", {"id": OTHER_SID, "cwd": "/tmp",
                                     "source": "cli",
                                     "model_provider": "openai"}),
            _record("event_msg", {"type": "task_started", "turn_id": "t1"}),
            _record("event_msg", {"type": "task_complete"}),
        ]
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "inconsistent turn ids"):
            handoff_codex.inspect_rollout(path, OTHER_SID)
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "inconsistent turn ids"):
            handoff_codex.inspect_rollout(path, OTHER_SID, allow_dangling=True)

    def test_id_boundary_cannot_close_idless_turn(self):
        records = [
            _record("session_meta", {"id": OTHER_SID, "cwd": "/tmp",
                                     "source": "cli",
                                     "model_provider": "openai"}),
            _record("event_msg", {"type": "task_started"}),
            _record("event_msg", {"type": "task_complete", "turn_id": "t1"}),
        ]
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "inconsistent turn ids"):
            handoff_codex.inspect_rollout(path, OTHER_SID)

    def test_fully_idless_lifecycle_accepted(self):
        # legacy layouts carry no turn ids anywhere — id-less pairing valid
        records = [
            _record("session_meta", {"id": OTHER_SID, "cwd": "/tmp",
                                     "source": "cli",
                                     "model_provider": "openai"}),
            _record("event_msg", {"type": "task_started"}),
            _record("event_msg", {"type": "task_complete"}),
        ]
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        handoff_codex.inspect_rollout(path, OTHER_SID)

    def test_interior_dangling_turn_refused_and_force_allows(self):
        records = [
            _record("session_meta", {"id": OTHER_SID, "cwd": "/tmp",
                                     "source": "cli",
                                     "model_provider": "openai"}),
            _record("event_msg", {"type": "task_started", "turn_id": "t1"}),
            _record("event_msg", {"type": "task_started", "turn_id": "t2"}),
            _record("event_msg", {"type": "task_complete", "turn_id": "t2"}),
        ]
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        with self.assertRaisesRegex(handoff.HandoffError, "mid-turn"):
            handoff_codex.inspect_rollout(path, OTHER_SID)
        handoff_codex.inspect_rollout(path, OTHER_SID, allow_dangling=True)

    def test_output_for_unknown_call_id_refused(self):
        records = _rollout_records(OTHER_SID)
        records.append(_record("response_item",
                               {"type": "function_call_output",
                                "call_id": "ghost", "output": "?"}))
        path = self._rollout(self.source_home, OTHER_SID,
                             data=_records_bytes(records))
        with self.assertRaisesRegex(handoff.HandoffError, "unknown id"):
            handoff_codex.inspect_rollout(path, OTHER_SID)

    def test_symlink_rollout_refused_by_inspect(self):
        link = os.path.join(self.temp.name, "link.jsonl")
        os.symlink(self.rollout, link)
        with self.assertRaisesRegex(handoff.HandoffError, "symlink"):
            handoff_codex.inspect_rollout(link, SID)


class HandoffGroupGate(unittest.TestCase):
    def test_same_group_allowed(self):
        self.assertEqual(handoff.guard_handoff_group(
            {"name": "a", "handoff_group": "g1"},
            {"name": "b", "handoff_group": "g1"}), "g1")

    def test_cross_group_refused(self):
        with self.assertRaisesRegex(handoff.HandoffError, "handoff_group"):
            handoff.guard_handoff_group(
                {"name": "a", "handoff_group": "g1"},
                {"name": "b", "handoff_group": "g2"})

    def test_one_sided_group_refused(self):
        with self.assertRaisesRegex(handoff.HandoffError, "handoff_group"):
            handoff.guard_handoff_group(
                {"name": "a", "handoff_group": "g1"}, {"name": "b"})
        with self.assertRaisesRegex(handoff.HandoffError, "handoff_group"):
            handoff.guard_handoff_group(
                {"name": "a"}, {"name": "b", "handoff_group": "g1"})

    def test_no_groups_preserves_claude_behaviour(self):
        self.assertIsNone(handoff.guard_handoff_group(
            {"name": "a"}, {"name": "b"}))

    def test_claude_plan_path_never_calls_group_gate(self):
        # P1 regression pin (Claude byte-identical): the generic Claude plan
        # path must NOT enforce handoff_group — the gate is codex-only,
        # applied at codex plan, commit-entry, and the publish/exec gate.
        self.assertNotIn("guard_handoff_group",
                         inspect.getsource(handoff.plan_handoff))
        for gate in (handoff_codex.plan_codex_handoff,
                     handoff_codex.verify_codex_commit,
                     handoff_codex.verify_codex_gate):
            self.assertIn("guard_handoff_group", inspect.getsource(gate))


class TargetEffectiveBinding(CodexHandoffBase):
    """P0-1: the TARGET home's effective provider/auth — not just the source
    rollout header — gates the handoff."""

    def _target_config(self, text):
        with open(os.path.join(self.target_home, "config.toml"), "w",
                  encoding="utf-8") as handle:
            handle.write(text)

    def test_default_config_is_openai_and_plan_passes(self):
        self.plan()  # no config.toml -> codex default provider "openai"

    def test_nonopenai_provider_refused_at_plan(self):
        self._target_config('model_provider = "azure"\n')
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "model_provider 'azure'"):
            self.plan()

    def test_profile_provider_override_refused(self):
        self._target_config(
            'profile = "work"\nmodel_provider = "openai"\n'
            '[profiles.work]\nmodel_provider = "ollama"\n')
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "model_provider 'ollama'"):
            self.plan()

    def test_missing_selected_profile_refused(self):
        self._target_config('profile = "ghost"\n')
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "profile that is missing"):
            self.plan()

    def test_openai_redefinition_refused(self):
        self._target_config(
            '[model_providers.openai]\n'
            'base_url = "http://proxy.internal:8080/v1"\n')
        with self.assertRaisesRegex(handoff.HandoffError, "redefines"):
            self.plan()

    def test_unparseable_config_refused(self):
        self._target_config("model_provider = [broken\n")
        with self.assertRaisesRegex(handoff.HandoffError, "unreadable"):
            self.plan()

    def test_symlinked_config_refused(self):
        outside = os.path.join(self.temp.name, "outside-config.toml")
        with open(outside, "w") as handle:
            handle.write("")
        os.symlink(outside, os.path.join(self.target_home, "config.toml"))
        with self.assertRaisesRegex(handoff.HandoffError, "symlink"):
            self.plan()

    def test_apikey_target_auth_refused(self):
        with open(os.path.join(self.target_home, "auth.json"), "w") as handle:
            json.dump({"OPENAI_API_KEY": "sk-SECRET"}, handle)
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "ChatGPT-subscription"):
            self.plan()

    def test_missing_target_auth_refused(self):
        os.unlink(os.path.join(self.target_home, "auth.json"))
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "auth.json is missing"):
            self.plan()

    def test_snapshot_apikey_auth_mode_refused(self):
        snapshot = self.snapshot(
            identity={"verified": True, "account_fingerprint": "AAAA",
                      "credential_digest": "BBBB", "lineage_digest": "LLLL",
                      "auth_mode": "apikey"})
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "ChatGPT-subscription"):
            self.plan(snapshot=snapshot)

    def _project_config(self, directory, text):
        codex_dir = os.path.join(directory, ".codex")
        os.makedirs(codex_dir, exist_ok=True)
        with open(os.path.join(codex_dir, "config.toml"), "w",
                  encoding="utf-8") as handle:
            handle.write(text)

    def test_project_config_provider_refused_at_plan(self):
        # P0: codex merges a project .codex/config.toml at the resume cwd —
        # $CODEX_HOME/config.toml alone is NOT the effective configuration
        self._project_config(self.cwd, 'model_provider = "ollama"\n')
        with self.assertRaisesRegex(handoff.HandoffError, "project config"):
            self.plan()

    def test_project_config_in_parent_directory_refused(self):
        # the walk covers every ancestor of the resume cwd
        self._project_config(self.temp.name, 'model_provider = "azure"\n')
        with self.assertRaisesRegex(handoff.HandoffError, "project config"):
            self.plan()

    def test_project_openai_redefinition_refused(self):
        self._project_config(
            self.cwd,
            '[model_providers.openai]\nbase_url = "https://evil.example"\n')
        with self.assertRaisesRegex(handoff.HandoffError, "redefines"):
            self.plan()

    def test_system_config_layer_refused(self):
        system = os.path.join(self.temp.name, "etc-codex-config.toml")
        with open(system, "w", encoding="utf-8") as handle:
            handle.write('model_provider = "azure"\n')
        with mock.patch.object(handoff_codex, "_SYSTEM_CONFIG_LAYERS",
                               (system,)):
            with self.assertRaisesRegex(handoff.HandoffError,
                                        "system config"):
                self.plan()

    def test_project_config_added_during_staging_aborts_before_publish(self):
        plan = self.plan()
        with self.assertRaisesRegex(handoff.HandoffError, "project config"):
            self.commit_with_staging_mutation(
                plan, lambda: self._project_config(
                    self.cwd, 'model_provider = "ollama"\n'))
        self.assert_nothing_published()

    def test_non_string_profile_refused_not_typeerror(self):
        # profile = ["work"] is valid TOML — it must REFUSE, never raise an
        # unhandled TypeError out of the gate
        self._target_config('profile = ["work"]\n'
                            '[profiles.work]\nmodel_provider = "openai"\n')
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "missing or unreadable"):
            self.plan()

    def test_provider_config_change_during_staging_aborts_before_publish(self):
        plan = self.plan()
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "model_provider 'azure'"):
            self.commit_with_staging_mutation(
                plan,
                lambda: self._target_config('model_provider = "azure"\n'))
        self.assert_nothing_published()


class CodexCommit(CodexHandoffBase):
    def test_commit_publishes_rollout_only_same_relative_path(self):
        result = handoff.commit_handoff(self.plan())
        destination = os.path.join(self.target_home, "sessions", "2026",
                                   "07", "13", ROLLOUT_NAME % SID)
        self.assertEqual(result.destination, destination)
        with open(destination, "rb") as handle:
            copied = handle.read()
        self.assertEqual(copied,
                         _rollout_bytes(SID) + tokens.handoff_marker_line())
        self.assertEqual(os.stat(destination).st_mode & 0o777, 0o600)
        # source rollout is immutable and both auth.json files are untouched
        with open(self.rollout, "rb") as handle:
            self.assertEqual(handle.read(), _rollout_bytes(SID))
        for home in (self.source_home, self.target_home):
            with open(os.path.join(home, "auth.json"), "rb") as handle:
                self.assertEqual(handle.read(), AUTH_BYTES)
        # nothing but the rollout appeared in the target home
        published = []
        for base, _, names in os.walk(self.target_home):
            published.extend(os.path.join(base, name) for name in names)
        self.assertEqual(sorted(published),
                         sorted([destination,
                                 os.path.join(self.target_home, "auth.json")]))

    def test_commit_ledger_shape(self):
        result = handoff.commit_handoff(self.plan(scope=None))
        record = result.record
        required = {"schema", "ts", "handoff_id", "action", "old_session_id",
                    "session_id", "source_slot", "target_slot", "cwd",
                    "actual_model_family", "transcript_sha256",
                    "transcript_bytes", "provider", "handoff_group",
                    "resume_command", "resume_headless_command", "reason"}
        self.assertTrue(required.issubset(record),
                        sorted(required - set(record)))
        self.assertEqual(record["provider"], "codex")
        self.assertEqual(record["handoff_group"], "domanski-server")
        self.assertEqual(record["old_session_id"], SID)
        self.assertEqual(record["actual_model_family"], "codex")
        self.assertEqual(record["transcript_sha256"],
                         hashlib.sha256(_rollout_bytes(SID)).hexdigest())
        self.assertEqual(
            record["resume_command"],
            f"CODEX_HOME={self.target_home} codex resume {SID}")
        self.assertIn("codex exec resume", record["resume_headless_command"])
        # never any token/rollout content in the ledger
        serialized = json.dumps(record)
        self.assertNotIn("SECRET", serialized)
        self.assertNotIn("hello", serialized)
        ledger = handoff._ledger_path()
        self.assertEqual(os.stat(ledger).st_mode & 0o777, 0o600)

    def test_commit_cools_capped_source(self):
        scope = {"key": "cxa:*", "account_wide": True, "window": "5h",
                 "used_percent": 100.0, "reset": time.time() + 3600,
                 "family": "codex"}
        with mock.patch.object(handoff.route, "mark") as mark:
            result = handoff.commit_handoff(self.plan(scope=scope))
        mark.assert_called_once_with("cxa", "codex", scope["reset"],
                                     account_wide=True, window="5h")
        self.assertEqual(result.record["reason"], "capped")

    def test_no_clobber_destination_refused_at_plan_and_commit(self):
        source = self.source()
        destination = os.path.join(self.target_home, "sessions", "2026",
                                   "07", "13", ROLLOUT_NAME % SID)
        plan = handoff_codex.plan_codex_handoff(
            source, self.accounts[1], self.snapshot(), None, self.cwd,
            require_executable=False)
        os.makedirs(os.path.dirname(destination))
        with open(destination, "w") as handle:
            handle.write("existing")
        # plan-time preflight refuses an existing destination
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "does not overwrite"):
            handoff_codex.plan_codex_handoff(
                source, self.accounts[1], self.snapshot(), None, self.cwd,
                require_executable=False)
        # commit-time recheck refuses a destination that appeared after plan
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "does not overwrite"):
            handoff.commit_handoff(plan)
        with open(destination) as handle:
            self.assertEqual(handle.read(), "existing")

    def test_uuid_in_both_homes_after_handoff_fails_closed(self):
        # P1-3: after a completed handoff the UUID exists in BOTH homes; a
        # bare re-resolve must fail closed (NO ledger disambiguation — the
        # ledger would name the stale pre-handoff copy), --from names one.
        handoff.commit_handoff(self.plan())
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "matched 2 codex rollouts"):
            handoff_codex.resolve_codex_source(SID, self.accounts)
        source = handoff_codex.resolve_codex_source(SID, self.accounts,
                                                    from_slot="cxb")
        self.assertEqual(source.account["name"], "cxb")
        self.assertEqual(
            source.rollout_path,
            os.path.realpath(os.path.join(self.target_home, "sessions",
                                          "2026", "07", "13",
                                          ROLLOUT_NAME % SID)))

    def test_target_identity_change_blocks_commit(self):
        plan = self.plan()
        self.binding_value = ("OTHER", "CHANGED")
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "identity or credential"):
            handoff.commit_handoff(plan)
        self.assertFalse(os.path.exists(plan.destination))

    def test_target_lineage_change_blocks_commit(self):
        plan = self.plan()
        self.lineage_value = "MMMM"
        with self.assertRaisesRegex(handoff.HandoffError, "lineage"):
            handoff.commit_handoff(plan)
        self.assertFalse(os.path.exists(plan.destination))

    def test_quarantined_target_blocks_commit(self):
        plan = self.plan()
        route.quarantine_mark("cxb", "codex auth rejected")
        with self.assertRaisesRegex(handoff.HandoffError, "quarantined"):
            handoff.commit_handoff(plan)
        self.assertFalse(os.path.exists(plan.destination))

    def test_cross_group_plan_refused(self):
        foreign = dict(self.accounts[1], handoff_group="client-x")
        with self.assertRaisesRegex(handoff.HandoffError, "handoff_group"):
            handoff_codex.plan_codex_handoff(
                self.source(), foreign, self.snapshot(), None, self.cwd,
                require_executable=False)

    def test_double_handoff_refused_without_force(self):
        result = handoff.commit_handoff(self.plan())
        digest = result.record["transcript_sha256"]
        with self.assertRaisesRegex(handoff.HandoffError, "different --to"):
            handoff.guard_not_duplicate(SID, digest)
        handoff.guard_not_duplicate(SID, digest, force=True)
        # a bare re-plan now fails closed on the ambiguous UUID (P1-3); and
        # naming the original source with --from refuses on the existing copy
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "matched 2 codex rollouts"):
            self.plan()
        source = handoff_codex.resolve_codex_source(SID, self.accounts,
                                                    from_slot="cxa")
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "does not overwrite"):
            handoff_codex.plan_codex_handoff(
                source, self.accounts[1], self.snapshot(), None, self.cwd,
                require_executable=False)

    def test_recovery_marker_v2_reconciles_incomplete_publication(self):
        plan = self.plan()
        with handoff._handoff_lock():
            marker = handoff._copy_publish_pending(plan)
        self.assertTrue(os.path.exists(plan.destination))
        self.assertEqual(marker["components"],
                         ["sessions", "2026", "07", "13"])
        on_disk = json.load(open(handoff._marker_path(plan.handoff_id)))
        self.assertEqual(on_disk["schema"], "headroom_handoff_recovery@2")
        # no staged ledger row -> the next lock rolls the publication back
        handoff.append_ledger({"session_id": "reconcile-sentinel"})
        self.assertFalse(os.path.exists(plan.destination))
        self.assertFalse(os.path.exists(
            handoff._marker_path(plan.handoff_id)))


class PublishGateRaces(CodexHandoffBase):
    """P0-2: the COMPLETE target gate re-runs against fresh state under the
    handoff lock, after the staging copy and immediately before publication.
    Each race mutates real registry/quarantine/binding/capacity state DURING
    staging (the plan→publish transition) and must abort before publish."""

    def test_target_relogin_during_staging_aborts_before_publish(self):
        plan = self.plan()

        def relogin():
            self.binding_value = ("OTHER", "CHANGED")

        with self.assertRaisesRegex(handoff.HandoffError,
                                    "identity or credential"):
            self.commit_with_staging_mutation(plan, relogin)
        self.assert_nothing_published()

    def test_target_lineage_change_during_staging_aborts_before_publish(self):
        plan = self.plan()

        def fresh_login():
            self.lineage_value = "MMMM"

        with self.assertRaisesRegex(handoff.HandoffError, "lineage"):
            self.commit_with_staging_mutation(plan, fresh_login)
        self.assert_nothing_published()

    def test_group_change_during_staging_aborts_before_publish(self):
        plan = self.plan()
        regrouped = [dict(self.accounts[0]),
                     dict(self.accounts[1], handoff_group="client-x")]

        with self.assertRaisesRegex(handoff.HandoffError, "handoff_group"):
            self.commit_with_staging_mutation(
                plan, lambda: self.write_config(regrouped))
        self.assert_nothing_published()

    def test_quarantine_during_staging_aborts_before_publish(self):
        plan = self.plan()
        with self.assertRaisesRegex(handoff.HandoffError, "quarantined"):
            self.commit_with_staging_mutation(
                plan, lambda: route.quarantine_mark(
                    "cxb", "codex auth rejected"))
        self.assert_nothing_published()

    def test_capacity_loss_during_staging_aborts_before_publish(self):
        # the live TARGETED read — not the stale plan snapshot — proves
        # capacity at the publish edge
        plan = self.plan()

        def capped():
            self.live_windows["5h"]["used_percent"] = 100.0

        with self.assertRaisesRegex(handoff.HandoffError,
                                    "no longer has proven headroom"):
            self.commit_with_staging_mutation(plan, capped)
        self.assert_nothing_published()

    def test_foreign_reservation_during_staging_aborts_before_publish(self):
        plan = self.plan()

        def reserve():
            # the commit holds the handoff lock here (staging), so append the
            # foreign reservation row unlocked — exactly what a concurrent
            # automatic handoff's row looks like on disk
            handoff._append_ledger_unlocked({
                "schema": handoff.SCHEMA, "ts": time.time(),
                "handoff_id": str(__import__("uuid").uuid4()),
                "action": "cap_confirmed", "automatic": True,
                "target_slot": "cxb",
                "reservation_until": time.time() + 300})

        with self.assertRaisesRegex(handoff.HandoffError, "reserved"):
            self.commit_with_staging_mutation(plan, reserve)
        self.assert_nothing_published()

    def test_slot_rehomed_during_staging_aborts_before_publish(self):
        plan = self.plan()
        other_home = os.path.join(self.temp.name, "cxb-new")
        os.makedirs(other_home)
        rehomed = [dict(self.accounts[0]),
                   dict(self.accounts[1], home=other_home)]

        with self.assertRaisesRegex(handoff.HandoffError, "different home"):
            self.commit_with_staging_mutation(
                plan, lambda: self.write_config(rehomed))
        self.assert_nothing_published()

    def test_healthy_staging_publishes(self):
        # the same hook path with NO mutation publishes normally, proving the
        # race tests fail on the mutation, not on the hook plumbing
        plan = self.plan()
        result = self.commit_with_staging_mutation(plan, lambda: None)
        self.assertTrue(os.path.exists(result.destination))

    def test_publish_link_runs_under_quarantine_writers_lock(self):
        # P0-2: the hard link happens while the quarantine writers' lock is
        # STILL HELD, so a quarantine cannot land between the publish gate's
        # read and the link becoming visible in the target home
        plan = self.plan()
        seen = {}
        real_link = os.link

        def probing_link(*args, **kwargs):
            checks = {
                "config_lock": paths.config_path() + ".lock",
                "cooldown_lock": paths.cooldowns_path() + ".lock",
                "quarantine_lock": paths.quarantine_path() + ".lock",
            }
            for name, lock_path in checks.items():
                with open(lock_path, "a+") as handle:
                    try:
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(handle, fcntl.LOCK_UN)
                        seen[name] = "free"
                    except OSError:
                        seen[name] = "held"
            return real_link(*args, **kwargs)

        with mock.patch.object(handoff.os, "link", side_effect=probing_link):
            result = handoff.commit_handoff(plan)
        self.assertEqual(seen, {"config_lock": "held",
                                "cooldown_lock": "held",
                                "quarantine_lock": "held"})
        self.assertTrue(os.path.exists(result.destination))


class ExecGate(CodexHandoffBase):
    """P0-2: the same full gate immediately before exec."""

    def test_exec_gate_passes_on_healthy_target(self):
        plan = self.plan()
        handoff.commit_handoff(plan)
        handoff_codex.exec_within_gate(plan, lambda: None)

    def test_exec_launch_runs_under_both_locks(self):
        # P0-2: the launch runs while the global handoff lock AND the
        # quarantine writers' lock are still held; the lock fds are CLOEXEC,
        # so a real exec releases them exactly at the boundary
        plan = self.plan()
        handoff.commit_handoff(plan)
        seen = {}

        def probe():
            checks = {
                "handoff_lock": os.path.join(paths.state_dir(),
                                             "handoffs.lock"),
                "config_lock": paths.config_path() + ".lock",
                "cooldown_lock": paths.cooldowns_path() + ".lock",
                "quarantine_lock": paths.quarantine_path() + ".lock",
            }
            for name, lock_path in checks.items():
                with open(lock_path, "a+") as handle:
                    try:
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(handle, fcntl.LOCK_UN)
                        seen[name] = "free"
                    except OSError:
                        seen[name] = "held"
            return "launched"

        self.assertEqual(
            handoff_codex.exec_within_gate(plan, probe), "launched")
        self.assertEqual(seen, {"handoff_lock": "held",
                                "config_lock": "held",
                                "cooldown_lock": "held",
                                "quarantine_lock": "held"})

    def test_quarantine_after_publish_blocks_exec(self):
        plan = self.plan()
        handoff.commit_handoff(plan)
        route.quarantine_mark("cxb", "codex auth rejected")
        with self.assertRaisesRegex(handoff.HandoffError, "quarantined"):
            handoff_codex.exec_within_gate(plan, lambda: None)

    def test_relogin_after_publish_blocks_exec(self):
        plan = self.plan()
        handoff.commit_handoff(plan)
        self.binding_value = ("OTHER", "CHANGED")
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "identity or credential"):
            handoff_codex.exec_within_gate(plan, lambda: None)

    def test_capacity_loss_after_publish_blocks_exec(self):
        plan = self.plan()
        handoff.commit_handoff(plan)
        self.live_windows["5h"]["used_percent"] = 100.0
        with self.assertRaisesRegex(handoff.HandoffError,
                                    "no longer has proven headroom"):
            handoff_codex.exec_within_gate(plan, lambda: None)

    def test_group_change_after_publish_blocks_exec(self):
        plan = self.plan()
        handoff.commit_handoff(plan)
        self.write_config([dict(self.accounts[0]),
                           dict(self.accounts[1], handoff_group="client-x")])
        with self.assertRaisesRegex(handoff.HandoffError, "handoff_group"):
            handoff_codex.exec_within_gate(plan, lambda: None)


class FreshCollect(CodexHandoffBase):
    """P1-5: the force-collect API accepts a genuinely just-collected
    snapshot (integer-second `generated`) that max_age=0 would reject."""

    def test_fresh_codex_snapshot_accepts_just_collected(self):
        stamped = self.snapshot()  # real collector shape: generated=int(now)
        self.assertIsInstance(stamped["generated"], int)
        with mock.patch.object(collect, "run_collect", return_value=stamped):
            snapshot = handoff_codex.fresh_codex_snapshot()
        self.assertIs(snapshot, stamped)

    def test_collect_failure_holds_handoff(self):
        with mock.patch.object(collect, "run_collect",
                               side_effect=OSError("boom")):
            with self.assertRaisesRegex(handoff.HandoffError, "held"):
                handoff_codex.fresh_codex_snapshot()

    def test_stale_collect_result_holds_handoff(self):
        stale = self.snapshot()
        stale["generated"] = int(time.time()) - 3600
        with mock.patch.object(collect, "run_collect", return_value=stale):
            with self.assertRaisesRegex(handoff.HandoffError, "fresh"):
                handoff_codex.fresh_codex_snapshot()

    def test_none_collect_result_holds_handoff(self):
        # a concurrent collector returning no snapshot must hold, not crash
        with mock.patch.object(collect, "run_collect", return_value=None):
            with self.assertRaisesRegex(handoff.HandoffError, "fresh"):
                handoff_codex.fresh_codex_snapshot()


class CodexResumeShape(CodexHandoffBase):
    def test_resume_commands_and_argv(self):
        self.assertEqual(
            handoff_codex.codex_resume_command("/x/home", SID),
            f"CODEX_HOME=/x/home codex resume {SID}")
        self.assertEqual(
            handoff_codex.codex_exec_resume_command("/x/home", SID, "carry on"),
            f"CODEX_HOME=/x/home codex exec resume {SID} 'carry on'")
        self.assertIn('"<continuation prompt>"',
                      handoff_codex.codex_exec_resume_command("/x/home", SID))
        result = handoff.commit_handoff(self.plan())
        self.assertEqual(handoff_codex.resume_argv(result),
                         ["codex", "resume", SID])
        self.assertEqual(
            handoff_codex.exec_resume_argv(result, "carry on"),
            ["codex", "exec", "resume", SID, "carry on"])
        with self.assertRaisesRegex(handoff.HandoffError, "baton"):
            handoff_codex.exec_resume_argv(result, "  ")


class CodexCommandFlow(CodexHandoffBase):
    """CLI flows run the REAL registry (on-disk config), REAL candidate
    routing, and the REAL force-collect freshness path; only run_collect
    (network), codex_live (app-server), token reads, `which`, and the
    quiet-period sleep are stubbed."""

    def _cmd(self, args, snapshot=None, which="/usr/bin/codex",
             run_collect=None):
        output, errors = io.StringIO(), io.StringIO()
        if run_collect is None:
            def run_collect(quiet=False):
                return self.snapshot() if snapshot is None else snapshot
        with mock.patch.object(collect, "run_collect",
                               side_effect=run_collect), \
                mock.patch.object(handoff_codex.shutil, "which",
                                  return_value=which), \
                mock.patch.object(handoff, "guard_source_stable"), \
                redirect_stdout(output), redirect_stderr(errors):
            result = handoff.cmd_handoff(args)
        return result, output.getvalue(), errors.getvalue()

    def _failure_rows(self):
        if not os.path.exists(handoff._ledger_path()):
            return []
        return [row for row in handoff._read_jsonl(handoff._ledger_path(),
                                                   "handoff ledger")
                if row.get("action") == "failure"]

    def test_print_flow_stages_and_prints_codex_baton(self):
        result, output, errors = self._cmd(["--session", SID, "--print"])
        self.assertEqual(result, 0, errors)
        self.assertIn("BATON — codex conversation staged", output)
        self.assertIn(f"CODEX_HOME={self.target_home} codex resume {SID}",
                      output)
        self.assertIn("codex exec resume", output)
        self.assertIn("running shell processes", output)
        destination = os.path.join(self.target_home, "sessions", "2026",
                                   "07", "13", ROLLOUT_NAME % SID)
        self.assertTrue(os.path.exists(destination))
        with open(handoff._ledger_path()) as handle:
            record = json.loads(handle.readline())
        self.assertEqual(record["provider"], "codex")

    def test_auto_detection_finds_codex_rollout(self):
        # no --provider: the UUID only resolves as a codex rollout
        result, output, _ = self._cmd(["--session", SID, "--print"])
        self.assertEqual(result, 0)
        self.assertIn("codex resume", output)

    def test_ambiguous_uuid_across_providers_requires_flag(self):
        claude_home = os.path.join(self.temp.name, "cl")
        slug = handoff._claude_slug(os.path.realpath(self.cwd))
        os.makedirs(os.path.join(claude_home, "projects", slug))
        transcript = os.path.join(claude_home, "projects", slug,
                                  SID + ".jsonl")
        with open(transcript, "w") as handle:
            handle.write(json.dumps({"type": "user"}) + "\n")
        self.write_config(self.accounts + [
            {"name": "cl", "provider": "claude", "home": claude_home}])
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = handoff.cmd_handoff(["--session", SID, "--print"])
        self.assertEqual(result, 2)
        self.assertIn("both a Claude home and a Codex home",
                      errors.getvalue())
        result, output, _ = self._cmd(
            ["--session", SID, "--provider", "codex", "--print"])
        self.assertEqual(result, 0)
        self.assertIn("codex resume", output)

    def test_codex_provider_requires_session(self):
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = handoff.cmd_handoff(["--provider", "codex", "--print"])
        self.assertEqual(result, 2)
        self.assertIn("requires --session", errors.getvalue())

    def test_claude_model_flag_refused_for_codex(self):
        result, _, errors = self._cmd(
            ["--session", SID, "--model", "sonnet", "--print"])
        self.assertEqual(result, 2)
        self.assertIn("Claude family", errors)

    def test_unknown_provider_flag_refused(self):
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = handoff.cmd_handoff(
                ["--session", SID, "--provider", "gemini", "--print"])
        self.assertEqual(result, 2)
        self.assertIn("--provider must be claude or codex", errors.getvalue())

    def test_missing_codex_binary_refused(self):
        result, _, errors = self._cmd(["--session", SID, "--print"],
                                      which=None)
        self.assertEqual(result, 2)
        self.assertIn("`codex` not found", errors)

    def test_codex_only_flags_refused_for_claude(self):
        for flags in (["--from", "cxa"], ["--headless", "carry on"]):
            errors = io.StringIO()
            with redirect_stderr(errors):
                result = handoff.cmd_handoff(
                    ["--provider", "claude", "--yes"] + flags)
            self.assertEqual(result, 2)
            self.assertIn("codex handoff options", errors.getvalue())

    def test_exec_flow_rechecks_full_gate_and_execs_codex(self):
        calls = {}

        def fake_exec(binary, argv, environment):
            calls["binary"] = binary
            calls["argv"] = argv
            calls["env"] = environment
            raise OSError("stop here")  # keep the test process alive

        with mock.patch.object(handoff_codex.os, "execvpe",
                               side_effect=fake_exec):
            result, _, errors = self._cmd(["--session", SID, "--yes"])
        self.assertEqual(result, 127, errors)
        self.assertEqual(calls["argv"], ["codex", "resume", SID])
        self.assertEqual(calls["env"]["CODEX_HOME"], self.target_home)
        self.assertNotIn("OPENAI_API_KEY", calls["env"])

    def test_headless_flow_execs_exec_resume_with_baton(self):
        # P1-6: a real product path for headless resume — full pre-exec gate
        # then `codex exec resume UUID BATON` on the scrubbed env
        calls = {}

        def fake_exec(binary, argv, environment):
            calls["argv"] = argv
            calls["env"] = environment
            raise OSError("stop here")

        with mock.patch.object(handoff_codex.os, "execvpe",
                               side_effect=fake_exec):
            result, output, errors = self._cmd(
                ["--session", SID, "--yes", "--headless", "carry on"])
        self.assertEqual(result, 127, errors)
        self.assertEqual(calls["argv"],
                         ["codex", "exec", "resume", SID, "carry on"])
        self.assertEqual(calls["env"]["CODEX_HOME"], self.target_home)
        self.assertNotIn("OPENAI_API_KEY", calls["env"])
        self.assertIn("BATON — codex conversation staged", output)

    def test_headless_gate_blocks_exec_when_target_quarantined(self):
        # quarantine lands between publication and exec: the headless path
        # must refuse to launch (and the refusal is ledgered with its stage)
        def quarantine_after_baton(*args, **kwargs):
            route.quarantine_mark("cxb", "codex auth rejected")

        with mock.patch.object(handoff_codex, "_print_baton",
                               side_effect=quarantine_after_baton), \
                mock.patch.object(handoff_codex.os, "execvpe") as execvpe:
            result, _, errors = self._cmd(
                ["--session", SID, "--yes", "--headless", "carry on"])
        self.assertEqual(result, 2)
        execvpe.assert_not_called()
        self.assertIn("quarantined", errors)
        self.assertIn("already published", errors)
        rows = self._failure_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["stage"], "exec")

    def test_headless_requires_nonempty_baton(self):
        result, _, errors = self._cmd(
            ["--session", SID, "--yes", "--headless", "   "])
        self.assertEqual(result, 2)
        self.assertIn("non-empty continuation baton", errors)
        self.assert_nothing_published()

    def test_headless_with_print_refused(self):
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = handoff.cmd_handoff(
                ["--session", SID, "--print", "--headless", "x"])
        self.assertEqual(result, 2)
        self.assertIn("mutually exclusive", errors.getvalue())

    def test_decline_confirmation_copies_nothing(self):
        stdin = mock.Mock()
        stdin.isatty.return_value = True
        output = io.StringIO()
        with mock.patch.object(handoff.sys, "stdin", stdin), \
                mock.patch("builtins.input", return_value="n"), \
                mock.patch.object(collect, "run_collect",
                                  side_effect=lambda quiet=False:
                                  self.snapshot()), \
                mock.patch.object(handoff_codex.shutil, "which",
                                  return_value="/usr/bin/codex"), \
                mock.patch.object(handoff, "guard_source_stable"), \
                redirect_stdout(output):
            result = handoff.cmd_handoff(["--session", SID])
        self.assertEqual(result, 0)
        self.assertIn("nothing copied or cooled", output.getvalue())
        self.assertFalse(os.path.exists(os.path.join(
            self.target_home, "sessions")))
        self.assertFalse(os.path.exists(handoff._ledger_path()))

    def test_target_relogin_during_confirmation_is_rejected(self):
        # a REAL relogin: the second collect sees the new identity AND the
        # local binding/lineage now derive to it consistently — the pinned
        # plan identity is what refuses
        state = {"calls": 0}

        def run_collect(quiet=False):
            state["calls"] += 1
            if state["calls"] == 1:
                return self.snapshot()
            self.binding_value = ("OTHER", "CHANGED")
            self.lineage_value = "MMMM"
            return self.snapshot(identity={
                "verified": True, "account_fingerprint": "OTHER",
                "credential_digest": "CHANGED", "lineage_digest": "MMMM",
                "auth_mode": "chatgpt"})

        stdin = mock.Mock()
        stdin.isatty.return_value = True
        errors = io.StringIO()
        with mock.patch.object(handoff.sys, "stdin", stdin), \
                mock.patch("builtins.input", return_value="y"), \
                mock.patch.object(collect, "run_collect",
                                  side_effect=run_collect), \
                mock.patch.object(handoff_codex.shutil, "which",
                                  return_value="/usr/bin/codex"), \
                mock.patch.object(handoff, "guard_source_stable"), \
                redirect_stdout(io.StringIO()), redirect_stderr(errors):
            result = handoff.cmd_handoff(["--session", SID])
        self.assertEqual(result, 2)
        self.assertIn("changed during confirmation", errors.getvalue())
        self.assertFalse(os.path.exists(os.path.join(
            self.target_home, "sessions")))
        rows = self._failure_rows()
        self.assertEqual(len(rows), 1)
        self.assertIn("changed during confirmation", rows[0]["reason"])


class RefusalLedger(CodexHandoffBase):
    """P2-7: every refusal appends a sanitized decision row — parity with the
    staged-success record; never rollout content, never credentials."""

    def _cmd(self, args, **kwargs):
        return CodexCommandFlow._cmd(self, args, **kwargs)

    def _failure_rows(self):
        return CodexCommandFlow._failure_rows(self)

    def test_ambiguity_refusal_is_ledgered(self):
        self._rollout(self.target_home, SID)
        result, _, errors = self._cmd(["--session", SID, "--print"])
        self.assertEqual(result, 2)
        self.assertIn("ambiguous", errors)
        rows = self._failure_rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["action"], "failure")
        self.assertEqual(row["provider"], "codex")
        self.assertEqual(row["stage"], "plan")
        self.assertIn("ambiguous", row["reason"])
        serialized = json.dumps(row)
        self.assertNotIn("SECRET", serialized)
        self.assertNotIn("hello", serialized)

    def test_quarantine_refusal_is_ledgered(self):
        route.quarantine_mark("cxb", "codex auth rejected")
        result, _, errors = self._cmd(
            ["--session", SID, "--to", "cxb", "--print"])
        self.assertEqual(result, 2)
        rows = self._failure_rows()
        self.assertEqual(len(rows), 1)
        self.assertIn("quarantin", rows[0]["reason"])
        self.assertEqual(rows[0]["source_slot"], "cxa")

    def test_capacity_refusal_is_ledgered(self):
        result, _, errors = self._cmd(
            ["--session", SID, "--print"],
            snapshot={"generated": int(time.time()), "accounts": [
                _codex_row("cxa", used5h=100.0),
                _codex_row("cxb", used5h=100.0)]})
        self.assertEqual(result, 2)
        self.assertIn("proven headroom", errors)
        rows = self._failure_rows()
        self.assertEqual(len(rows), 1)
        self.assertIn("headroom", rows[0]["reason"])

    def test_group_refusal_is_ledgered(self):
        self.write_config([dict(self.accounts[0]),
                           dict(self.accounts[1],
                                handoff_group="client-x")])
        result, _, errors = self._cmd(["--session", SID, "--print"])
        self.assertEqual(result, 2)
        rows = self._failure_rows()
        self.assertEqual(len(rows), 1)
        self.assertIn("handoff_group", rows[0]["reason"])
        self.assertEqual(rows[0]["target_slot"], "cxb")

    def test_publication_failure_is_ledgered_with_publish_stage(self):
        original = handoff._write_marker_unlocked

        def hooked(plan_, components, temporary, destination):
            marker = original(plan_, components, temporary, destination)
            route.quarantine_mark("cxb", "codex auth rejected")
            return marker

        with mock.patch.object(handoff, "_write_marker_unlocked",
                               side_effect=hooked):
            result, _, errors = self._cmd(["--session", SID, "--print"])
        self.assertEqual(result, 2)
        self.assertIn("quarantined", errors)
        self.assert_nothing_published()
        rows = self._failure_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["stage"], "publish")
        self.assertEqual(rows[0]["old_session_id"], SID)
        # the failure row is well-formed protective state: subsequent locked
        # ledger reads (a fresh plan) still validate and work
        self.plan()

    def test_ledger_failure_does_not_mask_refusal(self):
        self._rollout(self.target_home, SID)
        with mock.patch.object(handoff, "append_action",
                               side_effect=handoff.HandoffError("ledger down")):
            result, _, errors = self._cmd(["--session", SID, "--print"])
        self.assertEqual(result, 2)
        self.assertIn("ambiguous", errors)


if __name__ == "__main__":
    unittest.main()
