"""Opt-in local token telemetry parsing, persistence, and payload tests."""
import datetime
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

from headroom import collect as usage_collect
from headroom import dashboard, paths, registry, tokens


NOW = 2_000_000_000


def slot_id(name):
    return hashlib.sha256(name.encode()).hexdigest()[:12]


def counts(input_tokens, output, cache_read=0, cache_creation=0):
    total = input_tokens + output + cache_creation
    return {
        "input": input_tokens,
        "output": output,
        "cache_read": cache_read,
        "cache_creation": cache_creation,
        "total": total,
        "grand_total": total + cache_read,
    }


def day_counts(input_tokens, output, cache_read=0, cache_creation=0,
               session_count=0, longest_session_s=0, families=None,
               efforts=None):
    result = counts(input_tokens, output, cache_read, cache_creation)
    result.update({
        "session_count": session_count,
        "longest_session_s": longest_session_s,
        "families": families or {},
        "efforts": efforts or {},
    })
    return result


def claude_line(timestamp, request_id, message_id, input_tokens=5,
                output_tokens=3, cache_read=11, cache_creation=7,
                model="claude-sonnet-4-5-20250929"):
    return json.dumps({
        "type": "assistant",
        "timestamp": timestamp,
        "requestId": request_id,
        "uuid": "transcript-" + request_id,
        "message": {
            "id": message_id,
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": "must not persist"}],
            "usage": {
                "input_tokens": input_tokens,
                "cache_creation_input_tokens": cache_creation,
                "cache_read_input_tokens": cache_read,
                "output_tokens": output_tokens,
            },
        },
    }) + "\n"


def codex_line(timestamp, input_tokens, cached, output):
    return json.dumps({
        "timestamp": timestamp,
        "type": "event_msg",
        "payload": {
            "type": "token_count",
            "info": {
                "total_token_usage": {
                    "input_tokens": input_tokens,
                    "cached_input_tokens": cached,
                    "output_tokens": output,
                    "reasoning_output_tokens": output // 2,
                    "total_tokens": input_tokens + output,
                },
                "last_token_usage": {
                    "input_tokens": 999999,
                    "cached_input_tokens": 0,
                    "output_tokens": 999999,
                },
            },
        },
    }) + "\n"


def codex_context_line(timestamp, model="gpt-5.6-sol", effort="xhigh"):
    return json.dumps({
        "timestamp": timestamp,
        "type": "turn_context",
        "payload": {"model": model, "effort": effort},
    }) + "\n"


def usage_snapshot(account_id):
    return {
        "schema_version": 1,
        "generated": NOW,
        "accounts": [{
            "id": account_id,
            "name": "alpha",
            "provider": "claude",
            "ok": True,
            "stale": False,
            "captured_at": NOW,
            "windows": {
                "5h": {"used_percent": 10, "resets_at": NOW + 3600},
                "7d": {"used_percent": 20, "resets_at": NOW + 86400},
            },
        }],
    }


class TokenParserTests(unittest.TestCase):
    def test_claude_real_shape_dedupes_repeated_assistant_usage(self):
        first = claude_line(
            "2026-07-10T23:59:59.900-02:00", "req-1", "msg-1")
        duplicate = claude_line(
            "2026-07-11T01:59:59.950Z", "req-1", "msg-1",
            output_tokens=13)
        final_repeat = claude_line(
            "2026-07-11T02:00:00Z", "req-1", "msg-1",
            output_tokens=13)
        next_message = claude_line(
            "2026-07-12T00:00:00Z", "req-2", "msg-2",
            input_tokens=2, output_tokens=4, cache_read=6,
            cache_creation=8)
        stream = io.BytesIO(
            (first + duplicate + final_repeat + next_message).encode())
        parsed = tokens._parse_stream(stream, "claude")
        self.assertEqual(parsed["days"]["2026-07-11"],
                         day_counts(5, 13, 11, 7,
                                    families={"sonnet": 36}))
        self.assertEqual(parsed["days"]["2026-07-12"],
                         day_counts(2, 4, 6, 8,
                                    families={"sonnet": 20}))
        serialized = json.dumps(parsed)
        self.assertNotIn("must not persist", serialized)
        self.assertNotIn("req-1", serialized)
        self.assertNotIn("msg-1", serialized)

    def test_codex_cumulative_totals_use_deltas_and_split_cached_input(self):
        rows = [
            codex_line("2026-07-10T23:59:59Z", 100, 60, 20),
            codex_line("2026-07-11T00:00:01Z", 180, 100, 50),
            codex_line("2026-07-11T00:00:02Z", 180, 100, 50),
        ]
        parsed = tokens._parse_stream(
            io.BytesIO("".join(rows).encode()), "codex")
        self.assertEqual(parsed["days"]["2026-07-10"],
                         day_counts(40, 20, 60))
        self.assertEqual(parsed["days"]["2026-07-11"],
                         day_counts(40, 30, 40))
        lifetime = sum(day["total"] for day in parsed["days"].values())
        self.assertEqual(lifetime, 130)
        self.assertEqual(sum(day["grand_total"]
                             for day in parsed["days"].values()), 230)
        self.assertEqual(parsed["last_counter"], counts(80, 50, 100))

    def test_real_metadata_buckets_claude_families_and_codex_effort(self):
        claude_rows = "".join([
            claude_line("2026-07-11T00:00:00Z", "r1", "m1",
                        model="claude-fable-5"),
            claude_line("2026-07-11T00:01:00Z", "r2", "m2",
                        model="claude-opus-4-1"),
            claude_line("2026-07-11T00:02:00Z", "r3", "m3",
                        model="claude-haiku-3-5"),
            claude_line("2026-07-11T00:03:00Z", "r4", "m4",
                        model="custom-preview"),
        ])
        parsed = tokens._parse_stream(
            io.BytesIO(claude_rows.encode()), "claude")
        self.assertEqual(parsed["days"]["2026-07-11"]["families"], {
            "fable": 26, "opus": 26, "haiku": 26, "other": 26})

        codex_rows = codex_context_line("2026-07-11T00:00:00Z") + \
            codex_line("2026-07-11T00:00:01Z", 100, 60, 20)
        parsed = tokens._parse_stream(
            io.BytesIO(codex_rows.encode()), "codex")
        self.assertEqual(parsed["days"]["2026-07-11"]["families"],
                         {"gpt": 120})
        self.assertEqual(parsed["days"]["2026-07-11"]["efforts"],
                         {"xhigh": 120})

    def test_session_duration_uses_file_endpoints_with_clamp_and_cap(self):
        files = {}
        cases = (
            ("negative", "2026-07-10T01:00:00Z",
             "2026-07-10T00:00:00Z", 0),
            ("normal", "2026-07-11T00:00:00Z",
             "2026-07-11T01:30:00Z", 5400),
            ("capped", "2026-07-12T00:00:00Z",
             "2026-07-15T00:00:00Z", 48 * 60 * 60),
        )
        for name, first, last, _expected in cases:
            files[name] = {
                "slot_id": "slot", "days": {},
                "first_event_ts": tokens._timestamp(first),
                "last_event_ts": tokens._timestamp(last),
            }
        daily = tokens._daily_from_files(files)["slot"]
        for _name, first, _last, expected in cases:
            day = first[:10]
            self.assertEqual(daily[day]["session_count"], 1)
            self.assertEqual(daily[day]["longest_session_s"], expected)

    def test_malformed_lines_and_usage_are_skipped(self):
        invalid = json.dumps({
            "type": "assistant", "timestamp": "not-a-time",
            "message": {"role": "assistant", "usage": {
                "input_tokens": "secret", "output_tokens": 1}},
        }) + "\n"
        valid = claude_line("2026-07-10T00:00:00Z", "r", "m")
        parsed = tokens._parse_stream(
            io.BytesIO(("not-json\n" + invalid + valid).encode()), "claude")
        self.assertEqual(list(parsed["days"]), ["2026-07-10"])


class TokenStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {
            "HEADROOM_DIR": self.temp.name,
            "HEADROOM_TOKEN_SCAN_INTERVAL": "900",
        }, clear=False)
        self.env.start()
        os.environ.pop("HEADROOM_TOKEN_STATS", None)
        self.home = os.path.join(self.temp.name, "claude-home")
        self.project = os.path.join(self.home, "projects", "project")
        os.makedirs(self.project)
        self.account = {
            "id": slot_id("alpha"), "name": "alpha",
            "provider": "claude", "home": self.home,
        }
        self.config = {
            "schema_version": 1,
            "dashboard": {"token_stats": True},
            "accounts": [self.account],
        }
        registry.save(self.config)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def write(self, name, text, mode="w"):
        path = os.path.join(self.project, name)
        with open(path, mode, encoding="utf-8") as handle:
            handle.write(text)
        return path

    def test_incremental_grown_new_and_unchanged_files(self):
        first = self.write(
            "one.jsonl", claude_line(
                "2026-07-10T00:00:00Z", "r1", "m1"))
        self.assertTrue(tokens.collect(
            [self.account], config=self.config, now=NOW, force=True))
        first_size = os.path.getsize(first)
        with mock.patch.object(tokens, "_scan_file",
                               wraps=tokens._scan_file) as scan_file:
            self.assertTrue(tokens.collect(
                [self.account], config=self.config, now=NOW + 1, force=True))
        scan_file.assert_not_called()

        self.write("one.jsonl", claude_line(
            "2026-07-11T00:00:00Z", "r2", "m2"), mode="a")
        self.write("two.jsonl", claude_line(
            "2026-07-11T01:00:00Z", "r3", "m3",
            input_tokens=1, output_tokens=1, cache_read=1,
            cache_creation=1))
        starts = []
        original = tokens._parse_stream

        def track(handle, provider, start=0, previous=None):
            starts.append(start)
            return original(handle, provider, start=start, previous=previous)

        with mock.patch.object(tokens, "_parse_stream", side_effect=track):
            self.assertTrue(tokens.collect(
                [self.account], config=self.config, now=NOW + 2, force=True))
        self.assertIn(first_size, starts)
        self.assertIn(0, starts)
        store = paths.load_json(paths.token_daily_path())
        daily = store["accounts"][self.account["id"]]
        self.assertEqual(daily["2026-07-10"], day_counts(
            5, 3, 11, 7, session_count=1, longest_session_s=86400,
            families={"sonnet": 26}))
        self.assertEqual(daily["2026-07-11"], day_counts(
            6, 4, 12, 8, session_count=1,
            families={"sonnet": 30}))
        self.assertEqual(stat.S_IMODE(os.stat(paths.tokens_dir()).st_mode),
                         0o700)
        self.assertEqual(stat.S_IMODE(os.stat(
            paths.token_daily_path()).st_mode), 0o600)

    def test_throttle_returns_before_discovery(self):
        self.write("one.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "r1", "m1"))
        tokens.collect([self.account], config=self.config, now=NOW, force=True)
        with mock.patch.object(
                tokens, "_files",
                side_effect=AssertionError("filesystem discovery")):
            self.assertFalse(tokens.collect(
                [self.account], config=self.config, now=NOW + 899))

    def test_incremental_tail_resumes_progressive_claude_message(self):
        path = self.write("one.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "r1", "m1", output_tokens=4))
        tokens.collect([self.account], config=self.config, now=NOW, force=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(claude_line(
                "2026-07-10T00:00:01Z", "r1", "m1", output_tokens=10))
        tokens.collect(
            [self.account], config=self.config, now=NOW + 1, force=True)
        daily = paths.load_json(paths.token_daily_path())[
            "accounts"][self.account["id"]]
        self.assertEqual(daily["2026-07-10"], day_counts(
            5, 10, 11, 7, session_count=1, longest_session_s=1,
            families={"sonnet": 33}))

    def test_schema_bump_forces_full_rescan_before_throttle(self):
        path = self.write("one.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "r1", "m1"))
        stat_result = os.stat(path)
        paths.write_json_atomic(paths.token_scan_state_path(), {
            "schema_version": 1,
            "last_scan": NOW,
            "files": {path: {
                "slot_id": self.account["id"], "provider": "claude",
                "size": stat_result.st_size,
                "mtime_ns": stat_result.st_mtime_ns,
                "offset": stat_result.st_size,
                "days": {},
            }},
        })
        with mock.patch.object(tokens, "_scan_file",
                               wraps=tokens._scan_file) as scan_file:
            self.assertTrue(tokens.collect(
                [self.account], config=self.config, now=NOW + 1))
        scan_file.assert_called_once()
        self.assertEqual(paths.load_json(
            paths.token_scan_state_path())["schema_version"], 2)
        self.assertEqual(paths.load_json(
            paths.token_daily_path())["schema_version"], 2)

    def test_disabled_gate_does_not_scan_or_touch_token_state(self):
        disabled = dict(self.config)
        disabled["dashboard"] = {"token_stats": False}
        with mock.patch.object(
                tokens, "_files", side_effect=AssertionError("scanned")):
            self.assertFalse(tokens.collect(
                [self.account], config=disabled, now=NOW, force=True))
        self.assertFalse(os.path.exists(paths.tokens_dir()))
        self.assertFalse(registry.token_stats_enabled(disabled))
        with mock.patch.dict(os.environ, {"HEADROOM_TOKEN_STATS": "1"}):
            self.assertTrue(registry.token_stats_enabled(disabled))

    def test_unreadable_or_malformed_file_never_discards_prior_totals(self):
        path = self.write("one.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "r1", "m1"))
        tokens.collect([self.account], config=self.config, now=NOW, force=True)
        before = paths.load_json(paths.token_daily_path())
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("{malformed\n")
        with mock.patch.object(tokens, "_scan_file", side_effect=OSError("no")):
            self.assertTrue(tokens.collect(
                [self.account], config=self.config, now=NOW + 1, force=True))
        after = paths.load_json(paths.token_daily_path())
        self.assertEqual(after["accounts"], before["accounts"])


class TokenSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {
            "HEADROOM_DIR": self.temp.name,
        }, clear=False)
        self.env.start()
        os.environ.pop("HEADROOM_TOKEN_STATS", None)
        self.account = {
            "id": slot_id("alpha"), "name": "alpha",
            "provider": "claude", "home": os.path.join(self.temp.name, "a"),
        }
        self.config = {
            "schema_version": 1,
            "dashboard": {"token_stats": True},
            "accounts": [self.account],
        }
        registry.save(self.config)
        self.today = datetime.datetime.fromtimestamp(
            NOW, datetime.timezone.utc).date()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def day(self, offset):
        return (self.today + datetime.timedelta(days=offset)).isoformat()

    def test_daily_peak_streak_lifetime_last7_and_slot_allow_list(self):
        live_days = {}
        for offset in (-20, -19, -18, -17, -16, -3, -2, -1, 0):
            live_days[self.day(offset)] = day_counts(
                10 + offset + 20, 5, cache_read=2)
        live_days[self.day(-2)] = day_counts(
            100, 20, cache_read=50, session_count=2,
            longest_session_s=3700, families={"fable": 170},
            efforts={"xhigh": 170})
        store = {
            "schema_version": tokens.SCHEMA_VERSION,
            "generated": NOW - 10,
            "accounts": {
                self.account["id"]: live_days,
                slot_id("removed"): {
                    self.day(0): day_counts(9999, 1)},
            },
        }
        value = tokens.summarize(store, [self.account], now=NOW)
        self.assertEqual([row["id"] for row in value["accounts"]],
                         [self.account["id"]])
        self.assertEqual(value["summary"]["current_streak"], 4)
        self.assertEqual(value["summary"]["longest_streak"], 5)
        self.assertEqual(value["summary"]["peak"], {
            "date": self.day(-2), "total": 120, "grand_total": 170})
        row = value["accounts"][0]
        self.assertEqual(row["peak"], value["summary"]["peak"])
        self.assertEqual(row["last7d"], sum(
            live_days[self.day(offset)]["total"]
            for offset in (-3, -2, -1, 0)))
        self.assertEqual(row["lifetime"], value["summary"]["lifetime"])
        self.assertEqual(value["summary"]["grand_total"], sum(
            counts["grand_total"] for counts in live_days.values()))
        self.assertEqual(row["lifetime_grand_total"],
                         value["summary"]["grand_total"])
        self.assertEqual(row["last7d_grand_total"], sum(
            live_days[self.day(offset)]["grand_total"]
            for offset in (-3, -2, -1, 0)))
        self.assertEqual(value["summary"]["total_sessions"], 2)
        self.assertEqual(value["summary"]["longest_session"], {
            "seconds": 3700, "date": self.day(-2), "account": "alpha"})
        self.assertEqual(value["summary"]["active_days"], len(live_days))
        self.assertEqual(value["summary"]["most_used_model"], {
            "label": "fable", "share_pct": 100.0})
        self.assertEqual(value["summary"]["families"][0], {
            "label": "fable", "tokens": 170, "share_pct": 100.0})
        self.assertEqual(value["summary"]["efforts"][-1], {
            "label": "xhigh", "tokens": 170, "share_pct": 100.0})

    def test_missing_new_derived_fields_are_zero_safe(self):
        day = self.day(0)
        value = tokens.summarize({
            "schema_version": tokens.SCHEMA_VERSION,
            "generated": NOW,
            "accounts": {self.account["id"]: {day: counts(2, 3, 5)}},
        }, [self.account], now=NOW)
        self.assertEqual(value["summary"]["total_sessions"], 0)
        self.assertEqual(value["summary"]["longest_session"], {
            "seconds": 0, "date": None, "account": None})
        self.assertEqual(value["summary"]["most_used_model"], {
            "label": None, "share_pct": 0})

    def test_session_only_day_does_not_become_token_peak(self):
        day = self.day(0)
        value = tokens.summarize({
            "schema_version": tokens.SCHEMA_VERSION,
            "generated": NOW,
            "accounts": {self.account["id"]: {
                day: day_counts(0, 0, session_count=1,
                                longest_session_s=60)}},
        }, [self.account], now=NOW)
        self.assertEqual(value["summary"]["peak"], {
            "date": None, "total": 0, "grand_total": 0})
        self.assertEqual(value["summary"]["active_days"], 0)
        self.assertEqual(value["summary"]["total_sessions"], 1)

    def test_display_payload_embeds_only_when_enabled_and_caps_400_days(self):
        days = {}
        for offset in range(-404, 1):
            days[self.day(offset)] = day_counts(1, 1)
        paths.write_json_atomic(paths.token_daily_path(), {
            "schema_version": tokens.SCHEMA_VERSION, "generated": NOW,
            "accounts": {self.account["id"]: days},
        })
        snapshot = usage_snapshot(self.account["id"])
        enabled = dashboard.display_snapshot(
            snapshot, evaluated_at=NOW, config=self.config)
        self.assertIn("token_stats", enabled)
        self.assertEqual(len(enabled["token_stats"]["days"]), 400)
        self.assertEqual(min(enabled["token_stats"]["days"]), self.day(-399))
        disabled = dict(self.config)
        disabled["dashboard"] = {"token_stats": False}
        self.assertNotIn("token_stats", dashboard.display_snapshot(
            snapshot, evaluated_at=NOW, config=disabled))

    def test_enabled_without_store_omits_payload_key(self):
        value = dashboard.display_snapshot(
            usage_snapshot(self.account["id"]), evaluated_at=NOW,
            config=self.config)
        self.assertNotIn("token_stats", value)

    def test_run_collect_token_failure_is_nonfatal_and_disabled_skips_scan(self):
        snapshot = usage_snapshot(self.account["id"])
        snapshot.update({"run_id": "fixture", "generated_iso": "fixture"})
        with mock.patch.object(usage_collect, "collect",
                               return_value=snapshot), \
                mock.patch.object(registry, "apply_pins",
                                  return_value=[self.account]), \
                mock.patch.object(registry, "dashboard_settings",
                                  return_value={"redact_emails": True}), \
                mock.patch.object(usage_collect.history, "append_snapshot"), \
                mock.patch.object(tokens, "collect",
                                  side_effect=RuntimeError("broken")), \
                redirect_stderr(io.StringIO()):
            self.assertIs(usage_collect.run_collect(quiet=True), snapshot)
        disabled = dict(self.config)
        disabled["dashboard"] = {"token_stats": False}
        registry.save(disabled)
        with mock.patch.object(usage_collect, "collect",
                               return_value=snapshot), \
                mock.patch.object(registry, "apply_pins",
                                  return_value=[self.account]), \
                mock.patch.object(registry, "dashboard_settings",
                                  return_value={"redact_emails": True}), \
                mock.patch.object(usage_collect.history, "append_snapshot"), \
                mock.patch.object(tokens, "collect") as scan:
            usage_collect.run_collect(quiet=True)
        scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
