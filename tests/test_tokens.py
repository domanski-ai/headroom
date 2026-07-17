"""Opt-in local token telemetry parsing, persistence, and payload tests."""
import datetime
import hashlib
import io
import json
import os
import stat
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from unittest import mock

from headroom import collect as usage_collect
from headroom import __main__ as cli
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
               efforts=None, projects=None, attributed=None):
    result = counts(input_tokens, output, cache_read, cache_creation)
    result.update({
        "session_count": session_count,
        "longest_session_s": longest_session_s,
        "families": families or {},
        "efforts": efforts or {},
        "projects": projects or {},
        "attributed": attributed or {},
    })
    return result


def claude_line(timestamp, request_id, message_id, input_tokens=5,
                output_tokens=3, cache_read=11, cache_creation=7,
                model="claude-sonnet-4-5-20250929", cwd=None):
    row = {
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
    }
    if cwd is not None:
        row["cwd"] = cwd
    return json.dumps(row) + "\n"


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


def codex_session_line(timestamp, cwd):
    return json.dumps({
        "timestamp": timestamp,
        "type": "session_meta",
        "payload": {"cwd": cwd},
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
    def test_resource_bounds_are_documented(self):
        self.assertIn("2020-01-01", tokens.__doc__)
        self.assertIn("512 distinct days", tokens.__doc__)
        self.assertIn("3000 account/day entries", tokens.__doc__)
        self.assertIn("50,000 files", tokens.__doc__)
        self.assertIn("24 MiB", tokens.__doc__)

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
                         day_counts(40, 20, 60,
                                    families={"gpt": 120}))
        self.assertEqual(parsed["days"]["2026-07-11"],
                         day_counts(40, 30, 40,
                                    families={"gpt": 110}))
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

        for model in ("gpt-5.6-sol", "o3-mini", "o4-mini", "codex-mini",
                      "unrecognized-preview"):
            with self.subTest(model=model):
                self.assertEqual(tokens._model_family(
                    model, provider="codex"), "gpt")

    def test_cwd_bucketing_is_single_segment_sanitized_and_absent_safe(self):
        rows = "".join([
            claude_line("2026-07-11T00:00:00Z", "r1", "m1",
                        cwd="/home/u/dispatch/nested/work"),
            claude_line("2026-07-11T00:01:00Z", "r2", "m2",
                        cwd="/home/u"),
            claude_line("2026-07-11T00:02:00Z", "r3", "m3",
                        cwd="/home/u/hostile@example/private"),
            claude_line("2026-07-11T00:03:00Z", "r4", "m4",
                        cwd="/home/u/" + "x" * 25 + "/private"),
            claude_line("2026-07-11T00:04:00Z", "r5", "m5"),
        ])
        with mock.patch.dict(os.environ, {"HOME": "/home/u"}):
            parsed = tokens._parse_stream(
                io.BytesIO(rows.encode()), "claude")
        self.assertEqual(parsed["days"]["2026-07-11"]["projects"], {
            "dispatch": 26, "~": 26, "other": 52})
        serialized = json.dumps(parsed)
        self.assertNotIn("/home/u", serialized)
        self.assertNotIn("hostile@example", serialized)

    def test_codex_session_meta_cwd_applies_to_later_token_counts(self):
        rows = (codex_session_line(
            "2026-07-11T00:00:00Z", "/home/u/headroom/feature")
            + codex_context_line("2026-07-11T00:00:01Z")
            + codex_line("2026-07-11T00:00:02Z", 100, 60, 20))
        with mock.patch.dict(os.environ, {"HOME": "/home/u"}):
            parsed = tokens._parse_stream(
                io.BytesIO(rows.encode()), "codex")
        self.assertEqual(parsed["days"]["2026-07-11"]["projects"], {
            "headroom": 120})
        self.assertEqual(parsed["last_project"], "headroom")

    def test_project_cap_folds_thirteenth_label_into_other(self):
        day = "2026-07-11"
        files = {"slot": {
            f"file-{index}": {"days": {day: day_counts(
                1, 0, projects={f"project-{index}": 1})}}
            for index in range(tokens.MAX_PROJECT_LABELS + 1)
        }}
        projects = tokens._daily_from_files(files)["slot"][day]["projects"]
        self.assertEqual(projects["other"], 1)
        self.assertEqual(sum(projects.values()), 13)
        self.assertEqual(len([label for label in projects if label != "other"]),
                         tokens.MAX_PROJECT_LABELS)

    def test_session_duration_uses_file_endpoints_with_clamp_and_cap(self):
        files = {"slot": {}}
        cases = (
            ("negative", "2026-07-10T01:00:00Z",
             "2026-07-10T00:00:00Z", 0),
            ("normal", "2026-07-11T00:00:00Z",
             "2026-07-11T01:30:00Z", 5400),
            ("capped", "2026-07-12T00:00:00Z",
             "2026-07-15T00:00:00Z", 48 * 60 * 60),
        )
        for name, first, last, _expected in cases:
            files["slot"][name] = {
                "days": {},
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

    def test_hostile_terminated_records_are_skipped_and_checkpointed(self):
        huge = claude_line(
            "2026-07-10T00:00:00Z", "huge", "huge",
            input_tokens=int("9" * 400))
        deep = (b'{"nested":' + b"[" * 2000 + b"0"
                + b"]" * 2000 + b"}\n")
        explosive = claude_line(
            "2026-07-10T00:00:01Z", "overflow", "overflow")
        generic = claude_line(
            "2026-07-10T00:00:02Z", "generic", "generic")
        valid = claude_line(
            "2026-07-10T00:00:03Z", "valid", "valid")
        payload = (huge.encode() + deep + explosive.encode()
                   + generic.encode() + valid.encode())
        original = tokens.parse_claude_record
        original_loads = tokens.json.loads

        def load(record):
            if '"nested"' in record:
                raise RecursionError("deep nesting fixture")
            return original_loads(record)

        def parse(record):
            if record.get("requestId") == "overflow":
                raise OverflowError("hostile fixture")
            if record.get("requestId") == "generic":
                raise RuntimeError("hostile fixture")
            return original(record)

        self.assertIsNone(tokens.parse_claude_record(huge))
        with mock.patch.object(tokens.json, "loads", side_effect=load), \
                mock.patch.object(tokens, "parse_claude_record",
                                  side_effect=parse):
            parsed = tokens._parse_stream(
                io.BytesIO(payload), "claude", now=NOW)
        self.assertEqual(parsed["offset"], len(payload))
        self.assertEqual(parsed["days"]["2026-07-10"]["grand_total"], 26)

    def test_handoff_marker_skips_copied_prefix_but_keeps_delta_context(self):
        marker = tokens.handoff_marker_line().decode()
        claude = tokens._parse_stream(io.BytesIO((
            claude_line("2026-07-10T00:00:00Z", "r1", "m1") + marker
            + claude_line("2026-07-10T00:00:01Z", "r1", "m1",
                          output_tokens=10)).encode()), "claude")
        self.assertEqual(claude["days"]["2026-07-10"], day_counts(
            0, 7, families={"sonnet": 7}))

        codex = tokens._parse_stream(io.BytesIO((
            codex_context_line("2026-07-10T00:00:00Z")
            + codex_line("2026-07-10T00:00:01Z", 100, 60, 20)
            + marker
            + codex_line("2026-07-10T00:00:02Z", 180, 100, 50)
        ).encode()), "codex")
        self.assertEqual(codex["days"]["2026-07-10"], day_counts(
            40, 30, 40, families={"gpt": 110}, efforts={"xhigh": 110}))

    def test_bounded_reader_drains_giant_line_and_dedupe_tail_is_capped(self):
        rows = [claude_line("2026-07-10T00:00:00Z", f"r{i}", f"m{i}")
                for i in range(tokens.DEDUPE_TAIL_RECORDS + 8)]
        sizes = []
        class TrackingIO(io.BytesIO):
            def readline(self, size=-1):
                sizes.append(size)
                return super().readline(size)

        stream = TrackingIO(
            b"x" * (tokens.MAX_LINE_BYTES + 128 * 1024) + b"\n"
            + "".join(rows).encode()
            + rows[0].encode())
        parsed = tokens._parse_stream(stream, "claude")
        self.assertEqual(len(parsed["dedupe_tail"]),
                         tokens.DEDUPE_TAIL_RECORDS)
        self.assertLessEqual(max(sizes), tokens.MAX_LINE_BYTES + 1)
        expected_records = tokens.DEDUPE_TAIL_RECORDS + 9
        self.assertEqual(parsed["days"]["2026-07-10"]["grand_total"],
                         expected_records * 26)

    def test_completed_malformed_and_oversized_records_advance_checkpoint(self):
        malformed = b"{broken}\n"
        oversized = b"x" * (tokens.MAX_LINE_BYTES + 100) + b"\n"
        prefix = malformed + oversized
        initial = tokens._parse_stream(
            io.BytesIO(prefix), "claude", now=NOW)
        self.assertEqual(initial["offset"], len(prefix))
        self.assertEqual(initial["days"], {})

        valid = claude_line("2026-07-10T00:00:00Z", "r", "m").encode()
        resumed = tokens._parse_stream(
            io.BytesIO(prefix + valid), "claude", start=initial["offset"],
            previous=initial, now=NOW)
        self.assertEqual(resumed["offset"], len(prefix + valid))
        self.assertEqual(resumed["days"]["2026-07-10"]["grand_total"], 26)

    def test_day_bounds_and_per_file_cardinality_cap(self):
        scan_day = datetime.date(2026, 1, 1)
        scan_now = int(datetime.datetime(
            2026, 1, 1, tzinfo=datetime.timezone.utc).timestamp())
        rows = [
            claude_line("2019-12-31T23:59:59Z", "old", "old"),
            claude_line("2020-01-01T00:00:00Z", "floor", "floor"),
            claude_line("2026-01-03T23:59:59Z", "edge", "edge"),
            claude_line("2026-01-04T00:00:00Z", "future", "future"),
        ]
        bounded = tokens._parse_stream(
            io.BytesIO("".join(rows).encode()), "claude", now=scan_now)
        self.assertEqual(set(bounded["days"]), {"2020-01-01", "2026-01-03"})
        self.assertEqual(bounded["offset"], len("".join(rows).encode()))

        first = datetime.date(2020, 1, 1)
        many = "".join(claude_line(
            (first + datetime.timedelta(days=index)).isoformat() + "T00:00:00Z",
            f"r{index}", f"m{index}")
            for index in range(tokens.MAX_FILE_DAYS + 1))
        capped = tokens._parse_stream(
            io.BytesIO(many.encode()), "claude",
            now=int(datetime.datetime.combine(
                scan_day, datetime.time(),
                tzinfo=datetime.timezone.utc).timestamp()))
        self.assertEqual(len(capped["days"]), tokens.MAX_FILE_DAYS)
        self.assertTrue(capped["partial"])

    def test_codex_context_survives_checkpoint_without_a_token_event(self):
        first = codex_context_line(
            "2026-07-10T00:00:00Z", model="gpt-5.6-sol", effort="high")
        initial = tokens._parse_stream(io.BytesIO(first.encode()), "codex")
        combined = first + codex_line(
            "2026-07-10T00:00:01Z", 100, 60, 20)
        resumed = tokens._parse_stream(
            io.BytesIO(combined.encode()), "codex", start=initial["offset"],
            previous=initial)
        self.assertEqual(initial["last_family"], "gpt")
        self.assertEqual(initial["last_effort"], "high")
        self.assertEqual(resumed["days"]["2026-07-10"]["families"],
                         {"gpt": 120})
        self.assertEqual(resumed["days"]["2026-07-10"]["efforts"],
                         {"high": 120})


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

    def state_entry(self, name):
        state = paths.load_json(paths.token_scan_state_path())
        return state["files"][self.account["id"]][
            "projects/project/" + name]

    def add_extra_root(self, label, provider, home):
        self.config["dashboard"]["token_extra_roots"] = [{
            "label": label, "provider": provider, "path": home,
        }]
        registry.save(self.config)
        return registry.virtual_slot_id(label, provider, home)

    def test_extra_claude_root_scans_aggregates_and_enters_ranking(self):
        extra_home = os.path.join(self.temp.name, "interactive-claude")
        extra_project = os.path.join(extra_home, "projects", "interactive")
        os.makedirs(extra_project)
        scan_day = datetime.datetime.fromtimestamp(
            NOW, datetime.timezone.utc).date().isoformat()
        with open(os.path.join(extra_project, "session.jsonl"), "w",
                  encoding="utf-8") as handle:
            handle.write(claude_line(
                scan_day + "T00:00:00Z", "extra-r", "extra-m"))
        virtual_id = self.add_extra_root(
            "Primary CLI home", "claude", extra_home)

        self.assertTrue(tokens.collect(now=NOW, force=True))
        state = paths.load_json(paths.token_scan_state_path())
        self.assertIn(virtual_id, state["files"])
        payload = dashboard.display_snapshot(
            usage_snapshot(self.account["id"]), evaluated_at=NOW,
            config=self.config)["token_stats"]
        rows = {row["id"]: row for row in payload["accounts"]}
        self.assertEqual(rows[virtual_id]["name"], "Primary CLI home")
        self.assertEqual(rows[virtual_id]["provider"], "claude")
        self.assertEqual(rows[virtual_id]["lifetime_grand_total"], 26)
        self.assertEqual(rows[virtual_id]["projects"], [])
        self.assertEqual(payload["days"][scan_day]["grand_total"], 26)
        ranked = sorted(payload["accounts"], key=lambda row: (
            -row["lifetime_grand_total"], -row["last7d_grand_total"],
            row["name"], row["id"]))
        self.assertEqual(ranked[0]["id"], virtual_id)

    def test_extra_codex_root_uses_rollout_discovery(self):
        extra_home = os.path.join(self.temp.name, "interactive-codex")
        sessions = os.path.join(extra_home, "sessions", "2026", "07")
        os.makedirs(sessions)
        with open(os.path.join(sessions, "rollout-extra.jsonl"), "w",
                  encoding="utf-8") as handle:
            handle.write(codex_line(
                "2026-07-10T00:00:00Z", 20, 5, 10))
        virtual_id = self.add_extra_root(
            "Codex interactive", "codex", extra_home)

        tokens.collect(now=NOW, force=True)
        daily = paths.load_json(paths.token_daily_path())
        self.assertEqual(daily["accounts"][virtual_id]["2026-07-10"][
            "grand_total"], 30)

    def test_extra_root_stamps_new_files_and_keeps_stamps_across_identity_flip(self):
        self.account["expected_email"] = "alpha@example.test"
        beta_home = os.path.join(self.temp.name, "beta-home")
        os.makedirs(os.path.join(beta_home, "projects"))
        beta = {
            "id": slot_id("beta"), "name": "beta", "provider": "claude",
            "home": beta_home, "expected_email": "beta@example.test",
        }
        self.config["accounts"].append(beta)
        extra_home = os.path.join(self.temp.name, "workstation")
        extra_project = os.path.join(extra_home, "projects", "pooled")
        os.makedirs(extra_project)
        first_path = os.path.join(extra_project, "first.jsonl")
        with open(first_path, "w", encoding="utf-8") as handle:
            handle.write(claude_line(
                "2026-07-10T00:00:00Z", "first-r", "first-m",
                cwd="/home/operator/headroom/private"))
        virtual_id = self.add_extra_root("server-cli", "claude", extra_home)

        with mock.patch.dict(os.environ, {"HOME": "/home/operator"}), \
                mock.patch.object(usage_collect, "claude_identity", return_value={
                    "verified": True, "email": "alpha@example.test"}):
            tokens.collect(now=NOW, force=True)
        first_state = paths.load_json(paths.token_scan_state_path())
        first_entry = first_state["files"][virtual_id][
            "projects/pooled/first.jsonl"]
        self.assertEqual(first_entry["attributed_slot"], "alpha")

        with open(os.path.join(extra_project, "second.jsonl"), "w",
                  encoding="utf-8") as handle:
            handle.write(claude_line(
                "2026-07-10T00:01:00Z", "second-r", "second-m",
                cwd="/home/operator/dispatch/nested"))
        with mock.patch.dict(os.environ, {"HOME": "/home/operator"}), \
                mock.patch.object(usage_collect, "claude_identity", return_value={
                    "verified": True, "email": "beta@example.test"}):
            tokens.collect(now=NOW + 1, force=True)

        state = paths.load_json(paths.token_scan_state_path())
        entries = state["files"][virtual_id]
        self.assertEqual(entries["projects/pooled/first.jsonl"][
            "attributed_slot"], "alpha")
        self.assertEqual(entries["projects/pooled/second.jsonl"][
            "attributed_slot"], "beta")
        daily = paths.load_json(paths.token_daily_path())
        day = daily["accounts"][virtual_id]["2026-07-10"]
        self.assertEqual(day["attributed"], {"alpha": 26, "beta": 26})
        self.assertEqual(day["projects"], {"headroom": 26, "dispatch": 26})

        payload = dashboard.display_snapshot(
            usage_snapshot(self.account["id"]), evaluated_at=NOW + 1,
            config=self.config)["token_stats"]
        rows = {row["id"]: row for row in payload["accounts"]}
        self.assertEqual(rows[virtual_id]["attributed_breakdown"], [
            {"name": "alpha", "grand_total": 26},
            {"name": "beta", "grand_total": 26},
        ])
        self.assertNotIn("attributed_breakdown", rows[self.account["id"]])
        self.assertNotIn("attributed_breakdown", rows[beta["id"]])
        self.assertEqual(rows[virtual_id]["projects"][0]["grand_total"], 26)
        self.assertEqual(len(payload["summary"]["projects"]), 2)
        serialized = json.dumps({
            "state": state, "daily": daily, "payload": payload})
        for secret in ("/home/operator", "alpha@example.test",
                       "beta@example.test"):
            self.assertNotIn(secret, serialized)

    def test_schema_six_sessions_migrate_to_earlier_and_reparse_cwd(self):
        self.account["expected_email"] = "alpha@example.test"
        extra_home = os.path.join(self.temp.name, "legacy-workstation")
        extra_project = os.path.join(extra_home, "projects", "pooled")
        os.makedirs(extra_project)
        with open(os.path.join(extra_project, "legacy.jsonl"), "w",
                  encoding="utf-8") as handle:
            handle.write(claude_line(
                "2026-07-10T00:00:00Z", "legacy-r", "legacy-m",
                cwd="/home/operator/headroom/nested"))
        virtual_id = self.add_extra_root("server-cli", "claude", extra_home)
        identity = {"verified": True, "email": "alpha@example.test"}
        with mock.patch.dict(os.environ, {"HOME": "/home/operator"}), \
                mock.patch.object(usage_collect, "claude_identity",
                                  return_value=identity):
            tokens.collect(now=NOW, force=True)

        state = paths.load_json(paths.token_scan_state_path())
        state["schema_version"] = tokens.PREVIOUS_SCHEMA_VERSION
        legacy = state["files"][virtual_id]["projects/pooled/legacy.jsonl"]
        legacy.pop("attributed_slot")
        legacy.pop("project_schema")
        legacy["days"]["2026-07-10"].pop("projects")
        paths.write_json_atomic(paths.token_scan_state_path(), state)
        daily = paths.load_json(paths.token_daily_path())
        daily["schema_version"] = tokens.PREVIOUS_SCHEMA_VERSION
        paths.write_json_atomic(paths.token_daily_path(), daily)

        with mock.patch.dict(os.environ, {"HOME": "/home/operator"}), \
                mock.patch.object(usage_collect, "claude_identity",
                                  return_value=identity):
            self.assertTrue(tokens.collect(now=NOW + 1))
        migrated_state = paths.load_json(paths.token_scan_state_path())
        migrated = migrated_state["files"][virtual_id][
            "projects/pooled/legacy.jsonl"]
        self.assertEqual(migrated["attributed_slot"], "earlier")
        self.assertEqual(migrated["project_schema"],
                         tokens.PROJECT_SCHEMA_VERSION)
        migrated_day = paths.load_json(paths.token_daily_path())[
            "accounts"][virtual_id]["2026-07-10"]
        self.assertEqual(migrated_day["projects"], {"headroom": 26})
        self.assertEqual(migrated_day["attributed"], {"earlier": 26})

    def test_extra_root_removal_hides_immediately_then_lazy_prunes_state(self):
        extra_home = os.path.join(self.temp.name, "removable")
        project = os.path.join(extra_home, "projects", "p")
        os.makedirs(project)
        with open(os.path.join(project, "session.jsonl"), "w",
                  encoding="utf-8") as handle:
            handle.write(claude_line(
                "2026-07-10T00:00:00Z", "remove-r", "remove-m"))
        virtual_id = self.add_extra_root("Removable home", "claude", extra_home)
        tokens.collect(now=NOW, force=True)
        self.assertIn(virtual_id, paths.load_json(
            paths.token_scan_state_path())["files"])

        self.config["dashboard"]["token_extra_roots"] = []
        registry.save(self.config)
        payload = dashboard.display_snapshot(
            usage_snapshot(self.account["id"]), evaluated_at=NOW,
            config=self.config)["token_stats"]
        self.assertNotIn(virtual_id, {
            row["id"] for row in payload["accounts"]})
        self.assertIn(virtual_id, paths.load_json(
            paths.token_scan_state_path())["files"])

        tokens.collect(now=NOW + 1, force=True)
        self.assertNotIn(virtual_id, paths.load_json(
            paths.token_scan_state_path())["files"])
        self.assertNotIn(virtual_id, paths.load_json(
            paths.token_daily_path())["accounts"])

    def test_extra_root_rebinding_gets_fresh_id_and_prunes_old_state(self):
        first_home = os.path.join(self.temp.name, "first-extra")
        second_home = os.path.join(self.temp.name, "second-extra")
        for home, request in ((first_home, "first"), (second_home, "second")):
            project = os.path.join(home, "projects", "p")
            os.makedirs(project)
            with open(os.path.join(project, "session.jsonl"), "w",
                      encoding="utf-8") as handle:
                handle.write(claude_line(
                    "2026-07-10T00:00:00Z", request, request))

        old_id = self.add_extra_root("Rebound home", "claude", first_home)
        tokens.collect(now=NOW, force=True)
        new_id = self.add_extra_root("Rebound home", "claude", second_home)
        self.assertNotEqual(new_id, old_id)

        tokens.collect(now=NOW + 1, force=True)
        state = paths.load_json(paths.token_scan_state_path())
        daily = paths.load_json(paths.token_daily_path())
        self.assertNotIn(old_id, state["files"])
        self.assertNotIn(old_id, daily["accounts"])
        self.assertIn(new_id, state["files"])
        self.assertIn(new_id, daily["accounts"])

    def test_extra_root_containment_skips_symlinked_subdirectories(self):
        extra_home = os.path.join(self.temp.name, "contained")
        project = os.path.join(extra_home, "projects", "p")
        outside = os.path.join(self.temp.name, "outside")
        os.makedirs(project)
        os.makedirs(outside)
        with open(os.path.join(project, "inside.jsonl"), "w",
                  encoding="utf-8") as handle:
            handle.write(claude_line(
                "2026-07-10T00:00:00Z", "inside-r", "inside-m"))
        with open(os.path.join(outside, "escaped.jsonl"), "w",
                  encoding="utf-8") as handle:
            handle.write(claude_line(
                "2026-07-10T00:00:00Z", "outside-r", "outside-m"))
        os.symlink(outside, os.path.join(project, "escape"))
        virtual_id = self.add_extra_root("Contained home", "claude", extra_home)

        tokens.collect(now=NOW, force=True)
        files = paths.load_json(paths.token_scan_state_path())[
            "files"][virtual_id]
        self.assertEqual(set(files), {"projects/p/inside.jsonl"})

    def test_invalid_extra_path_marks_scan_and_payload_partial(self):
        missing = os.path.join(self.temp.name, "missing")
        virtual_id = self.add_extra_root("Missing home", "claude", missing)
        accounts, roots_partial = registry.token_accounts(
            self.config, include_status=True)
        self.assertTrue(roots_partial)
        self.assertNotIn(virtual_id, {account["id"] for account in accounts})

        tokens.collect(now=NOW, force=True)
        state = paths.load_json(paths.token_scan_state_path())
        daily = paths.load_json(paths.token_daily_path())
        self.assertTrue(state["extra_roots_partial"])
        self.assertTrue(daily["partial"])
        payload = dashboard.display_snapshot(
            usage_snapshot(self.account["id"]), evaluated_at=NOW,
            config=self.config)["token_stats"]
        self.assertTrue(payload["partial"])

    def test_registry_and_extra_roots_share_global_file_budget(self):
        self.write("registry.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "registry-r", "registry-m"))
        extra_home = os.path.join(self.temp.name, "budget-extra")
        project = os.path.join(extra_home, "projects", "p")
        os.makedirs(project)
        with open(os.path.join(project, "extra.jsonl"), "w",
                  encoding="utf-8") as handle:
            handle.write(claude_line(
                "2026-07-10T00:00:00Z", "extra-r", "extra-m"))
        self.add_extra_root("Budget home", "claude", extra_home)

        with mock.patch.object(tokens, "MAX_TRACKED_FILES", 1), \
                mock.patch.object(tokens, "MAX_SERIALIZED_STATE_BYTES",
                                  10 * 1024 * 1024):
            tokens.collect(now=NOW, force=True)
        state = paths.load_json(paths.token_scan_state_path())
        self.assertEqual(sum(len(files) for files in state["files"].values()), 1)
        self.assertEqual(sum(state["budget_dropped_files"].values()), 1)
        self.assertTrue(paths.load_json(paths.token_daily_path())["partial"])

    def test_incremental_grown_new_and_unchanged_files(self):
        first = self.write(
            "one.jsonl", "{}\n" * 1500 + claude_line(
                "2026-07-10T00:00:00Z", "r1", "m1"))
        self.assertTrue(tokens.collect(
            [self.account], config=self.config, now=NOW, force=True))
        first_size = os.path.getsize(first)
        with mock.patch.object(tokens, "_parse_stream",
                               wraps=tokens._parse_stream) as parse_stream:
            with mock.patch.object(os, "open", wraps=os.open) as opened:
                self.assertTrue(tokens.collect(
                    [self.account], config=self.config, now=NOW + 1,
                    force=True))
        parse_stream.assert_not_called()
        source = os.path.abspath(first)
        self.assertFalse(any(os.path.abspath(str(call.args[0])) == source
                             for call in opened.call_args_list))

        self.write("one.jsonl", claude_line(
            "2026-07-11T00:00:00Z", "r2", "m2"), mode="a")
        self.write("two.jsonl", claude_line(
            "2026-07-11T01:00:00Z", "r3", "m3",
            input_tokens=1, output_tokens=1, cache_read=1,
            cache_creation=1))
        starts = []
        original = tokens._parse_stream

        def track(handle, provider, start=0, previous=None, end=None, now=None):
            starts.append(start)
            return original(handle, provider, start=start, previous=previous,
                            end=end, now=now)

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
        self.assertEqual(stat.S_IMODE(os.stat(
            paths.token_scan_state_path()).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(
            paths.token_scan_lock_path()).st_mode), 0o600)
        state = paths.load_json(paths.token_scan_state_path())
        self.assertEqual(list(state["files"]), [self.account["id"]])
        self.assertEqual(set(state["files"][self.account["id"]]), {
            "projects/project/one.jsonl", "projects/project/two.jsonl"})
        self.assertNotIn(self.home, json.dumps(state))

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
            paths.token_scan_state_path())["schema_version"],
                         tokens.SCHEMA_VERSION)
        self.assertEqual(paths.load_json(
            paths.token_daily_path())["schema_version"],
                         tokens.SCHEMA_VERSION)

    def test_disabled_gate_does_not_scan_or_touch_token_state(self):
        disabled = dict(self.config)
        disabled["dashboard"] = {"token_stats": False}
        registry.save(disabled)
        with mock.patch.object(
                tokens, "_files", side_effect=AssertionError("scanned")):
            self.assertFalse(tokens.collect(
                [self.account], config=disabled, now=NOW, force=True))
        self.assertTrue(os.path.exists(paths.token_scan_lock_path()))
        self.assertFalse(os.path.exists(paths.token_daily_path()))
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

    def test_unterminated_eof_fragment_is_re_read_after_completion(self):
        prefix = "{}\n" * 1500 + claude_line(
            "2026-07-10T00:00:00Z", "r1", "m1")
        second = claude_line(
            "2026-07-10T00:00:01Z", "r2", "m2",
            input_tokens=2, output_tokens=4, cache_read=6,
            cache_creation=8)
        path = self.write("fragment.jsonl", prefix + second[:120])
        tokens.collect([self.account], config=self.config, now=NOW, force=True)
        first = self.state_entry("fragment.jsonl")
        self.assertEqual(first["offset"], len(prefix.encode()))
        self.assertLess(first["offset"], first["size"])
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(second[120:])
        tokens.collect(
            [self.account], config=self.config, now=NOW + 1, force=True)
        final = self.state_entry("fragment.jsonl")
        self.assertEqual(final["offset"], final["size"])
        daily = paths.load_json(paths.token_daily_path())[
            "accounts"][self.account["id"]]["2026-07-10"]
        self.assertEqual(daily, day_counts(
            7, 7, 17, 15, session_count=1, longest_session_s=1,
            families={"sonnet": 46}))

    def test_append_after_initial_fstat_is_deferred_to_next_scan(self):
        stable = "{}\n" * 1500
        first_line = claude_line("2026-07-10T00:00:00Z", "r1", "m1")
        second_line = claude_line("2026-07-10T00:00:01Z", "r2", "m2")
        path = self.write("race.jsonl", stable + first_line)
        os.utime(path, ns=(1_700_000_000_000_000_000,
                           1_700_000_000_000_000_000))
        bound_size = os.path.getsize(path)
        bound_mtime = os.stat(path).st_mtime_ns
        original = tokens._parse_stream
        appended = False

        def append_during_read(handle, provider, start=0, previous=None,
                               end=None, now=None):
            nonlocal appended
            if not appended:
                appended = True
                with open(path, "a", encoding="utf-8") as writer:
                    writer.write(second_line)
            return original(handle, provider, start=start, previous=previous,
                            end=end, now=now)

        with mock.patch.object(tokens, "_parse_stream",
                               side_effect=append_during_read):
            tokens.collect(
                [self.account], config=self.config, now=NOW, force=True)
        entry = self.state_entry("race.jsonl")
        self.assertEqual(entry["size"], bound_size)
        self.assertEqual(entry["offset"], bound_size)
        self.assertEqual(entry["mtime_ns"], bound_mtime)
        self.assertNotEqual(entry["mtime_ns"], os.stat(path).st_mtime_ns)
        first_daily = paths.load_json(paths.token_daily_path())[
            "accounts"][self.account["id"]]["2026-07-10"]
        self.assertEqual(first_daily["grand_total"], 26)
        tokens.collect(
            [self.account], config=self.config, now=NOW + 1, force=True)
        final_daily = paths.load_json(paths.token_daily_path())[
            "accounts"][self.account["id"]]["2026-07-10"]
        self.assertEqual(final_daily["grand_total"], 52)

    def test_rotation_or_fingerprint_change_replaces_file_contribution(self):
        path = self.write("rotate.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "r1", "m1"))
        tokens.collect([self.account], config=self.config, now=NOW, force=True)
        before = self.state_entry("rotate.jsonl")
        replacement = os.path.join(self.project, "replacement.jsonl")
        with open(replacement, "w", encoding="utf-8") as handle:
            handle.write(claude_line(
                "2026-07-11T00:00:00Z", "r2", "m2",
                input_tokens=1, output_tokens=1, cache_read=1,
                cache_creation=1))
        os.replace(replacement, path)
        tokens.collect(
            [self.account], config=self.config, now=NOW + 1, force=True)
        after = self.state_entry("rotate.jsonl")
        self.assertNotEqual(before["st_ino"], after["st_ino"])
        self.assertNotEqual(before["fingerprint"], after["fingerprint"])
        days = paths.load_json(paths.token_daily_path())[
            "accounts"][self.account["id"]]
        self.assertNotIn("2026-07-10", days)
        self.assertEqual(days["2026-07-11"], day_counts(
            1, 1, 1, 1, session_count=1,
            families={"sonnet": 4}))

    def test_same_inode_copy_truncate_checkpoint_mismatch_full_rescans(self):
        prefix = "{}\n" * 1500
        path = self.write("rewrite.jsonl", prefix + claude_line(
            "2026-07-10T00:00:00Z", "old", "old"))
        tokens.collect(now=NOW, force=True)
        before = self.state_entry("rewrite.jsonl")
        inode = os.stat(path).st_ino

        replacement = prefix + claude_line(
            "2026-07-11T00:00:00Z", "new", "new")
        self.assertEqual(len(replacement.encode()), before["size"])
        with open(path, "r+", encoding="utf-8") as handle:
            handle.seek(0)
            handle.write(replacement)
            handle.truncate()
        os.utime(path, ns=(before["mtime_ns"] + 1_000_000,
                           before["mtime_ns"] + 1_000_000))
        tokens.collect(now=NOW + 1, force=True)

        after = self.state_entry("rewrite.jsonl")
        self.assertEqual(os.stat(path).st_ino, inode)
        self.assertEqual(after["fingerprint"], before["fingerprint"])
        self.assertNotEqual(after["checkpoint_hash"],
                            before["checkpoint_hash"])
        days = paths.load_json(paths.token_daily_path())["accounts"][
            self.account["id"]]
        self.assertNotIn("2026-07-10", days)
        self.assertEqual(days["2026-07-11"]["grand_total"], 26)

    def test_symlinked_directory_escape_is_not_walked_or_opened(self):
        outside = os.path.join(self.temp.name, "outside")
        os.makedirs(outside)
        with open(os.path.join(outside, "escape.jsonl"), "w",
                  encoding="utf-8") as handle:
            handle.write(claude_line(
                "2026-07-10T00:00:00Z", "outside", "outside"))
        os.symlink(outside, os.path.join(self.project, "escape"))
        self.assertNotIn("projects/project/escape/escape.jsonl",
                         list(tokens._files(self.account)))
        with self.assertRaisesRegex(OSError, "escapes account home"):
            tokens._scan_file(
                self.home, "projects/project/escape/escape.jsonl", "claude")

    def test_failed_file_is_retained_and_payload_is_partial(self):
        self.write("good.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "r1", "m1"))
        self.write("bad.jsonl", claude_line(
            "2026-07-10T00:00:01Z", "r2", "m2"))
        original = tokens._scan_file

        def fail_bad(home, relative_path, provider, previous=None, now=None):
            if relative_path.endswith("bad.jsonl"):
                raise OSError("fixture")
            return original(home, relative_path, provider, previous, now=now)

        with mock.patch.object(tokens, "_scan_file", side_effect=fail_bad):
            tokens.collect(
                [self.account], config=self.config, now=NOW, force=True)
        state = paths.load_json(paths.token_scan_state_path())
        bad = state["files"][self.account["id"]][
            "projects/project/bad.jsonl"]
        self.assertEqual(bad["last_error"], "OSError")
        store = paths.load_json(paths.token_daily_path())
        self.assertTrue(store["partial"])
        self.assertEqual(store["failed_file_count"], 1)
        summary = tokens.summarize(store, [self.account], now=NOW)
        self.assertTrue(summary["partial"])
        self.assertEqual(summary["failed_file_count"], 1)

    def test_failed_root_retains_unseen_paths_until_authoritative_walk(self):
        first = self.write("one.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "r1", "m1"))
        second = self.write("two.jsonl", claude_line(
            "2026-07-11T00:00:00Z", "r2", "m2"))
        tokens.collect(now=NOW, force=True)
        before = paths.load_json(paths.token_daily_path())["accounts"]

        projects = os.path.join(self.home, "projects")
        hidden = os.path.join(self.home, "projects-hidden")
        os.rename(projects, hidden)
        tokens.collect(now=NOW + 1, force=True)
        failed = paths.load_json(paths.token_daily_path())
        self.assertTrue(failed["partial"])
        self.assertEqual(failed["failed_root_count"], 1)
        self.assertEqual(failed["accounts"], before)
        self.assertEqual(len(paths.load_json(
            paths.token_scan_state_path())["files"][self.account["id"]]), 2)

        os.unlink(os.path.join(hidden, "project", os.path.basename(second)))
        os.rename(hidden, projects)
        tokens.collect(now=NOW + 2, force=True)
        recovered = paths.load_json(paths.token_scan_state_path())[
            "files"][self.account["id"]]
        self.assertEqual(set(recovered), {"projects/project/one.jsonl"})
        self.assertTrue(os.path.exists(first))

    def test_rename_during_walk_error_drops_retained_inode_alias(self):
        old_path = self.write("old.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "r1", "m1"))
        tokens.collect(now=NOW, force=True)
        new_path = os.path.join(self.project, "new.jsonl")
        os.rename(old_path, new_path)
        new_relative = "projects/project/new.jsonl"

        def interrupted_walk(_account, errors=None):
            yield new_relative
            errors.append(OSError("walk interrupted"))

        with mock.patch.object(tokens, "_files", side_effect=interrupted_walk):
            tokens.collect(now=NOW + 1, force=True)
        state = paths.load_json(paths.token_scan_state_path())
        self.assertEqual(list(state["files"][self.account["id"]]),
                         [new_relative])
        daily = paths.load_json(paths.token_daily_path())
        self.assertEqual(daily["accounts"][self.account["id"]][
            "2026-07-10"]["grand_total"], 26)
        self.assertTrue(daily["partial"])
        self.assertEqual(daily["failed_root_slot_ids"], [self.account["id"]])

    def test_aggregation_dedupes_file_identity_first_path_wins(self):
        files = {self.account["id"]: {
            "first": {"st_dev": 7, "st_ino": 9,
                      "days": {"2026-07-10": day_counts(2, 3)}},
            "second": {"st_dev": 7, "st_ino": 9,
                       "days": {"2026-07-10": day_counts(90, 10)}},
        }}
        daily, partial = tokens._daily_from_files(files, include_status=True)
        self.assertTrue(partial)
        self.assertEqual(daily[self.account["id"]]["2026-07-10"],
                         day_counts(2, 3, families={"other": 5}))
        self.assertTrue(files[self.account["id"]]["second"][
            "duplicate_identity"])

    def test_symlinked_provider_root_is_rejected_and_marked_partial(self):
        self.write("one.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "r1", "m1"))
        projects = os.path.join(self.home, "projects")
        real_projects = os.path.join(self.home, "projects-real")
        os.rename(projects, real_projects)
        os.symlink(real_projects, projects)
        with self.assertRaisesRegex(OSError, "symlinked token provider root"):
            list(tokens._files(self.account))
        tokens.collect(now=NOW, force=True)
        daily = paths.load_json(paths.token_daily_path())
        self.assertTrue(daily["partial"])
        self.assertEqual(daily["failed_root_count"], 1)
        self.assertEqual(daily["accounts"], {})

    def test_file_and_global_day_caps_mark_partial_without_growth(self):
        first = datetime.date(2020, 1, 1)
        rows = "".join(claude_line(
            (first + datetime.timedelta(days=index)).isoformat() + "T00:00:00Z",
            f"r{index}", f"m{index}")
            for index in range(tokens.MAX_FILE_DAYS + 1))
        self.write("many.jsonl", rows)
        tokens.collect(now=NOW, force=True)
        entry = self.state_entry("many.jsonl")
        daily = paths.load_json(paths.token_daily_path())
        self.assertEqual(len(entry["days"]), tokens.MAX_FILE_DAYS)
        self.assertTrue(entry["partial"])
        self.assertTrue(daily["partial"])
        self.assertEqual(daily["partial_file_count"], 1)

        day_map = {
            (first + datetime.timedelta(days=index)).isoformat():
            day_counts(1, 1)
            for index in range(tokens.MAX_FILE_DAYS)
        }
        files = {f"slot-{slot}": {
            "log": {"provider": "claude", "days": dict(day_map)}}
            for slot in range(6)}
        accounts, partial = tokens._daily_from_files(
            files, include_status=True)
        self.assertTrue(partial)
        self.assertEqual(sum(len(days) for days in accounts.values()),
                         tokens.MAX_GLOBAL_DAYS)
        self.assertTrue(any(entry.get("partial") is True
                            for slot_files in files.values()
                            for entry in slot_files.values()))

    def test_state_budget_folding_preserves_aggregate_exactly(self):
        first = int(datetime.datetime(
            2026, 7, 10, tzinfo=datetime.timezone.utc).timestamp())
        entry = {
            "provider": "claude", "size": 5000, "mtime_ns": 0,
            "st_dev": 1, "st_ino": 2, "offset": 5000,
            "days": {
                "2026-07-10": day_counts(
                    10, 5, 3, 2, families={"sonnet": 20}),
                "2026-07-11": day_counts(
                    7, 4, families={"sonnet": 11}),
            },
            "first_event_ts": first, "last_event_ts": first + 3600,
            "dedupe_tail": [{"signature": "a" * 64,
                             "maximum": counts(1, 1, 1, 1)}
                            for _ in range(20)],
            "fingerprint": "f" * 64, "checkpoint_hash": "c" * 64,
        }
        state = {
            "schema_version": tokens.SCHEMA_VERSION,
            "files": {self.account["id"]: {"cold": entry}},
            "folded_changed_files": {},
        }
        expected_days = tokens._entry_days(entry)[0]
        expected_state = {
            "schema_version": tokens.SCHEMA_VERSION,
            "files": {self.account["id"]: {"cold": {
                "size": 5000, "mtime_ns": 0, "st_dev": 1, "st_ino": 2,
                "days": expected_days, "folded": True,
            }}},
            "folded_changed_files": {}, "compacted_file_count": 1,
            "budget_dropped_files": {}, "budget_partial": False,
        }
        budget = tokens._serialized_state_size(expected_state) + 1
        before = tokens._daily_from_files(state["files"])
        with mock.patch.object(tokens, "MAX_TRACKED_FILES", 10), \
                mock.patch.object(tokens, "MAX_SERIALIZED_STATE_BYTES", budget):
            compacted, dropped = tokens._enforce_state_budgets(state, NOW)
        after = tokens._daily_from_files(state["files"])

        self.assertEqual((compacted, dropped), (1, 0))
        self.assertEqual(after, before)
        self.assertEqual(state["files"][self.account["id"]]["cold"], {
            "size": 5000, "mtime_ns": 0, "st_dev": 1, "st_ino": 2,
            "days": expected_days, "folded": True})
        self.assertFalse(state["budget_partial"])
        self.assertLessEqual(tokens._serialized_state_size(state), budget)

    def test_folded_unchanged_file_skips_open_and_parse(self):
        path = self.write("cold.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "cold-r", "cold-m"))
        current = os.stat(path)
        sentinel = {
            "size": current.st_size,
            "mtime_ns": current.st_mtime_ns,
            "folded": True,
        }
        with mock.patch.object(
                tokens, "_open_contained",
                side_effect=AssertionError("opened folded file")), \
                mock.patch.object(
                    tokens, "_parse_stream",
                    side_effect=AssertionError("parsed folded file")):
            scanned = tokens._scan_file(
                self.home, "projects/project/cold.jsonl", "claude", sentinel,
                now=NOW)
        self.assertEqual(scanned, sentinel)

    def test_state_budget_measures_folding_in_batches(self):
        slot = self.account["id"]
        files = {
            f"cold-{index}": {
                "provider": "claude", "size": 100 + index,
                "mtime_ns": 0 if index < 150 else NOW * 1_000_000_000,
                "st_dev": 1, "st_ino": index,
                "days": {
                    "2026-07-10": day_counts(
                        1, 1, families={"other": 2})},
            }
            for index in range(300)
        }
        state = {
            "schema_version": tokens.SCHEMA_VERSION,
            "files": {slot: files},
            "folded_changed_files": {},
        }
        expected = {
            "schema_version": tokens.SCHEMA_VERSION,
            "files": {slot: {
                path: {"size": entry["size"],
                       "mtime_ns": entry["mtime_ns"],
                       "st_dev": entry["st_dev"],
                       "st_ino": entry["st_ino"],
                       "days": entry["days"],
                       "folded": True}
                for path, entry in files.items()
            }},
            "folded_changed_files": {},
            "compacted_file_count": 0,
            "budget_dropped_files": {},
            "budget_partial": False,
        }
        budget = tokens._serialized_state_size(expected) + 1
        original_size = tokens._serialized_state_size
        with mock.patch.object(tokens, "MAX_TRACKED_FILES", 1000), \
                mock.patch.object(tokens, "MAX_SERIALIZED_STATE_BYTES", budget), \
                mock.patch.object(
                    tokens, "_serialized_state_size",
                    wraps=original_size) as serialized:
            _compacted, dropped = tokens._enforce_state_budgets(state, NOW)

        self.assertEqual(dropped, 0)
        self.assertEqual(state, expected)
        self.assertLessEqual(serialized.call_count, 6)

    def test_folded_hardlink_identity_prevents_recount_on_next_scan(self):
        source = self.write("hardlink-a.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "hardlink-r", "hardlink-m"))
        linked = os.path.join(self.project, "hardlink-b.jsonl")
        os.link(source, linked)
        tokens.collect(now=NOW, force=True)
        state = paths.load_json(paths.token_scan_state_path())
        slot_files = state["files"][self.account["id"]]
        folded_path = next(path for path, entry in slot_files.items()
                           if not entry.get("duplicate_identity"))
        candidate = json.loads(json.dumps(state))
        self.assertTrue(tokens._fold_entry(
            candidate, self.account["id"], folded_path,
            candidate["files"][self.account["id"]][folded_path]))
        budget = tokens._serialized_state_size(candidate)

        with mock.patch.object(tokens, "COMPACT_AFTER_SECONDS", NOW * 2), \
                mock.patch.object(tokens, "MAX_SERIALIZED_STATE_BYTES", budget):
            _compacted, dropped = tokens._enforce_state_budgets(state, NOW)
        self.assertEqual(dropped, 0)
        sentinel = state["files"][self.account["id"]][folded_path]
        current = os.stat(source)
        self.assertEqual((sentinel["st_dev"], sentinel["st_ino"]),
                         (current.st_dev, current.st_ino))
        paths.write_json_atomic(
            paths.token_scan_state_path(), state, mode=0o600)

        other_path = next(path for path in slot_files if path != folded_path)
        with mock.patch.object(
                tokens, "_files", return_value=iter((folded_path, other_path))):
            tokens.collect(now=NOW + 1, force=True)
        daily = paths.load_json(paths.token_daily_path())
        self.assertEqual(daily["accounts"][self.account["id"]][
            "2026-07-10"]["grand_total"], 26)
        self.assertEqual(daily["duplicate_file_count"], 1)

    def test_folded_changed_and_missing_keep_subtotal_without_double_count(self):
        path = self.write("cold.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "cold-r", "cold-m"))
        tokens.collect(now=NOW, force=True)
        before = paths.load_json(paths.token_daily_path())["accounts"]
        state = paths.load_json(paths.token_scan_state_path())
        entry = state["files"][self.account["id"]][
            "projects/project/cold.jsonl"]
        entry["padding"] = "x" * 5000
        budget = tokens._serialized_state_size(state) - 2500
        with mock.patch.object(tokens, "MAX_SERIALIZED_STATE_BYTES", budget):
            _compacted, dropped = tokens._enforce_state_budgets(state, NOW)
        self.assertEqual(dropped, 0)
        self.assertTrue(state["files"][self.account["id"]][
            "projects/project/cold.jsonl"]["folded"])
        paths.write_json_atomic(
            paths.token_scan_state_path(), state, mode=0o600)

        with open(path, "a", encoding="utf-8") as handle:
            handle.write(claude_line(
                "2026-07-10T00:00:01Z", "new-r", "new-m"))
        with mock.patch.object(
                tokens, "_parse_stream",
                side_effect=AssertionError("parsed changed folded file")):
            tokens.collect(now=NOW + 1, force=True)
        changed = paths.load_json(paths.token_daily_path())
        self.assertEqual(changed["accounts"], before)
        self.assertTrue(changed["partial"])
        self.assertEqual(changed["folded_changed_file_count"], 1)
        self.assertEqual(tokens.summarize(
            changed, [self.account], now=NOW + 1)[
                "folded_changed_file_count"], 1)
        self.assertTrue(self.state_entry("cold.jsonl")["folded"])

        os.unlink(path)
        tokens.collect(now=NOW + 2, force=True)
        missing = paths.load_json(paths.token_daily_path())
        self.assertEqual(missing["accounts"], before)
        self.assertTrue(missing["partial"])
        self.assertEqual(missing["folded_changed_file_count"], 1)
        self.assertTrue(self.state_entry("cold.jsonl")["folded"])

    def test_remove_account_purges_folded_totals(self):
        target = self.account["id"]
        survivor = slot_id("survivor")
        daily_accounts = {
            target: {"2026-07-10": day_counts(1, 2)},
            survivor: {"2026-07-11": day_counts(3, 4)},
        }
        paths.write_json_atomic(paths.token_scan_state_path(), {
            "schema_version": tokens.SCHEMA_VERSION,
            "files": {
                target: {"cold": {"size": 1, "mtime_ns": 2,
                                    "days": daily_accounts[target],
                                    "folded": True}},
                survivor: {"cold": {"size": 3, "mtime_ns": 4,
                                      "days": daily_accounts[survivor],
                                      "folded": True}},
            },
            "failed_root_slot_ids": [], "failed_root_count": 0,
            "folded_changed_files": {target: 1, survivor: 2},
            "budget_dropped_files": {}, "budget_partial": False,
        })
        paths.write_json_atomic(paths.token_daily_path(), {
            "schema_version": tokens.SCHEMA_VERSION,
            "generated": NOW, "partial": True,
            "failed_file_count": 0, "failed_root_count": 0,
            "failed_root_slot_ids": [], "partial_file_count": 0,
            "duplicate_file_count": 0, "folded_changed_file_count": 3,
            "budget_dropped_file_count": 0,
            "accounts": daily_accounts,
        })

        tokens.remove_account(target)
        state = paths.load_json(paths.token_scan_state_path())
        daily = paths.load_json(paths.token_daily_path())
        self.assertNotIn(target, state["files"])
        self.assertNotIn(target, state["folded_changed_files"])
        self.assertIn(survivor, state["files"])
        self.assertNotIn(target, daily["accounts"])
        self.assertEqual(daily["folded_changed_file_count"], 2)
        self.assertTrue(daily["partial"])

    def test_three_files_two_cap_never_recounts_evicted_folded_sentinel(self):
        for index in range(3):
            self.write(f"{index}.jsonl", claude_line(
                "2026-07-10T00:00:00Z", f"r{index}", f"m{index}"))
        with mock.patch.object(tokens, "MAX_TRACKED_FILES", 2), \
                mock.patch.object(tokens, "MAX_SERIALIZED_STATE_BYTES",
                                  10 * 1024 * 1024):
            for scan_now in (NOW, NOW + 1):
                tokens.collect(now=scan_now, force=True)
                state = paths.load_json(paths.token_scan_state_path())
                daily = paths.load_json(paths.token_daily_path())
                entries = state["files"][self.account["id"]]

                self.assertEqual(len(entries), 2)
                self.assertTrue(all(entry.get("folded") is True
                                    for entry in entries.values()))
                self.assertTrue(state["budget_partial"])
                self.assertEqual(state["budget_dropped_files"], {
                    self.account["id"]: 1})
                self.assertTrue(daily["partial"])
                self.assertEqual(daily["budget_dropped_file_count"], 1)
                self.assertEqual(daily["accounts"][self.account["id"]][
                    "2026-07-10"]["grand_total"], 52)

    def test_scan_health_persists_attempt_and_success_separately(self):
        self.write("one.jsonl", claude_line(
            "2026-07-10T00:00:00Z", "r1", "m1"))
        tokens.collect(now=NOW, force=True)
        completed = paths.load_json(paths.token_daily_path())
        self.assertEqual(completed["last_attempt"], NOW)
        self.assertEqual(completed["last_success"], NOW)
        self.assertEqual(completed["generated"], NOW)

        with mock.patch.object(tokens, "_daily_from_files",
                               side_effect=RuntimeError("stop")):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                tokens.collect(now=NOW + 1, force=True)
        failed = paths.load_json(paths.token_daily_path())
        self.assertEqual(failed["last_attempt"], NOW + 1)
        self.assertEqual(failed["last_success"], NOW)
        self.assertEqual(failed["generated"], NOW)

    def test_removal_preserves_partial_metadata_when_state_unreadable(self):
        target = self.account["id"]
        paths.write_json_atomic(paths.token_daily_path(), {
            "schema_version": tokens.SCHEMA_VERSION,
            "generated": NOW,
            "partial": True,
            "failed_file_count": 7,
            "failed_root_count": 2,
            "partial_file_count": 3,
            "accounts": {target: {"2026-07-10": day_counts(1, 1)}},
        })
        os.makedirs(os.path.dirname(paths.token_scan_state_path()),
                    exist_ok=True)
        with open(paths.token_scan_state_path(), "w", encoding="utf-8") as handle:
            handle.write("{broken")
        with self.assertRaisesRegex(RuntimeError, "unreadable"):
            tokens.remove_account(target)
        daily = paths.load_json(paths.token_daily_path())
        self.assertEqual(daily["accounts"], {})
        self.assertTrue(daily["partial"])
        self.assertEqual(daily["failed_file_count"], 7)
        self.assertEqual(daily["failed_root_count"], 2)
        self.assertEqual(daily["partial_file_count"], 3)

    def test_removal_recomputes_failed_root_health_from_slot_ids(self):
        target = self.account["id"]
        survivor = slot_id("survivor")
        paths.write_json_atomic(paths.token_scan_state_path(), {
            "schema_version": tokens.SCHEMA_VERSION,
            "failed_root_count": 2,
            "failed_root_slot_ids": [target, survivor],
            "files": {target: {}, survivor: {}},
            "budget_dropped_files": {}, "budget_partial": False,
        })
        paths.write_json_atomic(paths.token_daily_path(), {
            "schema_version": tokens.SCHEMA_VERSION,
            "generated": NOW, "partial": True,
            "failed_file_count": 0, "failed_root_count": 2,
            "failed_root_slot_ids": [target, survivor],
            "partial_file_count": 0, "accounts": {target: {}, survivor: {}},
        })
        tokens.remove_account(target)
        state = paths.load_json(paths.token_scan_state_path())
        daily = paths.load_json(paths.token_daily_path())
        self.assertEqual(state["failed_root_slot_ids"], [survivor])
        self.assertEqual(daily["failed_root_count"], 1)
        self.assertTrue(daily["partial"])

        tokens.remove_account(survivor)
        daily = paths.load_json(paths.token_daily_path())
        self.assertEqual(daily["failed_root_slot_ids"], [])
        self.assertEqual(daily["failed_root_count"], 0)
        self.assertFalse(daily["partial"])

    def test_scan_lock_serializes_scans(self):
        with tokens.scan_lock(blocking=True):
            self.assertFalse(tokens.collect(
                [self.account], config=self.config, now=NOW, force=True))

    def test_authoritative_gate_and_enumeration_run_under_both_locks(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                held = {"scan": False, "config": False}
                view = {"schema_version": 1,
                        "dashboard": {"token_stats": enabled},
                        "accounts": [self.account]}
                events = []

                @contextmanager
                def scan_lock(blocking=False):
                    self.assertFalse(blocking)
                    held["scan"] = True
                    events.append("scan_lock")
                    try:
                        yield True
                    finally:
                        held["scan"] = False

                @contextmanager
                def config_lock():
                    self.assertTrue(held["scan"])
                    held["config"] = True
                    events.append("config_lock")
                    try:
                        yield
                    finally:
                        held["config"] = False

                def load():
                    self.assertTrue(held["scan"] and held["config"])
                    events.append("load")
                    return view

                def gate(config):
                    self.assertIs(config, view)
                    self.assertTrue(held["scan"] and held["config"])
                    events.append("gate")
                    return enabled

                def accounts(config):
                    self.assertIs(config, view)
                    self.assertTrue(held["scan"] and held["config"])
                    events.append("accounts")
                    return []

                with mock.patch.object(tokens, "scan_lock", scan_lock), \
                        mock.patch.object(registry, "config_lock", config_lock), \
                        mock.patch.object(registry, "load", side_effect=load), \
                        mock.patch.object(registry, "token_stats_enabled",
                                          side_effect=gate), \
                        mock.patch.object(registry, "accounts",
                                          side_effect=accounts):
                    result = tokens.collect(
                        accounts=[{"stale": True}], config={"stale": True},
                        now=NOW, force=True)
                expected = ["scan_lock", "config_lock", "load", "gate"]
                if enabled:
                    expected.append("accounts")
                    self.assertTrue(result)
                else:
                    self.assertFalse(result)
                self.assertEqual(events, expected)


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
            efforts={"xhigh": 170},
            projects={"headroom": 100, "dispatch": 70})
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
        self.assertEqual(value["summary"]["most_used_model"]["label"],
                         "other")
        self.assertEqual(sum(item["tokens"] for item in
                             value["summary"]["families"]),
                         value["summary"]["grand_total"])
        self.assertEqual(value["summary"]["families"][0]["tokens"], 170)
        self.assertEqual(value["summary"]["efforts"][-1], {
            "label": "xhigh", "tokens": 170, "share_pct": 100.0})
        self.assertEqual(row["projects"][0], {
            "label": "headroom", "grand_total": 100,
            "share_pct": round(100 * 100 / row["lifetime_grand_total"], 1),
        })
        self.assertEqual(value["summary"]["projects"], row["projects"])

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
            "label": "other", "share_pct": 100.0})
        self.assertEqual(value["accounts"][0]["projects"], [])
        self.assertEqual(value["summary"]["projects"], [])
        self.assertNotIn("attributed_breakdown", value["accounts"][0])

    def test_project_payload_lists_are_capped_at_top_six(self):
        day = self.day(0)
        project_counts = {f"project-{index}": index + 1
                          for index in range(8)}
        grand_total = sum(project_counts.values())
        value = tokens.summarize({
            "schema_version": tokens.SCHEMA_VERSION,
            "generated": NOW,
            "accounts": {self.account["id"]: {
                day: day_counts(grand_total, 0, projects=project_counts)}},
        }, [self.account], now=NOW)
        self.assertEqual(len(value["accounts"][0]["projects"]), 6)
        self.assertEqual(value["accounts"][0]["projects"],
                         value["summary"]["projects"])
        self.assertEqual(value["summary"]["projects"][0]["label"],
                         "project-7")

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
        self.assertIs(enabled["token_stats_enabled"], True)
        self.assertIn("token_stats", enabled)
        self.assertEqual(len(enabled["token_stats"]["days"]), 400)
        self.assertEqual(min(enabled["token_stats"]["days"]), self.day(-399))
        disabled = dict(self.config)
        disabled["dashboard"] = {"token_stats": False}
        poisoned = dict(snapshot, token_stats={"stale": True},
                        token_stats_enabled=True)
        disabled_payload = dashboard.display_snapshot(
            poisoned, evaluated_at=NOW, config=disabled)
        self.assertNotIn("token_stats", disabled_payload)
        self.assertIs(disabled_payload["token_stats_enabled"], False)

        with mock.patch.object(registry, "load",
                               return_value=self.config) as load, \
                mock.patch.object(registry, "token_accounts",
                                  wraps=registry.token_accounts) as token_accounts, \
                mock.patch.object(registry, "accounts",
                                  wraps=registry.accounts) as accounts:
            dashboard.display_snapshot(poisoned, evaluated_at=NOW)
        load.assert_called_once_with()
        token_accounts.assert_called_once_with(
            self.config, include_status=True)
        accounts.assert_called_once_with(self.config)

    def test_enabled_without_store_omits_payload_key(self):
        value = dashboard.display_snapshot(
            usage_snapshot(self.account["id"]), evaluated_at=NOW,
            config=self.config)
        self.assertIs(value["token_stats_enabled"], True)
        self.assertNotIn("token_stats", value)

    def test_run_collect_is_scan_free_for_quiet_and_verbose_callers(self):
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
                                  side_effect=AssertionError("token scan")):
            self.assertIs(usage_collect.run_collect(quiet=True), snapshot)
            with redirect_stdout(io.StringIO()):
                self.assertIs(usage_collect.run_collect(quiet=False), snapshot)

    def test_cli_collect_scans_synchronously_after_collection_lock_release(self):
        snapshot = usage_snapshot(self.account["id"])
        snapshot.update({"run_id": "fixture", "generated_iso": "fixture"})
        observed = []
        caller_thread = threading.get_ident()

        def assert_unlocked():
            with usage_collect.collection_lock(blocking=False) as locked:
                observed.append((locked, threading.get_ident()))
            return False

        with mock.patch.object(usage_collect, "collect",
                               return_value=snapshot), \
                mock.patch.object(registry, "apply_pins",
                                  return_value=[self.account]), \
                mock.patch.object(registry, "dashboard_settings",
                                  return_value={"redact_emails": True}), \
                mock.patch.object(usage_collect.history, "append_snapshot"), \
                mock.patch.object(tokens, "collect",
                                  side_effect=assert_unlocked) as scan:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli._dispatch(["collect"]), 0)
        scan.assert_called_once_with()
        self.assertEqual(observed, [(True, caller_thread)])

    def test_dashboard_owns_daemon_scans_and_they_remain_single_flight(self):
        entered = threading.Event()
        release = threading.Event()
        discovery_calls = []

        def slow_files(account, errors=None):
            discovery_calls.append(account["id"])
            entered.set()
            self.assertTrue(release.wait(2))
            return iter(())

        real_thread = threading.Thread
        workers = []

        def make_thread(*args, **kwargs):
            worker = real_thread(*args, **kwargs)
            workers.append(worker)
            return worker

        with mock.patch.object(tokens, "_files", side_effect=slow_files), \
                mock.patch.object(usage_collect.threading, "Thread",
                                  side_effect=make_thread):
            first = usage_collect._trigger_token_scan(synchronous=False)
            self.assertTrue(entered.wait(2))
            second = usage_collect._trigger_token_scan(synchronous=False)
            self.assertTrue(all(worker.daemon for worker in workers))
            self.assertTrue(first.is_alive())
            release.set()
            for worker in (first, second):
                worker.join(2)
        self.assertEqual(discovery_calls, [self.account["id"]])

        snapshot = usage_snapshot(self.account["id"])

        class CallingGate:
            def get(self, _load, collect_snapshot):
                collect_snapshot()
                return dashboard.RefreshResult(snapshot)

        handler = object.__new__(dashboard.Handler)
        handler.demo = False
        handler.refresh_gate = CallingGate()
        with mock.patch.object(usage_collect, "run_collect",
                               return_value=snapshot) as collect_snapshot, \
                mock.patch.object(usage_collect, "_trigger_token_scan") as trigger:
            self.assertEqual(handler._snapshot_result().snapshot, snapshot)
        collect_snapshot.assert_called_once_with(quiet=True)
        trigger.assert_called_once_with(synchronous=False)


if __name__ == "__main__":
    unittest.main()
