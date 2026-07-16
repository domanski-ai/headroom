"""Rolling percentage-history persistence and aggregation tests."""
import hashlib
import io
import json
import os
import stat
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from unittest import mock

from headroom import collect, history, paths, registry


NOW = 2_000_000_000


def slot_id(name):
    return hashlib.sha256(name.encode()).hexdigest()[:12]


def live_ids(*names):
    return {slot_id(name) for name in names}


def snapshot(used=42.0, name="alpha", email="owner@example.test",
             account_id=None):
    return {
        "schema_version": 1,
        "generated": NOW,
        "accounts": [{
            "id": account_id or slot_id(name),
            "name": name,
            "email": email,
            "provider": "claude",
            "plan": "Max",
            "ok": True,
            "stale": False,
            "identity": {"account_id": "secret"},
            "windows": {
                "5h": {"used_percent": used, "resets_at": NOW + 3600,
                       "email": "window@example.test"},
                "7d": {"used_percent": used + 5,
                       "resets_at": NOW + 86400},
            },
        }],
    }


def row(ts, used, name="alpha", ok=True, stale=False, account_id=None):
    value = snapshot(used=used, name=name, account_id=account_id)
    projected = history.project_snapshot(value, ts=ts)
    projected["accounts"][0]["ok"] = ok
    projected["accounts"][0]["stale"] = stale
    return projected


class HistoryPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {
            "HEADROOM_DIR": self.temp.name,
            "HEADROOM_HISTORY": "1",
            "HEADROOM_HISTORY_MIN_INTERVAL": "60",
            "HEADROOM_HISTORY_RETENTION_DAYS": "30",
        })
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_append_creates_private_jsonl_and_throttles(self):
        self.assertTrue(history.append_snapshot(snapshot(), now=NOW))
        self.assertFalse(history.append_snapshot(snapshot(50), now=NOW + 59))
        self.assertTrue(history.append_snapshot(snapshot(51), now=NOW + 60))
        with open(paths.history_path(), encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle]
        self.assertEqual([value["ts"] for value in rows], [NOW, NOW + 60])
        self.assertEqual(stat.S_IMODE(os.stat(paths.history_dir()).st_mode),
                         0o700)
        self.assertEqual(stat.S_IMODE(os.stat(paths.history_path()).st_mode),
                         0o600)

    def test_retention_prunes_old_rows_with_atomic_replace(self):
        with mock.patch.dict(os.environ, {
                "HEADROOM_HISTORY_MIN_INTERVAL": "0",
                "HEADROOM_HISTORY_RETENTION_DAYS": "1"}), \
                mock.patch.object(history.os, "replace",
                                  wraps=os.replace) as replace:
            history.append_snapshot(snapshot(10), now=NOW - 2 * 86400 - 1)
            history.append_snapshot(snapshot(20), now=NOW)
        replace.assert_called_once()
        with mock.patch.object(history.time, "time", return_value=NOW):
            rows = history.load_series(30, live_ids("alpha"))
        self.assertEqual([value["ts"] for value in rows], [NOW])
        self.assertEqual(rows[0]["accounts"][0]["windows"]["5h"][
            "used_percent"], 20.0)

    def test_failed_atomic_rewrite_keeps_original_and_cleans_temp(self):
        with mock.patch.dict(os.environ, {
                "HEADROOM_HISTORY_MIN_INTERVAL": "0",
                "HEADROOM_HISTORY_RETENTION_DAYS": "1"}):
            history.append_snapshot(snapshot(10), now=NOW - 2 * 86400 - 1)
            with open(paths.history_path(), "rb") as handle:
                before = handle.read()
            with mock.patch.object(history.os, "replace",
                                   side_effect=OSError("replace failed")):
                with self.assertRaises(OSError):
                    history.append_snapshot(snapshot(20), now=NOW)
        with open(paths.history_path(), "rb") as handle:
            self.assertEqual(handle.read(), before)
        leftovers = [name for name in os.listdir(paths.history_dir())
                     if name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_retention_prune_is_amortized_by_one_day_grace(self):
        with mock.patch.dict(os.environ, {
                "HEADROOM_HISTORY_MIN_INTERVAL": "0",
                "HEADROOM_HISTORY_RETENTION_DAYS": "1"}):
            history.append_snapshot(snapshot(10), now=NOW - 86400 - 10)
            with mock.patch.object(history.os, "replace",
                                   wraps=os.replace) as replace:
                history.append_snapshot(snapshot(20), now=NOW)
                history.append_snapshot(snapshot(30), now=NOW + 1)
                history.append_snapshot(snapshot(40), now=NOW + 2)
        replace.assert_not_called()
        with open(paths.history_path(), "rb") as handle:
            self.assertEqual(len(handle.readlines()), 4)

    def test_byte_cap_prunes_retention_then_oldest_rows_to_eighty_percent(self):
        paths.ensure_private(paths.history_dir())
        cap = history.MIN_MAX_BYTES
        line = (json.dumps(row(NOW - 10, 10), separators=(",", ":")) +
                "\n").encode("utf-8")
        with open(paths.history_path(), "wb") as handle:
            handle.write(line * (cap // len(line) + 100))
        self.assertGreater(os.path.getsize(paths.history_path()), cap)
        with mock.patch.dict(os.environ, {
                "HEADROOM_HISTORY_MAX_BYTES": "1",
                "HEADROOM_HISTORY_MIN_INTERVAL": "0"}), \
                mock.patch.object(history.os, "replace",
                                  wraps=os.replace) as replace:
            self.assertTrue(history.append_snapshot(snapshot(20), now=NOW))
        replace.assert_called_once()
        appended_size = history._row_size(
            history.project_snapshot(snapshot(20), ts=NOW))
        self.assertLessEqual(os.path.getsize(paths.history_path()),
                             int(cap * .8) + appended_size)

    def test_pruning_happens_before_throttle(self):
        with mock.patch.dict(os.environ, {
                "HEADROOM_HISTORY_MIN_INTERVAL": "0",
                "HEADROOM_HISTORY_RETENTION_DAYS": "1"}):
            history.append_snapshot(snapshot(10), now=NOW - 2 * 86400 - 1)
            history.append_snapshot(snapshot(20), now=NOW - 10)
        with mock.patch.dict(os.environ, {
                "HEADROOM_HISTORY_MIN_INTERVAL": "60",
                "HEADROOM_HISTORY_RETENTION_DAYS": "1"}), \
                mock.patch.object(history.os, "replace",
                                  wraps=os.replace) as replace:
            self.assertFalse(history.append_snapshot(snapshot(30), now=NOW))
        replace.assert_called_once()
        with open(paths.history_path(), encoding="utf-8") as handle:
            self.assertEqual([json.loads(line)["ts"] for line in handle],
                             [NOW - 10])

    def test_future_tail_does_not_throttle_new_append(self):
        self.assertTrue(history.append_snapshot(snapshot(10), now=NOW + 301))
        self.assertTrue(history.append_snapshot(snapshot(20), now=NOW))
        self.assertFalse(history.append_snapshot(snapshot(30), now=NOW + 30))
        with open(paths.history_path(), encoding="utf-8") as handle:
            self.assertEqual([json.loads(line)["ts"] for line in handle],
                             [NOW + 301, NOW])

    def test_future_first_row_does_not_block_retention_prune(self):
        paths.ensure_private(paths.history_dir())
        with open(paths.history_path(), "w", encoding="utf-8") as handle:
            handle.write(json.dumps(row(NOW + 301, 10)) + "\n")
            handle.write(json.dumps(row(NOW - 2 * 86400 - 1, 20)) + "\n")
        with mock.patch.dict(os.environ, {
                "HEADROOM_HISTORY_MIN_INTERVAL": "0",
                "HEADROOM_HISTORY_RETENTION_DAYS": "1"}), \
                mock.patch.object(history.os, "replace",
                                  wraps=os.replace) as replace:
            self.assertTrue(history.append_snapshot(snapshot(30), now=NOW))
        replace.assert_called_once()
        with open(paths.history_path(), encoding="utf-8") as handle:
            timestamps = [json.loads(line)["ts"] for line in handle]
        self.assertEqual(timestamps, [NOW])

    def test_kill_switch_returns_before_filesystem_access(self):
        with mock.patch.dict(os.environ, {"HEADROOM_HISTORY": "0"}), \
                mock.patch.object(history, "_oldest_row") as oldest, \
                mock.patch.object(history, "_read_rows",
                                  side_effect=AssertionError("filesystem read")):
            self.assertFalse(history.append_snapshot(snapshot(), now=NOW))
        oldest.assert_not_called()
        self.assertFalse(os.path.exists(paths.history_dir()))

    def test_malformed_lines_are_ignored_and_loaded_rows_are_sanitized(self):
        paths.ensure_private(paths.history_dir())
        valid = row(NOW - 10, 30)
        valid["accounts"][0]["email"] = "injected@example.test"
        with open(paths.history_path(), "w", encoding="utf-8") as handle:
            handle.write("not-json\n")
            handle.write(json.dumps({"ts": "bad", "accounts": []}) + "\n")
            handle.write(json.dumps({
                "ts": NOW - 20,
                "accounts": [{"name": "bad", "provider": "claude",
                              "windows": [{}]}],
            }) + "\n")
            handle.write(json.dumps(valid) + "\n")
        with mock.patch.object(history.time, "time", return_value=NOW):
            loaded = history.load_series(1, live_ids("alpha"))
        self.assertEqual(len(loaded), 1)
        self.assertNotIn("email", loaded[0]["accounts"][0])

    def test_bounded_giant_line_does_not_block_valid_rows_or_appends(self):
        paths.ensure_private(paths.history_dir())
        with open(paths.history_path(), "wb") as handle:
            handle.write(b"\xff\xfe not utf-8\n")
            handle.write(b"[" * 2000 + b"]" * 2000 + b"\n")
            handle.write(b"x" * (history.MAX_LINE_BYTES + 512 * 1024) + b"\n")
            handle.write(json.dumps(row(NOW - 10, 15)).encode("utf-8") + b"\n")
        sizes = []
        raw = open(paths.history_path(), "rb")

        class TrackingReader:
            name = raw.name

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                raw.close()

            def readline(self, size=-1):
                sizes.append(size)
                return raw.readline(size)

            def fileno(self):
                return raw.fileno()

            def tell(self):
                return raw.tell()

        with mock.patch("builtins.open", return_value=TrackingReader()):
            loaded = history._read_rows(paths.history_path())
        self.assertEqual([value["ts"] for value in loaded], [NOW - 10])
        self.assertTrue(sizes)
        self.assertLessEqual(max(sizes), history.MAX_LINE_BYTES + 1)
        with mock.patch.dict(os.environ, {
                "HEADROOM_HISTORY_MIN_INTERVAL": "0"}):
            self.assertTrue(history.append_snapshot(snapshot(25), now=NOW))
        with mock.patch.object(history.time, "time", return_value=NOW):
            loaded = history.load_series(1, live_ids("alpha"))
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[-1]["accounts"][0]["windows"]["5h"][
            "used_percent"], 25.0)

    def test_total_read_budget_is_enforced(self):
        paths.ensure_private(paths.history_dir())
        with open(paths.history_path(), "wb") as handle:
            handle.write(b"x" * 129)
        with mock.patch.object(history, "max_bytes", return_value=64), \
                self.assertRaisesRegex(OSError, "read budget"):
            history._read_rows(paths.history_path())

    def test_unreadable_over_cap_history_skips_append_and_rewrite(self):
        paths.ensure_private(paths.history_dir())
        with open(paths.history_path(), "wb") as handle:
            handle.write(json.dumps(row(NOW - 10, 10)).encode("utf-8") + b"\n")
        with open(paths.history_path(), "rb") as handle:
            before = handle.read()
        with mock.patch.object(history, "_file_size",
                               return_value=history.max_bytes() + 1), \
                mock.patch.object(history, "_read_rows",
                                  side_effect=PermissionError("unreadable")), \
                mock.patch.object(history, "_write_rows_atomic") as rewrite, \
                self.assertRaisesRegex(
                    RuntimeError, "byte cap.*append skipped.*unreadable"):
            history.append_snapshot(snapshot(20), now=NOW)
        rewrite.assert_not_called()
        with open(paths.history_path(), "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_unreadable_history_refuses_account_rewrite(self):
        history.append_snapshot(snapshot(), now=NOW)
        with mock.patch.object(history, "_read_rows",
                               side_effect=PermissionError("unreadable")), \
                mock.patch.object(history, "_write_rows_atomic") as rewrite:
            with self.assertRaisesRegex(
                    RuntimeError, "history purge failed.*unreadable"):
                history.remove_account(slot_id("alpha"), "alpha")
        rewrite.assert_not_called()

    def test_read_rows_treats_only_missing_as_empty(self):
        self.assertEqual(history._read_rows(paths.history_path()), [])
        with mock.patch("builtins.open",
                        side_effect=PermissionError("unreadable")), \
                self.assertRaisesRegex(PermissionError, "unreadable"):
            history._read_rows(paths.history_path())

    def test_oversized_encoded_row_is_not_appended(self):
        value = snapshot()
        value["accounts"] *= 6000
        with self.assertRaisesRegex(ValueError, "maximum line size"):
            history.append_snapshot(value, now=NOW)
        self.assertFalse(os.path.exists(paths.history_path()))

    def test_append_repairs_missing_trailing_newline(self):
        paths.ensure_private(paths.history_dir())
        first = json.dumps(row(NOW - 60, 10), separators=(",", ":"))
        with open(paths.history_path(), "w", encoding="utf-8") as handle:
            handle.write(first)
        self.assertTrue(history.append_snapshot(snapshot(20), now=NOW))
        with open(paths.history_path(), "rb") as handle:
            raw = handle.read()
        self.assertIn(b"}\n{", raw)
        self.assertTrue(raw.endswith(b"\n"))
        with mock.patch.object(history.time, "time", return_value=NOW):
            loaded = history.load_series(1, live_ids("alpha"))
        self.assertEqual([value["ts"] for value in loaded], [NOW - 60, NOW])

    def test_remove_account_rewrites_rows_and_drops_empty_rows(self):
        only_a = row(NOW - 3, 10, name="a")
        only_b = row(NOW - 2, 20, name="b")
        both = row(NOW - 1, 30, name="a")
        both["accounts"].extend(only_b["accounts"])
        legacy_a = row(NOW, 40, name="a")
        legacy_a["accounts"][0].pop("id")
        history._write_rows_atomic([only_a, only_b, both, legacy_a])
        with mock.patch.object(history.os, "replace",
                               wraps=os.replace) as replace:
            self.assertTrue(history.remove_account(slot_id("a"), "a"))
        replace.assert_called_once()
        with mock.patch.object(history.time, "time", return_value=NOW):
            loaded = history.load_series(1, live_ids("b"))
        self.assertEqual([value["ts"] for value in loaded],
                         [NOW - 2, NOW - 1])
        self.assertTrue(all([account["name"] for account in value["accounts"]]
                            == ["b"] for value in loaded))

    def test_same_name_reconnect_never_serves_or_merges_dead_generation(self):
        old_id = "111111111111"
        new_id = "222222222222"
        rows = [row(NOW - 3, 90, account_id=old_id),
                row(NOW - 2, 20, account_id=new_id),
                row(NOW - 1, 30, account_id=new_id)]
        history._write_rows_atomic(rows)
        with mock.patch.object(history.time, "time", return_value=NOW):
            loaded = history.load_series(1, {new_id})
        payload = history.response(
            1, {new_id}, rows=history._read_rows(paths.history_path()),
            generated=NOW)
        self.assertEqual([value["ts"] for value in loaded], [NOW - 2, NOW - 1])
        for key in ("series", "summary", "leaderboard"):
            self.assertEqual([entry["id"] for entry in payload[key]], [new_id])
        self.assertEqual(payload["summary"][0]["windows"]["5h"][
            "sample_count"], 2)
        self.assertEqual(payload["summary"][0]["windows"]["5h"]["peak"],
                         {"value": 30.0, "ts": NOW - 1})

    def test_amortized_prune_drops_dead_generation_rows(self):
        live_id = slot_id("alpha")
        dead_id = "dddddddddddd"
        rows = [row(NOW - 31 * 86400 - 1, 5, account_id=live_id),
                row(NOW - 120, 90, account_id=dead_id),
                row(NOW - 60, 20, account_id=live_id)]
        history._write_rows_atomic(rows)
        with mock.patch.dict(os.environ, {
                "HEADROOM_HISTORY_MIN_INTERVAL": "0"}):
            self.assertTrue(history.append_snapshot(
                snapshot(30, account_id=live_id), now=NOW,
                live_ids={live_id}))
        physical = history._read_rows(paths.history_path())
        self.assertEqual({account["id"] for value in physical
                          for account in value["accounts"]}, {live_id})
        self.assertEqual([value["ts"] for value in physical], [NOW - 60, NOW])

    def test_rows_without_ids_are_dead(self):
        legacy = row(NOW - 1, 20)
        legacy["accounts"][0].pop("id")
        history._write_rows_atomic([legacy])
        with mock.patch.object(history.time, "time", return_value=NOW):
            self.assertEqual(
                history.load_series(1, live_ids("alpha")), [])

    def test_remove_account_raises_clear_error_and_keeps_original(self):
        history.append_snapshot(snapshot(), now=NOW)
        with open(paths.history_path(), "rb") as handle:
            before = handle.read()
        with mock.patch.object(history.os, "replace",
                               side_effect=OSError("disk full")):
            with self.assertRaisesRegex(
                    RuntimeError, "history purge failed.*disk full"):
                history.remove_account(slot_id("alpha"), "alpha")
        with open(paths.history_path(), "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_throttle_carryover_accounts_are_not_projected(self):
        carried = snapshot(name="carried")["accounts"][0]
        carried["throttle_carryover"] = True
        fresh = snapshot(name="fresh")["accounts"][0]
        value = snapshot()
        value["accounts"] = [carried, fresh]
        projected = history.project_snapshot(value, ts=NOW)
        self.assertEqual([account["name"] for account in projected["accounts"]],
                         ["fresh"])

    def test_extreme_numeric_sample_is_ignored_without_escaping(self):
        paths.ensure_private(paths.history_dir())
        value = row(NOW - 10, 30)
        value["accounts"][0]["windows"]["5h"]["used_percent"] = 10 ** 1000
        value["accounts"][0]["windows"]["5h"]["resets_at"] = 10 ** 1000
        with open(paths.history_path(), "w", encoding="utf-8") as handle:
            handle.write(json.dumps(value) + "\n")
        with mock.patch.object(history.time, "time", return_value=NOW):
            loaded = history.load_series(1, live_ids("alpha"))
        window = loaded[0]["accounts"][0]["windows"]["5h"]
        self.assertEqual(window, {"used_percent": None, "resets_at": None})

    def test_public_snapshot_with_emails_never_leaks_to_history(self):
        value = snapshot()
        value["accounts"][0]["plan"] = "owner@example.test"
        value["accounts"][0]["windows"]["scoped:acct@example.test"] = {
            "used_percent": 91, "resets_at": NOW + 7200}
        self.assertTrue(history.append_snapshot(value, now=NOW))
        with open(paths.history_path(), encoding="utf-8") as handle:
            raw = handle.read()
        self.assertNotIn("@", raw)
        self.assertNotIn("owner@example.test", raw)
        self.assertNotIn("window@example.test", raw)
        self.assertNotIn("identity", raw)
        account = json.loads(raw)["accounts"][0]
        self.assertIsNone(account["plan"])
        self.assertNotIn("scoped:acct@example.test", account["windows"])
        self.assertEqual(set(account), {
            "id", "name", "provider", "plan", "ok", "stale", "windows"})
        self.assertEqual(set(account["windows"]["5h"]), {
            "used_percent", "resets_at"})

    def test_legacy_name_and_provider_identities_are_screened_on_load(self):
        paths.ensure_private(paths.history_dir())
        unsafe_name = row(NOW - 3, 10)
        unsafe_name["accounts"][0]["name"] = "owner@example.test"
        unsafe_provider = row(NOW - 2, 20)
        unsafe_provider["accounts"][0]["provider"] = "acct@example.test"
        safe = row(NOW - 1, 30, name="safe")
        with open(paths.history_path(), "w", encoding="utf-8") as handle:
            for value in (unsafe_name, unsafe_provider, safe):
                handle.write(json.dumps(value) + "\n")
        with mock.patch.object(history.time, "time", return_value=NOW):
            loaded = history.load_series(
                1, live_ids("alpha", "safe"))
        rendered = json.dumps(history.response(
            1, live_ids("alpha", "safe"), rows=loaded, generated=NOW))
        self.assertNotIn("@", rendered)
        self.assertEqual([account["name"] for account in loaded[-1]["accounts"]],
                         ["safe"])


class HistoryAggregationTests(unittest.TestCase):
    def test_cap_hits_are_episodes_with_hysteresis(self):
        values = [99.6, 99.7, 95, 89, 99.5, 90, 89, 99.4]
        rows = [row(NOW + index, value)
                for index, value in enumerate(values)]
        summary = history.summarize(
            7, rows=rows, generated=NOW + len(values) - 1)[0]["windows"]["5h"]
        self.assertEqual(summary["cap_hit_episodes"], 2)
        self.assertEqual(summary["current"], 99.4)
        self.assertEqual(summary["peak"], {"value": 99.7, "ts": NOW + 1})
        self.assertEqual(summary["sample_count"], len(values))
        self.assertEqual((summary["first_ts"], summary["last_ts"]),
                         (NOW, NOW + len(values) - 1))

    def test_stale_and_failed_samples_do_not_skew_summary(self):
        rows = [row(NOW, 10), row(NOW + 1, 80, stale=True),
                row(NOW + 2, 90, ok=False)]
        summary = history.summarize(7, rows=rows)[0]["windows"]["5h"]
        self.assertEqual(summary["average"], 10.0)
        self.assertEqual(summary["sample_count"], 1)

    def test_current_is_null_for_held_or_old_latest_sample(self):
        held_rows = [row(NOW, 10), row(NOW + 1, 80, stale=True)]
        held = history.response(
            7, live_ids("alpha"), rows=held_rows,
            generated=NOW + 1)["summary"][0]["windows"]["5h"]
        self.assertIsNone(held["current"])
        with mock.patch.dict(os.environ, {
                "HEADROOM_HISTORY_MIN_INTERVAL": "60"}):
            old = history.response(
                7, live_ids("alpha"), rows=[row(NOW, 10)],
                generated=NOW + 421)["summary"][0]["windows"]["5h"]
        self.assertIsNone(old["current"])

    def test_downsampling_is_bounded_and_preserves_bucket_peaks(self):
        rows = [row(NOW + index, index % 101) for index in range(1001)]
        points = history.chart_series(7, rows=rows)[0]["windows"]["5h"]
        self.assertLessEqual(len(points), history.MAX_CHART_POINTS)
        self.assertTrue(all(set(point) == {"ts", "mean", "max"}
                            for point in points))
        self.assertEqual(max(point["max"] for point in points), 100.0)

    def test_leaderboard_ranks_average_then_cap_episodes(self):
        rows = []
        for index, values in enumerate(((70, 80), (50.5, 99.5), (80, 90))):
            name = ("alpha", "bravo", "charlie")[index]
            for offset, value in enumerate(values):
                rows.append(row(NOW + offset, value - 5, name=name))
        ranked = history.leaderboard(7, rows=rows)
        self.assertEqual([entry["name"] for entry in ranked],
                         ["charlie", "bravo", "alpha"])
        self.assertEqual([entry["rank"] for entry in ranked], [1, 2, 3])


class CollectHistoryHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {
            "HEADROOM_DIR": self.temp.name, "HEADROOM_HISTORY": "1"})
        self.env.start()
        self.config = {"schema_version": 1, "accounts": []}
        self.private = {
            "schema_version": 1, "run_id": "fixture", "generated": NOW,
            "generated_iso": "fixture", "integrity_warnings": [],
            "accounts": snapshot()["accounts"],
        }

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def _patch_collect(self):
        return (
            mock.patch.object(registry, "load", return_value=self.config),
            mock.patch.object(registry, "accounts", return_value=[]),
            mock.patch.object(registry, "apply_pins", return_value=[]),
            mock.patch.object(registry, "dashboard_settings",
                              return_value={"redact_emails": False}),
            mock.patch.object(collect, "collect", return_value=self.private),
        )

    def test_hook_receives_exact_public_snapshot_after_publish(self):
        def verify(public, live_ids=None):
            self.assertEqual(paths.load_json(paths.public_snapshot_path()), public)
            self.assertEqual(live_ids, set())

        patches = self._patch_collect()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                mock.patch.object(history, "append_snapshot",
                                  side_effect=verify) as append:
            collect.run_collect(quiet=True)
        append.assert_called_once()

    def test_collect_backfills_legacy_registry_id_and_writes_it_to_history(self):
        config = {"schema_version": 1, "accounts": [{
            "name": "alpha", "provider": "claude", "home": "/tmp/alpha"}]}
        registry.save(config)
        private = json.loads(json.dumps(self.private))
        private["accounts"][0].pop("id")
        with mock.patch.object(collect, "collect", return_value=private):
            collect.run_collect(quiet=True)
        stored = registry.load()["accounts"][0]
        rows = history._read_rows(paths.history_path())
        self.assertRegex(stored["id"], r"^[0-9a-f]{12}$")
        self.assertEqual(registry.accounts()[0]["id"], stored["id"])
        self.assertEqual(rows[0]["accounts"][0]["id"], stored["id"])
        self.assertEqual(paths.load_json(paths.public_snapshot_path())[
            "accounts"][0]["id"], stored["id"])

    def test_history_failure_warns_once_and_collect_still_succeeds(self):
        errors = io.StringIO()
        patches = self._patch_collect()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                mock.patch.object(history, "append_snapshot",
                                  side_effect=OSError("disk full")), \
                redirect_stderr(errors):
            result = collect.run_collect(quiet=True)
        self.assertIs(result, self.private)
        self.assertIsNotNone(paths.load_json(paths.private_snapshot_path()))
        self.assertIsNotNone(paths.load_json(paths.public_snapshot_path()))
        self.assertEqual(errors.getvalue().count("history append failed"), 1)

    def test_history_warning_write_failure_does_not_fail_collection(self):
        class BrokenStderr:
            def write(self, _value):
                raise ValueError("closed")

            def flush(self):
                pass

        patches = self._patch_collect()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                mock.patch.object(history, "append_snapshot",
                                  side_effect=OSError("disk full")), \
                mock.patch.object(collect.sys, "stderr", BrokenStderr()):
            result = collect.run_collect(quiet=True)
        self.assertIs(result, self.private)


if __name__ == "__main__":
    unittest.main()
