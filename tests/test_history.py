"""Rolling percentage-history persistence and aggregation tests."""
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


def snapshot(used=42.0, name="alpha", email="owner@example.test"):
    return {
        "schema_version": 1,
        "generated": NOW,
        "accounts": [{
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


def row(ts, used, name="alpha", ok=True, stale=False):
    value = snapshot(used=used, name=name)
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
            history.append_snapshot(snapshot(10), now=NOW - 2 * 86400)
            history.append_snapshot(snapshot(20), now=NOW)
        replace.assert_called_once()
        with mock.patch.object(history.time, "time", return_value=NOW):
            rows = history.load_series(30)
        self.assertEqual([value["ts"] for value in rows], [NOW])
        self.assertEqual(rows[0]["accounts"][0]["windows"]["5h"][
            "used_percent"], 20.0)

    def test_failed_atomic_rewrite_keeps_original_and_cleans_temp(self):
        with mock.patch.dict(os.environ, {
                "HEADROOM_HISTORY_MIN_INTERVAL": "0",
                "HEADROOM_HISTORY_RETENTION_DAYS": "1"}):
            history.append_snapshot(snapshot(10), now=NOW - 2 * 86400)
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

    def test_kill_switch_returns_before_filesystem_access(self):
        with mock.patch.dict(os.environ, {"HEADROOM_HISTORY": "0"}), \
                mock.patch.object(history, "_read_rows",
                                  side_effect=AssertionError("filesystem read")):
            self.assertFalse(history.append_snapshot(snapshot(), now=NOW))
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
            loaded = history.load_series(1)
        self.assertEqual(len(loaded), 1)
        self.assertNotIn("email", loaded[0]["accounts"][0])

    def test_extreme_numeric_sample_is_ignored_without_escaping(self):
        paths.ensure_private(paths.history_dir())
        value = row(NOW - 10, 30)
        value["accounts"][0]["windows"]["5h"]["used_percent"] = 10 ** 1000
        value["accounts"][0]["windows"]["5h"]["resets_at"] = 10 ** 1000
        with open(paths.history_path(), "w", encoding="utf-8") as handle:
            handle.write(json.dumps(value) + "\n")
        with mock.patch.object(history.time, "time", return_value=NOW):
            loaded = history.load_series(1)
        window = loaded[0]["accounts"][0]["windows"]["5h"]
        self.assertEqual(window, {"used_percent": None, "resets_at": None})

    def test_public_snapshot_with_emails_never_leaks_to_history(self):
        self.assertTrue(history.append_snapshot(snapshot(), now=NOW))
        with open(paths.history_path(), encoding="utf-8") as handle:
            raw = handle.read()
        self.assertNotIn("owner@example.test", raw)
        self.assertNotIn("window@example.test", raw)
        self.assertNotIn("identity", raw)
        account = json.loads(raw)["accounts"][0]
        self.assertEqual(set(account), {
            "name", "provider", "plan", "ok", "stale", "windows"})
        self.assertEqual(set(account["windows"]["5h"]), {
            "used_percent", "resets_at"})


class HistoryAggregationTests(unittest.TestCase):
    def test_cap_hits_are_episodes_with_hysteresis(self):
        values = [99.6, 99.7, 95, 89, 99.5, 90, 89, 99.4]
        rows = [row(NOW + index, value)
                for index, value in enumerate(values)]
        summary = history.summarize(7, rows=rows)[0]["windows"]["5h"]
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
            mock.patch.object(registry, "apply_pins"),
            mock.patch.object(registry, "dashboard_settings",
                              return_value={"redact_emails": False}),
            mock.patch.object(collect, "collect", return_value=self.private),
        )

    def test_hook_receives_exact_public_snapshot_after_publish(self):
        def verify(public):
            self.assertEqual(paths.load_json(paths.public_snapshot_path()), public)

        patches = self._patch_collect()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                mock.patch.object(history, "append_snapshot",
                                  side_effect=verify) as append:
            collect.run_collect(quiet=True)
        append.assert_called_once()

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


if __name__ == "__main__":
    unittest.main()
