"""maximize (Fable-maximization calculator) unit tests — stdlib only.

Covers the stranding math, the fail-closed handling of unreadable windows,
the guard's demote/stand-down behavior, and the history ratio calibration's
conservative (upper-bound) direction.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401 — hermetic bootstrap; see tests/__init__.py

from headroom import maximize  # noqa: E402


def _row(used7d=20.0, fable_used=50.0, provider="claude", scoped=True,
         ok=True, stale=False):
    windows = {"5h": {"used_percent": 10.0, "resets_at": None},
               "7d": {"used_percent": used7d, "resets_at": 1000}}
    if scoped:
        windows["scoped:Fable"] = {"used_percent": fable_used,
                                   "resets_at": 2000}
    return {"name": "seat", "provider": provider, "ok": ok, "stale": stale,
            "windows": windows}


class SeatMetrics(unittest.TestCase):
    def test_ok_seat_has_positive_slack_and_nothing_at_risk(self):
        m = maximize.seat_metrics(_row(used7d=20.0, fable_used=50.0), 1.0)
        self.assertEqual(m["verdict"], "OK")
        self.assertAlmostEqual(m["usable"], 50.0)
        self.assertAlmostEqual(m["at_risk"], 0.0)
        self.assertAlmostEqual(m["slack"], 30.0)

    def test_at_risk_seat_counts_the_unreachable_fable(self):
        # 7d 1% left vs Fable 10% left: only 1% is reachable, 9% at risk.
        m = maximize.seat_metrics(_row(used7d=99.0, fable_used=90.0), 1.0)
        self.assertEqual(m["verdict"], "AT RISK")
        self.assertAlmostEqual(m["usable"], 1.0)
        self.assertAlmostEqual(m["at_risk"], 9.0)
        self.assertAlmostEqual(m["slack"], -9.0)

    def test_stranded_at_the_wall(self):
        # the post-mortem seat: 7d at 100% with half a Fable week unspent.
        m = maximize.seat_metrics(_row(used7d=100.0, fable_used=48.0), 1.0)
        self.assertEqual(m["verdict"], "STRANDED")
        self.assertAlmostEqual(m["usable"], 0.0)
        self.assertAlmostEqual(m["at_risk"], 52.0)

    def test_ratio_scales_what_fable_needs(self):
        # r=0.5: draining 40 Fable-% costs only 20 overall-%, so 30% overall
        # left covers it with 10% slack to spare.
        m = maximize.seat_metrics(_row(used7d=70.0, fable_used=60.0), 0.5)
        self.assertEqual(m["verdict"], "OK")
        self.assertAlmostEqual(m["slack"], 10.0)

    def test_unreadable_rows_score_none(self):
        self.assertIsNone(maximize.seat_metrics(None, 1.0))
        self.assertIsNone(maximize.seat_metrics(_row(provider="codex"), 1.0))
        self.assertIsNone(maximize.seat_metrics(_row(scoped=False), 1.0))
        expired = _row()
        expired["windows"]["scoped:Fable"]["freshness"] = "expired_observation"
        self.assertIsNone(maximize.seat_metrics(expired, 1.0))
        bad = _row()
        bad["windows"]["7d"]["used_percent"] = "high"
        self.assertIsNone(maximize.seat_metrics(bad, 1.0))

    def test_obsolete_collector_rows_score_none(self):
        # a stale or failed reading with valid-looking percentages must not
        # masquerade as stranded capacity in the calculator or tripwire
        self.assertIsNone(maximize.seat_metrics(
            _row(used7d=100.0, fable_used=48.0, ok=False), 1.0))
        self.assertIsNone(maximize.seat_metrics(
            _row(used7d=100.0, fable_used=48.0, stale=True), 1.0))


class PoolRatio(unittest.TestCase):
    def _cfg(self, value):
        return {"routing": {"fable_pool_ratio": value}}

    def test_default_and_garbage_yield_pessimistic_one(self):
        self.assertEqual(maximize.pool_ratio({}), 1.0)
        self.assertEqual(maximize.pool_ratio({"routing": []}), 1.0)
        self.assertEqual(maximize.pool_ratio(self._cfg("wide")), 1.0)

    def test_clamped_to_sane_band(self):
        self.assertEqual(maximize.pool_ratio(self._cfg(0.0)), 0.1)
        self.assertEqual(maximize.pool_ratio(self._cfg(9.0)), 2.0)
        self.assertEqual(maximize.pool_ratio(self._cfg(0.8)), 0.8)

    def test_non_finite_values_fall_back_pessimistic(self):
        # NaN/inf survive float() and would clamp to the PERMISSIVE end of
        # the band, under-protecting Fable — they must fall back to 1.0
        for garbage in ("nan", "inf", "-inf"):
            self.assertEqual(maximize.pool_ratio(self._cfg(garbage)), 1.0)
            self.assertEqual(
                maximize.pool_ratio(self._cfg(float(garbage))), 1.0)


class Guard(unittest.TestCase):
    def _entries(self, rows):
        return [({"name": name}, None, index, None)
                for index, name in enumerate(rows)]

    def test_unknown_seats_are_never_demoted(self):
        # a would be demoted on a reading, but has none; b is positive. The
        # guard acts on proof, so a stays eligible (ranked last elsewhere).
        rows = {"a": _row(scoped=False),
                "b": _row(used7d=10.0, fable_used=95.0)}
        guarded = maximize.fable_guard(self._entries(rows), "opus", rows, 1.0)
        self.assertTrue(all(reason is None for _, reason, _, _ in guarded))

    def test_non_guarded_family_passes_through(self):
        rows = {"a": _row(used7d=60.0, fable_used=20.0),
                "b": _row(used7d=10.0, fable_used=95.0)}
        entries = self._entries(rows)
        self.assertIs(maximize.fable_guard(entries, "fable", rows, 1.0),
                      entries)

    def test_already_blocked_rows_keep_their_reason(self):
        rows = {"a": _row(used7d=60.0, fable_used=20.0),
                "b": _row(used7d=10.0, fable_used=95.0)}
        entries = [({"name": "a"}, "7d at 100%", 0, None),
                   ({"name": "b"}, None, 1, None)]
        guarded = maximize.fable_guard(entries, "opus", rows, 1.0)
        self.assertEqual(guarded[0][1], "7d at 100%")


class Calibration(unittest.TestCase):
    def test_minimum_observed_ratio_wins(self):
        # same 7d window throughout; the cleanest (pure-Fable) interval has
        # the smallest delta ratio and is the tightest upper bound on r.
        # Each sample is widened to its rounding-safe ceiling (do+1)/(df-1):
        # intervals (10/10 -> 11/9) and (4/10 -> 5/9); the minimum wins.
        points = [(1, 10.0, 10.0, 99), (2, 20.0, 20.0, 99),
                  (3, 24.0, 30.0, 99)]
        self.assertAlmostEqual(maximize.calibrated_ratio(points), 5.0 / 9.0)

    def test_rounding_never_breaks_the_upper_bound(self):
        # the endpoint-rounding trap: true deltas 4.68/5.2 = 0.90 can display
        # as 5/6 = 0.83, below the true ratio. The widened sample (5+1)/(6-1)
        # = 1.2 stays a genuine upper bound.
        points = [(1, 10.0, 10.0, 99), (2, 15.0, 16.0, 99)]
        self.assertAlmostEqual(maximize.calibrated_ratio(points), 1.2)

    def test_reset_crossings_and_noise_are_discarded(self):
        points = [(1, 90.0, 80.0, 99), (2, 10.0, 5.0, 77),   # reset crossed
                  (3, 11.0, 8.0, 77),                        # delta too small
                  (4, 12.0, 6.0, 77)]                        # fable ran back
        self.assertIsNone(maximize.calibrated_ratio(points))

    def test_empty_history_yields_none(self):
        self.assertIsNone(maximize.calibrated_ratio([]))


class FleetReport(unittest.TestCase):
    def test_totals_sum_only_scored_seats(self):
        snapshot = {"accounts": [
            dict(_row(used7d=100.0, fable_used=48.0), name="wall"),
            dict(_row(used7d=20.0, fable_used=50.0), name="fine"),
            dict(_row(scoped=False), name="blind"),
        ]}
        accounts = [{"name": "wall", "provider": "claude"},
                    {"name": "fine", "provider": "claude"},
                    {"name": "blind", "provider": "claude"}]
        with mock.patch.object(maximize.registry, "ordered_for",
                               return_value=accounts):
            report, totals = maximize.fleet_report(snapshot, 1.0)
        self.assertEqual(totals["seats"], 2)
        self.assertAlmostEqual(totals["at_risk"], 52.0)
        self.assertAlmostEqual(totals["stranded_now"], 52.0)
        self.assertAlmostEqual(totals["usable"], 50.0)
        self.assertIsNone(dict((n, m) for n, m, _ in report)["blind"])


if __name__ == "__main__":
    unittest.main()
