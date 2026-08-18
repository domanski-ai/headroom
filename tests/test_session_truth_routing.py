"""Routing on the seat's own live statusline tee when the collector is old.

2026-08-17, rescue-path repair. The estate collector refreshes a given Claude
seat roughly once an hour on purpose (its per-source-IP call budget), so for
most of every hour a healthy seat's reading is older than
EXTERNAL_CLAUDE_MAX_AGE, arrives stale, and apply_integrity stamps it
stale_observation / routable False. Measured the same day: the dead man drill
could not find a routable seat in the same minute across five samples, and the
one rotation it did attempt was re-routed away by the router itself.

The cure adds a SECOND witness, never a wider window: a stale row whose own
session-truth tee is under 30 minutes old, names this account, carries both
required windows and shows 5h left above the routing floor is re-based on that
tee and routes with the named basis "tee-fresh". A row with neither a fresh
collector reading nor a fresh tee is held exactly as before. Every test below
pins one half of that sentence.
"""
import inspect
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401 - hermetic bootstrap; see tests/__init__.py

from headroom import collect, route  # noqa: E402

NOW = 2_000_000_000.0
FLOOR = 15.0


def stale_row(name="system", used5h=3.0, used7d=33.0, age=4809, **over):
    """A Claude row shaped exactly as the ingest leaves an old reading.

    Modelled on the live claude-system row the drill was refused on
    (captured_age 4809, ok True, stale True).
    """
    captured = int(NOW - age)
    row = {
        "id": "a" * 12, "name": name, "provider": "claude", "plan": "Max 20x",
        "ok": True, "stale": True, "captured_at": captured,
        "source": "ai_accounts_snapshot", "identity_verified": False,
        "identity": {"verified": False, "account_fingerprint": "AAAA",
                     "credential_digest": "BBBB"},
        "windows": {
            "5h": {"used_percent": used5h, "resets_at": captured + 3600,
                   "severity": "normal", "is_active": False,
                   "window_minutes": 300, "observed_at": captured},
            "7d": {"used_percent": used7d, "resets_at": captured + 8 * 86400,
                   "severity": "normal", "is_active": False,
                   "window_minutes": 10080, "observed_at": captured},
        },
    }
    row.update(over)
    return row


def tee(account="claude-system", used5h=3.0, used7d=33.0, age=460,
        schema="session_truth@1", **over):
    payload = {
        "schema": schema, "account": account,
        "captured_at": int(NOW - age), "provenance": "session_header",
        "windows": {
            "5h": {"used_percent": used5h, "resets_at": int(NOW + 15000)},
            "7d": {"used_percent": used7d, "resets_at": int(NOW + 500000)},
        },
    }
    payload.update(over)
    return payload


class TeeDirCase(unittest.TestCase):
    """Every test writes its own tee directory; nothing reads the live one."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="headroom-tee-")
        self._patches = [
            mock.patch.object(collect, "SESSION_TRUTH_DIR", self.dir),
            mock.patch.object(collect, "SESSION_TRUTH_ROUTING", 1),
            mock.patch.object(collect, "SESSION_TRUTH_MAX_AGE", 1800),
            mock.patch.object(collect, "SESSION_TRUTH_RESCUE_AFTER", 1800),
        ]
        for patch in self._patches:
            patch.start()
            self.addCleanup(patch.stop)

    def write(self, name, payload):
        path = os.path.join(self.dir, name + ".json")
        with open(path, "w") as handle:
            json.dump(payload, handle)
        return path

    def read(self, name="system", **kwargs):
        kwargs.setdefault("floor", FLOOR)
        return collect.session_truth_reading(name, NOW, **kwargs)


class TheTeeIsReadFailClosed(TeeDirCase):
    def test_a_fresh_matching_tee_reads(self):
        self.write("claude-system", tee())
        payload, why = self.read()
        self.assertIsNone(why)
        self.assertEqual(payload["captured_at"], int(NOW - 460))
        self.assertEqual(payload["left_5h"], 97.0)

    def test_the_bare_account_name_is_tried_too(self):
        self.write("system", tee(account="system"))
        payload, why = self.read()
        self.assertIsNone(why)
        self.assertEqual(payload["age"], 460)

    def test_no_tee_at_all_refuses(self):
        payload, why = self.read()
        self.assertIsNone(payload)
        self.assertIn("no session-truth tee", why)

    def test_an_old_tee_refuses(self):
        self.write("claude-system", tee(age=1801))
        payload, why = self.read()
        self.assertIsNone(payload)
        self.assertIn("older than", why)

    def test_a_tee_from_the_future_refuses(self):
        self.write("claude-system", tee(age=-3600))
        payload, why = self.read()
        self.assertIsNone(payload)
        self.assertIn("future", why)

    def test_a_tee_naming_another_account_refuses(self):
        # the one way this could ever serve a wrong seat's numbers
        self.write("claude-system", tee(account="claude-gmail"))
        payload, why = self.read()
        self.assertIsNone(payload)
        self.assertIn("names", why)

    def test_a_foreign_schema_refuses(self):
        self.write("claude-system", tee(schema="session_truth@2"))
        payload, why = self.read()
        self.assertIsNone(payload)
        self.assertIn("schema", why)

    def test_unreadable_json_refuses(self):
        with open(os.path.join(self.dir, "claude-system.json"), "w") as handle:
            handle.write("{not json")
        payload, why = self.read()
        self.assertIsNone(payload)
        self.assertIn("unreadable", why)

    def test_a_missing_weekly_window_refuses(self):
        payload = tee()
        del payload["windows"]["7d"]
        self.write("claude-system", payload)
        got, why = self.read()
        self.assertIsNone(got)
        self.assertIn("7d window missing", why)

    def test_a_non_numeric_percentage_refuses(self):
        payload = tee()
        payload["windows"]["5h"]["used_percent"] = "3"
        self.write("claude-system", payload)
        got, why = self.read()
        self.assertIsNone(got)
        self.assertIn("5h reading invalid", why)

    def test_a_boolean_percentage_refuses(self):
        payload = tee()
        payload["windows"]["5h"]["used_percent"] = True
        self.write("claude-system", payload)
        got, why = self.read()
        self.assertIsNone(got)
        self.assertIn("5h reading invalid", why)

    def test_at_the_routing_floor_refuses(self):
        # 15% left with a 15% floor is not ABOVE the floor
        self.write("claude-system", tee(used5h=85.0))
        payload, why = self.read()
        self.assertIsNone(payload)
        self.assertIn("routing floor", why)

    def test_below_the_routing_floor_refuses(self):
        self.write("claude-system", tee(used5h=99.0))
        payload, why = self.read()
        self.assertIsNone(payload)
        self.assertIn("1% left", why)

    def test_just_above_the_routing_floor_reads(self):
        self.write("claude-system", tee(used5h=84.9))
        payload, why = self.read()
        self.assertIsNone(why)
        self.assertAlmostEqual(payload["left_5h"], 15.1, places=6)

    def test_the_kill_switch_refuses_everything(self):
        self.write("claude-system", tee())
        with mock.patch.object(collect, "SESSION_TRUTH_ROUTING", 0):
            payload, why = self.read()
        self.assertIsNone(payload)
        self.assertIn("disabled", why)


class TheRescuePass(TeeDirCase):
    def rescue(self, rows):
        # the floor is pinned rather than read from config: the hermetic
        # bootstrap points HEADROOM_DIR at an empty temp dir, where
        # registry.reserve_percent() degrades to 0 and every "spent seat"
        # assertion below would pass for the wrong reason
        return collect.apply_session_truth_rescue(rows, now=NOW, floor=FLOOR)

    def integrity(self, rows):
        collect.apply_session_truth_rescue(rows, now=NOW, floor=FLOOR)
        collect.apply_integrity(rows)
        return rows

    def test_a_stale_row_with_a_fresh_tee_becomes_routable(self):
        self.write("claude-system", tee())
        rows = [stale_row()]
        self.assertEqual(self.rescue(list(rows)), ["system"])
        row = self.integrity(rows)[0]
        self.assertIs(row["stale"], False)
        self.assertEqual(row["trust_state"], "verified_local")
        self.assertIs(row["routable"], True)
        self.assertEqual(row["routing_basis"], "tee-fresh")
        self.assertEqual(row["captured_at"], int(NOW - 460))
        self.assertEqual(row["windows"]["5h"]["used_percent"], 3.0)
        self.assertEqual(row["windows"]["5h"]["observed_at"], int(NOW - 460))

    def test_a_stale_row_with_no_tee_stays_held(self):
        row = self.integrity([stale_row()])[0]
        self.assertIs(row["stale"], True)
        self.assertEqual(row["trust_state"], "stale_observation")
        self.assertIs(row["routable"], False)
        self.assertNotIn("routing_basis", row)
        self.assertIn("no session-truth tee", row["tee_note"])

    def test_a_stale_row_with_a_stale_tee_stays_held(self):
        self.write("claude-system", tee(age=3600))
        row = self.integrity([stale_row()])[0]
        self.assertIs(row["routable"], False)
        self.assertEqual(row["trust_state"], "stale_observation")

    def test_a_spent_tee_does_not_rescue(self):
        self.write("claude-system", tee(used5h=99.0))
        row = self.integrity([stale_row()])[0]
        self.assertIs(row["routable"], False)
        self.assertIn("routing floor", row["tee_note"])

    def test_a_held_row_is_never_rescued(self):
        self.write("claude-gmail", tee(account="claude-gmail"))
        row = stale_row(name="gmail", ok=False,
                        error_code="claude_local_binding_missing")
        out = self.integrity([row])[0]
        self.assertEqual(out["trust_state"], "held")
        self.assertIs(out["routable"], False)
        self.assertNotIn("routing_basis", out)

    def test_an_unpaid_row_is_never_rescued(self):
        self.write("claude-ops", tee(account="claude-ops"))
        row = stale_row(name="ops", ok=False, error_code="unpaid")
        out = self.integrity([row])[0]
        self.assertEqual(out["trust_state"], "held")
        self.assertIs(out["unpaid"], True)
        self.assertNotIn("routing_basis", out)

    def test_a_fresh_row_is_never_overwritten(self):
        # the tee here passes every gate and is NEWER than the row, so only
        # the "already fresh" guard can hold it off. A reading the collector
        # still vouches for stays authoritative: the tee rescues rows the
        # collector has given up on, it does not quietly re-base live ones.
        self.write("claude-system", tee(used5h=50.0, age=100))
        row = stale_row(stale=False, age=900)
        out = self.integrity([row])[0]
        self.assertEqual(out["windows"]["5h"]["used_percent"], 3.0)
        self.assertEqual(out["captured_at"], int(NOW - 900))
        self.assertNotIn("routing_basis", out)
        self.assertNotIn("tee_note", out)
        self.assertIs(out["routable"], True)

    def test_a_reading_the_router_would_expire_is_rescued_even_when_not_stale(self):
        # THE LIVE CASE, 2026-08-17T17:03Z: headroom-serve ingests at 3600s so
        # the row is not marked stale, and route.block_reason still refuses it
        # with "reading expired" past OBSERVATION_MAX_AGE. Eligibility is the
        # union of both gates or this repair fixes only half the failure.
        self.write("claude-system", tee())
        row = stale_row(stale=False, age=2100)
        out = self.integrity([row])[0]
        self.assertEqual(out["routing_basis"], "tee-fresh")
        self.assertEqual(out["captured_at"], int(NOW - 460))
        self.assertIs(out["routable"], True)

    def test_a_reading_inside_the_observation_window_is_left_alone(self):
        self.write("claude-system", tee(used5h=50.0, age=100))
        row = stale_row(stale=False, age=1799)
        out = self.integrity([row])[0]
        self.assertNotIn("routing_basis", out)
        self.assertEqual(out["captured_at"], int(NOW - 1799))

    def test_a_tee_older_than_the_reading_does_not_rescue(self):
        self.write("claude-system", tee(age=1000))
        row = stale_row(age=900)
        out = self.integrity([row])[0]
        self.assertIs(out["routable"], False)
        self.assertIn("not newer", out["tee_note"])

    def test_a_codex_row_is_untouched(self):
        self.write("claude-system", tee())
        row = stale_row(provider="codex")
        out = self.integrity([row])[0]
        self.assertNotIn("routing_basis", out)
        self.assertEqual(out["trust_state"], "stale_observation")

    def test_the_kill_switch_restores_the_old_behaviour(self):
        self.write("claude-system", tee())
        with mock.patch.object(collect, "SESSION_TRUTH_ROUTING", 0):
            row = self.integrity([stale_row()])[0]
        self.assertIs(row["routable"], False)
        self.assertEqual(row["trust_state"], "stale_observation")

    def test_a_critical_flag_survives_inside_the_same_window(self):
        # hold-only signals are carried forward: the window has not rolled and
        # usage has not fallen, so an old critical still stands
        self.write("claude-system", tee(used5h=80.0))
        row = stale_row(used5h=79.0)
        row["windows"]["5h"]["severity"] = "critical"
        row["windows"]["5h"]["is_active"] = True
        # the tee reports the same reset time as the stored window
        payload = tee(used5h=80.0)
        payload["windows"]["5h"]["resets_at"] = row["windows"]["5h"]["resets_at"]
        self.write("claude-system", payload)
        out = self.integrity([row])[0]
        self.assertEqual(out["windows"]["5h"]["severity"], "critical")
        self.assertIs(out["windows"]["5h"]["is_active"], True)

    def test_a_critical_flag_is_dropped_when_the_window_rolled(self):
        row = stale_row(used5h=95.0)
        row["windows"]["5h"]["severity"] = "critical"
        row["windows"]["5h"]["is_active"] = True
        self.write("claude-system", tee(used5h=3.0))
        out = self.integrity([row])[0]
        self.assertNotIn("severity", out["windows"]["5h"])
        self.assertNotIn("is_active", out["windows"]["5h"])
        self.assertIs(out["routable"], True)


class TheRouterSaysWhatItRoutedOn(unittest.TestCase):
    def setUp(self):
        self.now = NOW
        self._orig_binding = collect.local_binding
        collect.local_binding = lambda provider, home: ("AAAA", "BBBB")
        self.addCleanup(
            lambda: setattr(collect, "local_binding", self._orig_binding))

    def reason(self, row):
        return route.block_reason(
            {"name": row["name"], "provider": "claude",
             "home": "/tmp/hr-t/" + row["name"]},
            "sonnet", row, {}, self.now, reserve=FLOOR)

    def test_a_rescued_row_passes_the_router(self):
        row = stale_row()
        row.update({"stale": False, "captured_at": int(NOW - 460),
                    "trust_state": "verified_local", "routable": True,
                    "routing_basis": "tee-fresh"})
        for key in ("5h", "7d"):
            row["windows"][key]["observed_at"] = int(NOW - 460)
        self.assertIsNone(self.reason(row))

    def test_an_unrescued_stale_row_is_still_refused(self):
        row = stale_row()
        row.update({"trust_state": "stale_observation", "routable": False})
        self.assertEqual(self.reason(row),
                         "trust unverified: stale_observation")

    def test_routing_basis_reads_the_named_evidence(self):
        self.assertEqual(
            route.routing_basis({"routing_basis": "tee-fresh"}), "tee-fresh")
        self.assertIsNone(route.routing_basis({}))
        self.assertIsNone(route.routing_basis(None))
        self.assertIsNone(route.routing_basis({"routing_basis": ""}))

    def test_status_names_the_basis_on_the_seat_it_routed(self):
        import io
        from contextlib import redirect_stdout
        row = stale_row()
        row["routing_basis"] = "tee-fresh"
        plain = stale_row(name="mzansiedge")
        snapshot = {"accounts": [row, plain]}
        accounts = [{"name": "system", "provider": "claude"},
                    {"name": "mzansiedge", "provider": "claude"}]
        buffer = io.StringIO()
        with mock.patch.object(route, "ensure_fresh_snapshot",
                               return_value=snapshot), \
                mock.patch.object(route, "candidates",
                                  return_value=[(accounts[0], None),
                                                (accounts[1], None)]), \
                mock.patch.object(route.registry, "family_provider",
                                  return_value="codex"), \
                redirect_stdout(buffer):
            route.cmd_status("sonnet")
        out = buffer.getvalue()
        self.assertIn("tee-fresh", out)
        # the seat with no rescue must not borrow the label
        line = [ln for ln in out.splitlines() if "mzansiedge" in ln][0]
        self.assertNotIn("tee-fresh", line)


class TheKillSwitchIsHonest(unittest.TestCase):
    """HEADROOM_SESSION_TRUTH_ROUTING=0 must actually hold a tee-fresh seat.

    X1 P1, 2026-08-17. collect read the switch at COLLECT time and the rescue
    is persisted into the snapshot, so a row already stamped
    routing_basis="tee-fresh" kept routing for as long as that snapshot lived
    no matter what the operator set. route.py now reads the same variable and
    refuses those rows, which is the half that makes the disarm bind on the
    file that already exists. These tests pin both halves and the boundary
    between them.
    """

    def setUp(self):
        self._orig_binding = collect.local_binding
        collect.local_binding = lambda provider, home: ("AAAA", "BBBB")
        self.addCleanup(
            lambda: setattr(collect, "local_binding", self._orig_binding))

    def rescued_row(self):
        """A row exactly as apply_session_truth_rescue leaves it."""
        row = stale_row()
        row.update({"stale": False, "captured_at": int(NOW - 460),
                    "trust_state": "verified_local", "routable": True,
                    "routing_basis": "tee-fresh"})
        for key in ("5h", "7d"):
            row["windows"][key]["observed_at"] = int(NOW - 460)
        return row

    def reason(self, row):
        return route.block_reason(
            {"name": row["name"], "provider": "claude",
             "home": "/tmp/hr-t/" + row["name"]},
            "sonnet", row, {}, NOW, reserve=FLOOR)

    def test_armed_the_persisted_rescue_still_routes(self):
        # the control: without it, the test below proves nothing
        self.assertIsNone(self.reason(self.rescued_row()))

    def test_disarmed_the_persisted_rescue_is_held(self):
        with mock.patch.object(route, "SESSION_TRUTH_ROUTING", 0):
            reason = self.reason(self.rescued_row())
        self.assertIsNotNone(reason, "a tee-fresh row routed with the switch "
                                     "off: the snapshot outlived the disarm")
        self.assertIn("HEADROOM_SESSION_TRUTH_ROUTING=0", reason)

    def test_disarmed_an_ordinary_fresh_row_is_untouched(self):
        # the switch may only ever refuse rows the rescue actually touched
        row = self.rescued_row()
        row.pop("routing_basis")
        with mock.patch.object(route, "SESSION_TRUTH_ROUTING", 0):
            self.assertIsNone(self.reason(row))

    def test_both_modules_read_the_one_variable(self):
        """A second variable name, or a default of 0 in one module and 1 in
        the other, is the same silent half-disarm in a new costume."""
        declaration = 'paths.env_int("HEADROOM_SESSION_TRUTH_ROUTING", 1)'
        for module in (collect, route):
            self.assertEqual(inspect.getsource(module).count(declaration), 1,
                             f"{module.__name__} must read the switch once, "
                             "under that name, defaulting to armed")
        self.assertEqual(collect.SESSION_TRUTH_ROUTING,
                         route.SESSION_TRUTH_ROUTING)

    def test_the_disarm_is_documented_where_it_has_to_be_set(self):
        """The unit is where an operator sets it for the serve process, and a
        switch nobody can find is a switch nobody can pull."""
        unit = os.path.expanduser(
            "~/.config/systemd/user/headroom-serve.service")
        if not os.path.exists(unit):
            self.skipTest("no headroom-serve unit on this host")
        with open(unit) as handle:
            text = handle.read()
        self.assertIn("HEADROOM_SESSION_TRUTH_ROUTING", text)
        self.assertIn("restart headroom-serve", text)


class TheRescueIsWiredIntoTheCollectRun(unittest.TestCase):
    """The rescue is worthless unless collect() calls it, and calls it FIRST.

    apply_integrity is the call that turns ``stale`` into ``routable``. A
    rescue that ran after it would leave every rescued row stamped
    stale_observation and unroutable while looking, in isolation, correct.
    """

    def _calls(self):
        import ast
        import inspect
        import textwrap
        tree = ast.parse(textwrap.dedent(inspect.getsource(collect.collect)))
        return [node.func.id for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)]

    def test_collect_calls_the_rescue_before_apply_integrity(self):
        calls = self._calls()
        self.assertIn("apply_session_truth_rescue", calls)
        self.assertIn("apply_integrity", calls)
        self.assertLess(calls.index("apply_session_truth_rescue"),
                        calls.index("apply_integrity"))


if __name__ == "__main__":
    unittest.main()
