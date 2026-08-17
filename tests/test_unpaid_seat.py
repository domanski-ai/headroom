"""An unpaid seat, from the collector row to the pixels Paul sees.

Paul, 2026-08-17: claude-ops and codex-gmail are UNPAID. "No reading is
CORRECT until Paul pays." Neither is a fault, neither is routable, neither
may nag for re-auth.

The subtle rule these tests pin, and the reason it is not simply a new state
value: headroom_widget@1 consumers validate `state` against exactly
{current, limited, stale, held}. dashboard/template.html's hrValidFeed does,
both ubersicht widgets do, and Paul's compiled menubar app does, and that app
cannot be updated from this server. On 2026-08-08 a novel state ("carried")
failed that enum and the whole feed rendered as unreachable. So an unpaid row
projects "held" plus an ADDITIVE `unpaid: true`, and the renderers we own
read the flag to print the word.
"""
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401 - hermetic bootstrap; see tests/__init__.py

from headroom import collect, dashboard, paths, route, widget  # noqa: E402

NOW = 2_000_000_000
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE = os.path.join(ROOT, "dashboard", "template.html")


def unpaid_row(name="ops", provider="claude"):
    return {"id": "a" * 12, "name": name, "provider": provider,
            "ok": False, "error_code": "unpaid",
            "note": "unpaid; no reading expected until it is paid",
            "identity_verified": False, "trust_state": "held",
            "routable": False, "unpaid": True}


def unpaid_row_with_numbers(name="ops"):
    """The shape the widget's unpaid branch actually defends against.

    The plain fixture above has no windows and already projects held on its
    own, so forcing the state, demoting the windows and blanking
    last_observed were all unexercised: the reproduce lens mutated each of
    those three lines and the suite stayed green. This row carries a full
    reading AND the unpaid flag, which is what reaches the projector whenever
    a row is marked unpaid while a reading for it is still in flight (the
    estate registry knows about the bill before this config row does, and the
    carry shim can hand a stored row forward). Under that input each of the
    three lines is load-bearing.
    """
    row = paid_row(name)
    row.update({"error_code": "unpaid", "unpaid": True, "routable": False})
    return row


def paid_row(name="system"):
    windows = {
        "5h": {"used_percent": 10.0, "resets_at": NOW + 3600,
               "observed_at": NOW - 60, "window_minutes": 300},
        "7d": {"used_percent": 20.0, "resets_at": NOW + 86400,
               "observed_at": NOW - 60, "window_minutes": 10080},
    }
    return {"id": "b" * 12, "name": name, "provider": "claude", "ok": True,
            "trust_state": "verified", "routable": True, "stale": False,
            "captured_at": NOW - 60, "windows": windows}


def snapshot(rows):
    return {"schema_version": 1, "run_id": "r", "run_started": NOW - 120,
            "generated": NOW - 30, "generated_iso": "x", "accounts": rows}


class TheCollectorAnswersWithoutReadingIt(unittest.TestCase):
    def test_the_short_circuit_beats_every_provider_call(self):
        """Every provider surface is a home that does not exist. An unpaid row
        must still come out clean, which is what proves nothing read it."""
        accounts = [
            {"id": "a" * 12, "name": "ops", "provider": "claude",
             "home": "/nonexistent/ops", "expected_email": "ops@example.test",
             "status": "unpaid"},
            {"id": "c" * 12, "name": "codex-gmail", "provider": "codex",
             "home": "/nonexistent/codex", "expected_email": "cg@example.test",
             "status": "unpaid"},
        ]
        rows = {r["name"]: r for r in collect.collect(accounts)["accounts"]}
        for name in ("ops", "codex-gmail"):
            row = rows[name]
            self.assertIs(row["ok"], False, name)
            self.assertEqual(row["error_code"], "unpaid", name)
            self.assertEqual(row["trust_state"], "held", name)
            self.assertIs(row["routable"], False, name)
            self.assertIs(row["unpaid"], True, name)
            self.assertNotIn("retry_at", row)
            self.assertNotIn("windows", row)

    def test_the_flag_reaches_the_public_snapshot(self):
        self.assertIn("unpaid", collect.PUBLIC_FIELDS)

    def test_the_ingest_never_dresses_it_as_a_throttle(self):
        self.assertIn("unpaid", collect.EXTERNAL_HELD_CODES)

    def test_the_ingest_path_says_the_same_words_as_the_short_circuit(self):
        """The membership assertion above never DRIVES the raise. It shipped
        while the handler had no arm for the code, so an unpaid row that
        arrived through the estate ingest (config row not marked, estate
        registry marked) fell to the generic else and published "run
        `headroom connect` to re-login" on the public feed: the exact re-auth
        nagging Paul banned, plus an em dash, on a surface B1 newly routes
        into. This drives it."""
        account = {"id": "a" * 12, "name": "ops", "provider": "claude",
                   "home": "/nonexistent/ops",
                   "expected_email": "ops@example.test"}
        identity = {"verified": True, "method": "probe",
                    "email": "ops@example.test",
                    "account_fingerprint": "0123456789abcdef"}
        with mock.patch.object(collect, "claude_identity",
                               lambda home: dict(identity)), \
             mock.patch.object(collect, "credential_digest",
                               lambda provider, home: "dig"), \
             mock.patch.object(collect, "claude_plan", lambda home: "Max 20x"), \
             mock.patch.object(collect, "_auth_resident", lambda home: None), \
             mock.patch.object(collect, "external_claude_limits",
                               lambda name, ident, now: ("held", "unpaid")):
            row = collect.collect([account])["accounts"][0]
        self.assertEqual(row["error_code"], "unpaid")
        self.assertEqual(row["note"],
                         "unpaid; no reading expected until it is paid")
        self.assertIs(row["unpaid"], True)
        self.assertIs(row["routable"], False)
        for word in ("re-login", "connect", "sign in", "re-authenticate"):
            self.assertNotIn(word, row["note"])
        self.assertNotIn("\u2014", row["note"])

    def test_waiting_is_never_the_answer_to_a_bill(self):
        self.assertIn("unpaid", route.MUST_DISARM_ERROR_CODES)
        self.assertNotIn("unpaid", route.UNREADABLE_ERROR_CODES)


class TheWidgetDrawsItGreyAndSaysWhy(unittest.TestCase):
    def project(self, rows):
        value = widget.project(snapshot(rows), evaluated_at=NOW)
        return {a["name"]: a for a in value["accounts"]}, value

    def test_the_state_stays_inside_the_validated_enum(self):
        rows, _ = self.project([unpaid_row(), paid_row()])
        self.assertEqual(rows["ops"]["state"], "held")
        self.assertIn(rows["ops"]["state"],
                      {"current", "limited", "stale", "held"})

    def test_the_row_carries_the_additive_flag(self):
        rows, _ = self.project([unpaid_row(), paid_row()])
        self.assertIs(rows["ops"]["unpaid"], True)
        self.assertNotIn("unpaid", rows["system"])

    def test_an_unpaid_row_shows_no_numbers_at_all(self):
        rows, _ = self.project([unpaid_row(), paid_row()])
        for window in rows["ops"]["windows"].values():
            self.assertIsNone(window["left_percent"])
            self.assertIsNone(window["last_observed_left_percent"])

    def test_it_never_moves_the_fleet_average(self):
        _rows, value = self.project([unpaid_row(), paid_row()])
        self.assertEqual(value["headline"]["avg_5h_left_percent"], 90.0)
        self.assertEqual(value["headline"]["current_accounts"], 1)

    def test_a_row_that_arrives_carrying_numbers_is_still_stripped(self):
        """Mutating any of the three lines in the widget's unpaid branch left
        the suite green, because the plain fixture has no windows to demote.
        With a reading attached, each line is the only thing standing between
        Paul and a full battery on a seat he has not paid for."""
        rows, value = self.project([unpaid_row_with_numbers(), paid_row()])
        self.assertEqual(rows["ops"]["state"], "held")
        for window in rows["ops"]["windows"].values():
            self.assertIsNone(window["left_percent"])
            self.assertIsNone(window["last_observed_left_percent"])
        self.assertEqual(value["headline"]["current_accounts"], 1)
        self.assertEqual(value["headline"]["avg_5h_left_percent"], 90.0)

    def test_the_swiftbar_line_says_the_word(self):
        text = widget.render_swiftbar(snapshot([unpaid_row(), paid_row()]),
                                      dashboard_href="http://127.0.0.1:8377/")
        line = next(l for l in text.splitlines() if l.startswith("ops "))
        self.assertIn("UNPAID", line)
        self.assertIn("color=gray", line)
        self.assertNotIn("color=red", line)


class TheLastGoodCarryLeavesItAlone(unittest.TestCase):
    """The carry reads a STORE on disk. A test that never seeds it never
    enters the branch it is meant to pin: the reproduce lens deleted the
    unpaid guard and this class stayed green. Every test below seeds the
    store first, so the guard is the only thing that can keep the numbers
    off the row.
    """

    def store_path(self):
        return os.path.join(paths.state_dir(), "widget-lastgood-rows.json")

    def seed(self, names):
        """Seed the carry store inside a HEADROOM_DIR of this test's own.

        The suite shares one disposable HEADROOM_DIR, and writing the store
        into it leaked: with this file running first, test_widgets read the
        seeded rows and three of its dashboard projections flipped. Measured,
        then fixed by isolation rather than by cleanup, because a cleanup
        still leaves the directory in a state the next test did not expect.
        """
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        patched = mock.patch.dict(os.environ,
                                  {"HEADROOM_DIR": temporary.name})
        patched.start()
        self.addCleanup(patched.stop)
        path = self.store_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        remembered = widget.project(snapshot([paid_row(name) for name in names]),
                                    evaluated_at=NOW)
        store = {row["name"]: {"row": row, "saved_at": NOW - 600}
                 for row in remembered["accounts"]}
        with open(path, "w") as handle:
            json.dump(store, handle)
        return path

    def read_store(self):
        with open(self.store_path()) as handle:
            return json.load(handle)

    def test_no_stored_numbers_are_resurrected_onto_an_unpaid_seat(self):
        self.seed(["ops", "system"])
        value = widget.project(snapshot([unpaid_row(), paid_row()]),
                               evaluated_at=NOW)
        carried = dashboard._carry_lastgood_rows(json.loads(json.dumps(value)))
        row = next(a for a in carried["accounts"] if a["name"] == "ops")
        self.assertNotEqual(row.get("served_from"), "lastgood")
        self.assertIsNone(row.get("reading_source"))
        for window in row["windows"].values():
            self.assertIsNone(window["left_percent"])
            self.assertIsNone(window["last_observed_left_percent"])

    def test_the_stored_row_is_dropped_so_paying_starts_from_a_real_read(self):
        self.seed(["ops", "system"])
        value = widget.project(snapshot([unpaid_row(), paid_row()]),
                               evaluated_at=NOW)
        dashboard._carry_lastgood_rows(json.loads(json.dumps(value)))
        self.assertNotIn("ops", self.read_store())

    def test_a_paid_seat_is_still_carried(self):
        """Proof the seeding works, and that the guard is narrow: without
        this, a broken store would make the test above pass for the wrong
        reason."""
        self.seed(["ops", "system"])
        blind = paid_row("system")
        blind.update({"ok": False, "windows": {}, "trust_state": "held"})
        value = widget.project(snapshot([blind]), evaluated_at=NOW)
        carried = dashboard._carry_lastgood_rows(json.loads(json.dumps(value)))
        row = next(a for a in carried["accounts"] if a["name"] == "system")
        self.assertEqual(row.get("served_from"), "lastgood")


class ThePageSaysUnpaidInTheCalmTone(unittest.TestCase):
    """The rendered row is dashboard/template.html, which is what Paul's
    menubar app actually draws. Asserted on the source, because the page is
    built from this template at serve time."""

    def setUp(self):
        with open(TEMPLATE) as handle:
            self.source = handle.read()

    def test_the_account_card_branches_on_unpaid_first(self):
        body = self.source.split("function accountState(account){", 1)[1]
        head = body.split('const state=displayState(account);', 1)[0]
        self.assertIn('unpaid===true', head)
        self.assertIn('error_code==="unpaid"', head)
        self.assertIn('label:"Unpaid"', head)

    def test_the_unpaid_card_is_never_the_alarm_tone(self):
        body = self.source.split("function accountState(account){", 1)[1]
        head = body.split('const state=displayState(account);', 1)[0]
        self.assertIn('cls:"idle"', head)
        self.assertNotIn('cls:"limited"', head)

    def test_the_unpaid_card_never_asks_for_a_login(self):
        body = self.source.split("function accountState(account){", 1)[1]
        head = body.split('const state=displayState(account);', 1)[0]
        for word in ("login", "sign in", "re-auth", "reauth"):
            self.assertNotIn(word, head.lower())

    def test_the_account_row_no_longer_prints_the_tier(self):
        """Paul: the tier "should be completely eliminated as a factor"."""
        markup = self.source.split("function accountMarkup(", 1)[1].split("\n}", 1)[0]
        self.assertNotIn("account.plan", markup)
        self.assertIn("esc(account.provider)", markup)

    def test_the_feed_validator_still_rejects_a_fifth_state(self):
        """The reason `unpaid` is an additive flag and not a state. If this
        enum ever grows, revisit widget._is_unpaid deliberately, not by
        accident."""
        self.assertIn('["current","limited","stale","held"].includes(a.state)',
                      re.sub(r"\s+", "", self.source))


if __name__ == "__main__":
    unittest.main()
