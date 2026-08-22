"""The reading stamps must survive BOTH projections between collector and forecaster.

WHY THIS EXISTS (steward, 2026-08-22). ai-accounts/bin/collect.py allow lists
reading_age_seconds, reading_ceiling_seconds and reading_over_ceiling
deliberately, and its own comment says why: "without these three in the allow
list the fields are stripped before any reader sees them, which is how
reused_age_seconds came to exist with no consumer for so long".

They then crossed into headroom and were dropped again, by a DIFFERENT writer's
whitelist. Measured on the live estate that morning: 4 of 8 accounts carried a
reading_* field in the ai-accounts snapshot and 0 of 8 carried one in
headroom's. So the estate wrote the lesson down inside one program and repeated
the mistake in another, and two handoffs in a row asked for "a reader" when the
reader was never the missing part.

TWO PROJECTIONS, BOTH HAD TO LEARN THE FIELD:
  collect.external_claude_limits   the ingest boundary
  history._project_account         what the forecaster's history is built from

Fixing only the second achieves nothing, because its input is already stripped.

THE HALF THAT MUST NOT MOVE: an ABSENT stamp stays absent. A reader must be able
to tell "this account has no reading age" from "its reading age is zero", and a
defaulted field destroys exactly that distinction.
"""
import json
import math
import os
import sys

# HEADROOM_SUBJECT_DIR points at a PACKAGE directory, not a loose file. These
# modules do `from . import locks, paths`, so loading collect.py by path gives
# "attempted relative import with no known parent package". The control arm
# therefore uses a full package COPY with the pre fix files swapped in, and
# sys.path is pointed at its parent. A control that cannot import is not a
# control.
SUBJECT_PKG = os.environ.get("HEADROOM_SUBJECT_PKG")
FIELDS = ("reading_age_seconds", "reading_ceiling_seconds", "reading_over_ceiling")

if SUBJECT_PKG:
    sys.path.insert(0, os.path.dirname(os.path.abspath(SUBJECT_PKG)))
else:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from headroom import collect as _collect_mod   # noqa: E402
from headroom import history as _history_mod   # noqa: E402

# SAY WHICH BYTES ARE BEING GRADED. Every battery on this estate prints its
# subject for exactly this reason: a control arm that silently loads the live
# file passes and proves nothing.
print("SUBJECT collect.py:", _collect_mod.__file__)
print("SUBJECT history.py:", _history_mod.__file__)


def _load(name, filename):
    return _collect_mod if filename == "collect.py" else _history_mod


def _external_snapshot(tmp_path, row_extra):
    """An ai-accounts snapshot the ingest path will accept."""
    now = 1787400000
    row = {
        "name": "claude-probe",
        "provider": "claude",
        "ok": True,
        "windows": {
            "5h": {"used_percent": 40.0, "resets_at": now + 3600},
            "7d": {"used_percent": 20.0, "resets_at": now + 86400},
        },
        "observed_at": now - 60,
        "captured_at": now - 60,
        "email": "probe@domanskiops.com",
    }
    row.update(row_extra)
    doc = {"generated": now - 30, "accounts": [row]}
    path = tmp_path / "external.json"
    path.write_text(json.dumps(doc))
    return str(path), now


def _ingest(tmp_path, row_extra):
    collect = _load("subj_collect", "collect.py")
    path, now = _external_snapshot(tmp_path, row_extra)
    # The constant is referenced INSIDE the function body, so rebinding the
    # module global does reach it. That is NOT true of a default argument, which
    # binds at def time; the distinction cost this steward a round of vacuous
    # green elsewhere the same day, so the assertion below proves the rebind
    # actually took rather than assuming it.
    collect.EXTERNAL_CLAUDE_SNAPSHOT = path
    assert collect.EXTERNAL_CLAUDE_SNAPSHOT == path
    kind, payload = collect.external_claude_limits(
        "probe", {"email": "probe@domanskiops.com"}, now)
    assert kind == "ingest", (
        "the fixture did not reach the ingest path, so this case proves "
        "nothing: got %r %r" % (kind, payload))
    return payload


def test_ingest_carries_the_reading_stamps(tmp_path):
    payload = _ingest(tmp_path, {
        "reading_age_seconds": 1327,
        "reading_ceiling_seconds": 3600,
        "reading_over_ceiling": False,
    })
    assert payload["reading_age_seconds"] == 1327
    assert payload["reading_ceiling_seconds"] == 3600
    assert payload["reading_over_ceiling"] is False


def test_an_absent_stamp_stays_absent_at_ingest(tmp_path):
    payload = _ingest(tmp_path, {})
    for field in FIELDS:
        assert field not in payload, (
            "%s was invented for a row that never carried it, which destroys "
            "the difference between no reading age and a reading age of zero"
            % field)


def test_a_bogus_stamp_is_refused_at_ingest(tmp_path):
    payload = _ingest(tmp_path, {
        "reading_age_seconds": "quite old",
        "reading_ceiling_seconds": float("inf"),
    })
    assert "reading_age_seconds" not in payload
    assert "reading_ceiling_seconds" not in payload


def test_history_projection_carries_the_stamps():
    history = _load("subj_history", "history.py")
    account = {
        "id": "0123456789abcdef0123456789abcdef",
        "name": "probe",
        "provider": "claude",
        "ok": True,
        "windows": {"5h": {"used_percent": 40.0, "resets_at": 1787403600}},
        "reading_age_seconds": 1327,
        "reading_ceiling_seconds": 3600,
        "reading_over_ceiling": True,
    }
    projected = history._project_account(account)
    assert projected is not None, "the fixture account did not project at all"
    assert projected["reading_age_seconds"] == 1327
    assert projected["reading_ceiling_seconds"] == 3600
    assert projected["reading_over_ceiling"] is True


def test_history_projection_does_not_invent_stamps():
    history = _load("subj_history", "history.py")
    account = {
        "id": "0123456789abcdef0123456789abcdef",
        "name": "probe",
        "provider": "claude",
        "ok": True,
        "windows": {"5h": {"used_percent": 40.0, "resets_at": 1787403600}},
    }
    projected = history._project_account(account)
    assert projected is not None
    for field in FIELDS:
        assert field not in projected


def test_the_whole_chain_end_to_end(tmp_path):
    """Ingest then project, which is the path the forecaster's history follows.

    Fixing only one of the two achieves nothing, so the chain is graded as a
    chain rather than as two independent hops.
    """
    history = _load("subj_history", "history.py")
    payload = _ingest(tmp_path, {
        "reading_age_seconds": 735,
        "reading_ceiling_seconds": 3600,
        "reading_over_ceiling": False,
    })
    account = {
        "id": "0123456789abcdef0123456789abcdef",
        "name": "probe",
        "provider": "claude",
        "ok": True,
        "windows": payload["windows"],
    }
    for field in FIELDS:
        if field in payload:
            account[field] = payload[field]
    projected = history._project_account(account)
    assert projected["reading_age_seconds"] == 735
    assert projected["reading_over_ceiling"] is False
    assert math.isfinite(projected["reading_ceiling_seconds"])
