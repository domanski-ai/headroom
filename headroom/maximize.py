"""Scoped-pool maximization calculator — keep the Fable week spendable.

A Claude Max seat carries TWO weekly budgets: the account-wide 7d window and a
model-scoped weekly pool for the frontier family (``scoped:Fable``). Spending
Fable draws BOTH down; spending any other family (Opus/Sonnet/Haiku) draws
only the account-wide window. The account-wide window is therefore the gate:
once it reads 100%, whatever remains in the Fable pool is unreachable until
the weekly reset — capacity paid for and provably wasted. (Fleet post-mortem,
2026-07: one seat hit its 7d wall on Opus traffic with 52% of its Fable week
unspent; two more seats were part-stranded the same week.)

Everything here is expressed in "% left" (the batteries convention):

  fable_left   = 100 - scoped:Fable used_percent
  overall_left = 100 - 7d used_percent
  ratio r      = how many % of the account-wide window one % of the Fable
                 pool costs (config ``routing.fable_pool_ratio``, default 1.0
                 — deliberately pessimistic: the account-wide pool is at least
                 as large as the scoped pool in every plan we have observed,
                 so the true r <= 1 and 1.0 over-protects Fable)
  usable_fable = min(fable_left, overall_left / r)
  at_risk      = fable_left - usable_fable  (becomes stranded at the 7d wall)
  slack        = overall_left - r * fable_left  (% of the account-wide window
                 spendable on NON-Fable work before it starts eating capacity
                 the Fable pool still needs; negative = already eaten into it)

Note ``at_risk > 0`` and ``slack < 0`` are the same condition at different
scales: at_risk counts the Fable-% unreachable, slack counts the overall-%
missing. Both appear in output because operators reason about both pools.

Consumers:

* ``headroom fable`` (:func:`cmd_fable`) — the calculator: per-seat and
  fleet-wide stranded / at-risk / slack report, with routing directives and
  an optional history-calibrated ratio estimate per seat.
* ``route.candidates`` — ranks NON-Fable Claude launches by descending slack
  (:func:`slack_for`) and demotes negative-slack seats whenever a
  positive-slack alternative is eligible (:func:`fable_guard`), so Opus-class
  work can no longer strand a seat's Fable week the way the post-mortem seat
  was stranded. Fable launches keep the most-Fable-room-first ranking.

This module must not import ``route`` at module level (route imports us);
``cmd_fable`` imports it lazily.
"""
import json
import math
import sys
import time

from . import registry

# Claude families whose launches are steered AWAY from Fable capacity. The
# generic "claude" family is deliberately absent: a generic session can switch
# to Fable mid-flight, so it keeps the most-Fable-room-first ranking.
NONFABLE_GUARDED = ("opus", "sonnet", "haiku")

# The scoped pool being maximized. Matching is case-insensitive substring over
# "scoped:<name>" keys, same as route.scoped_window_for.
RANKED_FAMILY = "fable"

# Below this many %-points, stranding is reading noise (percents arrive as
# integers), not a signal.
TOLERANCE = 0.5

# A calibration delta smaller than this drowns in integer rounding
# (used_percent has no decimals at the provider), so it never yields a sample.
MIN_CALIBRATION_DELTA = 5.0


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def pool_ratio(config=None):
    """``routing.fable_pool_ratio`` from config, clamped to [0.1, 2.0].

    Never raises — an absent/unreadable config yields the pessimistic default
    1.0 so the guard degrades toward over-protecting Fable, never under."""
    try:
        config = registry.load() if config is None else config
    except registry.RegistryError:
        return 1.0
    routing = (config or {}).get("routing")
    if not isinstance(routing, dict):
        return 1.0
    try:
        value = float(routing.get("fable_pool_ratio", 1.0))
    except (TypeError, ValueError):
        return 1.0
    if not math.isfinite(value):
        # NaN/inf survive float() and would clamp to the PERMISSIVE end of
        # the band (NaN compares false everywhere), under-protecting Fable —
        # non-finite config falls back to the pessimistic default instead.
        return 1.0
    return min(2.0, max(0.1, value))


def _window_left(window):
    """Remaining % of a window, or None without a current, sane reading.

    Mirrors route._fable_room's validity rules: an expired observation or a
    non-numeric/out-of-range percent proves nothing and must read as unknown
    (fail-closed), never as 0 or 100."""
    if not isinstance(window, dict):
        return None
    if window.get("freshness") == "expired_observation":
        return None
    pct = window.get("used_percent")
    if not _number(pct) or not 0 <= pct <= 100:
        return None
    return 100.0 - pct


def _scoped_window(windows):
    for key, window in (windows or {}).items():
        if key.startswith("scoped:") and RANKED_FAMILY in key.lower():
            return window
    return None


def seat_metrics(row, ratio):
    """Per-seat maximization metrics, or None when this row cannot be scored.

    Only CURRENT rows (collector ok, not stale) with BOTH a readable 7d
    window and a readable scoped-Fable window score; anything else returns
    None and the caller treats the seat as unknown (ranked last, never
    guarded — the guard must only act on proven readings). Routing callers
    only pass rows block_reason already admitted, so this gate exists for
    the calculator and the status tripwire, where an obsolete reading must
    not masquerade as stranded capacity."""
    if not isinstance(row, dict) or row.get("provider") != "claude":
        return None
    if row.get("ok") is not True or row.get("stale"):
        return None
    windows = row.get("windows")
    if not isinstance(windows, dict):
        return None
    scoped = _scoped_window(windows)
    fable_left = _window_left(scoped)
    overall_left = _window_left(windows.get("7d"))
    if fable_left is None or overall_left is None:
        return None
    usable = min(fable_left, overall_left / ratio)
    at_risk = max(0.0, fable_left - usable)
    slack = overall_left - ratio * fable_left
    if overall_left <= TOLERANCE and at_risk > TOLERANCE:
        verdict = "STRANDED"
    elif at_risk > TOLERANCE:
        verdict = "AT RISK"
    else:
        verdict = "OK"
    resets = (scoped or {}).get("resets_at")
    return {
        "fable_left": fable_left, "overall_left": overall_left,
        "usable": usable, "at_risk": at_risk, "slack": slack,
        "verdict": verdict,
        "resets_at": resets if _number(resets) else None,
    }


def slack_for(row, ratio):
    """Ranking signal for NON-Fable Claude launches: higher slack = safer
    seat to burn account-wide capacity on. None = unknown, ranks last."""
    metrics = seat_metrics(row, ratio)
    return None if metrics is None else metrics["slack"]


def fable_guard(entries, fam, rows, ratio):
    """Demote eligible seats a non-Fable launch would strand.

    ``entries`` is route.candidates' working list of (account, reason, index,
    room). For a guarded family, any ELIGIBLE seat with proven negative slack
    gains a block reason — but only while at least one eligible seat has
    proven POSITIVE slack to fall through to. When every readable seat is
    negative the guard stands down entirely: a degraded fleet still routes,
    ranked least-harm-first by the slack ordering. Unknown seats (no scoped
    reading) are never demoted — the guard acts on proof, not absence."""
    if fam not in NONFABLE_GUARDED:
        return entries
    scored = {}
    for account, reason, _, _ in entries:
        if reason is None:
            scored[account["name"]] = seat_metrics(rows.get(account["name"]),
                                                   ratio)
    if not any(m is not None and m["slack"] > 0 for m in scored.values()):
        return entries
    guarded = []
    for account, reason, index, room in entries:
        metrics = scored.get(account["name"])
        if reason is None and metrics is not None and metrics["slack"] < 0:
            reason = (f"fable guard: {fam} here would strand "
                      f"{metrics['at_risk']:.0f}% of the Fable week "
                      f"(slack {metrics['slack']:.0f}%)")
        guarded.append((account, reason, index, room))
    return guarded


def calibration_points(series_rows):
    """{seat name: [(ts, overall_used, fable_used, overall_resets_at)]} from
    history rows, keeping only samples where both weekly readings exist."""
    points = {}
    for row in sorted(series_rows, key=lambda r: r.get("ts") or 0):
        ts = row.get("ts")
        for account in row.get("accounts") or []:
            if account.get("provider") != "claude":
                continue
            if not account.get("ok") or account.get("stale"):
                continue
            windows = account.get("windows") or {}
            overall = windows.get("7d") or {}
            scoped = _scoped_window(windows) or {}
            o_used = overall.get("used_percent")
            f_used = scoped.get("used_percent")
            # bounds double as a finiteness gate: NaN/inf fail 0<=x<=100
            if not (_number(o_used) and 0 <= o_used <= 100
                    and _number(f_used) and 0 <= f_used <= 100):
                continue
            points.setdefault(account["name"], []).append(
                (ts, float(o_used), float(f_used),
                 overall.get("resets_at")))
    return points


def calibrated_ratio(points):
    """History-estimated pool ratio for one seat, or None without evidence.

    Between two samples inside the SAME 7d window, the account-wide burn is
    r * (Fable burn) + (non-Fable burn), so every observed
    delta(overall)/delta(fable) is an UPPER bound on the true r; the minimum
    across intervals is the tightest bound history supports. An upper bound
    is the conservative direction everywhere this ratio is used: it can only
    overstate what the Fable pool still needs, never understate it.

    Readings arrive as INTEGER percents, so each endpoint carries up to one
    point of rounding and a raw do/df can dip BELOW the true interval ratio
    (true 4.68/5.2 = 0.90 can display as 5/6 = 0.83). Every sample is
    therefore widened to its rounding-safe ceiling (do+1)/(df-1), which the
    true ratio can never exceed; MIN_CALIBRATION_DELTA keeps the widened
    denominator positive and the looseness bounded. Interval pairs that
    cross a reset, run backwards, or move less than MIN_CALIBRATION_DELTA
    Fable-% are discarded."""
    best = None
    for (_, o1, f1, r1), (_, o2, f2, r2) in zip(points, points[1:]):
        if r1 is None or r2 is None or r1 != r2:
            continue  # different (or unknowable) 7d window — reset crossed?
        df, do = f2 - f1, o2 - o1
        if df < MIN_CALIBRATION_DELTA or do < 0:
            continue
        sample = (do + 1.0) / (df - 1.0)
        if best is None or sample < best:
            best = sample
    if best is None:
        return None
    return min(1.5, max(0.1, best))


def _tfmt(epoch):
    if not _number(epoch):
        return "?"
    return time.strftime("%a %H:%M", time.localtime(epoch))


def fleet_report(snapshot, ratio, calibrations=None):
    """[(name, metrics-or-None, calibrated-ratio-or-None)] for every Claude
    account in registry order, plus a totals dict over the scored seats."""
    rows = {row["name"]: row
            for row in (snapshot or {}).get("accounts") or []
            if isinstance(row, dict) and row.get("name")}
    calibrations = calibrations or {}
    report, totals = [], {"fable_left": 0.0, "usable": 0.0, "at_risk": 0.0,
                          "stranded_now": 0.0, "seats": 0}
    for account in registry.ordered_for(RANKED_FAMILY):
        name = account["name"]
        metrics = seat_metrics(rows.get(name), ratio)
        report.append((name, metrics, calibrations.get(name)))
        if metrics is None:
            continue
        totals["seats"] += 1
        totals["fable_left"] += metrics["fable_left"]
        totals["usable"] += metrics["usable"]
        totals["at_risk"] += metrics["at_risk"]
        if metrics["verdict"] == "STRANDED":
            totals["stranded_now"] += metrics["at_risk"]
    return report, totals


def cmd_fable(args):
    """``headroom fable [--json] [--days N]`` — the maximization calculator."""
    from . import history, route  # lazy: route imports this module
    as_json = "--json" in args
    days = history.retention_days()
    if "--days" in args:
        try:
            days = max(1, int(args[args.index("--days") + 1]))
        except (IndexError, ValueError):
            print("usage: headroom fable [--json] [--days N]", file=sys.stderr)
            return 2
    snapshot = route.ensure_fresh_snapshot()
    ratio = pool_ratio()
    live_ids = {account.get("id") for account in registry.accounts()
                if account.get("id")}
    try:
        series = history.load_series(days, live_ids)
    except Exception:  # noqa: BLE001 — calibration is optional evidence
        series = []
    calibrations = {name: calibrated_ratio(points) for name, points
                    in calibration_points(series).items()}
    report, totals = fleet_report(snapshot, ratio, calibrations)

    if as_json:
        print(json.dumps({
            "ratio": ratio,
            "seats": [{"name": name,
                       "calibrated_ratio": calibration,
                       **(metrics or {"verdict": "NO READING"})}
                      for name, metrics, calibration in report],
            "totals": totals,
        }, sort_keys=True))
        return 1 if totals["at_risk"] > TOLERANCE else 0

    print(f"fable calculator — pool ratio {ratio:g} "
          f"(config routing.fable_pool_ratio; batteries: % LEFT)")
    header = (f"  {'seat':<16} {'fable':>6} {'7d':>6} {'usable':>7} "
              f"{'at-risk':>8} {'slack':>7}   verdict")
    print(header)
    for name, metrics, calibration in report:
        if metrics is None:
            print(f"  {name:<16} {'—':>6} {'—':>6} {'—':>7} {'—':>8} {'—':>7}"
                  "   NO READING (fail-closed: not guarded, ranked last)")
            continue
        note = ""
        if metrics["verdict"] == "STRANDED":
            note = f" until reset {_tfmt(metrics['resets_at'])}"
        elif calibration is not None and calibration < ratio \
                and metrics["at_risk"] > TOLERANCE:
            usable = min(metrics["fable_left"],
                         metrics["overall_left"] / calibration)
            note = (f" (history ratio ~{calibration:.2f} → "
                    f"~{metrics['fable_left'] - usable:.0f}% truly at risk)")
        print(f"  {name:<16} {metrics['fable_left']:>5.0f}% "
              f"{metrics['overall_left']:>5.0f}% {metrics['usable']:>6.0f}% "
              f"{metrics['at_risk']:>7.0f}% {metrics['slack']:>+6.0f}%   "
              f"{metrics['verdict']}{note}")

    if totals["seats"]:
        print(f"fleet: {totals['fable_left']:.0f} Fable-% left across "
              f"{totals['seats']} seats — {totals['usable']:.0f} usable, "
              f"{totals['at_risk']:.0f} stranded/at-risk "
              f"({totals['stranded_now']:.0f} already at the wall)")

    safe = [(name, metrics) for name, metrics, _ in report
            if metrics and metrics["slack"] > 0]
    unsafe = [(name, metrics) for name, metrics, _ in report
              if metrics and metrics["verdict"] == "AT RISK"]
    if safe:
        print("  non-Fable work → " + ", ".join(
            f"{name} (+{metrics['slack']:.0f}% slack)"
            for name, metrics in sorted(safe, key=lambda e: -e[1]["slack"])))
    if unsafe:
        print("  never non-Fable on → " + ", ".join(
            f"{name} (would strand {metrics['at_risk']:.0f}%)"
            for name, metrics in unsafe) + "   [fable guard enforces this]")
    return 1 if totals["at_risk"] > TOLERANCE else 0
