"""Display-only widget projection and SwiftBar rendering.

The widget contract deliberately contains observations, not routing advice.  It
is projected from the sanitized public snapshot and fails closed whenever a
timestamp, trust marker, or percentage cannot be proven current.
"""
import datetime
import math
import os
import time
import unicodedata
from urllib.parse import urlsplit

from . import paths


SCHEMA = "headroom_widget@1"
TEXT_SCHEMA = "headroom_widget_txt@1"
WINDOW_KEYS = ("5h", "7d")
SNAPSHOT_MAX_AGE = paths.env_int("HEADROOM_SNAPSHOT_MAX_AGE", 900)
OBSERVATION_MAX_AGE = paths.env_int("HEADROOM_OBSERVATION_MAX_AGE", 1800)
SCOPED_PREFIX = "scoped:"
# THE COLLECTOR'S CADENCE IS THE SCOPED POOL'S ONLY CLOCK (2026-08-18).
#
# Paul, 05:2xZ: "Why is the Domanski system not reading on the widgets ... why
# do we still have dead readings." Measured that morning on the live feed:
# account `system` showed 5h and 7d CURRENT and `scoped:Fable` STALE, observed
# 04:10Z, 54 minutes old. Two other seats were the same.
#
# The cause is a bar set against the wrong evidence, not a broken reading.
# 5h and 7d have a PER-TURN source: every live agent's statusline tees the
# provider's own rate_limit headers to ~/ai-accounts/state/session-truth and
# collect.apply_session_truth_rescue folds them into the row, so demanding
# those windows be under 30 minutes old is a bar they can actually clear.
# A model-scoped weekly pool has no such source. Its ONLY producer is the
# ai-accounts cron collector, which re-reads a given account roughly once
# every 50 minutes because the usage API rate-limits per source IP and the
# 2026-08-08 breach cost the estate two days of blind meter. Judging a source
# that refreshes on a ~50-minute cadence against a 30-minute bar means the
# gauge is dark for most of every hour BY ARITHMETIC. It had been since the
# 2026-08-09 budget halving, and nobody had wired the two numbers together.
#
# So the scoped windows get their own ceiling, and the ceiling is Paul's own
# 60-minute accuracy law PLUS this server's own serve cache. The collector
# side was moved in the same change (ai-accounts/bin/collect.py: rank over
# paid Claude seats only, TTL 2400, stagger 120): its worst SERVED age,
# measured as the age of the reading about to be replaced, is exactly 3600 s
# (verifier P1, 2026-08-18; the build first claimed 3000 by measuring after
# the refresh). That is the arithmetic floor for five paid seats on one call
# per 600 s cron run, so the collector sits AT the law, not inside it. On top
# of that, /widget.json is served through RefreshGate with success_ttl
# SERVE_MAX_AGE (300 s), so a reading the collector lawfully serves at 3599 s
# can be shown at 3899 s. A ceiling of 3600 here would call that lawful
# reading dead for up to five minutes a cycle on four seats, the exact
# flicker Paul reported at a different scale. So the ceiling is the law plus
# the serve cache: 3600 + 300. The two collector constants and this one are a
# TRIPLE with SERVE_MAX_AGE: raising any of them without re-running
# simulate_claude_refresh is the defect coming back.
SCOPED_OBSERVATION_MAX_AGE = paths.env_int(
    "HEADROOM_SCOPED_OBSERVATION_MAX_AGE", 3600 + 300)
# WHAT THE ACCOUNT ROW'S `stale` FLAG MEANS AFTER THIS CHANGE.
#
# collect.external_claude_limits stamps stale=True when the ingested reading is
# older than EXTERNAL_CLAUDE_MAX_AGE (720 s), and collect.apply_integrity turns
# that flag into trust_state "stale_observation". That flag is an AGE statement
# about the ACCOUNT-WIDE 5h and 7d numbers, measured against the bar those
# windows can clear because they have a per-turn source. It is not, and never
# was, a statement about the scoped weekly pool, whose clock is 50 minutes
# long. So a scoped window re-judges "stale_observation" against its own
# observed_at and its own ceiling, and every OTHER non-verified trust state
# (held, duplicate_identity, dashboard_only) still holds it closed: those are
# correctness verdicts, staleness is not. This is the same distinction the
# statusline made on 2026-08-10 when the Fable gauge went dark there.
SCOPED_AGE_TRUST_STATES = ("verified", "verified_local", "stale_observation")
DASHBOARD_HREF = "http://127.0.0.1:8377/"


def _number(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def _epoch(value):
    return value if _number(value) else None


def _freshness(snapshot, evaluated_at, force_noncurrent_reason=None):
    if (not isinstance(snapshot, dict)
            or not isinstance(snapshot.get("accounts"), list)):
        return {"state": "held", "age_seconds": None,
                "reason": "invalid_snapshot_shape",
                "evaluated_at": evaluated_at}
    generated = _epoch(snapshot.get("generated")) \
        if isinstance(snapshot, dict) else None
    if generated is None:
        return {"state": "held", "age_seconds": None,
                "reason": "missing_or_invalid_snapshot_time",
                "evaluated_at": evaluated_at}
    age = evaluated_at - generated
    age_seconds = max(0, int(math.floor(age)))
    if age < 0:
        return {"state": "held", "age_seconds": age_seconds,
                "reason": "clock_skew", "evaluated_at": evaluated_at}
    if force_noncurrent_reason:
        return {"state": "stale", "age_seconds": age_seconds,
                "reason": str(force_noncurrent_reason),
                "evaluated_at": evaluated_at}
    if age > SNAPSHOT_MAX_AGE:
        return {"state": "stale", "age_seconds": age_seconds,
                "reason": "snapshot_expired", "evaluated_at": evaluated_at}
    return {"state": "current", "age_seconds": age_seconds,
            "reason": "snapshot_current", "evaluated_at": evaluated_at}


def _is_unpaid(account):
    """A seat Paul has not paid for (2026-08-17).

    THE STATE STAYS INSIDE THE CONTRACT ENUM ON PURPOSE. headroom_widget@1
    consumers validate `state` against exactly {current, limited, stale,
    held} (dashboard/template.html hrValidFeed, both ubersicht widgets, and
    Paul's compiled menubar app, which cannot be updated from this server).
    On 2026-08-08 a novel state value ("carried") failed that enum and the
    menubar rendered the WHOLE feed as unreachable, which is the blank widget
    Paul has forbidden. So an unpaid seat projects "held" (grey, never red,
    which is exactly what unpaid should look like) and carries an ADDITIVE
    `unpaid: true` that every validator ignores.

    WHICH SURFACES ACTUALLY PRINT THE WORD, measured rather than assumed
    (grep -c unpaid integrations/ubersicht/*.jsx returns 0 for both): the
    SwiftBar text at /widget.txt and the dashboard page. The two ubersicht
    widgets draw batteries with no per-account text, so an unpaid seat shows
    there as a grey held bar with no numbers, which is honest; and Paul's
    compiled menubar app cannot be rebuilt from this server. Do not read this
    flag as fleet-wide coverage."""
    return (isinstance(account, dict)
            and (account.get("unpaid") is True
                 or account.get("error_code") == "unpaid"))


def _account_base_state(account, freshness, evaluated_at, scoped=False):
    """The row's trust verdict, as the account-wide windows see it.

    ``scoped=True`` answers the same question for a model-scoped weekly
    window, which differs in exactly two places and nowhere else: the age bar
    is SCOPED_OBSERVATION_MAX_AGE, and the ``stale`` flag (with the
    trust_state "stale_observation" it produces) is read as the age statement
    it is rather than as a correctness verdict. Every correctness gate below
    is shared, so a scoped window can never render on evidence the
    account-wide windows would have refused: not ok, wrong or unverifiable
    identity, a missing or future capture time, or a snapshot the feed itself
    cannot vouch for all still hold it closed.
    """
    if freshness["state"] == "held":
        return "held"
    if freshness["state"] == "stale":
        return "stale"
    if not isinstance(account, dict) or account.get("ok") is not True:
        return "held"
    # the display layer must accept exactly the trust states the router
    # routes on (route.block_reason): a slot verified via local credential
    # binding is routable and must not render as held
    trusted = SCOPED_AGE_TRUST_STATES if scoped else ("verified",
                                                      "verified_local")
    if account.get("trust_state") not in trusted:
        return "held"
    captured_at = _epoch(account.get("captured_at"))
    if captured_at is None or captured_at > evaluated_at:
        return "held"
    max_age = SCOPED_OBSERVATION_MAX_AGE if scoped else OBSERVATION_MAX_AGE
    if evaluated_at - captured_at > max_age:
        return "stale"
    if not scoped and account.get("stale") is True:
        return "stale"
    return "current"


def _window_projection(raw, captured_at, base_state, evaluated_at,
                       max_age=None):
    max_age = OBSERVATION_MAX_AGE if max_age is None else max_age
    resets_at = _epoch(raw.get("resets_at")) \
        if isinstance(raw, dict) else None
    observed_at = None
    used_percent = None
    valid_percent = False
    if isinstance(raw, dict):
        observed_at = _epoch(raw.get("observed_at", captured_at))
        used_percent = raw.get("used_percent")
        valid_percent = (_number(used_percent)
                         and 0 <= used_percent <= 100)
    last_left = 100.0 - float(used_percent) if valid_percent else None

    if not valid_percent or observed_at is None:
        state = "held"
    elif observed_at > evaluated_at:
        state = "held"
    elif base_state == "held":
        state = "held"
    elif base_state == "stale" \
            or evaluated_at - observed_at > max_age:
        state = "stale"
    elif used_percent >= 100:
        state = "limited"
    else:
        state = "current"

    return {
        "left_percent": last_left if state == "current" else None,
        "resets_at": resets_at,
        "observed_at": observed_at,
        "state": state,
        "last_observed_left_percent": (None if state == "current"
                                         else last_left),
    }


def _demote_windows(windows, state, keep=()):
    """Grey every window to ``state`` and park its number as last-observed.

    ``keep`` names windows that survived the demotion on their OWN evidence.
    It exists for model-scoped pools: the account row is demoted because its
    5h/7d reading aged past a bar those windows can clear, and applying that
    verdict to a weekly pool whose only producer refreshes hourly is the
    2026-08-18 dead-gauge defect. Nothing else may be kept, and a caller that
    passes nothing gets exactly the old behaviour.
    """
    for key, window in windows.items():
        if key in keep:
            continue
        if _number(window.get("left_percent")):
            window["last_observed_left_percent"] = window["left_percent"]
        window["left_percent"] = None
        window["state"] = state


def calculate_headline(accounts):
    """The glanceable metrics: fullest current 5h tank (legacy) plus the
    fleet's average battery per window.

    An average includes every LIVE reading: a current window contributes its
    left_percent and a limited window contributes 0 (an exhausted tank is an
    honest 0%, not a missing reading). Held/stale windows never count —
    unverified data must not move an average."""
    current = sum(1 for account in accounts
                  if account.get("state") == "current")
    candidates = []
    averages = {"5h": [], "7d": []}
    for account in accounts:
        windows = account.get("windows") or {}
        window = windows.get("5h") or {}
        value = window.get("left_percent")
        if (account.get("state") == "current"
                and window.get("state") == "current" and _number(value)):
            candidates.append(float(value))
        for key, pool in averages.items():
            entry = windows.get(key) or {}
            state = entry.get("state")
            left = entry.get("left_percent")
            if state == "current" and _number(left):
                pool.append(float(left))
            elif state == "limited":
                pool.append(0.0)
    def _avg(pool):
        return round(sum(pool) / len(pool), 1) if pool else None
    return {
        "current_accounts": current,
        "total_accounts": len(accounts),
        "fullest_5h_left_percent": max(candidates) if candidates else None,
        "avg_5h_left_percent": _avg(averages["5h"]),
        "avg_7d_left_percent": _avg(averages["7d"]),
    }


def project(snapshot, evaluated_at=None, force_noncurrent_reason=None):
    """Project a public usage snapshot to the ``headroom_widget@1`` contract."""
    evaluated_at = time.time() if evaluated_at is None else evaluated_at
    if not _number(evaluated_at):
        raise ValueError("evaluated_at must be a finite timestamp")
    freshness = _freshness(snapshot, evaluated_at, force_noncurrent_reason)
    raw_accounts = snapshot.get("accounts") \
        if isinstance(snapshot, dict) else None
    raw_accounts = raw_accounts if isinstance(raw_accounts, list) else []
    accounts = []
    for raw in raw_accounts:
        raw = raw if isinstance(raw, dict) else {}
        captured_at = _epoch(raw.get("captured_at"))
        base_state = _account_base_state(raw, freshness, evaluated_at)
        scoped_base_state = _account_base_state(raw, freshness, evaluated_at,
                                                scoped=True)
        raw_windows = raw.get("windows")
        raw_windows = raw_windows if isinstance(raw_windows, dict) else {}
        windows = {}
        for key in WINDOW_KEYS:
            raw_window = raw_windows.get(key)
            # The 5h window is optional ONLY for codex: OpenAI lifted Codex's
            # 5h, so a live codex seat reports only the weekly window. A
            # genuinely ABSENT 5h on a live codex account is a lifted limit —
            # omit it so it neither renders as a failed read nor poisons the
            # account state below. A PRESENT but malformed 5h (e.g. "5h": null
            # in a corrupt snapshot) is NOT lifted: it falls through and
            # projects held (fail-closed). For any other provider a missing 5h
            # is a failed read that must project held, and the weekly (7d) stays
            # mandatory for everyone: a missing 7d still holds the seat.
            if (key == "5h" and key not in raw_windows and base_state != "held"
                    and raw.get("provider") == "codex"):
                continue
            windows[key] = _window_projection(raw_window, captured_at,
                                              base_state, evaluated_at)
        # model-scoped weekly windows (e.g. "scoped:Fable") ride along for
        # display with the same projection/demotion rules — but they never
        # drive the ACCOUNT state below: a scoped model cap does not block
        # the account's other models
        for key, raw_window in raw_windows.items():
            if isinstance(key, str) and key.startswith(SCOPED_PREFIX) \
                    and key not in windows:
                windows[key] = _window_projection(
                    raw_window, captured_at, scoped_base_state, evaluated_at,
                    max_age=SCOPED_OBSERVATION_MAX_AGE)
        states = {window["state"] for key, window in windows.items()
                  if key in WINDOW_KEYS}
        if base_state == "held" or "held" in states:
            state = "held"
        elif base_state == "stale" or "stale" in states:
            state = "stale"
        elif "limited" in states:
            state = "limited"
        else:
            state = "current"
        if state in {"held", "stale"}:
            # A scoped pool that is still current on its OWN clock survives
            # the account row's demotion. The account row is demoted because
            # its 5h/7d evidence aged past a 30-minute bar those windows have
            # a per-turn source to clear; the weekly Fable pool does not, and
            # greying a good weekly number because a session window went quiet
            # is exactly the dead gauge Paul reported on 2026-08-18.
            keep = tuple(key for key, window in windows.items()
                         if key.startswith(SCOPED_PREFIX)
                         and window["state"] in ("current", "limited"))
            _demote_windows(windows, state, keep=keep)
        row = {
            "name": raw.get("name") if isinstance(raw.get("name"), str)
            else "unknown",
            "provider": (raw.get("provider")
                         if isinstance(raw.get("provider"), str) else "unknown"),
            "state": state,
            "windows": windows,
        }
        if _is_unpaid(raw):
            # held (grey) plus the additive flag; see _is_unpaid for why the
            # enum may not grow a fifth value.
            row["state"] = "held"
            row["unpaid"] = True
            _demote_windows(row["windows"], "held")
            for window in row["windows"].values():
                # an unpaid seat has no reading at all, not even an old one
                window["last_observed_left_percent"] = None
        accounts.append(row)
    result = {"schema": SCHEMA, "freshness": freshness,
              "accounts": accounts}
    result["headline"] = calculate_headline(accounts)
    return result


project_widget = project
headline = calculate_headline


def sanitize(value, limit=160):
    """Make field-derived text inert in a one-line SwiftBar label."""
    text = str(value if value is not None else "")
    text = "".join(" " if unicodedata.category(char) in ("Cc", "Cf") else char
                   for char in text)
    text = " ".join(text.split())
    # A pipe begins SwiftBar parameters.  Full-width replacements also ensure
    # hostile field text cannot spell an execution parameter such as `bash=`.
    text = text.replace("|", "¦").replace("=", "﹦")
    return text[:limit]


sanitize_swiftbar = sanitize


def _display_percent(value):
    if not _number(value):
        return "--"
    rounded = round(value, 1)
    return str(int(rounded)) if rounded.is_integer() else str(rounded)


def _reset_label(value):
    if not _number(value):
        return "reset unknown"
    try:
        stamp = datetime.datetime.fromtimestamp(
            value, datetime.timezone.utc).strftime("%Y-%m-%d %H:%MZ")
    except (OSError, OverflowError, ValueError):
        return "reset unknown"
    return "resets " + stamp


def _tone(value):
    if not _number(value):
        return "gray"
    if value <= 10:
        return "red"
    if value <= 50:
        return "orange"
    return "green"


def _dashboard_tone(value):
    if not _number(value):
        return "unknown"
    if value <= 10:
        return "red"
    if value <= 30:
        return "orange"
    if value <= 50:
        return "yellow"
    return "green"


def _canonical_dashboard_href(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (parsed.scheme != "http" or parsed.hostname not in
            {"127.0.0.1", "localhost"} or port is None
            or not 1 <= port <= 65535
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        return None
    return "http://127.0.0.1:{}/".format(port)


def project_dashboard(snapshot, evaluated_at=None, force_noncurrent_reason=None):
    """Return the central projection plus inert tones used by dashboard DOM."""
    evaluated_at = time.time() if evaluated_at is None else evaluated_at
    result = project(snapshot, evaluated_at, force_noncurrent_reason)
    raw_accounts = snapshot.get("accounts") if isinstance(snapshot, dict) else []
    for index, account in enumerate(result["accounts"]):
        raw = raw_accounts[index] if index < len(raw_accounts) else {}
        raw = raw if isinstance(raw, dict) else {}
        raw_windows = raw.get("windows")
        raw_windows = raw_windows if isinstance(raw_windows, dict) else {}
        base_state = _account_base_state(raw, result["freshness"], evaluated_at)
        scoped_base_state = _account_base_state(
            raw, result["freshness"], evaluated_at, scoped=True)
        for key, raw_window in raw_windows.items():
            if not isinstance(key, str) or key in account["windows"]:
                continue
            scoped = key.startswith(SCOPED_PREFIX)
            window = _window_projection(
                raw_window, _epoch(raw.get("captured_at")),
                scoped_base_state if scoped else base_state, evaluated_at,
                max_age=SCOPED_OBSERVATION_MAX_AGE if scoped else None)
            if account["state"] in {"held", "stale"} \
                    and not (scoped and window["state"] in ("current",
                                                            "limited")):
                _demote_windows({key: window}, account["state"])
            account["windows"][key] = window
        for window in account["windows"].values():
            if (account["state"] == "current"
                    and window["state"] == "current"):
                window["tone"] = _dashboard_tone(window["left_percent"])
            elif (account["state"] == "limited"
                  and window["state"] == "limited"):
                window["tone"] = "red"
            else:
                window["tone"] = "unknown"
    return result


def render_swiftbar(value, evaluated_at=None, force_noncurrent_reason=None,
                    dashboard_href=None, projection=None):
    """Render the one trusted SwiftBar representation, including sentinel.

    `projection` lets a caller hand in a projection it has already built and
    post-processed, instead of this function projecting the snapshot again.
    That is how the served text stays identical to the served JSON: the
    dashboard applies its never-blank last-good carry to the projection, and
    before 2026-08-16 this function re-projected from the raw snapshot and threw
    that work away, so /widget.txt showed "-- (held)" for the very seat
    /widget.json and the dashboard page were showing a number for. Three
    surfaces, one snapshot, three different answers. Omitted, behaviour is
    exactly as before.
    """
    href = _canonical_dashboard_href(dashboard_href) or DASHBOARD_HREF
    if value is None:
        return "\n".join([
            TEXT_SCHEMA,
            "hr OFFLINE | color=gray",
            "---",
            "Headroom feed unavailable | color=gray",
            "Refresh | refresh=true",
            "Open dashboard | href=" + href,
            "",
        ])
    widget = (projection if isinstance(projection, dict)
              else project(value, evaluated_at, force_noncurrent_reason))
    summary = widget["headline"]
    avg5 = summary["avg_5h_left_percent"]
    avg7 = summary["avg_7d_left_percent"]
    shown = _display_percent(avg5)
    suffix = shown + "%" if shown != "--" else shown
    shown7 = _display_percent(avg7)
    suffix7 = shown7 + "%" if shown7 != "--" else shown7
    lines = [TEXT_SCHEMA,
             "hr {}/{} · {} | color={}".format(
                 summary["current_accounts"], summary["total_accounts"],
                 suffix, _tone(avg5)),
             "---",
             "Avg battery: 5h {} · 7d {} | color=gray".format(
                 suffix if shown != "--" else "unavailable",
                 suffix7 if shown7 != "--" else "unavailable")]
    for account in widget["accounts"]:
        name = sanitize(account.get("name"))
        provider = sanitize(account.get("provider"))
        state = account.get("state") \
            if account.get("state") in {"current", "limited", "stale", "held"} \
            else "held"
        # The SwiftBar line is plain text, not the validated enum, so it may
        # say the true word.
        label_state = "unpaid" if account.get("unpaid") is True else state
        windows_map = account.get("windows") or {}
        # OpenAI lifted Codex's 5h: when the session window is absent, color the
        # account row from the weekly (7d) so a current codex seat reads green,
        # not grey. Every other provider always carries a 5h, so this falls back
        # to 7d only for a lifted-5h codex seat.
        primary = windows_map.get("5h") or windows_map.get("7d") or {}
        account_value = primary.get("left_percent")
        color = _tone(account_value) if state == "current" \
            else ("red" if state == "limited" else "gray")
        lines.append("{} · {} · {} | color={}".format(
            name, provider, label_state.upper(), color))
        for key in WINDOW_KEYS:
            # project() omits an absent 5h on a live codex seat (OpenAI lifted
            # it); skip the dropped key so a current seat gets no phantom
            # "--5h: -- (held)" sub-row. 7d is always present (mandatory).
            if key not in windows_map:
                continue
            window = windows_map.get(key) or {}
            window_state = window.get("state")
            current_value = window.get("left_percent")
            last_value = window.get("last_observed_left_percent")
            display = current_value if _number(current_value) else last_value
            percent = _display_percent(display)
            if percent != "--":
                percent += "% left"
            live = state == "current" and window_state == "current"
            limited = state == "limited" and window_state == "limited"
            label = percent if live else "{} ({})".format(
                percent, sanitize(window_state or "held"))
            lines.append("--{}: {} · {} | color={}".format(
                key, label, _reset_label(window.get("resets_at")),
                _tone(current_value) if live else ("red" if limited else "gray")))
    lines.extend(["---", "Refresh | refresh=true",
                  "Open dashboard | href=" + href])
    return "\n".join(lines) + "\n"
