"""Widget contract, refresh gate, integrations, and release artifact tests."""
import hashlib
import io
import json
import math
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, redirect_stdout
from unittest import mock

from headroom import __main__, dashboard, history, paths, registry, widget


NOW = 2_000_000_000
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE = shutil.which("node")
UBERSICHT = os.path.join(ROOT, "integrations", "ubersicht")
PLUGIN = os.path.join(ROOT, "integrations", "swiftbar", "headroom.1m.sh")
WINDOWS_SCRIPT = os.path.join(ROOT, "experimental", "windows",
                              "headroom-tray.ps1")
WINDOWS_ICONS = os.path.join(ROOT, "experimental", "windows", "icons")


def slot_id(name):
    return hashlib.sha256(name.encode()).hexdigest()[:12]


def usage_account(name="alpha", used5=20.0, used7=40.0, **overrides):
    account = {
        "id": slot_id(name),
        "name": name,
        "provider": "claude",
        "ok": True,
        "stale": False,
        "trust_state": "verified",
        "captured_at": NOW - 20,
        "windows": {
            "5h": {"used_percent": used5, "resets_at": NOW + 1800,
                   "observed_at": NOW - 20},
            "7d": {"used_percent": used7, "resets_at": NOW + 86400,
                   "observed_at": NOW - 20},
        },
    }
    account.update(overrides)
    return account


def usage_snapshot(*accounts, generated=None):
    return {"schema_version": 1, "generated": NOW - 30 if generated is None
            else generated, "accounts": list(accounts)}


class MutableClock:
    def __init__(self, value=NOW):
        self.value = value

    def __call__(self):
        return self.value


def memory_get(handler_class, directory, route, host="127.0.0.1:8377",
               server_port=None):
    """Drive the real request handler without opening a sandbox-blocked socket."""
    handler = object.__new__(handler_class)
    handler.directory = directory
    handler.path = route
    handler.headers = {"Host": host}
    handler.command = "GET"
    handler.request_version = "HTTP/1.1"
    handler.requestline = "GET %s HTTP/1.1" % route
    handler.client_address = ("127.0.0.1", 1)
    if server_port is not None:
        server = object.__new__(dashboard.http.server.ThreadingHTTPServer)
        server.server_address = ("127.0.0.1", server_port)
        handler.server = server
    handler.close_connection = True
    handler.wfile = io.BytesIO()
    handler.do_GET()
    raw = handler.wfile.getvalue()
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.lower()] = value.strip()
    return status, headers, body


class WidgetContractTests(unittest.TestCase):
    def test_widget_contract_has_exact_versioned_shape(self):
        value = widget.project(usage_snapshot(usage_account()), NOW)
        self.assertEqual(set(value), {"schema", "freshness", "accounts",
                                      "headline"})
        self.assertEqual(value["schema"], "headroom_widget@1")
        self.assertEqual(set(value["freshness"]),
                         {"state", "age_seconds", "reason", "evaluated_at"})
        self.assertEqual(set(value["accounts"][0]["windows"]), {"5h", "7d"})
        self.assertEqual(set(value["accounts"][0]),
                         {"name", "provider", "state", "windows"})
        for window in value["accounts"][0]["windows"].values():
            self.assertEqual(set(window), {"left_percent", "resets_at",
                                           "observed_at", "state",
                                           "last_observed_left_percent"})

    def test_widget_projection_covers_all_account_states(self):
        accounts = [
            usage_account("current"),
            usage_account("limited", used5=100),
            usage_account("stale", stale=True),
            usage_account("held", ok=False, trust_state="held"),
        ]
        states = {row["name"]: row["state"]
                  for row in widget.project(usage_snapshot(*accounts), NOW)[
                      "accounts"]}
        self.assertEqual(states, {"current": "current", "limited": "limited",
                                  "stale": "stale", "held": "held"})

    def test_scoped_windows_ride_along_without_driving_account_state(self):
        account = usage_account("fabled")
        account["windows"]["scoped:Fable"] = {
            "used_percent": 100.0, "resets_at": NOW + 5 * 86400,
            "observed_at": NOW - 20, "window_minutes": 10080}
        row = widget.project(usage_snapshot(account), NOW)["accounts"][0]
        # the scoped weekly cap is VISIBLE (limited, 0 observed left)…
        scoped = row["windows"]["scoped:Fable"]
        self.assertEqual(scoped["state"], "limited")
        self.assertEqual(scoped["last_observed_left_percent"], 0.0)
        # …but a scoped model cap never blocks the account's other models
        self.assertEqual(row["state"], "current")
        # and it never moves the fleet averages (5h/7d only)
        headline = widget.project(usage_snapshot(account), NOW)["headline"]
        self.assertEqual(headline["avg_5h_left_percent"], 80.0)

    def test_verified_local_renders_current_not_held(self):
        # regression: the display layer must accept every trust state the
        # router routes on — verified_local slots rendered as "held, never
        # promoted to live" across the widget/SwiftBar/dashboard (2026-07-14)
        accounts = [
            usage_account("local", trust_state="verified_local"),
            usage_account("other", trust_state="verified_remote"),
        ]
        states = {row["name"]: row["state"]
                  for row in widget.project(usage_snapshot(*accounts), NOW)[
                      "accounts"]}
        self.assertEqual(states, {"local": "current", "other": "held"})

    def test_current_window_exposes_left_percent(self):
        window = widget.project(usage_snapshot(usage_account(used5=12.5)), NOW)[
            "accounts"][0]["windows"]["5h"]
        self.assertEqual(window["state"], "current")
        self.assertEqual(window["left_percent"], 87.5)
        self.assertIsNone(window["last_observed_left_percent"])

    def test_noncurrent_window_hides_live_value(self):
        window = widget.project(
            usage_snapshot(usage_account(stale=True, used5=25)), NOW)[
                "accounts"][0]["windows"]["5h"]
        self.assertEqual(window["state"], "stale")
        self.assertIsNone(window["left_percent"])
        self.assertEqual(window["last_observed_left_percent"], 75.0)

    def test_missing_windows_are_explicitly_held(self):
        account = usage_account()
        del account["windows"]["7d"]
        projected = widget.project(usage_snapshot(account), NOW)["accounts"][0]
        self.assertEqual(projected["state"], "held")
        self.assertEqual(projected["windows"]["5h"]["state"], "held")
        self.assertIsNone(projected["windows"]["5h"]["left_percent"])
        self.assertEqual(projected["windows"]["5h"][
            "last_observed_left_percent"], 80.0)
        self.assertEqual(projected["windows"]["7d"]["state"], "held")
        self.assertIsNone(projected["windows"]["7d"]["left_percent"])

    def test_lifted_5h_is_omitted_not_held(self):
        # OpenAI lifted Codex's 5h: a live seat reports only the weekly window.
        # An absent 5h must be OMITTED, never projected as held — a held 5h
        # would poison the account state and grey out a current seat. (The
        # weekly stays mandatory; see test_missing_windows_are_explicitly_held.)
        account = usage_account("codexmain", provider="codex")
        del account["windows"]["5h"]
        account["windows"]["scoped:Spark"] = {
            "used_percent": 3.0, "resets_at": NOW + 600000,
            "observed_at": NOW - 20}
        projected = widget.project(usage_snapshot(account), NOW)["accounts"][0]
        self.assertEqual(projected["state"], "current")
        self.assertNotIn("5h", projected["windows"])
        self.assertEqual(projected["windows"]["7d"]["state"], "current")
        self.assertEqual(
            projected["windows"]["scoped:Spark"]["state"],
            "current")

    def test_non_codex_missing_5h_projects_held(self):
        # 5h is optional ONLY for codex. A claude seat missing its 5h is a
        # failed read: it must project HELD (fail-closed), never be omitted the
        # way a lifted codex 5h is.
        account = usage_account("cl")  # provider defaults to "claude"
        del account["windows"]["5h"]
        projected = widget.project(usage_snapshot(account), NOW)["accounts"][0]
        self.assertEqual(projected["state"], "held")
        self.assertEqual(projected["windows"]["5h"]["state"], "held")

    def test_present_but_malformed_5h_holds_codex(self):
        # only a genuinely ABSENT 5h is lifted; a present-but-null 5h (corrupt
        # snapshot) is NOT lifted — it must project held, never be omitted.
        account = usage_account("cx", provider="codex")
        account["windows"]["5h"] = None
        projected = widget.project(usage_snapshot(account), NOW)["accounts"][0]
        self.assertEqual(projected["state"], "held")
        self.assertIn("5h", projected["windows"])
        self.assertEqual(projected["windows"]["5h"]["state"], "held")

    def test_one_stale_window_demotes_every_child_window(self):
        account = usage_account()
        account["windows"]["7d"]["observed_at"] = (
            NOW - widget.OBSERVATION_MAX_AGE - 1)
        projected = widget.project(usage_snapshot(account), NOW)["accounts"][0]
        self.assertEqual(projected["state"], "stale")
        for key, last in (("5h", 80.0), ("7d", 60.0)):
            self.assertEqual(projected["windows"][key]["state"], "stale")
            self.assertIsNone(projected["windows"][key]["left_percent"])
            self.assertEqual(projected["windows"][key][
                "last_observed_left_percent"], last)

    def test_widget_projection_rejects_out_of_range_values(self):
        bad_values = [-0.1, 100.1, float("inf"), float("nan"), "20", True]
        for bad in bad_values:
            with self.subTest(value=bad):
                account = usage_account()
                account["windows"]["5h"]["used_percent"] = bad
                window = widget.project(usage_snapshot(account), NOW)[
                    "accounts"][0]["windows"]["5h"]
                self.assertEqual(window["state"], "held")
                self.assertIsNone(window["left_percent"])
                self.assertIsNone(window["last_observed_left_percent"])

    def test_widget_projection_rejects_clock_skew(self):
        future_snapshot = widget.project(
            usage_snapshot(usage_account(), generated=NOW + 1), NOW)
        self.assertEqual(future_snapshot["freshness"]["state"], "held")
        account = usage_account()
        account["windows"]["5h"]["observed_at"] = NOW + 1
        future_window = widget.project(usage_snapshot(account), NOW)[
            "accounts"][0]["windows"]["5h"]
        self.assertEqual(future_window["state"], "held")
        self.assertIsNone(future_window["left_percent"])

    def test_freshness_age_uses_evaluated_at(self):
        value = widget.project(
            usage_snapshot(usage_account(), generated=NOW - 25), NOW)
        self.assertEqual(value["freshness"], {
            "state": "current", "age_seconds": 25,
            "reason": "snapshot_current", "evaluated_at": NOW})

    def test_widget_contract_omits_routing_claims(self):
        rendered = json.dumps(widget.project(
            usage_snapshot(usage_account()), NOW)).lower()
        for forbidden in ("best", "accounts_ok", "routable", "eligibility",
                          "eligible", "reserve", "recommendation"):
            self.assertNotIn(forbidden, rendered)

    def test_headline_carries_fullest_and_average_batteries(self):
        value = widget.project(usage_snapshot(
            usage_account("a", used5=55), usage_account("b", used5=8)), NOW)
        self.assertEqual(value["headline"], {
            "current_accounts": 2, "total_accounts": 2,
            "fullest_5h_left_percent": 92.0,
            "avg_5h_left_percent": 68.5,   # (45 + 92) / 2
            "avg_7d_left_percent": 60.0})

    def test_headline_excludes_noncurrent_candidates(self):
        value = widget.project(usage_snapshot(
            usage_account("current", used5=60),
            usage_account("limited", used5=100),
            usage_account("stale", used5=1, stale=True),
            usage_account("held", used5=0, ok=False, trust_state="held")), NOW)
        self.assertEqual(value["headline"]["current_accounts"], 1)
        self.assertEqual(value["headline"]["fullest_5h_left_percent"], 40.0)
        # the average counts LIVE windows only: current 40 left + limited 0;
        # stale/held never move it. The limited account's 7d window is still
        # current, so both 7d readings (60) count.
        self.assertEqual(value["headline"]["avg_5h_left_percent"], 20.0)
        self.assertEqual(value["headline"]["avg_7d_left_percent"], 60.0)

    def test_headline_without_candidate_is_gray_placeholder(self):
        value = usage_snapshot(usage_account(stale=True, used5=1))
        rendered = widget.render_swiftbar(value, NOW)
        self.assertIn("hr 0/1 · -- | color=gray", rendered.splitlines()[1])


# Drives the REAL dashboard template JS under node: exercise both consumer
# paths — the main dashboard (displayState/windowMarkup) and the compact widget
# (hrValidFeed/hrAccount/hrAcctMarkup/hrBarsMarkup) — with a lifted-5h codex
# seat and a fail-closed non-codex seat, and print one JSON verdict object.
_CODEX_5H_TAIL = r"""
;(function () {
  snapshotState = "current"; sourceFailed = false;
  const nowS = Date.now() / 1e3;
  const projWin = (state, left) => ({ state: state,
    left_percent: state === "current" ? left : null,
    last_observed_left_percent: state === "current" ? null : left,
    resets_at: nowS + 3600, observed_at: nowS - 30 });
  // main-dashboard account: RAW windows carry no 5h and the __display
  // projection (server-side widget.project) also omits it — exactly what a
  // lifted-5h codex seat looks like.
  const mainAcct = (provider) => ({ name: "cx", provider: provider,
    captured_at: nowS - 30,
    windows: { "7d": { used_percent: 20, resets_at: nowS + 8 * 86400 } },
    __display: { state: "current",
                 windows: { "7d": projWin("current", 80) } } });
  // compact-widget feed account (headroom_widget@1): 7d only, no 5h.
  const feedWin = { state: "current", left_percent: 80,
    last_observed_left_percent: null, resets_at: nowS + 3600,
    observed_at: nowS - 30 };
  const mkFeed = (provider) => ({ schema: "headroom_widget@1",
    freshness: { state: "current", age_seconds: 30, reason: "ok",
                 evaluated_at: nowS },
    accounts: [{ name: "cx", provider: provider, state: "current",
                 windows: { "7d": feedWin } }],
    headline: { current_accounts: 1, total_accounts: 1,
                fullest_5h_left_percent: null } });
  const acct = hrAccount({ name: "cx", provider: "codex", state: "current",
    windows: { "7d": feedWin } }, false);
  const acctMarkup = hrAcctMarkup(acct);
  const bars = hrBarsMarkup({ accts: [acct] });
  console.log(JSON.stringify({
    codex_displayState: displayState(mainAcct("codex")),
    claude_displayState: displayState(mainAcct("claude")),
    codex_5h_markup: windowMarkup(mainAcct("codex"), "5h"),
    codex_feed_valid: hrValidFeed(mkFeed("codex")),
    claude_feed_valid: hrValidFeed(mkFeed("claude")),
    hr_state: acct.state,
    hr_has5h: acct.has5h,
    hr_tile_fill: acct.tile.fill,
    hr_markup_has_5h_label: /class="hr-wlabel">5H</.test(acctMarkup),
    hr_markup_has_7d_label: /class="hr-wlabel">7D</.test(acctMarkup),
    hr_markup_has_na: acctMarkup.indexOf(">n/a<") !== -1,
    hr_bar_unknown: bars.indexOf("hr-tone-unknown") !== -1,
    hr_bar_green: bars.indexOf("hr-tone-green") !== -1
  }));
})();
"""


class CodexLiftedFiveHourDashboardJS(unittest.TestCase):
    """Execution-level coverage for the dashboard's optional-5h handling
    (dashboard/template.html). OpenAI lifted Codex's 5h, so a live codex seat
    reports only the weekly window: both the main-dashboard state path and the
    compact-widget path must keep it live (never grey/held), while a NON-codex
    seat missing its 5h still fails closed."""

    @staticmethod
    def _harness():
        with open(dashboard.TEMPLATE) as handle:
            html = handle.read()
        section = html.split(
            "/* ------------------------------------------------------------- helpers */",
            1)[1].split(
            "/* --------------------------------------------------------------- theme */",
            1)[0]
        return ("const OBSERVATION_MAX_AGE=1800,SNAPSHOT_MAX_AGE=900;\n"
                + section + _CODEX_5H_TAIL)

    @unittest.skipUnless(NODE, "node runtime required to execute dashboard JS")
    def test_lifted_5h_keeps_codex_live_but_holds_non_codex(self):
        proc = subprocess.run([NODE, "-"], input=self._harness(),
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        # F2: a live codex seat with a lifted 5h stays CURRENT on the main
        # dashboard; a claude seat missing its 5h fails closed to HELD.
        self.assertEqual(out["codex_displayState"], "current")
        self.assertEqual(out["claude_displayState"], "held")
        # F5: the codex 5h cell reads a neutral "no 5h limit", never "n/a".
        self.assertIn("no 5h limit", out["codex_5h_markup"])
        self.assertNotIn("n/a", out["codex_5h_markup"])
        # F6: the compact-widget validator accepts a codex feed with no 5h but
        # rejects a non-codex feed with no 5h (5h stays mandatory off codex).
        self.assertTrue(out["codex_feed_valid"])
        self.assertFalse(out["claude_feed_valid"])
        # F4: the compact widget renders the codex seat CURRENT with the battery
        # tile driven by 7d (filled/green), no phantom "5H" row or "n/a".
        self.assertEqual(out["hr_state"], "current")
        self.assertFalse(out["hr_has5h"])
        self.assertEqual(out["hr_tile_fill"], 80)
        self.assertFalse(out["hr_markup_has_5h_label"])
        self.assertTrue(out["hr_markup_has_7d_label"])
        self.assertFalse(out["hr_markup_has_na"])
        self.assertFalse(out["hr_bar_unknown"])
        self.assertTrue(out["hr_bar_green"])


class TokenChartMathJS(unittest.TestCase):
    @staticmethod
    def _harness():
        with open(dashboard.TEMPLATE) as handle:
            template = handle.read()
        validator = "function validate" + template.split(
            "function validate", 1)[1].split(
                "function withoutTokenStats", 1)[0]
        functions = "function tokenNumber" + template.split(
            "function tokenNumber", 1)[1].split(
                "function renderTokenStats", 1)[0]
        tail = r"""
const browserNow=Date.parse("2026-01-10T18:00:00Z");
Date.now=()=>browserNow;
const days={
  "2026-01-01":{grand_total:10},
  "2026-01-03":{grand_total:30},
  "2027-01-01":{grand_total:999}
};
const windowDays={
  "2026-01-01":{grand_total:10},
  "2026-01-03":{grand_total:30}
};
const weekly=tokenWeeklySeries(windowDays,"2026-01-11");
const cumulative=tokenCumulativeSeries(windowDays,"2026-01-05");
const count={input:1,output:1,cache_read:0,cache_creation:0,total:2,grand_total:2};
const generated=Date.parse("2026-01-10T12:00:00Z")/1e3;
const statsPayload=(summary={},accounts=[])=>({generated:generated,
  days:{"2026-01-10":Object.assign({},count)},accounts:accounts,
  summary:Object.assign({lifetime:2,current_streak:1,longest_streak:1,
    peak:{date:"2026-01-10",total:2}},summary)});
const hostilePeakDate=validateTokenStats(statsPayload({
  peak:{date:{toString:null},total:2}}));
const hostileAccountDate=validateTokenStats(statsPayload({},[{id:"a",name:"A",
  provider:"claude",lifetime:2,last7d:2,
  peak:{date:{toString:null},total:2}}]));
const hostileNested=validateTokenStats(statsPayload({
  longest_session:{seconds:1,date:null,account:{toString:null}},
  most_used_model:{label:{toString:null},share_pct:Infinity}}));
const outOfRangeShare=validateTokenStats(statsPayload({
  most_used_model:{label:"sonnet",share_pct:101}}));
const validDecimalShare=validateTokenStats(statsPayload({
  most_used_model:{label:"sonnet",share_pct:12.5}}));
const unsafeSummary=validateTokenStats(statsPayload({
  lifetime:Number.MAX_SAFE_INTEGER+1}));
const unsafeCounts=statsPayload();
unsafeCounts.days["2026-01-10"]={input:Number.MAX_SAFE_INTEGER,output:0,
  cache_read:1,cache_creation:0,total:Number.MAX_SAFE_INTEGER};
const unsafeDay=validateTokenStats(unsafeCounts);
const overflowDays={"2026-01-01":{grand_total:Number.MAX_SAFE_INTEGER},
  "2026-01-02":{grand_total:1}};
const weeklyOverflow=tokenWeeklySeries(overflowDays,"2026-01-02");
const cumulativeOverflow=tokenCumulativeSeries(overflowDays,"2026-01-02");
const disabledStats={};
Object.defineProperty(disabledStats,"generated",{get(){throw new Error("disabled telemetry inspected");}});
const disabled=validate({generated:generated,accounts:[],token_stats_enabled:false,
  token_stats:disabledStats,_headroom_display:{schema:"headroom_widget@1",
    freshness:{state:"current"},accounts:[]}});
const clamped=validateTokenStats({generated:generated,days:{
  "2024-12-06":Object.assign({},count),
  "2024-12-07":Object.assign({},count),
  "2026-01-10":Object.assign({},count),
  "2026-01-11":Object.assign({},count)
},accounts:[],summary:{lifetime:4,current_streak:1,longest_streak:1,
  peak:{date:"2026-01-10",total:2}}});
const futureGenerated=Date.parse("2026-01-12T12:00:00Z")/1e3;
const futureClamped=validateTokenStats({generated:futureGenerated,days:{
  "2024-12-07":Object.assign({},count),
  "2026-01-10":Object.assign({},count),
  "2026-01-11":Object.assign({},count)
},accounts:[],summary:{lifetime:4,current_streak:1,longest_streak:1,
  peak:{date:"2026-01-10",total:2}}});
const independentCap=tokenDenseSeries({"2000-01-01":{grand_total:1}},"2026-01-10");
const target={innerHTML:""};
globalThis.document={getElementById:()=>target};
renderTokenSeries(cumulative,"cumulative");
console.log(JSON.stringify({
  maximum:tokenHeatmapMaximum(days,new Date("2026-01-01T00:00:00Z"),new Date("2026-01-03T00:00:00Z")),
  weekly:weekly,
  cumulative:cumulative,
  clampedDays:Object.keys(clamped.days),
  futureClampedDays:Object.keys(futureClamped.days),
  futureEnd:utcDay(new Date(tokenWindowEnd(futureGenerated))),
  denseLength:independentCap.length,
  denseLast:independentCap[independentCap.length-1].date,
  staleAge:TOKEN_STALE_AGE,suppressAge:TOKEN_SUPPRESS_AGE,
  largeAges:tokenTelemetryThresholds(400000),
  staleState:tokenTelemetryState({generated:generated},generated+3600),
  suppressedState:tokenTelemetryState({generated:generated},generated+7*86400),
  futureState:tokenTelemetryState({generated:futureGenerated},generated),
  hostilePeakDate:hostilePeakDate===null,
  hostileAccountCount:hostileAccountDate.accounts.length,
  hostileNestedAccount:hostileNested.summary.longest_session.account,
  hostileNestedLabel:hostileNested.summary.most_used_model.label,
  hostileNestedShare:hostileNested.summary.most_used_model.share_pct,
  outOfRangeShare:outOfRangeShare.summary.most_used_model.share_pct,
  validDecimalShare:validDecimalShare.summary.most_used_model.share_pct,
  unsafeSummary:unsafeSummary===null,unsafeDay:unsafeDay===null,
  tokenNumbers:[tokenNumber(0),tokenNumber(Number.MAX_SAFE_INTEGER),
    tokenNumber(Number.MAX_SAFE_INTEGER+1),tokenNumber(1.5),tokenNumber(-1)],
  weeklyOverflow:weeklyOverflow,cumulativeOverflow:cumulativeOverflow,
  disabledHasTokenStats:Object.prototype.hasOwnProperty.call(disabled,"token_stats"),
  path:target.innerHTML
}));
"""
        return ('"use strict";\nconst TOKEN_MAX_DAYS=400,TOKEN_SCAN_INTERVAL=60,'
                'TOKEN_AGE_LIMITS=tokenTelemetryThresholds(TOKEN_SCAN_INTERVAL),'
                'TOKEN_STALE_AGE=TOKEN_AGE_LIMITS.stale,'
                'TOKEN_SUPPRESS_AGE=TOKEN_AGE_LIMITS.suppress;\n'
                'function esc(value){return String(value);}\n'
                + validator + functions + tail)

    @unittest.skipUnless(NODE, "node runtime required to execute token charts")
    def test_window_scale_dense_utc_buckets_and_step_cumulative(self):
        proc = subprocess.run([NODE, "-"], input=self._harness(),
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        value = json.loads(proc.stdout.strip().splitlines()[-1])
        # The out-of-window 999 value must not flatten the rendered heatmap.
        self.assertEqual(value["maximum"], 30)
        self.assertEqual([point["total"] for point in value["weekly"]],
                         [40, 0, 0])
        self.assertTrue(all(
            right["ts"] - left["ts"] == 7 * 86400000
            for left, right in zip(value["weekly"], value["weekly"][1:])))
        self.assertEqual([point["total"] for point in value["cumulative"]],
                         [10, 10, 40, 40, 40])
        self.assertTrue(all(
            right["ts"] - left["ts"] == 86400000
            for left, right in zip(
                value["cumulative"], value["cumulative"][1:])))
        path_data = re.search(r' d="([^"]+)"', value["path"]).group(1)
        # cumulative renders as a smoothed monotone curve (midpoint quadratics
        # with a straight closing segment), never the old step series
        self.assertIn(" Q", path_data)
        self.assertNotIn(" H", path_data)
        self.assertNotIn(" V", path_data)
        self.assertEqual(value["clampedDays"],
                         ["2024-12-07", "2026-01-10"])
        self.assertEqual(value["futureClampedDays"],
                         ["2024-12-07", "2026-01-10"])
        self.assertEqual(value["futureEnd"], "2026-01-10")
        self.assertEqual(value["denseLength"], 400)
        self.assertEqual(value["denseLast"], "2026-01-10")
        self.assertEqual(value["staleAge"], 3600)
        self.assertEqual(value["suppressAge"], 7 * 86400)
        self.assertEqual(value["largeAges"], {
            "stale": 4 * 400000, "suppress": 2 * 400000})
        self.assertEqual(value["staleState"],
                         {"stale": True, "suppressed": False})
        self.assertEqual(value["suppressedState"],
                         {"stale": False, "suppressed": True})
        self.assertEqual(value["futureState"],
                         {"stale": True, "suppressed": False})
        self.assertTrue(value["hostilePeakDate"])
        self.assertEqual(value["hostileAccountCount"], 0)
        self.assertIsNone(value["hostileNestedAccount"])
        self.assertIsNone(value["hostileNestedLabel"])
        self.assertIsNone(value["hostileNestedShare"])
        self.assertIsNone(value["outOfRangeShare"])
        self.assertEqual(value["validDecimalShare"], 12.5)
        self.assertTrue(value["unsafeSummary"])
        self.assertTrue(value["unsafeDay"])
        self.assertEqual(value["tokenNumbers"],
                         [True, True, False, False, False])
        self.assertEqual(value["weeklyOverflow"], [])
        self.assertEqual(value["cumulativeOverflow"], [])
        self.assertFalse(value["disabledHasTokenStats"])


class LegacyTokenCacheJS(unittest.TestCase):
    @unittest.skipUnless(NODE, "node runtime required to execute cache sanitizer")
    def test_both_legacy_cache_keys_are_sanitized_at_init(self):
        with open(dashboard.TEMPLATE) as handle:
            template = handle.read()
        functions = "function withoutTokenStats" + template.split(
            "function withoutTokenStats", 1)[1].split(
                "function render(data,forceNoncurrent)", 1)[0]
        script = r'''
const values=new Map([
  ["headroom-cache-r",JSON.stringify({generated:1,token_stats:{secret:1}})],
  ["headroom-cache-f",JSON.stringify({generated:2,token_stats:{secret:2}})]
]);
globalThis.localStorage={getItem:key=>values.has(key)?values.get(key):null,
  setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)};
sanitizeLegacyCaches();
console.log(JSON.stringify(Object.fromEntries(Array.from(values,([key,value])=>[key,JSON.parse(value)]))));
'''
        proc = subprocess.run(
            [NODE, "-"], input='"use strict";\n' + functions + script,
            capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        caches = json.loads(proc.stdout.strip())
        self.assertEqual(set(caches), {"headroom-cache-r", "headroom-cache-f"})
        self.assertTrue(all("token_stats" not in value
                            for value in caches.values()))


class WidgetRendererTests(unittest.TestCase):
    def test_sanitizer_removes_newlines_and_controls(self):
        cleaned = widget.sanitize("a\r\nb\x00c\x1fd\x7fe\u200bf")
        self.assertFalse(any(unicodedata in cleaned for unicodedata in
                             ("\r", "\n", "\x00", "\x1f", "\x7f", "\u200b")))
        self.assertEqual(cleaned, "a b c d e f")

    def test_sanitizer_escapes_swiftbar_parameter_syntax(self):
        cleaned = widget.sanitize("name | bash=/tmp/x param1=oops")
        self.assertNotIn("|", cleaned)
        self.assertNotIn("=", cleaned)
        self.assertNotIn("bash=", cleaned)
        self.assertIn("¦", cleaned)

    def test_swiftbar_renderer_starts_with_exact_sentinel(self):
        rendered = widget.render_swiftbar(
            usage_snapshot(usage_account()), NOW)
        self.assertEqual(rendered.splitlines()[0], "headroom_widget_txt@1")

    def test_swiftbar_renderer_contains_one_headline(self):
        rendered = widget.render_swiftbar(
            usage_snapshot(usage_account(used5=12)), NOW)
        headline_lines = [line for line in rendered.splitlines()
                          if line.startswith("hr ")]
        self.assertEqual(headline_lines, ["hr 1/1 · 88% | color=green"])

    def test_swiftbar_rows_include_both_windows_and_resets(self):
        rendered = widget.render_swiftbar(
            usage_snapshot(usage_account()), NOW)
        self.assertRegex(rendered, r"(?m)^--5h: .* · resets ")
        self.assertRegex(rendered, r"(?m)^--7d: .* · resets ")

    def test_swiftbar_renderer_labels_avg_battery(self):
        rendered = widget.render_swiftbar(
            usage_snapshot(usage_account()), NOW)
        self.assertIn("Avg battery: 5h 80% · 7d 60%", rendered)

    def test_swiftbar_omits_lifted_5h_row_on_current_codex_seat(self):
        # OpenAI lifted Codex's 5h: project() drops the absent 5h on a live
        # codex seat, so render_swiftbar must emit NO "--5h:" sub-row — never a
        # phantom "--5h: -- (held)" — and the seat must stay CURRENT.
        account = usage_account("cx", provider="codex")
        del account["windows"]["5h"]
        rendered = widget.render_swiftbar(usage_snapshot(account), NOW)
        self.assertNotRegex(rendered, r"(?m)^--5h:")
        self.assertRegex(rendered, r"(?m)^--7d: ")
        self.assertRegex(rendered, r"(?m)^cx · codex · CURRENT")
        # the account-row colour falls back to 7d (not the absent 5h), so a
        # current codex seat reads coloured, never greyed by its lifted session
        self.assertNotRegex(rendered,
                            r"(?m)^cx · codex · CURRENT \| color=gray")

    def test_swiftbar_renderer_emits_no_execution_directives(self):
        account = usage_account("safe")
        account["provider"] = "bad | bash=/tmp/x shell=yes terminal=true param1=x"
        rendered = widget.render_swiftbar(usage_snapshot(account), NOW).lower()
        self.assertIsNone(re.search(r"(?:bash|shell|terminal|param\d+)=", rendered))

    def test_schema_marker_never_bypasses_projection(self):
        poisoned = {
            "schema": widget.SCHEMA,
            "headline": {"current_accounts":
                         "1 | shell=/bin/sh param1=-c",
                         "total_accounts": 1,
                         "fullest_5h_left_percent": 99},
            "accounts": [],
        }
        rendered = widget.render_swiftbar(poisoned, NOW)
        self.assertIn("hr 0/0 · -- | color=gray", rendered)
        self.assertNotIn("shell=", rendered)

    def test_dashboard_href_is_parsed_and_reconstructed(self):
        valid = widget.render_swiftbar(
            None, dashboard_href="http://localhost:49152")
        self.assertIn("href=http://127.0.0.1:49152/", valid)
        attacks = (
            "http://127.0.0.1:8377@evil.example/",
            "http://localhost:8377@evil.example/",
            "http://127.0.0.1:8377/ | shell=/bin/sh",
            "http://127.0.0.1:8377/?x=1",
            "http://127.0.0.1:8377/#x",
            "http://127.0.0.1:0/",
            "http://127.0.0.1:65536/",
        )
        for href in attacks:
            with self.subTest(href=href):
                rendered = widget.render_swiftbar(None, dashboard_href=href)
                self.assertIn("href=" + widget.DASHBOARD_HREF, rendered)
                self.assertNotIn("evil.example", rendered)
                self.assertNotIn("shell=", rendered)

    def test_aggregate_noncurrent_rows_never_retain_live_colors(self):
        account = usage_account()
        del account["windows"]["7d"]
        rendered = widget.render_swiftbar(usage_snapshot(account), NOW)
        self.assertRegex(rendered, r"(?m)^--5h: .*\(held\).* \| color=gray$")
        self.assertNotRegex(rendered, r"(?m)^--5h: .* \| color=green$")

    def test_widget_feed_without_snapshot_is_static_offline(self):
        with mock.patch.object(paths, "load_json", return_value=None):
            output = io.StringIO()
            with redirect_stdout(output):
                result = __main__._dispatch(["widget-feed", "--swiftbar"])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), widget.render_swiftbar(None))
        self.assertIn("hr OFFLINE | color=gray", output.getvalue())

    def test_local_widget_feed_never_collects(self):
        from headroom import collect
        with mock.patch.object(paths, "load_json",
                               return_value=usage_snapshot(usage_account())), \
                mock.patch.object(collect, "run_collect",
                                  side_effect=AssertionError("must not collect")):
            output = io.StringIO()
            with redirect_stdout(output):
                result = __main__._dispatch(["widget-feed", "--swiftbar"])
        self.assertEqual(result, 0)
        self.assertTrue(output.getvalue().startswith("headroom_widget_txt@1\n"))


class RefreshGateTests(unittest.TestCase):
    def gate_fixture(self, failure_base=5, failure_cap=300):
        clock = MutableClock()
        state = {"snapshot": usage_snapshot(
            usage_account(), generated=clock.value - 301), "attempts": 0}

        def load():
            return state["snapshot"]

        def collect():
            state["attempts"] += 1
            state["snapshot"] = usage_snapshot(
                usage_account(), generated=clock.value)

        gate = dashboard.RefreshGate(300, failure_base, failure_cap, clock)
        return gate, clock, state, load, collect

    def test_refresh_gate_shares_success_across_all_feeds(self):
        gate, clock, state, load, collect = self.gate_fixture()
        results = [gate.get(load, collect) for route in
                   ("/usage.json", "/widget.json", "/widget.txt")]
        self.assertEqual(state["attempts"], 1)
        self.assertTrue(all(not result.refresh_failed for result in results))

    def test_refresh_gate_honors_300_second_success_ttl(self):
        gate, clock, state, load, collect = self.gate_fixture()
        gate.get(load, collect)
        clock.value += 299
        gate.get(load, collect)
        self.assertEqual(state["attempts"], 1)

    def test_refresh_gate_recollects_after_success_ttl(self):
        gate, clock, state, load, collect = self.gate_fixture()
        gate.get(load, collect)
        clock.value += 300
        gate.get(load, collect)
        self.assertEqual(state["attempts"], 2)

    def test_refresh_gate_failure_backoff_is_exponential_and_bounded(self):
        gate, clock, state, load, _ = self.gate_fixture(2, 5)
        delays = []

        def fail():
            state["attempts"] += 1
            raise OSError("offline")

        for expected in (2, 4, 5, 5):
            gate.get(load, fail)
            delays.append(gate.last_delay)
            self.assertEqual(gate.retry_at, clock.value + expected)
            clock.value += expected
        self.assertEqual(delays, [2, 4, 5, 5])

    def test_failed_publication_100_requests_attempt_once(self):
        gate, clock, state, load, _ = self.gate_fixture()

        def fail():
            state["attempts"] += 1
            raise OSError("offline")

        with ThreadPoolExecutor(max_workers=32) as pool:
            results = list(pool.map(lambda _: gate.get(load, fail), range(100)))
        self.assertEqual(state["attempts"], 1)
        self.assertTrue(all(result.refresh_failed for result in results))

    def test_refresh_gate_opens_once_at_retry_boundary(self):
        gate, clock, state, load, _ = self.gate_fixture()

        def fail():
            state["attempts"] += 1
            raise OSError("offline")

        gate.get(load, fail)
        clock.value = gate.retry_at
        with ThreadPoolExecutor(max_workers=32) as pool:
            list(pool.map(lambda _: gate.get(load, fail), range(100)))
        self.assertEqual(state["attempts"], 2)

    def test_failed_refresh_serves_last_good_as_noncurrent(self):
        gate, clock, state, load, _ = self.gate_fixture()

        def fail():
            raise OSError("offline")

        result = gate.get(load, fail)
        projected = widget.project(
            result.snapshot, clock.value,
            force_noncurrent_reason=result.reason)
        self.assertTrue(result.refresh_failed)
        self.assertEqual(projected["freshness"]["state"], "stale")
        self.assertEqual(projected["accounts"][0]["state"], "stale")
        self.assertIsNone(projected["accounts"][0]["windows"]["5h"][
            "left_percent"])

    def test_failed_refresh_without_snapshot_returns_503(self):
        class LiveHandler(dashboard.Handler):
            demo = False
            refresh_gate = dashboard.RefreshGate(failure_base=60)

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(paths, "load_json", return_value=None), \
                mock.patch.object(dashboard.collector, "run_collect",
                                  side_effect=OSError("offline")):
            status, headers, body = memory_get(
                LiveHandler, directory, "/widget.json")
        self.assertEqual(status, 503)
        self.assertEqual(headers["content-type"], "application/json")
        self.assertIn(b"no usage snapshot", body)


class HistoryHttpTests(unittest.TestCase):
    @contextmanager
    def live_server(self, with_history=True):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(os.environ, {
                    "HEADROOM_DIR": directory,
                    "HEADROOM_HISTORY": "1",
                    "HEADROOM_HISTORY_MIN_INTERVAL": "0",
                    "HEADROOM_HISTORY_RETENTION_DAYS": "30",
                }):
            account = usage_account()
            registry.save({"schema_version": 1, "accounts": [{
                "id": account["id"], "name": account["name"],
                "provider": account["provider"], "home": "/tmp/alpha"}]})
            if with_history:
                history.append_snapshot(
                    usage_snapshot(account), now=int(time.time()))

            class NoRefreshGate:
                def get(self, *_args):
                    raise AssertionError("history touched refresh gate")

            class LiveHandler(dashboard.Handler):
                demo = False
                refresh_gate = NoRefreshGate()

            yield LiveHandler, directory

    def test_days_default_invalid_and_bounds(self):
        expected = (("/history.json", 7),
                    ("/history.json?days=invalid", 7),
                    ("/history.json?days=0", 1),
                    ("/history.json?days=999", 30))
        with self.live_server() as server:
            responses = [(json.loads(memory_get(*server, route)[2])["days"],
                          days) for route, days in expected]
        self.assertTrue(all(actual == wanted
                            for actual, wanted in responses))

    def test_empty_and_malformed_only_history_return_503(self):
        with self.live_server(with_history=False) as server:
            empty = memory_get(*server, "/history.json")
            paths.ensure_private(paths.history_dir())
            with open(paths.history_path(), "w", encoding="utf-8",
                      newline="\n") as handle:
                handle.write(json.dumps({
                    "ts": int(time.time()),
                    "accounts": [{"name": "bad", "provider": "claude",
                                  "windows": [{}]}],
                }) + "\n")
            malformed = memory_get(*server, "/history.json")
        self.assertEqual(empty[0], 503)
        self.assertEqual(json.loads(empty[2]), {"error": "no history yet"})
        self.assertEqual(malformed[0], 503)
        self.assertEqual(json.loads(malformed[2]), {"error": "no history yet"})

    def test_binary_garbage_is_skipped_when_valid_history_follows(self):
        with self.live_server(with_history=False) as server:
            paths.ensure_private(paths.history_dir())
            valid = history.project_snapshot(
                usage_snapshot(usage_account()), ts=int(time.time()))
            with open(paths.history_path(), "wb") as handle:
                handle.write(b"\xff\xfe corrupt\n")
                handle.write(b"[" * 2000 + b"]" * 2000 + b"\n")
                handle.write(json.dumps(valid).encode("utf-8") + b"\n")
            status, headers, body = memory_get(*server, "/history.json")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json")
        self.assertTrue(json.loads(body)["series"])

    def test_provider_labels_with_emails_never_reach_history_feed(self):
        with self.live_server(with_history=False) as server:
            account = usage_account()
            account["plan"] = "owner@example.test"
            account["windows"]["scoped:acct@example.test"] = {
                "used_percent": 75, "resets_at": int(time.time()) + 3600}
            history.append_snapshot(
                usage_snapshot(account), now=int(time.time()))
            with open(paths.history_path(), "rb") as handle:
                raw = handle.read()
            status, _, body = memory_get(*server, "/history.json")
        self.assertEqual(status, 200)
        self.assertNotIn(b"@", raw)
        self.assertNotIn(b"@", body)

    def test_unexpected_history_error_returns_json_503(self):
        with self.live_server() as server, \
                mock.patch.object(history, "load_series",
                                  side_effect=RecursionError("corrupt")) as load:
            status, headers, body = memory_get(*server, "/history.json")
        load.assert_called_once()
        self.assertEqual(status, 503)
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(json.loads(body), {"error": "invalid history"})

    def test_disabled_wins_even_when_history_exists(self):
        with self.live_server() as server, \
                mock.patch.dict(os.environ, {"HEADROOM_HISTORY": "0"}), \
                mock.patch.object(
                    history, "_read_rows",
                    side_effect=AssertionError("history filesystem touched")):
            status, _, body = memory_get(*server, "/history.json")
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body), {"error": "history_disabled"})

    def test_history_route_never_collects_or_uses_refresh_gate(self):
        with self.live_server() as server, \
                mock.patch.object(dashboard.collector, "run_collect",
                                  side_effect=AssertionError("collected")), \
                mock.patch.object(registry, "apply_pins",
                                  side_effect=AssertionError("registry mutated")), \
                mock.patch.object(registry, "load",
                                  wraps=registry.load) as load:
            status, _, body = memory_get(*server, "/history.json?days=7")
        load.assert_called_once_with()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["schema_version"], 1)


class DashboardHttpTests(unittest.TestCase):
    @contextmanager
    def demo_server(self, snapshot=None, index=None):
        snapshot = snapshot or usage_snapshot(usage_account())
        index = index or b"<!doctype html><title>same template</title>"
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "usage.json"), "w") as handle:
                json.dump(snapshot, handle)
            with open(os.path.join(directory, "index.html"), "wb") as handle:
                handle.write(index)

            class DemoHandler(dashboard.Handler):
                demo = True

            yield DemoHandler, directory

    @staticmethod
    def template_text():
        with open(dashboard.TEMPLATE, encoding="utf-8") as handle:
            return handle.read()

    def test_endpoint_and_cli_use_byte_identical_renderer(self):
        snapshot = usage_snapshot(usage_account())
        with mock.patch.object(widget.time, "time", return_value=NOW):
            with self.demo_server(snapshot) as server:
                status, _, endpoint = memory_get(*server, "/widget.txt")
            output = io.StringIO()
            with mock.patch.object(paths, "load_json", return_value=snapshot), \
                    redirect_stdout(output):
                result = __main__._dispatch(["widget-feed", "--swiftbar"])
        self.assertEqual((status, result), (200, 0))
        self.assertEqual(endpoint, output.getvalue().encode("utf-8"))

    def test_widget_routes_and_content_types(self):
        with mock.patch.object(widget.time, "time", return_value=NOW):
            with self.demo_server() as server:
                json_response = memory_get(*server, "/widget.json")
                text_response = memory_get(*server, "/widget.txt")
        self.assertEqual(json_response[0], 200)
        self.assertEqual(json_response[1]["content-type"], "application/json")
        self.assertEqual(json.loads(json_response[2])["schema"],
                         "headroom_widget@1")
        self.assertEqual(text_response[0], 200)
        self.assertEqual(text_response[1]["content-type"],
                         "text/plain; charset=utf-8")
        self.assertTrue(text_response[2].startswith(b"headroom_widget_txt@1\n"))

    def test_widget_path_serves_existing_template(self):
        template = self.template_text().encode()
        with self.demo_server(index=template) as server:
            root = memory_get(*server, "/")
            widget_path = memory_get(*server, "/widget")
        self.assertEqual(root[0], 200)
        self.assertEqual(widget_path[0], 200)
        self.assertEqual(root[2], widget_path[2])

    def test_compact_query_uses_existing_template(self):
        template = self.template_text().encode()
        with self.demo_server(index=template) as server:
            normal = memory_get(*server, "/")
            compact = memory_get(*server, "/?compact=1")
        self.assertEqual(normal[2], compact[2])
        self.assertIn(b'params.get("compact")==="1"', compact[2])
        templates = [name for name in os.listdir(os.path.dirname(dashboard.TEMPLATE))
                     if name.endswith(".html")]
        self.assertEqual(templates, ["template.html"])

    def test_demo_widget_routes_never_collect(self):
        with mock.patch.object(widget.time, "time", return_value=NOW), \
                mock.patch.object(dashboard.collector, "run_collect",
                                  side_effect=AssertionError("demo collected")):
            with self.demo_server() as server:
                statuses = [memory_get(*server, route)[0] for route in
                            ("/usage.json", "/widget.json", "/widget.txt")]
        self.assertEqual(statuses, [200, 200, 200])

    def test_live_usage_handler_embeds_opted_in_token_summary(self):
        account = usage_account()
        token_value = {
            "generated": NOW,
            "days": {"2033-05-18": {
                "input": 10, "output": 5, "cache_read": 7,
                "cache_creation": 3, "total": 18, "grand_total": 25,
                "session_count": 1, "longest_session_s": 3600,
                "families": {"sonnet": 25}, "efforts": {}}},
            "accounts": [{
                "id": account["id"], "name": account["name"],
                "provider": account["provider"], "lifetime": 18,
                "lifetime_grand_total": 25, "last7d": 18,
                "last7d_grand_total": 25,
                "peak": {"date": "2033-05-18", "total": 18,
                         "grand_total": 25}}],
            "summary": {
                "lifetime": 18, "grand_total": 25,
                "peak": {"date": "2033-05-18", "total": 18,
                         "grand_total": 25},
                "current_streak": 1, "longest_streak": 1,
                "total_sessions": 1, "active_days": 1,
                "longest_session": {"seconds": 3600,
                                    "date": "2033-05-18",
                                    "account": account["name"]},
                "most_used_model": {"label": "sonnet",
                                    "share_pct": 100.0},
                "families": [{"label": "sonnet", "tokens": 25,
                              "share_pct": 100.0}]},
        }

        class StaticGate:
            def get(self, *_args):
                return dashboard.RefreshResult(usage_snapshot(account))

        class LiveHandler(dashboard.Handler):
            demo = False
            refresh_gate = StaticGate()

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(os.environ, {"HEADROOM_DIR": directory}), \
                mock.patch.object(dashboard.tokens, "load_summary",
                                  return_value=token_value):
            registry.save({
                "schema_version": 1,
                "dashboard": {"token_stats": True},
                "accounts": [{
                    "id": account["id"], "name": account["name"],
                    "provider": account["provider"], "home": "/tmp/alpha"}],
            })
            status, _, body = memory_get(
                LiveHandler, directory, "/usage.json")
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertIs(payload["token_stats_enabled"], True)
        self.assertEqual(payload["token_stats"], token_value)

    def test_demo_history_is_synthesized_without_collecting(self):
        with mock.patch.object(dashboard.collector, "run_collect",
                               side_effect=AssertionError("demo collected")):
            with self.demo_server() as server:
                status, _, body = memory_get(*server, "/history.json?days=7")
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["days"], 7)
        self.assertTrue(payload["series"])
        self.assertTrue(payload["summary"])

    def test_demo_history_respects_kill_switch(self):
        with self.demo_server() as server, \
                mock.patch.dict(os.environ, {"HEADROOM_HISTORY": "0"}):
            status, _, body = memory_get(*server, "/history.json")
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body), {"error": "history_disabled"})

    def test_all_responses_have_security_headers(self):
        with mock.patch.object(widget.time, "time", return_value=NOW):
            with self.demo_server() as server:
                responses = [memory_get(*server, route) for route in
                             ("/", "/widget.json", "/history.json",
                              "/missing")]
                responses.append(memory_get(*server, "/", "evil.example"))
        for _, headers, _ in responses:
            self.assertEqual(headers.get("cache-control"), "no-store")
            self.assertEqual(headers.get("x-content-type-options"), "nosniff")
            # containment even inside an embedding webview: same-origin
            # fetches + inline style/script only — no frames, objects,
            # forms, popup targets, or external subresources. Pinned as the
            # EXACT policy so no directive can silently loosen or vanish.
            self.assertEqual(
                headers.get("content-security-policy"),
                "default-src 'none'; script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline'; img-src 'self' data:; "
                "connect-src 'self'; frame-src 'none'; object-src 'none'; "
                "form-action 'none'; base-uri 'none'")

    def test_no_response_enables_cors(self):
        with mock.patch.object(widget.time, "time", return_value=NOW):
            with self.demo_server() as server:
                responses = [memory_get(*server, route) for route in
                             ("/", "/usage.json", "/widget.json",
                              "/widget.txt", "/history.json", "/missing")]
        for _, headers, _ in responses:
            self.assertNotIn("access-control-allow-origin", headers)

    def test_nonloopback_host_is_rejected_for_every_route(self):
        with self.demo_server() as server:
            statuses = [memory_get(*server, route, "attacker.example")[0]
                        for route in ("/", "/widget", "/usage.json",
                                      "/widget.json", "/widget.txt",
                                      "/history.json", "/missing")]
        self.assertEqual(statuses, [403] * 7)

    def test_dashboard_dom_projection_uses_widget_trust_and_freshness(self):
        held = usage_account(routable=True, trust_state="held")
        cases = (
            (usage_snapshot(usage_account(), generated=NOW - 1000), "stale"),
            (usage_snapshot(held), "held"),
        )
        for snapshot, expected in cases:
            with self.subTest(expected=expected):
                display = dashboard.display_snapshot(snapshot, NOW)[
                    "_headroom_display"]
                central = widget.project(snapshot, NOW)
                self.assertEqual(display["accounts"][0]["state"], expected)
                self.assertEqual(display["accounts"][0]["state"],
                                 central["accounts"][0]["state"])
                for window in display["accounts"][0]["windows"].values():
                    self.assertIsNone(window["left_percent"])
                    self.assertEqual(window["tone"], "unknown")

    def test_dashboard_dom_projection_colors_and_cache_fallback(self):
        snapshot = usage_snapshot(
            usage_account("green", used5=20),
            usage_account("yellow", used5=60),
            usage_account("orange", used5=80),
            usage_account("red", used5=95))
        display = dashboard.display_snapshot(snapshot, NOW)["_headroom_display"]
        account = display["accounts"][0]
        self.assertEqual(account["state"], "current")
        self.assertEqual(account["windows"]["5h"]["left_percent"], 80.0)
        self.assertEqual(account["windows"]["5h"]["tone"], "green")
        self.assertEqual([row["windows"]["5h"]["tone"]
                          for row in display["accounts"]],
                         ["green", "yellow", "orange", "red"])
        limited = dashboard.display_snapshot(
            usage_snapshot(usage_account(used5=100)), NOW)[
                "_headroom_display"]["accounts"][0]
        self.assertEqual(limited["state"], "limited")
        self.assertEqual(limited["windows"]["5h"]["tone"], "red")
        self.assertEqual(limited["windows"]["7d"]["tone"], "unknown")
        forced = dashboard.display_snapshot(
            usage_snapshot(usage_account()), NOW, "cache_fallback")[
                "_headroom_display"]
        self.assertEqual(forced["accounts"][0]["state"], "stale")
        self.assertEqual(forced["accounts"][0]["windows"]["5h"]["tone"],
                         "unknown")
        script = self.template_text().split("<script>", 1)[1].split(
            "</script>", 1)[0]
        render_body = script.split("function render(data,forceNoncurrent){",
                                   1)[1].split("\n}", 1)[0]
        fallback = script.split("async function load(manual){", 1)[1].split(
            "/* --------------------------------------------------------------- theme */",
            1)[0]
        self.assertRegex(render_body,
                         r"sourceFailed=forceNoncurrent===true\|\|")
        self.assertRegex(fallback, r"render\(cached,true\)")
        self.assertIn("JSON.stringify(withoutTokenStats(data))", fallback)
        self.assertIn("cached=withoutTokenStats(validate(", fallback)
        cache_strip = script.split("function withoutTokenStats(data){",
                                   1)[1].split("\n}", 1)[0]
        self.assertIn("delete clean.token_stats", cache_strip)
        self.assertIn("delete clean.token_stats_enabled", cache_strip)

    def test_dom_tone_allowlist_covers_every_projected_tone(self):
        # every colour tone the Python projection can emit for a live window
        # must be accepted by the browser's safeTone allowlist, or the DOM
        # renders it gray while the server data says otherwise.
        emitted = set()
        for used5 in (10, 45, 65, 85, 99):
            row = dashboard.display_snapshot(
                usage_snapshot(usage_account(used5=used5)), NOW)[
                    "_headroom_display"]["accounts"][0]["windows"]["5h"]
            self.assertEqual(row["state"], "current")
            emitted.add(row["tone"])
        self.assertEqual(emitted, {"green", "yellow", "orange", "red"})
        window_view = self.template_text().split(
            "function windowView(a,key){", 1)[1].split("\n}", 1)[0]
        allow = re.search(r'\[([^\]]*)\]\.includes\(w\.tone\)', window_view)
        self.assertIsNotNone(allow)
        allowed = set(re.findall(r'"(\w+)"', allow.group(1)))
        self.assertTrue(emitted <= allowed,
                        f"DOM allowlist {allowed} misses {emitted - allowed}")

    def test_static_dashboard_injects_shared_thresholds_and_projection(self):
        config = {"schema_version": 1,
                  "dashboard": {"theme": "midnight", "title": "test"},
                  "accounts": []}
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "out")
            os.makedirs(output)
            source = os.path.join(output, "usage.json")
            with open(source, "w") as handle:
                json.dump(usage_snapshot(usage_account()), handle)
            with redirect_stdout(io.StringIO()), \
                    mock.patch.object(widget.time, "time", return_value=NOW):
                dashboard.build(config, output, source)
            with open(os.path.join(output, "index.html")) as handle:
                html = handle.read()
            with open(os.path.join(output, "usage.json")) as handle:
                payload = json.load(handle)
        match = re.search(r"const CONFIG = (\{.*?\});", html)
        self.assertIsNotNone(match)
        injected = json.loads(match.group(1))
        self.assertEqual(injected["snapshot_max_age"],
                         widget.SNAPSHOT_MAX_AGE)
        self.assertEqual(injected["observation_max_age"],
                         widget.OBSERVATION_MAX_AGE)
        self.assertEqual(injected["token_scan_interval"],
                         dashboard.tokens.scan_interval())
        self.assertNotIn("token_stats_enabled", injected)
        self.assertIs(payload["token_stats_enabled"], False)
        self.assertNotIn("CONFIG.token_stats_enabled", html)
        self.assertIn(
            "tokenStatsEnabled=data.token_stats_enabled===true", html)
        self.assertEqual(payload["_headroom_display"]["accounts"][0][
            "windows"]["5h"]["tone"], "green")
        self.assertIn('id="stats-tab"', html)
        self.assertFalse(os.path.exists(os.path.join(output, "history.json")))

    def test_stats_template_navigation_reload_focus_and_color_contracts(self):
        template = self.template_text()
        nav = template.split('<nav class="side-nav"', 1)[1].split(
            "</nav>", 1)[0]
        self.assertNotIn('role="tablist"', nav)
        self.assertNotIn('role="tab"', nav)
        self.assertNotIn("aria-controls", nav)
        self.assertNotIn("aria-selected", template)
        self.assertNotIn('role="tabpanel"', template)
        self.assertNotIn('aria-labelledby="usage-nav"', template)
        self.assertNotIn('aria-labelledby="stats-nav"', template)
        self.assertIn('aria-current="page"', nav)
        self.assertIn('.side-nav a[aria-current="page"]', template)

        chart = template.split("function renderHistoryChart(data,key){",
                               1)[1].split("\n}", 1)[0]
        self.assertIn("const active=document.activeElement;", chart)
        self.assertIn("key:account.id", chart)
        self.assertIn("legend.contains(active)", chart)
        self.assertIn('item.getAttribute("data-series")===focusedSeries', chart)
        self.assertIn("if(replacement)replacement.focus({preventScroll:true});",
                      chart)
        self.assertLess(chart.index("color:SERIES_COLORS[index"),
                        chart.index(")).filter(account=>account.points.length)"))
        self.assertIn("color:account.color", chart)

        history_script = template.split("async function loadHistory(",
                                        1)[1].split(
            "/* =================================================== liquid-glass widget */",
            1)[0]
        self.assertIn("manual,background=false", history_script)
        self.assertIn("const replaceView=!background;", history_script)
        self.assertIn("if(background&&historyForegroundLoads)return;",
                      history_script)
        self.assertIn("++historyBackgroundRequest:++historyForegroundRequest",
                      history_script)
        self.assertIn("foregroundAtStart===historyForegroundRequest",
                      history_script)
        self.assertIn("isCurrent()&&replaceView", history_script)
        self.assertIn("if(!background)historyForegroundLoads--;",
                      history_script)
        self.assertIn('if(active==="stats")loadHistory(false);', history_script)
        self.assertIn('history-range").addEventListener("change",()=>loadHistory(false))',
                      history_script)
        self.assertIn('loadHistory(false,true);},6e4)', history_script)
        self.assertIn('link.setAttribute("aria-current","page")', history_script)
        self.assertIn('link.removeAttribute("aria-current")', history_script)

        self.assertIn('id="token-stats" hidden', template)
        self.assertIn('id="token-partial" hidden', template)
        self.assertIn('id="token-stale" hidden', template)
        self.assertIn('id="token-heatmap"', template)
        self.assertIn('class="token-heat-cell"', template)
        self.assertIn('data-token-mode="daily"', template)
        self.assertIn('data-token-mode="weekly"', template)
        self.assertIn('data-token-mode="cumulative"', template)
        weekly = template.split("function tokenWeeklySeries(days,endDay){",
                                1)[1].split("\n}", 1)[0]
        self.assertIn("tokenDenseSeries(days,endDay)", weekly)
        self.assertIn("buckets.set", weekly)
        cumulative = template.split(
            "function tokenCumulativeSeries(days,endDay){",
                                    1)[1].split("\n}", 1)[0]
        self.assertIn("running+=", cumulative)
        self.assertIn("if(!tokenNumber(running))return[];", cumulative)
        self.assertIn("tokenDenseSeries(days,endDay)", cumulative)
        series = template.split("function renderTokenSeries(series,mode){",
                                1)[1].split("\n}", 1)[0]
        self.assertIn("const tickIndexes=[...new Set(", series)
        activity = template.split("function renderTokenActivity(){",
                                  1)[1].split("\n}", 1)[0]
        self.assertIn(
            'getElementById("token-heat-legend").hidden=tokenActivityMode!=="daily"',
            activity)
        token_render = template.split("function renderTokenStats(){",
                                      1)[1].split("\n}", 1)[0]
        self.assertIn("if(!tokenStats)", token_render)
        self.assertIn("target.hidden=true", token_render)
        self.assertIn("target.hidden=false", token_render)
        self.assertIn("summary.grand_total", token_render)
        self.assertIn("summary.peak.grand_total", token_render)
        self.assertIn('getElementById("token-longest-session")', token_render)
        self.assertIn('getElementById("token-insights")', token_render)
        self.assertIn("tokenStats.partial", token_render)
        self.assertIn("tokenStats.failed_file_count", token_render)
        self.assertIn("telemetry stale", token_render)
        self.assertIn(
            "Window % read live · token totals from your local session logs.",
            token_render)
        self.assertIn(
            'sideNote.innerHTML="Window percentage only.<br>No token counts stored."',
            token_render)
        self.assertIn(
            'historyData&&!document.getElementById("stats-content").hidden',
            token_render)
        self.assertIn('class="mix-bar"', token_render)
        self.assertIn("renderPodium();", token_render)
        render = template.split("function render(data,forceNoncurrent){",
                                1)[1].split("\n}", 1)[0]
        self.assertIn(
            "tokenStatsEnabled&&!tokenState.suppressed?data.token_stats:null",
            render)
        validate = template.split("function validate(data){",
                                  1)[1].split("\n}", 1)[0]
        self.assertLess(validate.index("data.token_stats_enabled"),
                        validate.index("validateTokenStats(data.token_stats)"))
        self.assertIn("else delete data.token_stats", validate)
        stats_state = template.split("function showStatsState(",
                                     1)[1].split("\n}", 1)[0]
        self.assertIn(
            'document.getElementById("leaderboard-panel").hidden=true;',
            stats_state)
        init = template.split("(function init(){", 1)[1].split("})();", 1)[0]
        self.assertLess(init.index("sanitizeLegacyCaches();"),
                        init.index("if(widgetMode)"))
        leaderboard = template.split("function renderLeaderboard(data){",
                                     1)[1].split("\n}", 1)[0]
        # with telemetry on, the ranking lives in the Accounts column and the
        # window-% leaderboard hides; without it, the fallback stays intact
        self.assertIn("if(tokenStats)", leaderboard)
        self.assertIn("panel.hidden=true;\n    return;", leaderboard)
        self.assertIn("Avg weekly used", leaderboard)
        self.assertIn("if(!data){panel.hidden=true;return;}", leaderboard)
        self.assertIn("Ranked by average Weekly-all utilization", leaderboard)
        accounts = template.split("function renderTokenAccounts(){",
                                  1)[1].split("\n}", 1)[0]
        self.assertIn("lifetime_grand_total", accounts)
        self.assertIn("last7d_grand_total", accounts)
        self.assertIn("token-account-row", accounts)

    def test_widget_href_uses_actual_server_address_port(self):
        port = 49152
        with mock.patch.object(widget.time, "time", return_value=NOW), \
                self.demo_server() as server:
            status, _, body = memory_get(
                *server, "/widget.txt", server_port=port)
        body = body.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn("Open dashboard | href=http://127.0.0.1:%d/" % port,
                      body)

    def test_widget_mode_retains_state_disclosure(self):
        # The widget view may hide the full dashboard, but every element
        # that discloses state (snapshot freshness, per-account badge,
        # banner, note) must be part of every popover render, and the
        # small/medium layouts must keep the freshness dot + live line.
        template = self.template_text()
        popup = template.split("function hrPopMarkup(v){", 1)[1].split(
            "\n}", 1)[0]
        account_row = template.split("function hrAcctMarkup(a){", 1)[1].split(
            "\n}", 1)[0]
        for disclosure in ("hr-fresh", "hr-banner", "hrDotMarkup(v)"):
            self.assertIn(disclosure, popup)
        for disclosure in ("hr-badge", "hr-note"):
            self.assertIn(disclosure, account_row)
        self.assertIn("hr-dot", template.split("function hrDotMarkup(v){",
                                               1)[1].split("\n}", 1)[0])
        for builder in ("hrSmallMarkup", "hrMediumMarkup"):
            body = template.split("function " + builder + "(v){", 1)[1].split(
                "\n}", 1)[0]
            self.assertIn("hr-liveline", body)
        self.assertIn("hrDotMarkup(v)", template.split(
            "function hrSmallMarkup(v){", 1)[1].split("\n}", 1)[0])
        # offline fetch failures must render, not blank the page
        self.assertIn("function hrOfflineView(){", template)
        self.assertIn("feed unreachable", template)


class LiquidGlassWidgetTests(unittest.TestCase):
    """The /widget liquid-glass surface: five glass themes, real-feed wiring,
    size variants, and the fail-closed projection→class mapping."""

    THEMES = ("minimal", "chrome", "paper", "terminal")
    GLASS_TOKENS = ("--glass:", "--glass-2:", "--glass-line:", "--glass-hi:",
                    "--sep:", "--row-hov:", "--shadow-pop:", "--wall:",
                    "--pop-radius:", "--widget-radius:", "--cell-bg:",
                    "--cell-glow:", "--unknown:")

    @staticmethod
    def template_text():
        with open(dashboard.TEMPLATE, encoding="utf-8") as handle:
            return handle.read()

    @classmethod
    def widget_css(cls):
        return cls.template_text().split(
            "/* ==================================================== widget: liquid glass",
            1)[1].split("</style>", 1)[0]

    @classmethod
    def widget_script(cls):
        return cls.template_text().split(
            "/* =================================================== liquid-glass widget */",
            1)[1].split(
            "/* --------------------------------------------------------------- theme */",
            1)[0]

    @classmethod
    def js_function(cls, name):
        return cls.widget_script().split("function " + name + "(", 1)[1].split(
            "\n}", 1)[0]

    @staticmethod
    def fleet(mutate=None):
        """A design-shaped fleet: five Claude accounts plus two Codex ones."""
        accounts = [
            usage_account("domanski-ai", used5=0, used7=4),
            usage_account("system", used5=8, used7=26),
            usage_account("ops", used5=22, used7=39),
            usage_account("gmail", used5=36, used7=42),
            usage_account("mzansiedge", used5=45, used7=51),
            usage_account("codex-domanski-ai", used5=29, used7=15,
                          provider="codex"),
            usage_account("codex-gmail", used5=17, used7=23,
                          provider="codex"),
        ]
        if mutate:
            mutate(accounts)
        return accounts

    # ----------------------------------------------------------- theming
    def test_widget_css_defines_all_five_glass_themes(self):
        css = self.widget_css()
        base = css.split(".hr {", 1)[1].split("}", 1)[0]
        for token in self.GLASS_TOKENS:
            self.assertIn(token, base)
        for theme in self.THEMES:
            with self.subTest(theme=theme):
                block = css.split('.hr[data-theme="%s"] {' % theme,
                                  1)[1].split("}", 1)[0]
                self.assertIn("--glass:", block)
                self.assertIn("--wall:", block)
                self.assertIn("--glass-line:", block)

    def test_widget_surfaces_use_liquid_glass_tokens(self):
        css = self.widget_css()
        glass = css.split(".hr-glass {", 1)[1].split("}", 1)[0]
        self.assertIn("background: var(--glass)", glass)
        self.assertIn("backdrop-filter: blur(38px) saturate(170%)", glass)
        self.assertIn("-webkit-backdrop-filter: blur(38px) saturate(170%)",
                      glass)
        self.assertIn("border: 1px solid var(--glass-line)", glass)
        self.assertIn("var(--shadow-pop), var(--glass-hi)", glass)
        # popover and both desktop widgets all sit on the same glass class
        script = self.widget_script()
        for surface in ('"hr-pop hr-glass', '"hr-card small hr-glass',
                        '"hr-card medium hr-glass'):
            self.assertIn(surface, script)

    # --------------------------------------------------- routing / sizes
    def test_widget_mode_detection_and_size_variants(self):
        template = self.template_text()
        self.assertIn('==="/widget"', template)
        self.assertIn('params.get("compact")==="1"', template)
        self.assertIn('hrInit(params.get("size"))', template)
        init = self.js_function("hrInit")
        self.assertIn('size==="small"||size==="medium"', init)

    def test_small_and_medium_layout_dimensions(self):
        css = self.widget_css()
        self.assertIn(".hr-card.small { width: 206px; height: 206px; }", css)
        self.assertIn(".hr-card.medium { width: 438px; height: 206px;", css)
        self.assertIn("grid-template-columns: 140px 1fr", css)
        self.assertIn("grid-template-columns: 110px 1fr 36px", css)
        # popover window meters keep the design geometry: a label column that
        # starts at the 5H/7D width but can grow for scoped labels (FABLE),
        # then cells, then the 46px value column
        self.assertIn(
            "grid-template-columns: minmax(24px, max-content) 1fr 46px", css)
        self.assertIn(".hr-pop { width: 352px;", css)

    # ------------------------------------------------------- data wiring
    def test_widget_script_reads_only_widget_feed_and_no_emails(self):
        script = self.widget_script()
        self.assertIn('const HR_URL="widget.json";', script)
        self.assertIn('data.schema!=="headroom_widget@1"', script)
        self.assertNotIn(".email", script)
        self.assertNotIn("usage.json", script)
        # field-derived text is escaped on the way into the DOM
        for escaped in ("esc(a.name)", "esc(a.provider)", "esc(a.note)",
                        "esc(v.freshText)", "esc(v.banner.text)"):
            self.assertIn(escaped, script)

    def test_widget_script_consumes_projection_fields(self):
        script = self.widget_script()
        value = widget.project(usage_snapshot(*self.fleet()), NOW)
        for field in ("freshness", "age_seconds", "fullest_5h_left_percent",
                      "current_accounts", "total_accounts", "left_percent",
                      "last_observed_left_percent", "resets_at",
                      "observed_at"):
            with self.subTest(field=field):
                self.assertIn(field, script)
                self.assertIn(field, json.dumps(value))

    # -------------------------------------------------- fail-closed core
    def test_widget_tone_ramp_matches_projection_thresholds(self):
        body = self.js_function("hrTone")
        self.assertIn('left==null?"unknown":left<=10?"red":left<=30?'
                      '"orange":left<=50?"yellow":"green"', body)
        # pinned to the Python projection's ramp, not a lookalike
        samples = {5: "red", 10: "red", 11: "orange", 30: "orange",
                   31: "yellow", 50: "yellow", 51: "green", 100: "green"}
        for left, expected in samples.items():
            self.assertEqual(widget._dashboard_tone(left), expected)
        self.assertEqual(widget._dashboard_tone(None), "unknown")

    def test_fail_closed_only_current_windows_get_live_tone(self):
        body = self.js_function("hrWindow")
        # exactly one branch may produce a live tone, and it requires a
        # current state AND a finite live reading
        self.assertEqual(body.count("hrTone("), 1)
        self.assertIn('if(st==="current"&&live!=null)', body)
        live_guard, rest = body.split('if(st==="current"&&live!=null)', 1)
        self.assertNotIn("hrTone(", live_guard)
        limited, stale = rest.split('if(st==="limited")', 1)[1].split(
            'if(st==="stale"&&last!=null)', 1)
        self.assertIn('tone:"red"', limited)
        self.assertIn('tone:"unknown"', stale)
        self.assertIn('value:"n/a"', stale)          # held fallback
        # the noncurrent branches never call the live tone ramp
        self.assertNotIn("hrTone(", limited)
        self.assertNotIn("hrTone(", stale)

    def test_demoted_and_offline_renders_are_grey_only(self):
        script = self.widget_script()
        demote = self.js_function("hrDemoteWindow")
        self.assertNotIn("hrTone(", demote)
        self.assertNotIn('"green"', demote)
        self.assertEqual(demote.count('tone:"unknown"'), 2)
        # a noncurrent feed demotes every account before rendering
        account = self.js_function("hrAccount")
        self.assertIn('if(demote&&st!=="held")st="stale";', account)
        view = self.js_function("hrView")
        self.assertIn('const demote=offline||fresh.state!=="current";', view)
        # the client re-checks snapshot age between polls, failing closed
        fresh = self.js_function("hrFreshness")
        self.assertIn("age>SNAPSHOT_MAX_AGE", fresh)
        self.assertIn('state="stale"', fresh)
        self.assertIn("feed unreachable", script)

    def test_badges_map_projection_states_to_design_labels(self):
        account = self.js_function("hrAccount")
        self.assertIn('{label:"CURRENT",tone:"green",dot:true}', account)
        self.assertIn('{label:"AT LIMIT",tone:"red",dot:true}', account)
        self.assertIn('{label:"STALE",tone:"dim",dot:false}', account)
        self.assertIn('{label:"WAITING",tone:"dim",dot:false}', account)
        # held accounts show no meters (WAITING has no windows to trust)
        self.assertIn('hasW:st!=="held"', account)
        css = self.widget_css()
        for grey in (".hr-tone-unknown", ".hr-tone-dim"):
            block = css.split(grey + " {", 1)[1].split("}", 1)[0]
            self.assertIn("--wtone: var(--unknown)", block)
            self.assertIn("color: var(--ink-3)", block)
            self.assertNotIn("--green", block)

    def test_banner_covers_limit_hit_and_stale_feed(self):
        view = self.js_function("hrView")
        self.assertIn("hit its 5h cap", view)
        self.assertIn("never promoted to live", view)
        self.assertIn('Math.floor(SNAPSHOT_MAX_AGE/60)+"m', view)
        self.assertIn('cls:"is-red"', view)
        self.assertIn('cls:"is-orange"', view)

    def test_pulse_only_for_current_freshness(self):
        template = self.template_text()
        self.assertIn('v.fresh.state==="current"&&!v.offline?" is-live":""',
                      template)
        motion = template.split(".hr-dot.is-live::after { animation:", 1)
        self.assertEqual(len(motion), 2)
        media = template.rsplit("@media (prefers-reduced-motion: no-preference)",
                                1)[1]
        self.assertIn(".hr-dot.is-live::after { animation: hr-pulse", media)

    def test_footer_keeps_refresh_dashboard_link_and_sentinel(self):
        popup = self.js_function("hrPopMarkup")
        self.assertIn("↻ Refresh", popup)
        self.assertIn("Open Fleet Dashboard", popup)
        self.assertIn('href="/" target="_blank" rel="noopener"', popup)
        self.assertIn('"hr-schema">\'+esc(v.schema)', popup)
        view = self.js_function("hrView")
        self.assertIn('"headroom_widget@1"', view)

    # ------------------------------------------------ self-containment
    def test_widget_page_is_self_contained_no_external_hosts(self):
        template = self.template_text()
        self.assertNotIn("<script src", template)
        self.assertNotIn("<link", template)
        self.assertNotIn("@import", template)
        self.assertNotIn("url(http", template)
        allowed = "https://github.com/domanski-ai/headroom"
        for url in re.findall(r"https?://[^\s\"'<>)]+", template):
            self.assertEqual(url, allowed)

    # --------------------------------- the three design scenarios, real data
    def test_cruising_scenario_projects_live_meters(self):
        value = widget.project(usage_snapshot(*self.fleet()), NOW)
        self.assertEqual(value["freshness"]["state"], "current")
        self.assertEqual(value["headline"], {
            "current_accounts": 7, "total_accounts": 7,
            "fullest_5h_left_percent": 100.0,
            "avg_5h_left_percent": 77.6,
            "avg_7d_left_percent": 71.4})
        providers = {row["provider"] for row in value["accounts"]}
        self.assertEqual(providers, {"claude", "codex"})
        for row in value["accounts"]:
            self.assertEqual(row["state"], "current")
            for window in row["windows"].values():
                self.assertEqual(window["state"], "current")
                self.assertTrue(math.isfinite(window["left_percent"]))

    def test_limit_hit_scenario_projects_red_cap_and_live_7d(self):
        def cap_first(accounts):
            accounts[0]["windows"]["5h"]["used_percent"] = 100
        value = widget.project(usage_snapshot(*self.fleet(cap_first)), NOW)
        capped = value["accounts"][0]
        self.assertEqual(capped["state"], "limited")
        self.assertEqual(capped["windows"]["5h"]["state"], "limited")
        self.assertIsNone(capped["windows"]["5h"]["left_percent"])
        self.assertEqual(capped["windows"]["5h"][
            "last_observed_left_percent"], 0.0)
        # the design keeps the 7d meter live on a 5h-capped account
        self.assertEqual(capped["windows"]["7d"]["state"], "current")
        self.assertTrue(math.isfinite(capped["windows"]["7d"]["left_percent"]))
        # headline never counts the capped tank
        self.assertEqual(value["headline"]["current_accounts"], 6)
        self.assertEqual(value["headline"]["fullest_5h_left_percent"], 92.0)

    def test_feed_stale_scenario_holds_all_readings_grey(self):
        value = widget.project(usage_snapshot(
            *self.fleet(), generated=NOW - widget.SNAPSHOT_MAX_AGE - 100),
            NOW)
        self.assertEqual(value["freshness"]["state"], "stale")
        self.assertEqual(value["freshness"]["reason"], "snapshot_expired")
        self.assertIsNone(value["headline"]["fullest_5h_left_percent"])
        self.assertEqual(value["headline"]["current_accounts"], 0)
        for row in value["accounts"]:
            self.assertEqual(row["state"], "stale")
            for window in row["windows"].values():
                self.assertEqual(window["state"], "stale")
                self.assertIsNone(window["left_percent"])
                self.assertTrue(math.isfinite(
                    window["last_observed_left_percent"]))
        # every state the projection can emit has an explicit JS branch
        script = self.widget_script()
        for state in ("current", "limited", "stale", "held"):
            self.assertIn('"%s"' % state, script)


@unittest.skipIf(os.name == "nt", "Übersicht integration is Unix-only")
class UbersichtWidgetTests(unittest.TestCase):
    """The Übersicht desktop port and the shared fail-closed guards.

    The state mapping is one contract in four copies (dashboard/template.html
    is the source; headroom-small.jsx, headroom-medium.jsx and preview.html
    are the ports).  These tests execute the real JS of every copy under node
    and drive the guard FAILURE cases — an expired-but-current snapshot, a
    future evaluated_at, missing timing, a lying headline, and structurally
    malformed feeds — asserting each renders held/grey/offline, never live.
    """

    SMALL = os.path.join(UBERSICHT, "headroom-small.jsx")
    MEDIUM = os.path.join(UBERSICHT, "headroom-medium.jsx")
    PREVIEW = os.path.join(UBERSICHT, "preview.html")
    UB_README = os.path.join(UBERSICHT, "README.md")
    _battery_cache = {}

    @staticmethod
    def read(path):
        with open(path) as handle:
            return handle.read()

    @classmethod
    def sources(cls):
        return {"template": dashboard.TEMPLATE, "small": cls.SMALL,
                "medium": cls.MEDIUM, "preview": cls.PREVIEW}

    @classmethod
    def guard_js(cls, path):
        """Extract the executable state-mapping JS from one of the copies."""
        text = cls.read(path)
        if path.endswith("template.html"):
            code = text.split(
                "/* =================================================== liquid-glass widget */",
                1)[1].split(
                "/* --------------------------------------------------------------- theme */",
                1)[0]
            return ('const SNAPSHOT_MAX_AGE=900;\n'
                    'function clamp(v,lo,hi){return Math.min(hi,Math.max(lo,v));}\n'
                    'function esc(v){return String(v==null?"":v);}\n'
                    'function untilReset(v){return "resets soon";}\n'
                    'function age(v){return "just now";}\n') + code
        if path.endswith("preview.html"):
            return text.split('"use strict";', 1)[1].split(
                "document.querySelectorAll", 1)[0]
        body = text.split(
            "/* ------------------------------------------------------------- helpers",
            1)[1].split(
            "/* --------------------------------------------------------------- styles",
            1)[0]
        return "const SNAPSHOT_MAX_AGE=900;\n/*" + body

    # Scenario battery run against every copy: the three happy-path render
    # states plus every guard failure case from the adversarial review.
    GUARD_TAIL = r"""
;(function () {
  const NOW = Date.now() / 1e3;
  function mkWin(state, left) {
    return { state: state,
      left_percent: state === "current" ? left : null,
      last_observed_left_percent:
        state === "current" || state === "held" ? null : left,
      resets_at: NOW + 3600,
      observed_at: state === "held" ? null : NOW - 40 };
  }
  function mkAcct(state, left, w5, w7) {
    return { name: "acct-" + state, provider: "claude", state: state,
      windows: { "5h": w5 || mkWin(state, left),
                 "7d": w7 || mkWin(state, left) } };
  }
  function mkFeed(fresh, accounts, headline) {
    return { schema: "headroom_widget@1", freshness: fresh,
      accounts: accounts, headline: headline };
  }
  const scenarios = {
    cruising: mkFeed(
      { state: "current", age_seconds: 41, reason: "snapshot_current",
        evaluated_at: NOW },
      [mkAcct("current", 82), mkAcct("current", 47)],
      { current_accounts: 2, total_accounts: 2, fullest_5h_left_percent: 82 }),
    limit_hit: mkFeed(
      { state: "current", age_seconds: 41, reason: "snapshot_current",
        evaluated_at: NOW },
      [mkAcct("current", 82),
       mkAcct("limited", 0, mkWin("limited", 0), mkWin("current", 31))],
      { current_accounts: 1, total_accounts: 2, fullest_5h_left_percent: 82 }),
    feed_stale: mkFeed(
      { state: "stale", age_seconds: 2400, reason: "snapshot_expired",
        evaluated_at: NOW },
      [mkAcct("stale", 58), mkAcct("stale", 71)],
      { current_accounts: 0, total_accounts: 2,
        fullest_5h_left_percent: null }),
    expired: mkFeed(
      { state: "current", age_seconds: 41, reason: "snapshot_current",
        evaluated_at: NOW - 4000 },
      [mkAcct("current", 82)],
      { current_accounts: 1, total_accounts: 1, fullest_5h_left_percent: 82 }),
    future: mkFeed(
      { state: "current", age_seconds: 41, reason: "snapshot_current",
        evaluated_at: NOW + 600 },
      [mkAcct("current", 82)],
      { current_accounts: 1, total_accounts: 1, fullest_5h_left_percent: 82 }),
    missing_timing: mkFeed(
      { state: "current", reason: "snapshot_current" },
      [mkAcct("current", 82)],
      { current_accounts: 1, total_accounts: 1, fullest_5h_left_percent: 82 }),
    lying_headline: mkFeed(
      { state: "current", age_seconds: 5, reason: "snapshot_current",
        evaluated_at: NOW },
      [mkAcct("held", null), mkAcct("held", null)],
      { current_accounts: 3, total_accounts: 2,
        fullest_5h_left_percent: 82 }),
  };
  const grokNo5h = mkAcct("current", 50);
  grokNo5h.provider = "grok";
  delete grokNo5h.windows["5h"];
  scenarios.grok_no_5h = mkFeed(
    { state: "current", age_seconds: 5, reason: "snapshot_current",
      evaluated_at: NOW },
    [grokNo5h],
    { current_accounts: 1, total_accounts: 1,
      fullest_5h_left_percent: null });
  const okHead = { current_accounts: 1, total_accounts: 1,
                   fullest_5h_left_percent: 50 };
  const okFresh = { state: "current", age_seconds: 5,
                    reason: "snapshot_current", evaluated_at: NOW };
  const badCurrent = mkAcct("current", 50);
  badCurrent.windows["5h"].left_percent = null;
  const badStale = mkAcct("stale", 50);
  badStale.windows["5h"].left_percent = 55;
  const badTyped = mkAcct("current", 50);
  badTyped.windows["5h"].left_percent = "50";
  const noSeven = mkAcct("current", 50);
  delete noSeven.windows["7d"];
  // strictness battery: MISSING fields are not null, reason must be a string,
  // headline counts are integers and percentages live in 0-100
  const bareWindows = mkAcct("current", 50);
  bareWindows.windows["5h"] = { state: "current", left_percent: 50 };
  bareWindows.windows["7d"] = { state: "current", left_percent: 50 };
  const numericReason = Object.assign({}, okFresh, { reason: 7 });
  const overHead = Object.assign({}, okHead,
    { fullest_5h_left_percent: 101 });
  const fractionalHead = Object.assign({}, okHead, { current_accounts: 1.5 });
  const negativeAge = Object.assign({}, okFresh, { age_seconds: -5 });
  const malformed = [
    "", "not json", "[]",
    JSON.stringify(Object.assign({}, scenarios.cruising,
      { schema: "headroom_widget@2" })),
    JSON.stringify(Object.assign({}, scenarios.cruising,
      { accounts: "not-an-array" })),
    JSON.stringify(Object.assign({}, scenarios.cruising,
      { freshness: { state: "live", age_seconds: 5, evaluated_at: NOW } })),
    JSON.stringify(Object.assign({}, scenarios.cruising, { headline: null })),
    JSON.stringify(mkFeed(okFresh,
      [{ name: 7, provider: "claude", state: "current",
         windows: { "5h": mkWin("current", 50),
                    "7d": mkWin("current", 50) } }], okHead)),
    JSON.stringify(mkFeed(okFresh, [badCurrent], okHead)),
    JSON.stringify(mkFeed(okFresh, [badStale], okHead)),
    JSON.stringify(mkFeed(okFresh, [badTyped], okHead)),
    JSON.stringify(mkFeed(okFresh, [noSeven], okHead)),
    JSON.stringify(mkFeed(okFresh, [bareWindows], okHead)),
    JSON.stringify(mkFeed(numericReason, [mkAcct("current", 50)], okHead)),
    JSON.stringify(mkFeed(okFresh, [mkAcct("current", 50)], overHead)),
    JSON.stringify(mkFeed(okFresh, [mkAcct("current", 50)], fractionalHead)),
    JSON.stringify(mkFeed(negativeAge, [mkAcct("current", 50)], okHead)),
  ];
  const usesParse = typeof parseFeed === "function";
  const markupFor = (v) => (typeof hrSmallMarkup === "function"
    ? hrSmallMarkup(v) : hrMediumMarkup(v));
  const results = { has_small: typeof hrSmallMarkup === "function",
                    views: {}, rejected: [] };
  for (const name of Object.keys(scenarios)) {
    const feed = scenarios[name];
    const v = hrView(feed);
    const markup = markupFor(v);
    results.views[name] = {
      fresh: v.fresh.state, value: v.hl.value, tone: v.hl.tone,
      line: v.liveLine,
      accepted: usesParse ? parseFeed(JSON.stringify(feed)) !== null
                          : hrValidFeed(feed),
      live_tones: /hr-tone-(green|yellow|orange)/.test(markup),
      red_tone: markup.indexOf("hr-tone-red") !== -1,
      dot_live: markup.indexOf("is-live") !== -1,
    };
  }
  for (const raw of malformed) {
    if (usesParse) results.rejected.push(parseFeed(raw) === null);
    else {
      let rejected = true;
      try { rejected = !hrValidFeed(JSON.parse(raw)); }
      catch (error) { rejected = true; }
      results.rejected.push(rejected);
    }
  }
  console.log(JSON.stringify(results));
})();
"""

    @classmethod
    def battery(cls, name):
        if name not in cls._battery_cache:
            script = cls.guard_js(cls.sources()[name]) + cls.GUARD_TAIL
            proc = subprocess.run([NODE, "-"], input=script,
                                  capture_output=True, text=True, timeout=60)
            if proc.returncode != 0:
                raise AssertionError("node battery failed for %s:\n%s"
                                     % (name, proc.stderr))
            cls._battery_cache[name] = json.loads(
                proc.stdout.strip().splitlines()[-1])
        return cls._battery_cache[name]

    # -------------------------------------------- guard failure cases (node)
    @unittest.skipUnless(NODE, "node runtime required to execute widget JS")
    def test_expired_current_snapshot_demotes_to_stale_grey(self):
        for name in self.sources():
            with self.subTest(source=name):
                view = self.battery(name)["views"]["expired"]
                self.assertEqual(view["fresh"], "stale")
                self.assertEqual(view["value"], "—")
                self.assertEqual(view["tone"], "dim")
                self.assertEqual(view["line"], "0/1 live · feed stale")
                self.assertFalse(view["live_tones"])
                self.assertFalse(view["red_tone"])
                self.assertFalse(view["dot_live"])

    @unittest.skipUnless(NODE, "node runtime required to execute widget JS")
    def test_future_evaluated_at_holds_never_current(self):
        for name in self.sources():
            with self.subTest(source=name):
                view = self.battery(name)["views"]["future"]
                self.assertEqual(view["fresh"], "held")
                self.assertEqual(view["value"], "—")
                self.assertEqual(view["line"], "0/1 live · feed held")
                self.assertFalse(view["live_tones"])
                self.assertFalse(view["dot_live"])

    @unittest.skipUnless(NODE, "node runtime required to execute widget JS")
    def test_missing_timing_is_held_and_structurally_rejected(self):
        for name in self.sources():
            with self.subTest(source=name):
                view = self.battery(name)["views"]["missing_timing"]
                # defence in depth: the freshness guard holds it AND the
                # structural validation refuses to accept the feed at all
                self.assertEqual(view["fresh"], "held")
                self.assertEqual(view["value"], "—")
                self.assertFalse(view["live_tones"])
                self.assertFalse(view["accepted"])

    @unittest.skipUnless(NODE, "node runtime required to execute widget JS")
    def test_headline_is_derived_never_trusted(self):
        # a current snapshot whose accounts are all held but whose headline
        # claims 82% must render the held "—", not a green 82%
        for name in self.sources():
            with self.subTest(source=name):
                view = self.battery(name)["views"]["lying_headline"]
                self.assertEqual(view["fresh"], "current")
                self.assertEqual(view["value"], "—")
                self.assertEqual(view["tone"], "dim")
                self.assertEqual(view["line"], "0/2 accounts live")
                self.assertFalse(view["live_tones"])
                self.assertFalse(view["red_tone"])

    @unittest.skipUnless(NODE, "node runtime required to execute widget JS")
    def test_malformed_feeds_reject_to_offline(self):
        for name in self.sources():
            with self.subTest(source=name):
                rejected = self.battery(name)["rejected"]
                self.assertEqual(len(rejected), 17)
                self.assertTrue(all(rejected),
                                "a malformed feed was accepted: %s" % rejected)
        # a rejected parse selects the offline view in the widget render
        for path in (self.SMALL, self.MEDIUM):
            text = self.read(path)
            self.assertIn("const data = error ? null : parseFeed(output);",
                          text)
            self.assertIn("const v = data ? hrView(data) : hrOfflineView();",
                          text)

    @unittest.skipUnless(NODE, "node runtime required to execute widget JS")
    def test_happy_path_render_states_are_unchanged(self):
        for name in self.sources():
            with self.subTest(source=name):
                views = self.battery(name)["views"]
                has_small = self.battery(name)["has_small"]
                cruising = views["cruising"]
                self.assertEqual(cruising["fresh"], "current")
                # headline = fleet average battery: (82 + 47) / 2 -> 65%
                self.assertEqual(cruising["value"], "65%")
                self.assertEqual(cruising["tone"], "green")
                self.assertEqual(cruising["line"], "2/2 accounts live")
                self.assertTrue(cruising["accepted"])
                self.assertTrue(cruising["live_tones"])
                if has_small:
                    self.assertTrue(cruising["dot_live"])
                limit = views["limit_hit"]
                # (82 + an honest 0 for the capped window) / 2 -> 41%
                self.assertEqual(limit["value"], "41%")
                self.assertEqual(limit["tone"], "yellow")
                self.assertEqual(limit["line"], "1/2 live · 1 at limit")
                # design intent: a really-capped window stays RED, not dimmed
                self.assertTrue(limit["red_tone"])
                self.assertTrue(limit["accepted"])
                stale = views["feed_stale"]
                self.assertEqual(stale["fresh"], "stale")
                self.assertEqual(stale["value"], "—")
                self.assertEqual(stale["tone"], "dim")
                self.assertEqual(stale["line"], "0/2 live · feed stale")
                self.assertTrue(stale["accepted"])
                self.assertFalse(stale["live_tones"])
                self.assertFalse(stale["red_tone"])
                self.assertFalse(stale["dot_live"])
                grok = views["grok_no_5h"]
                self.assertTrue(grok["accepted"])
                self.assertTrue(grok["live_tones"])

    # ------------------------------------------------- static port contract
    @classmethod
    def command_script(cls, path):
        """The executable shell of one widget's `command` export."""
        text = cls.read(path)
        command = text.split("export const command = `", 1)[1].split(
            "`;", 1)[0]
        # the JSX template literal escapes `${...}` — undo for real sh
        return command.replace("\\$", "$")

    def run_command(self, path, url):
        """Run the widget command under /bin/sh with curl stubbed out.

        Returns (returncode, curl_argv or None) — None when the guard
        rejected the URL before any fetch could happen.
        """
        with tempfile.TemporaryDirectory() as directory:
            log = os.path.join(directory, "curl-args.log")
            stub = os.path.join(directory, "curl")
            with open(stub, "w") as handle:
                handle.write('#!/bin/sh\nprintf \'%s\\n\' "$@" > "$CURL_LOG"\n')
            os.chmod(stub, 0o755)
            env = os.environ.copy()
            env["PATH"] = directory + os.pathsep + env["PATH"]
            env["CURL_LOG"] = log
            env.pop("HEADROOM_WIDGET_URL", None)
            if url is not None:
                env["HEADROOM_WIDGET_URL"] = url
            proc = subprocess.run(
                ["/bin/sh", "-c", self.command_script(path)], env=env,
                capture_output=True, text=True, timeout=30)
            argv = None
            if os.path.exists(log):
                with open(log) as handle:
                    argv = handle.read().splitlines()
            return proc.returncode, argv

    def test_ubersicht_command_is_hermetic_and_fail_closed(self):
        for path in (self.SMALL, self.MEDIUM):
            with self.subTest(path=os.path.basename(path)):
                text = self.read(path)
                command = text.split("export const command = `", 1)[1].split(
                    "`;", 1)[0]
                # the port is the EXACT remainder of an accepted loopback
                # prefix — never a substring parse that can be smuggled past
                self.assertIn('http://127.0.0.1:*) '
                              'port="\\${url#http://127.0.0.1:}" ;;', command)
                self.assertIn('http://localhost:*) '
                              'port="\\${url#http://localhost:}" ;;', command)
                self.assertIn('""|0*|*[!0-9]*)', command)
                self.assertIn('[ "$port" -ge 1 ] && [ "$port" -le 65535 ] '
                              "|| exit 1", command)
                self.assertIn("exec curl -q --fail --silent --show-error "
                              "--noproxy '*' --max-time 4 "
                              '"http://127.0.0.1:$port/widget.json"', command)
                self.assertNotIn("curl -s ", command)

    def test_ubersicht_command_rejects_hostile_urls_executably(self):
        hostile = [
            "http://127.0.0.1:8377@evil.example:80",
            "http://127.0.0.1:8377/path:80",
            "http://localhost:8377;ignored:80",
            "http://127.0.0.1:8377?x=1:80",
            "http://127.0.0.1.evil.example:8377",
            "http://evil.example:8377",
            "https://127.0.0.1:8377",
            "ftp://127.0.0.1:8377",
            "http://127.0.0.1:",
            "http://127.0.0.1:0",
            "http://127.0.0.1:080",
            "http://127.0.0.1:65536",
            "http://127.0.0.1:99999999999999999999",
            "http://localhost:8377 http://evil.example",
        ]
        for path in (self.SMALL, self.MEDIUM):
            for url in hostile:
                with self.subTest(path=os.path.basename(path), url=url):
                    code, argv = self.run_command(path, url)
                    self.assertNotEqual(code, 0, "guard accepted %r" % url)
                    self.assertIsNone(argv, "curl ran for %r: %r"
                                      % (url, argv))

    def test_ubersicht_command_accepts_only_canonical_loopback(self):
        accepted = {
            None: "http://127.0.0.1:8377/widget.json",
            "http://127.0.0.1:9000": "http://127.0.0.1:9000/widget.json",
            "http://localhost:8377": "http://127.0.0.1:8377/widget.json",
            "http://localhost:8377/": "http://127.0.0.1:8377/widget.json",
        }
        for path in (self.SMALL, self.MEDIUM):
            for url, fetch in accepted.items():
                with self.subTest(path=os.path.basename(path), url=url):
                    code, argv = self.run_command(path, url)
                    self.assertEqual(code, 0)
                    self.assertIsNotNone(argv)
                    # curl fetches ONLY the canonically rebuilt loopback URL
                    self.assertEqual(argv[-1], fetch)

    def test_ubersicht_state_mapping_is_byte_identical_across_ports(self):
        functions = ("no5h", "hrTone", "hrPct", "hrWindow", "hrDemoteWindow",
                     "hrFreshness", "hrAccount", "hrView", "hrOfflineView",
                     "hrFiniteOrNull", "hrValidWindow", "hrValidFeed",
                     "parseFeed")
        texts = {path: self.read(path)
                 for path in (self.SMALL, self.MEDIUM, self.PREVIEW)}
        for name in functions:
            bodies = set()
            for path, text in texts.items():
                self.assertIn("function %s(" % name, text,
                              "%s missing from %s" % (name, path))
                bodies.add(text.split("function %s(" % name, 1)[1].split(
                    "\n}", 1)[0])
            self.assertEqual(len(bodies), 1,
                             "%s drifted between the Übersicht copies" % name)

    def test_ubersicht_readme_reconciles_expired_future_as_held(self):
        readme = self.read(self.UB_README)
        self.assertIn("expired, future-dated, or timing-less snapshot",
                      readme)
        self.assertIn("grey stale/held card", readme)
        self.assertIn("headline % is derived, not trusted", readme)
        # "feed unreachable" is reserved for transport/shape failures
        unreachable = readme.split('renders the grey "feed unreachable"', 1)[0]
        self.assertIn("`headroom_widget@1` shape check",
                      unreachable.rsplit("- ", 1)[1])
        for flag in ("-q", "--fail", "--noproxy '*'", "--show-error"):
            self.assertIn(flag, readme)

    def test_preview_carries_guard_failure_fixtures(self):
        preview = self.read(self.PREVIEW)
        for fixture in ("expired", "future", "missing-timing",
                        "inconsistent-headline", "malformed"):
            self.assertIn('data-fixture="%s"' % fixture, preview)
        for constant in ("const EXPIRED", "const FUTURE",
                         "const MISSING_TIMING", "const INCONSISTENT",
                         "const MALFORMED"):
            self.assertIn(constant, preview)
        # the malformed fixture must flow through the real parseFeed gate
        wiring = preview.split('if (kind === "malformed")', 1)[1]
        self.assertIn("parseFeed(MALFORMED)", wiring.split("}", 1)[0])


@unittest.skipIf(os.name == "nt", "SwiftBar integration is macOS-only")
class SwiftBarPluginTests(unittest.TestCase):
    @staticmethod
    def valid_body(port=8377):
        return ("headroom_widget_txt@1\n"
                "hr 1/1 · 80% | color=green\n"
                "---\n"
                "alpha · claude · CURRENT | color=green\n"
                "Refresh | refresh=true\n"
                f"Open dashboard | href=http://127.0.0.1:{port}/\n")

    @classmethod
    def run_plugin(cls, body, url="http://127.0.0.1:8377", local=False):
        with tempfile.TemporaryDirectory() as directory:
            body_path = os.path.join(directory, "body.txt")
            log_path = os.path.join(directory, "args.log")
            with open(body_path, "w") as handle:
                handle.write(body)
            env = os.environ.copy()
            env["HEADROOM_TEST_BODY"] = body_path
            env["HEADROOM_TEST_CURL_LOG"] = log_path
            if local:
                client = os.path.join(directory, "headroom-test")
                with open(client, "w") as handle:
                    handle.write(
                        "#!/bin/sh\n"
                        "printf '%s\\n' \"$@\" >\"$HEADROOM_TEST_CURL_LOG\"\n"
                        "cat \"$HEADROOM_TEST_BODY\"\n")
                os.chmod(client, 0o755)
                env.pop("HEADROOM_WIDGET_URL", None)
                env["HEADROOM_BIN"] = client
            else:
                client = os.path.join(directory, "curl")
                with open(client, "w") as handle:
                    handle.write(
                        "#!/bin/sh\n"
                        "printf '%s\\n' \"$@\" >\"$HEADROOM_TEST_CURL_LOG\"\n"
                        "[ -z \"${HEADROOM_TEST_CURL_EXIT:-}\" ] || exit \"$HEADROOM_TEST_CURL_EXIT\"\n"
                        "out=\n"
                        "seen=0\n"
                        "while [ \"$#\" -gt 0 ]; do\n"
                        "  case \"$1\" in\n"
                        "    --output) shift; out=$1 ;;\n"
                        "    --) shift; [ \"$#\" -eq 1 ] || exit 91; seen=1; break ;;\n"
                        "  esac\n"
                        "  shift\n"
                        "done\n"
                        "[ \"$seen\" -eq 1 ] && [ -n \"$out\" ] || exit 92\n"
                        "cp \"$HEADROOM_TEST_BODY\" \"$out\"\n")
                os.chmod(client, 0o755)
                env["PATH"] = directory + os.pathsep + env.get("PATH", "")
                env["HEADROOM_WIDGET_URL"] = url
                env.pop("HEADROOM_BIN", None)
            result = subprocess.run(
                [PLUGIN], env=env, text=True, capture_output=True,
                timeout=5, check=False)
            arguments = []
            if os.path.exists(log_path):
                with open(log_path) as handle:
                    arguments = handle.read().splitlines()
            return result, arguments

    @classmethod
    def run_failed_curl(cls):
        with mock.patch.dict(os.environ, {"HEADROOM_TEST_CURL_EXIT": "22"}):
            return cls.run_plugin(cls.valid_body())

    def test_plugin_filename_requests_one_minute_polling(self):
        self.assertEqual(os.path.basename(PLUGIN), "headroom.1m.sh")
        self.assertTrue(os.access(PLUGIN, os.X_OK))

    def test_plugin_local_mode_runs_installed_binary(self):
        result, arguments = self.run_plugin(self.valid_body(), local=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(arguments, ["widget-feed", "--swiftbar"])
        self.assertIn("hr 1/1 · 80% | color=green", result.stdout)

    def test_plugin_remote_mode_uses_bounded_curl(self):
        result, arguments = self.run_plugin(self.valid_body())
        self.assertEqual(result.returncode, 0)
        self.assertEqual(arguments[-2:],
                         ["--", "http://127.0.0.1:8377/widget.txt"])
        self.assertIn("--fail", arguments)
        self.assertIn("--silent", arguments)
        self.assertEqual(arguments[arguments.index("--max-time") + 1], "3")
        self.assertEqual(arguments[arguments.index("--max-filesize") + 1],
                         "65536")
        self.assertNotIn("headroom_widget_txt@1", result.stdout)

    def test_plugin_rejects_missing_or_wrong_sentinel(self):
        for body in ("PWN | color=green\n", "wrong\nPWN | color=green\n"):
            with self.subTest(body=body):
                result, _ = self.run_plugin(body)
                self.assertIn("hr OFFLINE | color=gray", result.stdout)
                self.assertNotIn("PWN", result.stdout)

    def test_plugin_rejects_oversized_response(self):
        result, _ = self.run_plugin(
            "headroom_widget_txt@1\n" + "x" * 65536 + "\n")
        self.assertIn("hr OFFLINE | color=gray", result.stdout)
        self.assertNotIn("x" * 100, result.stdout)

    def test_plugin_curl_failure_is_visible_offline(self):
        result, arguments = self.run_failed_curl()
        self.assertNotEqual(arguments, [])
        self.assertEqual(result.returncode, 0)
        self.assertIn("hr OFFLINE | color=gray", result.stdout)

    def test_plugin_rejects_hostile_fetched_parameter_sections(self):
        attacks = (
            "headroom_widget_txt@1\nPWN | shell=/bin/sh param1=-c\n",
            self.valid_body().replace(
                "color=green\n", "color=green shell=/bin/sh\n", 1),
            self.valid_body().replace(
                "href=http://127.0.0.1:8377/",
                "href=http://127.0.0.1:8377@evil.example/"),
        )
        for body in attacks:
            with self.subTest(body=body):
                result, _ = self.run_plugin(body)
                self.assertEqual(result.returncode, 0)
                self.assertIn("hr OFFLINE | color=gray", result.stdout)
                self.assertNotIn("PWN", result.stdout)
                self.assertNotIn("shell=", result.stdout)
                self.assertNotIn("evil.example", result.stdout)

    def test_plugin_rejects_hostile_url_before_curl(self):
        attacks = (
            "http://127.0.0.1:8377 | shell=/bin/sh",
            "http://localhost:8377@evil.example/widget.txt",
            "http://127.0.0.1:8377/widget.txt?x=1",
            "http://127.0.0.1:0/widget.txt",
            "https://127.0.0.1:8377/widget.txt",
        )
        for url in attacks:
            with self.subTest(url=url):
                result, arguments = self.run_plugin(self.valid_body(), url)
                self.assertEqual(arguments, [])
                self.assertIn("hr OFFLINE | color=gray", result.stdout)
                self.assertIn("href=http://127.0.0.1:8377/", result.stdout)
                self.assertNotIn("shell=", result.stdout)
                self.assertNotIn("evil.example", result.stdout)

    def test_plugin_canonicalizes_localhost_origin(self):
        result, arguments = self.run_plugin(
            self.valid_body(49152), "http://localhost:49152/widget.txt")
        self.assertEqual(arguments[-1],
                         "http://127.0.0.1:49152/widget.txt")
        self.assertIn("href=http://127.0.0.1:49152/", result.stdout)


class ExperimentalWindowsTests(unittest.TestCase):
    @staticmethod
    def script():
        with open(WINDOWS_SCRIPT) as handle:
            return handle.read()

    def test_windows_script_uses_application_context(self):
        script = self.script()
        self.assertIn("New-Object System.Windows.Forms.ApplicationContext", script)
        self.assertIn("[System.Windows.Forms.Application]::Run($script:Context)",
                      script)
        self.assertIn("System.Windows.Forms.NotifyIcon", script)

    def test_windows_script_maps_all_four_states_to_static_icons(self):
        script = self.script()
        expected = {"green", "amber", "red", "gray"}
        for state in expected:
            name = "headroom-%s.ico" % state
            self.assertIn(name, script)
            path = os.path.join(WINDOWS_ICONS, name)
            self.assertTrue(os.path.isfile(path))
            with open(path, "rb") as handle:
                header = struct.unpack("<HHH", handle.read(6))
            self.assertEqual(header, (0, 1, 3))

    def test_windows_tooltip_is_capped_at_63_characters(self):
        script = self.script()
        assignments = [line.strip() for line in script.splitlines()
                       if "$script:Tray.Text =" in line]
        self.assertEqual(len(assignments), 1)
        self.assertIn(".Substring(0, [Math]::Min(63, $Tooltip.Length))",
                      assignments[0])

    def test_windows_context_menu_has_refresh_and_open_dashboard(self):
        script = self.script()
        self.assertIn('ToolStripMenuItem("Refresh")', script)
        self.assertIn("$refreshItem.add_Click({ Refresh-Headroom })", script)
        self.assertIn('ToolStripMenuItem("Open dashboard")', script)
        self.assertIn("$openItem.add_Click({ Start-Process $DashboardUrl })", script)

    def test_windows_failure_always_selects_gray_offline(self):
        script = self.script()
        refresh = script.split("function Refresh-Headroom {", 1)[1].split(
            "\n}\n\n$menu", 1)[0]
        self.assertEqual(refresh.count("\n    catch {"), 1)
        attempt, failure = refresh.split("\n    catch {", 1)
        self.assertRegex(failure, r'^\s*Set-TrayStatus "gray" '
                         r'"headroom OFFLINE"\s*\}\s*$')
        thrown = set(re.findall(r'throw "([^"]+)"', attempt))
        self.assertEqual(thrown, {
            "widget response too large", "widget schema mismatch",
            "widget is not current", "widget clock invalid",
            "widget fields missing", "widget counts invalid",
            "widget percentage invalid",
        })
        guards = (
            r'if \(\[Text\.Encoding\]::UTF8\.GetByteCount\('
            r'\$response\.Content\) -gt 65536\) \{\s*'
            r'throw "widget response too large"\s*\}',
            r'if \(\$data\.schema -ne "headroom_widget@1"\) '
            r'\{ throw "widget schema mismatch" \}',
            r'if \(\$null -eq \$data\.freshness -or '
            r'\$data\.freshness\.state -ne "current"\) \{\s*'
            r'throw "widget is not current"\s*\}',
            r'if \(\$null -eq \$data\.accounts -or '
            r'\$null -eq \$data\.headline\) \{\s*'
            r'throw "widget fields missing"\s*\}',
            r'if \(\$evaluatedAt -gt \$now -or '
            r'\(\$now - \$evaluatedAt\) -gt 300 -or\s*'
            r'\$ageSeconds -lt 0 -or \$ageSeconds -gt 900\) \{\s*'
            r'throw "widget clock invalid"\s*\}',
            r'if \(\$current -lt 0 -or \$total -lt \$current -or\s*'
            r'\$total -ne \$accountCount\) \{ throw "widget counts invalid" \}',
            r'if \(\[Double\]::IsNaN\(\$percent\) -or '
            r'\[Double\]::IsInfinity\(\$percent\) -or\s*'
            r'\$percent -lt 0 -or \$percent -gt 100\) \{\s*'
            r'throw "widget percentage invalid"\s*\}',
        )
        for guard in guards:
            self.assertRegex(attempt, guard)

    def test_windows_script_has_no_gdi_or_rotation_actions(self):
        script = self.script().lower()
        for forbidden in ("system.drawing.bitmap", "graphics", "drawicon",
                          "rotate", "headroom mark", "headroom clear",
                          "headroom pick", "headroom env"):
            self.assertNotIn(forbidden, script)


class WidgetDocumentationTests(unittest.TestCase):
    @staticmethod
    def readme():
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
            return handle.read()

    def test_readme_documents_widget_security_and_ssh_only_remote_path(self):
        readme = self.readme()
        widgets = readme.split("## Widgets", 1)[1].split("## The commands", 1)[0]
        self.assertIn("ssh -N -L 8377:127.0.0.1:8377", widgets)
        self.assertIn("only supported remote pattern", widgets)
        for constraint in ("loopback-only", "Host", "no CORS", "no-store",
                           "nosniff", "never evaluates", "64 KB"):
            self.assertIn(constraint, widgets)

    def test_readme_labels_windows_experimental(self):
        readme = self.readme()
        windows = readme.split("### Windows tray — EXPERIMENTAL", 1)[1].split(
            "## The commands", 1)[0]
        self.assertIn("not stable or supported", windows)
        self.assertIn("powershell -ExecutionPolicy Bypass -File experimental/windows/headroom-tray.ps1",
                      windows)
        self.assertIn("Windows 10/11 PowerShell 5.1", windows)

    def test_widgets_hero_capture_exists(self):
        readme = self.readme()
        reference = ("![Menu bar widget and compact dashboard, rendered from "
                     "live fleet data](marketing/hr-widgets.png)")
        self.assertIn(reference, readme)
        self.assertTrue(os.path.exists(os.path.join(ROOT,
                                                    "marketing/hr-widgets.png")))


if __name__ == "__main__":
    unittest.main()
