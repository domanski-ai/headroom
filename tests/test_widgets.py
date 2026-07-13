"""Widget contract, refresh gate, integrations, and release artifact tests."""
import io
import json
import math
import os
import re
import struct
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, redirect_stdout
from unittest import mock

from headroom import __main__, dashboard, paths, widget


NOW = 2_000_000_000
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(ROOT, "integrations", "swiftbar", "headroom.1m.sh")
WINDOWS_SCRIPT = os.path.join(ROOT, "experimental", "windows",
                              "headroom-tray.ps1")
WINDOWS_ICONS = os.path.join(ROOT, "experimental", "windows", "icons")


def usage_account(name="alpha", used5=20.0, used7=40.0, **overrides):
    account = {
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


def memory_get(handler_class, directory, route, host="127.0.0.1:8377"):
    """Drive the real request handler without opening a sandbox-blocked socket."""
    handler = object.__new__(handler_class)
    handler.directory = directory
    handler.path = route
    handler.headers = {"Host": host}
    handler.command = "GET"
    handler.request_version = "HTTP/1.1"
    handler.requestline = "GET %s HTTP/1.1" % route
    handler.client_address = ("127.0.0.1", 1)
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
        self.assertEqual(projected["windows"]["7d"]["state"], "held")
        self.assertIsNone(projected["windows"]["7d"]["left_percent"])

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

    def test_headline_uses_fullest_current_5h_tank(self):
        value = widget.project(usage_snapshot(
            usage_account("a", used5=55), usage_account("b", used5=8)), NOW)
        self.assertEqual(value["headline"], {
            "current_accounts": 2, "total_accounts": 2,
            "fullest_5h_left_percent": 92.0})

    def test_headline_excludes_noncurrent_candidates(self):
        value = widget.project(usage_snapshot(
            usage_account("current", used5=60),
            usage_account("limited", used5=100),
            usage_account("stale", used5=1, stale=True),
            usage_account("held", used5=0, ok=False, trust_state="held")), NOW)
        self.assertEqual(value["headline"]["current_accounts"], 1)
        self.assertEqual(value["headline"]["fullest_5h_left_percent"], 40.0)

    def test_headline_without_candidate_is_gray_placeholder(self):
        value = usage_snapshot(usage_account(stale=True, used5=1))
        rendered = widget.render_swiftbar(value, NOW)
        self.assertIn("hr 0/1 · -- | color=gray", rendered.splitlines()[1])


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

    def test_swiftbar_renderer_labels_fullest_tank(self):
        rendered = widget.render_swiftbar(
            usage_snapshot(usage_account()), NOW)
        self.assertIn("Fullest tank: 80% (current 5h)", rendered)

    def test_swiftbar_renderer_emits_no_execution_directives(self):
        account = usage_account("safe")
        account["provider"] = "bad | bash=/tmp/x shell=yes terminal=true param1=x"
        rendered = widget.render_swiftbar(usage_snapshot(account), NOW).lower()
        self.assertIsNone(re.search(r"(?:bash|shell|terminal|param\d+)=", rendered))

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
        with open(dashboard.TEMPLATE) as handle:
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

    def test_all_responses_have_security_headers(self):
        with mock.patch.object(widget.time, "time", return_value=NOW):
            with self.demo_server() as server:
                responses = [memory_get(*server, route) for route in
                             ("/", "/widget.json", "/missing")]
                responses.append(memory_get(*server, "/", "evil.example"))
        for _, headers, _ in responses:
            self.assertEqual(headers.get("cache-control"), "no-store")
            self.assertEqual(headers.get("x-content-type-options"), "nosniff")

    def test_no_response_enables_cors(self):
        with mock.patch.object(widget.time, "time", return_value=NOW):
            with self.demo_server() as server:
                responses = [memory_get(*server, route) for route in
                             ("/", "/usage.json", "/widget.json",
                              "/widget.txt", "/missing")]
        for _, headers, _ in responses:
            self.assertNotIn("access-control-allow-origin", headers)

    def test_nonloopback_host_is_rejected_for_every_route(self):
        with self.demo_server() as server:
            statuses = [memory_get(*server, route, "attacker.example")[0]
                        for route in ("/", "/widget", "/usage.json",
                                      "/widget.json", "/widget.txt", "/missing")]
        self.assertEqual(statuses, [403] * 6)

    def test_stale_and_held_fleet_bars_are_gray(self):
        template = self.template_text()
        self.assertIn("if(!isCurrent(a)||left==null)return'<span class=\"fbar is-unknown\"",
                      template)
        self.assertIn("const left=isCurrent(account)?capacity(w):null", template)
        self.assertIn(".fbar.is-unknown { background: var(--unknown)", template)

    def test_current_fleet_bars_retain_capacity_colors(self):
        template = self.template_text()
        self.assertIn("'<span class=\"fbar tone-'+tone(left)", template)
        self.assertIn("function tone(left)", template)

    def test_compact_mode_retains_state_disclosure(self):
        template = self.template_text()
        compact_css = template.split("/* Compact mode", 1)[1].split("</style>", 1)[0]
        self.assertIn("body.is-compact .acct-identity, body.is-compact .state",
                      compact_css)
        self.assertNotIn("display: none", compact_css)
        self.assertIn('class="statusline" id="status"', template)


class SwiftBarPluginTests(unittest.TestCase):
    @staticmethod
    def script():
        with open(PLUGIN) as handle:
            return handle.read()

    def test_plugin_filename_requests_one_minute_polling(self):
        self.assertEqual(os.path.basename(PLUGIN), "headroom.1m.sh")
        self.assertTrue(os.access(PLUGIN, os.X_OK))

    def test_plugin_local_mode_runs_installed_binary(self):
        script = self.script()
        local = script.split("else", 1)[1]
        self.assertIn("${HEADROOM_BIN:-headroom} widget-feed --swiftbar", local)
        self.assertNotIn("curl", local.split("fi", 1)[0])

    def test_plugin_remote_mode_uses_bounded_curl(self):
        script = self.script()
        self.assertIn("curl --fail --silent --max-time 3", script)
        self.assertIn("--max-filesize 65536", script)
        self.assertIn("[ \"$bytes\" -gt 65536 ]", script)

    def test_plugin_accepts_only_exact_sentinel(self):
        script = self.script()
        self.assertIn("sentinel='headroom_widget_txt@1'", script)
        self.assertIn('[ "$first" != "$sentinel" ]', script)
        self.assertIn("sed '1d' \"$tmp\"", script)

    def test_plugin_rejects_missing_or_wrong_sentinel(self):
        script = self.script()
        guard = script.split('if [ "$bytes" -gt 65536 ]', 1)[1]
        self.assertIn('[ "$lines" -lt 2 ]', guard)
        self.assertIn('[ "$first" != "$sentinel" ]', guard)
        self.assertIn("offline", guard.split("\nfi\n", 1)[0])

    def test_plugin_curl_failure_is_visible_offline(self):
        script = self.script()
        remote = script.split("if ! curl", 1)[1].split("else", 1)[0]
        self.assertIn("offline", remote)
        self.assertIn("exit 0", remote)
        self.assertIn("hr OFFLINE | color=gray", script)

    def test_plugin_rejects_oversized_response(self):
        script = self.script()
        self.assertIn("--max-filesize 65536", script)
        oversized = script.split('[ "$bytes" -gt 65536 ]', 1)[1]
        self.assertIn("offline", oversized.split("\nfi\n", 1)[0])

    def test_plugin_never_evaluates_response(self):
        script = self.script().lower()
        for forbidden in ("eval", "source", "bash -c", "sh -c", "exec $",
                          "`$", "$(cat"):
            self.assertNotIn(forbidden, script)


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
        failure = script.split("\n    catch {", 1)[1].split("\n    }", 1)[0]
        self.assertIn('Set-TrayStatus "gray" "headroom OFFLINE"', failure)
        for validation in ("schema mismatch", "not current", "clock invalid",
                           "fields missing", "counts invalid",
                           "percentage invalid", "response too large"):
            self.assertIn(validation, script)

    def test_windows_script_has_no_gdi_or_rotation_actions(self):
        script = self.script().lower()
        for forbidden in ("system.drawing.bitmap", "graphics", "drawicon",
                          "rotate", "headroom mark", "headroom clear",
                          "headroom pick", "headroom env"):
            self.assertNotIn(forbidden, script)


class WidgetDocumentationTests(unittest.TestCase):
    @staticmethod
    def readme():
        with open(os.path.join(ROOT, "README.md")) as handle:
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
        reference = ("![Placeholder: Mac menu bar and compact dashboard capture "
                     "will be added after E2E](marketing/hr-widgets.png)")
        self.assertIn(reference, readme)
        # The build brief reserves capture creation for the orchestrator.
        self.assertFalse(os.path.exists(os.path.join(ROOT,
                                                     "marketing/hr-widgets.png")))


if __name__ == "__main__":
    unittest.main()
