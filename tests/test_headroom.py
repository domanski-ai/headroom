"""headroom test suite — stdlib unittest only, no pytest, no network.

Run:  python3 -m unittest discover -s tests   (from the repo root)

Covers the load-bearing safety logic: config validation, the fail-closed
router (`block_reason`), redaction, and the public-snapshot projection.
"""
import json
import hashlib
import io
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from headroom import collect, connect, handoff, registry, route, statusline  # noqa: E402


def _claude_row(name="a", used5h=10.0, used7d=20.0, ok=True, **over):
    now = int(time.time())
    row = {
        "name": name, "provider": "claude", "plan": "Max 20x", "ok": ok,
        "stale": False, "routable": ok, "identity_verified": True,
        "identity": {"account_fingerprint": "AAAA", "credential_digest": "BBBB"},
        "trust_state": "verified" if ok else "held", "captured_at": now - 10,
        "source": "anthropic_usage_api",
        "windows": {
            "5h": {"used_percent": used5h, "resets_at": now + 3600,
                   "window_minutes": 300},
            "7d": {"used_percent": used7d, "resets_at": now + 8 * 86400,
                   "window_minutes": 10080},
        },
    }
    row.update(over)
    return row


def _account(name="a", provider="claude"):
    return {"name": name, "provider": provider, "home": "/tmp/hr-t/" + name}


class RegistryValidation(unittest.TestCase):
    def test_rejects_bad_schema(self):
        with self.assertRaises(registry.RegistryError):
            registry.validate({"accounts": []})

    def test_rejects_bad_name(self):
        cfg = {"schema_version": 1, "accounts": [
            {"name": "Bad Name!", "provider": "claude", "home": "/tmp/x"}]}
        with self.assertRaises(registry.RegistryError):
            registry.validate(cfg)

    def test_rejects_duplicate_home(self):
        cfg = {"schema_version": 1, "accounts": [
            {"name": "a", "provider": "claude", "home": "/tmp/x"},
            {"name": "b", "provider": "claude", "home": "/tmp/x"}]}
        with self.assertRaises(registry.RegistryError):
            registry.validate(cfg)

    def test_accepts_valid(self):
        cfg = {"schema_version": 1, "accounts": [
            {"name": "personal", "provider": "claude", "home": "~/.claude"}]}
        self.assertEqual(registry.validate(cfg), cfg)

    def test_unknown_model_family_raises(self):
        with self.assertRaises(registry.RegistryError):
            registry.family("banana-model-xyz")

    def test_known_families(self):
        self.assertEqual(registry.family("claude-opus-4"), "opus")
        self.assertEqual(registry.family("gpt-5.6-codex"), "codex")
        self.assertEqual(registry.family(""), "claude")


class BlockReasonFailClosed(unittest.TestCase):
    def setUp(self):
        self.now = time.time()
        # the router re-derives the slot's live identity+credential; in tests
        # there are no real homes, so return the fixture's bound values
        self._orig_binding = collect.local_binding
        collect.local_binding = lambda provider, home: ("AAAA", "BBBB")

    def tearDown(self):
        collect.local_binding = self._orig_binding

    _UNSET = object()

    def reason(self, row, fam="sonnet", cool=_UNSET):
        cool = {} if cool is self._UNSET else cool
        return route.block_reason(_account(), fam, row, cool, self.now)

    def test_healthy_routes(self):
        self.assertIsNone(self.reason(_claude_row(used5h=10)))

    def test_100pct_holds(self):
        self.assertIsNotNone(self.reason(_claude_row(used5h=100)))

    def test_missing_row_holds(self):
        self.assertIsNotNone(self.reason(None))

    def test_not_ok_holds(self):
        self.assertIsNotNone(self.reason(_claude_row(ok=False)))

    def test_string_percent_holds(self):
        row = _claude_row()
        row["windows"]["5h"]["used_percent"] = "10"
        self.assertIsNotNone(self.reason(row))

    def test_future_capture_holds(self):
        row = _claude_row()
        row["captured_at"] = self.now + 10_000
        self.assertIsNotNone(self.reason(row))

    def test_stale_holds(self):
        self.assertIsNotNone(self.reason(_claude_row(stale=True)))

    def test_corrupt_cooldown_value_holds(self):
        r = self.reason(_claude_row(), cool={"a:sonnet": "not-a-number"})
        self.assertIsNotNone(r)

    def test_none_ledger_holds(self):
        self.assertIsNotNone(self.reason(_claude_row(), cool=None))

    def test_trust_routable_mismatch_holds(self):
        row = _claude_row()
        row["trust_state"] = "held"  # but routable stayed True
        self.assertIsNotNone(self.reason(row))

    def test_expired_observation_holds(self):
        row = _claude_row()
        row["windows"]["5h"] = {"used_percent": None,
                                "freshness": "expired_observation",
                                "resets_at": 1, "window_minutes": 300}
        self.assertIsNotNone(self.reason(row))

    def test_identity_mismatch_holds(self):
        collect.local_binding = lambda provider, home: ("XXXX", "BBBB")
        self.assertIsNotNone(self.reason(_claude_row()))

    def test_credential_changed_holds(self):
        collect.local_binding = lambda provider, home: ("AAAA", "WRONG")
        self.assertIsNotNone(self.reason(_claude_row()))

    def test_identity_match_routes(self):
        # setUp already patches local_binding to the matching values
        self.assertIsNone(self.reason(_claude_row()))

    def test_no_snapshot_identity_holds(self):
        row = _claude_row()
        row.pop("identity")
        self.assertIsNotNone(self.reason(row))

    def test_no_credential_digest_holds(self):
        row = _claude_row()
        row["identity"] = {"account_fingerprint": "AAAA"}  # no credential_digest
        self.assertIsNotNone(self.reason(row))

    def test_non_dict_windows_holds(self):
        row = _claude_row()
        row["windows"] = ["not", "a", "dict"]
        self.assertIsNotNone(self.reason(row))

    def test_generic_claude_not_blocked_by_opus_cap(self):
        row = _claude_row()
        row["windows"]["scoped:Opus"] = {"used_percent": 100.0,
                                         "resets_at": self.now + 8 * 86400,
                                         "window_minutes": 10080}
        # generic claude route must NOT be held by an Opus-only cap
        self.assertIsNone(self.reason(row, fam="claude"))
        # but the opus family IS held
        self.assertIsNotNone(self.reason(row, fam="opus"))


class ReservePercent(unittest.TestCase):
    """`reserve_percent` skips accounts with less than N% headroom left so a
    session starts fresh instead of hitting a wall mid-task."""

    def setUp(self):
        self.now = time.time()
        self._orig = collect.local_binding
        collect.local_binding = lambda provider, home: ("AAAA", "BBBB")

    def tearDown(self):
        collect.local_binding = self._orig

    def reason(self, row, fam="sonnet", reserve=0.0):
        return route.block_reason(_account(), fam, row, {}, self.now,
                                  reserve=reserve)

    def test_zero_reserve_uses_account_to_the_limit(self):
        self.assertIsNone(self.reason(_claude_row(used5h=97), reserve=0.0))

    def test_below_reserve_holds(self):
        # 3% left < 10% reserve -> held
        self.assertIsNotNone(self.reason(_claude_row(used5h=97), reserve=10))

    def test_exactly_at_reserve_routes(self):
        # 10% left is not < 10% reserve -> still routable
        self.assertIsNone(self.reason(_claude_row(used5h=90), reserve=10))

    def test_comfortably_above_reserve_routes(self):
        self.assertIsNone(self.reason(_claude_row(used5h=50), reserve=10))

    def test_reserve_applies_to_weekly_window(self):
        # 5h fine, but 7d has only 5% left
        self.assertIsNotNone(self.reason(_claude_row(used5h=10, used7d=95),
                                         reserve=10))

    def test_reserve_gates_scoped_model_cap(self):
        row = _claude_row(used5h=10, used7d=10)
        row["windows"]["scoped:Opus"] = {"used_percent": 95.0,
                                         "resets_at": self.now + 8 * 86400,
                                         "window_minutes": 10080}
        # opus family held (5% left on its cap); generic claude unaffected
        self.assertIsNotNone(self.reason(row, fam="opus", reserve=10))
        self.assertIsNone(self.reason(row, fam="claude", reserve=10))


class ReserveConfig(unittest.TestCase):
    def cfg(self, value):
        return {"schema_version": 1, "accounts": [
            {"name": "a", "provider": "claude", "home": "~/.claude"}],
            "routing": {"reserve_percent": value}}

    def test_reads_and_clamps(self):
        self.assertEqual(registry.reserve_percent(self.cfg(10)), 10.0)
        self.assertEqual(registry.reserve_percent(self.cfg(150)), 0.0)
        self.assertEqual(registry.reserve_percent(self.cfg("junk")), 0.0)

    def test_absent_defaults_zero(self):
        cfg = {"schema_version": 1, "accounts": [
            {"name": "a", "provider": "claude", "home": "~/.claude"}]}
        self.assertEqual(registry.reserve_percent(cfg), 0.0)


class Redaction(unittest.TestCase):
    def test_redacts_email(self):
        self.assertEqual(collect.redact_email("paul@x.com"), "p***@x.com")

    def test_non_email_fully_masked(self):
        self.assertEqual(collect.redact_email("not-an-email"), "***")

    def test_none_passthrough(self):
        self.assertIsNone(collect.redact_email(None))

    def test_fingerprint_rejects_falsy(self):
        with self.assertRaises(collect.IdentityBindingError):
            collect.fingerprint(None)


class ClaudeIdentity(unittest.TestCase):
    def _make_runner(self, payload):
        import subprocess
        class FakeResult:
            returncode = 0
            stdout = __import__("json").dumps(payload)
        def runner(cmd, **_kwargs):
            return FakeResult()
        return runner

    def test_null_org_id_returns_none_fingerprint(self):
        """Personal Max accounts return orgId=null from claude auth status.
        This must not raise — account_fingerprint should be None so the
        trust-on-first-use usage-org binding can proceed."""
        runner = self._make_runner({
            "loggedIn": True,
            "email": "user@example.com",
            "orgId": None,
            "subscriptionType": "max",
        })
        result = collect.claude_identity("/nonexistent", runner=runner)
        self.assertIsNone(result["account_fingerprint"])
        self.assertEqual(result["method"], "claude_auth_status")
        self.assertTrue(result["verified"])

    def test_valid_org_id_fingerprinted(self):
        """Accounts with orgId still get a proper fingerprint."""
        runner = self._make_runner({
            "loggedIn": True,
            "email": "user@example.com",
            "orgId": "org-abc123",
            "subscriptionType": "max",
        })
        result = collect.claude_identity("/nonexistent", runner=runner)
        self.assertIsNotNone(result["account_fingerprint"])
        self.assertEqual(result["method"], "claude_auth_status")


class ClaudeLimits(unittest.TestCase):
    """The direct usage probe: cached-token expiry and auth rejection must
    hold with distinct, actionable codes — never a raw HTTPError that would
    surface as a permanent, opaque 'collector error'."""

    def _oauth(self, **extra):
        return dict({"accessToken": "tok-abc"}, **extra)

    def _with_oauth(self, oauth):
        return mock.patch.object(collect, "claude_oauth",
                                 return_value=oauth)

    @staticmethod
    def _http_error(code):
        import urllib.error
        return urllib.error.HTTPError("https://api.anthropic.com/api/oauth/"
                                      "usage", code, "denied", {}, None)

    def test_expired_cached_token_holds_without_network(self):
        opener = mock.Mock(side_effect=AssertionError("probe must not run"))
        expired_ms = (time.time() - 60) * 1000
        with self._with_oauth(self._oauth(expiresAt=expired_ms)):
            with self.assertRaises(collect.IdentityBindingError) as caught:
                collect.claude_limits("/h", None, opener=opener)
        self.assertEqual(caught.exception.code, "claude_usage_token_expired")
        opener.assert_not_called()

    def test_expired_token_in_plain_seconds_also_holds(self):
        opener = mock.Mock(side_effect=AssertionError("probe must not run"))
        with self._with_oauth(self._oauth(expiresAt=time.time() - 60)):
            with self.assertRaises(collect.IdentityBindingError) as caught:
                collect.claude_limits("/h", None, opener=opener)
        self.assertEqual(caught.exception.code, "claude_usage_token_expired")

    def test_future_or_absent_expiry_probes_normally(self):
        for oauth in (self._oauth(),  # no expiresAt recorded
                      self._oauth(expiresAt=(time.time() + 3600) * 1000),
                      self._oauth(expiresAt="soon")):  # mistyped: not proof
            opener = mock.Mock(side_effect=self._http_error(500))
            with self._with_oauth(oauth):
                # the probe RAN (reached the opener) — a 500 propagates raw
                with self.assertRaises(Exception) as caught:
                    collect.claude_limits("/h", None, opener=opener)
            self.assertNotIsInstance(caught.exception,
                                     collect.IdentityBindingError)
            opener.assert_called_once()

    def test_http_401_and_403_hold_as_token_rejected(self):
        for code in (401, 403):
            opener = mock.Mock(side_effect=self._http_error(code))
            with self._with_oauth(self._oauth()):
                with self.assertRaises(collect.IdentityBindingError) as caught:
                    collect.claude_limits("/h", None, opener=opener)
            self.assertEqual(caught.exception.code,
                             "claude_usage_token_rejected")

    def test_http_429_still_maps_to_provider_throttle(self):
        opener = mock.Mock(side_effect=self._http_error(429))
        with self._with_oauth(self._oauth()):
            with self.assertRaises(collect.ProviderThrottleError):
                collect.claude_limits("/h", None, opener=opener)


class PublicSnapshot(unittest.TestCase):
    def test_error_never_leaks_to_public_note(self):
        snap = {"schema_version": 1, "run_id": "t", "generated": 1,
                "generated_iso": "x", "integrity_warnings": [],
                "accounts": [{
                    "name": "a", "provider": "claude", "ok": False,
                    "error": "FileNotFoundError: /home/secret/.creds",
                    "note": "FileNotFoundError: /home/secret/.creds"}]}
        pub = collect.public_snapshot(snap, redact_emails=True)
        note = pub["accounts"][0].get("note", "")
        self.assertNotIn("secret", note)
        self.assertNotIn("error", pub["accounts"][0])

    def test_redacts_emails_when_asked(self):
        snap = {"schema_version": 1, "run_id": "t", "generated": 1,
                "generated_iso": "x", "integrity_warnings": [],
                "accounts": [{"name": "a", "provider": "claude",
                              "email": "paul@x.com", "ok": True}]}
        pub = collect.public_snapshot(snap, redact_emails=True)
        self.assertEqual(pub["accounts"][0]["email"], "p***@x.com")


class CodexWindowMapping(unittest.TestCase):
    """The app-server reports windows by real duration and omits any that is
    not a current constraint, so 5h/7d must be bucketed by windowDurationMins,
    never by primary/secondary position."""

    def test_standard_primary_secondary(self):
        rl = {"primary": {"usedPercent": 12, "windowDurationMins": 300},
              "secondary": {"usedPercent": 88, "windowDurationMins": 10080}}
        w = collect.codex_windows(rl, now=1000)
        self.assertEqual(w["5h"]["used_percent"], 12.0)
        self.assertEqual(w["7d"]["used_percent"], 88.0)

    def test_weekly_in_primary_slot_with_null_secondary(self):
        # freshly reset 5h omitted; weekly lands in the primary slot
        rl = {"primary": {"usedPercent": 16, "windowDurationMins": 10080},
              "secondary": None}
        w = collect.codex_windows(rl, now=1000)
        self.assertEqual(w["7d"]["used_percent"], 16.0)
        self.assertEqual(w["5h"]["used_percent"], 0.0)  # absent -> available
        self.assertEqual(w["5h"]["window_minutes"], 300)

    def test_only_5h_present(self):
        rl = {"primary": {"usedPercent": 40, "windowDurationMins": 300}}
        w = collect.codex_windows(rl, now=1000)
        self.assertEqual(w["5h"]["used_percent"], 40.0)
        self.assertEqual(w["7d"]["used_percent"], 0.0)

    def test_empty_payload_holds(self):
        # an empty rate-limit response proves NOTHING — it must hold the
        # seat, never synthesize a routable 0%/0%
        with self.assertRaises(collect.IdentityBindingError) as caught:
            collect.codex_windows({}, now=1000)
        self.assertEqual(caught.exception.code, "codex_capacity_unrecognized")

    def test_unrecognized_durations_only_holds(self):
        rl = {"primary": {"usedPercent": 10, "windowDurationMins": 60}}
        with self.assertRaises(collect.IdentityBindingError):
            collect.codex_windows(rl, now=1000)


class FakeCompleted:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


class ClaudeKeychain(unittest.TestCase):
    """macOS stores the Claude token in the login Keychain, not a file, and
    CLAUDE_CONFIG_DIR does not relocate it — headroom must read it via
    `security`. All tests force the darwin path so they run on any host."""

    def setUp(self):
        self._platform = collect.sys.platform
        self._which = collect.shutil.which
        collect.sys.platform = "darwin"
        # the Linux test host has no `security` binary; pretend it resolves so
        # the runner (which we inject) is what actually gets exercised
        collect.shutil.which = lambda name: "/usr/bin/security"

    def tearDown(self):
        collect.sys.platform = self._platform
        collect.shutil.which = self._which

    def _runner(self, payload, returncode=0):
        def run(cmd, **kwargs):
            self.assertIn("find-generic-password", cmd)
            return FakeCompleted(stdout=payload, returncode=returncode)
        return run

    def test_reads_wrapped_credential(self):
        blob = json.dumps({"claudeAiOauth": {"accessToken": "tok-abc",
                                             "subscriptionType": "max"}})
        oauth = collect.claude_keychain_oauth(runner=self._runner(blob))
        self.assertEqual(oauth["accessToken"], "tok-abc")

    def test_tolerates_bare_credential(self):
        blob = json.dumps({"accessToken": "tok-bare"})
        oauth = collect.claude_keychain_oauth(runner=self._runner(blob))
        self.assertEqual(oauth["accessToken"], "tok-bare")

    def test_absent_item_returns_none(self):
        oauth = collect.claude_keychain_oauth(
            runner=self._runner("", returncode=44))
        self.assertIsNone(oauth)

    def test_garbage_returns_none(self):
        oauth = collect.claude_keychain_oauth(runner=self._runner("not-json"))
        self.assertIsNone(oauth)

    def test_non_darwin_never_shells_out(self):
        collect.sys.platform = "linux"

        def explode(*a, **k):
            raise AssertionError("security must not run off-macOS")
        self.assertIsNone(collect.claude_keychain_oauth(runner=explode))

    def test_oauth_prefers_file_over_keychain(self):
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, ".credentials.json"), "w") as fh:
                json.dump({"claudeAiOauth": {"accessToken": "from-file"}}, fh)

            def explode(*a, **k):
                raise AssertionError("keychain must not run when file present")
            oauth = collect.claude_oauth(home, runner=explode)
            self.assertEqual(oauth["accessToken"], "from-file")

    def test_oauth_falls_back_to_keychain_when_no_file(self):
        with tempfile.TemporaryDirectory() as home:
            blob = json.dumps({"claudeAiOauth": {"accessToken": "from-keychain"}})
            oauth = collect.claude_oauth(home, runner=self._runner(blob))
            self.assertEqual(oauth["accessToken"], "from-keychain")


class DarwinKeychainGuard(unittest.TestCase):
    """macOS Keychain capability gate: current CLI builds namespace their
    Keychain item per config dir (multi-account safe); legacy builds share one
    item where a second login clobbers the first. The guard allows a login
    only when every Keychain-backed slot has its own namespaced item."""

    def setUp(self):
        self._platform = connect.sys.platform
        self._col_platform = collect.sys.platform
        self._which = collect.shutil.which
        connect.sys.platform = "darwin"
        collect.sys.platform = "darwin"
        collect.shutil.which = lambda name: "/usr/bin/security"

    def tearDown(self):
        connect.sys.platform = self._platform
        collect.sys.platform = self._col_platform
        collect.shutil.which = self._which

    def cfg(self, homes):
        return {"schema_version": 1, "accounts": [
            {"name": f"c{i}", "provider": "claude", "home": h}
            for i, h in enumerate(homes)]}

    @staticmethod
    def probe(found):
        def run(cmd, **kwargs):
            return FakeCompleted(returncode=0 if found else 44)
        return run

    def test_refuses_when_slot_is_on_legacy_shared_item(self):
        with tempfile.TemporaryDirectory() as home:  # no .credentials.json
            self.assertFalse(connect.darwin_keychain_guard(
                self.cfg([home]), "claude", quiet=True,
                runner=self.probe(found=False)))

    def test_allows_when_slot_has_namespaced_item(self):
        with tempfile.TemporaryDirectory() as home:
            self.assertTrue(connect.darwin_keychain_guard(
                self.cfg([home]), "claude", quiet=True,
                runner=self.probe(found=True)))

    def test_allows_when_existing_slot_has_file_credentials(self):
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, ".credentials.json"), "w") as fh:
                fh.write("{}")
            self.assertTrue(connect.darwin_keychain_guard(
                self.cfg([home]), "claude", quiet=True,
                runner=self.probe(found=False)))

    def test_allows_first_claude_account(self):
        self.assertTrue(connect.darwin_keychain_guard(
            self.cfg([]), "claude", quiet=True,
            runner=self.probe(found=False)))

    def test_never_blocks_codex(self):
        with tempfile.TemporaryDirectory() as home:
            self.assertTrue(connect.darwin_keychain_guard(
                self.cfg([home]), "codex", quiet=True,
                runner=self.probe(found=False)))

    def test_never_blocks_off_macos(self):
        connect.sys.platform = "linux"
        with tempfile.TemporaryDirectory() as home:
            self.assertTrue(connect.darwin_keychain_guard(
                self.cfg([home]), "claude", quiet=True,
                runner=self.probe(found=False)))


class KeychainNamespacing(unittest.TestCase):
    """Service-name derivation must match the CLI: base name for no home,
    base + '-' + sha256(NFC(home))[:8] per config dir."""

    def test_legacy_service_without_home(self):
        self.assertEqual(collect.claude_keychain_service(),
                         "Claude Code-credentials")

    def test_namespaced_service_is_stable_and_distinct(self):
        a = collect.claude_keychain_service("/Users/x/.headroom/homes/a")
        b = collect.claude_keychain_service("/Users/x/.headroom/homes/b")
        self.assertTrue(a.startswith("Claude Code-credentials-"))
        self.assertEqual(len(a), len("Claude Code-credentials-") + 8)
        self.assertNotEqual(a, b)
        self.assertEqual(a, collect.claude_keychain_service(
            "/Users/x/.headroom/homes/a"))

    def test_matches_sha256_derivation(self):
        import hashlib as h
        import unicodedata
        home = "/Users/x/.headroom/homes/a"
        expected = "Claude Code-credentials-" + h.sha256(
            unicodedata.normalize("NFC", home).encode()).hexdigest()[:8]
        self.assertEqual(collect.claude_keychain_service(home), expected)

    def test_oauth_probes_namespaced_before_legacy(self):
        platform, which = collect.sys.platform, collect.shutil.which
        collect.sys.platform = "darwin"
        collect.shutil.which = lambda name: "/usr/bin/security"
        try:
            home = "/Users/x/.headroom/homes/a"
            namespaced = collect.claude_keychain_service(home)
            calls = []

            def run(cmd, **kwargs):
                service = cmd[cmd.index("-s") + 1]
                calls.append(service)
                if service == namespaced:
                    return FakeCompleted(
                        stdout=json.dumps(
                            {"claudeAiOauth": {"accessToken": "ns-tok"}}),
                        returncode=0)
                return FakeCompleted(returncode=44)
            oauth = collect.claude_keychain_oauth(runner=run, home=home)
            self.assertEqual(oauth["accessToken"], "ns-tok")
            self.assertEqual(calls[0], namespaced)
        finally:
            collect.sys.platform, collect.shutil.which = platform, which


class StatuslineJournal(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_headroom = os.environ.get("HEADROOM_DIR")
        os.environ["HEADROOM_DIR"] = self.temp.name
        self.payload = {
            "session_id": "11111111-1111-4111-8111-111111111111",
            "transcript_path": "/tmp/session.jsonl", "cwd": "/tmp/work",
            "model": {"display_name": "Sonnet"}, "version": "1.2.3",
        }

    def tearDown(self):
        if self.old_headroom is None:
            os.environ.pop("HEADROOM_DIR", None)
        else:
            os.environ["HEADROOM_DIR"] = self.old_headroom
        self.temp.cleanup()

    def test_writes_payload_and_throttles_for_60_seconds(self):
        with mock.patch.object(statusline.time, "time",
                               side_effect=[1000, 1030, 1061]):
            self.assertTrue(statusline.journal_session(self.payload))
            self.assertFalse(statusline.journal_session(self.payload))
            self.assertTrue(statusline.journal_session(self.payload))
        journal = os.path.join(self.temp.name, "state", "sessions.jsonl")
        with open(journal) as handle:
            rows = [json.loads(line) for line in handle]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["model"], "Sonnet")
        self.assertEqual(rows[0]["config_dir"],
                         os.environ.get("CLAUDE_CONFIG_DIR") or "")
        self.assertEqual(os.stat(journal).st_mode & 0o777, 0o600)

    def test_malformed_payload_never_raises(self):
        for payload in (None, [], {}, {"session_id": "../bad"},
                        {"session_id": 4, "transcript_path": []}):
            self.assertFalse(statusline.journal_session(payload, now=1000))

    def test_capped_hint_replaces_next_candidate(self):
        snapshot = {"accounts": [{"name": "source", "provider": "claude",
                                   "windows": {"5h": {"used_percent": 99},
                                               "7d": {"used_percent": 20}}}]}
        output = io.StringIO()
        account = {"name": "source", "provider": "claude", "home": "/tmp/source"}
        with mock.patch.object(statusline.sys, "stdin", io.StringIO("{}")), \
                mock.patch.object(statusline.paths, "load_json", return_value=snapshot), \
                mock.patch.object(statusline.registry, "accounts", return_value=[account]), \
                mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "/tmp/source"}), \
                redirect_stdout(output):
            self.assertEqual(statusline.main(), 0)
        self.assertIn("capped -> /exit, then: headroom handoff", output.getvalue())


class HandoffSafety(unittest.TestCase):
    SID = "11111111-1111-4111-8111-111111111111"
    OTHER_SID = "22222222-2222-4222-8222-222222222222"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_headroom = os.environ.get("HEADROOM_DIR")
        os.environ["HEADROOM_DIR"] = os.path.join(self.temp.name, "headroom")
        self.old_cwd = os.getcwd()
        self.cwd = os.path.join(self.temp.name, "work")
        os.makedirs(self.cwd)
        os.chdir(self.cwd)
        self.source_home = os.path.join(self.temp.name, "source")
        self.target_home = os.path.join(self.temp.name, "target")
        os.makedirs(self.target_home)
        self.accounts = [
            {"name": "source", "provider": "claude", "home": self.source_home,
             "expected_email": "one@example.com"},
            {"name": "target", "provider": "claude", "home": self.target_home,
             "expected_email": "two@example.com"},
        ]
        self.transcript = self._transcript(self.source_home, self.SID)
        self.bytes = (json.dumps({"type": "user", "message": {
            "content": [{"type": "text", "text": "hello"}]}}) + "\n").encode()
        with open(self.transcript, "wb") as handle:
            handle.write(self.bytes)
        old = time.time() - 20
        os.utime(self.transcript, (old, old))
        self.binding = mock.patch.object(
            collect, "local_binding", return_value=("AAAA", "BBBB"))
        self.binding.start()

    def tearDown(self):
        self.binding.stop()
        os.chdir(self.old_cwd)
        if self.old_headroom is None:
            os.environ.pop("HEADROOM_DIR", None)
        else:
            os.environ["HEADROOM_DIR"] = self.old_headroom
        self.temp.cleanup()

    def _transcript(self, home, session_id):
        slug = handoff._claude_slug(os.path.realpath(self.cwd))
        directory = os.path.join(home, "projects", slug)
        os.makedirs(directory, exist_ok=True)
        return os.path.join(directory, session_id + ".jsonl")

    def _journal(self, rows):
        state = os.path.join(os.environ["HEADROOM_DIR"], "state")
        os.makedirs(state, exist_ok=True)
        with open(os.path.join(state, "sessions.jsonl"), "w") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")

    def _journal_row(self, session_id, path, ts=100, model="Sonnet"):
        return {"ts": ts, "session_id": session_id,
                "transcript_path": path, "cwd": self.cwd, "model": model,
                "version": "1", "config_dir": self.source_home}

    def test_explicit_session_wins_over_ambiguous_journal(self):
        other = self._transcript(self.source_home, self.OTHER_SID)
        with open(other, "w") as handle:
            handle.write("{}\n")
        self._journal([self._journal_row(self.OTHER_SID, other),
                       self._journal_row("33333333-3333-4333-8333-333333333333",
                                         "/missing", ts=200)])
        source = handoff.resolve_source(self.SID, self.accounts, self.cwd)
        self.assertEqual(source.session_id, self.SID)
        self.assertEqual(source.transcript_path, self.transcript)

    def test_journal_current_cwd_resolves_source(self):
        self._journal([self._journal_row(self.SID, self.transcript)])
        source = handoff.resolve_source(accounts=self.accounts, cwd=self.cwd)
        self.assertEqual(source.account["name"], "source")

    def test_journal_ambiguity_requires_session(self):
        self._journal([self._journal_row(self.SID, self.transcript),
                       self._journal_row(self.OTHER_SID, "/tmp/other", ts=200)])
        with self.assertRaisesRegex(handoff.HandoffError, "multiple sessions"):
            handoff.resolve_source(accounts=self.accounts, cwd=self.cwd, now=300)

    def test_single_recent_cwd_scan_is_offered(self):
        errors = io.StringIO()
        with redirect_stderr(errors):
            source = handoff.resolve_source(accounts=self.accounts, cwd=self.cwd)
        self.assertEqual(source.session_id, self.SID)
        self.assertIn("found session", errors.getvalue())

    def test_claude_slug_replaces_every_non_slug_character(self):
        self.assertEqual(handoff._claude_slug("/tmp/x/slug_test.dir/a_b.c"),
                         "-tmp-x-slug-test-dir-a-b-c")

    def test_scan_uses_claude_slug_for_special_characters(self):
        cwd = os.path.join(self.temp.name, "slug_test.dir", "a_b.c")
        os.makedirs(cwd)
        directory = os.path.join(self.source_home, "projects",
                                 handoff._claude_slug(os.path.realpath(cwd)))
        os.makedirs(directory)
        transcript = os.path.join(directory, self.OTHER_SID + ".jsonl")
        with open(transcript, "wb") as handle:
            handle.write(self.bytes)
        old = time.time() - 20
        os.utime(transcript, (old, old))
        source = handoff.resolve_source(accounts=self.accounts, cwd=cwd)
        self.assertEqual(source.transcript_path, transcript)

    def test_fresh_mtime_refuses_still_running_source(self):
        os.utime(self.transcript, None)
        with self.assertRaisesRegex(handoff.HandoffError, "/exit"):
            handoff.guard_source_stable(self.transcript, now=time.time(), sleep=lambda n: None)

    def test_truncated_final_line_refused(self):
        with open(self.transcript, "ab") as handle:
            handle.write(b'{"type":')
        with self.assertRaisesRegex(handoff.HandoffError,
                                   "incomplete final line"):
            handoff.inspect_transcript(self.transcript)

    def test_unresolved_tool_use_refused(self):
        event = {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "x", "name": "Read"}]}}
        with open(self.transcript, "w") as handle:
            handle.write(json.dumps(event) + "\n")
        with self.assertRaisesRegex(handoff.HandoffError, "mid-tool-call"):
            handoff.inspect_transcript(self.transcript)

    def test_destination_collision_refused(self):
        destination = self._transcript(self.target_home, self.SID)
        with open(destination, "w") as handle:
            handle.write("existing")
        digest = hashlib.sha256(self.bytes).hexdigest()
        with self.assertRaisesRegex(handoff.HandoffError, "does not overwrite"):
            handoff.stage_transcript(self.transcript, destination, digest)

    def test_command_delegates_collision_check_to_atomic_staging(self):
        self._journal([self._journal_row(self.SID, self.transcript)])
        destination = handoff.destination_path(self.target_home, self.transcript,
                                               self.SID)
        os.makedirs(os.path.dirname(destination))
        with open(destination, "w") as handle:
            handle.write("existing")
        errors = io.StringIO()
        collision = handoff.HandoffError("atomic collision sentinel")
        with mock.patch.object(handoff.registry, "accounts",
                               return_value=self.accounts), \
                mock.patch.object(handoff.route, "ensure_fresh_snapshot",
                                  return_value={"accounts": []}), \
                mock.patch.object(handoff.route, "candidates",
                                  return_value=[(self.accounts[1], None)]), \
                mock.patch.object(handoff, "guard_source_stable"), \
                mock.patch.object(handoff, "stage_transcript",
                                  side_effect=collision) as stage, \
                redirect_stderr(errors):
            result = handoff.cmd_handoff(
                ["--session", self.SID, "--model", "sonnet", "--print"])
        self.assertEqual(result, 2)
        stage.assert_not_called()
        self.assertIn("does not overwrite", errors.getvalue())

    def test_symlink_source_refused(self):
        link = os.path.join(self.temp.name, "link.jsonl")
        os.symlink(self.transcript, link)
        with self.assertRaisesRegex(handoff.HandoffError, "symlink"):
            handoff.inspect_transcript(link)

    def test_double_handoff_refused_and_force_overrides(self):
        digest = hashlib.sha256(self.bytes).hexdigest()
        handoff.append_ledger({"session_id": self.SID,
                               "transcript_sha256": digest,
                               "target_slot": "target", "ts": 100})
        with self.assertRaisesRegex(handoff.HandoffError, "different --to"):
            handoff.guard_not_duplicate(self.SID, digest)
        handoff.guard_not_duplicate(self.SID, digest, force=True)

    def test_handoff_ledger_disambiguates_source_after_copy(self):
        target = self._transcript(self.target_home, self.SID)
        with open(target, "wb") as handle:
            handle.write(self.bytes)
        digest = hashlib.sha256(self.bytes).hexdigest()
        handoff.append_ledger({"session_id": self.SID, "ts": 100,
                               "target_slot": "target", "source_slot": "source",
                               "transcript_sha256": digest})

        source = handoff.resolve_source(self.SID, self.accounts, self.cwd)

        self.assertEqual(source.transcript_path, self.transcript)
        self.assertEqual(source.account["name"], "source")
        with self.assertRaisesRegex(handoff.HandoffError, "already handed off"):
            handoff.guard_not_duplicate(self.SID, digest)

    def test_copy_hash_permissions_and_source_untouched(self):
        destination = handoff.destination_path(self.target_home, self.transcript,
                                               self.SID)
        digest = hashlib.sha256(self.bytes).hexdigest()
        handoff.stage_transcript(self.transcript, destination, digest)
        with open(self.transcript, "rb") as handle:
            self.assertEqual(handle.read(), self.bytes)
        with open(destination, "rb") as handle:
            copied = handle.read()
        self.assertEqual(hashlib.sha256(copied).hexdigest(), digest)
        self.assertEqual(os.stat(destination).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(destination)).st_mode & 0o777,
                         0o700)

    def test_destination_reuses_source_project_directory_basename(self):
        directory = os.path.join(self.source_home, "projects", "weird.slug_dir")
        source = os.path.join(directory, self.SID + ".jsonl")
        os.makedirs(directory)
        with open(source, "wb") as handle:
            handle.write(self.bytes)
        destination = handoff.destination_path(self.target_home, source, self.SID)
        self.assertEqual(destination, os.path.join(
            self.target_home, "projects", "weird.slug_dir", self.SID + ".jsonl"))

    def test_target_selection_uses_router_and_excludes_source(self):
        blocked = [(self.accounts[1], "5h at 100%"), (self.accounts[0], None)]
        with mock.patch.object(handoff.route, "candidates", return_value=blocked) as call:
            with self.assertRaisesRegex(handoff.HandoffError, "proven headroom"):
                handoff.select_target("source", {}, requested="target")
            call.assert_called_with("claude", {})
        ranked = [(self.accounts[0], None), (self.accounts[1], None)]
        with mock.patch.object(handoff.route, "candidates", return_value=ranked):
            target = handoff.select_target("source", {})
        self.assertEqual(target["name"], "target")

    def test_print_handoff_writes_baton_ledger_and_cools_source(self):
        now = time.time()
        source_row = _claude_row("source", used5h=100.0)
        source_row["email"] = "one@example.com"
        target_row = _claude_row("target", used5h=10.0)
        target_row["email"] = "two@other.test"
        snapshot = {"generated": now, "accounts": [source_row, target_row]}
        output = io.StringIO()
        errors = io.StringIO()
        with mock.patch.object(handoff.registry, "accounts", return_value=self.accounts), \
                mock.patch.object(handoff.route, "ensure_fresh_snapshot",
                                  return_value=snapshot), \
                mock.patch.object(handoff.route, "candidates",
                                  return_value=[(self.accounts[0], "5h at 100%"),
                                                (self.accounts[1], None)]), \
                mock.patch.object(handoff, "guard_source_stable"), \
                mock.patch.object(handoff.route, "mark") as mark, \
                redirect_stdout(output), redirect_stderr(errors):
            result = handoff.cmd_handoff(
                ["--session", self.SID, "--model", "sonnet", "--print"])
        self.assertEqual(result, 0, errors.getvalue())
        ledger = os.path.join(os.environ["HEADROOM_DIR"], "state", "handoffs.jsonl")
        with open(ledger) as handle:
            record = json.loads(handle.readline())
        required = {"schema", "ts", "session_id", "source_slot",
                    "source_email_redacted", "target_slot", "cwd",
                    "transcript_sha256", "transcript_bytes", "source_5h_used",
                    "reason", "resume_command"}
        self.assertTrue(required.issubset(record))
        expected = (f"CLAUDE_CONFIG_DIR={self.target_home} claude --resume "
                    f"{self.SID} --fork-session")
        self.assertEqual(record["resume_command"], expected)
        self.assertIn("NEXT COMMAND:\n" + expected, output.getvalue())
        self.assertIn("background tasks / MCP connections / permission approvals",
                      output.getvalue())
        self.assertIn("data boundary", output.getvalue())
        self.assertEqual(os.stat(ledger).st_mode & 0o777, 0o600)
        mark.assert_called_once_with("source", "sonnet", mock.ANY,
                                     account_wide=True, window="5h")

    def test_decline_happens_before_any_mutation(self):
        output = io.StringIO()
        stdin = mock.Mock()
        stdin.isatty.return_value = True
        with mock.patch.object(handoff.sys, "stdin", stdin), \
                mock.patch("builtins.input", return_value="n"), \
                mock.patch.object(handoff.registry, "accounts",
                                  return_value=self.accounts), \
                mock.patch.object(handoff.route, "ensure_fresh_snapshot",
                                  return_value={"generated": time.time(),
                                                "accounts": [
                                                    _claude_row("source"),
                                                    _claude_row("target")]}), \
                mock.patch.object(handoff.route, "candidates",
                                  return_value=[(self.accounts[1], None)]), \
                mock.patch.object(handoff, "guard_source_stable"), \
                mock.patch.object(handoff.route, "mark"), \
                redirect_stdout(output):
            result = handoff.cmd_handoff(
                ["--session", self.SID, "--model", "sonnet"])
        self.assertEqual(result, 0)
        self.assertIn("nothing copied or cooled", output.getvalue())
        destination = handoff.destination_path(
            self.target_home, self.transcript, self.SID)
        self.assertFalse(os.path.exists(destination))
        self.assertFalse(os.path.exists(handoff._ledger_path()))

    def test_target_relogin_during_confirmation_is_rejected(self):
        initial = {"generated": time.time(), "accounts": [
            _claude_row("source"), _claude_row("target")]}
        changed_target = _claude_row("target")
        changed_target["identity"] = {
            "account_fingerprint": "OTHER", "credential_digest": "CHANGED"}
        refreshed = {"generated": time.time(), "accounts": [
            _claude_row("source"), changed_target]}
        stdin = mock.Mock()
        stdin.isatty.return_value = True
        errors = io.StringIO()
        with mock.patch.object(handoff.sys, "stdin", stdin), \
                mock.patch("builtins.input", return_value="y"), \
                mock.patch.object(handoff.registry, "accounts",
                                  return_value=self.accounts), \
                mock.patch.object(handoff.route, "ensure_fresh_snapshot",
                                  side_effect=[initial, refreshed]) as recollect, \
                mock.patch.object(handoff.route, "candidates",
                                  return_value=[(self.accounts[0], None),
                                                (self.accounts[1], None)]), \
                mock.patch.object(handoff, "guard_source_stable"), \
                redirect_stderr(errors):
            result = handoff.cmd_handoff(
                ["--session", self.SID, "--model", "sonnet"])
        self.assertEqual(result, 2)
        self.assertEqual(recollect.call_count, 2)
        self.assertIn("changed during confirmation", errors.getvalue())
        self.assertFalse(os.path.exists(handoff.destination_path(
            self.target_home, self.transcript, self.SID)))

    def test_manual_exec_rechecks_pinned_identity_after_commit(self):
        snapshot = {"generated": time.time(), "accounts": [
            _claude_row("source", used5h=100.0), _claude_row("target")]}
        errors = io.StringIO()
        with mock.patch.object(handoff.registry, "accounts",
                               return_value=self.accounts), \
                mock.patch.object(handoff.route, "ensure_fresh_snapshot",
                                  return_value=snapshot), \
                mock.patch.object(handoff.route, "candidates",
                                  return_value=[(self.accounts[0], "capped"),
                                                (self.accounts[1], None)]), \
                mock.patch.object(handoff, "guard_source_stable"), \
                mock.patch.object(handoff.route, "mark"), \
                mock.patch.object(
                    collect, "local_binding",
                    side_effect=[("AAAA", "BBBB"),
                                 ("AAAA", "BBBB"),
                                 ("OTHER", "CHANGED")]) as binding, \
                mock.patch.object(handoff.os, "execvpe") as execute, \
                redirect_stderr(errors):
            result = handoff.cmd_handoff([
                "--session", self.SID, "--model", "sonnet", "--yes"])
        self.assertEqual(result, 2)
        self.assertEqual(binding.call_count, 3)
        execute.assert_not_called()
        self.assertIn("identity or credential changed", errors.getvalue())
        self.assertTrue(os.path.exists(handoff.destination_path(
            self.target_home, self.transcript, self.SID)))
class ClaudePlan(unittest.TestCase):
    """rateLimitTier is unreliable on team seats — one seat of an org can
    carry a per-user tier (default_claude_max_5x) while another carries the
    org's shared-pool tier (default_raven), and the field is cached at login
    and never refreshed. subscriptionType must win for team."""

    def _home_with(self, home, **oauth):
        with open(os.path.join(home, ".credentials.json"), "w") as fh:
            json.dump({"claudeAiOauth": dict({"accessToken": "tok"}, **oauth)}, fh)

    def test_team_wins_over_per_user_tier(self):
        with tempfile.TemporaryDirectory() as home:
            self._home_with(home, subscriptionType="team",
                            rateLimitTier="default_claude_max_5x")
            self.assertEqual(collect.claude_plan(home), "Team")

    def test_team_with_org_pool_tier(self):
        with tempfile.TemporaryDirectory() as home:
            self._home_with(home, subscriptionType="team",
                            rateLimitTier="default_raven")
            self.assertEqual(collect.claude_plan(home), "Team")

    def test_non_team_keeps_tier_first(self):
        with tempfile.TemporaryDirectory() as home:
            self._home_with(home, subscriptionType="max",
                            rateLimitTier="default_claude_max_20x")
            self.assertEqual(collect.claude_plan(home), "Max 20x")


def _codex_row(name="cx", used5h=10.0, used7d=20.0, **over):
    now = int(time.time())
    row = {
        "name": name, "provider": "codex", "plan": "ChatGPT Pro", "ok": True,
        "stale": False, "routable": True, "identity_verified": True,
        "identity": {"verified": True, "account_fingerprint": "AAAA",
                     "credential_digest": "BBBB", "lineage_digest": "LLLL",
                     "auth_mode": "chatgpt"},
        "trust_state": "verified", "captured_at": now - 10,
        "source": "codex_app_server",
        "windows": {
            "5h": {"used_percent": used5h, "resets_at": now + 3600,
                   "window_minutes": 300},
            "7d": {"used_percent": used7d, "resets_at": now + 8 * 86400,
                   "window_minutes": 10080},
        },
    }
    row.update(over)
    return row


def _codex_account(name="cx", **over):
    account = {"name": name, "provider": "codex", "home": "/tmp/hr-t/" + name}
    account.update(over)
    return account


class CodexBlockReasonFailClosed(unittest.TestCase):
    """Codex eligibility is stricter than Claude's and fully provider-gated:
    live app-server source, network-verified identity, ChatGPT subscription
    auth, matching refresh-token lineage, and no quarantine."""

    def setUp(self):
        self.now = time.time()
        self.temp = tempfile.TemporaryDirectory()
        self.old_headroom = os.environ.get("HEADROOM_DIR")
        os.environ["HEADROOM_DIR"] = self.temp.name
        self.binding = mock.patch.object(
            collect, "local_binding", return_value=("AAAA", "BBBB"))
        self.binding.start()
        self.lineage = mock.patch.object(
            collect, "codex_lineage_digest", return_value="LLLL")
        self.lineage.start()

    def tearDown(self):
        self.lineage.stop()
        self.binding.stop()
        if self.old_headroom is None:
            os.environ.pop("HEADROOM_DIR", None)
        else:
            os.environ["HEADROOM_DIR"] = self.old_headroom
        self.temp.cleanup()

    def reason(self, row, account=None, fam="codex"):
        account = _codex_account() if account is None else account
        return route.block_reason(account, fam, row, {}, self.now)

    def test_healthy_codex_routes(self):
        self.assertIsNone(self.reason(_codex_row()))

    def test_verified_local_not_routable_for_codex(self):
        row = _codex_row(trust_state="verified_local")
        row["identity"]["verified"] = False
        reason = self.reason(row)
        self.assertIsNotNone(reason)
        self.assertIn("network-verified", reason)

    def test_non_app_server_source_holds(self):
        row = _codex_row(source="codex_session_telemetry")
        reason = self.reason(row)
        self.assertIsNotNone(reason)
        self.assertIn("app-server", reason)

    def test_apikey_auth_mode_holds(self):
        row = _codex_row()
        row["identity"]["auth_mode"] = "apikey"
        reason = self.reason(row)
        self.assertIsNotNone(reason)
        self.assertIn("ChatGPT-subscription", reason)

    def test_missing_lineage_holds(self):
        row = _codex_row()
        row["identity"].pop("lineage_digest")
        self.assertIsNotNone(self.reason(row))

    def test_lineage_mismatch_holds(self):
        with mock.patch.object(collect, "codex_lineage_digest",
                               return_value="FRESH-LOGIN"):
            reason = self.reason(_codex_row())
        self.assertIsNotNone(reason)
        self.assertIn("lineage changed", reason)

    def test_unreadable_lineage_holds(self):
        with mock.patch.object(collect, "codex_lineage_digest",
                               return_value=None):
            self.assertIsNotNone(self.reason(_codex_row()))

    def test_shared_desktop_stable_lineage_routes(self):
        account = _codex_account(shared_desktop=True)
        self.assertIsNone(self.reason(_codex_row(), account=account))

    def test_shared_desktop_lineage_change_holds_with_mac_warning(self):
        account = _codex_account(shared_desktop=True)
        with mock.patch.object(collect, "codex_lineage_digest",
                               return_value="MAC-RELOGIN"):
            reason = self.reason(_codex_row(), account=account)
        self.assertIsNotNone(reason)
        self.assertIn("shared_desktop_identity", reason)
        self.assertIn("Mac re-login", reason)

    def test_quarantined_seat_holds(self):
        route.quarantine_mark("cx", "codex auth rejected")
        reason = self.reason(_codex_row())
        self.assertIsNotNone(reason)
        self.assertIn("quarantined", reason)

    def test_corrupt_quarantine_ledger_holds(self):
        os.makedirs(os.path.join(self.temp.name, "state"), exist_ok=True)
        with open(os.path.join(self.temp.name, "state",
                               "quarantine.json"), "w") as handle:
            handle.write("not-json{")
        reason = self.reason(_codex_row())
        self.assertIsNotNone(reason)
        self.assertIn("quarantine ledger unreadable", reason)

    def test_routing_disabled_refuses_with_clear_reason(self):
        with mock.patch.object(route, "CODEX_ROUTING_ENABLED", False):
            reason = self.reason(_codex_row())
        self.assertIsNotNone(reason)
        self.assertIn("HEADROOM_CODEX_ROUTING", reason)

    def test_codex_gate_never_touches_claude(self):
        # a Claude row with none of the codex-only fields still routes, even
        # when a quarantine entry exists under the same account name
        route.quarantine_mark("a", "codex auth rejected")
        reason = route.block_reason(_account(), "sonnet", _claude_row(),
                                    {}, self.now)
        self.assertIsNone(reason)


class GreatestHeadroom(unittest.TestCase):
    """Candidate order prefers the greatest PROVEN headroom —
    min(100-used_5h, 100-used_7d) — with registry order as the tie-break."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_headroom = os.environ.get("HEADROOM_DIR")
        os.environ["HEADROOM_DIR"] = self.temp.name
        self.binding = mock.patch.object(
            collect, "local_binding", return_value=("AAAA", "BBBB"))
        self.binding.start()
        self.lineage = mock.patch.object(
            collect, "codex_lineage_digest", return_value="LLLL")
        self.lineage.start()

    def tearDown(self):
        self.lineage.stop()
        self.binding.stop()
        if self.old_headroom is None:
            os.environ.pop("HEADROOM_DIR", None)
        else:
            os.environ["HEADROOM_DIR"] = self.old_headroom
        self.temp.cleanup()

    def ranked(self, fam, accounts, rows):
        snapshot = {"generated": time.time(), "accounts": rows}
        with mock.patch.object(route.registry, "ordered_for",
                               return_value=accounts), \
                mock.patch.object(route.registry, "reserve_percent",
                                  return_value=0.0):
            return route.candidates(fam, snapshot)

    def test_codex_picks_greatest_headroom(self):
        accounts = [_codex_account("cx1"), _codex_account("cx2")]
        rows = [_codex_row("cx1", used5h=60.0, used7d=30.0),
                _codex_row("cx2", used5h=10.0, used7d=20.0)]
        ranked = self.ranked("codex", accounts, rows)
        self.assertEqual([a["name"] for a, r in ranked if r is None],
                         ["cx2", "cx1"])

    def test_score_is_min_of_both_windows(self):
        # cx1: 5h says 90 free but 7d only 5 free -> score 5; cx2 -> score 40
        accounts = [_codex_account("cx1"), _codex_account("cx2")]
        rows = [_codex_row("cx1", used5h=10.0, used7d=95.0),
                _codex_row("cx2", used5h=60.0, used7d=40.0)]
        ranked = self.ranked("codex", accounts, rows)
        self.assertEqual(ranked[0][0]["name"], "cx2")

    def test_tie_breaks_on_registry_order(self):
        accounts = [_codex_account("cx1"), _codex_account("cx2")]
        rows = [_codex_row("cx1", used5h=50.0, used7d=50.0),
                _codex_row("cx2", used5h=50.0, used7d=50.0)]
        ranked = self.ranked("codex", accounts, rows)
        self.assertEqual(ranked[0][0]["name"], "cx1")

    def test_blocked_accounts_follow_eligible_ones(self):
        accounts = [_codex_account("cx1"), _codex_account("cx2")]
        rows = [_codex_row("cx1", used5h=100.0),
                _codex_row("cx2", used5h=10.0)]
        ranked = self.ranked("codex", accounts, rows)
        self.assertEqual(ranked[0][0]["name"], "cx2")
        self.assertIsNone(ranked[0][1])
        self.assertIsNotNone(ranked[1][1])

    def test_claude_keeps_registry_order(self):
        # Greatest-headroom ordering is Codex-only (Paul 2026-07-14); Claude
        # keeps its established registry-order preference even when a later
        # account has more room, so daily Claude routing is unchanged.
        accounts = [_account("a"), _account("b")]
        rows = [_claude_row("a", used5h=80.0, used7d=10.0),
                _claude_row("b", used5h=20.0, used7d=10.0)]
        ranked = self.ranked("sonnet", accounts, rows)
        self.assertEqual([r[0]["name"] for r in ranked], ["a", "b"])


class CodexCollectClassification(unittest.TestCase):
    """collect() must keep codex app-server outcomes distinct and NEVER fall
    back to routable local telemetry after an explicit auth/protocol error."""

    def account(self, home="/tmp/hr-t/none"):
        return {"name": "cx", "provider": "codex", "home": home}

    def collect_one(self, account=None, backoff=None, persist=None):
        return collect.collect([self.account() if account is None
                                else account], backoff, persist)

    def test_auth_reject_never_falls_back_to_local_telemetry(self):
        with mock.patch.object(
                collect, "codex_live",
                side_effect=collect.IdentityBindingError(
                    "codex_auth_rejected")), \
                mock.patch.object(collect, "codex_identity") as identity, \
                mock.patch.object(collect, "codex_limits") as limits:
            snapshot = self.collect_one()
        row = snapshot["accounts"][0]
        identity.assert_not_called()
        limits.assert_not_called()
        self.assertFalse(row["ok"])
        self.assertEqual(row["error_code"], "codex_auth_rejected")
        self.assertEqual(row["trust_state"], "held")
        self.assertFalse(row["routable"])
        self.assertIn("re-login", row["note"])

    def test_protocol_error_never_falls_back(self):
        with mock.patch.object(
                collect, "codex_live",
                side_effect=collect.IdentityBindingError(
                    "codex_app_server_protocol_error")), \
                mock.patch.object(collect, "codex_limits") as limits:
            snapshot = self.collect_one()
        row = snapshot["accounts"][0]
        limits.assert_not_called()
        self.assertFalse(row["ok"])
        self.assertEqual(row["error_code"], "codex_app_server_protocol_error")
        self.assertFalse(row["routable"])

    def test_app_server_unavailable_falls_back_display_only(self):
        identity = {"verified": False, "email": "cx@example.com",
                    "account_fingerprint": "FP",
                    "method": "openai_local_id_token", "plan_type": "pro",
                    "subscription": {"status": "unknown"}}
        telemetry = {"captured_at": int(time.time()) - 5,
                     "source": "codex_session_telemetry", "stale": False,
                     "windows": {"5h": {"used_percent": 1.0},
                                 "7d": {"used_percent": 2.0}},
                     "plan_type": "pro"}
        with mock.patch.object(
                collect, "codex_live",
                side_effect=collect.IdentityBindingError(
                    "codex_app_server_no_response")), \
                mock.patch.object(collect, "codex_identity",
                                  return_value=dict(identity)), \
                mock.patch.object(collect, "codex_limits",
                                  return_value=dict(telemetry)), \
                mock.patch.object(collect, "credential_digest",
                                  return_value="BBBB"), \
                mock.patch.object(collect, "codex_lineage_digest",
                                  return_value="LLLL"):
            snapshot = self.collect_one()
        row = snapshot["accounts"][0]
        self.assertFalse(row["ok"])
        self.assertFalse(row["routable"])
        self.assertEqual(row["trust_state"], "dashboard_only")
        self.assertEqual(row["error_code"], "codex_dashboard_only")
        # telemetry is still there for display
        self.assertEqual(row["windows"]["5h"]["used_percent"], 1.0)

    def test_throttle_persists_provider_backoff_and_holds(self):
        recorded = {}

        def persist(retry_at, provider="anthropic_usage_api"):
            recorded["retry_at"] = retry_at
            recorded["provider"] = provider
        with mock.patch.object(
                collect, "codex_live",
                side_effect=collect.IdentityBindingError(
                    "codex_app_server_throttled")):
            snapshot = self.collect_one(persist=persist)
        row = snapshot["accounts"][0]
        self.assertFalse(row["ok"])
        self.assertEqual(row["error_code"], "codex_app_server_throttled")
        self.assertEqual(recorded["provider"], "codex_app_server")
        self.assertGreater(recorded["retry_at"], time.time() - 5)

    def test_active_codex_backoff_holds_without_spawning(self):
        backoff = {"schema_version": 1, "providers": {"codex_app_server": {
            "retry_at": int(time.time()) + 300}}}
        with mock.patch.object(collect, "codex_live") as live:
            snapshot = self.collect_one(backoff=backoff)
        live.assert_not_called()
        row = snapshot["accounts"][0]
        self.assertFalse(row["ok"])
        self.assertEqual(row["error_code"], "codex_provider_backoff")

    def test_apikey_seat_is_capacity_unavailable(self):
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, "auth.json"), "w") as handle:
                json.dump({"OPENAI_API_KEY": "sk-test-not-a-real-key"}, handle)
            snapshot = self.collect_one(self.account(home))
        row = snapshot["accounts"][0]
        self.assertFalse(row["ok"])
        self.assertEqual(row["error_code"], "codex_capacity_unavailable")
        self.assertFalse(row["routable"])
        self.assertIn("API-key", row["note"])

    def test_auth_mode_detection(self):
        self.assertEqual(collect.codex_auth_mode(
            {"OPENAI_API_KEY": "sk-x"}), "apikey")
        self.assertEqual(collect.codex_auth_mode(
            {"auth_mode": "apikey", "tokens": {"id_token": "x"}}), "apikey")
        self.assertEqual(collect.codex_auth_mode(
            {"tokens": {"id_token": "x"}, "OPENAI_API_KEY": None}), "chatgpt")
        self.assertEqual(collect.codex_auth_mode({}), "unknown")

    def test_lineage_digest_is_nonsecret_and_stable(self):
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, "auth.json"), "w") as handle:
                json.dump({"tokens": {"refresh_token": "rt-secret"}}, handle)
            digest = collect.codex_lineage_digest(home)
            self.assertEqual(digest, collect.codex_lineage_digest(home))
            self.assertEqual(len(digest), 16)
            self.assertNotIn("rt-secret", digest)
            self.assertEqual(
                digest, hashlib.sha256(b"rt-secret").hexdigest()[:16])

    def test_lineage_digest_missing_refresh_is_none(self):
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, "auth.json"), "w") as handle:
                json.dump({"tokens": {}}, handle)
            self.assertIsNone(collect.codex_lineage_digest(home))

    def test_appserver_error_classification(self):
        classify = collect.classify_codex_appserver_error
        self.assertEqual(classify({"code": 401, "message": "unauthorized"}),
                         "codex_auth_rejected")
        self.assertEqual(classify({"message": "token_invalidated"}),
                         "codex_auth_rejected")
        self.assertEqual(classify({"message": "refresh token already used"}),
                         "codex_auth_rejected")
        self.assertEqual(classify({"message": "429 too many requests"}),
                         "codex_app_server_throttled")
        self.assertEqual(classify({"message": "server overloaded"}),
                         "codex_app_server_throttled")
        self.assertEqual(classify({"message": "something else broke"}),
                         "codex_app_server_protocol_error")


class FakeProcess:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class CmdRunCodexClassification(unittest.TestCase):
    """A failed codex child is classified — subscription cap cools + reports
    the next seat, invalid auth quarantines WITHOUT a cooldown, overload backs
    the provider off, network/unknown just hold. Never a blind replay."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_headroom = os.environ.get("HEADROOM_DIR")
        os.environ["HEADROOM_DIR"] = self.temp.name
        self.acct1 = _codex_account("cx1")
        self.acct2 = _codex_account("cx2")

    def tearDown(self):
        if self.old_headroom is None:
            os.environ.pop("HEADROOM_DIR", None)
        else:
            os.environ["HEADROOM_DIR"] = self.old_headroom
        self.temp.cleanup()

    def run_codex(self, stderr, successor=None):
        snapshot = {"generated": time.time(),
                    "accounts": [_codex_row("cx1"), _codex_row("cx2")]}
        errors = io.StringIO()
        with mock.patch.object(route, "ensure_fresh_snapshot",
                               return_value=snapshot), \
                mock.patch.object(route, "candidates",
                                  return_value=[(self.acct1, None),
                                                (self.acct2, None)]), \
                mock.patch.object(route, "block_reason", return_value=None), \
                mock.patch.object(route, "pick", return_value=successor), \
                mock.patch.object(
                    route.subprocess, "run",
                    return_value=FakeProcess(returncode=1,
                                             stderr=stderr)) as child, \
                redirect_stdout(io.StringIO()), redirect_stderr(errors):
            code = route.cmd_run("codex", ["codex", "exec", "task"])
        return code, child, errors.getvalue()

    def test_subscription_cap_cools_and_reports_without_replay(self):
        code, child, err = self.run_codex(
            "You've hit your usage limit. Try again later.",
            successor=self.acct2)
        self.assertEqual(code, 1)
        self.assertEqual(child.call_count, 1)  # NO replay on the next seat
        cool = route.cooldowns()
        self.assertIn("cx1:*", cool)
        self.assertIn("cx2", err)  # next healthy seat is reported
        self.assertIn("never auto-replayed", err)
        self.assertEqual(route.quarantines(), {})

    def test_invalid_token_quarantines_without_cooldown(self):
        code, child, err = self.run_codex(
            "ERROR: token_invalidated — please run `codex login`")
        self.assertEqual(code, 1)
        self.assertEqual(child.call_count, 1)
        self.assertEqual(route.cooldowns(), {})  # NO capacity cooldown
        quarantine = route.quarantines()
        self.assertIn("cx1", quarantine)
        self.assertIn("headroom connect cx1", err)

    def test_overload_sets_provider_backoff_only(self):
        code, child, err = self.run_codex("HTTP 429 Too Many Requests")
        self.assertEqual(code, 1)
        self.assertEqual(child.call_count, 1)
        self.assertEqual(route.cooldowns(), {})
        self.assertEqual(route.quarantines(), {})
        document = route.paths.load_json(route.paths.backoff_path())
        self.assertIn("codex_app_server", document["providers"])

    def test_network_failure_holds_everything(self):
        code, child, err = self.run_codex("connection refused by proxy")
        self.assertEqual(code, 1)
        self.assertEqual(route.cooldowns(), {})
        self.assertEqual(route.quarantines(), {})
        self.assertIn("holding", err)

    def test_unclassified_failure_takes_no_protective_action(self):
        code, child, err = self.run_codex("SyntaxError: bad task file")
        self.assertEqual(code, 1)
        self.assertEqual(child.call_count, 1)
        self.assertEqual(route.cooldowns(), {})
        self.assertEqual(route.quarantines(), {})

    def test_auth_error_mentioning_limit_is_auth_not_cap(self):
        code, child, err = self.run_codex(
            "401 unauthorized: usage limit check failed, please login again")
        self.assertEqual(route.cooldowns(), {})  # not cooled as a cap
        self.assertIn("cx1", route.quarantines())

    def test_claude_limit_still_rotates_and_replays(self):
        # regression: the Claude path keeps its documented rotate-and-replay
        acct_a, acct_b = _account("a"), _account("b")
        snapshot = {"generated": time.time(),
                    "accounts": [_claude_row("a"), _claude_row("b")]}
        with mock.patch.object(route, "ensure_fresh_snapshot",
                               return_value=snapshot), \
                mock.patch.object(route, "candidates",
                                  return_value=[(acct_a, None),
                                                (acct_b, None)]), \
                mock.patch.object(route, "block_reason", return_value=None), \
                mock.patch.object(route, "mark") as marked, \
                mock.patch.object(
                    route.subprocess, "run",
                    side_effect=[FakeProcess(returncode=1,
                                             stderr="usage limit reached"),
                                 FakeProcess(returncode=0)]) as child, \
                redirect_stdout(io.StringIO()), \
                redirect_stderr(io.StringIO()):
            code = route.cmd_run("sonnet", ["claude", "-p", "task"])
        self.assertEqual(code, 0)
        self.assertEqual(child.call_count, 2)  # rotated onto the next account
        marked.assert_called_once()


class CmdExecCodexRefusal(unittest.TestCase):
    """HEADROOM_CODEX_ROUTING=0 means headroom REFUSES codex routing — the
    old 'launch the first codex account anyway' fail-open path is gone."""

    def test_disabled_refuses_and_never_launches(self):
        errors = io.StringIO()
        with mock.patch.object(route, "CODEX_ROUTING_ENABLED", False), \
                mock.patch.object(route.registry, "ordered_for") as ordered, \
                mock.patch.object(route.os, "execvp") as execute, \
                redirect_stderr(errors):
            code = route.cmd_exec("codex", ["codex"])
        self.assertEqual(code, 2)
        execute.assert_not_called()
        ordered.assert_not_called()  # no first-account fallback consulted
        self.assertIn("HEADROOM_CODEX_ROUTING=0", errors.getvalue())
        self.assertIn("refusing", errors.getvalue())

    def test_enabled_but_no_headroom_refuses(self):
        errors = io.StringIO()
        with mock.patch.object(route, "pick", return_value=None), \
                mock.patch.object(route.os, "execvp") as execute, \
                redirect_stderr(errors):
            code = route.cmd_exec("codex", ["codex"])
        self.assertEqual(code, 2)
        execute.assert_not_called()
        self.assertIn("proven headroom", errors.getvalue())


class RegistryCodexSeats(unittest.TestCase):
    """The locked two-seat codex topology validates, and the new optional
    fields are type-checked without breaking existing configs."""

    def fleet(self):
        return {"schema_version": 1, "accounts": [
            {"name": "domanski-ai", "provider": "claude",
             "home": "~/ai-accounts/homes/claude-domanski-ai",
             "expected_email": "paul@domanski.ai"},
            {"name": "codex-domanski-ai", "provider": "codex",
             "home": "~/ai-accounts/homes/codex-domanski-ai",
             "expected_email": "paul@domanski.ai",
             "handoff_group": "domanski-server"},
            {"name": "codex-gmail", "provider": "codex",
             "home": "~/ai-accounts/homes/codex-gmail",
             "expected_email": "domanskip.paul@gmail.com",
             "handoff_group": "domanski-server",
             "shared_desktop": True},
        ]}

    def test_codex_seats_validate(self):
        config = self.fleet()
        self.assertEqual(registry.validate(config), config)

    def test_shared_desktop_must_be_bool(self):
        config = self.fleet()
        config["accounts"][2]["shared_desktop"] = "yes"
        with self.assertRaises(registry.RegistryError):
            registry.validate(config)

    def test_handoff_group_must_be_nonempty_string(self):
        config = self.fleet()
        config["accounts"][1]["handoff_group"] = ""
        with self.assertRaises(registry.RegistryError):
            registry.validate(config)
        config["accounts"][1]["handoff_group"] = 7
        with self.assertRaises(registry.RegistryError):
            registry.validate(config)

    def test_configs_without_new_fields_still_validate(self):
        config = {"schema_version": 1, "accounts": [
            {"name": "personal", "provider": "claude", "home": "~/.claude"}]}
        self.assertEqual(registry.validate(config), config)


if __name__ == "__main__":
    unittest.main()
