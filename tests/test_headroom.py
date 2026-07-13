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

    def test_empty_payload_defaults_available(self):
        w = collect.codex_windows({}, now=1000)
        self.assertEqual(w["5h"]["used_percent"], 0.0)
        self.assertEqual(w["7d"]["used_percent"], 0.0)


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

    def tearDown(self):
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
        snapshot = {"generated": now, "accounts": [
            {"name": "source", "email": "one@example.com", "windows": {
                "5h": {"used_percent": 100.0, "resets_at": now + 1200}}},
            {"name": "target", "email": "two@other.test", "windows": {
                "5h": {"used_percent": 10.0}}},
        ]}
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
                                  return_value={"accounts": []}), \
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


if __name__ == "__main__":
    unittest.main()
