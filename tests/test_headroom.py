"""headroom test suite — stdlib unittest only, no network.

Run:  python3 -m unittest discover -s tests   (from the repo root)

Covers the load-bearing safety logic: config validation, the fail-closed
router (`block_reason`), redaction, and the public-snapshot projection.
"""
import ast
import base64
import errno
import importlib
import json
import hashlib
import io
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from headroom import (  # noqa: E402
    __main__, collect, connect, dashboard, handoff, history, paths, registry,
    locks, route, statusline, supervisor, tokens,
)


def _slot_id(name):
    return hashlib.sha256(name.encode()).hexdigest()[:12]


def _claude_row(name="a", used5h=10.0, used7d=20.0, ok=True, **over):
    now = int(time.time())
    row = {
        "id": _slot_id(name), "name": name, "provider": "claude",
        "plan": "Max 20x", "ok": ok,
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


def _install_fake_claude(directory):
    os.makedirs(directory)
    fake = os.path.join(os.path.dirname(__file__), "fake_claude.py")
    if os.name == "nt":
        launcher = os.path.join(directory, "claude.cmd")
        with open(launcher, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(f'@"{sys.executable}" "{fake}" %*\n')
    else:
        os.symlink(fake, os.path.join(directory, "claude"))


class LockAbstraction(unittest.TestCase):
    def test_unix_backend_is_a_direct_flock_passthrough(self):
        backend = mock.Mock(LOCK_EX=2, LOCK_NB=4, LOCK_SH=1, LOCK_UN=8)
        handle = object()
        with mock.patch.object(locks, "_msvcrt", None), \
                mock.patch.object(locks, "_fcntl", backend):
            self.assertTrue(locks.exclusive(handle, blocking=False))
            self.assertTrue(locks.shared(handle))
            locks.unlock(handle)
        self.assertEqual(backend.flock.call_args_list, [
            mock.call(handle, 6), mock.call(handle, 1), mock.call(handle, 8)])

    def test_windows_backend_locks_byte_zero_and_unlocks_before_close(self):
        class Shim:
            LK_LOCK = 1
            LK_NBLCK = 2
            LK_UNLCK = 3

            def __init__(self):
                self.calls = []

            def locking(self, descriptor, mode, count):
                self.calls.append(
                    (os.lseek(descriptor, 0, os.SEEK_CUR), mode, count))

        shim = Shim()
        with tempfile.TemporaryFile("w+b") as handle, \
                mock.patch.object(locks, "_msvcrt", shim):
            handle.write(b"lock")
            handle.seek(3)
            self.assertTrue(locks.exclusive(handle))
            handle.seek(2)
            locks.unlock(handle)
            descriptor = os.dup(handle.fileno())
            locks.exclusive(descriptor)
            locks.close(descriptor)
        self.assertEqual(shim.calls, [(0, shim.LK_LOCK, 1),
                                      (0, shim.LK_UNLCK, 1),
                                      (0, shim.LK_LOCK, 1),
                                      (0, shim.LK_UNLCK, 1)])

    def test_windows_nonblocking_contention_and_shared_refusal(self):
        backend = mock.Mock(LK_LOCK=1, LK_NBLCK=2, LK_UNLCK=3)
        backend.locking.side_effect = OSError(errno.EACCES, "held")
        with tempfile.TemporaryFile("w+b") as handle, \
                mock.patch.object(locks, "_msvcrt", backend):
            self.assertFalse(locks.exclusive(handle, blocking=False))
            with self.assertRaises(locks.UnsupportedOnWindows):
                locks.shared(handle)

    def test_real_backend_reports_nonblocking_contention(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = os.path.join(directory, "real.lock")
            with open(lock_path, "w+b") as first, open(lock_path, "r+b") as second:
                first.write(b"x")
                first.flush()
                locks.exclusive(first)
                try:
                    self.assertFalse(locks.exclusive(second, blocking=False))
                finally:
                    locks.unlock(first)

    def test_permission_helpers_are_noops_on_windows(self):
        with mock.patch.object(paths.os, "name", "nt"), \
                mock.patch.object(paths.os, "chmod") as chmod, \
                mock.patch.object(paths.os, "fchmod", create=True) as fchmod:
            paths.chmod_private("ignored", 0o700)
            paths.fchmod_private(7, 0o600)
        chmod.assert_not_called()
        fchmod.assert_not_called()


class PlatformImportCleanliness(unittest.TestCase):
    def test_platform_imports_are_isolated_or_guarded(self):
        package_dir = os.path.dirname(paths.__file__)
        seen_termios = []
        for name in os.listdir(package_dir):
            if not name.endswith(".py"):
                continue
            filename = os.path.join(package_dir, name)
            with open(filename, encoding="utf-8") as handle:
                tree = ast.parse(handle.read(), filename=filename)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = {alias.name for alias in node.names}
                    if "fcntl" in imported:
                        self.assertEqual(name, "locks.py")
                    if "termios" in imported:
                        seen_termios.append((name, node))
            direct = [node for node in tree.body if isinstance(node, ast.Import)]
            self.assertFalse(any(alias.name in {"fcntl", "termios"}
                                 for node in direct for alias in node.names))
            importlib.import_module("headroom." + name[:-3])
        self.assertEqual([name for name, _ in seen_termios], ["supervisor.py"])
        with open(supervisor.__file__, encoding="utf-8") as handle:
            supervisor_tree = ast.parse(handle.read())
        self.assertTrue(any(
            isinstance(node, ast.Try) and any(
                isinstance(child, ast.Import)
                and any(alias.name == "termios" for alias in child.names)
                for child in node.body)
            for node in supervisor_tree.body))


class WindowsSupervisionDegradation(unittest.TestCase):
    def test_claude_launches_directly_with_one_clear_message(self):
        errors = io.StringIO()
        with mock.patch.object(supervisor, "termios", None), \
                mock.patch.object(route, "cmd_exec", return_value=17) as execute, \
                redirect_stderr(errors):
            result = __main__._launch(
                "claude", ["--headroom-auto-handoff",
                           "--headroom-launch-fallback"])
        self.assertEqual(result, 17)
        self.assertEqual(errors.getvalue(), supervisor.UNSUPERVISED_MESSAGE + "\n")
        execute.assert_called_once_with(
            "claude", ["claude"],
            launch_note="supervision unavailable on this platform",
            fallback=True)


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

    def test_token_extra_roots_reject_bad_labels_providers_and_duplicates(self):
        base = {"schema_version": 1, "accounts": [_account("alpha")]}
        entries = [
            [{"label": "", "provider": "claude", "path": "/tmp"}],
            [{"label": "bad@example", "provider": "claude",
              "path": "/tmp"}],
            [{"label": "x" * 41, "provider": "claude", "path": "/tmp"}],
            [{"label": "interactive", "provider": "other", "path": "/tmp"}],
            # grok is a valid account provider but has no token-log format, so a
            # grok token extra-root is rejected (would be scanned as codex)
            [{"label": "grok-root", "provider": "grok", "path": "/tmp"}],
            [{"label": "alpha", "provider": "claude", "path": "/tmp"}],
            [{"label": "interactive", "provider": "claude", "path": "/tmp"},
             {"label": "interactive", "provider": "codex", "path": "/tmp"}],
        ]
        for roots in entries:
            config = dict(base, dashboard={"token_extra_roots": roots})
            with self.subTest(roots=roots), \
                    self.assertRaises(registry.RegistryError):
                registry.validate(config)

    def test_token_extra_root_bad_paths_are_skipped_and_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            regular_file = os.path.join(directory, "file")
            with open(regular_file, "w", encoding="utf-8") as handle:
                handle.write("x")
            config = {"schema_version": 1, "accounts": [_account("alpha")],
                      "dashboard": {"token_extra_roots": [
                          {"label": "valid", "provider": "claude",
                           "path": directory},
                          {"label": "relative", "provider": "codex",
                           "path": "sessions"},
                          {"label": "missing", "provider": "claude",
                           "path": os.path.join(directory, "missing")},
                          {"label": "file", "provider": "claude",
                           "path": regular_file},
                      ]}}
            self.assertEqual(registry.validate(config), config)
            roots, partial = registry.token_extra_roots(
                config, include_status=True)
        self.assertTrue(partial)
        self.assertEqual([root["name"] for root in roots], ["valid"])

    def test_virtual_slot_id_is_stable_and_outside_registry_namespace(self):
        home = "/tmp/headroom-roots/../primary"
        canonical = registry.expand(home)
        expected = "x-" + hashlib.sha256(
            f"Primary CLI home\0claude\0{canonical}".encode()).hexdigest()[:24]
        slot = registry.virtual_slot_id(
            "Primary CLI home", "claude", home)
        self.assertEqual(slot, expected)
        self.assertEqual(slot, registry.virtual_slot_id(
            "Primary CLI home", "claude", canonical))
        self.assertNotEqual(slot, registry.virtual_slot_id(
            "Primary CLI home", "codex", canonical))
        self.assertNotEqual(slot, registry.virtual_slot_id(
            "Primary CLI home", "claude", "/tmp/another-home"))
        self.assertRegex(slot, registry.VIRTUAL_ID_RE)
        self.assertNotRegex(slot, registry.ID_RE)
        self.assertNotEqual(slot, _slot_id("Primary CLI home"))

    def test_token_extra_roots_reject_derived_id_and_canonical_root_collisions(self):
        base = {"schema_version": 1, "accounts": [_account("alpha")]}
        duplicate_roots = (
            [
                {"label": "one", "provider": "claude", "path": "/tmp/root"},
                {"label": "two", "provider": "codex", "path": "/tmp/./root"},
            ],
            [{"label": "one", "provider": "claude",
              "path": _account("alpha")["home"]}],
        )
        for roots in duplicate_roots:
            config = dict(base, dashboard={"token_extra_roots": roots})
            with self.subTest(roots=roots), \
                    self.assertRaisesRegex(
                        registry.RegistryError, "canonical root"):
                registry.validate(config)

        collision = dict(base, dashboard={"token_extra_roots": [
            {"label": "one", "provider": "claude", "path": "/tmp/one"},
            {"label": "two", "provider": "codex", "path": "/tmp/two"},
        ]})
        with mock.patch.object(
                registry, "virtual_slot_id", return_value="x-" + "a" * 24), \
                self.assertRaisesRegex(registry.RegistryError,
                                       "duplicate derived id"):
            registry.validate(collision)

    def test_rejects_invalid_or_duplicate_slot_ids(self):
        invalid = {"schema_version": 1, "accounts": [
            dict(_account("a"), id="NOT-HEX")]}
        duplicate = {"schema_version": 1, "accounts": [
            dict(_account("a"), id="aaaaaaaaaaaa"),
            dict(_account("b"), id="aaaaaaaaaaaa")]}
        for config in (invalid, duplicate):
            with self.subTest(config=config), \
                    self.assertRaises(registry.RegistryError):
                registry.validate(config)

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

    def test_claude_missing_5h_holds(self):
        # the 5h window is optional ONLY for codex (OpenAI lifted it). A claude
        # seat missing its 5h is a failed read and must hold — fail-closed.
        row = _claude_row()
        del row["windows"]["5h"]
        reason = self.reason(row)
        self.assertIsNotNone(reason)
        self.assertIn("5h window missing", reason)


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
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        bin_dir = os.path.join(self.temp.name, "bin")
        _install_fake_claude(bin_dir)
        self.env = mock.patch.dict(os.environ, {
            "PATH": bin_dir + os.pathsep + os.environ.get("PATH", "")})
        self.env.start()
        self.addCleanup(self.env.stop)

    def _make_runner(self, payload):
        import subprocess
        class FakeResult:
            returncode = 0
            stdout = __import__("json").dumps(payload)
        def runner(cmd, **_kwargs):
            return FakeResult()
        return runner

    def test_default_profile_metadata_read_from_profile_root(self):
        """The default layout (config dir named .claude) keeps oauthAccount in
        the PROFILE ROOT ~/.claude.json — the file inside the config dir is a
        stub. Windows single-account setups hit this; the binding must fall
        back to the sibling, and managed slot homes must never look up."""
        profile = os.path.join(self.temp.name, "profile")
        home = os.path.join(profile, ".claude")
        os.makedirs(home)
        with open(os.path.join(home, ".claude.json"), "w") as handle:
            json.dump({"installMethod": "unknown"}, handle)  # the stub
        with open(os.path.join(profile, ".claude.json"), "w") as handle:
            json.dump({"oauthAccount": {
                "emailAddress": "shaun@example.com",
                "organizationUuid": "org-1234"}}, handle)
        result = collect.claude_local_identity(home)
        self.assertEqual(result["email"], "shaun@example.com")
        self.assertEqual(result["method"], "claude_local_metadata")
        managed = os.path.join(profile, "claude-slot")
        os.makedirs(managed)
        with self.assertRaises(collect.IdentityBindingError):
            collect.claude_local_identity(managed)

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


class ThrottleCarryover(unittest.TestCase):
    """A rate-limited USAGE CHECK is not evidence of missing capacity: the
    last verified reading is carried forward (age-bounded) instead of holding
    the slot — a busy meter must never strand launches."""

    def _account(self):
        return {"name": "a", "provider": "claude", "home": "/tmp/h"}

    FRESH_IDENTITY = {"account_fingerprint": "AAAA",
                      "credential_digest": "BBBB"}

    def _previous_row(self, captured_at=1_000_000, **over):
        base = captured_at if isinstance(captured_at, int) \
            and not isinstance(captured_at, bool) else 1_000_000
        row = {
            "name": "a", "provider": "claude", "ok": True, "routable": True,
            "trust_state": "verified_local", "stale": False,
            "captured_at": captured_at,
            "identity": {"verified": False, "method": "local",
                         "email": "e@x.com", "account_fingerprint": "AAAA",
                         "credential_digest": "BBBB"},
            "windows": {
                "5h": {"used_percent": 10.0, "resets_at": base + 3600,
                       "observed_at": base, "window_minutes": 300},
                "7d": {"used_percent": 20.0,
                       "resets_at": base + 7 * 86400,
                       "observed_at": base, "window_minutes": 10080},
            },
        }
        row.update(over)
        return row

    def previous(self, **over):
        return {"accounts": [self._previous_row(**over)]}

    def test_fresh_verified_row_carries(self):
        carried = collect._throttle_carryover(
            self.previous(), self._account(), 1_000_060,
            self.FRESH_IDENTITY)
        self.assertIsNotNone(carried)
        self.assertEqual(carried["windows"]["5h"]["used_percent"], 10.0)

    def test_carried_row_is_a_copy(self):
        previous = self.previous()
        carried = collect._throttle_carryover(
            previous, self._account(), 1_000_060, self.FRESH_IDENTITY)
        carried["windows"]["5h"]["used_percent"] = 99.0
        self.assertEqual(
            previous["accounts"][0]["windows"]["5h"]["used_percent"], 10.0)

    def test_expired_row_does_not_carry(self):
        now = 1_000_000 + collect.OBSERVATION_MAX_AGE + 1
        self.assertIsNone(collect._throttle_carryover(
            self.previous(), self._account(), now, self.FRESH_IDENTITY))

    def test_less_than_verified_success_does_not_carry(self):
        for over in ({"ok": False}, {"routable": False},
                     {"trust_state": "held"},
                     {"trust_state": "dashboard_only"},
                     {"captured_at": None}, {"captured_at": True},
                     {"captured_at": 2_000_000}):  # future = clock skew
            self.assertIsNone(collect._throttle_carryover(
                self.previous(**over), self._account(), 1_000_060,
                self.FRESH_IDENTITY), over)

    def test_missing_or_malformed_previous_does_not_carry(self):
        for previous in (None, {}, {"accounts": None}, {"accounts": "x"},
                         {"accounts": []},
                         {"accounts": [{"name": "other", "ok": True}]}):
            self.assertIsNone(collect._throttle_carryover(
                previous, self._account(), 1_000_060,
                self.FRESH_IDENTITY), previous)

    def test_changed_identity_or_credential_does_not_carry(self):
        # a relogged slot must never republish the prior identity's reading
        for fresh in ({"account_fingerprint": "ZZZZ",
                       "credential_digest": "BBBB"},
                      {"account_fingerprint": "AAAA",
                       "credential_digest": "YYYY"},
                      {"account_fingerprint": "AAAA"},
                      {}, None):
            self.assertIsNone(collect._throttle_carryover(
                self.previous(), self._account(), 1_000_060, fresh), fresh)
        mismatched = self.previous()
        mismatched["accounts"][0]["provider"] = "codex"
        self.assertIsNone(collect._throttle_carryover(
            mismatched, self._account(), 1_000_060, self.FRESH_IDENTITY))

    def _throttled_collect(self, previous):
        identity = {"verified": False, "method": "local", "email": "e@x.com",
                    "account_fingerprint": "AAAA"}
        throttle = collect.ProviderThrottleError(
            int(time.time()) + 300, provider_response=True)
        with mock.patch.object(collect, "claude_identity",
                               return_value=dict(identity)), \
                mock.patch.object(collect, "credential_digest",
                                  return_value="BBBB"), \
                mock.patch.object(collect, "claude_plan",
                                  return_value="Max 20x"), \
                mock.patch.object(collect, "claude_limits",
                                  side_effect=throttle):
            return collect.collect([self._account()], previous=previous)

    def test_collect_serves_carryover_row_through_a_throttle(self):
        previous = {"accounts": [
            self._previous_row(captured_at=int(time.time()) - 60)]}
        row = self._throttled_collect(previous)["accounts"][0]
        self.assertIs(row["ok"], True)
        self.assertIs(row["throttle_carryover"], True)
        self.assertIs(row["routable"], True)
        self.assertIn(row["trust_state"], ("verified", "verified_local"))
        self.assertEqual(row["windows"]["5h"]["used_percent"], 10.0)
        self.assertIn("last verified reading", row["note"])

    def test_collect_still_holds_without_a_carryover_row(self):
        row = self._throttled_collect(previous=None)["accounts"][0]
        self.assertIs(row["ok"], False)
        self.assertEqual(row["error_code"], "usage_source_rate_limited")
        self.assertNotIn("throttle_carryover", row)

    def test_carryover_survives_public_projection(self):
        previous = {"accounts": [
            self._previous_row(captured_at=int(time.time()) - 60)]}
        snapshot = self._throttled_collect(previous)
        public = collect.public_snapshot(snapshot, redact_emails=True)
        row = public["accounts"][0]
        self.assertIs(row["ok"], True)
        self.assertIs(row["throttle_carryover"], True)


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

    def test_five_hour_lifted_omits_5h(self):
        # OpenAI lifted the 5h limit (2026-07): only the weekly window is
        # reported. An absent 5h must be OMITTED, never synthesized as 0% --
        # faking capacity for a limit that no longer exists is a lie.
        rl = {"primary": {"usedPercent": 16, "windowDurationMins": 10080},
              "secondary": None}
        w = collect.codex_windows(rl, now=1000)
        self.assertEqual(w["7d"]["used_percent"], 16.0)
        self.assertNotIn("5h", w)

    def test_only_reports_present_windows(self):
        # a lone 5h reports 5h only -- the weekly is not synthesized either;
        # validate_required_windows is what holds a seat missing its weekly.
        rl = {"primary": {"usedPercent": 40, "windowDurationMins": 300}}
        w = collect.codex_windows(rl, now=1000)
        self.assertEqual(w["5h"]["used_percent"], 40.0)
        self.assertNotIn("7d", w)

    def test_scoped_bucket_becomes_scoped_row(self):
        # a model-scoped bucket (limitName "GPT-5.3-Codex-Spark") rides alongside
        # the codex windows as a scoped:<codename> weekly row -- the verbose name
        # is shortened to its trailing codename ("Spark") for a compact label.
        rl = {"primary": {"usedPercent": 7, "windowDurationMins": 10080},
              "secondary": None}
        scoped = {"codex_bengalfox": {
            "limitName": "GPT-5.3-Codex-Spark",
            "primary": {"usedPercent": 3, "windowDurationMins": 10080},
            "secondary": None}}
        w = collect.codex_windows(rl, now=1000, scoped_limits=scoped)
        self.assertEqual(w["7d"]["used_percent"], 7.0)
        self.assertNotIn("5h", w)
        self.assertNotIn("scoped:GPT-5.3-Codex-Spark", w)
        self.assertEqual(w["scoped:Spark"]["used_percent"], 3.0)
        self.assertEqual(w["scoped:Spark"]["window_minutes"], 10080)

    def test_scoped_bucket_without_weekly_is_skipped(self):
        # a scoped bucket carrying no usable weekly window is dropped, never
        # rendered as an empty/unknown scoped column.
        rl = {"primary": {"usedPercent": 7, "windowDurationMins": 10080}}
        scoped = {"x": {"limitName": "Weird", "primary": None,
                        "secondary": None}}
        w = collect.codex_windows(rl, now=1000, scoped_limits=scoped)
        self.assertNotIn("scoped:Weird", w)

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


class ValidateRequiredWindows(unittest.TestCase):
    W = {"used_percent": 5.0}

    def test_require_5h_false_allows_missing_5h(self):
        # codex after the 5h lift: only the weekly window is mandatory
        collect.validate_required_windows({"7d": self.W}, require_5h=False)

    def test_require_5h_false_still_requires_weekly(self):
        with self.assertRaises(ValueError):
            collect.validate_required_windows({"5h": self.W}, require_5h=False)

    def test_default_requires_both(self):
        with self.assertRaises(ValueError):
            collect.validate_required_windows({"7d": self.W})
        collect.validate_required_windows({"5h": self.W, "7d": self.W})


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

    @unittest.skipIf(os.name == "nt", "POSIX permission bits do not apply")
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


@unittest.skipIf(os.name == "nt", "transactional handoff is Unix-gated in v1")
class HandoffSafety(unittest.TestCase):
    SID = "11111111-1111-4111-8111-111111111111"
    OTHER_SID = "22222222-2222-4222-8222-222222222222"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_path = os.environ.get("PATH")
        bin_dir = os.path.join(self.temp.name, "bin")
        _install_fake_claude(bin_dir)
        os.environ["PATH"] = bin_dir + os.pathsep + (self.old_path or "")
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
        if self.old_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = self.old_path
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
        with open(os.path.join(state, "sessions.jsonl"), "w",
                  encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")

    def _journal_row(self, session_id, path, ts=100, model="Sonnet"):
        return {"ts": ts, "session_id": session_id,
                "transcript_path": path, "cwd": self.cwd, "model": model,
                "version": "1", "config_dir": self.source_home}

    def test_explicit_session_wins_over_ambiguous_journal(self):
        other = self._transcript(self.source_home, self.OTHER_SID)
        with open(other, "w", encoding="utf-8", newline="\n") as handle:
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
        with open(self.transcript, "w", encoding="utf-8",
                  newline="\n") as handle:
            handle.write(json.dumps(event) + "\n")
        with self.assertRaisesRegex(handoff.HandoffError, "mid-tool-call"):
            handoff.inspect_transcript(self.transcript)

    def test_destination_collision_refused(self):
        destination = self._transcript(self.target_home, self.SID)
        with open(destination, "w", encoding="utf-8",
                  newline="\n") as handle:
            handle.write("existing")
        digest = hashlib.sha256(self.bytes).hexdigest()
        with self.assertRaisesRegex(handoff.HandoffError, "does not overwrite"):
            handoff.stage_transcript(self.transcript, destination, digest)

    def test_command_delegates_collision_check_to_atomic_staging(self):
        self._journal([self._journal_row(self.SID, self.transcript)])
        destination = handoff.destination_path(self.target_home, self.transcript,
                                               self.SID)
        os.makedirs(os.path.dirname(destination))
        with open(destination, "w", encoding="utf-8",
                  newline="\n") as handle:
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
        self.assertTrue(copied.startswith(self.bytes))
        self.assertTrue(copied.endswith(tokens.handoff_marker_line()))
        self.assertEqual(hashlib.sha256(self.bytes).hexdigest(), digest)
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
        destination = handoff.destination_path(
            self.target_home, self.transcript, self.SID)
        with open(destination, "rb") as handle:
            copied = handle.read()
        self.assertEqual(copied, self.bytes + tokens.handoff_marker_line())
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
@unittest.skipIf(os.name == "nt", "transactional handoff is Unix-gated in v1")
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


def _grok_row(name="g", used7d=20.0, **over):
    now = int(time.time())
    row = {
        "name": name, "provider": "grok", "plan": "Grok", "ok": True,
        "stale": False, "routable": True, "identity_verified": False,
        "identity": {"account_fingerprint": "AAAA", "credential_digest": "BBBB"},
        "trust_state": "verified_local", "captured_at": now - 10,
        "source": "grok_build_billing",
        "windows": {"7d": {"used_percent": used7d, "resets_at": now + 8 * 86400,
                           "window_minutes": 10080, "observed_at": now - 10,
                           "freshness": "fresh"}},
    }
    row.update(over)
    return row


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

    def test_lifted_5h_still_routes(self):
        # OpenAI lifted Codex's 5h: a live seat reports only the weekly window.
        # An absent 5h must NOT block the seat (it used to fail "5h window
        # missing", blocking every codex seat once the fake 0% was removed).
        row = _codex_row()
        del row["windows"]["5h"]
        self.assertIsNone(self.reason(row))

    def test_present_but_malformed_5h_holds_for_codex(self):
        # only a genuinely ABSENT 5h is the lifted limit; a present-but-
        # malformed 5h (null/string/number in a corrupt snapshot) is NOT
        # lifted — fail closed and hold, never route on it.
        for bad in (None, "garbage", 5):
            row = _codex_row()
            row["windows"]["5h"] = bad
            reason = self.reason(row)
            self.assertIsNotNone(reason, bad)
            self.assertIn("5h window missing", reason)

    def test_missing_weekly_still_holds_for_codex(self):
        # the weekly (7d) stays mandatory even for codex — fail-closed.
        row = _codex_row()
        del row["windows"]["7d"]
        reason = self.reason(row)
        self.assertIsNotNone(reason)
        self.assertIn("7d window missing", reason)


class GreatestHeadroom(unittest.TestCase):
    """Candidate order follows REGISTRY preference for every family
    (operator 2026-07-18, reversing the 2026-07-14 Codex greatest-headroom
    scoping): the registry lists accounts primary-first and overflow happens
    only through eligibility, never emptiest-first hopping."""

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

    def test_codex_keeps_registry_order_while_primary_is_eligible(self):
        # cx2 has more room, but cx1 is the registry primary and eligible —
        # the sticky primary wins until it is actually blocked.
        accounts = [_codex_account("cx1"), _codex_account("cx2")]
        rows = [_codex_row("cx1", used5h=60.0, used7d=30.0),
                _codex_row("cx2", used5h=10.0, used7d=20.0)]
        ranked = self.ranked("codex", accounts, rows)
        self.assertEqual([a["name"] for a, r in ranked if r is None],
                         ["cx1", "cx2"])

    def test_registry_order_holds_even_with_thin_primary_windows(self):
        # cx1 is nearly out of weekly room but still ELIGIBLE — registry
        # preference keeps it first; overflow only happens on a real block.
        accounts = [_codex_account("cx1"), _codex_account("cx2")]
        rows = [_codex_row("cx1", used5h=10.0, used7d=95.0),
                _codex_row("cx2", used5h=60.0, used7d=40.0)]
        ranked = self.ranked("codex", accounts, rows)
        self.assertEqual(ranked[0][0]["name"], "cx1")

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

    def test_lifted_5h_seats_are_routable_and_scored_on_weekly(self):
        # both codex seats have their 5h lifted (absent). They must stay
        # ROUTABLE (reason None) in registry order — a lifted 5h window must
        # never block a seat or perturb the preference ordering.
        accounts = [_codex_account("cx1"), _codex_account("cx2")]
        rows = [_codex_row("cx1", used7d=70.0), _codex_row("cx2", used7d=20.0)]
        for row in rows:
            del row["windows"]["5h"]
        ranked = self.ranked("codex", accounts, rows)
        self.assertEqual([a["name"] for a, r in ranked if r is None],
                         ["cx1", "cx2"])

    def test_pick_returns_lifted_5h_codex_seat(self):
        account = _codex_account("cx1")
        row = _codex_row("cx1", used7d=20.0)
        del row["windows"]["5h"]
        snapshot = {"generated": time.time(), "accounts": [row]}
        with mock.patch.object(route.registry, "ordered_for",
                               return_value=[account]), \
                mock.patch.object(route.registry, "reserve_percent",
                                  return_value=0.0), \
                mock.patch.object(route, "ensure_fresh_snapshot",
                                  return_value=snapshot):
            chosen = route.pick("codex")
        self.assertIsNotNone(chosen)
        self.assertEqual(chosen["name"], "cx1")


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
        environ = {k: v for k, v in os.environ.items() if k != "CODEX_HOME"}
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(route, "pick", return_value=None), \
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


class ReservedAccounts(unittest.TestCase):
    """`reserved: true` = tracked but never auto-routed. The gate lives in
    block_reason so EVERY selection path (pick, candidates, launch, rotation
    and handoff targets) refuses it, while collect/dashboard still see it."""

    def setUp(self):
        self._orig_binding = collect.local_binding
        collect.local_binding = lambda provider, home: ("AAAA", "BBBB")

    def tearDown(self):
        collect.local_binding = self._orig_binding

    def test_reserved_must_be_bool(self):
        config = {"schema_version": 1, "accounts": [
            {"name": "a", "provider": "claude", "home": "/tmp/x",
             "reserved": "yes"}]}
        with self.assertRaises(registry.RegistryError):
            registry.validate(config)

    def test_reserved_true_and_false_validate(self):
        config = {"schema_version": 1, "accounts": [
            {"name": "a", "provider": "claude", "home": "/tmp/x",
             "reserved": True},
            {"name": "b", "provider": "claude", "home": "/tmp/y",
             "reserved": False}]}
        self.assertEqual(registry.validate(config), config)

    def test_reserved_holds_even_when_healthy(self):
        account = dict(_account("a"), reserved=True)
        reason = route.block_reason(account, "sonnet", _claude_row("a"),
                                    {}, time.time())
        self.assertIsNotNone(reason)
        self.assertIn("reserved", reason)

    def test_reserved_false_routes_normally(self):
        account = dict(_account("a"), reserved=False)
        self.assertIsNone(route.block_reason(account, "sonnet",
                                             _claude_row("a"), {}, time.time()))

    def test_pick_skips_reserved_for_next_eligible(self):
        reserved = dict(_account("a"), reserved=True)
        open_account = _account("b")
        snapshot = {"generated": time.time(),
                    "accounts": [_claude_row("a"), _claude_row("b")]}
        with mock.patch.object(route, "ensure_fresh_snapshot",
                               return_value=snapshot), \
                mock.patch.object(route.registry, "ordered_for",
                                  return_value=[reserved, open_account]), \
                mock.patch.object(route.registry, "reserve_percent",
                                  return_value=0.0), \
                mock.patch.object(route, "cooldowns", return_value={}):
            chosen = route.pick("sonnet")
        self.assertEqual(chosen["name"], "b")


class EnvPinnedAccount(unittest.TestCase):
    """An explicitly exported config home that names a registered account is
    consumed as the initial slot instead of being re-routed."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home_a = os.path.join(self.temp.name, "homes", "a")
        self.home_b = os.path.join(self.temp.name, "homes", "b")
        os.makedirs(self.home_a)
        os.makedirs(self.home_b)
        self.accounts = [
            {"name": "a", "provider": "claude", "home": self.home_a},
            {"name": "b", "provider": "claude", "home": self.home_b}]

    def tearDown(self):
        self.temp.cleanup()

    def pinned(self, fam="sonnet", **env):
        environ = {k: v for k, v in os.environ.items()
                   if k not in ("CLAUDE_CONFIG_DIR", "CODEX_HOME")}
        environ.update(env)
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(route.registry, "ordered_for",
                                  return_value=self.accounts):
            return route.env_pinned_account(fam)

    def test_unset_env_is_no_pin(self):
        self.assertIsNone(self.pinned())

    def test_env_home_maps_to_registered_account(self):
        chosen = self.pinned(CLAUDE_CONFIG_DIR=self.home_b)
        self.assertEqual(chosen["name"], "b")

    def test_unregistered_home_is_no_pin(self):
        self.assertIsNone(self.pinned(CLAUDE_CONFIG_DIR=self.temp.name))

    def test_registry_error_is_no_pin(self):
        environ = dict(os.environ, CLAUDE_CONFIG_DIR=self.home_a)
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(
                    route.registry, "ordered_for",
                    side_effect=registry.RegistryError("no config")):
            self.assertIsNone(route.env_pinned_account("sonnet"))

    def test_cmd_exec_consumes_pinned_account(self):
        snapshot = {"generated": time.time(), "accounts": [
            _claude_row("a"), _claude_row("b")]}
        environ = {k: v for k, v in os.environ.items()
                   if k != "HEADROOM_LAUNCH_MARKER"}
        environ["CLAUDE_CONFIG_DIR"] = self.home_b
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(route.registry, "ordered_for",
                                  return_value=self.accounts), \
                mock.patch.object(route, "ensure_fresh_snapshot",
                                  return_value=snapshot), \
                mock.patch.object(route, "block_reason", return_value=None), \
                mock.patch.object(route, "cooldowns", return_value={}), \
                mock.patch.object(route, "pick") as picked, \
                mock.patch.object(route.os, "execvp") as execute, \
                redirect_stderr(io.StringIO()):
            route.cmd_exec("sonnet", ["claude"])
            selected = os.environ.get("CLAUDE_CONFIG_DIR")
        picked.assert_not_called()  # the exported home was consumed, not re-routed
        execute.assert_called_once()
        self.assertEqual(selected, self.home_b)

    def test_cmd_exec_repicks_when_pinned_account_is_blocked(self):
        snapshot = {"generated": time.time(), "accounts": [
            _claude_row("a"), _claude_row("b", used5h=100)]}
        open_account = self.accounts[0]
        errors = io.StringIO()
        environ = {k: v for k, v in os.environ.items()
                   if k != "HEADROOM_LAUNCH_MARKER"}
        environ["CLAUDE_CONFIG_DIR"] = self.home_b
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(route.registry, "ordered_for",
                                  return_value=self.accounts), \
                mock.patch.object(route, "ensure_fresh_snapshot",
                                  return_value=snapshot), \
                mock.patch.object(route, "block_reason",
                                  side_effect=["at limit", None]), \
                mock.patch.object(route, "cooldowns", return_value={}), \
                mock.patch.object(route, "pick",
                                  return_value=open_account) as picked, \
                mock.patch.object(route.os, "execvp") as execute, \
                redirect_stderr(errors):
            route.cmd_exec("sonnet", ["claude"])
            selected = os.environ.get("CLAUDE_CONFIG_DIR")
        picked.assert_called_once()
        execute.assert_called_once()
        self.assertIn("not routable", errors.getvalue())
        self.assertEqual(selected, self.home_a)


class LaunchMarker(unittest.TestCase):
    """HEADROOM_LAUNCH_MARKER: the wrapper handshake is written before any
    launch, and a requested-but-unwritable marker aborts instead of leaving
    the wrapper's fallback logic racing a CLI headroom did start."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_headroom = os.environ.get("HEADROOM_DIR")
        os.environ["HEADROOM_DIR"] = os.path.join(self.temp.name, "hr")
        self.account = {"name": "a", "provider": "claude",
                        "home": os.path.join(self.temp.name, "homes", "a")}

    def tearDown(self):
        self.temp.cleanup()
        if self.old_headroom is None:
            os.environ.pop("HEADROOM_DIR", None)
        else:
            os.environ["HEADROOM_DIR"] = self.old_headroom

    def marker_env(self, value):
        environ = {k: v for k, v in os.environ.items()
                   if k != "HEADROOM_LAUNCH_MARKER"}
        if value is not None:
            environ["HEADROOM_LAUNCH_MARKER"] = value
        return mock.patch.dict(os.environ, environ, clear=True)

    def test_no_marker_requested_is_a_no_op_success(self):
        with self.marker_env(None):
            self.assertTrue(route.write_launch_marker("exec", self.account))

    def test_marker_written_with_mode_account_and_note(self):
        destination = os.path.join(self.temp.name, "marker.json")
        with self.marker_env(destination):
            self.assertTrue(route.write_launch_marker(
                "supervised", self.account, note="why not"))
        with open(destination, encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["mode"], "supervised")
        self.assertEqual(payload["account"], "a")
        self.assertEqual(payload["note"], "why not")

    def test_marker_never_clobbers_an_existing_file(self):
        destination = os.path.join(self.temp.name, "precious.json")
        with open(destination, "w", encoding="utf-8") as handle:
            handle.write("do not lose me")
        with self.marker_env(destination), \
                redirect_stderr(io.StringIO()):
            self.assertFalse(route.write_launch_marker("exec", self.account))
        with open(destination, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "do not lose me")

    def test_relative_marker_path_refuses_launch(self):
        with self.marker_env("relative/marker.json"), \
                redirect_stderr(io.StringIO()):
            self.assertFalse(route.write_launch_marker("exec", self.account))

    def test_unwritable_marker_refuses_launch(self):
        destination = os.path.join(self.temp.name, "missing-dir-parent")
        # a FILE where the parent directory should be makes makedirs fail
        with open(destination, "w", encoding="utf-8") as handle:
            handle.write("x")
        with self.marker_env(os.path.join(destination, "marker.json")), \
                redirect_stderr(io.StringIO()):
            self.assertFalse(route.write_launch_marker("exec", self.account))

    def test_cmd_exec_aborts_before_exec_when_marker_unwritable(self):
        snapshot = {"generated": time.time(), "accounts": [_claude_row("a")]}
        blocker = os.path.join(self.temp.name, "blocker")
        with open(blocker, "w", encoding="utf-8") as handle:
            handle.write("x")
        environ = {k: v for k, v in os.environ.items()
                   if k not in ("CLAUDE_CONFIG_DIR", "CODEX_HOME")}
        environ["HEADROOM_LAUNCH_MARKER"] = os.path.join(blocker, "m.json")
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(route, "pick", return_value=self.account), \
                mock.patch.object(route, "ensure_fresh_snapshot",
                                  return_value=snapshot), \
                mock.patch.object(route, "block_reason", return_value=None), \
                mock.patch.object(route, "cooldowns", return_value={}), \
                mock.patch.object(route.os, "execvp") as execute, \
                redirect_stderr(io.StringIO()):
            code = route.cmd_exec("sonnet", ["claude"])
        self.assertEqual(code, 2)
        execute.assert_not_called()

    def test_cmd_exec_marker_records_exec_mode_and_note(self):
        snapshot = {"generated": time.time(), "accounts": [_claude_row("a")]}
        destination = os.path.join(self.temp.name, "marker.json")
        environ = {k: v for k, v in os.environ.items()
                   if k not in ("CLAUDE_CONFIG_DIR", "CODEX_HOME")}
        environ["HEADROOM_LAUNCH_MARKER"] = destination
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(route, "pick", return_value=self.account), \
                mock.patch.object(route, "ensure_fresh_snapshot",
                                  return_value=snapshot), \
                mock.patch.object(route, "block_reason", return_value=None), \
                mock.patch.object(route, "cooldowns", return_value={}), \
                mock.patch.object(route.os, "execvp") as execute, \
                redirect_stderr(io.StringIO()):
            route.cmd_exec("sonnet", ["claude"],
                           launch_note="auto-handoff disabled: --settings")
        execute.assert_called_once()
        with open(destination, encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["mode"], "exec")
        self.assertEqual(payload["note"], "auto-handoff disabled: --settings")


class CollectionLockOrdering(unittest.TestCase):
    def test_collector_locks_before_loading_registry_and_never_scans_tokens(self):
        config = {"schema_version": 1, "accounts": [_account("a")]}
        observed = []

        def guarded_load():
            with open(paths.collect_lock_path(), "a") as handle:
                if not locks.exclusive(handle, blocking=False):
                    observed.append(True)
                else:
                    observed.append(False)
                    locks.unlock(handle)
            return config

        snapshot = {"schema_version": 1, "run_id": "fixture", "generated": 1,
                    "generated_iso": "fixture", "accounts": []}
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.dict(os.environ, {"HEADROOM_DIR": root}), \
                mock.patch.object(registry, "load", side_effect=guarded_load), \
                mock.patch.object(collect, "collect", return_value=snapshot), \
                mock.patch.object(registry, "dashboard_settings",
                                  return_value={"redact_emails": True}), \
                mock.patch.object(tokens, "collect",
                                  side_effect=AssertionError("token scan")):
            collect.run_collect(quiet=True)
        # Initial collection and the locked ID/pin merge remain inside the
        # collection lock. Quiet route/handoff callers do no token work.
        self.assertEqual(observed, [True, True])


class AuthRefreshCommand(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"HEADROOM_DIR": self.temp.name})
        self.env.start()
        self.home = os.path.join(paths.homes_dir(), "claude-a")
        os.makedirs(self.home)
        self.config = {"schema_version": 1, "accounts": [{
            "name": "claude-a", "provider": "claude", "home": self.home,
            "expected_email": "owner@example.test", "pinned_usage_org": "PIN",
        }]}
        registry.save(self.config)
        self.credentials = os.path.join(self.home, ".credentials.json")
        with open(self.credentials, "w") as handle:
            json.dump({"claudeAiOauth": {"accessToken": "old"}}, handle)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_refresh_relogs_owned_slot_without_changing_registry_or_pins(self):
        def login(_argv, env):
            self.assertTrue(os.path.samefile(
                env["CLAUDE_CONFIG_DIR"], self.home))
            self.assertNotIn("ANTHROPIC_API_KEY", env)
            with open(self.credentials, "w") as handle:
                json.dump({"claudeAiOauth": {"accessToken": "new"}}, handle)
            return type("Completed", (), {"returncode": 0})()

        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "override"}), \
                mock.patch.object(connect, "provider_binary", return_value="claude"), \
                mock.patch.object(connect.subprocess, "run", side_effect=login), \
                mock.patch.object(connect, "slot_identity", return_value={
                    "email": "owner@example.test", "account_fingerprint": "same-slot"}), \
                redirect_stdout(io.StringIO()) as output:
            code = __main__._dispatch(["auth", "refresh", "claude-a"])
        self.assertEqual(code, 0)
        self.assertIn("headroom collect", output.getvalue())
        with open(self.credentials) as handle:
            self.assertEqual(json.load(handle)["claudeAiOauth"]["accessToken"], "new")
        self.assertEqual(registry.load(), self.config)

    def test_refresh_expected_email_mismatch_restores_credentials(self):
        def login(_argv, env):
            with open(self.credentials, "w") as handle:
                json.dump({"claudeAiOauth": {"accessToken": "wrong"}}, handle)
            return type("Completed", (), {"returncode": 0})()

        errors = io.StringIO()
        with mock.patch.object(connect, "provider_binary", return_value="claude"), \
                mock.patch.object(connect.subprocess, "run", side_effect=login), \
                mock.patch.object(connect, "slot_identity", return_value={
                    "email": "other@example.test", "account_fingerprint": "other"}), \
                redirect_stderr(errors):
            code = connect.cmd_refresh(["claude-a"])
        self.assertEqual(code, 1)
        self.assertIn("expected email", errors.getvalue())
        with open(self.credentials) as handle:
            self.assertEqual(json.load(handle)["claudeAiOauth"]["accessToken"], "old")
        self.assertEqual(registry.load(), self.config)

    def test_refresh_refuses_keychain_backed_slot_before_login(self):
        os.remove(self.credentials)
        errors = io.StringIO()
        with mock.patch.object(connect.sys, "platform", "darwin"), \
                mock.patch.object(connect, "provider_binary") as binary, \
                mock.patch.object(connect.subprocess, "run") as run, \
                redirect_stderr(errors):
            code = connect.cmd_refresh(["claude-a"])
        self.assertEqual(code, 2)
        binary.assert_not_called()
        run.assert_not_called()
        self.assertIn("Keychain-backed Claude slot", errors.getvalue())
        self.assertIn("cannot safely roll back", errors.getvalue())

    def test_refresh_rejects_external_or_non_claude_slots(self):
        self.config["accounts"].append({
            "name": "codex-a", "provider": "codex", "home": "/tmp/codex-a"})
        self.config["accounts"].append({
            "name": "adopted", "provider": "claude", "home": "/tmp/adopted"})
        registry.save(self.config)
        errors = io.StringIO()
        with redirect_stderr(errors):
            self.assertEqual(connect.cmd_refresh(["codex-a"]), 2)
            self.assertEqual(connect.cmd_refresh(["adopted"]), 2)
            self.assertEqual(connect.cmd_refresh([]), 2)
        self.assertIn("only owned Claude", errors.getvalue())
        self.assertIn("adopted or external", errors.getvalue())


class RemoveCommand(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"HEADROOM_DIR": self.temp.name})
        self.env.start()
        self.home_a = os.path.join(self.temp.name, "home-a")
        self.home_b = os.path.join(self.temp.name, "home-b")
        os.makedirs(self.home_a)
        os.makedirs(self.home_b)
        self.credential = os.path.join(self.home_a, ".credentials.json")
        with open(self.credential, "w") as handle:
            json.dump({"claudeAiOauth": {"accessToken": "kept"}}, handle)
        registry.save({"schema_version": 1, "dashboard": {"title": "keep"},
                       "accounts": [
                           {"id": _slot_id("a"), "name": "a",
                            "provider": "claude", "home": self.home_a},
                           {"id": _slot_id("b"), "name": "b",
                            "provider": "claude", "home": self.home_b},
                       ]})

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def _write_state(self):
        private = {"schema_version": 1, "run_id": "fixture",
                   "generated": int(time.time()), "generated_iso": "fixture",
                   "accounts": [_claude_row("a"), _claude_row("b")],
                   "integrity_warnings": [
                       "duplicate claude identity: a and b are the same login; routing held",
                       "unrelated warning"]}
        public = collect.public_snapshot(private, redact_emails=True)
        paths.write_json_atomic(paths.private_snapshot_path(), private)
        paths.write_json_atomic(paths.public_snapshot_path(), public, mode=0o644)
        history.append_snapshot(public, now=int(time.time()))
        paths.write_json_atomic(paths.cooldowns_path(), {
            "a:*": 100, "a:sonnet": 200, "b:*": 300})
        paths.write_json_atomic(paths.quarantine_path(), {
            "a": {"reason": "rejected"}, "b": {"reason": "other"}})
        paths.write_json_atomic(paths.backoff_path(), {
            "schema_version": 1, "providers": {"anthropic_usage_api": {
                "retry_at": 500, "observed_at": 400}}})
        paths.write_json_atomic(paths.token_scan_state_path(), {
            "schema_version": tokens.SCHEMA_VERSION,
            "last_scan": int(time.time()),
            "files": {
                _slot_id("a"): {"projects/a.jsonl": {
                    "provider": "claude", "days": {}}},
                _slot_id("b"): {"projects/b.jsonl": {
                    "provider": "claude", "days": {}}},
            },
        })
        paths.write_json_atomic(paths.token_daily_path(), {
            "schema_version": tokens.SCHEMA_VERSION,
            "generated": int(time.time()), "partial": False,
            "failed_file_count": 0,
            "accounts": {
                _slot_id("a"): {"2026-07-15": {}},
                _slot_id("b"): {"2026-07-15": {}},
            },
        })

    def test_remove_preserves_home_and_non_target_state(self):
        self._write_state()
        with mock.patch.object(collect, "collection_lock",
                               wraps=collect.collection_lock) as locked, \
                mock.patch.object(sys.stdin, "isatty", return_value=False), \
                redirect_stdout(io.StringIO()):
            code = collect.cmd_remove(["a", "--yes"])
        self.assertEqual(code, 0)
        locked.assert_called_once_with()
        self.assertEqual([entry["name"] for entry in registry.load()["accounts"]],
                         ["b"])
        self.assertEqual(registry.load()["dashboard"], {"title": "keep"})
        self.assertTrue(os.path.isdir(self.home_a))
        self.assertTrue(os.path.exists(self.credential))
        self.assertEqual([row["name"] for row in
                          paths.load_json(paths.private_snapshot_path())["accounts"]],
                         ["b"])
        public = paths.load_json(paths.public_snapshot_path())
        self.assertEqual([row["name"] for row in public["accounts"]], ["b"])
        self.assertEqual(paths.load_json(paths.private_snapshot_path())["integrity_warnings"],
                         ["unrelated warning"])
        self.assertEqual(public["integrity_warnings"], ["unrelated warning"])
        history_rows = history.load_series(1, {_slot_id("b")})
        self.assertEqual(len(history_rows), 1)
        self.assertEqual([row["name"] for row in history_rows[0]["accounts"]],
                         ["b"])
        self.assertEqual(route.cooldowns(), {"b:*": 300})
        self.assertEqual(route.quarantines(), {"b": {"reason": "other"}})
        self.assertIn("anthropic_usage_api",
                      paths.load_json(paths.backoff_path())["providers"])
        token_state = paths.load_json(paths.token_scan_state_path())
        token_daily = paths.load_json(paths.token_daily_path())
        self.assertEqual(list(token_state["files"]), [_slot_id("b")])
        self.assertEqual(list(token_daily["accounts"]), [_slot_id("b")])

    def test_remove_rejects_noninteractive_without_yes_unknown_and_final(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=False), \
                redirect_stderr(io.StringIO()):
            self.assertEqual(collect.cmd_remove(["a"]), 2)
            self.assertEqual(collect.cmd_remove(["missing", "--yes"]), 2)
        self.assertEqual(len(registry.load()["accounts"]), 2)
        registry.save({"schema_version": 1, "accounts": [
            {"name": "a", "provider": "claude", "home": self.home_a}]})
        with mock.patch.object(sys.stdin, "isatty", return_value=False), \
                redirect_stderr(io.StringIO()):
            self.assertEqual(collect.cmd_remove(["a", "--yes"]), 2)
        self.assertEqual(len(registry.load()["accounts"]), 1)

    def test_history_hygiene_runs_after_registry_and_snapshots_commit(self):
        self._write_state()
        def assert_committed(slot_id, name):
            self.assertEqual(slot_id, _slot_id("a"))
            self.assertEqual(name, "a")
            self.assertEqual([entry["name"] for entry in
                              registry.load()["accounts"]], ["b"])
            for path in (paths.private_snapshot_path(),
                         paths.public_snapshot_path()):
                self.assertEqual([entry["name"] for entry in
                                  paths.load_json(path)["accounts"]], ["b"])

        with mock.patch.object(history, "remove_account",
                               side_effect=assert_committed) as purge:
            removed = collect.remove_slot("a")
        self.assertEqual(removed["name"], "a")
        purge.assert_called_once_with(_slot_id("a"), "a")

    def test_token_purge_takes_token_lock_and_runs_after_registry_commit(self):
        self._write_state()
        original = tokens.remove_account

        def assert_committed(slot_id):
            self.assertEqual(slot_id, _slot_id("a"))
            self.assertEqual([entry["name"] for entry in
                              registry.load()["accounts"]], ["b"])
            return original(slot_id)

        with mock.patch.object(tokens, "remove_account",
                               side_effect=assert_committed) as purge, \
                mock.patch.object(tokens, "scan_lock",
                                  wraps=tokens.scan_lock) as locked:
            removed = collect.remove_slot("a")
        self.assertEqual(removed["name"], "a")
        purge.assert_called_once_with(_slot_id("a"))
        locked.assert_called_once_with(blocking=True)

    def test_history_purge_failure_warns_but_removal_succeeds(self):
        self._write_state()
        history_file = paths.history_path()
        errors = io.StringIO()
        with mock.patch.object(
                history, "remove_account", side_effect=OSError("disk full")), \
                redirect_stderr(errors):
            removed = collect.remove_slot("a")
        message = errors.getvalue()
        self.assertEqual(removed["name"], "a")
        self.assertIn("the slot is removed", message)
        self.assertIn(history_file, message)
        self.assertIn("history purge", message)
        self.assertEqual(route.cooldowns(), {"b:*": 300})
        self.assertEqual(route.quarantines(), {"b": {"reason": "other"}})
        self.assertEqual([entry["name"] for entry in registry.load()["accounts"]],
                         ["b"])
        for path in (paths.private_snapshot_path(),
                     paths.public_snapshot_path()):
            self.assertEqual([entry["name"] for entry in
                              paths.load_json(path)["accounts"]], ["b"])

    def test_token_purge_failure_warns_but_removal_succeeds(self):
        self._write_state()
        errors = io.StringIO()
        with mock.patch.object(
                tokens, "remove_account", side_effect=OSError("disk full")), \
                redirect_stderr(errors):
            removed = collect.remove_slot("a")
        self.assertEqual(removed["name"], "a")
        self.assertIn("token purge", errors.getvalue())
        self.assertIn(paths.tokens_dir(), errors.getvalue())

    def test_removal_aggregates_history_and_route_cleanup_errors(self):
        self._write_state()
        with mock.patch.object(history, "remove_account",
                               side_effect=OSError("disk full")) as purge, \
                mock.patch.object(route, "remove_slot_state",
                                  side_effect=OSError("ledger locked")) as cleanup:
            with self.assertRaises(RuntimeError) as raised:
                collect.remove_slot("a")
        purge.assert_called_once_with(_slot_id("a"), "a")
        cleanup.assert_called_once_with("a")
        message = str(raised.exception)
        self.assertIn("history purge", message)
        self.assertIn("disk full", message)
        self.assertIn("route cleanup", message)
        self.assertIn("ledger locked", message)

    def test_snapshot_failure_still_attempts_route_cleanup(self):
        self._write_state()
        original_write = paths.write_json_atomic

        def fail_private(path, value, mode=0o600):
            if path == paths.private_snapshot_path():
                raise OSError("snapshot crash")
            return original_write(path, value, mode=mode)

        with mock.patch.object(paths, "write_json_atomic",
                               side_effect=fail_private), \
                mock.patch.object(route, "remove_slot_state",
                                  wraps=route.remove_slot_state) as cleanup, \
                self.assertRaisesRegex(
                    RuntimeError, "private snapshot cleanup.*snapshot crash"):
            collect.remove_slot("a")
        cleanup.assert_called_once_with("a")
        self.assertEqual([entry["name"] for entry in registry.load()["accounts"]],
                         ["b"])
        self.assertEqual(route.cooldowns(), {"b:*": 300})
        self.assertEqual(route.quarantines(), {"b": {"reason": "other"}})

    def test_registry_removal_without_purge_hides_dead_id_immediately(self):
        self._write_state()
        registry.remove_account("a")
        self.assertTrue(any(account["name"] == "a"
                            for value in history._read_rows(paths.history_path())
                            for account in value["accounts"]))
        served = history.load_series(1, {_slot_id("b")})
        self.assertEqual({account["name"] for value in served
                          for account in value["accounts"]}, {"b"})

    def test_same_name_add_clears_leftover_route_state(self):
        self._write_state()
        old_id = registry.remove_account("a")["id"]
        added = connect.add_account(
            registry.load(), "a", "claude", self.home_a, "a@example.test")
        self.assertRegex(added["id"], r"^[0-9a-f]{12,32}$")
        self.assertNotEqual(added["id"], old_id)
        self.assertEqual(route.cooldowns(), {"b:*": 300})
        self.assertEqual(route.quarantines(), {"b": {"reason": "other"}})


class DashboardRemovalOrdering(unittest.TestCase):
    def test_dashboard_cannot_republish_snapshot_after_remove(self):
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.dict(os.environ, {"HEADROOM_DIR": root}):
            home_a = os.path.join(root, "home-a")
            home_b = os.path.join(root, "home-b")
            registry.save({"schema_version": 1, "accounts": [
                {"name": "a", "provider": "claude", "home": home_a},
                {"name": "b", "provider": "claude", "home": home_b},
            ]})
            private = {
                "schema_version": 1,
                "run_id": "fixture",
                "generated": int(time.time()),
                "generated_iso": "fixture",
                "accounts": [_claude_row("a"), _claude_row("b")],
                "integrity_warnings": [],
            }
            paths.write_json_atomic(paths.private_snapshot_path(), private)
            paths.write_json_atomic(
                paths.public_snapshot_path(),
                collect.public_snapshot(private, redact_emails=True), mode=0o644)

            loaded = threading.Event()
            release_dashboard = threading.Event()
            removed = threading.Event()
            dashboard_result = []
            remove_result = []
            original_load = paths.load_json
            original_remove = registry.remove_account

            def delayed_load(path):
                if path == paths.private_snapshot_path():
                    loaded.set()
                    self.assertTrue(release_dashboard.wait(2))
                return original_load(path)

            def marked_remove(name):
                removed.set()
                return original_remove(name)

            with mock.patch.object(paths, "load_json", side_effect=delayed_load), \
                    mock.patch.object(dashboard, "build"), \
                    mock.patch.object(registry, "remove_account",
                                      side_effect=marked_remove):
                dashboard_thread = threading.Thread(
                    target=lambda: dashboard_result.append(
                        __main__._dispatch(["dashboard"])))
                dashboard_thread.start()
                self.assertTrue(loaded.wait(2))
                remove_thread = threading.Thread(
                    target=lambda: remove_result.append(collect.remove_slot("a")))
                remove_thread.start()
                self.assertFalse(removed.wait(0.1))
                release_dashboard.set()
                dashboard_thread.join(2)
                remove_thread.join(2)

            self.assertFalse(dashboard_thread.is_alive())
            self.assertFalse(remove_thread.is_alive())
            self.assertEqual(dashboard_result, [0])
            self.assertEqual(remove_result[0]["name"], "a")
            self.assertTrue(removed.is_set())
            public = paths.load_json(paths.public_snapshot_path())
            self.assertEqual([row["name"] for row in public["accounts"]], ["b"])


class ActionableClaudeRefresh(unittest.TestCase):
    def test_expired_claude_token_recommends_manual_refresh(self):
        account = _account("a")
        identity = {"verified": True, "email": "a@example.test",
                    "account_fingerprint": "FP", "method": "local"}
        with mock.patch.object(collect, "claude_identity", return_value=identity), \
                mock.patch.object(collect, "credential_digest", return_value="digest"), \
                mock.patch.object(collect, "claude_plan", return_value="Max"), \
                mock.patch.object(collect, "claude_limits", side_effect=
                                  collect.IdentityBindingError(
                                      "claude_usage_token_expired")):
            row = collect.collect([account])["accounts"][0]
        self.assertEqual(row["error_code"], "claude_usage_token_expired")
        self.assertIn("headroom auth refresh a", row["note"])
        self.assertNotIn("headroom connect a", row["note"])


# =========================================================================
# Grok (xAI SuperGrok / X Premium+) provider
# =========================================================================

# Real HTTP response bodies captured live (2026-07-18) from
# GrokBuildBilling/GetGrokCreditsConfig — gRPC-web framed. Both must parse to
# resets_at 1784839764; used_percent 0.0 (percent field omitted, a proto3 zero)
# and 1.0 respectively. Embedding the raw wire proves the parser end-to-end.
_GROK_ZERO_FIXTURE = bytes.fromhex(
    "00000000480a4612001a00220c08d487e5d20610b0bbe8cf012a0c08d4fc89d3"
    "0610b0bbe8cf01421e0802120c08d487e5d20610b0bbe8cf011a0c08d4fc89d3"
    "0610b0bbe8cf01580162006801800000000f677270632d7374617475733a300d0a")
_GROK_ONE_FIXTURE = bytes.fromhex(
    "000000005a0a580d0000803f12001a00220c08d487e5d20610b0bbe8cf012a0c"
    "08d4fc89d30610b0bbe8cf013a070802150000803f3a020804421e0802120c08"
    "d487e5d20610b0bbe8cf011a0c08d4fc89d30610b0bbe8cf0158016200680180"
    "0000000f677270632d7374617475733a300d0a")

_GROK_AUTH = {
    "key": "grok-bearer", "refresh_token": "r",
    "expires_at": "2999-01-01T00:00:00.000000Z",
    "email": "me@x.ai", "user_id": "u-1", "team_id": "t-1",
    "auth_mode": "oidc",
}
_GROK_SCOPE = "https://auth.x.ai::client-uuid"


class _GrokResp:
    """Minimal context-manager HTTP response for a fake opener."""

    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        return self._body if size is None or size < 0 else self._body[:size]


def _grok_opener(body):
    return lambda request, timeout: _GrokResp(body)


def _grok_http_error(code):
    import urllib.error
    return urllib.error.HTTPError(collect.GROK_USAGE_URL, code, "denied", {},
                                  None)


def _grok_frame(flag, payload):
    return bytes([flag]) + len(payload).to_bytes(4, "big") + payload


def _grok_response(payload, status=0):
    """Build a gRPC-web body: optional data frame + a grpc-status trailer."""
    body = b""
    if payload is not None:
        body += _grok_frame(0x00, payload)
    body += _grok_frame(0x80, ("grpc-status:%d\r\n" % status).encode("ascii"))
    return body


class GrokAuth(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = self.temp.name

    def _write(self, credential):
        with open(os.path.join(self.home, "auth.json"), "w") as handle:
            json.dump({"https://auth.x.ai::client-uuid": credential}, handle)

    def test_refresh_owned_home_rotates_tokens_and_preserves_identity(self):
        headroom = os.path.join(self.home, "headroom")
        owned = os.path.join(headroom, "homes", "g")
        os.makedirs(owned)
        credential = dict(
            _GROK_AUTH,
            principal_type="user", principal_id="principal-1",
            expires_at="2000-01-01T00:00:00.000000Z")
        third_party = dict(
            credential, key="enterprise-bearer",
            oidc_issuer="https://login.example.com")
        with open(os.path.join(owned, "auth.json"), "w") as handle:
            json.dump({
                "https://login.example.com::enterprise-client": third_party,
                _GROK_SCOPE: credential,
            }, handle)
        opener = mock.Mock(return_value=_GrokResp(json.dumps({
            "access_token": "new-bearer",
            "refresh_token": "new-refresh",
            "expires_in": 21600,
        }).encode()))

        with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}):
            self.assertTrue(collect.grok_refresh_token(
                owned, "g", collect.fingerprint("u-1:t-1"), opener=opener,
                now=1_700_000_000))

        refreshed = collect.grok_auth(owned)
        self.assertEqual(refreshed["key"], "new-bearer")
        self.assertEqual(refreshed["refresh_token"], "new-refresh")
        self.assertEqual(refreshed["email"], "me@x.ai")
        self.assertEqual(collect.grok_expires_at(refreshed), 1_700_021_600)
        with open(os.path.join(owned, "auth.json")) as handle:
            written = json.load(handle)
        self.assertEqual(
            written["https://login.example.com::enterprise-client"],
            third_party)
        request = opener.call_args.args[0]
        self.assertEqual(request.full_url, collect.GROK_TOKEN_URL)
        self.assertEqual(
            urllib.parse.parse_qs(request.data.decode()),
            {"grant_type": ["refresh_token"], "refresh_token": ["r"],
             "client_id": ["client-uuid"], "principal_type": ["user"],
             "principal_id": ["principal-1"]})

    def test_refresh_refuses_adopted_home_without_network_or_write(self):
        credential = dict(
            _GROK_AUTH, oidc_client_id="client-uuid",
            expires_at="2000-01-01T00:00:00.000000Z")
        self._write(credential)
        auth_path = os.path.join(self.home, "auth.json")
        with open(auth_path, "rb") as handle:
            before = handle.read()
        opener = mock.Mock(side_effect=AssertionError("network must not run"))

        with mock.patch.dict(os.environ, {
                "HEADROOM_DIR": os.path.join(self.home, "headroom")}):
            self.assertFalse(collect.grok_refresh_token(
                self.home, "g", collect.fingerprint("u-1:t-1"), opener=opener,
                now=1_700_000_000))

        opener.assert_not_called()
        with open(auth_path, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_owned_home_accepts_canonical_path_under_symlinked_root(self):
        real_headroom = os.path.join(self.home, "real-headroom")
        linked_headroom = os.path.join(self.home, "linked-headroom")
        owned = os.path.join(real_headroom, "homes", "g")
        os.makedirs(owned)
        os.symlink(real_headroom, linked_headroom)

        with mock.patch.dict(os.environ, {"HEADROOM_DIR": linked_headroom}):
            self.assertTrue(collect._grok_owned_home(
                os.path.realpath(owned), "g"))

    def test_owned_home_rejects_slot_symlink_to_adopted_home(self):
        headroom = os.path.join(self.home, "headroom")
        homes = os.path.join(headroom, "homes")
        adopted = os.path.join(self.home, "adopted")
        os.makedirs(homes)
        os.makedirs(adopted)
        linked_slot = os.path.join(homes, "g")
        os.symlink(adopted, linked_slot)

        with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}):
            self.assertFalse(collect._grok_owned_home(linked_slot, "g"))

    def test_owned_home_rejects_other_direct_child_adopted_by_slot(self):
        headroom = os.path.join(self.home, "headroom")
        adopted = os.path.join(headroom, "homes", "external-login")
        os.makedirs(adopted)

        with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}):
            self.assertFalse(collect._grok_owned_home(adopted, "g"))

    def test_refresh_refuses_auth_symlink_to_adopted_credential(self):
        headroom = os.path.join(self.home, "headroom")
        owned = os.path.join(headroom, "homes", "g")
        adopted = os.path.join(self.home, "adopted")
        os.makedirs(owned)
        os.makedirs(adopted)
        adopted_auth = os.path.join(adopted, "auth.json")
        credential = dict(
            _GROK_AUTH, oidc_client_id="client-uuid",
            expires_at="2000-01-01T00:00:00.000000Z")
        with open(adopted_auth, "w") as handle:
            json.dump({_GROK_SCOPE: credential}, handle)
        with open(adopted_auth, "rb") as handle:
            before = handle.read()
        os.symlink(adopted_auth, os.path.join(owned, "auth.json"))
        opener = mock.Mock(side_effect=AssertionError("network must not run"))

        with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}):
            self.assertFalse(collect.grok_refresh_token(
                owned, "g", collect.fingerprint("u-1:t-1"), opener=opener,
                now=1_700_000_000))

        opener.assert_not_called()
        with open(adopted_auth, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_refresh_refuses_hard_linked_adopted_credential(self):
        headroom = os.path.join(self.home, "headroom")
        owned = os.path.join(headroom, "homes", "g")
        adopted = os.path.join(self.home, "adopted")
        os.makedirs(owned)
        os.makedirs(adopted)
        adopted_auth = os.path.join(adopted, "auth.json")
        credential = dict(
            _GROK_AUTH, oidc_client_id="client-uuid",
            expires_at="2000-01-01T00:00:00.000000Z")
        with open(adopted_auth, "w") as handle:
            json.dump({_GROK_SCOPE: credential}, handle)
        with open(adopted_auth, "rb") as handle:
            before = handle.read()
        os.link(adopted_auth, os.path.join(owned, "auth.json"))
        opener = mock.Mock(side_effect=AssertionError("network must not run"))

        with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}):
            self.assertFalse(collect.grok_refresh_token(
                owned, "g", collect.fingerprint("u-1:t-1"), opener=opener,
                now=1_700_000_000))

        opener.assert_not_called()
        with open(adopted_auth, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_refresh_refuses_identity_changed_before_locked_read(self):
        headroom = os.path.join(self.home, "headroom")
        owned = os.path.join(headroom, "homes", "g")
        os.makedirs(owned)
        changed = dict(
            _GROK_AUTH, user_id="u-2", oidc_client_id="client-uuid",
            expires_at="2000-01-01T00:00:00.000000Z")
        with open(os.path.join(owned, "auth.json"), "w") as handle:
            json.dump({_GROK_SCOPE: changed}, handle)
        opener = mock.Mock(side_effect=AssertionError("network must not run"))

        with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}):
            self.assertFalse(collect.grok_refresh_token(
                owned, "g", collect.fingerprint("u-1:t-1"), opener=opener,
                now=1_700_000_000))

        opener.assert_not_called()

    def test_refresh_refuses_non_xai_oidc_issuer(self):
        headroom = os.path.join(self.home, "headroom")
        owned = os.path.join(headroom, "homes", "g")
        os.makedirs(owned)
        credential = dict(
            _GROK_AUTH, oidc_client_id="enterprise-client",
            oidc_issuer="https://login.example.com",
            expires_at="2000-01-01T00:00:00.000000Z")
        with open(os.path.join(owned, "auth.json"), "w") as handle:
            json.dump({"https://login.example.com::enterprise-client":
                       credential}, handle)
        opener = mock.Mock(side_effect=AssertionError("network must not run"))

        with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}):
            self.assertFalse(collect.grok_refresh_token(
                owned, "g", collect.fingerprint("u-1:t-1"), opener=opener,
                now=1_700_000_000))

        opener.assert_not_called()

    def test_refresh_busy_auth_lock_fails_without_network(self):
        headroom = os.path.join(self.home, "headroom")
        owned = os.path.join(headroom, "homes", "g")
        os.makedirs(owned)
        credential = dict(
            _GROK_AUTH, oidc_client_id="client-uuid",
            expires_at="2000-01-01T00:00:00.000000Z")
        with open(os.path.join(owned, "auth.json"), "w") as handle:
            json.dump({_GROK_SCOPE: credential}, handle)
        lock_context = mock.MagicMock()
        lock_context.__enter__.return_value = False
        opener = mock.Mock(side_effect=AssertionError("network must not run"))

        with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}), \
                mock.patch.object(collect.locks, "exclusive_lock",
                                  return_value=lock_context):
            self.assertFalse(collect.grok_refresh_token(
                owned, "g", collect.fingerprint("u-1:t-1"), opener=opener,
                now=1_700_000_000))

        opener.assert_not_called()

    def test_refresh_malformed_response_fails_without_overwrite(self):
        headroom = os.path.join(self.home, "headroom")
        owned = os.path.join(headroom, "homes", "g")
        os.makedirs(owned)
        credential = dict(
            _GROK_AUTH, oidc_client_id="client-uuid",
            expires_at="2000-01-01T00:00:00.000000Z")
        auth_path = os.path.join(owned, "auth.json")
        with open(auth_path, "w") as handle:
            json.dump({_GROK_SCOPE: credential}, handle)
        with open(auth_path, "rb") as handle:
            before = handle.read()

        with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}):
            self.assertFalse(collect.grok_refresh_token(
                owned, "g", collect.fingerprint("u-1:t-1"),
                opener=mock.Mock(return_value=_GrokResp(b"[]")),
                now=1_700_000_000))

        with open(auth_path, "rb") as handle:
            self.assertEqual(handle.read(), before)

    def test_refresh_uses_access_token_exp_when_expires_in_is_absent(self):
        headroom = os.path.join(self.home, "headroom")
        owned = os.path.join(headroom, "homes", "g")
        os.makedirs(owned)
        credential = dict(
            _GROK_AUTH, oidc_client_id="client-uuid",
            expires_at="2000-01-01T00:00:00.000000Z")
        with open(os.path.join(owned, "auth.json"), "w") as handle:
            json.dump({_GROK_SCOPE: credential}, handle)
        payload = base64.urlsafe_b64encode(json.dumps({
            "exp": 1_700_021_600,
        }).encode()).rstrip(b"=").decode()
        bearer = f"header.{payload}.signature"
        opener = mock.Mock(return_value=_GrokResp(json.dumps({
            "access_token": bearer,
        }).encode()))

        with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}):
            self.assertTrue(collect.grok_refresh_token(
                owned, "g", collect.fingerprint("u-1:t-1"), opener=opener,
                now=1_700_000_000))

        self.assertEqual(
            collect.grok_expires_at(collect.grok_auth(owned)), 1_700_021_600)

    def test_reads_first_scope_value(self):
        self._write(dict(_GROK_AUTH))
        auth = collect.grok_auth(self.home)
        self.assertEqual(auth["key"], "grok-bearer")
        self.assertEqual(auth["email"], "me@x.ai")

    def test_reads_only_xai_oidc_scope(self):
        third_party = dict(_GROK_AUTH, key="enterprise-bearer")
        xai = dict(_GROK_AUTH)
        with open(os.path.join(self.home, "auth.json"), "w") as handle:
            json.dump({
                "https://login.example.com::enterprise-client": third_party,
                _GROK_SCOPE: xai,
            }, handle)
        self.assertEqual(collect.grok_auth(self.home)["key"], "grok-bearer")

        with open(os.path.join(self.home, "auth.json"), "w") as handle:
            json.dump({
                "https://login.example.com::enterprise-client": third_party,
            }, handle)
        self.assertIsNone(collect.grok_auth(self.home))

    def test_missing_file_is_none(self):
        self.assertIsNone(collect.grok_auth(self.home))

    def test_expires_at_parses_microseconds_z(self):
        got = collect.grok_expires_at(
            {"expires_at": "2026-07-18T11:15:41.558875Z"})
        self.assertIsNotNone(got)
        from datetime import datetime, timezone
        self.assertEqual(int(got), int(datetime(
            2026, 7, 18, 11, 15, 41, tzinfo=timezone.utc).timestamp()))

    def test_expires_at_malformed_or_absent_is_none(self):
        self.assertIsNone(collect.grok_expires_at({"expires_at": "nope"}))
        self.assertIsNone(collect.grok_expires_at({}))
        self.assertIsNone(collect.grok_expires_at({"expires_at": 123}))


class GrokIdentity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = self.temp.name

    def _write(self, **fields):
        credential = dict(_GROK_AUTH)
        credential.update(fields)
        credential = {k: v for k, v in credential.items() if v is not None}
        with open(os.path.join(self.home, "auth.json"), "w") as handle:
            json.dump({"https://auth.x.ai::client-uuid": credential}, handle)

    def test_local_metadata_identity(self):
        self._write()
        identity = collect.grok_identity(self.home)
        self.assertFalse(identity["verified"])
        self.assertEqual(identity["email"], "me@x.ai")
        self.assertEqual(identity["method"], "grok_local_metadata")

    def test_fingerprint_is_seat_composite_with_team(self):
        self._write()
        identity = collect.grok_identity(self.home)
        self.assertEqual(identity["account_fingerprint"],
                         collect.fingerprint("u-1:t-1"))

    def test_fingerprint_falls_back_to_user_without_team(self):
        self._write(team_id=None)
        identity = collect.grok_identity(self.home)
        self.assertEqual(identity["account_fingerprint"],
                         collect.fingerprint("u-1"))
        # the composite (contains ":") and the bare UUID form never collide
        self.assertNotEqual(identity["account_fingerprint"],
                            collect.fingerprint("u-1:t-1"))

    def test_missing_auth_holds(self):
        with self.assertRaises(collect.IdentityBindingError) as caught:
            collect.grok_identity(self.home)  # empty dir, no auth.json
        self.assertEqual(caught.exception.code, "grok_local_binding_missing")

    def test_missing_user_id_holds(self):
        self._write(user_id=None)
        with self.assertRaises(collect.IdentityBindingError) as caught:
            collect.grok_identity(self.home)
        self.assertEqual(caught.exception.code, "grok_local_binding_missing")


class GrokLimits(unittest.TestCase):
    def _auth(self, **over):
        return mock.patch.object(collect, "grok_auth",
                                 return_value=dict(_GROK_AUTH, **over))

    def test_zero_fixture_parses_to_zero_percent(self):
        with self._auth():
            result = collect.grok_limits(
                "/h", opener=_grok_opener(_GROK_ZERO_FIXTURE),
                now=1_700_000_000)
        windows = result["windows"]
        self.assertEqual(set(windows), {"7d"})  # no 5h fabricated
        self.assertEqual(windows["7d"]["used_percent"], 0.0)
        self.assertEqual(windows["7d"]["resets_at"], 1784839764)
        self.assertEqual(windows["7d"]["window_minutes"], 10080)
        self.assertEqual(result["source"], "grok_build_billing")

    def test_one_percent_fixture_parses(self):
        with self._auth():
            result = collect.grok_limits(
                "/h", opener=_grok_opener(_GROK_ONE_FIXTURE), now=1_700_000_000)
        self.assertEqual(result["windows"]["7d"]["used_percent"], 1.0)
        self.assertEqual(result["windows"]["7d"]["resets_at"], 1784839764)

    def test_expired_token_holds_without_network(self):
        opener = mock.Mock(side_effect=AssertionError("probe must not run"))
        with mock.patch.object(collect, "grok_auth", return_value={
                "key": "tok", "expires_at": "2000-01-01T00:00:00.000000Z"}):
            with self.assertRaises(collect.IdentityBindingError) as caught:
                collect.grok_limits("/h", opener=opener)
        self.assertEqual(caught.exception.code, "grok_token_expired")
        opener.assert_not_called()

    def test_absent_expiry_treated_expired_without_network(self):
        opener = mock.Mock(side_effect=AssertionError("probe must not run"))
        with mock.patch.object(collect, "grok_auth",
                               return_value={"key": "tok"}):
            with self.assertRaises(collect.IdentityBindingError) as caught:
                collect.grok_limits("/h", opener=opener)
        self.assertEqual(caught.exception.code, "grok_token_expired")
        opener.assert_not_called()

    def test_missing_key_holds_as_binding_missing(self):
        opener = mock.Mock(side_effect=AssertionError("probe must not run"))
        with mock.patch.object(collect, "grok_auth", return_value={}):
            with self.assertRaises(collect.IdentityBindingError) as caught:
                collect.grok_limits("/h", opener=opener)
        self.assertEqual(caught.exception.code, "grok_local_binding_missing")
        opener.assert_not_called()

    def test_http_401_403_hold_as_rejected(self):
        for code in (401, 403):
            with self._auth():
                with self.assertRaises(collect.IdentityBindingError) as caught:
                    collect.grok_limits("/h", opener=mock.Mock(
                        side_effect=_grok_http_error(code)))
            self.assertEqual(caught.exception.code, "grok_usage_rejected")

    def test_nonzero_grpc_status_holds_as_rejected(self):
        body = _grok_response(bytes([0x0a, 0x00]), status=5)
        with self._auth():
            with self.assertRaises(collect.IdentityBindingError) as caught:
                collect.grok_limits("/h", opener=_grok_opener(body))
        self.assertEqual(caught.exception.code, "grok_usage_rejected")

    def test_missing_weekly_holds(self):
        # grpc-status 0, but the GrokCreditsConfig carries no period
        body = _grok_response(bytes([0x0a, 0x00]), status=0)
        with self._auth():
            with self.assertRaises(collect.IdentityBindingError) as caught:
                collect.grok_limits("/h", opener=_grok_opener(body))
        self.assertEqual(caught.exception.code, "grok_missing_weekly")

    def test_invalid_raw_usage_percent_holds_before_rounding(self):
        body = _grok_response(b"payload", status=0)
        for percent in (-0.04, 100.01, float("nan"), float("inf")):
            with self.subTest(percent=percent), self._auth(), \
                    mock.patch.object(
                        collect, "_grok_parse_credits",
                        return_value=(percent, 1_784_839_764)):
                with self.assertRaises(
                        collect.IdentityBindingError) as caught:
                    collect.grok_limits("/h", opener=_grok_opener(body))
                self.assertEqual(caught.exception.code, "grok_missing_weekly")

    def test_oversized_response_holds(self):
        # an abnormal/hostile response over the cap is held, never read unbounded
        big = b"x" * (collect.GROK_MAX_RESPONSE_BYTES + 100)
        with self._auth():
            with self.assertRaises(collect.IdentityBindingError) as caught:
                collect.grok_limits("/h", opener=_grok_opener(big))
        self.assertEqual(caught.exception.code, "grok_missing_weekly")

    def test_trailing_bytes_after_frames_hold(self):
        # leftover bytes past the trailer = malformed response → fail closed
        body = _grok_response(bytes([0x0a, 0x00]), status=0) + b"\x99\x99"
        with self._auth():
            with self.assertRaises(collect.IdentityBindingError) as caught:
                collect.grok_limits("/h", opener=_grok_opener(body))
        self.assertEqual(caught.exception.code, "grok_missing_weekly")


class GrokCollect(unittest.TestCase):
    """The collect() grok branch: healthy read, expected-email binding, and an
    actionable hold note — all without spending a token."""

    def _identity(self, email="me@x.ai"):
        return {"verified": False, "email": email,
                "account_fingerprint": collect.fingerprint("u-1:t-1"),
                "method": "grok_local_metadata", "plan_type": None}

    def _windows(self):
        now = 1_700_000_000
        return {"captured_at": now, "source": "grok_build_billing",
                "stale": False,
                "windows": {"7d": {"used_percent": 12.0, "resets_at": 1784839764,
                                   "window_minutes": 10080, "observed_at": now,
                                   "freshness": "fresh"}}}

    def test_expired_owned_token_refreshes_before_snapshot_binding(self):
        with tempfile.TemporaryDirectory() as headroom:
            home = os.path.join(headroom, "homes", "g")
            os.makedirs(home)
            auth_path = os.path.join(home, "auth.json")
            expired = dict(
                _GROK_AUTH, oidc_client_id="client-uuid",
                expires_at="2000-01-01T00:00:00.000000Z")
            with open(auth_path, "w") as handle:
                json.dump({_GROK_SCOPE: expired}, handle)
            account = _account("g", "grok")
            account["home"] = home

            def refresh(_home, _slot_name, _fingerprint, now=None):
                fresh = dict(expired, key="new-bearer",
                             expires_at="2999-01-01T00:00:00.000000Z")
                with open(auth_path, "w") as handle:
                    json.dump({_GROK_SCOPE: fresh}, handle)
                return True

            with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}), \
                    mock.patch.object(collect, "grok_refresh_token",
                                      side_effect=refresh) as refresh_mock, \
                    mock.patch.object(collect, "grok_limits",
                                      return_value=self._windows()):
                row = collect.collect([account])["accounts"][0]

        refresh_mock.assert_called_once_with(
            home, "g", collect.fingerprint("u-1:t-1"), now=mock.ANY)
        self.assertTrue(row["ok"])
        self.assertEqual(
            row["identity"]["credential_digest"],
            hashlib.sha256(b"new-bearer").hexdigest()[:16])

    def test_failed_refresh_rebinds_identity_before_usage(self):
        """A concurrent re-login can swap the seat while refresh fails closed.

        ``grok_refresh_token`` returns False on fingerprint mismatch. The
        collector must still re-read identity before ``grok_limits`` so the
        new bearer's usage is never published under the preflight seat —
        Grok billing has no identity header to catch the swap.
        """
        with tempfile.TemporaryDirectory() as headroom:
            home = os.path.join(headroom, "homes", "g")
            os.makedirs(home)
            auth_path = os.path.join(home, "auth.json")
            preflight = dict(
                _GROK_AUTH, email="a@x.ai", user_id="u-a",
                oidc_client_id="client-uuid", key="a-old",
                expires_at="2000-01-01T00:00:00.000000Z")
            swapped = dict(
                _GROK_AUTH, email="b@x.ai", user_id="u-b",
                oidc_client_id="client-uuid", key="b-new",
                expires_at="2999-01-01T00:00:00.000000Z")
            with open(auth_path, "w") as handle:
                json.dump({_GROK_SCOPE: preflight}, handle)
            account = _account("g", "grok")
            account["home"] = home

            def refresh(_home, _slot_name, _fingerprint, now=None):
                with open(auth_path, "w") as handle:
                    json.dump({_GROK_SCOPE: swapped}, handle)
                return False  # fingerprint mismatch under the lock

            with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}), \
                    mock.patch.object(collect, "grok_refresh_token",
                                      side_effect=refresh) as refresh_mock, \
                    mock.patch.object(collect, "grok_limits",
                                      return_value=self._windows()):
                row = collect.collect([account])["accounts"][0]

        refresh_mock.assert_called_once_with(
            home, "g", collect.fingerprint("u-a:t-1"), now=mock.ANY)
        self.assertTrue(row["ok"])
        self.assertEqual(row["email"], "b@x.ai")
        self.assertEqual(
            row["identity"]["account_fingerprint"],
            collect.fingerprint("u-b:t-1"))
        self.assertEqual(
            row["identity"]["credential_digest"],
            hashlib.sha256(b"b-new").hexdigest()[:16])

    def test_failed_refresh_identity_swap_respects_expected_email(self):
        """Same race as above, with expected_email: hold on the post-swap seat."""
        with tempfile.TemporaryDirectory() as headroom:
            home = os.path.join(headroom, "homes", "g")
            os.makedirs(home)
            auth_path = os.path.join(home, "auth.json")
            preflight = dict(
                _GROK_AUTH, email="a@x.ai", user_id="u-a",
                oidc_client_id="client-uuid", key="a-old",
                expires_at="2000-01-01T00:00:00.000000Z")
            swapped = dict(
                _GROK_AUTH, email="b@x.ai", user_id="u-b",
                oidc_client_id="client-uuid", key="b-new",
                expires_at="2999-01-01T00:00:00.000000Z")
            with open(auth_path, "w") as handle:
                json.dump({_GROK_SCOPE: preflight}, handle)
            account = _account("g", "grok")
            account["home"] = home
            account["expected_email"] = "a@x.ai"

            def refresh(_home, _slot_name, _fingerprint, now=None):
                with open(auth_path, "w") as handle:
                    json.dump({_GROK_SCOPE: swapped}, handle)
                return False

            with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}), \
                    mock.patch.object(collect, "grok_refresh_token",
                                      side_effect=refresh), \
                    mock.patch.object(collect, "grok_limits") as limits_mock:
                row = collect.collect([account])["accounts"][0]

        limits_mock.assert_not_called()
        self.assertFalse(row["ok"])
        self.assertEqual(row["error_code"], "slot_bound_to_unexpected_email")
        self.assertEqual(row["email"], "b@x.ai")

    def test_unexpected_owned_identity_holds_before_refresh(self):
        with tempfile.TemporaryDirectory() as headroom:
            home = os.path.join(headroom, "homes", "g")
            os.makedirs(home)
            expired = dict(
                _GROK_AUTH, oidc_client_id="client-uuid",
                expires_at="2000-01-01T00:00:00.000000Z")
            with open(os.path.join(home, "auth.json"), "w") as handle:
                json.dump({_GROK_SCOPE: expired}, handle)
            account = _account("g", "grok")
            account["home"] = home
            account["expected_email"] = "someone-else@x.ai"

            with mock.patch.dict(os.environ, {"HEADROOM_DIR": headroom}), \
                    mock.patch.object(collect, "grok_refresh_token") \
                    as refresh_mock:
                row = collect.collect([account])["accounts"][0]

        refresh_mock.assert_not_called()
        self.assertFalse(row["ok"])
        self.assertEqual(row["error_code"], "slot_bound_to_unexpected_email")
        self.assertEqual(row["email"], "me@x.ai")
        self.assertEqual(row["identity_method"], "grok_local_metadata")

    def test_healthy_grok_account_reports_weekly_only(self):
        account = _account("g", "grok")
        with mock.patch.object(collect, "grok_identity",
                               return_value=self._identity()), \
                mock.patch.object(collect, "credential_digest",
                                  return_value="digest"), \
                mock.patch.object(collect, "grok_limits",
                                  return_value=self._windows()):
            row = collect.collect([account])["accounts"][0]
        self.assertTrue(row["ok"])
        self.assertEqual(row["provider"], "grok")
        self.assertEqual(row["plan"], "Grok")
        self.assertEqual(set(row["windows"]), {"7d"})  # no fabricated 5h
        self.assertEqual(row["windows"]["7d"]["used_percent"], 12.0)

    def test_expected_email_mismatch_holds(self):
        account = _account("g", "grok")
        account["expected_email"] = "someone-else@x.ai"
        with mock.patch.object(collect, "grok_identity",
                               return_value=self._identity("me@x.ai")), \
                mock.patch.object(collect, "credential_digest",
                                  return_value="digest"), \
                mock.patch.object(collect, "grok_limits",
                                  side_effect=AssertionError("must not read")):
            row = collect.collect([account])["accounts"][0]
        self.assertFalse(row["ok"])
        self.assertEqual(row["error_code"], "slot_bound_to_unexpected_email")

    def test_token_expired_hold_note_is_actionable(self):
        account = _account("g", "grok")
        with mock.patch.object(collect, "grok_identity",
                               return_value=self._identity()), \
                mock.patch.object(collect, "credential_digest",
                                  return_value="digest"), \
                mock.patch.object(collect, "grok_limits", side_effect=
                                  collect.IdentityBindingError(
                                      "grok_token_expired")):
            row = collect.collect([account])["accounts"][0]
        self.assertEqual(row["error_code"], "grok_token_expired")
        self.assertIn("grok", row["note"].lower())


class GrokWidgetProjection(unittest.TestCase):
    """The widget projection omits an absent 5h for grok (a no-5h provider)
    without fabricating a phantom held 5h row."""

    def test_projection_has_no_five_hour(self):
        from headroom import widget
        now = 1_700_000_000
        snapshot = {"generated": now, "accounts": [{
            "name": "g", "provider": "grok", "ok": True, "routable": True,
            "trust_state": "verified_local", "stale": False,
            "captured_at": now, "identity_verified": False,
            "windows": {"7d": {"used_percent": 20.0,
                               "resets_at": now + 7 * 86400,
                               "window_minutes": 10080, "observed_at": now,
                               "freshness": "fresh"}}}]}
        projected = widget.project(snapshot, evaluated_at=now + 10)
        account = projected["accounts"][0]
        self.assertEqual(account["provider"], "grok")
        self.assertNotIn("5h", account["windows"])
        self.assertIn("7d", account["windows"])
        self.assertEqual(account["state"], "current")


class RegistryGrokSeats(unittest.TestCase):
    def fleet(self):
        return {"schema_version": 1, "accounts": [
            {"name": "grok", "provider": "grok", "home": "~/.grok",
             "expected_email": "me@x.ai"},
        ]}

    def test_grok_seat_validates(self):
        config = self.fleet()
        self.assertEqual(registry.validate(config), config)

    def test_grok_is_a_recognized_family(self):
        self.assertEqual(registry.family("grok"), "grok")
        self.assertEqual(registry.family_provider("grok"), "grok")

    def test_grok_excluded_from_token_scanning(self):
        # grok has no local per-session token logs; it must not be fed to the
        # token scanner (which would treat it as codex and mark the feed partial)
        config = {"schema_version": 1, "accounts": [
            {"name": "c", "provider": "claude", "home": "~/.claude"},
            {"name": "x", "provider": "codex", "home": "~/.codex"},
            {"name": "g", "provider": "grok", "home": "~/.grok"},
        ]}
        providers = {account["provider"]
                     for account in registry.token_accounts(config)}
        self.assertEqual(providers, {"claude", "codex"})


class GrokRouting(unittest.TestCase):
    """A healthy grok seat reports only a 7d window (no 5h). The router must
    treat grok as a no-5h provider (like codex — see registry.NO_5H_PROVIDERS)
    and route it, not reject the row as '5h window missing'."""

    def setUp(self):
        self.now = time.time()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # isolate reserve_percent() from the real ~/.headroom config
        self.env = mock.patch.dict(os.environ, {"HEADROOM_DIR": self.temp.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        # the router re-derives the slot's live identity+credential; return the
        # fixture's bound values so the binding matches
        self.binding = mock.patch.object(
            collect, "local_binding", return_value=("AAAA", "BBBB"))
        self.binding.start()
        self.addCleanup(self.binding.stop)

    def _row(self, **over):
        row = {
            "name": "g", "provider": "grok", "plan": "Grok", "ok": True,
            "stale": False, "routable": True, "identity_verified": False,
            "identity": {"account_fingerprint": "AAAA",
                         "credential_digest": "BBBB"},
            "trust_state": "verified_local", "captured_at": self.now - 10,
            "source": "grok_build_billing",
            "windows": {"7d": {"used_percent": 50.0,
                               "resets_at": self.now + 8 * 86400,
                               "window_minutes": 10080,
                               "observed_at": self.now - 10,
                               "freshness": "fresh"}},
        }
        row.update(over)
        return row

    def test_seven_day_only_routes(self):
        # no 5h window present — must NOT be rejected as "5h window missing"
        self.assertIsNone(route.block_reason(
            _account("g", "grok"), "grok", self._row(), {}, self.now))

    def test_missing_weekly_still_holds(self):
        row = self._row()
        row["windows"] = {}  # 7d stays mandatory for every provider
        reason = route.block_reason(_account("g", "grok"), "grok", row, {},
                                    self.now)
        self.assertIsNotNone(reason)
        self.assertIn("7d window missing", reason)

    def test_run_refuses_grok(self):
        # grok is monitor/env-pick only: `headroom run grok` must never spawn a
        # process on a grok seat (read-only, no token spend)
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            rc = route.cmd_run("grok", ["/bin/echo", "hi"])
        self.assertEqual(rc, 2)
        self.assertIn("does not launch grok", buffer.getvalue())

    def test_exec_routed_refuses_grok(self):
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            rc = route._exec_routed("grok", ["grok"])
        self.assertEqual(rc, 2)

    def test_rotate_cools_grok_for_the_weekly_window(self):
        # a grok seat resets weekly, so cooling it must use the 7d window — a
        # +5h fallback would re-offer an exhausted pool far too early
        grok = _account("g", "grok")
        with mock.patch.object(route, "ensure_fresh_snapshot", return_value={}), \
                mock.patch.object(route, "candidates",
                                  return_value=[(grok, None)]), \
                mock.patch.object(route, "current_account", return_value=grok), \
                mock.patch.object(route, "window_reset", return_value=None), \
                mock.patch.object(route, "pick", return_value=None), \
                redirect_stdout(io.StringIO()):
            route.cmd_rotate("grok")
        reset = (route.cooldowns() or {}).get("g:*")
        self.assertIsNotNone(reset)
        self.assertGreater(reset - self.now, 6 * 86400)  # ~weekly, not 5h


class GrokConnect(unittest.TestCase):
    """`grok` is in registry.PROVIDERS, so the connect CLI must handle it
    coherently: fresh logins run `grok login` in an isolated home (same as
    claude/codex), and adopting an existing ~/.grok reads its local identity."""

    def test_fresh_connect_runs_grok_login(self):
        """connect_fresh for grok creates an isolated home and calls
        `grok login`, just like claude/codex."""
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.dict(os.environ, {"HEADROOM_DIR": root}), \
                mock.patch.object(connect, "provider_binary",
                                  return_value="/usr/bin/grok"), \
                mock.patch("subprocess.run") as run, \
                mock.patch.object(connect, "slot_identity") as ident:
            config = {"schema_version": 1, "accounts": [],
                      "dashboard": dict(registry.DEFAULT_DASHBOARD)}
            with open(os.path.join(root, "config.json"), "w") as f:
                json.dump(config, f)
            run.return_value = mock.Mock(returncode=0)
            ident.return_value = {"email": "new@x.ai",
                                  "account_fingerprint": "new_fp",
                                  "method": "grok_local_metadata"}
            result = connect.connect_fresh(config, "g", "grok")
        self.assertIsNotNone(result)
        argv = run.call_args.args[0]
        self.assertEqual(argv, ["/usr/bin/grok", "login"])
        env = run.call_args.kwargs.get("env") or run.call_args[1].get("env", {})
        self.assertIn("GROK_HOME", env)

    def test_slot_identity_reads_grok_for_adopt(self):
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, "auth.json"), "w") as handle:
                json.dump({"https://auth.x.ai::client": dict(_GROK_AUTH)},
                          handle)
            identity = connect.slot_identity("grok", home)
        self.assertIsNotNone(identity)
        self.assertEqual(identity["email"], "me@x.ai")
        self.assertEqual(identity["method"], "grok_local_metadata")

    def test_grok_offered_as_interactive_provider_choice(self):
        """The provider prompt must list every registry provider — a grok
        seat must be reachable without knowing the --provider flag."""
        self.assertIn("grok", registry.PROVIDERS)
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.dict(os.environ, {
                    "HEADROOM_DIR": root,
                    # empty home: no auth.json, so the grok default-adopt
                    # stays inert and the flow reaches connect_fresh
                    "GROK_HOME": os.path.join(root, "empty")}), \
                mock.patch.object(connect, "prompt_choice",
                                  return_value="grok") as choice, \
                mock.patch.object(connect, "connect_fresh",
                                  return_value=None) as fresh, \
                mock.patch("builtins.input", return_value="gk"):
            connect.cmd_connect([])
        choice.assert_called_once()
        self.assertEqual(choice.call_args.args[1], list(registry.PROVIDERS))
        fresh.assert_called_once()  # no login on disk -> fresh login flow

    def test_cmd_connect_grok_defaults_to_adopting_grok_home(self):
        """`headroom connect gk --provider grok` with a grok login on disk
        adopts $GROK_HOME without needing an explicit --adopt path."""
        with tempfile.TemporaryDirectory() as root:
            grok_home = os.path.join(root, "grokhome")
            os.makedirs(grok_home)
            with open(os.path.join(grok_home, "auth.json"), "w") as handle:
                json.dump({"https://auth.x.ai::client": dict(_GROK_AUTH)},
                          handle)
            with mock.patch.dict(os.environ, {"HEADROOM_DIR": root,
                                              "GROK_HOME": grok_home}):
                code = connect.cmd_connect(["gk", "--provider", "grok"])
                config = registry.load()
        self.assertEqual(code, 0)
        slot = next(a for a in config["accounts"] if a["name"] == "gk")
        self.assertEqual(slot["provider"], "grok")
        self.assertEqual(slot["home"], registry.expand(grok_home))
        self.assertEqual(slot["expected_email"], "me@x.ai")

    def test_detect_existing_offers_grok_login(self):
        """The wizard's adopt flow must surface an existing $GROK_HOME login
        alongside claude/codex ones."""
        with tempfile.TemporaryDirectory() as grok_home:
            with open(os.path.join(grok_home, "auth.json"), "w") as handle:
                json.dump({"https://auth.x.ai::client": dict(_GROK_AUTH)},
                          handle)
            with mock.patch.dict(os.environ, {"GROK_HOME": grok_home}):
                found = connect.detect_existing()
        rows = [row for row in found if row["provider"] == "grok"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["email"], "me@x.ai")
        self.assertEqual(rows[0]["home"], grok_home)


if __name__ == "__main__":
    unittest.main()
