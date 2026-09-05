"""Regression coverage for explicit Claude OAuth lifecycle classification."""

import json
import os
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401 — hermetic bootstrap; see tests/__init__.py

from headroom import collect, dashboard, paths, widget


def account(name, provider="claude"):
    return {
        "id": name,
        "name": name,
        "provider": provider,
        "home": "/profiles/" + name,
        "expected_email": name + "@example.test",
    }


def identity(name):
    return {
        "verified": True,
        "email": name + "@example.test",
        "account_fingerprint": "fp-" + name,
        "method": "injected",
    }


def limits(now=None):
    now = int(time.time()) if now is None else now
    return {
        "captured_at": now,
        "source": "anthropic_usage_api",
        "stale": False,
        "windows": {
            "5h": {"used_percent": 10.0, "resets_at": now + 3600,
                   "observed_at": now, "window_minutes": 300},
            "7d": {"used_percent": 20.0, "resets_at": now + 86400,
                   "observed_at": now, "window_minutes": 10080},
        },
    }


class OAuthCollectionIsolation(unittest.TestCase):
    def run_collect(self, expired=()):
        accounts = [account("wm-a"), account("wm-b"),
                    account("wm-codex", "codex")]

        def claude_identity(home):
            return identity(os.path.basename(home))

        def claude_limits(home, _pin):
            if os.path.basename(home) in expired:
                raise collect.IdentityBindingError(
                    "claude_usage_token_expired")
            return limits()

        codex = (dict(identity("wm-codex"), plan_type="plus",
                      subscription={"status": "unknown"}),
                 "plus", limits()["windows"])
        with mock.patch.object(collect, "estate_credential_dir",
                               return_value=(None, None)), \
                mock.patch.object(collect, "external_claude_limits",
                                  return_value=("native", None)), \
                mock.patch.object(collect, "external_codex_limits",
                                  return_value=("native", None)), \
                mock.patch.object(collect, "claude_identity",
                                  side_effect=claude_identity), \
                mock.patch.object(collect, "credential_digest",
                                  return_value="credential-digest"), \
                mock.patch.object(collect, "claude_plan", return_value="Pro"), \
                mock.patch.object(collect, "claude_limits",
                                  side_effect=claude_limits), \
                mock.patch.object(collect, "codex_live", return_value=codex):
            return collect.collect(accounts)

    def assert_expired(self, row):
        self.assertFalse(row["ok"])
        self.assertEqual(row["trust_state"], "held")
        self.assertFalse(row["routable"])
        self.assertEqual(row["error_code"],
                         "claude_usage_token_expired")
        self.assertEqual(row["auth_state"], "renewal_required")

    def test_expired_wm_a_does_not_block_wm_b_or_codex(self):
        rows = {r["name"]: r for r in
                self.run_collect({"wm-a"})["accounts"]}
        self.assert_expired(rows["wm-a"])
        self.assertTrue(rows["wm-b"]["ok"])
        self.assertTrue(rows["wm-codex"]["ok"])

    def test_expired_wm_b_does_not_block_wm_a_or_codex(self):
        rows = {r["name"]: r for r in
                self.run_collect({"wm-b"})["accounts"]}
        self.assertTrue(rows["wm-a"]["ok"])
        self.assert_expired(rows["wm-b"])
        self.assertTrue(rows["wm-codex"]["ok"])

    def test_both_expired_leave_collector_and_codex_healthy(self):
        snapshot = self.run_collect({"wm-a", "wm-b"})
        rows = {r["name"]: r for r in snapshot["accounts"]}
        self.assert_expired(rows["wm-a"])
        self.assert_expired(rows["wm-b"])
        self.assertTrue(rows["wm-codex"]["ok"])
        self.assertEqual(snapshot["integrity_warnings"], [])

    def test_successful_lifecycle_renewal_returns_slot_to_live(self):
        before = {r["name"]: r for r in
                  self.run_collect({"wm-a"})["accounts"]}
        after = {r["name"]: r for r in self.run_collect()["accounts"]}
        self.assert_expired(before["wm-a"])
        self.assertTrue(after["wm-a"]["ok"])
        self.assertEqual(after["wm-a"]["trust_state"], "verified")
        self.assertTrue(after["wm-a"]["routable"])
        self.assertNotIn("auth_state", after["wm-a"])

    def test_expired_opted_in_slot_auto_renews_and_retries_quota(self):
        slot = account("wm-a")
        slot["claude_auth_auto_renew"] = True
        renewed = identity("wm-a")
        with mock.patch.object(collect, "estate_credential_dir",
                               return_value=(None, None)), \
                mock.patch.object(collect, "external_claude_limits",
                                  return_value=("native", None)), \
                mock.patch.object(collect, "claude_identity",
                                  return_value=identity("wm-a")), \
                mock.patch.object(collect, "credential_digest",
                                  return_value="credential-digest"), \
                mock.patch.object(collect, "claude_plan", return_value="Pro"), \
                mock.patch.object(collect, "claude_renew_oauth",
                                  return_value=renewed) as renew, \
                mock.patch.object(
                    collect, "claude_limits",
                    side_effect=[collect.IdentityBindingError(
                        "claude_usage_token_expired"), limits()]) as quota:
            row = collect.collect([slot])["accounts"][0]
        self.assertTrue(row["ok"])
        self.assertEqual(row["trust_state"], "verified")
        self.assertTrue(row["routable"])
        renew.assert_called_once()
        self.assertEqual(quota.call_count, 2)

    def test_identity_mismatch_after_auto_renewal_holds_slot(self):
        slot = account("wm-a")
        slot["claude_auth_auto_renew"] = True
        with mock.patch.object(collect, "estate_credential_dir",
                               return_value=(None, None)), \
                mock.patch.object(collect, "external_claude_limits",
                                  return_value=("native", None)), \
                mock.patch.object(collect, "claude_identity",
                                  return_value=identity("wm-a")), \
                mock.patch.object(collect, "credential_digest",
                                  return_value="credential-digest"), \
                mock.patch.object(collect, "claude_plan", return_value="Pro"), \
                mock.patch.object(
                    collect, "claude_renew_oauth",
                    side_effect=collect.IdentityBindingError(
                        "claude_auth_identity_changed")), \
                mock.patch.object(
                    collect, "claude_limits",
                    side_effect=collect.IdentityBindingError(
                        "claude_usage_token_expired")):
            row = collect.collect([slot])["accounts"][0]
        self.assertFalse(row["ok"])
        self.assertEqual(row["trust_state"], "held")
        self.assertFalse(row["routable"])
        self.assertEqual(row["error_code"],
                         "claude_auth_identity_changed")
        self.assertEqual(row["auth_state"], "identity_changed")

    def test_opt_in_never_renews_a_different_resolved_home(self):
        slot = account("wm-a")
        slot["claude_auth_auto_renew"] = True
        with mock.patch.object(collect, "estate_credential_dir",
                               return_value=("/profiles/other", "home")), \
                mock.patch.object(collect, "external_claude_limits",
                                  return_value=("native", None)), \
                mock.patch.object(collect, "claude_identity",
                                  return_value=identity("wm-a")), \
                mock.patch.object(collect, "credential_digest",
                                  return_value="credential-digest"), \
                mock.patch.object(collect, "claude_plan", return_value="Pro"), \
                mock.patch.object(collect, "claude_renew_oauth") as renew, \
                mock.patch.object(
                    collect, "claude_limits",
                    side_effect=collect.IdentityBindingError(
                        "claude_usage_token_expired")):
            row = collect.collect([slot])["accounts"][0]
        renew.assert_not_called()
        self.assertFalse(row["ok"])
        self.assertEqual(row["auth_state"], "renewal_required")

    def test_public_projection_is_explicit_and_contains_no_token(self):
        snapshot = self.run_collect({"wm-a"})
        public = collect.public_snapshot(snapshot, redact_emails=True)
        row = public["accounts"][0]
        self.assertEqual(row["auth_state"], "renewal_required")
        self.assertEqual(row["error_code"],
                         "claude_usage_token_expired")
        rendered = json.dumps(public).lower()
        private_rendered = json.dumps(snapshot).lower()
        self.assertNotIn("accesstoken", rendered)
        self.assertNotIn("refreshtoken", rendered)
        self.assertNotIn("credential-digest", rendered)
        self.assertNotIn("accesstoken", private_rendered)
        self.assertNotIn("refreshtoken", private_rendered)


class ClaudeOwnedRenewal(unittest.TestCase):
    def oauth(self):
        return {
            "accessToken": "fake-access-secret",
            "refreshToken": "fake-refresh-secret",
            "refreshTokenExpiresAt": int((time.time() + 3600) * 1000),
            "scopes": ["user:profile", "user:inference"],
        }

    def expected(self):
        return {
            "verified": True,
            "email": "wm-a@example.test",
            "account_fingerprint": "fp-wm-a",
            "method": "before",
        }

    def renewed(self):
        return dict(self.expected(), method="after")

    def test_cli_owner_exchange_is_slot_scoped_and_output_is_captured(self):
        seen = {}

        def runner(argv, **kwargs):
            seen["argv"] = argv
            seen["env"] = kwargs["env"]
            seen["capture_output"] = kwargs["capture_output"]
            seen["timeout"] = kwargs["timeout"]
            return subprocess.CompletedProcess(argv, 0, "signed in", "")

        with mock.patch.object(collect, "claude_oauth",
                               return_value=self.oauth()), \
                mock.patch.object(collect, "claude_bin",
                                  return_value="claude"):
            value = collect.claude_renew_oauth(
                "/profiles/wm-a", self.expected(), runner=runner,
                identity_reader=lambda _home: self.renewed())
        self.assertEqual(value["account_fingerprint"], "fp-wm-a")
        self.assertEqual(seen["argv"],
                         ["claude", "auth", "login", "--claudeai"])
        self.assertEqual(seen["env"]["CLAUDE_CONFIG_DIR"],
                         "/profiles/wm-a")
        self.assertEqual(seen["env"]["CLAUDE_CODE_OAUTH_REFRESH_TOKEN"],
                         "fake-refresh-secret")
        self.assertEqual(seen["env"]["CLAUDE_CODE_OAUTH_SCOPES"],
                         "user:profile user:inference")
        self.assertTrue(seen["capture_output"])
        self.assertEqual(seen["timeout"],
                         collect.CLAUDE_AUTH_RENEW_TIMEOUT)

    def test_timeout_requires_operator_renewal(self):
        def runner(*_args, **_kwargs):
            raise subprocess.TimeoutExpired("claude", 1)

        with mock.patch.object(collect, "claude_oauth",
                               return_value=self.oauth()), \
                mock.patch.object(collect, "claude_bin",
                                  return_value="claude"):
            with self.assertRaises(collect.IdentityBindingError) as raised:
                collect.claude_renew_oauth(
                    "/profiles/wm-a", self.expected(), runner=runner,
                    identity_reader=lambda _home: self.renewed())
        self.assertEqual(raised.exception.code,
                         "claude_auth_renewal_required")

    def test_identity_mismatch_after_renewal_fails_closed(self):
        changed = dict(self.renewed(), email="other@example.test",
                       account_fingerprint="different-account")
        with mock.patch.object(collect, "claude_oauth",
                               return_value=self.oauth()), \
                mock.patch.object(collect, "claude_bin",
                                  return_value="claude"):
            with self.assertRaises(collect.IdentityBindingError) as raised:
                collect.claude_renew_oauth(
                    "/profiles/wm-a", self.expected(),
                    runner=lambda argv, **kwargs:
                    subprocess.CompletedProcess(argv, 0, "", ""),
                    identity_reader=lambda _home: changed)
        self.assertEqual(raised.exception.code,
                         "claude_auth_identity_changed")


class OAuthDisplayClassification(unittest.TestCase):
    def expired_snapshot(self, now):
        return {
            "schema_version": 1,
            "generated": now,
            "accounts": [{
                "name": "wm-a", "provider": "claude", "ok": False,
                "trust_state": "held", "routable": False,
                "error_code": "claude_usage_token_expired",
                "auth_state": "renewal_required",
            }],
        }

    def test_lastgood_carry_preserves_immediate_auth_classification(self):
        now = int(time.time())
        prior = widget.project({
            "schema_version": 1, "generated": now - 60,
            "accounts": [{
                "name": "wm-a", "provider": "claude", "ok": True,
                "trust_state": "verified", "routable": True,
                "captured_at": now - 60, "stale": False,
                "windows": limits(now - 60)["windows"],
            }],
        }, now)
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(paths, "state_dir", return_value=directory):
            dashboard._carry_lastgood_rows(prior)
            current = widget.project(self.expired_snapshot(now), now)
            carried = dashboard._carry_lastgood_rows(current)["accounts"][0]
        self.assertEqual(carried["state"], "stale")
        self.assertEqual(carried["auth_state"], "renewal_required")
        self.assertEqual(carried["error_code"],
                         "claude_usage_token_expired")
        self.assertIn("authentication renewal required",
                      carried["reading_note"])

    def test_dashboard_prioritizes_auth_renewal_over_stale_badge(self):
        template_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "dashboard", "template.html")
        with open(template_path, encoding="utf-8") as handle:
            template = handle.read()
        auth = template.index('label:"Auth renewal required"')
        stale = template.index('if(state==="stale")')
        self.assertLess(auth, stale)


if __name__ == "__main__":
    unittest.main()
