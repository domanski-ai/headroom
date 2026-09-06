"""A failed Claude OAuth renewal must never be retried with the same token.

Both halves of the 2026-09-06 wm-a incident live here.

The renewal path added for expired logins had no single-shot guard: it re-fired
on every 5-minute collection cycle for as long as the error code held. OAuth
refresh tokens are single-use, so the second attempt replayed a token the
provider had already consumed, the provider answered invalid_grant, and the CLI
purged the stored token pair in place. A recoverable expiry became a destroyed
login that only an interactive browser flow could undo.

The blanked record that survived then read as `claude_credentials_missing`,
which carries no auth_state — so the dashboard's last-good carry showed four
hours of dead credential as ordinary staleness, the exact badge the renewal
work was written to eliminate.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401 — hermetic bootstrap; see tests/__init__.py

from headroom import collect, paths, route  # noqa: E402

REFRESH = "refresh-token-alpha-" + "a" * 40
ROTATED = "refresh-token-bravo-" + "b" * 40
ACCESS = "access-token-" + "c" * 40


def credential(access=ACCESS, refresh=REFRESH):
    return {"claudeAiOauth": {
        "accessToken": access,
        "refreshToken": refresh,
        "expiresAt": 4_102_444_800_000,
        "refreshTokenExpiresAt": 4_102_444_800_000,
        "scopes": ["user:inference", "user:profile"],
        "subscriptionType": "pro",
        "rateLimitTier": "default_claude_pro",
    }}


class RenewalTestCase(unittest.TestCase):
    """Each test gets its own HEADROOM_DIR so the attempt ledger cannot leak
    between cases, and its own credential home."""

    def setUp(self):
        state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, state, ignore_errors=True)
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        patcher = mock.patch.dict(os.environ, {"HEADROOM_DIR": state})
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_credential(self, record):
        with open(os.path.join(self.home, ".credentials.json"), "w") as handle:
            json.dump(record, handle)

    def renew(self, runner, identity_reader=None):
        reader = identity_reader or (lambda home: {
            "verified": True, "email": "wm-a@example.test",
            "account_fingerprint": "fp-wm-a", "method": "injected"})
        with mock.patch.object(collect, "claude_bin",
                               return_value="/usr/bin/claude"):
            return collect.claude_renew_oauth(
                self.home, {"email": "wm-a@example.test"},
                runner=runner, identity_reader=reader)

    def assert_renews(self, runner, why):
        """Renewal must go through. A refusal here is the defect under test,
        so it has to read as a failed assertion rather than as an uncaught
        error escaping the call."""
        try:
            self.renew(runner)
        except collect.IdentityBindingError as exc:
            self.fail("%s, so renewal had to be allowed; it was refused as "
                      "%s" % (why, exc.code))


class RenewalIsSingleShotPerRefreshCredential(RenewalTestCase):
    def test_the_first_attempt_on_a_credential_reaches_the_cli(self):
        self.write_credential(credential())
        runner = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 0, stdout="", stderr=""))
        self.renew(runner)
        runner.assert_called_once()

    def test_a_second_attempt_on_the_same_token_never_reaches_the_cli(self):
        """THE regression. Before the guard this called out twice, and the
        second call is what destroyed wm-a's login."""
        self.write_credential(credential())
        failing = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 1, stdout="", stderr="Login failed"))
        with self.assertRaises(collect.IdentityBindingError) as first:
            self.renew(failing)
        self.assertEqual(first.exception.code, "claude_auth_renewal_required")
        self.assertEqual(failing.call_count, 1)

        replay = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 0, stdout="", stderr=""))
        with self.assertRaises(collect.IdentityBindingError) as second:
            self.renew(replay)
        self.assertEqual(second.exception.code, "claude_auth_renewal_required")
        replay.assert_not_called()

    def test_the_attempt_is_burned_even_when_the_exchange_never_returns(self):
        """A timeout is the worst case, not an exempt one: the request went
        out, so the token may already be spent. Recording after the call would
        leave exactly this case free to replay."""
        self.write_credential(credential())
        timing_out = mock.Mock(
            side_effect=subprocess.TimeoutExpired(cmd=[], timeout=45))
        with self.assertRaises(collect.IdentityBindingError):
            self.renew(timing_out)
        self.assertEqual(timing_out.call_count, 1)

        replay = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 0, stdout="", stderr=""))
        with self.assertRaises(collect.IdentityBindingError) as refused:
            self.renew(replay)
        self.assertEqual(refused.exception.code,
                         "claude_auth_renewal_required")
        replay.assert_not_called()

    def test_a_rotated_credential_is_renewable_again(self):
        """The guard is the token's digest, not the slot. A credential that
        genuinely rotated is new bytes and must not inherit the refusal."""
        self.write_credential(credential())
        failing = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 1, stdout="", stderr=""))
        with self.assertRaises(collect.IdentityBindingError):
            self.renew(failing)

        self.write_credential(credential(refresh=ROTATED))
        succeeding = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 0, stdout="", stderr=""))
        self.assert_renews(succeeding, "the credential rotated to new bytes")
        succeeding.assert_called_once()

    def test_a_missing_binary_does_not_burn_the_one_attempt(self):
        """Nothing reached the provider, so nothing was consumed."""
        self.write_credential(credential())
        with mock.patch.object(collect, "claude_bin", return_value=None):
            with self.assertRaises(collect.IdentityBindingError):
                collect.claude_renew_oauth(
                    self.home, {"email": "wm-a@example.test"})
        runner = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 0, stdout="", stderr=""))
        self.assert_renews(runner, "no request ever reached the provider")
        runner.assert_called_once()

    def test_the_ledger_records_a_digest_and_never_the_token(self):
        self.write_credential(credential())
        runner = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 1, stdout="", stderr=""))
        with self.assertRaises(collect.IdentityBindingError):
            self.renew(runner)
        with open(paths.auth_renewal_path()) as handle:
            raw = handle.read()
        self.assertNotIn(REFRESH, raw)
        self.assertNotIn(ACCESS, raw)
        entry = next(iter(json.loads(raw).values()))
        self.assertEqual(len(entry["refresh_digest"]), 16)
        self.assertIsInstance(entry["attempted_at"], int)


class ABlankedCredentialIsItsOwnLifecycleState(RenewalTestCase):
    def limits(self):
        return collect.claude_limits(self.home, None)

    def test_an_emptied_token_pair_is_not_reported_as_merely_missing(self):
        """wm-a's exact on-disk shape: the record survived, the tokens did
        not. `expiresAt` zeroed, metadata intact."""
        record = credential(access="", refresh="")
        record["claudeAiOauth"]["expiresAt"] = 0
        self.write_credential(record)
        with self.assertRaises(collect.IdentityBindingError) as raised:
            self.limits()
        self.assertEqual(raised.exception.code, "claude_credentials_blanked")

    def test_a_slot_that_never_logged_in_is_still_credentials_missing(self):
        with self.assertRaises(collect.IdentityBindingError) as raised:
            self.limits()
        self.assertEqual(raised.exception.code, "claude_credentials_missing")

    def test_a_readable_refresh_token_is_still_credentials_missing(self):
        """Only the pair being empty means destroyed. A record still holding a
        refresh token is renewable, and must keep the old code."""
        self.write_credential(credential(access=""))
        with self.assertRaises(collect.IdentityBindingError) as raised:
            self.limits()
        self.assertEqual(raised.exception.code, "claude_credentials_missing")

    def collect_with(self, error_code):
        """One published row for a slot whose quota read raises ``error_code``."""
        slot = {"id": "wm-a", "name": "wm-a", "provider": "claude",
                "home": self.home, "expected_email": "wm-a@example.test"}
        with mock.patch.object(collect, "estate_credential_dir",
                               return_value=(None, None)), \
                mock.patch.object(collect, "external_claude_limits",
                                  return_value=("native", None)), \
                mock.patch.object(collect, "claude_identity",
                                  return_value={
                                      "verified": True,
                                      "email": "wm-a@example.test",
                                      "account_fingerprint": "fp-wm-a",
                                      "method": "injected"}), \
                mock.patch.object(collect, "credential_digest",
                                  return_value=None), \
                mock.patch.object(collect, "claude_plan", return_value="Pro"), \
                mock.patch.object(
                    collect, "claude_limits",
                    side_effect=collect.IdentityBindingError(error_code)):
            return collect.collect([slot])["accounts"][0]

    def test_the_published_row_names_the_lifecycle_instead_of_going_stale(self):
        row = self.collect_with("claude_credentials_blanked")
        self.assertFalse(row["ok"])
        self.assertEqual(row["error_code"], "claude_credentials_blanked")
        # .get, not [] — a missing auth_state is the regression this test
        # exists for, and it has to read as a failed assertion rather than a
        # KeyError.
        self.assertEqual(row.get("auth_state"), "renewal_required")
        self.assertEqual(row["trust_state"], "held")
        self.assertFalse(row["routable"])
        # The note must not send an operator to a renewal that cannot work:
        # the refresh token went with the access token.
        note = row.get("note", "").lower()
        self.assertIn("sign in again", note)
        # ...nor to `headroom auth refresh <slot>`, which refuses an adopted
        # or external home (connect.cmd_refresh) — the very shape of slot this
        # state appears on. wm-a's home is adopted, so that advice would have
        # sent an operator to a command that exits 2.
        self.assertNotIn("auth refresh", note)
        # `note` is published, so it must never carry a local path.
        self.assertNotIn(self.home.lower(), note)

    def test_the_missing_credentials_note_also_avoids_auth_refresh(self):
        """The pre-existing sibling note carried the same wrong advice. Both
        codes land on adopted slots, where `headroom auth refresh <slot>`
        exits 2 (connect.cmd_refresh refuses a non-owned home)."""
        row = self.collect_with("claude_credentials_missing")
        note = row.get("note", "").lower()
        self.assertNotIn("auth refresh", note)
        self.assertIn("claude auth login", note)
        # the macOS Keychain guidance is still correct and must survive
        self.assertIn("keychain", note)

    def test_the_new_code_can_never_hold_routing_authority(self):
        self.assertIn("claude_credentials_blanked",
                      route.MUST_DISARM_ERROR_CODES)
        self.assertNotIn("claude_credentials_blanked",
                         route.UNREADABLE_ERROR_CODES)


if __name__ == "__main__":
    unittest.main()
