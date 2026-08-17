"""WHERE a credential lives, on every path that boots or blocks a lane.

The estate rotates an account's login into ANOTHER seat's home in place. The
registry home is then where the account belongs, not where its chain is, and
one rule (ai-accounts/bin/credloc.py) is the only thing that knows the
difference. On 2026-08-17 the collector, the refresher, the rotator and
ai-accounts/bin/route.py were all taught that rule and the router that
actually boots lanes was not, so:

  * `headroom env fable` handed a lane the REGISTRY home of a rotated account,
    a directory the refresher no longer touches. The chain there dies at its
    next expiry and the lane strands at its first refresh.
  * block_reason re-derived the slot identity from the registry home and
    compared it to a snapshot taken at the RESOLVED one, so a lawfully
    rotated seat blocked itself for ever with "slot identity changed since
    snapshot, recollect": a false diagnosis whose cure cannot work, because
    the next collect reads the resolved directory again.
  * a vaulted account (resident in no home at all) could be dispatched into
    the vault, which carries no settings.json, so no SessionStart hook, no
    guard and no fan-out gate.

Both halves have to move together. Emitting the resolved directory while
block_reason still checks the registry home swaps one fault for the other, so
these tests pin the pair, and each one fails when its own guard is removed
(mutation table in R3/REPORT.md).

The resolver is reached through the HEADROOM_CREDLOC seam, which exists
because headroom also runs on the Mac where ai-accounts does not: a box the
resolver cannot serve keeps exactly today's behaviour, and that fallback is
pinned here too so it can never quietly become the normal case.
"""
import ast
import contextlib
import glob
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401 - hermetic bootstrap; see tests/__init__.py

from headroom import collect, handoff, route  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _dispatch_dir_fallbacks(source, label):
    """``["<label>:<line>", ...]`` for every ``dispatch_dir(...) or ...``.

    THE PATTERN, NOT THREE SPELLINGS OF IT (2026-08-17, R5 repair). R5
    guarded this with three literal receiver names in one module, and a
    fourth caller with any other name, or in any other module, walked past
    it: a planted mutant survived all 54 tests. Reading the AST makes the
    guard blind to naming and blind to text, so a comment or a docstring
    that QUOTES the pattern cannot make it fire either, which is what a
    plain grep over this tree does today.

    It answers on the ``or`` whose LEFT side calls dispatch_dir, which is
    the shape that discards the resolver's refusal. A ternary spelled
    around the same call would not be caught; nothing in the tree is
    written that way, and this says so rather than implying more.
    """
    hits = []
    for node in ast.walk(ast.parse(source, filename=label)):
        if not isinstance(node, ast.BoolOp) or not isinstance(node.op, ast.Or):
            continue
        for value in node.values[:-1]:
            if not isinstance(value, ast.Call):
                continue
            function = value.func
            name = (function.attr if isinstance(function, ast.Attribute)
                    else getattr(function, "id", ""))
            if name == "dispatch_dir":
                hits.append("%s:%d" % (label, value.lineno))
    return hits

# A stand-in for ai-accounts/bin/credloc.py that answers from a JSON file.
# The real module is not imported: this suite must pass on a box that has no
# ai-accounts tree, which is the whole reason the seam exists.
FIXTURE_CREDLOC = '''\
import json
import os


def _answers():
    with open(os.environ["FIXTURE_CREDLOC_JSON"]) as handle:
        return json.load(handle)


def load_rows():
    return _answers()["rows"]


def resolve(row, rows):
    # answers are keyed by SLOT, the roster name without the "claude-" prefix
    return _answers()["resolve"][row["name"].split("claude-", 1)[-1]]
'''


def _slot_id(name):
    """A registry id the config validator accepts: 12 to 32 lowercase hex."""
    return "abcdef012345"


def _claude_row(name="gmail", **over):
    """A snapshot row that is routable and fresh, so nothing but the thing
    under test can block it."""
    now = int(time.time())
    row = {
        "id": _slot_id("ab"), "name": name, "provider": "claude",
        "ok": True, "stale": False, "routable": True,
        "identity_verified": True,
        "identity": {"account_fingerprint": "AAAA", "credential_digest": "BBBB"},
        "trust_state": "verified", "captured_at": now - 10,
        "source": "anthropic_usage_api",
        "windows": {
            "5h": {"used_percent": 10.0, "resets_at": now + 3600,
                   "window_minutes": 300},
            "7d": {"used_percent": 20.0, "resets_at": now + 8 * 86400,
                   "window_minutes": 10080},
        },
    }
    row.update(over)
    return row


class CredlocSeam(unittest.TestCase):
    """Points HEADROOM_CREDLOC at a fixture resolver for the whole test."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hr-credloc-")
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.credloc = os.path.join(self.tmp, "credloc.py")
        with open(self.credloc, "w") as handle:
            handle.write(FIXTURE_CREDLOC)
        self.answers = os.path.join(self.tmp, "answers.json")

    def arm(self, resolve, rows=None):
        """Install the fixture answers and clear the module cache."""
        rows = rows if rows is not None else [
            {"name": "claude-" + slot} for slot in resolve]
        with open(self.answers, "w") as handle:
            json.dump({"rows": rows, "resolve": resolve}, handle)
        # the env var is read once at import, so an in process test moves the
        # module attribute; the variable itself still has to be set for the
        # subprocess cases, which import the module fresh
        patcher = mock.patch.dict(os.environ, {
            "HEADROOM_CREDLOC": self.credloc,
            "FIXTURE_CREDLOC_JSON": self.answers,
        })
        patcher.start()
        self.addCleanup(patcher.stop)
        attribute = mock.patch.object(collect, "_ESTATE_CREDLOC", self.credloc)
        attribute.start()
        self.addCleanup(attribute.stop)
        collect._ESTATE_CREDLOC_CACHE.clear()
        del collect._ESTATE_CREDLOC_WARNED[:]
        self.addCleanup(collect._ESTATE_CREDLOC_CACHE.clear)

    def blind(self):
        """A box the resolver cannot serve at all."""
        gone = os.path.join(self.tmp, "gone.py")
        patcher = mock.patch.dict(os.environ, {"HEADROOM_CREDLOC": gone})
        patcher.start()
        self.addCleanup(patcher.stop)
        attribute = mock.patch.object(collect, "_ESTATE_CREDLOC", gone)
        attribute.start()
        self.addCleanup(attribute.stop)
        collect._ESTATE_CREDLOC_CACHE.clear()
        del collect._ESTATE_CREDLOC_WARNED[:]
        self.addCleanup(collect._ESTATE_CREDLOC_CACHE.clear)

    def account(self, name="gmail", home=None, provider="claude"):
        return {"name": name, "provider": provider,
                "home": home or os.path.join(self.tmp, "homes", "claude-" + name)}


class TheRouterDispatchesWhereTheCredentialIs(CredlocSeam):
    def test_a_resident_account_is_dispatched_to_the_home_that_holds_its_chain(self):
        # the 2026-08-17 shape: claude-mzansiedge's chain lives in
        # homes/claude-gmail, and nothing refreshes its own home any more
        resident = os.path.join(self.tmp, "homes", "claude-gmail")
        self.arm({"mzansiedge": {"kind": "resident", "dir": resident}})
        account = self.account("mzansiedge")
        self.assertEqual(route.credential_dir(account), (resident, "resident"))
        self.assertEqual(route.dispatch_dir(account), resident)
        self.assertNotEqual(route.dispatch_dir(account), account["home"])

    def test_a_canonical_account_is_dispatched_to_its_own_home(self):
        account = self.account("system")
        self.arm({"system": {"kind": "canonical", "dir": account["home"]}})
        self.assertEqual(route.dispatch_dir(account), account["home"])
        self.assertIsNone(route.credential_location_reason(account))

    def test_a_vaulted_account_is_never_dispatchable(self):
        vault = os.path.join(self.tmp, "vault", "claude-gmail")
        self.arm({"gmail": {"kind": "vault", "dir": vault}})
        account = self.account("gmail")
        self.assertIsNone(route.dispatch_dir(account))
        reason = route.credential_location_reason(account)
        self.assertIn("vault", reason)
        self.assertNotIn(vault, str(route.dispatch_dir(account)))

    def test_an_account_with_no_location_is_never_dispatchable(self):
        self.arm({"gmail": {"kind": "none", "dir": None}})
        account = self.account("gmail")
        self.assertIsNone(route.dispatch_dir(account))
        self.assertIn("rotate it back", route.credential_location_reason(account))

    def test_a_box_without_the_estate_resolver_keeps_todays_behaviour(self):
        # headroom runs on the Mac too; blindness must never block a launch
        self.blind()
        account = self.account("gmail")
        self.assertEqual(route.dispatch_dir(account), account["home"])
        self.assertIsNone(route.credential_location_reason(account))

    def test_the_blind_fallback_says_so_once_on_stderr(self):
        # every escape is LOGGED, and a negative is never cached: an
        # unreadable credloc.py for one moment must not silently pin every
        # row to the registry home for the daemon's life
        self.blind()
        with mock.patch("sys.stderr") as err:
            self.assertIsNone(collect.estate_credloc())
            self.assertIsNone(collect.estate_credloc())
        printed = "".join(str(call) for call in err.write.call_args_list)
        self.assertIn("estate resolver", printed)
        self.assertEqual(printed.count("estate resolver"), 1)

    def test_a_codex_seat_is_never_sent_through_the_claude_resolver(self):
        self.arm({"gmail": {"kind": "vault", "dir": "/nope"}})
        account = self.account("cx", provider="codex")
        self.assertEqual(route.dispatch_dir(account), account["home"])


class TheBlockReasonTellsTheTruthAboutTheVault(CredlocSeam):
    def _block(self, account, row):
        return route.block_reason(account, "fable", row, {}, time.time())

    def test_a_vaulted_seat_is_blocked_by_its_location_not_by_a_false_identity(self):
        vault = os.path.join(self.tmp, "vault", "claude-gmail")
        self.arm({"gmail": {"kind": "vault", "dir": vault}})
        reason = self._block(self.account("gmail"), _claude_row())
        self.assertIn("vault", reason)
        # the cure it used to print could never work: the next collect reads
        # the vault again, so "recollect" is an instruction to loop for ever
        self.assertNotIn("recollect", reason)
        self.assertIn("rotate it into a home", reason)

    def test_an_account_with_no_location_is_blocked_and_told_what_to_do(self):
        self.arm({"gmail": {"kind": "none", "dir": None}})
        reason = self._block(self.account("gmail"), _claude_row())
        self.assertIn("rotate it back into a home or sign in", reason)
        self.assertNotIn("recollect", reason)

    def test_a_rotated_seat_is_re_verified_at_the_directory_it_was_read_from(self):
        # THE PAIR. The snapshot was taken at the resident home, so the TOCTOU
        # re-derivation has to read the resident home as well. Reading the
        # registry home compares two different accounts' chains and blocks the
        # seat for ever the moment they diverge, which is what happens as soon
        # as the refresher rotates the resident chain and leaves the other
        # copy behind.
        resident = os.path.join(self.tmp, "homes", "claude-gmail")
        account = self.account("mzansiedge")
        self.arm({"mzansiedge": {"kind": "resident", "dir": resident}})
        bindings = {resident: ("AAAA", "BBBB"),
                    account["home"]: ("STALE", "STALE")}
        with mock.patch.object(collect, "local_binding",
                               side_effect=lambda provider, home:
                               bindings.get(home, (None, None))):
            self.assertIsNone(self._block(account, _claude_row("mzansiedge")))

    def test_a_seat_whose_resolved_binding_really_changed_still_blocks(self):
        # the guard above must not become "never check": a home re-logged
        # into a different account must still hold
        resident = os.path.join(self.tmp, "homes", "claude-gmail")
        account = self.account("mzansiedge")
        self.arm({"mzansiedge": {"kind": "resident", "dir": resident}})
        with mock.patch.object(collect, "local_binding",
                               return_value=("SOMEONE-ELSE", "BBBB")):
            reason = self._block(account, _claude_row("mzansiedge"))
        self.assertIn("slot identity changed", reason)


class TheEnvCommandEmitsTheResolvedDirectory(CredlocSeam):
    """bin/headroom env <family> is what lane-boot.sh:199 evals into a live
    agent, so it is tested through the process, not through a function."""

    def _seat_dir(self, path, email, org, token):
        """A real claude config directory, so the router's own TOCTOU
        re-derivation runs against real files rather than a mock."""
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, ".claude.json"), "w") as handle:
            json.dump({"oauthAccount": {"emailAddress": email,
                                        "organizationUuid": org}}, handle)
        with open(os.path.join(path, ".credentials.json"), "w") as handle:
            json.dump({"claudeAiOauth": {"accessToken": token}}, handle)
        return collect.local_binding("claude", path)

    def _run_env(self, resolve, rows, snapshot_rows, config_accounts):
        headroom_dir = os.path.join(self.tmp, "hrdir")
        os.makedirs(os.path.join(headroom_dir, "state"))
        with open(os.path.join(headroom_dir, "config.json"), "w") as handle:
            json.dump({"schema_version": 1, "accounts": config_accounts}, handle)
        now = time.time()
        with open(os.path.join(headroom_dir, "state", "usage-private.json"),
                  "w") as handle:
            json.dump({"schema_version": collect.SCHEMA_VERSION,
                       "generated": now, "generated_iso": "now",
                       "accounts": snapshot_rows}, handle)
        with open(self.answers, "w") as handle:
            json.dump({"rows": rows, "resolve": resolve}, handle)
        env = dict(os.environ)
        env.update({"HEADROOM_DIR": headroom_dir,
                    "HEADROOM_CREDLOC": self.credloc,
                    "FIXTURE_CREDLOC_JSON": self.answers})
        return subprocess.run(
            [sys.executable, "-m", "headroom", "env", "fable"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)

    def test_it_exports_the_home_that_holds_the_chain_not_the_registry_home(self):
        resident = os.path.join(self.tmp, "homes", "claude-gmail")
        registry_home = os.path.join(self.tmp, "homes", "claude-mzansiedge")
        # the live 2026-08-17 shape: the registry home still holds a copy that
        # nothing refreshes any more, so the two diverge and the seat that is
        # re-verified against the wrong one blocks itself for ever
        fingerprint, digest = self._seat_dir(
            resident, "paul@mzansiedge.co.za", "org-live", "token-live")
        self._seat_dir(registry_home, "paul@mzansiedge.co.za", "org-live",
                       "token-stale-copy")
        done = self._run_env(
            {"mzansiedge": {"kind": "resident", "dir": resident}},
            [{"name": "claude-mzansiedge"}],
            [_claude_row("mzansiedge",
                         identity={"account_fingerprint": fingerprint,
                                   "credential_digest": digest})],
            [{"name": "mzansiedge", "provider": "claude", "home": registry_home,
              "id": _slot_id("ab")}])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(f"export CLAUDE_CONFIG_DIR={resident}", done.stdout)
        self.assertNotIn(registry_home, done.stdout)

    def test_it_refuses_to_export_a_vault_and_exits_non_zero(self):
        vault = os.path.join(self.tmp, "vault", "claude-gmail")
        home = os.path.join(self.tmp, "homes", "claude-gmail")
        done = self._run_env(
            {"gmail": {"kind": "vault", "dir": vault}},
            [{"name": "claude-gmail"}],
            [_claude_row("gmail")],
            [{"name": "gmail", "provider": "claude", "home": home,
              "id": _slot_id("ab")}])
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn("export", done.stdout)
        self.assertNotIn(vault, done.stdout)


class TheSupervisedLaunchUsesTheResolvedDirectory(CredlocSeam):
    """The path lane-boot.sh actually takes.

    MEASURED, not predicted: dmux pid 1189983 started 2026-08-17T12:58:43Z,
    sixteen minutes after the router cure landed, with
    LANE_SEAT=homes/claude-gmail (the cure, correct) and
    CLAUDE_CONFIG_DIR=homes/claude-mzansiedge (supervisor.py:2834, wrong). A
    fix verified through `headroom env` and `headroom pick` had proved the
    wrong path: the supervised launch built its own environment and carried a
    fourth private copy of "the registry home is the seat home".
    """

    def environment(self, account):
        from headroom import supervisor
        blank = supervisor.Supervisor.__new__(supervisor.Supervisor)
        blank.supervisor_id = "s"
        return supervisor.Supervisor._environment(blank, account, 1, False)

    def test_the_child_is_launched_where_the_chain_actually_is(self):
        resident = os.path.join(self.tmp, "homes", "claude-gmail")
        self.arm({"mzansiedge": {"kind": "resident", "dir": resident}})
        account = self.account("mzansiedge")
        self.assertEqual(
            self.environment(account)["CLAUDE_CONFIG_DIR"], resident)

    def test_a_canonical_seat_is_launched_in_its_own_home(self):
        account = self.account("system")
        self.arm({"system": {"kind": "canonical", "dir": account["home"]}})
        self.assertEqual(
            self.environment(account)["CLAUDE_CONFIG_DIR"], account["home"])

    def test_it_refuses_rather_than_launching_a_child_into_the_vault(self):
        """A None here must never fall back to the registry home: that is the
        directory known to hold somebody else's chain."""
        from headroom import supervisor
        self.arm({"gmail": {"kind": "vault",
                            "dir": os.path.join(self.tmp, "vault", "claude-gmail")}})
        with self.assertRaises(supervisor.SupervisorError) as raised:
            self.environment(self.account("gmail"))
        self.assertIn("vault", str(raised.exception))

    def test_a_box_without_the_resolver_launches_exactly_as_before(self):
        self.blind()
        account = self.account("gmail")
        self.assertEqual(
            self.environment(account)["CLAUDE_CONFIG_DIR"], account["home"])


class TheWidgetReadsTheVault(CredlocSeam):
    """Paul's ruling one, on the surface Paul reads: an account resident in no
    home still gets its 5h, 7d and Fable. Before this arm the widget read the
    slot's own home, found the lawful occupant, and held the row with no
    numbers at all."""

    def test_the_resolver_answers_the_vault_for_a_rotated_out_account(self):
        vault = os.path.join(self.tmp, "vault", "claude-gmail")
        self.arm({"gmail": {"kind": "vault", "dir": vault}})
        self.assertEqual(collect.estate_credential_dir("gmail"), (vault, "vault"))

    def test_a_vaulted_slot_is_read_at_the_vault_not_at_its_own_home(self):
        vault = os.path.join(self.tmp, "vault", "claude-gmail")
        self.arm({"gmail": {"kind": "vault", "dir": vault}})
        account = self.account("gmail")
        account["id"] = _slot_id("ab")
        seen = []

        def spy(home, *args, **kwargs):
            seen.append(home)
            raise collect.IdentityBindingError("stop_here")

        with mock.patch.object(collect, "claude_identity", side_effect=spy):
            collect.collect([account])
        self.assertEqual(seen, [vault])

    def test_no_location_raises_its_own_code_and_never_opens_a_credential(self):
        self.arm({"gmail": {"kind": "none", "dir": None}})
        account = self.account("gmail")
        account["id"] = _slot_id("ab")
        with mock.patch.object(collect, "claude_identity",
                               side_effect=AssertionError(
                                   "no credential may be opened")) as identity:
            snapshot = collect.collect([account])
        row = snapshot["accounts"][0]
        self.assertEqual(row["error_code"], "no_credential_location")
        self.assertIs(row["ok"], False)
        identity.assert_not_called()

    def test_a_blind_resolver_leaves_the_slot_reading_its_own_home(self):
        self.blind()
        account = self.account("gmail")
        account["id"] = _slot_id("ab")
        seen = []

        def spy(home, *args, **kwargs):
            seen.append(home)
            raise collect.IdentityBindingError("stop_here")

        with mock.patch.object(collect, "claude_identity", side_effect=spy):
            collect.collect([account])
        self.assertEqual(seen, [account["home"]])


class AVaultEntryBindsItsIdentity(unittest.TestCase):
    """The reader end of the 2026-08-17 16:2xZ vault identity defect (X2).

    A vault entry is not a seat home and the CLI never logs in there, so its
    .claude.json carries onboarding state and no oauthAccount; the identity
    travels beside the chain as oauthAccount.json, which IS the block. This
    collector read only .claude.json, so claude_local_identity raised
    claude_local_binding_missing, route.py held the row, and the widget said
    "provider identity mismatch" about an account whose credential and
    identity were both intact in the directory it had just been pointed at.

    ai-accounts/bin/credloc.py now writes the binding file too, so a NEW
    entry needs nothing here. This class is what makes every entry written
    before that change, or by any other hand, bind.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hr-vaultbind-")
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)

    def entry(self, email="paul@gmail.test", org="org-gmail",
              claude_json=None, snapshot=True, synthesized=False):
        directory = os.path.join(self.tmp, "vault", "claude-gmail")
        os.makedirs(directory, exist_ok=True)
        if snapshot:
            block = {"emailAddress": email, "organizationUuid": org}
            if synthesized:
                block["synthesized_from_registry"] = True
            with open(os.path.join(directory, "oauthAccount.json"), "w") as handle:
                json.dump(block, handle)
        if claude_json is not None:
            with open(os.path.join(directory, ".claude.json"), "w") as handle:
                json.dump(claude_json, handle)
        return directory

    def test_the_snapshot_binds_when_claude_json_carries_no_oauth_account(self):
        directory = self.entry(claude_json={"hasCompletedOnboarding": True})
        identity = collect.claude_local_identity(directory)
        self.assertEqual(identity["email"], "paul@gmail.test")
        self.assertEqual(identity["method"], "claude_local_metadata")
        self.assertFalse(identity["verified"])

    def test_the_snapshot_binds_when_there_is_no_claude_json_at_all(self):
        self.assertEqual(
            collect.claude_local_identity(self.entry())["email"],
            "paul@gmail.test")

    def test_local_binding_answers_a_fingerprint_for_a_vault_entry(self):
        """The router compares this pair against the snapshot to notice a home
        re-logged into a different account. A None fingerprint from a healthy
        vault entry is what made the whole row hold."""
        directory = self.entry(claude_json={"hasCompletedOnboarding": True})
        with open(os.path.join(directory, ".credentials.json"), "w") as handle:
            json.dump({"claudeAiOauth": {"accessToken": "tok"}}, handle)
        fingerprint, digest = collect.local_binding("claude", directory)
        self.assertEqual(fingerprint, collect.fingerprint("org-gmail"))
        self.assertTrue(digest)

    def test_a_real_login_in_the_directory_still_wins(self):
        directory = self.entry(email="stale@example.test", org="org-stale",
                               claude_json={"oauthAccount": {
                                   "emailAddress": "real@example.test",
                                   "organizationUuid": "org-real"}})
        self.assertEqual(collect.claude_local_identity(directory)["email"],
                         "real@example.test")

    def test_a_synthesized_snapshot_never_binds(self):
        """ai-accounts/bin/credloc.py stamps a snapshot it GUESSED from a
        registry row. A guess is not evidence of whose credential is here."""
        directory = self.entry(synthesized=True,
                               claude_json={"hasCompletedOnboarding": True})
        with self.assertRaises(collect.IdentityBindingError):
            collect.claude_local_identity(directory)

    def test_half_a_pair_never_binds(self):
        directory = self.entry(org="")
        with self.assertRaises(collect.IdentityBindingError):
            collect.claude_local_identity(directory)

    def test_a_directory_with_neither_still_raises(self):
        directory = self.entry(snapshot=False,
                               claude_json={"hasCompletedOnboarding": True})
        with self.assertRaises(collect.IdentityBindingError):
            collect.claude_local_identity(directory)


class RotatedEstate(CredlocSeam):
    """A fixture estate with ONE rotated account, plus a real headroom config.

    The shape is the live 2026-08-17 one: account "mzansiedge" is registered
    at homes/claude-mzansiedge, its chain actually lives in homes/claude-gmail
    (marker plus resolver), and the registry home still holds a superseded
    copy that nothing refreshes. Every directory here is a real config
    directory with real files, so identity re-derivation runs against files
    rather than a mock.
    """

    SID = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0001"

    def setUp(self):
        super().setUp()
        # a HEADROOM_DIR per test: the ledger, the cooldowns and the recovery
        # markers are real files, and a shared one lets one test's committed
        # handoff refuse the next test's plan as a duplicate
        state = mock.patch.dict(os.environ, {
            "HEADROOM_DIR": os.path.join(self.tmp, "hrdir")})
        state.start()
        self.addCleanup(state.stop)
        self.homes = os.path.join(self.tmp, "homes")
        self.source_home = os.path.join(self.homes, "claude-source")
        self.resident = os.path.join(self.homes, "claude-gmail")
        self.registry_home = os.path.join(self.homes, "claude-mzansiedge")
        self.vault = os.path.join(self.tmp, "vault", "claude-gmail")
        self.live = self.seat(self.resident, "paul@mzansiedge.co.za",
                              "org-live", "token-live")
        self.stale = self.seat(self.registry_home, "paul@mzansiedge.co.za",
                               "org-live", "token-stale-copy")
        self.seat(self.source_home, "source@example.test", "org-src", "tok-src")
        self.cwd = os.path.join(self.tmp, "work")
        os.makedirs(self.cwd, exist_ok=True)
        self.transcript = self.stage_transcript(self.source_home)
        self.accounts = [
            {"name": "source", "provider": "claude", "home": self.source_home,
             "expected_email": "source@example.test", "id": _slot_id("ab")},
            {"name": "mzansiedge", "provider": "claude",
             "home": self.registry_home,
             "expected_email": "paul@mzansiedge.co.za", "id": "abcdef012346"},
        ]
        self.write_config(self.accounts)
        self.arm({"mzansiedge": {"kind": "resident", "dir": self.resident},
                  "source": {"kind": "canonical", "dir": self.source_home}})

    # ---- fixture builders ------------------------------------------------

    def seat(self, path, email, org, token):
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, ".claude.json"), "w") as handle:
            json.dump({"oauthAccount": {"emailAddress": email,
                                        "organizationUuid": org}}, handle)
        with open(os.path.join(path, ".credentials.json"), "w") as handle:
            json.dump({"claudeAiOauth": {"accessToken": token}}, handle)
        return collect.local_binding("claude", path)

    def stage_transcript(self, home, session=None):
        session = session or self.SID
        slug = "-tmp-work"
        directory = os.path.join(home, "projects", slug)
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, session + ".jsonl")
        with open(path, "w") as handle:
            handle.write(json.dumps({"type": "user", "message": {
                "role": "user", "content": "hello"}}) + "\n")
        return path

    def write_config(self, accounts):
        os.makedirs(os.environ["HEADROOM_DIR"], exist_ok=True)
        with open(os.path.join(os.environ["HEADROOM_DIR"], "config.json"),
                  "w") as handle:
            json.dump({"schema_version": 1, "accounts": accounts}, handle)

    def marker(self, home, account):
        with open(os.path.join(home, "auth-resident.json"), "w") as handle:
            json.dump({"schema": "auth_resident@1", "account":
                       "claude-" + account, "lane": "dmux",
                       "since": 1786000000}, handle)

    def snapshot(self):
        rows = [_claude_row("source"),
                _claude_row("mzansiedge",
                            identity={"account_fingerprint": self.live[0],
                                      "credential_digest": self.live[1]})]
        return {"schema_version": collect.SCHEMA_VERSION,
                "generated": time.time(), "generated_iso": "now",
                "accounts": rows}

    def target(self):
        return next(a for a in self.accounts if a["name"] == "mzansiedge")

    def source(self):
        account = next(a for a in self.accounts if a["name"] == "source")
        return handoff.SourceSession(self.SID, self.transcript, account,
                                     "opus", int(time.time()))


class TheHandoffLandsWhereTheChainIs(RotatedEstate):
    """R3's P1-1, on BOTH verifiers: handoff.py was the fifth private copy of
    "the registry home is the seat home", and R3's supervisor fix turned that
    into a live regression, because the rescue then staged the conversation in
    one directory and launched the child in another.
    """

    def test_the_target_directory_is_the_one_that_holds_the_chain(self):
        self.assertEqual(handoff.target_directory(self.target()), self.resident)
        self.assertNotEqual(handoff.target_directory(self.target()),
                            self.registry_home)

    def test_a_vaulted_target_refuses_instead_of_falling_back(self):
        """A vault entry has no settings.json, so no SessionStart hook, no
        guard and no fan-out gate: a session may never launch there."""
        self.arm({"mzansiedge": {"kind": "vault", "dir": self.vault}})
        with self.assertRaises(handoff.HandoffError) as raised:
            handoff.target_directory(self.target())
        self.assertIn("vault", str(raised.exception))
        self.assertNotIn(self.vault, str(raised.exception))

    def test_the_plan_stages_into_the_resident_home(self):
        plan = handoff.plan_handoff(
            self.source(), "opus", self.target(), self.snapshot(), {},
            self.cwd, require_executable=False)
        self.assertTrue(plan.destination.startswith(self.resident + os.sep),
                        plan.destination)
        self.assertNotIn(self.registry_home, plan.destination)

    def test_the_binding_check_reads_the_directory_the_snapshot_came_from(self):
        """THE PAIR. plan.target_identity is taken by the collector at the
        RESOLVED directory; re-deriving it at the registry home compares two
        different chains. The two are byte identical only until the first
        refresh, and then every automatic handoff dies pre-spawn with "target
        identity or credential changed since planning" while nothing changed.
        """
        self.assertNotEqual(self.live, self.stale)
        plan = handoff.plan_handoff(
            self.source(), "opus", self.target(), self.snapshot(), {},
            self.cwd, require_executable=False)
        handoff.verify_target_binding(plan)  # must not raise

    def test_a_target_whose_resolved_chain_really_changed_still_refuses(self):
        """The guard above must not become "never check"."""
        plan = handoff.plan_handoff(
            self.source(), "opus", self.target(), self.snapshot(), {},
            self.cwd, require_executable=False)
        with open(os.path.join(self.resident, ".credentials.json"),
                  "w") as handle:
            json.dump({"claudeAiOauth": {"accessToken": "rotated-away"}},
                      handle)
        with self.assertRaises(handoff.HandoffError):
            handoff.verify_target_binding(plan)

    def test_the_conversation_lands_where_the_child_is_launched(self):
        """R3's own regression, closed end to end: stage through
        commit_handoff, then ask the supervisor where it would start the
        child, and require the same directory."""
        from headroom import supervisor
        plan = handoff.plan_handoff(
            self.source(), "opus", self.target(), self.snapshot(), {},
            self.cwd, require_executable=False)
        result = handoff.commit_handoff(plan)
        self.assertTrue(os.path.isfile(result.destination))
        blank = supervisor.Supervisor.__new__(supervisor.Supervisor)
        blank.supervisor_id = "s"
        launch_dir = supervisor.Supervisor._environment(
            blank, self.target(), 1, True)["CLAUDE_CONFIG_DIR"]
        staged_under = os.path.dirname(os.path.dirname(
            os.path.dirname(result.destination)))
        self.assertEqual(staged_under, launch_dir)
        self.assertEqual(launch_dir, self.resident)
        # and the line an operator is told to paste names the same directory
        self.assertIn(self.resident, result.record["resume_command"])
        self.assertNotIn(self.registry_home, result.record["resume_command"])

    def test_a_session_running_on_a_rotated_seat_can_still_be_handed_off(self):
        """After R3 a lane spending mzansiedge writes its transcripts under
        homes/claude-gmail. Binding a session to an account through
        account["home"]/projects alone refused exactly those lanes, and named
        every one of their transcripts after the home's registered owner."""
        self.marker(self.resident, "mzansiedge")
        transcript = self.stage_transcript(
            self.resident, "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0002")
        found = handoff._account_for_path(transcript, self.accounts)
        self.assertEqual(found["name"], "mzansiedge")
        self.assertEqual(
            handoff._contained_transcript(
                transcript, "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0002", found),
            os.path.realpath(transcript))

    def test_an_older_transcript_under_the_registry_home_is_still_found(self):
        """The account ran there before it was rotated; those conversations
        must not become unrescuable."""
        transcript = self.stage_transcript(
            self.registry_home, "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0003")
        found = handoff._account_for_path(transcript, self.accounts)
        self.assertEqual(found["name"], "mzansiedge")

    def test_a_box_without_the_resolver_stages_exactly_as_before(self):
        self.blind()
        self.assertEqual(handoff.target_directory(self.target()),
                         self.registry_home)


class TheDirectoryMapsBackToTheAccountSpendingIt(RotatedEstate):
    """R3 correctness lens P2-1. R3 taught every launch path to EXPORT the
    resolved directory and left the map BACK comparing registry homes, so for
    the one kind of seat it fixed, the directory headroom had just printed
    mapped to a different account: the operator's pin was dropped and the
    refusal named the wrong seat."""

    def pin(self, directory):
        patcher = mock.patch.dict(os.environ,
                                  {"CLAUDE_CONFIG_DIR": directory})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_rotated_seat_keeps_the_pin_it_was_given(self):
        self.marker(self.resident, "mzansiedge")
        self.pin(self.resident)
        self.assertEqual(route.env_pinned_account("opus")["name"], "mzansiedge")
        self.assertEqual(route.current_account("opus")["name"], "mzansiedge")

    def test_an_unmarked_home_still_maps_to_its_registered_owner(self):
        """The probe moves its input: the same directory, no marker."""
        self.pin(self.registry_home)
        self.assertEqual(route.env_pinned_account("opus")["name"], "mzansiedge")

    def test_an_uncorroborated_marker_cannot_move_the_answer(self):
        """The marker is an unauthenticated plain file. When the identity
        signed in there is somebody else's, it is not believed, and the answer
        falls back to exactly today's behaviour."""
        self.seat(self.resident, "someone@else.test", "org-x", "tok-x")
        self.marker(self.resident, "mzansiedge")
        self.pin(self.resident)
        self.assertIsNone(route.env_pinned_account("opus"))

    def test_an_unknown_directory_pins_nothing(self):
        self.pin(os.path.join(self.tmp, "not-a-seat"))
        self.assertIsNone(route.env_pinned_account("opus"))

    def test_the_supervisor_supervises_the_account_the_lane_spends(self):
        """The point of use: lane-boot exports the resolved directory and
        _initial_account reads it back.

        The ranked list deliberately holds ONLY the other account, so a
        dropped pin cannot pass this by re-picking the same seat: the answer
        is mzansiedge if and only if the pin round tripped."""
        from headroom import supervisor
        self.marker(self.resident, "mzansiedge")
        self.pin(self.resident)
        snapshot = self.snapshot()
        other = next(a for a in self.accounts if a["name"] == "source")
        with mock.patch.object(route, "ensure_fresh_snapshot",
                               return_value=snapshot), \
                mock.patch.object(route, "candidates",
                                  return_value=[(other, None)]), \
                mock.patch.object(route, "cooldowns", return_value={}):
            chosen = supervisor._initial_account("opus")
        self.assertIsNotNone(chosen)
        self.assertEqual(chosen["name"], "mzansiedge")


class TwoRegistriesOneName(RotatedEstate):
    """headroom's config and ai-accounts' registry are joined on a NAME. When
    they carry different homes for that name they are not describing the same
    seat, and believing the estate's answer would hand a caller a directory
    this box's own registry never sanctioned."""

    def test_a_disagreeing_estate_row_is_not_believed(self):
        self.arm({"mzansiedge": {"kind": "canonical",
                                 "dir": "/somewhere/else/claude-mzansiedge"}},
                 rows=[{"name": "claude-mzansiedge",
                        "home": "/somewhere/else/claude-mzansiedge"}])
        self.assertEqual(route.credential_dir(self.target()),
                         (self.registry_home, None))
        self.assertEqual(handoff.target_directory(self.target()),
                         self.registry_home)

    def test_an_agreeing_estate_row_is_believed(self):
        """The probe moves its input: the same call with the homes agreeing."""
        self.arm({"mzansiedge": {"kind": "resident", "dir": self.resident}},
                 rows=[{"name": "claude-mzansiedge",
                        "home": self.registry_home}])
        self.assertEqual(route.credential_dir(self.target()),
                         (self.resident, "resident"))

    def test_it_says_so_once_on_stderr(self):
        self.arm({"mzansiedge": {"kind": "canonical", "dir": "/elsewhere"}},
                 rows=[{"name": "claude-mzansiedge", "home": "/elsewhere"}])
        del collect._ESTATE_HOME_MISMATCH_WARNED[:]
        self.addCleanup(collect._ESTATE_HOME_MISMATCH_WARNED.clear)
        with mock.patch("sys.stderr") as err:
            route.credential_dir(self.target())
            route.credential_dir(self.target())
        printed = "".join(str(call) for call in err.write.call_args_list)
        self.assertIn("estate registry", printed)
        self.assertEqual(printed.count("estate registry"), 1)


class TheOperatorRecoveryLinesRefuseAVault(RotatedEstate):
    """R4 correctness lens F1. Three operator facing sites read
    ``route.dispatch_dir(x) or x["home"]``, and the ``or`` threw the
    resolver's refusal away and printed the REGISTRY HOME: for a vaulted
    account, the one directory known to hold somebody else's chain. Pasting
    it starts a session on another account's credential while every ledger,
    cooldown and reading calls it this one.

    Both sites are reached by the SAME failure. `_environment` raises for a
    vaulted target, which is one of the reasons automatic recovery cannot
    start Claude, which is what prints the manual instruction next.
    """

    def vaulted(self):
        self.arm({"mzansiedge": {"kind": "vault", "dir": self.vault},
                  "source": {"kind": "canonical", "dir": self.source_home}})

    def recovery(self):
        from headroom import supervisor
        return supervisor.Recovery(self.target(), ["--resume", self.SID],
                                   self.cwd, self.SID)

    def test_a_vaulted_account_gets_a_refusal_never_a_pasteable_line(self):
        self.vaulted()
        line, pasteable = self.recovery().paste_line()
        self.assertFalse(pasteable, line)
        self.assertEqual(line, self.recovery().command())
        self.assertNotIn("CLAUDE_CONFIG_DIR", line)
        self.assertNotIn(self.registry_home, line)
        self.assertNotIn(self.vault, line)
        self.assertNotIn("claude --resume", line)
        # it names the account, where the credential is, and the cure
        self.assertIn("mzansiedge", line)
        self.assertIn("vault", line)
        self.assertIn("rotate it into a home", line)

    def test_the_same_call_still_pastes_when_the_chain_is_in_a_home(self):
        """The probe moves its input: without this the refusal above could be
        a renderer that never prints anything."""
        line, pasteable = self.recovery().paste_line()
        self.assertTrue(pasteable, line)
        self.assertTrue(line.startswith("CLAUDE_CONFIG_DIR=" + self.resident
                                        + " "), line)
        self.assertNotIn(self.registry_home, line)
        self.assertIn("--resume " + self.SID, line)

    def test_an_account_no_home_and_no_vault_holds_says_exactly_that(self):
        self.arm({"mzansiedge": {"kind": "none", "dir": None},
                  "source": {"kind": "canonical", "dir": self.source_home}})
        line, pasteable = self.recovery().paste_line()
        self.assertFalse(pasteable, line)
        self.assertNotIn("CLAUDE_CONFIG_DIR", line)
        self.assertNotIn(self.registry_home, line)
        self.assertIn("mzansiedge", line)
        self.assertIn("no seat home and no vault", line)
        self.assertIn("rotate it back into a home", line)

    def test_the_unrequested_death_line_is_still_redacted(self):
        """The redaction is a property of the renderer, and the renderer
        changed. A resume argv carries no document today and still may not
        start reproducing one."""
        from headroom import supervisor
        secret = '{"env": {"MY_API_KEY": "sk-super-secret"}}'
        recovery = supervisor.Recovery(
            self.target(), ["--resume", self.SID, "--settings=" + secret],
            self.cwd, self.SID)
        self.assertNotIn("sk-super-secret", recovery.command())
        self.assertIn("<inline JSON>", recovery.command())

    def test_the_manual_recovery_pair_never_prints_a_registry_home(self):
        """_print_manual_recovery, the other reachable site: the target is
        vaulted, the source is not, so one line is a refusal and one is still
        a command."""
        from headroom import supervisor
        plan = handoff.plan_handoff(
            self.source(), "opus", self.target(), self.snapshot(), {},
            self.cwd, require_executable=False)
        self.vaulted()
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            supervisor.Supervisor._print_manual_recovery(plan)
        printed = errors.getvalue()
        self.assertNotIn(self.registry_home, printed)
        self.assertIn("mzansiedge", printed)
        self.assertIn("vault", printed)
        commands = [line for line in printed.splitlines()
                    if line.startswith("CLAUDE_CONFIG_DIR=")]
        self.assertEqual(len(commands), 1, printed)
        self.assertTrue(commands[0].startswith(
            "CLAUDE_CONFIG_DIR=" + self.source_home + " "), commands[0])

    def test_the_lead_in_never_offers_a_choice_of_zero_commands(self):
        """R5 made the OTHER two lead ins depend on `pasteable` and left this
        one saying "run one of:" unconditionally, so an operator whose two
        seats are both unresolvable was invited to run one of two refusals.
        """
        from headroom import supervisor
        plan = handoff.plan_handoff(
            self.source(), "opus", self.target(), self.snapshot(), {},
            self.cwd, require_executable=False)
        self.arm({"mzansiedge": {"kind": "vault", "dir": self.vault},
                  "source": {"kind": "vault", "dir": self.vault}})
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            supervisor.Supervisor._print_manual_recovery(plan)
        printed = errors.getvalue()
        self.assertNotIn("run one of:", printed)
        self.assertNotIn("Claude; run:", printed)
        self.assertIn("neither seat has a command to hand back", printed)
        self.assertEqual(
            [line for line in printed.splitlines()
             if line.startswith("CLAUDE_CONFIG_DIR=")], [], printed)
        self.assertNotIn(self.registry_home, printed)

    def test_the_lead_in_says_run_when_exactly_one_seat_resolves(self):
        """The probe moves its input, at the lead in and not only at the
        lines: one refusal and one command is "run:", never "run one of:"."""
        from headroom import supervisor
        plan = handoff.plan_handoff(
            self.source(), "opus", self.target(), self.snapshot(), {},
            self.cwd, require_executable=False)
        self.vaulted()
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            supervisor.Supervisor._print_manual_recovery(plan)
        printed = errors.getvalue()
        self.assertIn("could not start Claude; run:", printed)
        self.assertNotIn("run one of:", printed)

    def test_the_lead_in_offers_a_choice_when_both_seats_resolve(self):
        from headroom import supervisor
        plan = handoff.plan_handoff(
            self.source(), "opus", self.target(), self.snapshot(), {},
            self.cwd, require_executable=False)
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            supervisor.Supervisor._print_manual_recovery(plan)
        self.assertIn("run one of:", errors.getvalue())

    def test_the_no_location_sentence_has_exactly_one_owner(self):
        """R5 answered a location-less account from a verbatim sixth copy of
        route.UNDISPATCHABLE_LOCATION["none"], inside the build whose thesis
        is that this rule has one owner. Same sentence, one source."""
        self.arm({"mzansiedge": {"kind": "none", "dir": None},
                  "source": {"kind": "canonical", "dir": self.source_home}})
        line, pasteable = self.recovery().paste_line()
        self.assertFalse(pasteable, line)
        self.assertIn(route.UNDISPATCHABLE_LOCATION["none"], line)
        supervisor_body = open(
            os.path.join(ROOT, "headroom", "supervisor.py"),
            encoding="utf-8").read()
        self.assertNotIn(route.UNDISPATCHABLE_LOCATION["none"].split(";")[0],
                         supervisor_body)

    def test_both_lines_are_commands_when_both_seats_resolve(self):
        """The probe moves its input, on the pair as well."""
        from headroom import supervisor
        plan = handoff.plan_handoff(
            self.source(), "opus", self.target(), self.snapshot(), {},
            self.cwd, require_executable=False)
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            supervisor.Supervisor._print_manual_recovery(plan)
        printed = errors.getvalue()
        commands = [line for line in printed.splitlines()
                    if line.startswith("CLAUDE_CONFIG_DIR=")]
        self.assertEqual(len(commands), 2, printed)
        self.assertIn(self.resident, commands[0])
        self.assertNotIn(self.registry_home, printed)

    def test_no_line_in_any_module_falls_back_to_a_registry_home(self):
        """The point of use for a pattern that keeps coming back.

        R5 pinned three exact spellings in ONE module. A fourth caller with
        different variable names, or the same caller in route.py, handoff.py
        or __main__.py, was not covered, and a planted mutant survived the
        whole green suite. This reads every module headroom ships.
        """
        offenders = []
        directory = os.path.join(ROOT, "headroom")
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(directory, name), encoding="utf-8") as fh:
                offenders.extend(_dispatch_dir_fallbacks(fh.read(), name))
        self.assertEqual(offenders, [], offenders)

    def test_the_guard_finds_a_fourth_caller_under_any_name(self):
        """The probe moves its input. Without this the guard above could be
        a finder that never finds anything, which is exactly how R5's three
        literals passed while the pattern was reintroducible."""
        mutant = (
            "def a_fourth_operator_line(child, rendered):\n"
            "    return '%s %s' % (\n"
            "        route.dispatch_dir(child.account) or child.account['home'],\n"
            "        rendered)\n")
        self.assertEqual(_dispatch_dir_fallbacks(mutant, "mutant.py"),
                         ["mutant.py:3"])


class TwoAccountsOneDirectory(RotatedEstate):
    """R4 correctness lens F2, on the shape R4's fixture could not express.

    homes/claude-gmail is not an unowned directory: it is claude-gmail's own
    registry home, and claude-gmail is a registered account whose chain has
    been rotated out to the vault. So two accounts name one directory, one
    transcript sits in it, and R4's unranked, undeduplicated scans returned
    that file twice. `headroom handoff --session <id>` then refused with
    "matched 2 configured transcripts" and the cwd scan listed the same
    session id twice: both doors of the MANUAL rescue shut, each pointing at
    the other, on the estate's escape hatch from the automatic one.
    """

    ROTATED = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0010"
    IN_CWD = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0011"

    def setUp(self):
        super().setUp()
        self.accounts.append(
            {"name": "gmail", "provider": "claude", "home": self.resident,
             "expected_email": "paul@gmail.test", "id": "abcdef012347"})
        self.write_config(self.accounts)
        self.arm({"mzansiedge": {"kind": "resident", "dir": self.resident},
                  "source": {"kind": "canonical", "dir": self.source_home},
                  "gmail": {"kind": "vault", "dir": self.vault}})
        self.marker(self.resident, "mzansiedge")
        self.rotated = self.stage_transcript(self.resident, self.ROTATED)

    def stage_in_cwd(self, home, session):
        """A transcript under the slug resolve_source scans for THIS cwd."""
        directory = os.path.join(
            home, "projects", handoff._claude_slug(os.path.realpath(self.cwd)))
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, session + ".jsonl")
        with open(path, "w") as handle:
            handle.write(json.dumps({"type": "user", "message": {
                "role": "user", "content": "hello"}}) + "\n")
        return path

    def test_the_two_accounts_really_do_name_the_one_directory(self):
        """The fixture is the bug's precondition, so it is asserted, not
        assumed: R4's suite passed because its estate could not express it."""
        target = self.target()
        gmail = next(a for a in self.accounts if a["name"] == "gmail")
        self.assertIn(self.resident, handoff.account_directories(target))
        self.assertIn(self.resident, handoff.account_directories(gmail))
        self.assertIsNone(route.dispatch_dir(gmail))

    def test_one_transcript_on_disk_is_one_match(self):
        matches = handoff._filesystem_matches(self.ROTATED, self.accounts)
        self.assertEqual(len(matches), 1, matches)
        path, account = matches[0]
        self.assertEqual(path, os.path.realpath(self.rotated))
        self.assertEqual(account["name"], "mzansiedge")

    def test_the_manual_handoff_resolves_that_session(self):
        source = handoff.resolve_source(session_id=self.ROTATED,
                                        accounts=self.accounts, cwd=self.cwd)
        self.assertEqual(source.session_id, self.ROTATED)
        self.assertEqual(source.account["name"], "mzansiedge")
        self.assertEqual(source.transcript_path,
                         os.path.realpath(self.rotated))

    def test_the_cwd_scan_finds_exactly_one_session(self):
        staged = self.stage_in_cwd(self.resident, self.IN_CWD)
        with contextlib.redirect_stderr(io.StringIO()):
            source = handoff.resolve_source(accounts=self.accounts,
                                            cwd=self.cwd)
        self.assertEqual(source.session_id, self.IN_CWD)
        self.assertEqual(source.account["name"], "mzansiedge")
        self.assertEqual(source.transcript_path, os.path.realpath(staged))

    def test_the_owner_of_a_shared_directory_is_not_the_registry_order(self):
        """The account whose chain is IN the directory wins whichever way the
        registry is ordered. Ranking by list position instead of by claim
        would make a vaulted account's registry home a rank 0 claim and hand
        the answer to whoever happened to be listed first."""
        for accounts in (self.accounts, list(reversed(self.accounts))):
            owner = handoff._account_for_path(self.rotated, accounts)
            self.assertEqual(owner["name"], "mzansiedge")
            matches = handoff._filesystem_matches(self.ROTATED, accounts)
            self.assertEqual(len(matches), 1, matches)
            self.assertEqual(matches[0][1]["name"], "mzansiedge")

    def test_two_real_copies_in_two_homes_still_refuse(self):
        """The dedup may not become "always one". Two DIFFERENT files with
        one session id are a genuine ambiguity and must still be refused."""
        self.stage_transcript(self.source_home, self.ROTATED)
        matches = handoff._filesystem_matches(self.ROTATED, self.accounts)
        self.assertEqual(len(matches), 2, matches)
        with self.assertRaises(handoff.HandoffError) as raised:
            handoff.resolve_source(session_id=self.ROTATED,
                                   accounts=self.accounts, cwd=self.cwd)
        self.assertIn("matched 2 configured transcripts",
                      str(raised.exception))

    def test_two_recent_sessions_in_one_cwd_are_still_ambiguous(self):
        """The same control on the cwd scan, and the id is printed once."""
        self.stage_in_cwd(self.resident, self.IN_CWD)
        other = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0012"
        self.stage_in_cwd(self.source_home, other)
        with self.assertRaises(handoff.HandoffError) as raised:
            handoff.resolve_source(accounts=self.accounts, cwd=self.cwd)
        message = str(raised.exception)
        self.assertIn("multiple sessions share this cwd", message)
        self.assertEqual(message.count(self.IN_CWD), 1, message)
        self.assertEqual(message.count(other), 1, message)

    def test_an_older_transcript_under_the_registry_home_is_still_found(self):
        """The rotated account ran in its own home before the rotation, and
        nobody else claims that directory, so those conversations stay
        rescuable."""
        old = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0013"
        self.stage_transcript(self.registry_home, old)
        matches = handoff._filesystem_matches(old, self.accounts)
        self.assertEqual(len(matches), 1, matches)
        self.assertEqual(matches[0][1]["name"], "mzansiedge")

    def test_the_module_holds_one_directory_to_account_map(self):
        """Point of use: the two scans and the path map must answer from the
        same object, or the module holds two disagreeing maps again."""
        owners = handoff.directory_owners(self.accounts)
        self.assertEqual(owners[os.path.realpath(self.resident)]["name"],
                         "mzansiedge")
        self.assertEqual(owners[os.path.realpath(self.registry_home)]["name"],
                         "mzansiedge")
        self.assertEqual(owners[os.path.realpath(self.source_home)]["name"],
                         "source")
        self.assertEqual(len(owners), 3, owners)


class TheLedgerReopensTheDoorForTwoCopies(RotatedEstate):
    """R5 correctness lens F1: R5 shut the door it was built to open.

    R5 made one directory answer to one OWNER, the account whose credential
    is actually in it. The ledger tie breaker below it still asked for the
    match whose owner is NAMED by the ledger's source slot, and a rotated
    account owns no directory at all, so that comparison could never be true
    again. Every session with a second copy on disk whose source slot has
    since been rotated went from resolving to "matched 2 configured
    transcripts", which is the exact refusal R5 exists to eliminate, on the
    manual rescue that is the estate's escape hatch from the automatic one.

    Measured on the live ledger at repair time: five sessions, all with
    source slot `gmail`, whose chain is in the vault.

    The second half of this is older than R5. One automatic handoff writes
    five rows under one handoff_id and the LAST of them, `resume_spawned`,
    carries no source_slot, so reading the newest row answered None for
    every completed handoff and the tie breaker dead ended on the common
    shape while looking like it worked.
    """

    SHARED = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0020"
    OTHER = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0021"

    def setUp(self):
        super().setUp()
        self.accounts.append(
            {"name": "gmail", "provider": "claude", "home": self.resident,
             "expected_email": "paul@gmail.test", "id": "abcdef012347"})
        self.write_config(self.accounts)
        self.arm({"mzansiedge": {"kind": "resident", "dir": self.resident},
                  "source": {"kind": "canonical", "dir": self.source_home},
                  "gmail": {"kind": "vault", "dir": self.vault}})
        self.marker(self.resident, "mzansiedge")
        # the shape a previous handoff leaves behind: one copy in the source
        # home, one in the target home, and a ledger row naming the source
        self.in_rotated = self.stage_transcript(self.resident, self.SHARED)
        self.in_source = self.stage_transcript(self.source_home, self.SHARED)

    def ledger(self, rows):
        path = handoff._ledger_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")

    def staged(self, slot, ts=1000.0, session=None):
        return {"schema": "handoff@1", "action": "staged", "ts": ts,
                "old_session_id": session or self.SHARED,
                "source_slot": slot, "target_slot": "system"}

    def resume_spawned(self, ts=2000.0):
        """The row the estate writes LAST, and it names no source slot."""
        return {"schema": "handoff@1", "action": "resume_spawned", "ts": ts,
                "old_session_id": self.SHARED, "target_slot": "system"}

    def resolve(self):
        return handoff.resolve_source(session_id=self.SHARED,
                                      accounts=self.accounts, cwd=self.cwd)

    def test_two_copies_with_no_ledger_row_are_still_an_ambiguity(self):
        """The control. The door may only open on evidence, so with nothing
        in the ledger this must still refuse, and the fixture is proved to
        be a two match estate before anything else is claimed about it."""
        self.ledger([])
        self.assertEqual(
            len(handoff._filesystem_matches(self.SHARED, self.accounts)), 2)
        with self.assertRaises(handoff.HandoffError) as raised:
            self.resolve()
        self.assertIn("matched 2 configured transcripts", str(raised.exception))

    def test_a_source_slot_whose_chain_is_in_the_vault_still_claims_its_home(self):
        """The P1. `gmail` owns no directory now, so a name comparison can
        never match it again; its registry home is still its claim."""
        self.ledger([self.staged("gmail")])
        source = self.resolve()
        self.assertEqual(source.transcript_path,
                         os.path.realpath(self.in_rotated))
        # the SLOT picks the directory; the OWNER of that directory is who
        # the resume actually spends, and it is re-derived, never assumed
        self.assertEqual(source.account["name"], "mzansiedge")

    def test_a_slot_that_never_moved_resolves_exactly_as_before(self):
        """Parity with the behaviour R5 broke: this case worked before R5
        and must still work, or the repair traded one regression for
        another."""
        self.ledger([self.staged("source")])
        source = self.resolve()
        self.assertEqual(source.transcript_path,
                         os.path.realpath(self.in_source))
        self.assertEqual(source.account["name"], "source")

    def test_the_newest_row_that_names_a_slot_wins_not_the_newest_row(self):
        """The five row shape every completed automatic handoff writes."""
        self.ledger([self.staged("gmail", ts=1000.0),
                     self.resume_spawned(ts=2000.0)])
        source = self.resolve()
        self.assertEqual(source.transcript_path,
                         os.path.realpath(self.in_rotated))

    def test_the_newest_naming_row_wins_over_an_older_naming_row(self):
        """Two handoffs of one session: the later one says where it was."""
        self.ledger([self.staged("gmail", ts=1000.0),
                     self.staged("source", ts=3000.0),
                     self.resume_spawned(ts=4000.0)])
        source = self.resolve()
        self.assertEqual(source.transcript_path,
                         os.path.realpath(self.in_source))

    def test_a_ledger_naming_a_slot_that_is_not_registered_still_refuses(self):
        self.ledger([self.staged("ghost")])
        with self.assertRaises(handoff.HandoffError) as raised:
            self.resolve()
        self.assertIn("matched 2 configured transcripts", str(raised.exception))

    def test_a_ledger_row_about_another_session_does_not_disambiguate(self):
        self.ledger([self.staged("gmail", session=self.OTHER)])
        with self.assertRaises(handoff.HandoffError) as raised:
            self.resolve()
        self.assertIn("matched 2 configured transcripts", str(raised.exception))

    def test_a_slot_claims_the_directory_its_chain_is_in_before_its_home(self):
        """A slot can claim two directories at once. The one its chain is in
        today ranks first, and that ordering may not be read off the list
        position: a vaulted account has no resolved directory at all, so its
        registry home is FIRST in the list while being a rank 1 claim."""
        os.remove(self.in_source)
        self.stage_transcript(self.registry_home, self.SHARED)
        self.ledger([self.staged("mzansiedge")])
        source = self.resolve()
        self.assertEqual(source.transcript_path,
                         os.path.realpath(self.in_rotated))

    # ---- X2: the dead end says why, 2026-08-17 -------------------------

    def test_a_vaulted_slot_with_no_copy_under_it_names_the_vault(self):
        """R5 residual P1. `gmail` is vaulted and neither of its claims holds
        a copy of this session, so the tie breaker answers nothing and the
        caller printed a count. The operator's next move is to rotate the
        chain out of the vault, and nothing said so."""
        os.remove(self.in_rotated)
        self.stage_transcript(self.registry_home, self.SHARED)
        self.assertEqual(
            len(handoff._filesystem_matches(self.SHARED, self.accounts)), 2)
        self.ledger([self.staged("gmail")])
        with self.assertRaises(handoff.HandoffError) as raised:
            self.resolve()
        message = str(raised.exception)
        self.assertIn("came from gmail", message)
        self.assertIn("credential is in the vault", message)
        self.assertIn("rotate it into a home", message)

    def test_a_slot_with_no_credential_anywhere_says_that_instead(self):
        """kind none is a different fact and gets its own sentence."""
        os.remove(self.in_rotated)
        self.stage_transcript(self.registry_home, self.SHARED)
        self.arm({"mzansiedge": {"kind": "resident", "dir": self.resident},
                  "source": {"kind": "canonical", "dir": self.source_home},
                  "gmail": {"kind": "none", "dir": None}})
        self.ledger([self.staged("gmail")])
        with self.assertRaises(handoff.HandoffError) as raised:
            self.resolve()
        self.assertIn("no seat home and no vault holds",
                      str(raised.exception))

    def test_a_vaulted_slot_that_does_hold_a_copy_still_resolves(self):
        """The regression guard on the cure above. The R5 repair exists to
        make exactly this resolve, so the new refusal may not reach it."""
        self.ledger([self.staged("gmail")])
        source = self.resolve()
        self.assertEqual(source.transcript_path,
                         os.path.realpath(self.in_rotated))
        self.assertEqual(source.account["name"], "mzansiedge")

    def test_a_resident_slot_resolves_to_the_home_its_chain_is_in(self):
        """The other half of the cure, stated on its own. `mzansiedge` is
        resident in homes/claude-gmail, both of its claims hold a copy, and
        the one holding the CHAIN is the answer."""
        os.remove(self.in_source)
        self.stage_transcript(self.registry_home, self.SHARED)
        self.ledger([self.staged("mzansiedge")])
        source = self.resolve()
        self.assertEqual(source.transcript_path,
                         os.path.realpath(self.in_rotated))
        self.assertEqual(source.account["name"], "mzansiedge")

    def test_a_blind_resolver_keeps_the_old_count_message(self):
        """Diagnostics must never block. On a box the estate resolver cannot
        serve there is no location to report, so the caller behaves exactly
        as it did before this cure."""
        os.remove(self.in_rotated)
        self.stage_transcript(self.registry_home, self.SHARED)
        self.blind()
        self.ledger([self.staged("gmail")])
        with self.assertRaises(handoff.HandoffError) as raised:
            self.resolve()
        self.assertIn("matched 2 configured transcripts",
                      str(raised.exception))
        self.assertNotIn("vault", str(raised.exception))


class OneFileIsOneHitThroughTwoDoors(RotatedEstate):
    """The `seen` sets in both scans, which nothing tested.

    `directory_owners` makes one DIRECTORY one entry. That is not the same
    claim as one FILE one hit: two owned directories can reach one file when
    a project slug under the registry home is a link into the home the chain
    was rotated to, which is what an operator does to keep one history
    visible from both. Deleting either `seen` set left all 54 tests green
    (reproduce lens F4), so the claim in the code was untested.
    """

    LINKED = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0030"
    SECOND = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0031"

    def setUp(self):
        super().setUp()
        self.marker(self.resident, "mzansiedge")

    def link_slug(self, slug):
        """Point the registry home's slug at the resident home's slug, so one
        FILE sits under two directories the scans both own."""
        target = os.path.join(self.resident, "projects", slug)
        os.makedirs(target, exist_ok=True)
        link = os.path.join(self.registry_home, "projects", slug)
        os.makedirs(os.path.dirname(link), exist_ok=True)
        if os.path.lexists(link):
            os.remove(link)
        os.symlink(target, link)
        return target

    def stage_in_cwd(self, home, session):
        directory = os.path.join(
            home, "projects", handoff._claude_slug(os.path.realpath(self.cwd)))
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, session + ".jsonl")
        with open(path, "w") as handle:
            handle.write(json.dumps({"type": "user", "message": {
                "role": "user", "content": "hello"}}) + "\n")
        return path

    def test_one_file_reached_through_two_directories_is_one_match(self):
        path = self.stage_transcript(self.resident, self.LINKED)
        self.link_slug("-tmp-work")
        # The precondition, asserted rather than assumed: two OWNED
        # directories reach this session id, and both reach one FILE.
        reached = []
        for directory in handoff.directory_owners(self.accounts):
            reached.extend(glob.glob(
                os.path.join(directory, "projects", "**",
                             self.LINKED + ".jsonl"), recursive=True))
        self.assertEqual(len(reached), 2, reached)
        self.assertEqual(len({os.path.realpath(p) for p in reached}), 1,
                         reached)
        matches = handoff._filesystem_matches(self.LINKED, self.accounts)
        self.assertEqual(len(matches), 1, matches)
        self.assertEqual(matches[0][0], os.path.realpath(path))

    def test_that_one_file_still_resolves_instead_of_refusing(self):
        self.stage_transcript(self.resident, self.LINKED)
        self.link_slug("-tmp-work")
        source = handoff.resolve_source(session_id=self.LINKED,
                                        accounts=self.accounts, cwd=self.cwd)
        self.assertEqual(source.account["name"], "mzansiedge")

    def test_two_real_files_under_the_same_two_doors_still_refuse(self):
        """The dedup may not become "always one": these are two different
        files, and a genuine ambiguity has to survive."""
        self.stage_transcript(self.resident, self.LINKED)
        self.stage_transcript(self.source_home, self.LINKED)
        matches = handoff._filesystem_matches(self.LINKED, self.accounts)
        self.assertEqual(len(matches), 2, matches)

    def test_one_file_in_the_cwd_reached_twice_is_one_session(self):
        slug = handoff._claude_slug(os.path.realpath(self.cwd))
        self.stage_in_cwd(self.resident, self.LINKED)
        self.link_slug(slug)
        with contextlib.redirect_stderr(io.StringIO()):
            source = handoff.resolve_source(accounts=self.accounts,
                                            cwd=self.cwd)
        self.assertEqual(source.session_id, self.LINKED)

    def test_two_real_sessions_in_that_cwd_are_still_ambiguous(self):
        """The same control on the cwd scan, and each id is printed once."""
        self.stage_in_cwd(self.resident, self.LINKED)
        self.stage_in_cwd(self.resident, self.SECOND)
        self.link_slug(handoff._claude_slug(os.path.realpath(self.cwd)))
        with self.assertRaises(handoff.HandoffError) as raised:
            handoff.resolve_source(accounts=self.accounts, cwd=self.cwd)
        message = str(raised.exception)
        self.assertIn("multiple sessions share this cwd", message)
        self.assertEqual(message.count(self.LINKED), 1, message)
        self.assertEqual(message.count(self.SECOND), 1, message)


class ACodexSeatMayNotHideAClaudeTranscript(RotatedEstate):
    """`directory_owners` ranks a Claude account ahead of a same rank non
    Claude one, and nothing tested it: deleting the key left all 54 tests
    green (reproduce lens F3). It is not decoration. Both scans skip a
    directory whose owner is not a Claude account, so a codex seat winning
    a shared directory on registry order alone makes every real Claude
    transcript inside it invisible to `--session` and to the cwd scan.
    """

    HIDDEN = "0199aaaa-bbbb-4ccc-8ddd-eeeeffff0040"

    def accounts_with_codex_first(self):
        codex = {"name": "codex-seat", "provider": "codex",
                 "home": self.resident, "id": "abcdef012349"}
        return [codex] + self.accounts

    def test_a_claude_account_wins_a_directory_a_codex_seat_also_claims(self):
        self.marker(self.resident, "mzansiedge")
        path = self.stage_transcript(self.resident, self.HIDDEN)
        accounts = self.accounts_with_codex_first()
        owners = handoff.directory_owners(accounts)
        self.assertEqual(owners[os.path.realpath(self.resident)]["name"],
                         "mzansiedge")
        matches = handoff._filesystem_matches(self.HIDDEN, accounts)
        self.assertEqual(len(matches), 1, matches)
        self.assertEqual(matches[0][0], os.path.realpath(path))

    def test_the_claim_really_is_a_tie_before_the_provider_breaks_it(self):
        """The probe moves its input: both accounts must reach that one
        directory at the SAME rank, or the test above is passing on the rank
        and would still pass with the provider key deleted."""
        accounts = self.accounts_with_codex_first()
        codex = accounts[0]
        target = self.target()
        self.assertEqual(handoff.account_directory_claims(codex),
                         [(self.resident, 0)])
        self.assertIn((self.resident, 0),
                      handoff.account_directory_claims(target))


if __name__ == "__main__":
    unittest.main()
