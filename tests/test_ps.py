"""`headroom ps` — the pre-kill gate, and the direction it fails in.

On 2026-08-01 an operator read a live lane's argv in `ps`, read it as stale
supervisor scaffolding, and killed two live sessions. There was no command on
the host that could have answered "is this pid a live lane?", so these tests
pin the command that now answers it — and, harder, they pin WHICH WAY IT
FAILS.

The whole safety argument is one asymmetry: `--killable` exits ZERO only when
the census was read AND the pid was proven absent from every lane cone.
Everything else — a broken census, a raising oracle, an unreadable /proc
entry, a pid that has already gone, a starttime that moved — is non-zero, so
the shell idiom `headroom ps --killable "$p" && kill "$p"` refuses on doubt.
`--is-lane` is the informational inverse and fails OPEN in that idiom, which
is exactly why both exist and why the tests below assert exit-code SHAPE
rather than message text.

Two red-first pins earned during the design cycle:

  * the naive ancestor rule calls the tmux server `lane-boot` — one lane's
    boot shell — when killing it takes down six. It refuses correctly and
    explains wrongly, which is the sentinel's lookalike-parent lesson.
  * an argv-substring rule can be spoofed by any process whose command line
    merely QUOTES a lane's identifying strings; during the design cycle it
    was spoofed by the grep that was writing the design. The oracle must
    anchor on environment + parentage, and this suite proves it does.
"""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402,F401 — hermetic bootstrap; see tests/__init__.py

from headroom import __main__, ops_status, ps  # noqa: E402

from tests.test_ops_status import (  # noqa: E402
    SUP_A, SUP_B, SUPERVISOR_ARGV, OpsStatusCase,
)

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="headroom ps reads a Unix process table")

# the maximally lane-shaped argv from the design's spoof fixture: every
# argv-substring rule in the estate matches it, and it carries no supervisor
# id at all (§1.5 of KILL-HYGIENE-DESIGN-20260803.md)
SPOOF_ARGV = [
    "bash", "/home/paulsportsza/bin/lane-boot.sh", "headroom.__main__",
    "claude", "--settings",
    "/home/paulsportsza/.headroom/state/supervisors/"
    "00000000-0000-4000-8000-000000000000-1.mzansiedge.settings.json",
    "--model", "fable"]

#: `cli(panes=…)` default. `None` is a MEANINGFUL value there — it is tmux
#: being unreachable, which is not the same fact as tmux answering `{}` — so
#: "argument not given" needs its own sentinel.
NO_TMUX_OVERRIDE = object()


class PsCase(OpsStatusCase):
    """The ops-status synthetic host, queried through `headroom ps`."""

    def census(self):
        children, reason = ops_status.supervised_children(self.proc)
        self.assertIsNotNone(children, reason)
        return children

    def verdict(self, pid, starttime=None):
        return ps.classify(pid, self.census(), self.proc, starttime)

    def cli(self, argv, panes=NO_TMUX_OVERRIDE, proc_root=None):
        """`headroom ps …` against this test's synthetic host.

        `panes=None` means tmux itself is UNREACHABLE — distinct from `{}`,
        which is tmux answering that nothing runs under it. Returns
        `(exit_code, stdout, stderr)`."""
        out, err = io.StringIO(), io.StringIO()
        panes = {} if panes is NO_TMUX_OVERRIDE else panes
        with mock.patch.object(ops_status, "PROC_ROOT",
                               proc_root or self.proc), \
                mock.patch.object(ops_status, "tmux_panes",
                                  return_value=panes), \
                redirect_stdout(out), redirect_stderr(err):
            code = __main__._dispatch(["ps"] + argv)
        return code, out.getvalue(), err.getvalue()

    def two_lanes_under_one_ancestor(self):
        """One shared ancestor (a tmux server), two whole lane chains under
        it. Returns `(ancestor, boot_a, sup_a, cli_a, boot_b, sup_b, cli_b)`."""
        shared = self.write_proc(3000, ["/usr/bin/tmux", "new-session", "-d"],
                                 {}, ppid=1, started=self.now - 9000)
        self.write_proc(3100, ["bash", "/home/x/bin/lane-boot.sh", "alpha"],
                        {}, ppid=shared, started=self.now - 8000)
        self.write_proc(3101, SUPERVISOR_ARGV, {}, ppid=3100,
                        started=self.now - 8000)
        self.write_proc(3102, ["claude", "--model", "fable"],
                        self.child_env(SUP_A), ppid=3101,
                        started=self.now - 8000)
        self.write_proc(3200, ["bash", "/home/x/bin/lane-boot.sh", "beta"],
                        {}, ppid=shared, started=self.now - 7000)
        self.write_proc(3201, SUPERVISOR_ARGV, {}, ppid=3200,
                        started=self.now - 7000)
        self.write_proc(3202, ["claude", "--model", "fable"],
                        self.child_env(SUP_B), ppid=3201,
                        started=self.now - 7000)
        return shared, 3100, 3101, 3102, 3200, 3201, 3202


# --- the taxonomy -----------------------------------------------------------

class Taxonomy(PsCase):
    """Every rung of a live lane, and both predicates on each. A rung that
    classifies wrongly is either a refused cleanup (harmless) or a killed
    lane (the incident), and only the exit codes say which."""

    def setUp(self):
        super().setUp()
        (self.shared, self.boot_a, self.sup_a, self.cli_a,
         self.boot_b, self.sup_b, self.cli_b) = \
            self.two_lanes_under_one_ancestor()

    def assertVerdict(self, pid, verdict, is_lane, killable):
        answer = self.verdict(pid)
        self.assertEqual(answer["verdict"], verdict)
        self.assertEqual(ps.is_lane_exit(answer["verdict"]), is_lane)
        self.assertEqual(ps.killable_exit(answer["verdict"]), killable)

    def test_the_supervised_cli_itself(self):
        # the shape that was killed on 2026-08-01
        self.assertVerdict(self.cli_a, "lane", 0, 1)

    def test_the_supervisor_that_owns_a_live_cli(self):
        self.assertVerdict(self.sup_a, "lane-supervisor", 0, 1)

    def test_a_sole_ancestor_is_the_lane_boot_shell(self):
        self.assertVerdict(self.boot_a, "lane-boot", 0, 1)

    def test_a_descendant_of_a_live_cli(self):
        self.write_proc(3150, ["/bin/bash", "-c", "sleep 20"], {},
                        ppid=self.cli_a, started=self.now - 60)
        self.assertVerdict(3150, "lane-child", 0, 1)

    def test_an_unrelated_process_is_the_only_killable_verdict(self):
        self.write_proc(5000, ["/usr/bin/pyright-langserver", "--stdio"], {},
                        ppid=1, started=self.now - 60)
        self.assertVerdict(5000, "not-lane", 1, 0)

    def test_a_shared_ancestor_is_never_called_one_lanes_boot_shell(self):
        """RED-FIRST. The naive ancestor rule answers `lane-boot` here — it
        refuses correctly and explains wrongly, telling an operator that a
        process holding SIX lanes is one lane's boot shell. "Killing this
        takes six lanes down" is categorically different advice."""
        self.assertVerdict(self.shared, "shared-ancestor", 2, 2)
        answer = self.verdict(self.shared)
        self.assertEqual(answer["lanes_beneath"], 2)
        self.assertEqual(sorted(answer["lane_pids"]),
                         [self.cli_a, self.cli_b])

    def test_a_lane_holding_another_lane_still_reports_the_blast_radius(self):
        # a nested supervisor: the outer CLI is itself an ancestor of a live
        # inner one, so `lane` must not swallow the count
        self.write_proc(3300, SUPERVISOR_ARGV, {}, ppid=self.cli_a,
                        started=self.now - 100)
        self.write_proc(3301, ["claude", "--model", "fable"],
                        self.child_env(SUP_B, generation=2), ppid=3300,
                        started=self.now - 100)
        answer = self.verdict(self.cli_a)
        self.assertEqual(answer["verdict"], "lane")
        self.assertEqual(answer["lanes_beneath"], 1)


# --- identity: pid alone is not a name --------------------------------------

class Identity(PsCase):
    """The estate already learned this: the sentinel dedupes orphan receipts
    by pid+starttime, never pid. The dangerous window is not the pid_max wrap
    — it is the milliseconds between the check and the kill."""

    def test_a_matching_starttime_is_accepted(self):
        self.supervised(4001, started=self.now - 500)
        ticks = ops_status._proc_stat_fields(self.proc, 4001)[1]
        answer = self.verdict(4001, starttime=ticks)
        self.assertEqual(answer["verdict"], "lane")

    def test_a_starttime_that_moved_is_a_distinct_refusal(self):
        self.supervised(4001, started=self.now - 500)
        ticks = ops_status._proc_stat_fields(self.proc, 4001)[1]
        answer = self.verdict(4001, starttime=ticks + 1000)
        self.assertEqual(answer["verdict"], "identity-mismatch")
        self.assertEqual(ps.killable_exit(answer["verdict"]), 4)
        self.assertEqual(ps.is_lane_exit(answer["verdict"]), 4)
        self.assertIn("starttime", answer["reason"])

    def test_a_pid_that_does_not_exist_is_refused_by_BOTH_predicates(self):
        """THE PINNED DECISION. A pid with no /proc entry is not "proven not
        a lane" — it is a pid whose identity cannot be established at all,
        and it is the pid most likely to be handed to a new process in the
        next millisecond. `--killable` therefore REFUSES it (exit 4) rather
        than reading the absence as a licence.

        The alternative — exit 0, "it's already dead, killing it is a
        no-op" — is true of the pid the caller MEANT and false of the pid
        the kernel may have just reassigned. Refusing costs a caller one
        harmless `kill` of a corpse it never needed to make."""
        self.supervised(4001)
        answer = self.verdict(999_001)
        self.assertEqual(answer["verdict"], "no-such-process")
        self.assertEqual(ps.killable_exit(answer["verdict"]), 4)
        self.assertEqual(ps.is_lane_exit(answer["verdict"]), 4)
        self.assertNotEqual(ps.killable_exit(answer["verdict"]), 0)

    def test_a_starttime_on_a_vanished_pid_is_also_refused(self):
        self.supervised(4001)
        answer = self.verdict(999_001, starttime=12345)
        self.assertEqual(ps.killable_exit(answer["verdict"]), 4)

    def test_a_proc_entry_with_no_stat_is_refused_not_declared_safe(self):
        # a pid whose ancestry cannot be walked cannot be proven to be
        # outside every lane cone, and unprovable is a refusal
        self.supervised(4001)
        os.makedirs(os.path.join(self.proc, "6000"))
        answer = self.verdict(6000)
        self.assertEqual(answer["verdict"], "unreadable")
        self.assertEqual(ps.killable_exit(answer["verdict"]), 4)

    def test_the_pid_starttime_argument_parses_both_halves(self):
        self.supervised(4001, started=self.now - 500)
        ticks = ops_status._proc_stat_fields(self.proc, 4001)[1]
        self.assertEqual(ps.parse_target("4001"), (4001, None))
        self.assertEqual(ps.parse_target(f"4001:{int(ticks)}"),
                         (4001, float(int(ticks))))
        for bad in ("", "x", "4001:", ":9", "4001:x", "-1", "0", "4001:-2"):
            with self.assertRaises(ValueError, msg=bad):
                ps.parse_target(bad)


# --- the spoofing pin -------------------------------------------------------

class ArgvCannotBeTrusted(PsCase):
    """§1.5. An agent's Bash command can contain any string, including every
    identifying string of every lane process — so any "is this a lane?" rule
    built on argv substrings can be made to answer yes by a process that is
    not one. This is the regression that stops anyone simplifying the oracle
    into a `ps | grep`."""

    def test_a_maximally_lane_shaped_argv_with_no_env_marker_is_not_a_lane(self):
        self.supervised(4001)
        self.write_proc(7000, SPOOF_ARGV, {}, ppid=1, started=self.now - 10)
        answer = self.verdict(7000)
        self.assertEqual(answer["verdict"], "not-lane")
        self.assertEqual(ps.killable_exit(answer["verdict"]), 0)
        # and it is genuinely the shape every argv rule in the estate matches
        joined = " ".join(SPOOF_ARGV)
        for marker in ("lane-boot.sh", "headroom.__main__", "--settings",
                       ".headroom/state/supervisors/", ".settings.json"):
            self.assertIn(marker, joined)

    def test_the_same_argv_WITH_a_supervisor_parent_is_a_lane(self):
        # the control: the shape is not what makes it safe or unsafe — the
        # environment and the parentage are
        self.write_proc(7100, SUPERVISOR_ARGV, {}, ppid=1,
                        started=self.now - 10)
        self.write_proc(7101, SPOOF_ARGV[3:], self.child_env(), ppid=7100,
                        started=self.now - 10)
        self.assertEqual(self.verdict(7101)["verdict"], "lane")

    def test_a_process_merely_quoting_a_lane_pid_is_not_a_lane(self):
        # the accident that produced the design's second proof: a searcher
        # whose own argv quotes the thing it is searching for
        cli = self.supervised(4001)
        self.write_proc(7200, ["/bin/bash", "-c",
                               f"ugrep -G 'supervisors/{SUP_A}' /var/log"],
                        {}, ppid=1, started=self.now - 5)
        self.assertEqual(self.verdict(cli)["verdict"], "lane")
        self.assertEqual(self.verdict(7200)["verdict"], "not-lane")


# --- fail-safe --------------------------------------------------------------

class FailsInTheSafeDirection(PsCase):
    """"The fail-safe direction is encoded in WHICH PREDICATE YOU ASK, not in
    the caller's discipline." Every one of these is a way the oracle can be
    unable to answer, and every one must leave `--killable` non-zero."""

    def gone(self):
        return os.path.join(self.temp.name, "gone-proc")

    def test_an_unreadable_process_table_refuses_both_predicates(self):
        for flag in ("--killable", "--is-lane"):
            code, _out, err = self.cli([flag, "4001"], proc_root=self.gone())
            self.assertEqual(code, 3, flag)
            self.assertIn("census", err)

    def test_a_raising_oracle_never_authorises_a_kill(self):
        self.supervised(4001)
        boom = mock.patch.object(ops_status, "supervised_children",
                                 side_effect=RuntimeError("kernel on fire"))
        with boom:
            code, _out, err = self.cli(["--killable", "9999"])
        self.assertNotEqual(code, 0)
        self.assertEqual(code, 3)
        self.assertIn("kernel on fire", err)

    def test_a_raising_classifier_never_authorises_a_kill(self):
        self.supervised(4001)
        with mock.patch.object(ps, "classify",
                               side_effect=OSError("proc vanished")):
            code, _out, _err = self.cli(["--killable", "9999"])
        self.assertEqual(code, 3)

    def test_every_failure_mode_is_non_zero_for_killable(self):
        """The property in one place: enumerate the ways this can fail and
        assert the SHAPE of the exit code, not the message."""
        self.supervised(4001)
        os.makedirs(os.path.join(self.proc, "6000"))
        ticks = ops_status._proc_stat_fields(self.proc, 4001)[1]
        cases = {
            "the lane itself": (["--killable", "4001"], None),
            "the supervisor": (["--killable", "4000"], None),
            "a vanished pid": (["--killable", "999001"], None),
            "an unreadable /proc entry": (["--killable", "6000"], None),
            "a starttime that moved":
                ([f"--killable", f"4001:{int(ticks) + 99}"], None),
            "a malformed target": (["--killable", "not-a-pid"], None),
            "both predicates at once":
                (["--killable", "4001", "--is-lane", "4001"], None),
            "an unreadable census": (["--killable", "4001"], self.gone()),
        }
        for name, (argv, proc_root) in cases.items():
            code, _out, _err = self.cli(argv, proc_root=proc_root)
            self.assertNotEqual(code, 0, f"{name} authorised a kill")

    def test_the_shell_gate_performs_no_kill_on_any_failure(self):
        """`--killable && kill` — the literal idiom, with the kill replaced
        by a counter. The inverse idiom is asserted alongside so the reason
        both predicates exist stays measured rather than argued."""
        self.supervised(4001)
        killed = []
        for target, proc_root in (("4001", None), ("999001", None),
                                  ("4001", self.gone())):
            code, _out, _err = self.cli(["--killable", target],
                                        proc_root=proc_root)
            if code == 0:
                killed.append(target)
        self.assertEqual(killed, [])
        # and the WRONG idiom, `--is-lane || kill`, would have killed on a
        # broken census — the whole reason --killable exists
        code, _out, _err = self.cli(["--is-lane", "4001"],
                                    proc_root=self.gone())
        self.assertNotEqual(code, 0)  # non-zero -> `|| kill` FIRES

    def test_an_unknown_verdict_is_a_refusal_never_a_licence(self):
        # the table's default: a verdict added later without a mapping must
        # refuse, the way ops_status._turn_state reads an unknown reason as
        # busy
        self.assertNotEqual(ps.killable_exit("something-new"), 0)
        self.assertNotEqual(ps.is_lane_exit("something-new"), 0)


# --- empty is not failed ----------------------------------------------------

class EmptyIsNotFailed(PsCase):
    """A census that reports empty-on-failure would mark every process on the
    box killable at the exact moment the box is sick."""

    def test_an_empty_host_lists_zero_lanes_and_exits_zero(self):
        code, out, _err = self.cli([])
        self.assertEqual(code, 0)
        self.assertIn("0 lanes", out)

    def test_an_unreadable_process_table_is_an_error_not_zero_lanes(self):
        code, out, err = self.cli(
            [], proc_root=os.path.join(self.temp.name, "gone"))
        self.assertEqual(code, 3)
        self.assertNotIn("0 lanes", out)
        self.assertIn("unreadable", err)

    def test_the_json_listing_keeps_null_apart_from_empty(self):
        code, out, _err = self.cli(["--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["lanes"], [])
        code, out, _err = self.cli(
            ["--json"], proc_root=os.path.join(self.temp.name, "gone"))
        self.assertEqual(code, 3)
        report = json.loads(out)
        self.assertIsNone(report["lanes"])
        self.assertTrue(report["errors"])

    def test_an_empty_host_makes_an_unrelated_pid_killable(self):
        # the other side: nothing running is a FACT, and the gate must not
        # refuse everything just because it found no lanes
        self.write_proc(5000, ["sleep", "20"], {}, ppid=1)
        code, _out, _err = self.cli(["--killable", "5000"])
        self.assertEqual(code, 0)


# --- the listing ------------------------------------------------------------

class Listing(PsCase):

    def test_the_human_table_names_every_pid_whose_death_takes_the_lane(self):
        shared, boot_a, sup_a, cli_a, _b, _s, _c = \
            self.two_lanes_under_one_ancestor()
        code, out, _err = self.cli([], panes={shared: "work"})
        self.assertEqual(code, 0)
        self.assertIn("2 lanes", out)
        for pid in (cli_a, sup_a, boot_a):
            self.assertIn(str(pid), out)
        # the shared ancestor is NOT presented as any one lane's boot pid
        self.assertNotIn(str(shared), out.split("KILLING")[0])
        self.assertIn("KILLING ANY PID IN THE PID/SUP/BOOT COLUMNS", out)
        self.assertIn("--killable", out)

    def test_census_fidelity(self):
        self.two_lanes_under_one_ancestor()
        code, out, _err = self.cli(["--json"])
        self.assertEqual(code, 0)
        lanes = json.loads(out)["lanes"]
        self.assertEqual(sorted(row["pid"] for row in lanes),
                         sorted(row["pid"] for row in self.census()))

    def test_the_json_row_carries_the_identity_tuple(self):
        _shared, boot_a, sup_a, cli_a, _b, _s, _c = \
            self.two_lanes_under_one_ancestor()
        code, out, _err = self.cli(["--json"])
        self.assertEqual(code, 0)
        row = [r for r in json.loads(out)["lanes"] if r["pid"] == cli_a][0]
        self.assertEqual(set(row), ps.LANE_KEYS)
        self.assertEqual(row["supervisor_pid"], sup_a)
        self.assertEqual(row["boot_pid"], boot_a)
        self.assertIsNotNone(row["starttime_ticks"])
        self.assertEqual(row["generation"], 1)
        self.assertEqual(row["model"], "fable")
        self.assertEqual(row["seat"], "claude-acct-a")

    def test_a_headless_lane_outside_tmux_is_still_a_lane(self):
        """The mosh/`/goal` worker: ops_status reports 7 lanes where tmux
        shows 6 panes. Any oracle keyed on "is there a pane above it" would
        have declared this one dead."""
        self.supervised(4001)
        code, out, _err = self.cli(["--json"], panes={})
        lanes = json.loads(out)["lanes"]
        self.assertEqual(len(lanes), 1)
        self.assertEqual(lanes[0]["container"], "")
        self.assertEqual(lanes[0]["lane"], "(bare)")
        code, _out, _err = self.cli(["--killable", "4001"], panes={})
        self.assertEqual(code, 1)


class TmuxIsDecorative(PsCase):
    """§5.1's honest gap: when tmux is unreachable every container degrades
    to null and `snapshot()` still reports `errors: []`. `headroom ps` says
    so instead of inheriting the silence — and the liveness answer is
    unaffected either way."""

    def test_liveness_survives_an_unreachable_tmux(self):
        self.supervised(4001)
        code, out, _err = self.cli(["--json"], panes=None)
        self.assertEqual(code, 0)
        lanes = json.loads(out)["lanes"]
        self.assertEqual(len(lanes), 1)
        self.assertIsNone(lanes[0]["container"])
        code, _out, _err = self.cli(["--killable", "4001"], panes=None)
        self.assertEqual(code, 1)

    def test_an_unreachable_tmux_is_named_in_errors(self):
        self.supervised(4001)
        with mock.patch.object(ops_status, "PROC_ROOT", self.proc), \
                mock.patch.object(ops_status, "tmux_panes", return_value=None):
            out = io.StringIO()
            with redirect_stdout(out):
                code = __main__._dispatch(["ps", "--json"])
        self.assertEqual(code, 0)
        report = json.loads(out.getvalue())
        self.assertEqual(report["errors"], ["tmux_unreachable: the LANE and "
                                            "container columns are unknown; "
                                            "liveness is unaffected"])

    def test_the_human_form_says_so_too(self):
        self.supervised(4001)
        with mock.patch.object(ops_status, "PROC_ROOT", self.proc), \
                mock.patch.object(ops_status, "tmux_panes", return_value=None):
            out = io.StringIO()
            with redirect_stdout(out):
                __main__._dispatch(["ps"])
        self.assertIn("tmux_unreachable", out.getvalue())


# --- the command surface ----------------------------------------------------

class Command(PsCase):

    def test_usage_refusals(self):
        for argv in (["--is-lane"], ["--killable"], ["--restart-everything"],
                     ["--is-lane", "4001", "--killable", "4001"],
                     ["--is-lane", "4001", "--is-lane", "4002"],
                     ["4001"], ["--killable", "4001", "extra"]):
            code, _out, err = self.cli(argv)
            self.assertEqual(code, 2, argv)
            self.assertIn("usage", err.lower(), argv)

    def test_json_verdict_shape(self):
        self.supervised(4001)
        code, out, _err = self.cli(["--json", "--killable", "4001"])
        self.assertEqual(code, 1)
        answer = json.loads(out)
        self.assertEqual(answer["schema"], "headroom_ps_verdict@1")
        self.assertEqual(answer["verdict"], "lane")
        self.assertEqual(answer["pid"], 4001)
        self.assertEqual(answer["exit"], 1)
        self.assertEqual(answer["predicate"], "killable")
        self.assertTrue(answer["reason"])

    def test_a_refusal_names_the_lane_on_stderr(self):
        self.supervised(4001)
        code, _out, err = self.cli(["--killable", "4001"], panes={4000: "sales"})
        self.assertEqual(code, 1)
        self.assertIn("LIVE LANE", err)
        self.assertIn("sales", err)
        self.assertIn("4001", err)

    def test_a_nested_lane_refusal_names_the_pid_s_OWN_lane(self):
        """A live CLI can be the ancestor of another live CLI (a nested
        supervisor). Describing the pid by what hangs BENEATH it would name
        the wrong lane in the one message whose entire job is naming the
        right one — the incident was a naming failure."""
        self.write_proc(4000, SUPERVISOR_ARGV, {}, ppid=1,
                        started=self.now - 900)
        self.write_proc(4001, ["claude", "--model", "fable"],
                        self.child_env(SUP_A), ppid=4000,
                        started=self.now - 900)
        self.write_proc(4100, SUPERVISOR_ARGV, {}, ppid=4001,
                        started=self.now - 100)
        self.write_proc(4101, ["claude", "--model", "fable"],
                        self.child_env(SUP_B), ppid=4100,
                        started=self.now - 100)
        code, _out, err = self.cli(["--killable", "4001"],
                                   panes={4000: "outer", 4100: "inner"})
        self.assertEqual(code, 1)
        self.assertIn("outer", err)
        self.assertNotIn("inner", err)
        self.assertIn("1 further live lane", err)
        # a SUPERVISOR's lanes_beneath counts the lane it was just named for,
        # so "further" there would double-count the same session
        code, _out, err = self.cli(["--killable", "4100"],
                                   panes={4000: "outer", 4100: "inner"})
        self.assertEqual(code, 1)
        self.assertIn("inner", err)
        self.assertNotIn("further live lane", err)
        # and the OUTER supervisor holds both, so it is a shared ancestor —
        # never "lane outer's supervisor", which would understate the blast
        code, _out, err = self.cli(["--killable", "4000"],
                                   panes={4000: "outer", 4100: "inner"})
        self.assertEqual(code, 2)
        self.assertIn("2 LIVE LANES", err)

    def test_a_shared_ancestor_refusal_names_every_lane_that_dies(self):
        shared, _ba, _sa, cli_a, _bb, _sb, cli_b = \
            self.two_lanes_under_one_ancestor()
        code, _out, err = self.cli(["--killable", str(shared)],
                                   panes={cli_a: "alpha", cli_b: "beta"})
        self.assertEqual(code, 2)
        self.assertIn("2 LIVE LANES", err)
        self.assertIn("alpha", err)
        self.assertIn("beta", err)

    def test_a_killable_pid_is_silent_and_zero(self):
        self.write_proc(5000, ["sleep", "20"], {}, ppid=1)
        code, out, err = self.cli(["--killable", "5000"])
        self.assertEqual((code, out, err), (0, "", ""))

    def test_help_advertises_the_command_and_the_fail_open_warning(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(__main__._dispatch(["--help"]), 0)
        self.assertIn("headroom ps", buffer.getvalue())
        code, out, _err = self.cli(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("--killable", out)
        # the informational predicate must carry its own warning: the natural
        # `--is-lane || kill` idiom authorises every kill on a broken census
        self.assertIn("FAILS OPEN", out)
        self.assertIn("--is-lane", out)

    def test_the_command_writes_nothing(self):
        self.two_lanes_under_one_ancestor()

        def tree(root):
            listing = {}
            for base, _dirs, names in os.walk(root):
                for name in names:
                    path = os.path.join(base, name)
                    stat = os.stat(path)
                    listing[path] = (stat.st_size, stat.st_mtime_ns)
            return listing

        from headroom import paths
        watched = (paths.base_dir(), self.home, self.proc)
        before = {root: tree(root) for root in watched}
        for argv in ([], ["--json"], ["--killable", "3102"],
                     ["--is-lane", "3000"], ["--killable", "999001"]):
            self.cli(argv)
        self.assertEqual({root: tree(root) for root in watched}, before)


class DefaultsArePinned(PsCase):
    """House law: a constant every test overrides is a constant nobody
    tests. These are the two that bound this command's worst case."""

    def test_the_shipped_bounds(self):
        self.assertEqual(ops_status.MAX_ANCESTRY, 64)
        self.assertEqual(ops_status.TMUX_TIMEOUT, 1.0)

    def test_the_ancestry_walk_is_bounded_by_the_shipped_constant(self):
        # a /proc cycle must cost a bounded walk, never a hang
        self.write_proc(8000, ["sleep", "20"], {}, ppid=8001)
        self.write_proc(8001, ["sleep", "20"], {}, ppid=8000)
        chain = ps.ancestry(self.proc, 8000)
        self.assertLessEqual(len(chain), ops_status.MAX_ANCESTRY)
        self.assertEqual(self.verdict(8000)["verdict"], "not-lane")

    def test_the_classifier_reuses_the_shipped_oracle(self):
        # not a second opinion about liveness: the census IS
        # ops_status.supervised_children, and a stub proves the call
        self.supervised(4001)
        with mock.patch.object(ops_status, "supervised_children",
                               return_value=([], "")) as stub:
            code, out, _err = self.cli(["--json"])
        self.assertTrue(stub.called)
        self.assertEqual(json.loads(out)["lanes"], [])
        self.assertEqual(code, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
