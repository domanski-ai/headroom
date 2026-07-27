"""`headroom ops-status` — the read-only fleet snapshot an ops layer consumes.

The command exists to be TRUSTED by something that may restart a session, so
these tests pin the two properties that make it safe to trust: it never
invents a value it could not read, and no single unreadable session can cost
the report (or the exit code).

Covered here:
  * the exact JSON shape and its schema tag
  * discovery from the process table, and the descendants it must NOT count
  * tmux container mapping through pane-pid ANCESTRY (a pane runs the
    supervisor, or a wrapper, never the CLI itself)
  * ctx staleness -> null, and the fallback that only speaks when the context
    window is certain
  * per-session degradation: unknowns, never a crash, never a nonzero exit
  * the command writes nothing
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from headroom import (  # noqa: E402
    __main__, ops_status, paths, registry, supervisor,
)

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="ops-status reads a Unix process table")

SUP_A = "11111111-2222-3333-4444-555555555555"
SUP_B = "66666666-7777-8888-9999-aaaaaaaaaaaa"
SID_A = "aaaaaaaa-1111-2222-3333-444444444444"
SID_B = "bbbbbbbb-1111-2222-3333-444444444444"

SESSION_KEYS = {
    "container", "supervisor_id", "session_id", "seat", "pid", "turn",
    "subagents", "context_remaining_percentage", "last_transcript_write",
    "generation", "recent_events",
}
SEAT_KEYS = {"name", "fable_used", "five_h_used", "seven_d_used"}


def assistant(total=1000):
    return {"type": "assistant", "isSidechain": False,
            "message": {"role": "assistant", "model": "claude-fable-5",
                        "content": [{"type": "text", "text": "done"}],
                        "usage": {"input_tokens": 1,
                                  "cache_read_input_tokens": max(total - 2, 0),
                                  "cache_creation_input_tokens": 1,
                                  "output_tokens": 7}}}


def user(text="go"):
    return {"type": "user",
            "message": {"role": "user", "content": [{"type": "text",
                                                     "text": text}]}}


class OpsStatusCase(unittest.TestCase):
    """A fresh HEADROOM_DIR and a synthetic /proc per test."""

    CLEAR_VARS = ("CLAUDE_CONFIG_DIR", "HEADROOM_CTX_WINDOW",
                  "HEADROOM_SUPERVISOR_ID", "HEADROOM_CHILD_GENERATION")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        environ = {key: value for key, value in os.environ.items()
                   if key not in self.CLEAR_VARS}
        environ["HEADROOM_DIR"] = os.path.join(self.temp.name, "headroom")
        patcher = mock.patch.dict(os.environ, environ, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.proc = os.path.join(self.temp.name, "proc")
        os.makedirs(self.proc)
        self.boot = 1_000_000.0
        with open(os.path.join(self.proc, "stat"), "w") as handle:
            handle.write("cpu 1 2 3\nbtime %d\nprocesses 9\n" % self.boot)
        self.now = self.boot + 100_000.0
        self.home = os.path.join(self.temp.name, "homes", "claude-acct-a")
        os.makedirs(os.path.join(self.home, "projects", "-home-x"))
        registry.save({"schema_version": 1, "accounts": [
            {"name": "acct-a", "provider": "claude", "home": self.home}]})

    # --- fixtures ---------------------------------------------------------

    def write_proc(self, pid, argv, environ=None, ppid=1, started=None):
        directory = os.path.join(self.proc, str(pid))
        os.makedirs(directory)
        with open(os.path.join(directory, "cmdline"), "wb") as handle:
            handle.write(b"\0".join(a.encode() for a in argv) + b"\0")
        with open(os.path.join(directory, "environ"), "wb") as handle:
            handle.write(b"\0".join(
                f"{k}={v}".encode() for k, v in (environ or {}).items()))
        ticks = (0.0 if started is None
                 else (started - self.boot) * ops_status._clock_ticks())
        # /proc stat: field 3 state, field 4 ppid, field 22 starttime — the
        # comm is parenthesised and deliberately contains a space here so the
        # parser is proven to split after its LAST ')'
        tail = ["S", str(ppid)] + ["0"] * 17 + [repr(ticks)] + ["0"] * 8
        with open(os.path.join(directory, "stat"), "w") as handle:
            handle.write(f"{pid} (cl (aude) " + " ".join(tail) + "\n")
        return pid

    def child_env(self, supervisor_id=SUP_A, generation=1, home=None):
        return {"HEADROOM_SUPERVISOR_ID": supervisor_id,
                "HEADROOM_CHILD_GENERATION": str(generation),
                "HEADROOM_SOURCE_SLOT": "acct-a",
                "CLAUDE_CONFIG_DIR": home or self.home}

    def transcript(self, session_id, records):
        path = os.path.join(self.home, "projects", "-home-x",
                            session_id + ".jsonl")
        with open(path, "w") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")
        os.utime(path, (self.now - 30, self.now - 30))
        return path

    def journal(self, supervisor_id, rows):
        directory = paths.ensure_private(
            os.path.join(paths.state_dir(), "supervisors"))
        path = os.path.join(directory, supervisor_id + ".jsonl")
        with open(path, "w") as handle:
            for received, generation, event, session_id, transcript in rows:
                handle.write(json.dumps({
                    "schema": "headroom_hook_event@1",
                    "received_at": received, "supervisor_id": supervisor_id,
                    "generation": generation, "source_slot": "acct-a",
                    "config_dir": self.home, "matcher": "",
                    "payload": {"hook_event_name": event,
                                "session_id": session_id,
                                "transcript_path": transcript},
                }) + "\n")
        return path

    def ctx(self, session_id, remaining, age=0.0):
        directory = paths.ensure_private(
            os.path.join(paths.state_dir(), "ctx"))
        path = os.path.join(directory, session_id + ".json")
        with open(path, "w") as handle:
            json.dump({"remaining_percentage": remaining,
                       "used_percentage": 100 - remaining,
                       "ts": self.now - age}, handle)
        return path

    def usage(self, rows):
        paths.write_json_atomic(paths.private_snapshot_path(),
                                {"generated": self.now, "accounts": rows})

    def one_live_session(self, records=None, session_id=SID_A):
        """A single, fully-wired supervised session: journal, transcript,
        supervisor process and its claude child."""
        transcript = self.transcript(
            session_id, [user(), assistant()] if records is None else records)
        self.journal(SUP_A, [
            (self.now - 900, 1, "SessionStart", session_id, transcript),
            (self.now - 500, 1, "CwdChanged", session_id, transcript)])
        self.write_proc(4000, ["python3", "-c", "...", "claude"], {},
                        ppid=1, started=self.now - 1000)
        self.write_proc(4001, ["claude", "--settings", "/x.settings.json"],
                        self.child_env(), ppid=4000, started=self.now - 1000)
        return transcript

    def snapshot(self, panes=None):
        return ops_status.snapshot(
            now=self.now, proc_root=self.proc, panes=panes,
            fallback_path=os.path.join(self.temp.name, "absent.json"))


# --- shape ------------------------------------------------------------------

class ReportShape(OpsStatusCase):

    def test_exact_contract_shape(self):
        self.one_live_session()
        self.ctx(SID_A, 62.5)
        self.usage([{"name": "acct-a", "windows": {
            "5h": {"used_percent": 21.0}, "7d": {"used_percent": 43.0},
            "scoped:Fable": {"used_percent": 13.0}}}])
        report, ok = self.snapshot(panes={4000: "sales"})
        self.assertTrue(ok)
        self.assertEqual(set(report), {"schema", "generated_at", "sessions",
                                       "seats"})
        self.assertEqual(report["schema"], "headroom_ops_status@1")
        self.assertEqual(report["generated_at"],
                         time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                       time.gmtime(self.now)))
        self.assertEqual(len(report["sessions"]), 1)
        session = report["sessions"][0]
        self.assertEqual(set(session), SESSION_KEYS)
        self.assertEqual(session["container"], "sales")
        self.assertEqual(session["supervisor_id"], SUP_A)
        self.assertEqual(session["session_id"], SID_A)
        self.assertEqual(session["seat"], "claude-acct-a")
        self.assertEqual(session["pid"], 4001)
        self.assertEqual(session["turn"], "complete")
        self.assertEqual(session["subagents"], "idle")
        self.assertEqual(session["context_remaining_percentage"], 62.5)
        self.assertEqual(session["last_transcript_write"],
                         time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                       time.gmtime(self.now - 30)))
        self.assertEqual(session["generation"], 1)
        self.assertEqual(session["recent_events"], ["SessionStart"])
        self.assertEqual(report["seats"], [
            {"name": "claude-acct-a", "fable_used": 13.0,
             "five_h_used": 21.0, "seven_d_used": 43.0}])
        # the whole report must survive a JSON round trip with no NaN
        self.assertEqual(json.loads(json.dumps(report, allow_nan=False)),
                         report)

    def test_seat_keys_are_exactly_the_contract(self):
        self.usage([{"name": "acct-a", "windows": {}}])
        report, _ok = self.snapshot(panes={})
        self.assertEqual(set(report["seats"][0]), SEAT_KEYS)
        self.assertEqual(report["seats"][0],
                         {"name": "claude-acct-a", "fable_used": None,
                          "five_h_used": None, "seven_d_used": None})

    def test_recent_events_drop_cwdchanged_and_keep_the_last_few(self):
        transcript = self.transcript(SID_A, [assistant()])
        rows = [(self.now - 100 + index, 1,
                 "CwdChanged" if index % 2 else "SessionStart",
                 SID_A, transcript) for index in range(20)]
        self.journal(SUP_A, rows)
        self.write_proc(4001, ["claude"], self.child_env(), ppid=1)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"][0]["recent_events"],
                         ["SessionStart"] * ops_status.RECENT_EVENTS)

    def test_session_id_comes_from_the_journal_not_the_resume_argv(self):
        # a `--resume X --fork-session` launch runs as a NEW session; only the
        # harness's own SessionStart names the conversation that is live
        transcript = self.transcript(SID_A, [assistant()])
        self.journal(SUP_A, [(self.now - 60, 1, "SessionStart", SID_A,
                              transcript)])
        self.write_proc(4001, ["claude", "--resume", SID_B, "--fork-session"],
                        self.child_env(), ppid=1)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"][0]["session_id"], SID_A)

    def test_binding_prefers_this_generation(self):
        old = self.transcript(SID_B, [assistant()])
        new = self.transcript(SID_A, [assistant()])
        self.journal(SUP_A, [
            (self.now - 900, 1, "SessionStart", SID_B, old),
            (self.now - 100, 2, "SessionStart", SID_A, new)])
        self.write_proc(4001, ["claude"], self.child_env(generation=1),
                        ppid=1)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"][0]["session_id"], SID_B)
        self.assertEqual(report["sessions"][0]["generation"], 1)

    def test_sessions_sort_by_container_then_supervisor(self):
        transcript = self.transcript(SID_A, [assistant()])
        for index, (supervisor_id, pid) in enumerate(
                ((SUP_B, 5001), (SUP_A, 5002))):
            self.journal(supervisor_id, [(self.now - 60 + index, 1,
                                          "SessionStart", SID_A, transcript)])
            self.write_proc(pid, ["claude"],
                            self.child_env(supervisor_id=supervisor_id),
                            ppid=1)
        report, _ok = self.snapshot(panes={5001: "zeta", 5002: "alpha"})
        self.assertEqual([row["container"] for row in report["sessions"]],
                         ["alpha", "zeta"])


# --- discovery --------------------------------------------------------------

class Discovery(OpsStatusCase):

    def test_descendants_inheriting_the_env_are_not_sessions(self):
        # every tool call a session makes inherits HEADROOM_SUPERVISOR_ID; the
        # environment alone would report each of them as a live session
        self.one_live_session()
        self.write_proc(4002, ["bash", "-c", "sleep 1"], self.child_env(),
                        ppid=4001)
        self.write_proc(4003, ["python3", "build.py"], self.child_env(),
                        ppid=4002)
        report, _ok = self.snapshot(panes={})
        self.assertEqual([row["pid"] for row in report["sessions"]], [4001])

    def test_a_headless_claude_the_session_spawned_is_not_a_session(self):
        # observed live: a session's own `claude -p …` workers inherit both
        # the supervisor env and the program name, and would each report the
        # SAME session id as their parent — a duplicate-session reading is
        # exactly what an ops layer must never be handed
        self.one_live_session()
        self.write_proc(4002, ["bash", "-c", "claude -p …"], self.child_env(),
                        ppid=4001)
        self.write_proc(4003, ["claude", "-p", "write the email"],
                        self.child_env(), ppid=4002)
        report, _ok = self.snapshot(panes={})
        self.assertEqual([row["pid"] for row in report["sessions"]], [4001])

    def test_a_nested_supervisor_is_still_a_session(self):
        # a session that launches `headroom claude` gets a FRESH supervisor
        # id, so its child's parent carries a different one
        self.one_live_session()
        nested_env = self.child_env(supervisor_id=SUP_B)
        self.write_proc(4002, ["python3", "-c", "...", "claude"],
                        self.child_env(), ppid=4001)
        self.write_proc(4003, ["claude"], nested_env, ppid=4002)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(sorted(row["pid"] for row in report["sessions"]),
                         [4001, 4003])

    def test_unsupervised_claude_is_not_a_session(self):
        # a goal runner is a claude process with no supervisor of its own
        self.write_proc(7001, ["claude", "--name", "side-task"],
                        {"CLAUDE_CONFIG_DIR": self.home}, ppid=1)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"], [])

    def test_a_launcher_argv_is_still_found_by_its_settings_file(self):
        transcript = self.transcript(SID_A, [assistant()])
        self.journal(SUP_A, [(self.now - 60, 1, "SessionStart", SID_A,
                              transcript)])
        self.write_proc(4001, ["node", "/opt/cli.js", "--settings",
                               f"/state/supervisors/{SUP_A}-1.settings.json"],
                        self.child_env(), ppid=1)
        report, _ok = self.snapshot(panes={})
        self.assertEqual([row["pid"] for row in report["sessions"]], [4001])

    def test_a_foreign_settings_file_is_not_a_session(self):
        self.write_proc(4001, ["node", "/opt/cli.js", "--settings",
                               f"/state/supervisors/{SUP_B}-1.settings.json"],
                        self.child_env(), ppid=1)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"], [])

    def test_a_malformed_supervisor_id_is_refused(self):
        self.write_proc(4001, ["claude"],
                        {"HEADROOM_SUPERVISOR_ID": "not-a-uuid",
                         "HEADROOM_CHILD_GENERATION": "1"}, ppid=1)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"], [])


# --- containers -------------------------------------------------------------

class Containers(OpsStatusCase):

    def rewrite_ppid(self, pid, ppid):
        path = os.path.join(self.proc, str(pid), "stat")
        with open(path) as handle:
            text = handle.read()
        head, _, tail = text.partition(")")
        fields = tail.split()
        fields[1] = str(ppid)
        with open(path, "w") as handle:
            handle.write(head + ") " + " ".join(fields) + "\n")

    def test_pane_pid_is_matched_through_ancestry(self):
        # the real shape: pane -> wrapper -> supervisor -> claude
        self.one_live_session()
        self.write_proc(3999, ["bash", "-c", "while kill -0 …"], {}, ppid=1)
        self.rewrite_ppid(4000, 3999)
        report, _ok = self.snapshot(panes={3999: "claude-acct-a-1a2b3c4d"})
        self.assertEqual(report["sessions"][0]["container"],
                         "claude-acct-a-1a2b3c4d")

    def test_a_session_matched_at_its_own_pid(self):
        self.one_live_session()
        report, _ok = self.snapshot(panes={4001: "sales"})
        self.assertEqual(report["sessions"][0]["container"], "sales")

    def test_bare_session_reports_empty_container(self):
        self.one_live_session()
        report, _ok = self.snapshot(panes={9999: "somewhere-else"})
        self.assertEqual(report["sessions"][0]["container"], "")

    def test_container_is_unknown_when_tmux_cannot_be_consulted(self):
        # "" would claim the session is BARE — a claim we cannot make when
        # tmux never answered
        self.one_live_session()
        with mock.patch.object(ops_status, "tmux_panes", return_value=None):
            report, _ok = ops_status.snapshot(
                now=self.now, proc_root=self.proc,
                fallback_path=os.path.join(self.temp.name, "absent.json"))
        self.assertIsNone(report["sessions"][0]["container"])

    def test_tmux_failure_and_names_with_spaces(self):
        class Result:
            returncode = 0
            stdout = b"my project 1234\nother 77\nbroken line\n"
        with mock.patch.object(ops_status.subprocess, "run",
                               return_value=Result()):
            self.assertEqual(ops_status.tmux_panes(),
                             {1234: "my project", 77: "other"})
        with mock.patch.object(ops_status.subprocess, "run",
                               side_effect=OSError("no tmux")):
            self.assertIsNone(ops_status.tmux_panes())
        with mock.patch.object(
                ops_status.subprocess, "run",
                side_effect=ops_status.subprocess.TimeoutExpired("tmux", 2)):
            self.assertIsNone(ops_status.tmux_panes())

    def test_ancestry_cycle_cannot_hang(self):
        self.one_live_session()
        self.rewrite_ppid(4000, 4001)  # 4001 -> 4000 -> 4001 …
        self.rewrite_ppid(4001, 4000)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"][0]["container"], "")


# --- context ----------------------------------------------------------------

class Context(OpsStatusCase):

    def test_fresh_ctx_file_is_reported(self):
        self.one_live_session()
        self.ctx(SID_A, 47, age=60)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(
            report["sessions"][0]["context_remaining_percentage"], 47.0)

    def test_stale_ctx_file_is_null(self):
        self.one_live_session()
        self.ctx(SID_A, 47, age=ops_status.CTX_MAX_AGE + 1)
        report, _ok = self.snapshot(panes={})
        self.assertIsNone(
            report["sessions"][0]["context_remaining_percentage"])

    def test_absent_ctx_file_is_null(self):
        self.one_live_session()
        report, _ok = self.snapshot(panes={})
        self.assertIsNone(
            report["sessions"][0]["context_remaining_percentage"])

    def test_a_corrupt_ctx_file_is_null_not_a_crash(self):
        self.one_live_session()
        path = self.ctx(SID_A, 47)
        with open(path, "w") as handle:
            handle.write("{not json")
        report, _ok = self.snapshot(panes={})
        self.assertIsNone(
            report["sessions"][0]["context_remaining_percentage"])

    def test_out_of_range_ctx_reading_is_refused(self):
        self.one_live_session()
        path = self.ctx(SID_A, 47)
        with open(path, "w") as handle:
            json.dump({"remaining_percentage": 140, "ts": self.now}, handle)
        report, _ok = self.snapshot(panes={})
        self.assertIsNone(
            report["sessions"][0]["context_remaining_percentage"])

    def test_stale_ctx_falls_back_only_when_the_window_is_certain(self):
        # ~200k used is both "dying" (200k window) and "barely started" (1M):
        # with no proof of the window, the honest answer is null
        big = supervisor.CONTEXT_WINDOW_FIT_LIMIT - 1000
        self.one_live_session(records=[user(), assistant(total=big)])
        report, _ok = self.snapshot(panes={})
        self.assertIsNone(
            report["sessions"][0]["context_remaining_percentage"])

    def test_usage_above_the_fit_limit_pins_the_window(self):
        big = supervisor.CONTEXT_WINDOW_FIT_LIMIT + 50_000
        self.one_live_session(records=[user(), assistant(total=big)])
        report, _ok = self.snapshot(panes={})
        expected = round(100.0 * (supervisor.CONTEXT_WINDOW_LARGE - big)
                         / supervisor.CONTEXT_WINDOW_LARGE, 1)
        self.assertEqual(
            report["sessions"][0]["context_remaining_percentage"], expected)

    def test_an_explicit_1m_model_pins_the_window(self):
        transcript = self.transcript(SID_A, [user(), assistant(total=100_000)])
        self.journal(SUP_A, [(self.now - 60, 1, "SessionStart", SID_A,
                              transcript)])
        self.write_proc(4001, ["claude", "--model", "opus[1m]"],
                        self.child_env(), ppid=1)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(
            report["sessions"][0]["context_remaining_percentage"], 90.0)

    def test_a_fresh_ctx_file_beats_the_transcript(self):
        big = supervisor.CONTEXT_WINDOW_FIT_LIMIT + 50_000
        self.one_live_session(records=[user(), assistant(total=big)])
        self.ctx(SID_A, 12)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(
            report["sessions"][0]["context_remaining_percentage"], 12.0)


# --- activity ---------------------------------------------------------------

class Activity(OpsStatusCase):

    def subagent(self, session_id, name="agent-x", age=0.0, records=None):
        directory = os.path.join(self.home, "projects", "-home-x",
                                 session_id, "subagents")
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name + ".jsonl")
        with open(path, "w") as handle:
            for record in (records or [assistant()]):
                handle.write(json.dumps(record) + "\n")
        os.utime(path, (self.now - age, self.now - age))
        return path

    def test_a_prompt_awaiting_its_answer_is_in_flight(self):
        self.one_live_session(records=[assistant(), user()])
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"][0]["turn"], "in_flight")

    def test_a_transcript_with_no_assistant_turn_is_unknown(self):
        self.one_live_session(records=[{"type": "system", "subtype": "x"}])
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"][0]["turn"], "unknown")

    def test_a_missing_transcript_degrades_both_activity_fields(self):
        transcript = self.one_live_session()
        os.unlink(transcript)
        report, _ok = self.snapshot(panes={})
        session = report["sessions"][0]
        self.assertEqual(session["turn"], "unknown")
        self.assertEqual(session["subagents"], "unknown")
        self.assertIsNone(session["last_transcript_write"])
        # the row itself survives, fully identified
        self.assertEqual(session["session_id"], SID_A)
        self.assertEqual(session["pid"], 4001)

    def test_a_malformed_transcript_tail_is_unknown_not_idle(self):
        transcript = self.one_live_session()
        with open(transcript, "a") as handle:
            handle.write("{ this is not json\n")
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"][0]["turn"], "unknown")
        self.assertEqual(report["sessions"][0]["subagents"], "unknown")

    def test_a_recently_written_subagent_is_active(self):
        self.one_live_session()
        self.subagent(SID_A, age=1.0)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"][0]["subagents"], "active")
        # a finished main turn with live background work is the normal shape
        self.assertEqual(report["sessions"][0]["turn"], "complete")

    def test_a_quiet_finished_subagent_is_idle(self):
        self.one_live_session()
        self.subagent(SID_A, age=supervisor.PREEMPT_IDLE_SECONDS + 600)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"][0]["subagents"], "idle")

    def test_a_quiet_subagent_mid_tool_call_is_still_active(self):
        # SHAPE, not age: an agent blocked in one long tool call writes
        # nothing for minutes and must never read as finished
        self.one_live_session()
        self.subagent(SID_A, age=supervisor.PREEMPT_IDLE_SECONDS + 600,
                      records=[assistant(), user()])
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"][0]["subagents"], "active")

    def test_a_subagent_from_a_previous_process_does_not_count(self):
        # a forked session inherits the whole subagents directory; an agent of
        # a process that has exited is not running
        self.one_live_session()
        self.subagent(SID_A, age=supervisor.PREEMPT_IDLE_SECONDS + 600,
                      records=[assistant(), user()])
        # move the child's start AFTER that write
        self.write_proc(4004, ["claude"], self.child_env(SUP_B), ppid=1,
                        started=self.now - 1.0)
        self.journal(SUP_B, [(self.now - 5, 1, "SessionStart", SID_A,
                              os.path.join(self.home, "projects", "-home-x",
                                           SID_A + ".jsonl"))])
        report, _ok = self.snapshot(panes={})
        rows = {row["pid"]: row for row in report["sessions"]}
        self.assertEqual(rows[4004]["subagents"], "idle")
        self.assertEqual(rows[4001]["subagents"], "active")


# --- seats ------------------------------------------------------------------

class Seats(OpsStatusCase):

    def test_window_key_spellings_from_both_feeds(self):
        self.usage([{"name": "acct-a", "windows": {
            "5h": {"used_percent": 1.0}, "7d": {"used_percent": 2.0},
            "fable": {"used_percent": 3.0}}}])
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["seats"][0]["fable_used"], 3.0)

    def test_public_feed_is_the_fallback_when_the_private_one_is_absent(self):
        public = os.path.join(self.temp.name, "usage.json")
        with open(public, "w") as handle:
            json.dump({"accounts": [
                {"name": "claude-acct-b", "windows": {
                    "5h": {"used_percent": 4.0},
                    "7d": {"used_percent": 5.0},
                    "fable": {"used_percent": 6.0}}}]}, handle)
        report, ok = ops_status.snapshot(
            now=self.now, proc_root=self.proc, panes={}, fallback_path=public)
        self.assertTrue(ok)
        self.assertEqual(report["seats"], [
            {"name": "claude-acct-b", "fable_used": 6.0, "five_h_used": 4.0,
             "seven_d_used": 5.0}])

    def test_an_unregistered_row_keeps_its_own_name(self):
        self.usage([{"name": "stranger", "windows": {}},
                    {"name": "acct-a", "windows": {}}])
        report, _ok = self.snapshot(panes={})
        self.assertEqual([seat["name"] for seat in report["seats"]],
                         ["claude-acct-a", "stranger"])

    def test_a_dotted_home_names_itself_by_account(self):
        registry.save({"schema_version": 1, "accounts": [
            {"name": "codex-primary", "provider": "codex",
             "home": os.path.join(self.temp.name, ".codex")}]})
        self.usage([{"name": "codex-primary", "windows": {
            "7d": {"used_percent": 30.0}}}])
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["seats"][0]["name"], "codex-primary")

    def test_a_nonsense_window_value_is_null(self):
        self.usage([{"name": "acct-a", "windows": {
            "5h": {"used_percent": "lots"}, "7d": {"used_percent": None}}}])
        report, _ok = self.snapshot(panes={})
        self.assertIsNone(report["seats"][0]["five_h_used"])
        self.assertIsNone(report["seats"][0]["seven_d_used"])


# --- degradation and exit codes --------------------------------------------

class Degradation(OpsStatusCase):

    def test_one_broken_session_never_costs_the_others(self):
        self.one_live_session()
        self.write_proc(6001, ["claude"], self.child_env(SUP_B), ppid=1)
        real = ops_status._session_report

        def explode(child, *args, **kwargs):
            if child["pid"] == 6001:
                raise RuntimeError("unreadable")
            return real(child, *args, **kwargs)

        with mock.patch.object(ops_status, "_session_report", explode):
            report, ok = self.snapshot(panes={})
        self.assertTrue(ok)
        rows = {row["pid"]: row for row in report["sessions"]}
        self.assertEqual(set(rows), {4001, 6001})
        self.assertEqual(set(rows[6001]), SESSION_KEYS)
        self.assertEqual(rows[6001]["turn"], "unknown")
        self.assertEqual(rows[6001]["subagents"], "unknown")
        self.assertIsNone(rows[6001]["session_id"])
        self.assertEqual(rows[4001]["turn"], "complete")

    def test_an_absent_journal_leaves_a_row_with_unknowns(self):
        self.write_proc(4001, ["claude"], self.child_env(), ppid=1)
        report, ok = self.snapshot(panes={})
        self.assertTrue(ok)
        session = report["sessions"][0]
        self.assertEqual(session["supervisor_id"], SUP_A)
        self.assertIsNone(session["session_id"])
        self.assertEqual(session["turn"], "unknown")
        self.assertEqual(session["recent_events"], [])

    def test_a_corrupt_journal_line_is_skipped_not_fatal(self):
        transcript = self.transcript(SID_A, [assistant()])
        path = self.journal(SUP_A, [(self.now - 60, 1, "SessionStart", SID_A,
                                     transcript)])
        with open(path, "a") as handle:
            handle.write("{not json\n")
            handle.write(json.dumps({"schema": "someone_elses@1"}) + "\n")
        self.write_proc(4001, ["claude"], self.child_env(), ppid=1)
        report, _ok = self.snapshot(panes={})
        self.assertEqual(report["sessions"][0]["session_id"], SID_A)

    def test_an_unreadable_process_table_is_not_an_empty_fleet(self):
        self.usage([{"name": "acct-a", "windows": {}}])
        report, ok = ops_status.snapshot(
            now=self.now, proc_root=os.path.join(self.temp.name, "gone"),
            panes={}, fallback_path=os.path.join(self.temp.name, "absent"))
        # the usage feed still read, so the report is real — just sessionless
        self.assertTrue(ok)
        self.assertEqual(report["sessions"], [])
        self.assertEqual(len(report["seats"]), 1)

    def test_nothing_readable_is_the_only_nonzero_exit(self):
        report, ok = ops_status.snapshot(
            now=self.now, proc_root=os.path.join(self.temp.name, "gone"),
            panes={}, fallback_path=os.path.join(self.temp.name, "absent"))
        self.assertFalse(ok)
        # even then the output is valid JSON of the declared schema
        self.assertEqual(report["schema"], "headroom_ops_status@1")
        self.assertEqual(report["sessions"], [])
        self.assertEqual(report["seats"], [])


# --- the command ------------------------------------------------------------

class Command(OpsStatusCase):

    def cli(self):
        """The dispatcher, pointed at this test's synthetic host."""
        absent = os.path.join(self.temp.name, "absent.json")
        return (mock.patch.object(ops_status, "PROC_ROOT", self.proc),
                mock.patch.object(ops_status, "FALLBACK_USAGE_PATH", absent),
                mock.patch.object(ops_status, "tmux_panes", return_value={}))

    def test_dispatch_prints_json_and_exits_zero(self):
        self.one_live_session()
        self.usage([{"name": "acct-a", "windows": {}}])
        buffer = io.StringIO()
        proc, fallback, panes = self.cli()
        with proc, fallback, panes, redirect_stdout(buffer):
            code = __main__._dispatch(["ops-status", "--json"])
        self.assertEqual(code, 0)
        report = json.loads(buffer.getvalue())
        self.assertEqual(report["schema"], "headroom_ops_status@1")
        self.assertEqual(report["sessions"][0]["session_id"], SID_A)

    def test_dispatch_without_the_flag_is_the_same_report(self):
        buffer = io.StringIO()
        proc, fallback, panes = self.cli()
        with proc, fallback, panes, redirect_stdout(buffer):
            self.assertEqual(__main__._dispatch(["ops-status"]), 0)
        self.assertEqual(json.loads(buffer.getvalue())["schema"],
                         "headroom_ops_status@1")

    def test_an_unknown_flag_is_refused(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(
                __main__._dispatch(["ops-status", "--restart-everything"]), 2)
        self.assertEqual(buffer.getvalue(), "")

    def test_help_advertises_the_command(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(__main__._dispatch(["--help"]), 0)
        self.assertIn("ops-status", buffer.getvalue())

    def test_the_command_writes_nothing(self):
        self.one_live_session()
        self.ctx(SID_A, 40)
        self.usage([{"name": "acct-a", "windows": {}}])

        def tree(root):
            listing = {}
            for base, _dirs, names in os.walk(root):
                for name in names:
                    path = os.path.join(base, name)
                    stat = os.stat(path)
                    listing[path] = (stat.st_size, stat.st_mtime_ns)
            return listing

        watched = (paths.base_dir(), self.home)
        before = {root: tree(root) for root in watched}
        buffer = io.StringIO()
        proc, fallback, panes = self.cli()
        with proc, fallback, panes, redirect_stdout(buffer):
            __main__._dispatch(["ops-status", "--json"])
        self.assertEqual({root: tree(root) for root in watched}, before)


# --- the supervisor contract this command is built on -----------------------

class SupervisorContract(OpsStatusCase):
    """`_turn_is_complete` answers with PROSE, and this command classifies
    that prose. Pin the mapping against the real function so a reworded
    reason cannot silently turn a mid-turn session into an idle one."""

    def test_turn_state_mapping_matches_the_real_reasons(self):
        complete = self.transcript(SID_A, [user(), assistant()])
        self.assertEqual(
            ops_status._turn_state(supervisor._turn_is_complete(complete)),
            "complete")
        pending = self.transcript(SID_B, [assistant(), user()])
        self.assertEqual(
            ops_status._turn_state(supervisor._turn_is_complete(pending)),
            "in_flight")
        empty = self.transcript("empty", [])
        self.assertEqual(
            ops_status._turn_state(supervisor._turn_is_complete(empty)),
            "unknown")

    def test_an_unrecognised_reason_reads_as_busy(self):
        # fail closed: an ops layer must never restart on a reason it does
        # not recognise
        self.assertEqual(ops_status._turn_state("something new happened"),
                         "in_flight")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
