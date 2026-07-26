#!/usr/bin/env python3
"""Fake Claude CLI used by supervisor integration tests."""
import json
import os
import signal
import subprocess
import sys
import time
import uuid


def slug(_cwd):
    return "fake-project"


def hook(settings, name, payload):
    if not settings:
        return
    config = json.load(open(settings, encoding="utf-8"))
    rows = config.get("hooks", {}).get(name, [])
    if not rows:
        return
    command = rows[0]["hooks"][0]["command"]
    subprocess.run(command, shell=True, input=json.dumps(payload), text=True,
                   check=True, env=os.environ.copy())


def session_id(slot, generation, transition=""):
    suffix = f"-{transition}" if transition else ""
    return str(uuid.uuid5(
        uuid.NAMESPACE_DNS, f"headroom-fake-{slot}-{generation}{suffix}"))


def append_event(path, event):
    with open(path, "a", encoding="utf-8", newline="\n") as out:
        out.write(json.dumps(event) + "\n")
        out.flush()
        os.fsync(out.fileno())


def main():
    args = sys.argv[1:]
    settings = ""
    if "--settings" in args:
        index = args.index("--settings")
        settings = args[index + 1]
        del args[index:index + 2]
    scenario = os.environ.get("FAKE_CLAUDE_SCENARIO", "handoff")
    slot = os.environ.get("HEADROOM_SOURCE_SLOT", "recovery")
    generation = int(os.environ.get("HEADROOM_CHILD_GENERATION", "0"))
    state = os.environ.get("FAKE_CLAUDE_STATE", "/tmp")
    os.makedirs(state, exist_ok=True)
    with open(os.path.join(state, "launches.jsonl"), "a", encoding="utf-8",
              newline="\n") as out:
        out.write(json.dumps({
            "args": args, "config_dir": os.environ.get("CLAUDE_CONFIG_DIR", ""),
            "cwd": os.getcwd(), "slot": slot, "generation": generation,
        }) + "\n")
    if scenario == "foreground":
        ok = os.getpgrp() == os.tcgetpgrp(0)
        received = {"signal": ""}

        def foreground_signal(signum, _frame):
            received["signal"] = signal.Signals(signum).name

        # Install BEFORE announcing readiness: the test sends ^C the instant
        # it sees PGRP_OK, so printing first raced the handler installation
        # and the child died of KeyboardInterrupt (an intermittent failure of
        # this test that has nothing to do with what it asserts).
        signal.signal(signal.SIGINT, foreground_signal)
        signal.signal(signal.SIGTERM, foreground_signal)
        print("PGRP_OK" if ok else "PGRP_BAD", flush=True)
        deadline = time.time() + 3
        while not received["signal"] and time.time() < deadline:
            time.sleep(0.02)
        print(received["signal"] + "_OK", flush=True)
        return 0
    if not settings:
        with open(os.path.join(state, "recovered"), "a", encoding="utf-8") as out:
            out.write(" ".join(args) + "\n")
        return 0
    if scenario == "banner":
        print("You've hit your session limit · resets 12:20pm (UTC)",
              file=sys.stderr, flush=True)
        time.sleep(0.5)
        return 0

    sid = session_id(slot, generation)
    home = os.environ["CLAUDE_CONFIG_DIR"]
    directory = os.path.join(home, "projects", slug(os.getcwd()))
    os.makedirs(directory, exist_ok=True)
    transcript = os.path.join(directory, sid + ".jsonl")
    model_id = os.environ.get(
        "FAKE_CAP_MODEL", "claude-sonnet-4-5-20250929")
    cap_event = {"type": "assistant", "isApiErrorMessage": True,
                 "error": "rate_limit", "apiErrorStatus": 429,
                 "message": {"model": "<synthetic>", "content": [
                 {"type": "text", "text":
                  "You've hit your session limit · resets 12:20pm (UTC)"}]}}
    with open(transcript, "w", encoding="utf-8", newline="\n") as out:
        if scenario == "corrupt":
            out.write('{"type":')
        else:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "hello"}]}}) + "\n")
            out.write(json.dumps({"type": "assistant", "message": {
                "model": model_id, "content": [
                    {"type": "text", "text": "real assistant turn"}]}}) + "\n")
            out.flush()
            os.fsync(out.fileno())
    common = {"session_id": sid, "transcript_path": transcript,
              "cwd": os.getcwd(), "model": {"display_name": "Sonnet"},
              "version": "2.1.fake"}
    terminated = {"value": False, "count": 0}

    def on_term(_signum, _frame):
        terminated["value"] = True
        terminated["count"] += 1

    # Install BEFORE announcing readiness. SessionStart is what arms the
    # supervisor, and a preemptive rotation can decide to stop an idle child
    # within a poll tick of it — if the handler were still uninstalled, the
    # default disposition would kill this process instantly, with no
    # sigterm_flush and no SessionEnd. A real CLI has its handlers up before
    # it announces a session; the fake must too.
    signal.signal(signal.SIGTERM, on_term)
    hook(settings, "SessionStart",
         dict(common, hook_event_name="SessionStart", source="startup"))
    changed_cwd = os.environ.get("FAKE_CHANGED_CWD")
    if changed_cwd and slot == os.environ.get("FAKE_CHANGED_CWD_SLOT", "source"):
        hook(settings, "CwdChanged",
             dict(common, hook_event_name="CwdChanged", cwd=changed_cwd))
    with open(os.path.join(state, "active-slot"), "w", encoding="utf-8") as out:
        out.write(slot)

    cap_slots = set(filter(None, os.environ.get("FAKE_CAP_SLOTS", "source").split(",")))
    is_resume = "--resume" in args
    if scenario in ("handoff", "delayed-flush", "idle",
                    "idle-cap-on-stop") and is_resume:
        time.sleep(0.35)
        return 0
    if scenario == "missing-end" and is_resume:
        time.sleep(0.35)
        return 0
    if slot not in cap_slots and scenario == "loop":
        time.sleep(0.35)
        return 0

    # "idle": a bound, quiescent session that never caps — the child the
    # preemptive path must be able to rotate at a safe boundary.
    # "idle-cap-on-stop": the same, but the seat caps while the preemptive
    # stop is already in flight (StopFailure fired from the SIGTERM handler).
    idle_scenarios = ("idle", "idle-cap-on-stop")
    if scenario not in ("corrupt", "delayed-flush") + idle_scenarios:
        append_event(transcript, cap_event)

    message = "rate limit: try again" if scenario == "transient" else \
        "You've hit your session limit · resets 12:20pm (UTC)"
    if scenario not in idle_scenarios:
        hook(settings, "StopFailure", dict(
            common, hook_event_name="StopFailure", error="rate_limit",
            last_assistant_message=message))
    if scenario == "delayed-flush":
        time.sleep(0.4)
        append_event(transcript, cap_event)

    if scenario in ("clear", "resume-transition"):
        hook(settings, "SessionEnd", dict(
            common, hook_event_name="SessionEnd",
            reason="clear" if scenario == "clear" else "resume"))
        next_sid = session_id(slot, generation, scenario)
        next_transcript = os.path.join(directory, next_sid + ".jsonl")
        with open(next_transcript, "w", encoding="utf-8", newline="\n") as out:
            out.write(json.dumps({"type": "user", "message": {
                "content": [{"type": "text", "text": "replacement"}]}}) + "\n")
            out.flush()
            os.fsync(out.fileno())
        next_common = dict(common, session_id=next_sid,
                           transcript_path=next_transcript)
        hook(settings, "SessionStart", dict(
            next_common, hook_event_name="SessionStart",
            source="clear" if scenario == "clear" else "resume"))
        time.sleep(0.5)
        return 0
    # the preemptive path has to poll usage, prove idleness, admit through the
    # ledger (fsync) and stop us — give it room on a loaded machine so the
    # test measures behaviour, not scheduling luck
    lifetime = 3.0 if scenario == "loop" else 1.5
    if scenario in idle_scenarios:
        lifetime = 3.0
    deadline = time.time() + lifetime
    while time.time() < deadline:
        if terminated["value"]:
            with open(os.path.join(state, "sigterm-" + slot), "a",
                      encoding="utf-8") as out:
                out.write("1\n")
            if scenario == "ignore-term":
                terminated["value"] = False
                continue
            append_event(transcript, {"type": "system",
                                      "subtype": "sigterm_flush"})
            if scenario == "idle-cap-on-stop":
                # the seat caps while the rotation is already stopping us:
                # the hook lands between SIGTERM and SessionEnd
                hook(settings, "StopFailure", dict(
                    common, hook_event_name="StopFailure", error="rate_limit",
                    last_assistant_message="You've hit your session limit"))
            if scenario != "missing-end":
                hook(settings, "SessionEnd",
                     dict(common, hook_event_name="SessionEnd", reason="other"))
            return 0
        time.sleep(0.02)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
