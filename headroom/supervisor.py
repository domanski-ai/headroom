"""Resident, fail-closed Claude auto-handoff supervisor.

One 250 ms loop owns hook ingestion and child lifecycle.  Hook evidence never
terminates a child by itself: it must be bound to the current child, match a
narrow subscription-cap phrase, and be corroborated by a fresh identity-bound
usage collect before every remaining pre-stop check succeeds.
"""
import contextlib
import copy
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field, replace

try:
    import termios
except ImportError:  # Windows has no POSIX terminal settings API.
    termios = None

from . import collect, handoff, locks, notify, paths, registry, route

UNSUPERVISED_MESSAGE = (
    "supervision requires a Unix terminal — launching unsupervised")

POLL_SECONDS = 0.25
BIND_TIMEOUT = 30.0
TERM_TIMEOUT = 10.0
QUIET_SECONDS = 5.0
CAP_MODEL_TIMEOUT = QUIET_SECONDS + 1.0
LOOP_WINDOW = 10 * 60
LOOP_MAX = 3
MAX_HOOK_BYTES = 1024 * 1024

# --- preemptive rotation cadence -------------------------------------------
# Cap-reactive handoff only fires once the provider has already refused a
# turn. A seat that climbs to 97% while the session sits idle strands the
# operator instead: they notice the percentage, /exit, and hand off by hand.
# The preemptive poll closes that gap by rotating at a threshold, at a SAFE
# BOUNDARY (an idle child), through the exact same handoff pipeline.
#
# Every number here is a cadence, not a safety bound — the safety bounds are
# the unchanged handoff guards. Poll rarely (usage windows move in minutes,
# not milliseconds), demand a long quiet period so an active turn is never
# interrupted, and back off hard when a crossing cannot be acted on so a
# stranded session does not retry (or notify) every tick.
PREEMPT_POLL_SECONDS = max(5.0, float(
    paths.env_int("HEADROOM_PREEMPTIVE_POLL_SECONDS", 60)))
PREEMPT_BACKOFF_SECONDS = max(PREEMPT_POLL_SECONDS, float(
    paths.env_int("HEADROOM_PREEMPTIVE_BACKOFF_SECONDS", 300)))
PREEMPT_IDLE_SECONDS = max(QUIET_SECONDS, float(
    paths.env_int("HEADROOM_PREEMPTIVE_IDLE_SECONDS", 60)))
# how long an observed crossing stays actionable: the analogue of the cap
# path's "the proven cap reset is still in the future" admission gate
PREEMPT_DECISION_TTL = max(PREEMPT_IDLE_SECONDS + 10.0, float(
    paths.env_int("HEADROOM_PREEMPTIVE_DECISION_TTL", 120)))
# reuse the fleet's own usage feed when it is this fresh before paying for a
# private collect (a running `headroom serve` refreshes it continuously)
PREEMPT_SNAPSHOT_MAX_AGE = max(30, paths.env_int(
    "HEADROOM_PREEMPTIVE_SNAPSHOT_MAX_AGE", 300))
# How much better a target's 5h window must be before moving there ANSWERS a
# 5h crossing. Leaving a seat at 97% for one at 96% is not a rotation, it is a
# restart with a five-minute reprieve: the successor trips the same threshold
# almost immediately and the loop guard, not the routing, ends up doing the
# thinking. Only applied to a 5h-triggered rotation — for a spent WEEKLY
# window a target with a busy-but-healing 5h is still a fine place to be.
PREEMPT_SESSION_MARGIN = max(0.0, float(
    paths.env_int("HEADROOM_PREEMPTIVE_SESSION_MARGIN", 10)))

# --- waiting out a cap -----------------------------------------------------
# A cap arrives and there is nowhere to go: every seat is capped too. The old
# answer was to disarm this child permanently, on the capped seat, while it is
# still alive — so when a seat came back forty minutes later, nothing rotated
# and nothing said why. Nobody is watching a percentage at 3am; that is the
# whole reason this program exists.
#
# So a capacity refusal HOLDS instead. The child keeps running, automation
# stays armed, and the proof is re-tried on this cadence until a seat frees
# up, until the cap's own window resets (which ends the hold — see
# CapCleared), or until the budget runs out and it disarms exactly as before.
# The bound is what keeps it honest: a fleet where every account is capped
# retries at this interval and then stops, rather than collecting forever.
CAP_HOLD_SECONDS = max(30.0, float(
    paths.env_int("HEADROOM_CAP_HOLD_SECONDS", 300)))
# 60 × 300s ≈ five hours: long enough to outlast a 5h window (the common
# case — every seat capped on the same 5h clock), short enough that a
# permanently capped fleet stops paying for collects the same day.
# HEADROOM_CAP_HOLD_MAX=0 restores the pre-hold behaviour exactly: the first
# capacity refusal disarms.
CAP_HOLD_MAX = max(0, paths.env_int("HEADROOM_CAP_HOLD_MAX", 60))
# Mid-hold, fresh usage can legitimately resolve to a DIFFERENT cooldown key
# than the one the hold recorded — the 5h window fills behind a scoped weekly
# pool and the account-wide scope starts winning. The recorded scope stays
# immutable either way (only the cap it corroborated may ever move a session),
# but "different key" used to have only two endings: the recorded window reads
# below 99 and the cap is over, or it holds as "not readable". A recorded
# window sitting at a readable, legitimate 100% fell into the second and could
# never proceed — so the session waited out the whole budget with a free seat
# in front of it and then disarmed on the capped account.
# HEADROOM_CAP_ROTATE_AT_WALL=0 restores that two-outcome behaviour.
CAP_ROTATE_AT_WALL = os.environ.get("HEADROOM_CAP_ROTATE_AT_WALL", "1") != "0"
# How many extra CAP_MODEL_TIMEOUT windows the cap-time model lookup may wait
# before the child is disarmed. A transcript that has not yet been flushed is
# not a contradicted proof, and 6s is a short window to bet a session on.
# HEADROOM_CAP_MODEL_RETRIES=0 restores the single-window behaviour.
CAP_MODEL_RETRIES = max(0, paths.env_int("HEADROOM_CAP_MODEL_RETRIES", 2))
# How many extra collects the cap path may spend waiting out ANOTHER
# collector. `collect.run_collect` takes the collection lock nonblocking and,
# on contention, returns the PREVIOUS snapshot from disk with no exception and
# no sentinel — so a skip reads as success, and its stale `run_started` then
# reads as "collect did not start after the cap event" and disarms a live
# session. Three serve daemons and every resident supervisor on a busy box
# drive run_collect, and one run spans several seconds, so the window is open
# a real fraction of every minute.
# HEADROOM_COLLECT_RETRIES=0 restores the single-attempt behaviour.
COLLECT_CONTENTION_RETRIES = max(0, paths.env_int("HEADROOM_COLLECT_RETRIES", 4))
# What a CAPPED session may be moved onto. The routing gate rejects a seat at
# 100%, critical, under reserve or unreadable — and nothing else, so a seat
# reading 99% was a legal destination for a real cap: a handoff, a restart and
# a third of the loop budget spent to arrive at the same wall.
#
# The bar here is deliberately LOWER than the preemptive one. A preemptive
# rotation is elective, so it can demand margin; a capped source is already
# refusing, so demanding margin would strand a dead session over a merely busy
# seat. All this asks is that the destination is not itself about to refuse —
# and how close "about to" is depends on how long the window runs. 97% of a
# five-hour window is nine minutes; 97% of a week is most of a working day.
# The 5h ceiling is therefore the same "the wall is imminent" number the 5h
# trigger uses, and the weekly one is its own, later number.
# HEADROOM_CAP_TARGET_WEEKLY=100 restores the routing gate's own bar.
CAP_TARGET_WEEKLY_PERCENT = min(100.0, max(0.0, float(
    paths.env_int("HEADROOM_CAP_TARGET_WEEKLY", 99))))
# THE TRAIN KEEPS MOVING (Paul's rule, 2026-07-31). When every seat is walled
# for the family a session was running, holding the conversation until the
# window resets is the wrong answer: a WEAKER family on a healthy seat keeps
# the work alive, and the operator can move back up later. Strongest first;
# the walk starts one past the capped family, so a cap can only ever move a
# session DOWN the ladder, never promote it onto capacity it just exhausted.
# Set HEADROOM_FAMILY_FALLBACK=0 to restore hold-instead-of-downgrade.
FAMILY_LADDER = ("fable", "opus", "sonnet", "haiku")
FAMILY_FALLBACK_ENABLED = os.environ.get("HEADROOM_FAMILY_FALLBACK", "1") != "0"
# how much of a transcript's END the poll parses (see _transcript_records)
TRANSCRIPT_TAIL_BYTES = max(64 * 1024, paths.env_int(
    "HEADROOM_TRANSCRIPT_TAIL_BYTES", 256 * 1024))
# bound on the sidechain scan that proves no background agent is working
MAX_SUBAGENT_SCAN = max(64, paths.env_int("HEADROOM_MAX_SUBAGENT_SCAN", 512))
# a sidechain only has to be judged by its last few records, so its tail is
# much smaller than the main transcript's — the scan may touch many files
SIDECHAIN_TAIL_BYTES = max(8 * 1024, paths.env_int(
    "HEADROOM_SIDECHAIN_TAIL_BYTES", 32 * 1024))

# --- context: the OTHER wall -----------------------------------------------
# Usage caps are not the only way a session dies. A long parent session fills
# its context window, and at 0% remaining the conversation is simply over —
# with whatever was not written down lost with it.
#
# The intended answer is COOPERATIVE and lives outside this process: a
# UserPromptSubmit hook measures the same numbers below and, from 30%
# remaining, instructs the session every turn to write a baton and refresh
# itself. That path produces a considered handoff and must be allowed to win.
#
# This is the fail-safe UNDER it, for a session that ignores the nudge — one
# wedged in a loop, or spending its last context in a single long turn. At a
# far later threshold (10% remaining) the supervisor forces ONE lossless
# rotation of its own: the same stop + `--resume --fork-session` pipeline,
# on the SAME seat. Nothing is cleared — the fork carries the whole
# conversation — and the window-fit rule below puts it on a model whose
# context window can actually hold it.
#
# Transcripts do not record the context window, so it is inferred exactly the
# way the hook infers it, from the usage the provider charged:
CONTEXT_WINDOW_STANDARD = 200_000
CONTEXT_WINDOW_LARGE = 1_000_000
# Usage above this ceiling can only have been served by the 1M-token window: a
# standard-window session would have been REFUSED ("Prompt is too long")
# instead of being charged for it. So this one number does two jobs — it
# infers the window, and it decides whether a transcript may be resumed under
# the standard window at all (see _window_fit_argv; a resume that ignores it
# dies on its first prompt, observed twice in production 2026-07-27).
CONTEXT_WINDOW_FIT_LIMIT = max(1, paths.env_int(
    "HEADROOM_CONTEXT_FIT_LIMIT", 205_000))
# The model an over-limit transcript must be resumed with. It is a MODEL
# choice, not a family choice: only the 1M-window variants can hold such a
# transcript, so a session that outgrew the standard window continues on this
# one whatever it was running before.
CONTEXT_FIT_MODEL = (os.environ.get("HEADROOM_CONTEXT_FIT_MODEL", "").strip()
                     or "opus[1m]")
# A resume argv names only `--resume`/`--fork-session`, so a child KNOWN to be
# on the 1M window would silently come back on the standard one. Below this
# much free space in a standard window, that shrink is not acceptable — the
# successor would be born inside the warning zone the cooperative handoff
# exists for, and would have to rotate again immediately. Above it, shrinking
# is harmless and family routing wins.
CONTEXT_KEEP_LARGE_PERCENT = 30.0
# How many forced context rotations this supervisor may perform in one
# LOOP_WINDOW. The analogue of the handoff ledger's loop guard, kept local
# because a same-seat rotation reserves nothing: it moves no account, cools
# nothing, and must never spend the ledger budget a genuine cap needs. The
# bound matters because a fork INHERITS its parent's usage records, so a
# rotation that cannot change the window (already on 1M) would otherwise
# observe the same crossing again on the next poll, forever.
CONTEXT_BACKSTOP_MAX = max(1, paths.env_int("HEADROOM_CONTEXT_BACKSTOP_MAX", 2))
# A forced rotation is only worth its restart if the successor gets a window
# the conversation actually fits in. A session already on the 1M window has
# nowhere bigger to go: forking it would carry the same tokens into the same
# ceiling, cost the user a restart, and change nothing. By default the
# backstop refuses that (loudly — the operator is the only one who can save
# such a session); HEADROOM_CONTEXT_BACKSTOP_ALWAYS=1 forces it anyway.
CONTEXT_BACKSTOP_ALWAYS = (
    os.environ.get("HEADROOM_CONTEXT_BACKSTOP_ALWAYS", "").strip() == "1")

# The cap vocabulary is route's, not a second copy of it (see route.CAP_RE).
# This file held the copy that drifted: it knew "out of usage credits" and did
# NOT know "hit your 5-hour limit", which route has always matched, so a
# 5-hour refusal worded that way never reached the cap-reactive path and the
# session sat on a dead seat. Transient 429/overload stay out of it — those
# are retried on the same seat, never rotated.
CAP_RE = route.CAP_RE

# Background-agent lifecycle, as the parent transcript actually records it.
# Every discriminator below is pinned from live fleet data (50 sessions):
#
#   launch    a `user` record whose message content holds the Agent tool's own
#             `tool_result` block, whose text carries "agent launched
#             successfully … agentId: <id>"  (139 in the fleet)
#   finish    a `user` record the HARNESS injects, marked
#             origin={"kind": "task-notification"} (promptSource "system"),
#             whose message content is the XML STRING itself  (659 in the
#             fleet; no genuine notification has any other shape)
#   statuses  completed / failed / killed / stopped — the complete observed
#             vocabulary. "stopped" is terminal-but-resumable; a later
#             SendMessage re-arms it. An UNKNOWN status is NEVER terminal.
#
# Shape decides, never text: the same XML also appears quoted inside other
# tools' results (a Bash tool that cats a transcript — there is exactly such
# a record in the fleet today), inside queue-operation and attachment
# records, and in assistant prose. Retiring an agent on any of those would
# let a copied envelope bearing a LIVE agent's id clear the way for its
# SIGTERM, so only the authoritative record shape may mark an agent finished.
BACKGROUND_LAUNCH_RE = re.compile(
    r"agent launched successfully.{0,400}?agentId:\s*([0-9A-Za-z_-]{4,})",
    re.I | re.S)
TASK_ID_RE = re.compile(r"<task-id>\s*([0-9A-Za-z_-]{4,})\s*</task-id>")
TASK_STATUS_RE = re.compile(r"<status>\s*([A-Za-z_-]+)\s*</status>")
TERMINAL_TASK_STATUS = {"completed", "failed", "killed", "stopped"}
TASK_NOTIFICATION_ORIGIN = "task-notification"

HOOK_EVENTS = {"SessionStart", "StopFailure", "CwdChanged", "SessionEnd"}
INCOMPATIBLE_FLAGS = {
    "--bare", "--safe-mode", "--disable-all-hooks", "--print", "-p",
    "--output-format", "--input-format", "--no-session-persistence",
}
# --- Claude's own option grammar -------------------------------------------
# Audited option-by-option against the top-level `claude` command table in
# Claude Code 2.1.220 (its whole `.option(...)` chain, hidden entries
# included). Every headroom argv walker has to see the argv Claude will see,
# and commander parses THREE classes differently:
#
#   `<value>` / `<values...>`  required — ALWAYS consumes the next token
#   `[value]`                  optional — consumes the next token only when it
#                              does not itself look like an option
#   everything else            boolean  — consumes nothing
#
# Getting a class wrong is not cosmetic. `--ide` sat in the required list and
# is boolean, and `--resume`/`-r` sat there and are optional, so
# `--ide --settings user.json` and `--resume --settings user.json` walked
# straight PAST the user's settings: the flag stayed on the child's argv
# beside the supervisor's own, and Claude honours the last one. The opposite
# error is just as real — a required option missing from the table (`--agent`
# was) lets its VALUE be read as an option.
CLAUDE_VALUE_FLAGS = {
    "--add-dir", "--advisor", "--agent", "--agent-color", "--agent-id",
    "--agent-name", "--agent-type", "--agents", "--allowed-tools",
    "--allowedTools", "--append-subagent-system-prompt",
    "--append-system-prompt", "--append-system-prompt-file", "--betas",
    "--channels", "--dangerously-load-development-channels",
    "--debug-file", "--deep-link-cwd-b64", "--deep-link-last-fetch",
    "--deep-link-repo", "--disallowed-tools", "--disallowedTools",
    "--effort", "--fallback-model", "--file", "--input-format",
    "--json-schema", "--managed-settings", "--max-budget-usd",
    "--max-thinking-tokens", "--max-turns", "--mcp-config", "--model",
    "-n", "--name", "--output-format", "--parent-session-id",
    "--permission-mode", "--permission-prompt-tool",
    "--plan-mode-instructions", "--plugin-dir", "--plugin-dir-no-mcp",
    "--plugin-url", "--prefill", "--prefill-b64",
    "--remote-control-session-name-prefix", "--resume-session-at",
    "--rewind-files", "--sdk-url", "--session-id", "--setting-sources",
    "--settings", "--system-prompt", "--system-prompt-file", "--task-budget",
    "--team-name", "--teammate-mode", "--thinking", "--thinking-display",
    "--tools", "--workload",
}
# `[value]` options. Commander's own rule: the following token is the value
# only when it is not option-shaped, which is exactly why `--resume
# --settings x` leaves `--settings x` to be parsed as settings.
CLAUDE_OPTIONAL_VALUE_FLAGS = {
    "--cloud", "-d", "--debug", "--from-pr", "--prompt-suggestions", "--rc",
    "--remote", "--remote-control", "-r", "--resume", "--teleport",
    "-w", "--worktree",
}
# Every other maintained Claude flag (--ide, --brief, --fork-session, --tmux,
# --chrome, …) is the boolean complement.  Unknown flags are boolean too; only
# the two tables above may consume the following argument.
HEADROOM_OVERRIDE_FLAGS = {
    "--headroom-auto-handoff", "--headroom-no-auto-handoff",
    "--headroom-launch-fallback"}

# --- user --settings, merged rather than obeyed ----------------------------
# Claude takes ONE `--settings` (a path or an inline JSON string); a second
# occurrence replaces the first. Passing the user's file straight through
# would therefore DELETE the supervisor's injected hooks — no SessionStart
# handshake, no cap rotation, no context backstop, no journal — so the
# supervisor takes the flag off the child's argv, merges the user's document
# UNDER its own, and writes the single file it owns. Supervision is never
# traded away for a settings file: an unmergeable document refuses the launch.
#
# Two settings keys can suppress hooks outright. There is no merge that keeps
# supervision armed once either is set, so either one is a refusal.
HOOK_RESTRICTING_KEYS = ("disableAllHooks", "allowManagedHooksOnly")
# Environment a settings `env` block may NOT set, by NAMESPACE rather than by
# name. The hook process inherits the child's environment, so this list is
# the CLI's whole execution-control surface plus headroom's own — and an
# enumeration of it is unprovable: naming CLAUDE_CODE_SAFE_MODE and
# CLAUDE_CODE_SIMPLE missed CLAUDE_CODE_SHELL_PREFIX (which REPLACES the
# command that gets spawned), CLAUDE_CODE_SHELL, CLAUDE_CODE_PROCESS_WRAPPER,
# the sandbox switches, and HEADROOM_DIR (which moves the whole state tree
# the adapter writes into). Any release can add another.
#
# So the rule is the namespace, not the name: neither surface may be
# reconfigured by the document the surface is reading. `CLAUDE_*` covers
# CLAUDE_CONFIG_DIR and every CLAUDE_CODE_* execution knob, present and
# future; `HEADROOM_*` covers every variable the hook adapter authenticates
# against. HOME/USERPROFILE are named explicitly because they sit in no
# namespace and relocate `~/.headroom` — the same redirection by another
# route.
#
# An ALLOWLIST was considered and rejected: passing the operator's own
# variables through is the whole point of merging an `env` block, and there
# is no finite set of "safe" names to enumerate. See also `_hook_command`,
# which pins the event path INTO the command so a redirection cannot depend
# on this check being complete, and the 30-second handshake timeout, which is
# what actually makes an unrunnable hook fail closed and loudly.
RESERVED_SETTINGS_ENV = ("HOME", "USERPROFILE")
RESERVED_SETTINGS_ENV_PREFIXES = ("CLAUDE_", "HEADROOM_")
# CLI flags that suppress the injected hooks no matter what the merged
# document says, and so cannot be merged at all. `--managed-settings` loads a
# POLICY document, and policy sits ABOVE flag settings: an
# `allowManagedHooksOnly` or `strictPluginOnlyCustomization` in there turns
# the injected hooks off and nothing in the merged document can answer for it
# (the standing managed-policy caveat in docs/KNOWN-LIMITS.md). There is
# nothing to merge, so it is refused by name like an unmergeable key.
HOOK_SUPPRESSING_FLAGS = ("--managed-settings",)
# How deep a settings document may nest. Every step of the merge recurses
# (parse, deep copy, serialize), and a RecursionError raised anywhere in there
# is a bare RuntimeError that the launch guard would answer by bare-execing —
# unsupervised, with the very document it could not read. Whether the
# interpreter raises at all depends on how deep the stack already was, so the
# refusal cannot be left to it: the depth is measured ITERATIVELY and refused
# by policy, with the RecursionError catches kept only as a backstop. Real
# settings are five or six levels deep; this is an order of magnitude of room.
MAX_SETTINGS_DEPTH = 64


class SupervisorError(RuntimeError):
    """A fail-closed supervisor refusal."""


class UserSettingsError(SupervisorError):
    """A user `--settings` document that cannot be merged under supervision.

    Its own class because it is the ONE refusal that must never degrade into a
    bare CLI exec: falling back would run exactly the unsupervised child this
    merge exists to prevent."""


class PermanentSupervisorError(SupervisorError):
    """A child-local condition that cannot become safe on a later hook."""


class PendingCapTimeout(PermanentSupervisorError):
    """A payload-proven cap whose transcript model never became available."""


class CapacityHold(SupervisorError):
    """A proven cap that cannot be acted on YET, and might be later.

    The proof is intact and uncontradicted; what is missing is somewhere to go
    (no seat has headroom) or the means to look (the collect failed). Neither
    says the cap is false, and both fix themselves.

    Every OTHER cap-path refusal disarms this child permanently, which is
    right for a proof that was contradicted and catastrophic for one that was
    merely unlucky: the session is sitting on the capped seat, which is the
    one state where it most needs the rotation it just gave up on. So this
    class holds instead — bounded, backed off, and disarming in the end if
    capacity never comes back."""


class CapCleared(SupervisorError):
    """The proven cap is over: its own window reset while we were holding.

    Not a failure and not a retry — there is nothing left to rotate away
    from. Drop the proof, leave automation armed for the next one."""


@dataclass(frozen=True)
class Binding:
    session_id: str
    transcript_path: str
    cwd: str
    model: str
    version: str
    config_dir: str
    epoch: int = 0
    received_at: float = 0.0


@dataclass(frozen=True)
class CapProof:
    event: dict
    message: str
    family: str
    session_id: str
    transcript_path: str
    epoch: int
    transcript_stat: tuple
    preemptive: bool = False


@dataclass(frozen=True)
class PreemptiveProof:
    """A threshold crossing on an idle child — deliberately shape-compatible
    with :class:`CapProof` so every shared guard (`_proof_current`,
    `_events_pending`, `_stop_and_commit`, `_consume_stop_events`) treats it
    identically.  It proves far LESS than a CapProof (no provider refusal, no
    cap-time model from an API-error event), which is exactly why acting on it
    is gated on an idle transcript and why any refusal only defers."""
    event: dict
    message: str
    family: str
    session_id: str
    transcript_path: str
    epoch: int
    transcript_stat: tuple
    window: str = ""
    used_percent: float = 0.0
    # the instant this observation stops being actionable; the analogue of
    # the cap path's proven reset, checked at every admission/stop edge
    deadline: float = 0.0
    preemptive: bool = True


@dataclass(frozen=True)
class ContextProof:
    """A measured context crossing on an idle child.

    Shape-compatible with :class:`CapProof` / :class:`PreemptiveProof` for the
    same reason they are compatible with each other: every shared guard
    (`_proof_current`, `_events_pending`, `_event_stop_guard`, `_wait_stopped`,
    `_consume_stop_events`) must treat it identically. It proves nothing about
    usage — only that this session is close to the end of its context window —
    so it may never rotate a seat; it only forks the conversation in place."""
    event: dict
    message: str
    session_id: str
    transcript_path: str
    epoch: int
    transcript_stat: tuple
    used: int = 0
    window: int = 0
    remaining_percent: float = 0.0
    deadline: float = 0.0
    # this is NOT a usage-threshold rotation: it must never reach the cap
    # path's commit deadline or the preemptive notify/ledger vocabulary
    preemptive: bool = False
    backstop: bool = True


@dataclass(frozen=True)
class PendingCap:
    event: dict
    session_id: str
    transcript_path: str
    epoch: int
    received_at: float
    deadline: float
    # how many extra CAP_MODEL_TIMEOUT windows this lookup has already been
    # given (bounded by CAP_MODEL_RETRIES)
    extensions: int = 0


@dataclass
class Child:
    process: subprocess.Popen
    account: dict
    generation: int
    event_path: str
    settings_path: str
    launched_at: float
    automation: bool
    binding: Binding = None
    session_ended: bool = False
    session_end_received_at: float = 0.0
    session_epoch: int = 0
    event_offset: int = 0
    hint_printed: bool = False
    resume_bound: bool = False
    dead_sessions: set = field(default_factory=set)
    session_epochs: dict = field(default_factory=dict)
    last_received_at: float = 0.0
    # fingerprints of the records already accepted AT last_received_at, which
    # is what tells a duplicate apart from a clock-resolution tie
    last_received_ids: set = field(default_factory=set)
    pending_cap: PendingCap = None
    # a proven cap that has nowhere to go yet: how many times it has been
    # re-tried, when the next attempt is due, and the last reason announced
    cap_hold_attempts: int = 0
    cap_hold_next: float = 0.0
    cap_hold_reason: str = ""
    # which proof the hold above belongs to; a different one resets it
    cap_hold_key: tuple = ()
    # WHICH cap fresh usage corroborated: the cooldown key it would spend
    # ("<account>:*" / "<account>:<family>") and the window that proved it
    # ("5h", "7d", "scoped:<family>"; "" = none yet). Written once per proof
    # and never rewritten — a retry that finds a DIFFERENT scope has found a
    # different cap, and only the recorded window may say this one is over.
    cap_scope_key: str = ""
    cap_scope_window: str = ""
    # the last disarm reason already notified ("" / False = none yet)
    supervision_loss_notified: object = False
    # preemptive rotation state (never affects the cap-reactive path)
    preemptive_next_check: float = 0.0
    preemptive_announced: bool = False
    preemptive_last_hold: str = ""
    # the argv this child was spawned with: an explicit `--model …[1m]` is
    # KNOWLEDGE about its context window, better than any inference
    spawn_args: tuple = ()
    # context backstop state (independent of both paths above)
    context_next_check: float = 0.0
    context_announced: bool = False
    context_last_hold: str = ""


@dataclass(frozen=True)
class Recovery:
    """How to bring a session back when its REPLACEMENT could not be spawned.

    The account-to-account paths carry a `HandoffPlan` for this, and run()
    recovers the source from it. A same-seat context rotation has no plan (it
    reserves nothing and moves nothing), so it carries this instead: without
    it an unambiguous spawn failure after an ELECTIVE stop exits 127 on a
    session that was already stopped — the exact "strand the user" outcome the
    rotation exists to prevent."""
    account: dict
    argv: list
    cwd: str
    session_id: str
    reason: str = "context_backstop"

    def command(self):
        """This recovery as a command a human can paste.

        Built from the stored argv itself, never re-derived: the argv already
        encodes both things a reconstruction gets wrong — the model a large
        transcript must be resumed on, and whether forking is safe.

        A resume argv is `--resume`/`--fork-session`/`--model` and carries no
        user document today, so the redaction is a no-op here — it is applied
        anyway so that "an argv headroom prints never reproduces a document"
        is a property of every renderer rather than an argument about one."""
        return (f"CLAUDE_CONFIG_DIR={shlex.quote(self.account['home'])} "
                + redacted_command(["claude"] + list(self.argv)))


@dataclass(frozen=True)
class Relaunch:
    account: dict
    argv: list
    cwd: str
    automatic: bool
    handoff_id: str = ""
    plan: object = None
    reason: str = "cap"
    # Whether the relaunched child is supervised. None = "same as automatic",
    # which is every pre-existing case: an automatic rotation is supervised
    # and a cap recovery deliberately is not. Only an ABORTED preemptive
    # rotation sets it independently — that source is not capped, so it is
    # recovered with auto-handoff still armed.
    supervised: object = None
    # What to fall back to if THIS relaunch cannot be spawned (see Recovery).
    # Only the planless same-seat rotation needs it; every other path recovers
    # from its plan.
    recovery: object = None


def _lose_supervision(child, reason):
    """Turn automation off for this child and notify the loss.

    Post-spawn supervision loss is exactly what an external dispatcher cannot
    see on its own: the launch looked supervised, but auto-handoff will
    silently not fire. Every stderr diagnostic at each call site is unchanged;
    this adds the structured event, so a dashboard can surface an unprotected
    session. The notify is a no-op unless HEADROOM_NOTIFY_CMD is set.

    Dedupe is per REASON, not per child: a disarm that repeats on every 250 ms
    poll (e.g. the bind timeout) notifies once, but a genuinely different
    later disarm is never swallowed into silence by the first one."""
    child.automation = False
    reason = str(reason)
    if child.supervision_loss_notified == reason:
        return
    child.supervision_loss_notified = reason
    notify.emit({"event": "supervision_lost",
                 "account": child.account.get("name", ""),
                 "reason": reason})


def _supervisors_dir():
    return os.path.join(paths.state_dir(), "supervisors")


def event_path(supervisor_id):
    return os.path.join(_supervisors_dir(), supervisor_id + ".jsonl")


def _model_name(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("display_name", "displayName", "name", "model"):
            if isinstance(value.get(key), str):
                return value[key]
    return ""


def _hook_executable():
    override = os.environ.get("HEADROOM_EXECUTABLE")
    if override:
        return override
    installed = shutil.which("headroom")
    if installed:
        return installed
    return os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "bin", "headroom")


def _hook_command(matcher=""):
    command = shlex.quote(_hook_executable()) + " _hook-event"
    if matcher:
        command = "HEADROOM_HOOK_MATCHER=" + shlex.quote(matcher) + " " + command
    # Pin the state tree INTO the command. The hook process inherits the
    # child's environment, so a settings `env` (or anything else) that moved
    # HEADROOM_DIR — or HOME, where the default `~/.headroom` lives — would
    # send every event into a different tree: hooks that run perfectly while
    # the supervisor waits deaf and disarms at the 30-second timeout. A shell
    # assignment on the command line beats any inherited value, so the event
    # path is fixed here, at launch, and does not depend on the reserved-env
    # check catching every name that could point it elsewhere.
    return ("HEADROOM_DIR=" + shlex.quote(paths.base_dir()) + " " + command)


def hook_settings():
    normal = {"type": "command", "command": _hook_command()}
    limited = {"type": "command", "command": _hook_command("rate_limit")}
    return {"hooks": {
        "SessionStart": [{"hooks": [normal]}],
        "StopFailure": [{"matcher": "rate_limit", "hooks": [limited]}],
        "CwdChanged": [{"hooks": [normal]}],
        "SessionEnd": [{"hooks": [normal]}],
    }}


def write_hook_event(stream=None, environ=None, now=None):
    """Hidden hook adapter: validate an envelope and append one private row."""
    stream = sys.stdin if stream is None else stream
    environ = os.environ if environ is None else environ
    try:
        raw = stream.read(MAX_HOOK_BYTES + 1)
        if len(raw.encode("utf-8")) > MAX_HOOK_BYTES:
            raise SupervisorError("hook payload too large")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise SupervisorError("hook payload must be an object")
        hook_name = payload.get("hook_event_name")
        if hook_name not in HOOK_EVENTS:
            raise SupervisorError("unknown hook event")
        supervisor_id = environ.get("HEADROOM_SUPERVISOR_ID", "")
        if not handoff._valid_uuid(supervisor_id):
            raise SupervisorError("invalid supervisor id")
        generation_raw = environ.get("HEADROOM_CHILD_GENERATION", "")
        if not generation_raw.isdigit():
            raise SupervisorError("invalid child generation")
        slot = environ.get("HEADROOM_SOURCE_SLOT", "")
        if not registry.NAME_RE.fullmatch(slot):
            raise SupervisorError("invalid source slot")
        config_dir = environ.get("CLAUDE_CONFIG_DIR", "")
        if not config_dir:
            raise SupervisorError("missing Claude config home")
        record = {
            "schema": "headroom_hook_event@1",
            "received_at": time.time() if now is None else float(now),
            "supervisor_id": supervisor_id,
            "generation": int(generation_raw),
            "source_slot": slot,
            "config_dir": registry.expand(config_dir),
            "matcher": environ.get("HEADROOM_HOOK_MATCHER", ""),
            "payload": payload,
        }
        directory = paths.ensure_private(_supervisors_dir())
        destination = os.path.join(directory, supervisor_id + ".jsonl")
        descriptor = os.open(destination,
                             os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            paths.fchmod_private(descriptor, 0o600)
            locks.exclusive(descriptor)
            encoded = (json.dumps(record, separators=(",", ":"),
                                  allow_nan=False) + "\n").encode("utf-8")
            if os.write(descriptor, encoded) != len(encoded):
                raise SupervisorError("hook event append was incomplete")
            os.fsync(descriptor)
        finally:
            locks.unlock(descriptor)
            os.close(descriptor)
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError,
            SupervisorError) as error:
        print(f"headroom: hook event refused: {error}", file=sys.stderr)
        return 2


def _option_shaped(arg):
    """Commander's own test for "this token cannot be my optional value"."""
    return len(arg) > 1 and arg.startswith("-")


def takes_value(arg, following):
    """Whether Claude's parser will consume `following` as `arg`'s value.

    `following` is None at the end of the argv. This is the one place the
    three option classes are resolved, so every headroom walker splits an
    argv the same way Claude does."""
    if arg in CLAUDE_VALUE_FLAGS:
        return True
    if arg in CLAUDE_OPTIONAL_VALUE_FLAGS:
        return following is not None and not _option_shaped(following)
    return False


def incompatible_args(args):
    # NOTE: `--settings` is deliberately NOT here. It used to return
    # "user-supplied --settings" and disarm supervision for the whole run —
    # silently, since the run still started. It is now merged instead; see
    # split_user_settings/merge_user_settings.
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        if arg in INCOMPATIBLE_FLAGS or any(
                arg.startswith(flag + "=")
                for flag in ("--output-format", "--input-format")):
            return arg
        following = args[index + 1] if index + 1 < len(args) else None
        index += 2 if takes_value(arg, following) else 1
    return ""


def split_headroom_flags(args):
    """Remove every headroom-owned flag from Claude's option segment.

    Returns (cleaned_args, flags_found). Values of known value-taking Claude
    flags and everything after `--` pass through untouched, exactly like the
    original override stripping."""
    cleaned = []
    found = set()
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            cleaned.extend(args[index:])
            break
        if arg in HEADROOM_OVERRIDE_FLAGS:
            found.add(arg)
            index += 1
            continue
        cleaned.append(arg)
        following = args[index + 1] if index + 1 < len(args) else None
        if takes_value(arg, following):
            cleaned.append(following)
            index += 2
        else:
            index += 1
    return cleaned, found


def strip_headroom_overrides(args):
    """Remove only real headroom options from Claude's option segment."""
    cleaned, found = split_headroom_flags(args)
    return (cleaned, "--headroom-auto-handoff" in found,
            "--headroom-no-auto-handoff" in found)


def split_user_settings(args):
    """`(cleaned_args, raw_value)` — lift the user's `--settings` off the argv.

    Value-aware exactly like `split_headroom_flags` — same `takes_value`
    grammar, so an argument that is another option's VALUE (`--model
    --settings`, `--agent --settings`) stays that option's value, a boolean
    (`--ide`) or an optional-value option facing an option-shaped token
    (`--resume --settings`) consumes nothing, and everything after `--` is
    prompt text. Claude honours one `--settings` and a later one replaces an
    earlier one, so when several are given the LAST wins here too — the
    supervisor merges what Claude would have loaded, never more.

    `raw` is None when no `--settings` was given at all. An EMPTY value
    (`--settings=` or `--settings ""`) is not the same thing and must not
    collapse into it: it is a value headroom cannot read, so it is returned
    as the empty string and refused downstream."""
    cleaned = []
    raw = None
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            cleaned.extend(args[index:])
            break
        if arg == "--settings":
            if index + 1 >= len(args):
                # Claude would refuse the option outright, and a supervisor
                # that silently dropped it would be guessing
                raise UserSettingsError("--settings was given no value")
            raw = args[index + 1]
            index += 2
            continue
        if arg.startswith("--settings="):
            raw = arg.split("=", 1)[1]
            index += 1
            continue
        cleaned.append(arg)
        following = args[index + 1] if index + 1 < len(args) else None
        if takes_value(arg, following):
            cleaned.append(following)
            index += 2
        else:
            index += 1
    return cleaned, raw


def _nested_too_deeply(document, limit=MAX_SETTINGS_DEPTH):
    """Whether a parsed document nests past `limit`.

    Deliberately ITERATIVE: a recursive probe would be the exact crash it
    exists to prevent, and would inherit the same stack-depth dependence that
    makes RecursionError an unreliable gate."""
    stack = [(document, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > limit:
            return True
        if isinstance(value, dict):
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
    return False


def hook_suppressing_flag(args):
    """The first argv option that would suppress the injected hooks, or "".

    Walks with the same grammar as every other splitter, so an occurrence
    that is another option's VALUE — or prompt text after `--` — is not one."""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        for flag in HOOK_SUPPRESSING_FLAGS:
            if arg == flag or arg.startswith(flag + "="):
                return flag
        following = args[index + 1] if index + 1 < len(args) else None
        index += 2 if takes_value(arg, following) else 1
    return ""


def refuse_hook_suppressing_flags(args):
    """Fail closed on an argv option that supervision cannot merge with."""
    flag = hook_suppressing_flag(args)
    if flag:
        raise UserSettingsError(
            f"{flag} loads settings that sit ABOVE the document headroom "
            f"merges, so it can turn the supervisor's own hooks off and no "
            f"merge can answer for it — drop it, or launch without headroom")


def load_user_settings(raw):
    """`(document, source)` — read a user `--settings` value the way Claude
    does: a JSON object literal is inline settings, anything else is a path.

    Every failure is loud and names what was read. A settings document that
    cannot be read is never a reason to run the child unsupervised — which is
    why RecursionError is caught at every recursive step (parse, round-trip,
    and the deep copy in the merge): a deeply nested document would otherwise
    escape as a bare RuntimeError, and the launch guard above catches broad
    exceptions to bare-exec them."""
    value = (raw or "").strip()
    if not value:
        raise UserSettingsError(
            "--settings was given an empty value")
    if value[0] in "{[":            # a path never starts with a JSON opener
        source = "the inline --settings JSON"
        try:
            document = json.loads(value)
        except ValueError as error:
            raise UserSettingsError(
                f"{source} is not valid JSON: {error}") from error
        except RecursionError as error:
            raise UserSettingsError(
                f"{source} is nested too deeply to read") from error
    else:
        source = os.path.abspath(os.path.expanduser(value))
        try:
            with open(source, encoding="utf-8") as handle:
                document = json.load(handle)
        except FileNotFoundError as error:
            raise UserSettingsError(
                f"--settings file {source} does not exist") from error
        except (OSError, UnicodeError) as error:
            raise UserSettingsError(
                f"--settings file {source} could not be read: "
                f"{error}") from error
        except ValueError as error:
            raise UserSettingsError(
                f"--settings file {source} is not valid JSON: "
                f"{error}") from error
        except RecursionError as error:
            raise UserSettingsError(
                f"--settings file {source} is nested too deeply "
                f"to read") from error
    if not isinstance(document, dict):
        raise UserSettingsError(
            f"{source} must be a JSON object, not "
            f"{type(document).__name__}")
    if _nested_too_deeply(document):
        raise UserSettingsError(
            f"{source} is nested too deeply to merge safely (more than "
            f"{MAX_SETTINGS_DEPTH} levels)")
    try:
        # the merged document is written back out with allow_nan=False; a NaN
        # or Infinity accepted here would only fail at spawn time, after the
        # launch was already committed
        json.dumps(document, allow_nan=False)
    except ValueError as error:
        raise UserSettingsError(
            f"{source} holds a value that is not portable JSON: "
            f"{error}") from error
    except RecursionError as error:
        raise UserSettingsError(
            f"{source} is nested too deeply to write back out") from error
    return document, source


def merge_user_settings(document=None, source=""):
    """The single settings document the child is launched with.

    The user's keys pass through untouched — model preferences, `ultracode`,
    `effortLevel`, statusline, permissions, anything Claude accepts — and the
    supervisor's own keys are merged ON TOP, so supervision always wins the
    collision it cares about. For the four supervised hook events the
    supervisor's hook groups are PREPENDED to the user's rather than replacing
    them: Claude runs every matching group, so the handshake fires first and
    the user's own hooks still fire.

    With no user document this returns exactly `hook_settings()`, so the
    unmerged launch is byte-identical to the one before merging existed."""
    document = {} if document is None else document
    where = source or "the --settings document"
    if _nested_too_deeply(document):
        # checked here too: this is called per generation and is public, so it
        # may not rely on load_user_settings having been the way in
        raise UserSettingsError(
            f"{where} is nested too deeply to merge safely (more than "
            f"{MAX_SETTINGS_DEPTH} levels)")
    offenders = [key for key in HOOK_RESTRICTING_KEYS if document.get(key)]
    if offenders:
        raise UserSettingsError(
            f"{where} sets {', '.join(offenders)}, which suppresses the hooks "
            f"supervision runs on — remove it, or launch without headroom")
    environment = document.get("env")
    if environment is not None and not isinstance(environment, dict):
        raise UserSettingsError(f"{where} has a non-object \"env\"")
    reserved = sorted(
        key for key in (environment or {})
        if key in RESERVED_SETTINGS_ENV
        or key.startswith(RESERVED_SETTINGS_ENV_PREFIXES))
    if reserved:
        raise UserSettingsError(
            f"{where} sets {', '.join(reserved)} in \"env\" — headroom and "
            f"Claude Code own those names for this child (they decide where "
            f"the hook writes and whether it runs at all). Remove them, or "
            f"launch without headroom")
    hooks = document.get("hooks")
    if hooks is not None and not isinstance(hooks, dict):
        raise UserSettingsError(f"{where} has a non-object \"hooks\"")
    try:
        merged = copy.deepcopy(document)
    except RecursionError as error:
        raise UserSettingsError(
            f"{where} is nested too deeply to merge") from error
    # an explicit null `hooks` normalises to an empty block: the injected
    # hooks still have to land somewhere
    supervised = merged["hooks"] = dict(merged.get("hooks") or {})
    for event, groups in hook_settings()["hooks"].items():
        existing = supervised.get(event, [])
        if not isinstance(existing, list):
            raise UserSettingsError(
                f"{where} has a non-list \"hooks.{event}\", which cannot be "
                f"merged with the supervisor's own {event} hook")
        supervised[event] = list(groups) + list(existing)
    return merged


def validate_user_settings(args):
    """Pre-launch gate: prove the user's `--settings` can be merged.

    Raises :class:`UserSettingsError` — never returns a "supervision off"
    answer, because there is no such answer: the launch either runs supervised
    with the merged document or it does not run. `raw is None` (no flag) is
    the only case that passes without reading anything; an EMPTY value is a
    given flag headroom cannot honour, so it refuses like any other."""
    refuse_hook_suppressing_flags(args)
    _cleaned, raw = split_user_settings(args)
    if raw is None:
        return {}
    document, source = load_user_settings(raw)
    return merge_user_settings(document, source)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _event_text(event):
    if not isinstance(event, dict):
        return ""
    message = event.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return content
    texts = []
    for item in content if isinstance(content, list) else []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            texts.append(item["text"])
    if texts:
        return "\n".join(texts)
    return "\n".join(_strings(event.get("text")))


SYNTHETIC_MODEL = "<synthetic>"


def _real_assistant_model(event):
    if (not isinstance(event, dict) or event.get("type") != "assistant"
            or event.get("isSidechain") is True):
        return ""
    message = event.get("message")
    if isinstance(message, dict) and message.get("isSidechain") is True:
        return ""
    model = message.get("model") if isinstance(message, dict) else None
    if not isinstance(model, str) or not model.strip() \
            or model.strip() == SYNTHETIC_MODEL:
        return ""
    return model.strip()


def _active_model(lines, cap_event):
    """The model the session was actually running at cap time.

    The API-error event itself carries model "<synthetic>" (observed live), so
    the authoritative source is the LAST preceding assistant event with a real
    model id — that reflects in-session /model switches, unlike SessionStart.
    """
    for raw in reversed(lines[:-1]):
        try:
            event = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError, json.JSONDecodeError):
            continue
        model = _real_assistant_model(event)
        if model:
            return model
    return ""


def _last_transcript_cap_evidence(path):
    """Locate the cap as the transcript's LATEST assistant activity.

    Observed live: Claude appends trailing non-assistant records (system
    turn_duration, last-prompt, file-history-snapshot, user, attachment)
    after the API-error event, so the cap is rarely the final line.  Scanning
    backward, the first assistant event must BE the cap — a successful
    assistant turn after it means the session is not capped (fail closed).
    """
    try:
        with open(path, "rb") as handle:
            lines = [line for line in handle.read().splitlines() if line.strip()]
        event = None
        cap_index = len(lines)
        for index in range(len(lines) - 1, -1, -1):
            candidate = json.loads(lines[index].decode("utf-8"))
            if not isinstance(candidate, dict) \
                    or candidate.get("type") != "assistant" \
                    or candidate.get("isSidechain") is True:
                continue
            message = candidate.get("message")
            if isinstance(message, dict) and message.get("isSidechain") is True:
                continue
            event, cap_index = candidate, index
            break
        lines = lines[:cap_index + 1]
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(event, dict) or event.get("type") != "assistant":
        return None
    is_api = event.get("isApiErrorMessage") is True
    if not is_api and isinstance(event.get("message"), dict):
        is_api = event["message"].get("isApiErrorMessage") is True
    text = _event_text(event)
    model = _active_model(lines, event)
    top_model = event.get("model")
    if (not is_api or not CAP_RE.search(text) or not model
            or (isinstance(top_model, str) and top_model.strip()
                and top_model.strip() not in (model, SYNTHETIC_MODEL))):
        return None
    try:
        signature = handoff._transcript_stat(path)
    except handoff.HandoffError:
        return None
    return {"message": text, "model": model, "stat": signature}


def _last_transcript_cap(path):
    evidence = _last_transcript_cap_evidence(path)
    return evidence["message"] if evidence else ""


def _namespace_matches(record, child):
    if not isinstance(record, dict):
        return False
    expected_id = os.path.splitext(os.path.basename(child.event_path))[0]
    return (record.get("supervisor_id") == expected_id
            and record.get("generation") == child.generation)


def _record_matches(record, child, binding=None):
    if not _namespace_matches(record, child):
        return False
    if record.get("source_slot") != child.account.get("name") \
            or not isinstance(record.get("config_dir"), str) \
            or registry.expand(record["config_dir"]) \
            != registry.expand(child.account["home"]):
        return False
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return False
    if binding is not None:
        if payload.get("session_id") != binding.session_id:
            return False
        transcript = payload.get("transcript_path")
        if transcript is not None and os.path.realpath(transcript) \
                != binding.transcript_path:
            return False
    return True


# A brand-new session fires SessionStart BEFORE its transcript file exists on
# disk. The identity check below reads that file, so a hook that wins the race
# used to look exactly like a forged event: "transcript no longer exists" ->
# PermanentSupervisorError -> supervision disarmed for the whole run. Every
# lane on this estate booted disarmed because of it, which is why a cap could
# not rotate anything (2026-07-31). The file appears in milliseconds; waiting
# a bounded moment for it is the difference between a supervised lane and an
# unprotected one. A transcript still missing at the deadline is a real
# failure and still fails closed.
def _grace_seconds(raw, default=BIND_TIMEOUT, ceiling=BIND_TIMEOUT):
    """A tolerant, FINITE grace window (the project's numeric-env convention).

    A malformed value must not crash import, and `inf` must not turn the
    bounded wait into a permanent one — this poll also drives cap detection
    and exit handling, so its upper bound is a real budget.

    The default is BIND_TIMEOUT and not a number of its own. It was 3.0, and
    3.0 was measured wrong: across all 45 SessionStart hooks on the
    production box (2026-08-02) transcript births are bimodal — a thin
    cluster under 2.7s, the bulk at 6-8s, a tail to 104s — so 3.0 sat in the
    trough and 18 of 39 measurable launches crossed it. Losing this race
    disarms automatic handoff for the child's entire life, and there is no
    re-arm path, so the lane stays unsupervised until its pane restarts.
    Two of two fresh launches lost it on 2026-08-01/02.

    One budget, not two: the supervisor already grants a child BIND_TIMEOUT
    to bind, and a transcript still missing at the end of that is a real
    failure that still fails closed. A second, smaller, undocumented window
    is what let the wrong number go unnoticed."""
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(value):
        return default
    return min(ceiling, max(0.0, value))


TRANSCRIPT_GRACE_SECONDS = _grace_seconds(
    os.environ.get("HEADROOM_TRANSCRIPT_GRACE"))
TRANSCRIPT_GRACE_STEP = 0.1


def _source_once_written(transcript, session_id, child, config_dir,
                         sleep=time.sleep, now=time.time):
    """`handoff._source`, tolerant of a transcript that is still being born.

    Retries ONLY the not-yet-written case — every other HandoffError (wrong
    basename, symlink, foreign home) is a genuine identity failure and is
    raised on the first look, unchanged."""
    deadline = now() + max(0.0, TRANSCRIPT_GRACE_SECONDS)
    while True:
        try:
            return handoff._source(transcript, session_id, [child.account],
                                   config_dir=config_dir)
        except handoff.HandoffError as error:
            if "transcript no longer exists" not in str(error) \
                    or now() >= deadline:
                raise
            sleep(TRANSCRIPT_GRACE_STEP)


def _validated_event(record, child, binding=None):
    if not _namespace_matches(record, child):
        raise SupervisorError("hook event does not match this child")
    if record.get("source_slot") != child.account.get("name"):
        raise PermanentSupervisorError("hook event source slot is malformed")
    config_dir = record.get("config_dir")
    if not isinstance(config_dir, str) or not config_dir \
            or registry.expand(config_dir) \
            != registry.expand(child.account["home"]):
        raise PermanentSupervisorError("hook event config home is malformed")
    received = record.get("received_at")
    if (not isinstance(received, (int, float)) or isinstance(received, bool)
            or not math.isfinite(received) or received < child.launched_at
            or received > time.time() + route.CLOCK_SKEW):
        raise PermanentSupervisorError("hook event timestamp is not post-launch")
    payload = record.get("payload")
    if not isinstance(payload, dict):
        raise PermanentSupervisorError("hook event payload is malformed")
    session_id = payload.get("session_id")
    transcript = payload.get("transcript_path")
    cwd = payload.get("cwd")
    if not isinstance(session_id, str) or not handoff._valid_uuid(session_id):
        raise PermanentSupervisorError("hook event session id is malformed")
    if not isinstance(transcript, str) or not transcript \
            or os.path.abspath(os.path.expanduser(transcript)) != transcript:
        raise PermanentSupervisorError("hook event transcript path is not canonical")
    try:
        source = _source_once_written(transcript, session_id, child, config_dir)
    except handoff.HandoffError as error:
        raise PermanentSupervisorError(str(error)) from error
    if source.transcript_path != transcript:
        raise PermanentSupervisorError("hook event transcript path is not canonical")
    if not isinstance(cwd, str) or not cwd \
            or not os.path.isdir(os.path.realpath(cwd)):
        raise PermanentSupervisorError("hook event cwd is missing or unreadable")
    if binding is not None and (session_id != binding.session_id
                                or transcript != binding.transcript_path):
        raise SupervisorError("hook event belongs to a different session epoch")
    return source, os.path.realpath(cwd)


def parse_session_start(record, child):
    source, cwd = _validated_event(record, child)
    payload = record["payload"]
    if payload.get("hook_event_name") != "SessionStart":
        raise SupervisorError("not a SessionStart event")
    return Binding(
        source.session_id, source.transcript_path, cwd,
        _model_name(payload.get("model")),
        payload.get("version", "") if isinstance(payload.get("version"), str)
        else "", record["config_dir"], child.session_epoch + 1,
        record["received_at"])


def _cap_text(record, *, absent=""):
    """The cap phrase from a record's OWN payload, or "".

    The binding-free half of cap_message. It reads only the payload and never
    touches a transcript, so it can speak for a child that never bound a
    session — which is the whole point. It deliberately does NOT run
    _validated_event: validating an event requires a binding, and a child
    without one still deserves to have its wall announced. ACTING still needs
    cap_message's full proof; SAYING SO does not.

    `absent` is returned for EXACTLY ONE of the ways this can come back
    empty: an in-class record whose payload says nothing about itself
    (neither last_assistant_message nor error_details). The three cap-CLASS
    gates below — wrong hook, wrong matcher, wrong error type — and a payload
    that speaks but is not a cap always return "", because those records are
    not rate-limit refusals and NO transcript may be allowed to speak for
    them. cap_message passes absent=None so it can tell that one case apart
    and fall back to the transcript exactly where it always did; every
    announce-only caller takes the default and sees a single falsy answer.

    Do not turn `absent` into a positional argument, and do not widen which
    branch returns it. Collapsing these five empty answers into one and then
    reconstructing which happened from the payload can only distinguish
    "self-described" from "said nothing" — so a record that failed the
    MATCHER or ERROR-TYPE gate carrying no payload text becomes
    indistinguishable from an in-class silent one, reads the transcript, and
    returns a stale cap left there earlier in the session. That is a rotation
    off a non-cap, on the live acting path.
    `CapClassIsNotDelegatedToTheTranscript` is the only test that catches it."""
    payload = record["payload"]
    if payload.get("hook_event_name") != "StopFailure":
        return ""
    if record.get("matcher") != "rate_limit":
        return ""
    error_type = payload.get("error") or payload.get("error_type")
    if error_type is not None and error_type != "rate_limit":
        return ""
    direct = payload.get("last_assistant_message")
    if direct is None:
        direct = payload.get("error_details")
    if direct is None:
        return absent
    text = "\n".join(_strings(direct))
    return text if CAP_RE.search(text) else ""


def _subagent_attributed(record):
    """Whether this hook event is attributed to a background subagent.

    Payload-only, no transcript. The field names are provider-controlled, so
    a rename reverts to the old behaviour rather than to something worse."""
    payload = record.get("payload") if isinstance(record, dict) else None
    payload = payload if isinstance(payload, dict) else {}
    return bool(str(payload.get("agent_id") or "").strip()
                or str(payload.get("agent_type") or "").strip())


def cap_message(record, child):
    """Return the narrow cap message, or empty when any binding proof fails."""
    binding = child.binding
    if binding is None:
        return ""
    try:
        _validated_event(record, child, binding)
    except SupervisorError:
        return ""
    text = _cap_text(record, absent=None)
    if text is None:
        # The ONE case that may reach the transcript: a record that IS a
        # rate-limit StopFailure but whose payload carries no
        # self-description. Every other empty answer — not a StopFailure, not
        # the rate_limit matcher, a non-rate_limit error type, or text that is
        # present and is not a cap — is a decision that this record CANNOT be
        # a cap, and the transcript must not get a second vote.
        return _last_transcript_cap(binding.transcript_path)
    return text


def _read_events(child):
    if not os.path.exists(child.event_path):
        return []
    try:
        with open(child.event_path, "rb") as handle:
            locks.shared(handle)
            handle.seek(child.event_offset)
            data = handle.read()
            locks.unlock(handle)
        if not data:
            return []
        if not data.endswith(b"\n"):
            raise SupervisorError("hook event file has an incomplete record")
        events = []
        for line in data.splitlines():
            record = json.loads(line.decode("utf-8"))
            received = record.get("received_at") if isinstance(record, dict) else None
            payload = record.get("payload") if isinstance(record, dict) else None
            if (not isinstance(record, dict)
                    or record.get("schema") != "headroom_hook_event@1"
                    or not handoff._valid_uuid(record.get("supervisor_id"))
                    or not isinstance(record.get("generation"), int)
                    or isinstance(record.get("generation"), bool)
                    or not isinstance(record.get("source_slot"), str)
                    or not isinstance(record.get("config_dir"), str)
                    or not isinstance(record.get("matcher"), str)
                    or not isinstance(received, (int, float))
                    or isinstance(received, bool) or not math.isfinite(received)
                    or not isinstance(payload, dict)
                    or payload.get("hook_event_name") not in HOOK_EVENTS):
                raise ValueError
            events.append(record)
        child.event_offset += len(data)
        events.sort(key=lambda record: record["received_at"])
        return events
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise SupervisorError("hook event file is unreadable") from error


def _binding_key(binding):
    return (binding.session_id, binding.epoch) if binding is not None else None


def _remember_binding(child):
    binding = child.binding
    if binding is None:
        return
    child.session_epochs.setdefault(
        (binding.session_id, binding.transcript_path), binding.epoch)
    child.last_received_at = max(child.last_received_at, binding.received_at)


def _event_epoch(child, source):
    binding = child.binding
    if (binding is not None and source.session_id == binding.session_id
            and source.transcript_path == binding.transcript_path):
        return binding.epoch
    return child.session_epochs.get(
        (source.session_id, source.transcript_path))


def _event_identity(record):
    """A stable fingerprint of one journaled record.

    Canonical JSON of the record as the reader parsed it: same bytes in, same
    fingerprint out, and two records that differ anywhere — including in the
    payload alone — never collide."""
    return hashlib.sha256(json.dumps(
        record, sort_keys=True, separators=(",", ":"),
        default=str).encode("utf-8")).hexdigest()


def _accept_event_order(child, record):
    """True = process this record, False = drop it, raise = fail closed.

    A hook event stamped at or before the frontier used to be one thing —
    "ambiguous" — and cost the child its supervision for the rest of its life.
    It is really three, and only the last of them is ambiguous:

      * THE SAME RECORD AGAIN. The journal cursor is monotonic so the file
        cannot serve one twice, but any in-memory replay can — the exit drain
        used to be the worry, and the cross-poll retry below is one by
        construction. A duplicate carries no information; dropping it is
        harmless, and disarming for it is a self-inflicted wound.
      * A DISTINCT RECORD AT THE SAME CLOCK READING. `write_hook_event` reads
        `time.time()` and only then takes the append lock, so two hooks firing
        together can carry one reading. That is a clock-resolution tie, not
        evidence of forgery: keep both, and hold the frontier where it is.
      * A DISTINCT RECORD FROM BEFORE THE FRONTIER. Still fails closed. It is
        either an out-of-order append or a replay of something older than this
        frontier, and the journal cannot tell those apart — accepting it would
        let a stale StopFailure act, which is a change to when headroom STOPS
        a child.

    `last_received_ids` holds the fingerprints accepted AT `last_received_at`,
    so its size is bounded by one clock reading's worth of events and it needs
    no eviction policy. It is not a general replay cache: an older duplicate
    still meets the fail-closed branch, which is what it met before.

    Measured on the live estate 2026-08-02 before this changed: 258 records
    across 32 journals, zero duplicate readings and zero non-monotonic pairs.
    This is a latent hazard, and the deterministic rejection it produces can
    never heal by retry — which is why it is excluded from the transient
    allowlist and given a rule instead."""
    received = record["received_at"]
    if received > child.last_received_at:
        child.last_received_at = received
        child.last_received_ids = {_event_identity(record)}
        return True
    identity = _event_identity(record)
    if identity in child.last_received_ids:
        return False
    if received == child.last_received_at:
        child.last_received_ids.add(identity)
        return True
    raise PermanentSupervisorError(
        "hook event order is ambiguous for the current binding")


@contextlib.contextmanager
def _event_stop_guard(child):
    """Prevent a session-transition hook from landing between check and TERM."""
    try:
        handle = open(child.event_path, "rb")
    except OSError as error:
        raise SupervisorError("cannot lock hook event journal before stop") \
            from error
    try:
        locks.shared(handle)
        if os.fstat(handle.fileno()).st_size != child.event_offset:
            raise SupervisorError("cap proof expired after a newer hook event")
        yield
    finally:
        locks.unlock(handle)
        handle.close()


def _number(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def _transcript_records(path, whole=False, limit=None):
    """``(records, complete, malformed)`` parsed from the END of a transcript.

    Everything the preemptive poll asks of a transcript — the model in use,
    whether the newest turn finished — lives at its end, so read a bounded
    tail rather than the whole session: a full parse every minute is
    O(session size) work on the one loop that also has to ingest hooks and
    prove caps. ``complete`` says whether the tail covered the whole file, so
    a caller that found nothing can decide to pay for the full read.

    ``malformed`` reports a line that would not parse. The read starts at a
    record BOUNDARY (the partial record at the seek point is discarded), so
    anything unparseable after it is either real corruption or a record being
    written this instant — never an artefact of the tail. Dropping such a line
    silently would let a valid final assistant record followed by a broken
    newest line read as a finished turn, so idleness callers refuse on it."""
    limit = TRANSCRIPT_TAIL_BYTES if limit is None else limit
    try:
        with open(path, "rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            complete = whole or size <= limit
            if not complete:
                handle.seek(size - limit)
                handle.readline()  # drop the partial record at the boundary
            data = handle.read()
    except OSError:
        return [], False, False
    records = []
    malformed = False
    for raw in data.splitlines():
        if not raw.strip():
            continue
        try:
            event = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError, json.JSONDecodeError):
            malformed = True
            continue
        records.append(event)
    return records, complete, malformed


def _last_assistant_model(records):
    for event in reversed(records):
        model = _real_assistant_model(event)
        if model:
            return model
    return ""


def _transcript_model(path):
    """The model this session is CURRENTLY running: the last real assistant
    model in the transcript.

    Same authority the cap path trusts (``_active_model``) and for the same
    reason — it reflects in-session ``/model`` switches, unlike the model
    named at SessionStart. Unreadable/absent yields "" and the caller falls
    back to the bound SessionStart model."""
    records, complete, _malformed = _transcript_records(path)
    model = _last_assistant_model(records)
    if model or complete:
        return model
    # a tail full of tool traffic with no assistant record is possible on a
    # huge session — only then pay for the whole file
    return _last_assistant_model(_transcript_records(path, whole=True)[0])


def _assistant_usage(event):
    """Context tokens ONE main-loop assistant record was charged for.

    The three input-side counters are the whole prompt the provider saw:
    fresh input, cache reads and cache writes. Output tokens are deliberately
    excluded — they are already inside the NEXT request's input.

    Sidechains are excluded because a subagent runs in its own window; adding
    its usage to the parent's would report a context pressure the parent does
    not have. BOTH sidechain markers are honoured — the record's own and the
    nested `message.isSidechain` — exactly as `_turn_is_complete` does: a
    subagent turn carrying only the nested marker would otherwise be read as
    the parent's own occupancy and could force a rotation the parent never
    needed. Nested per-`iterations` usage is ignored for the mirror-image
    reason: those are the same tokens as the record's own totals, and summing
    both would double-count a multi-iteration turn straight past the ceiling.
    Only the record's top-level counters count.

    Same rule the UserPromptSubmit context-guard hook applies, deliberately:
    the cooperative nudge and this backstop must never disagree about how much
    context a session has left."""
    if not isinstance(event, dict) or event.get("type") != "assistant" \
            or event.get("isSidechain"):
        return 0
    message = event.get("message")
    if isinstance(message, dict) and message.get("isSidechain") is True:
        return 0
    usage = message.get("usage") if isinstance(message, dict) else None
    if not isinstance(usage, dict):
        return 0
    total = 0
    for key in ("input_tokens", "cache_read_input_tokens",
                "cache_creation_input_tokens"):
        value = usage.get(key)
        if _number(value) and value >= 0:
            total += int(value)
    return total


def _context_used(path, records=None):
    """Context tokens the NEWEST main-loop assistant record was charged for,
    or None when the transcript cannot say.

    The newest record, not the largest and not a sum: each request carries the
    whole conversation, so the last one IS the current occupancy. Records with
    no usage at all (synthetic notices, tool bookkeeping) are skipped rather
    than read as zero — a zero would look like an empty window.

    None means UNKNOWN, and every caller treats unknown as "change nothing":
    never rotate, never rewrite a resume's model."""
    try:
        if records is None:
            records, complete, _malformed = _transcript_records(path)
            if not any(_assistant_usage(event) for event in records) \
                    and not complete:
                # a tail full of one enormous tool result can hold no assistant
                # record at all — only then pay for the whole file (the same
                # trade _transcript_model makes)
                records = _transcript_records(path, whole=True)[0]
        used = None
        for event in records:
            total = _assistant_usage(event)
            if total:
                used = total
        return used
    except Exception:  # noqa: BLE001 — a measurement never breaks supervision
        return None


def _context_window(used, model="", environ=None):
    """The context window a session with this usage is running in.

    KNOWLEDGE FIRST: a child spawned with an explicit `--model …[1m]` is on the
    1M window and there is nothing to infer. Otherwise infer from the usage
    itself — anything past the fit limit could not have been served by the
    standard window. `HEADROOM_CTX_WINDOW` overrides both (the same knob, with
    the same precedence, as the cooperative hook)."""
    if "[1m]" in str(model or "").lower():
        window = CONTEXT_WINDOW_LARGE
    elif _number(used) and used > CONTEXT_WINDOW_FIT_LIMIT:
        window = CONTEXT_WINDOW_LARGE
    else:
        window = CONTEXT_WINDOW_STANDARD
    environ = os.environ if environ is None else environ
    override = str(environ.get("HEADROOM_CTX_WINDOW", "")).strip()
    if override:
        try:
            forced = int(override)
        except (TypeError, ValueError):
            return window
        if forced > 0:
            return forced
    return window


def _context_remaining(used, window):
    """Percent of the window still free (0-100), fail-closed on nonsense."""
    if not (_number(used) and _number(window)) or window <= 0 or used < 0:
        return None
    # (window - used) / window, not 1 - used/window: the second form makes the
    # exact threshold land a float epsilon off (180000/200000 -> 9.999…%), and
    # a boundary this code compares against must be exact
    return max(0.0, min(100.0, 100.0 * (window - used) / window))


def _model_flag(args):
    """The value of the last `--model` in a Claude argv ("" when absent).

    Everything after `--` is the child's own payload, never an option."""
    value = ""
    expected = False
    for arg in args or ():
        if not isinstance(arg, str):
            continue
        if expected:
            value, expected = arg, False
            continue
        if arg == "--":
            break
        if arg == "--model":
            expected = True
        elif arg.startswith("--model="):
            value = arg.split("=", 1)[1]
    return value


def _with_model(args, model):
    """`args` carrying exactly one `--model`, set to `model`."""
    cleaned, tail = [], []
    expected = False
    after_separator = False
    for arg in args:
        if after_separator:
            tail.append(arg)
            continue
        if expected:
            expected = False
            continue
        if arg == "--":
            after_separator = True
            tail.append(arg)
            continue
        if arg == "--model":
            expected = True
            continue
        if isinstance(arg, str) and arg.startswith("--model="):
            continue
        cleaned.append(arg)
    return cleaned + ["--model", model] + tail


def _family_or_blank(model):
    """`registry.family`, but an unrecognised model is simply unknown here.

    Model naming is the registry's problem; a fit decision must never raise
    over one, and "" compares unequal to every real family, which is the
    conservative answer at both call sites."""
    try:
        return registry.family(model)
    except registry.RegistryError:
        return ""


def _plan_family(plan, attribute):
    """A plan's family field as a STRING, "" when absent or not one.

    Plans reach here from several vintages (a ledger recovery predating
    `resume_family`, a test double), and only a family name means anything to
    the argv builder — anything else must read as "unset", never as truthy."""
    value = getattr(plan, attribute, "")
    return value if isinstance(value, str) else ""


def _resume_argv_for(plan, model=""):
    """``(argv, forced)`` — how a successor of `plan` resumes on the TARGET.

    One definition for both the automatic relaunch and the manual command
    printed when that relaunch cannot start; they were allowed to drift once
    and the operator got the wrong model out of it. `model` is what the
    stopped child was RUNNING, and `forced` is the window-fit model when the
    transcript demanded one (a tier downgrade alone does not set it — that is
    a routing fact, and it has its own announcement)."""
    resume_family = _plan_family(plan, "resume_family")
    # The window fit is bounded by the family the SEAT was gated on, which is
    # target_family whether or not a downgrade happened. `resume_family` alone
    # was not enough: a child spawned `--model sonnet[1m]` whose session had
    # since moved to Opus would have carried sonnet[1m] onto an Opus-gated
    # seat — checked one pool, spent another, with no downgrade in sight.
    gate = _plan_family(plan, "target_family") or resume_family
    argv = ["--resume", plan.source.session_id, "--fork-session"]
    if resume_family:
        argv = _with_model(argv, resume_family)
    return _window_fit_argv(argv, plan.source.transcript_path,
                            model=model, family=gate)


def _window_fit_argv(args, transcript_path, used=None, model="", family=""):
    """``(argv, forced model)`` — make a resume argv FIT the transcript it
    resumes.

    A transcript past the fit limit cannot be replayed into the standard
    window: the resumed session dies on its first prompt with "Prompt is too
    long" and the conversation is stranded on a seat nobody is watching
    (production, 2026-07-27, twice in one day). So every automatic resume this
    supervisor performs — cap rotation, preemptive rotation, source recovery,
    context backstop — is re-modelled onto the 1M window when, and only when,
    the transcript proves it needs one.

    `model` is what the stopped child was RUNNING. When that is already a 1M
    variant the conversation keeps it rather than being shrunk back into the
    standard window — but only once it is big enough for the shrink to matter
    (CONTEXT_KEEP_LARGE_PERCENT), so a small session on a big model still
    follows normal family routing.

    `family` is the family the successor has been ROUTED to, set only when a
    cap forced it down a tier. It bounds this function the way it bounds the
    ladder: the child's own 1M model is only worth keeping when it belongs to
    that family, because carrying a `fable[1m]` model onto a seat chosen for
    Opus would re-cap the conversation on the very pool that just walled it.

    Unknown usage changes nothing: an unmeasurable transcript resumes exactly
    as it would have before."""
    args = list(args)
    if used is None:
        used = _context_used(transcript_path)
    if used is None:
        return args, ""
    large = "[1m]" in str(model or "").lower()
    if large and family and _family_or_blank(model) != family:
        large = False
    needed = used > CONTEXT_WINDOW_FIT_LIMIT
    if not needed and large:
        standard = _context_remaining(used, CONTEXT_WINDOW_STANDARD)
        needed = standard is not None and standard <= CONTEXT_KEEP_LARGE_PERCENT
    if not needed:
        return args, ""
    # keep the child's own 1M model where it has one; only a session with no
    # such model of its own is moved onto the default fit model
    fit = model if large else CONTEXT_FIT_MODEL
    if _model_flag(args) == fit:
        return args, ""
    return _with_model(args, fit), fit


def _turn_is_complete(path, records=None, complete=True):
    """"" when the transcript's newest conversational record is a FINISHED
    main-thread assistant turn; otherwise why the child may be MID-TURN.

    Transcript quiescence alone is not proof of idleness: a turn can stay
    silent for minutes while the model thinks or waits on a remote response,
    and throughout that silence the newest conversational record is the
    user's prompt (or a tool_result the model has not answered yet). So the
    newest ``user``/``assistant`` record must be a main-thread assistant
    record. Trailing bookkeeping records (system turn_duration, last-prompt,
    file-history-snapshot, summary) are skipped — Claude writes those after a
    turn ends, as the cap-evidence scanner already documents."""
    if records is None:
        records, complete, malformed = _transcript_records(path)
        if malformed:
            return "the transcript tail has an unreadable record"
    for event in reversed(records):
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        if kind not in ("user", "assistant"):
            continue
        message = event.get("message")
        if event.get("isSidechain") is True or (
                isinstance(message, dict)
                and message.get("isSidechain") is True):
            return "a subagent turn is still in flight"
        if kind == "user":
            return "a prompt is still awaiting its answer"
        return ""
    return ("no completed assistant turn in the transcript" if complete
            else "no completed assistant turn in the transcript tail")


def _subagents_dir(transcript_path):
    """The sibling directory Claude writes BACKGROUND agent transcripts into.

    Live layout: ``projects/<slug>/<session-id>.jsonl`` alongside
    ``projects/<slug>/<session-id>/subagents/agent-<id>.jsonl`` (each with an
    ``agent-<id>.meta.json``; nested worker directories occur too)."""
    return os.path.join(
        os.path.dirname(transcript_path),
        os.path.splitext(os.path.basename(transcript_path))[0], "subagents")


def _blocks(event):
    message = event.get("message") if isinstance(event, dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    return content if isinstance(content, list) else []


def _launch_agent_ids(event):
    """Ids from an AUTHORITATIVE background-launch record.

    The Agent tool's own result: a `user` record carrying a `tool_result`
    block whose text names the agent. Read from THAT block, never from the
    record's flattened strings — an assistant merely writing "the agent
    launched successfully" about a previous spawn must not enter the ledger.
    (Erring loose here only over-reports work, which holds a rotation; the
    dangerous direction is retiring an agent, and that is gated far harder.)"""
    if not isinstance(event, dict) or event.get("type") != "user":
        return []
    ids = []
    for block in _blocks(event):
        if not isinstance(block, dict) or block.get("type") != "tool_result":
            continue
        ids.extend(BACKGROUND_LAUNCH_RE.findall(
            "\n".join(_strings(block.get("content")))))
    return ids


def _terminal_notification(event):
    """``(ids, status)`` of an AUTHORITATIVE terminal task-notification, else
    None.

    THE ONLY THING THAT MAY RETIRE AN AGENT, so it is the strictest check in
    the file. Three conditions, all pinned from fleet data and all required:
    a `user` record, marked by the harness with
    ``origin={"kind": "task-notification"}``, whose message content is the
    notification STRING itself. A quoted copy inside another tool's result,
    an attachment, a queue-operation record or assistant prose satisfies none
    of them — which is the point: such copies exist in real transcripts, and
    one bearing a live agent's id would otherwise mark it finished and clear
    the way for a SIGTERM. The status must be parsed from THAT record and be
    in the observed terminal vocabulary; anything else leaves the agent
    live."""
    if not isinstance(event, dict) or event.get("type") != "user":
        return None
    origin = event.get("origin")
    if not isinstance(origin, dict) \
            or origin.get("kind") != TASK_NOTIFICATION_ORIGIN:
        return None
    message = event.get("message")
    body = message.get("content") if isinstance(message, dict) else None
    if not isinstance(body, str) or "<task-notification>" not in body:
        return None
    status = TASK_STATUS_RE.search(body)
    return TASK_ID_RE.findall(body), (status.group(1).lower() if status else "")


def _agent_lifecycle(records):
    """``(live ids, terminated ids)`` from the parent's own ledger.

    THE STRONGEST SIGNAL ON DISK, and the reason it exists: it is the
    parent's record of what it started, so it does not depend on the agent
    having written — or being about to write — anything at all. A background
    Agent call returns IMMEDIATELY, which is exactly why the main turn can
    look finished while the agent works; `SendMessage` puts a stopped agent
    back to work; only an authoritative terminal notification retires one.

    Both sets come from ONE pass so they can never drift apart. Truncating to
    a tail is sound: notifications always follow their launch, so a tail can
    only miss a launch (covered by the per-sidechain shape check), never
    invent a live agent. The caller must still bound these ids by the CURRENT
    child's lifetime — a resumed or forked session inherits its predecessor's
    records, and an agent from a process that has exited is not running."""
    live, terminated = {}, set()
    for event in records:
        if not isinstance(event, dict):
            continue
        for block in _blocks(event):
            if isinstance(block, dict) and block.get("type") == "tool_use" \
                    and block.get("name") == "SendMessage":
                target = block.get("input")
                target = target.get("to") if isinstance(target, dict) else None
                if isinstance(target, str) and target.strip():
                    # back to work: it is live again and no longer retired
                    live[target.strip()] = True
                    terminated.discard(target.strip())
        for agent_id in _launch_agent_ids(event):
            live[agent_id] = True
            terminated.discard(agent_id)
        notification = _terminal_notification(event)
        if notification is not None and notification[1] in TERMINAL_TASK_STATUS:
            for agent_id in notification[0]:
                live.pop(agent_id, None)
                terminated.add(agent_id)
    return set(live), terminated


def _launched_background_agents(records):
    """Ids started and not yet authoritatively reported back."""
    return _agent_lifecycle(records)[0]


def _sidechain_busy(path):
    """Why one sidechain transcript looks LIVE, or "" when it is finished.

    SHAPE, not age. An agent thinking silently, or blocked inside a single
    long tool call (a build, a network wait), writes nothing for minutes — so
    recency proves activity but never completion, and treating "old" as
    "finished" is exactly how live delegated work gets killed. A finished
    agent's transcript ends with the assistant message that IS its return
    value; a working one ends with input it has not answered yet, or with a
    tool_use whose result has not landed. Anything unreadable or shapeless
    refuses (fail closed)."""
    records, _complete, malformed = _transcript_records(
        path, limit=SIDECHAIN_TAIL_BYTES)
    if malformed:
        # a broken newest line past the boundary is corruption, or a record
        # being written right now — either way this agent is not provably done
        return "a subagent transcript has an unreadable record"
    if not records:
        return "a subagent transcript could not be read"
    unresolved = handoff.unresolved_tool_ids(records)
    for event in reversed(records):
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        if kind not in ("user", "assistant"):
            continue
        if kind == "user":
            return "a background subagent is answering its latest input"
        if unresolved:
            return "a background subagent is waiting on a tool call"
        return ""
    return "a subagent transcript has no conversational record"


def _terminated_agents(records):
    """Ids the parent AUTHORITATIVELY records as having stopped.

    Same single pass, same discriminators and same terminal vocabulary as the
    live set — the two must never disagree about what "finished" means, and
    this one only ever skips work (the sidechain shape check), so a looser
    rule here would silently undo the harder one."""
    return _agent_lifecycle(records)[1]


def _subagent_activity(transcript_path, now, quiet_seconds, since=0.0,
                       launched=(), finished=()):
    """"" when no background subagent is still working.

    One bounded walk of the sidechain directory, cheapest test first:

      recent/future mtime   activity outright, no parse needed
      mtime < `since`       written before THIS child started, so its agent
                            died with the previous process — a resumed or
                            forked session inherits the whole directory, and
                            a dead agent must not block rotation forever
      parent saw it stop    a terminal <task-notification> needs no more proof
      otherwise             its transcript SHAPE decides (see _sidechain_busy)

    Finally, an id the parent launched but that has no sidechain file of this
    child's own is treated as live: an agent that was just spawned has not
    necessarily written anything yet, and that is precisely the blind spot the
    parent's record exists to cover."""
    directory = _subagents_dir(transcript_path)
    scanned = 0
    seen = {}
    try:
        for root, _dirs, names in os.walk(directory):
            for name in names:
                if not name.endswith(".jsonl"):
                    continue
                scanned += 1
                if scanned > MAX_SUBAGENT_SCAN:
                    # a pathological session cannot be allowed to stall the
                    # 250 ms loop; refuse the rotation instead of scanning on
                    return ("too many subagent transcripts to prove idle "
                            f"({MAX_SUBAGENT_SCAN}+)")
                path = os.path.join(root, name)
                try:
                    mtime = os.stat(path).st_mtime
                except OSError:
                    return "a subagent transcript could not be inspected"
                # agent-<id>.jsonl -> <id>
                seen[os.path.splitext(name)[0].partition("-")[2]] = mtime
                if now - mtime < quiet_seconds:
                    return ("a background subagent wrote "
                            f"{max(now - mtime, 0):.0f}s ago")
                if mtime < since:
                    continue
                if os.path.splitext(name)[0].partition("-")[2] in finished:
                    continue
                busy = _sidechain_busy(path)
                if busy:
                    return busy
    except OSError:
        return ""
    pending = [agent for agent in launched
               if seen.get(agent, since) >= since]
    if pending:
        return (f"{len(pending)} background agent(s) started by this session "
                "have not reported back")
    return ""


def _idle_refusal(transcript_path, now, quiet_seconds, since=0.0):
    """"" when the child is genuinely idle; otherwise why it is still busy.

    Three independent proofs, each covering the others' blind spot: the main
    thread's own turn shape, the parent's record of background agents it
    started but has not seen finish, and the shape of every sidechain
    transcript this child could have written. None of them is "the file has
    not changed lately" — recency can prove work, never completion."""
    records, complete, malformed = _transcript_records(transcript_path)
    if malformed:
        # the tail starts at a record boundary, so a broken line after it is
        # real corruption or a record being written right now — either way
        # this transcript cannot prove the child is idle
        return "the transcript tail has an unreadable record"
    launched, finished = _agent_lifecycle(records)
    return (_turn_is_complete(transcript_path, records, complete)
            or _subagent_activity(
                transcript_path, now, quiet_seconds, since=since,
                launched=launched, finished=finished))


def _capacity_reasons(family):
    """Block reasons that mean 'this seat is spent', not 'this reading cannot
    be trusted'. A spent source is the whole point of a rotation; anything
    else means the source row is unusable and the rotation must hold."""
    return {"5h at 100%", "7d at 100%", "5h critical", "7d critical",
            f"{family} weekly cap at 100%", f"{family} weekly cap critical"}


def _snapshot_row(snapshot, name):
    rows = snapshot.get("accounts") if isinstance(snapshot, dict) else None
    if not isinstance(rows, list):
        return None
    return next((row for row in rows if isinstance(row, dict)
                 and row.get("name") == name), None)


def _preemptive_row_bound(account, family, row, now):
    """"" when ``row`` is a current, identity-bound reading for this account;
    otherwise why an early rotation may not be based on it.

    Deliberately the same shape of proof the cap path demands of its source
    row — minus the "collected after the cap event" clause, which has no
    meaning without an event. Capacity reasons pass (they are the trigger);
    every trust/staleness reason holds."""
    if not isinstance(row, dict):
        return "source has no usage row in the snapshot"
    reason = route.block_reason(account, family, row, {}, now, reserve=0)
    if reason is not None and reason not in _capacity_reasons(family):
        return reason
    captured = row.get("captured_at")
    if not _number(captured) or now - captured > route.OBSERVATION_MAX_AGE:
        return "source observation is not current"
    return ""


def _source_reading_unavailable(reason, family):
    """Whether a `_source_row_is_bound` refusal is "no current reading".

    route.reading_unavailable owns the block_reason vocabulary; these four
    are this function's OWN strings, and they say the same thing about the
    snapshot as a whole — it is too old, or it is not there. A cap that has
    already been corroborated once waits those out; it never disarms on them.
    Nothing about identity, trust or policy is in either list.

    They are literals in two functions, so they can only drift apart, never
    fail loudly. `TheSupervisorsOwnUnreadableStrings` compares this list
    against what `_source_row_is_bound` actually returns and fails if a
    reword touches one and not the other."""
    return reason in ("collect returned no snapshot",
                      "collect did not start after the cap event",
                      "collect did not finish after the cap event",
                      "source observation predates the cap event") \
        or route.reading_unavailable(reason, family)


def _source_row_is_bound(account, family, snapshot, collect_started):
    if not isinstance(snapshot, dict):
        return "collect returned no snapshot"
    started = snapshot.get("run_started")
    generated = snapshot.get("generated")
    floor = int(collect_started)
    if not isinstance(started, (int, float)) or isinstance(started, bool) \
            or started < floor:
        return "collect did not start after the cap event"
    if not isinstance(generated, (int, float)) or isinstance(generated, bool) \
            or generated < floor:
        return "collect did not finish after the cap event"
    row = next((item for item in snapshot.get("accounts", [])
                if isinstance(item, dict) and item.get("name") == account["name"]),
               None)
    reason = route.block_reason(account, family, row, {}, time.time(), reserve=0)
    # One vocabulary, one owner. This was a second copy of _capacity_reasons
    # that had lost `<family> weekly cap critical`, so a scoped cap in the
    # [99,100) band read as a TRUST failure and disarmed supervision — the
    # exact band route.py's scoped-critical gate exists to rotate off.
    # _preemptive_row_bound already reads the helper; so does this.
    if reason is not None and reason not in _capacity_reasons(family):
        return reason
    captured = row.get("captured_at") if isinstance(row, dict) else None
    if not isinstance(captured, (int, float)) or isinstance(captured, bool) \
            or captured < floor:
        return "source observation predates the cap event"
    return ""


class _SignalGuard:
    def __init__(self, process=None):
        self.original = {}
        self.shutdown_signal = None
        self.forwarded = False
        # the child to forward a shutdown signal to; forwarding happens the
        # INSTANT the signal is latched (in _shutdown), not on a later poll,
        # so no notifier-bearing work can run between latch and forward (P1, r6)
        self._process = process

    def _forward(self, signum):
        # os.kill + int attribute reads only — async-signal-safe, so this is
        # correct to call directly from the signal handler
        if self.forwarded or self._process is None:
            return
        self.forwarded = True
        try:
            os.kill(self._process.pid, signum)
        except (ProcessLookupError, OSError):
            pass

    def _shutdown(self, signum, _frame):
        if self.shutdown_signal is None:
            self.shutdown_signal = signum
            self._forward(signum)  # forward immediately, before returning

    def attach(self, process):
        """Bind the live child to this already-installed guard (P1, r7).

        Called the instant Popen returns a child, BEFORE any post-spawn work.
        Idempotent. Set _process FIRST so a signal delivered during attach is
        forwarded by the handler; then forward any signal that was already
        latched while there was no child (e.g. during the Popen fork window)."""
        if self._process is not None:
            return
        self._process = process
        if self.shutdown_signal is not None and not self.forwarded:
            self._forward(self.shutdown_signal)

    def install(self):
        for signum in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
            self.original[signum] = signal.getsignal(signum)
        signal.signal(signal.SIGINT, lambda _s, _f: None)
        signal.signal(signal.SIGHUP, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def poll(self, process):
        # backstop only: forwarding is normally done in _shutdown. If a signal
        # was latched without a process handle, forward it here once.
        if self.shutdown_signal is None or process.poll() is not None:
            return
        if not self.forwarded:
            self.forwarded = True
            try:
                os.kill(process.pid, self.shutdown_signal)
            except (ProcessLookupError, OSError):
                pass

    def restore(self):
        for signum, handler in self.original.items():
            try:
                signal.signal(signum, handler)
            except OSError:
                # CPython raises "signal ignored due to race condition" if a
                # signal is delivered during this handler swap. Restoring the
                # remaining signals must still proceed, and _spawn samples our
                # latch AFTER restore() returns — so this best-effort restore
                # can never skip the requested-kill replay (r9/r10).
                pass


class Supervisor:
    def __init__(self, family, args, account, *, collect_fn=None,
                 popen=None, now=None, sleep=None, supervisor_id=None):
        self.family = family
        # The user's `--settings` never reaches the child as a flag — Claude
        # honours only one and the child must be launched with the
        # supervisor's. It is lifted off the argv here, read ONCE (a mid-run
        # edit can no more flip settings under a live child than it can flip
        # the rotation policy), and merged under the injected document for
        # every generation. Anything unmergeable raises out of the
        # constructor: no child is spawned at all.
        refuse_hook_suppressing_flags(list(args))
        self.initial_args, raw_settings = split_user_settings(list(args))
        self.user_settings = {}
        self.user_settings_source = ""
        if raw_settings is not None:    # an EMPTY value is given, and refused
            self.user_settings, self.user_settings_source = \
                load_user_settings(raw_settings)
            merge_user_settings(self.user_settings, self.user_settings_source)
        self.account = account
        self.collect_fn = collect.run_collect if collect_fn is None else collect_fn
        self.popen = subprocess.Popen if popen is None else popen
        self.now = time.time if now is None else now
        self.sleep = time.sleep if sleep is None else sleep
        self.supervisor_id = supervisor_id or str(uuid.uuid4())
        # Preemptive rotation is resolved ONCE per supervised launch, so a
        # config edit mid-session can never flip the policy under a live
        # child. Reading it can't fail the launch (registry helpers swallow a
        # broken config and return the default).
        self.preemptive = registry.preemptive_handoff()
        self.preemptive_scoped, self.preemptive_overall = \
            registry.preemptive_thresholds()
        # The 5h window: its own switch and its own (higher) threshold, for
        # the reasons in registry.preemptive_session. The THRESHOLD is read
        # whether or not the trigger is armed, because it also defines when a
        # candidate seat is too close to its own 5h wall to be a target.
        self.preemptive_session = registry.preemptive_session()
        self.preemptive_session_percent = registry.preemptive_session_threshold()
        # a supervisor-wide hold that survives a child swap, so an aborted
        # rotation cannot immediately re-target the recovered session
        self.preemptive_hold_until = 0.0
        # Context backstop policy, resolved once per launch for the same
        # reason: no config edit may flip it under a live child. It is
        # deliberately INDEPENDENT of preemptive rotation — one is about the
        # seat's usage, the other about the conversation's own window.
        self.context_backstop = registry.context_backstop()
        self.context_backstop_percent = registry.context_backstop_percent()
        # the same hold/budget shape the preemptive path uses: a forked child
        # inherits its parent's usage records, so without them a rotation that
        # could not change the window would repeat forever
        self.context_hold_until = 0.0
        self.context_rotations = []
        # The model the most recently STOPPED child was running. Recovery
        # happens after that child is gone — in _stop_and_commit, and in run()
        # where the Child handle no longer exists — but what it was running
        # still decides what window its conversation may be resumed into.
        self.stopped_child_model = ""
        self.generation = 0
        self.settings_files = []
        # True once ANY child CLI process has been successfully spawned —
        # the hard boundary for the opt-in launch fallback (see cmd_claude):
        # a failure after this point is normal supervision/exit, never a
        # "no CLI was ever started" condition
        self.spawned_any = False
        # True only inside the Popen window (P0-3): while set, the spawn
        # outcome is unknown and the launch fallback must be suppressed
        self.spawn_ambiguous = False
        # the account whose most recent spawn was left ambiguous — its lease
        # must NOT be released on unwind, since a live child may hold it (P0-1)
        self._ambiguous_account = None
        # the signal guard for the CURRENT spawn cycle: installed by _spawn
        # BEFORE the spawn window and reused by _monitor, so no instant after a
        # child exists is ever unguarded (P1, r7)
        self._signals = None
        # Stamped with self.now() immediately before every DELIBERATE signal
        # this supervisor sends, so _monitor can tell "I stopped it" from
        # "something else did". The THIRD deliberate signal — the shutdown
        # forward inside _SignalGuard — deliberately does NOT write here: a
        # signal handler may do os.kill and int reads only, and the guard
        # already latches shutdown_signal, which is the int _monitor reads.
        self._requested_stop_at = 0.0
        # (returncode, observed_at) once a death nobody asked for is seen.
        # It survives the child, because run()'s cleanup asks it whether the
        # forensics are still needed.
        self.unrequested_death = None

    def _settings_file(self, generation, account, automatic=True):
        directory = paths.ensure_private(_supervisors_dir())
        # The slot name goes in the filename because the filename is the ONLY
        # thing a live lane says about itself in `ps`. On 2026-08-01 at
        # 07:30:37Z an operator read `<uuid>-1.settings.json`, concluded
        # "stale supervisor scaffolding", and killed two live lanes; both
        # panes then sat dark overnight.
        #
        # APPENDED, never prefixed, and never a subdirectory: ops_status
        # (_is_supervised_child) matches `supervisor_id + "-"` at the start
        # and `.settings.json` at the end, and the estate's kill-hygiene glob
        # `supervisors/*.settings.json` matches on the same two anchors. Both
        # still hold, so a pre-upgrade child stays in the census.
        #
        # The account name is CONFIG-controlled, i.e. untrusted input to a
        # path: sanitise before joining.
        slot = re.sub(r"[^A-Za-z0-9_.-]", "_",
                      str(account.get("name") or "lane"))
        filename = f"{self.supervisor_id}-{generation}.{slot}.settings.json"
        destination = os.path.join(directory, filename)
        if automatic:
            # one file, supervisor keys on top; identical to hook_settings()
            # when the user gave none
            document = merge_user_settings(self.user_settings,
                                           self.user_settings_source)
        else:
            # An UNSUPERVISED child (post-rotation source recovery) still gets
            # the user's document — losing a rotation must not also lose their
            # settings — but NOT the hooks. This child deliberately carries no
            # supervisor identity in its environment, so every injected hook
            # would be refused by the adapter and print to the operator's
            # terminal: automation off has to mean off, not noisy.
            document = copy.deepcopy(self.user_settings)
        paths.write_json_atomic(destination, document, mode=0o600)
        self.settings_files.append(destination)
        return destination

    def _cleanup_files(self):
        for destination in self.settings_files + [event_path(self.supervisor_id)]:
            try:
                os.unlink(destination)
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _environment(self, account, generation, automatic):
        environment = collect.scrubbed_env()
        environment["CLAUDE_CONFIG_DIR"] = account["home"]
        if automatic:
            environment.update({
                "HEADROOM_SUPERVISOR_ID": self.supervisor_id,
                "HEADROOM_CHILD_GENERATION": str(generation),
                "HEADROOM_SOURCE_SLOT": account["name"],
            })
        else:
            for key in ("HEADROOM_SUPERVISOR_ID", "HEADROOM_CHILD_GENERATION",
                        "HEADROOM_SOURCE_SLOT", "HEADROOM_HOOK_MATCHER"):
                environment.pop(key, None)
        return environment

    def _spawn(self, account, args, cwd, automatic, plan=None):
        self.generation += 1
        # a settings file is written whenever there is anything to say: the
        # supervisor's hooks, the user's document, or both. With neither
        # (an unsupervised child and no user settings) the argv is unchanged.
        settings = ""
        if automatic or self.user_settings:
            settings = self._settings_file(self.generation, account, automatic)
        argv = ["claude"]
        if settings:
            argv.extend(["--settings", settings])
        argv.extend(args)
        environment = self._environment(account, self.generation, automatic)
        launched_at = self.now()
        # Install the signal guard BEFORE the spawn window and reuse it in
        # _monitor, so no instant after a child could exist is ever unguarded
        # (P1, r7). A signal before any child attaches just latches with
        # nothing to forward; if a child then attaches it is forwarded then,
        # and if the spawn fails the guard is restored below with no orphan.
        guard = _SignalGuard()
        guard.install()
        self._signals = guard
        try:
            # ---- PRE-SPAWN validation (OUTSIDE the ambiguous window) ----
            # Everything that can POSITIVELY prove "no child will exist" is
            # checked here, synchronously, BEFORE spawn_ambiguous is set. A
            # failure here is an unambiguous pre-spawn failure: no fork has
            # happened, so run() may safely recover / the caller may fall back.
            try:
                if plan is not None:
                    handoff.verify_target_binding(plan)
            except handoff.HandoffError as error:
                raise SupervisorError(str(error)) from error
            # resolve the executable up-front so a missing binary is a POSITIVE
            # pre-spawn failure (preserving the missing-binary fallback nicety)
            # instead of being inferred from catching Popen's OSError inside the
            # window. (r5)
            if shutil.which(argv[0]) is None:
                raise SupervisorError(
                    f"`{argv[0]}` not found on PATH; nothing was started")
            # the wrapper handshake means "launch committed": it must be the
            # LAST fallible pre-spawn operation, AFTER every other pre-spawn
            # check (settings/argv/env, verify_target_binding, which) — so an
            # external marker-based wrapper sees a marker only when the spawn is
            # truly imminent (P2-a, r6). A marker with no child would suppress
            # the wrapper's bare-CLI fallback.
            if self.generation == 1:
                if not route.write_launch_marker("supervised", account):
                    raise SupervisorError(
                        "launch marker could not be written; nothing was "
                        "started")
            # hand the account's lease fd to the child so the flock rides on
            # the child (survives an ambiguous spawn / a supervisor exit);
            # no-op unless HEADROOM_SLOT_LEASE=1 (then held_lease_fd is None and
            # no pass_fds kwarg is added, so legacy-off Popen calls are
            # byte-identical) (P0-1)
            popen_kwargs = {}
            lease_fd = route.held_lease_fd(account.get("name"))
            if lease_fd is not None:
                popen_kwargs["pass_fds"] = (lease_fd,)
            # ---- the ambiguous window: ONLY the Popen call (r5) ----
            # Conservative by type-INDEPENDENCE: set spawn_ambiguous=True right
            # before Popen and, on ANY exception escaping Popen (OSError,
            # KeyboardInterrupt, a trace/profile hook raising, anything), LEAVE
            # it True — a child MAY be live, so the run() gate must suppress
            # fallback and source recovery and retain the lease. We do NOT
            # classify the exception; nothing inside this window ever clears the
            # flag. No signal masking, no preexec_fn — trace hooks and signals
            # are both moot.
            #
            # Accepted tiny trade: if the binary vanishes in the microsecond
            # between which() and Popen (TOCTOU), the launch exits 127 without
            # falling back. That is SAFE (never a double-brain), just a missed
            # fallback in an astronomically rare case — safety beats the nicety.
            self.spawn_ambiguous = True
            process = self.popen(argv, env=environment, cwd=cwd,
                                 **popen_kwargs)
        except BaseException:
            # No child was attached to this guard (a pre-spawn failure, or an
            # ambiguous Popen exception whose possible orphan we have no handle
            # for — the accepted r5 trade). Restore the handlers so run()'s
            # recovery / fallback / stop runs with normal signal disposition.
            guard.restore()
            # Sample the latch AFTER restore(): the guard's handler stays
            # installed until restore() reinstalls the originals, so a SIGTERM
            # arriving DURING restore still latches into the guard — reading
            # shutdown_signal before restore() would miss it (P1, r9). Once
            # restored, a further signal reaches the original disposition, not
            # the guard, so this read captures exactly what the guard latched.
            latched = guard.shutdown_signal
            self._signals = None
            # If a shutdown was requested DURING the pre-spawn window (which()
            # / marker write) and that op then failed, honour the kill with the
            # now-restored disposition instead of propagating into fallback /
            # source recovery — a requested kill must never result in a NEW
            # launch. Replay it before re-raising (P1, r8).
            if latched is not None:
                signal.raise_signal(latched)
            raise
        # Popen succeeded: a child IS live. ATTACH it to the already-installed
        # guard IMMEDIATELY, before ANY post-spawn work (the notify below, the
        # Child construction) — so from this instant a delivered signal is
        # forwarded to the child, closing the r6 attach gap (P1, r7).
        guard.attach(process)
        # Do NOT clear spawn_ambiguous or set spawned_any here — leave the
        # window OPEN across the ENTIRE successful return. run() closes it only
        # once it has safely received this Child and taken ownership, so any
        # failure between Popen-success and run()-holds-Child (e.g. Child
        # construction) keeps spawn_ambiguous True → the run() gate suppresses
        # source recovery and retains the lease. (P0-1)
        # launch notify only AFTER a real child exists, so a lost `fallback`
        # event can never leave a dispatcher believing "supervised and started"
        # when nothing did (P1-5)
        if self.generation == 1:
            notify.emit({"event": "launch", "mode": "supervised",
                         "account": account.get("name", ""),
                         "model": self.family, "note": ""})
        return Child(process, account, self.generation,
                     event_path(self.supervisor_id), settings, launched_at,
                     automatic, spawn_args=tuple(args))

    def _collect_once(self, event_time):
        # Provider snapshots use whole-second timestamps.  Crossing the next
        # second before starting removes the historical same-second ambiguity.
        boundary = math.floor(event_time) + 1
        while self.now() < boundary:
            self.sleep(min(POLL_SECONDS, boundary - self.now()))
        started = self.now()
        try:
            snapshot = self.collect_fn(quiet=True)
        except TypeError:
            snapshot = self.collect_fn()
        except Exception as error:  # noqa: BLE001 — a failed proof never stops
            # A collect that failed proves nothing either way: it is the same
            # "no information" class as an empty target ranking, not a
            # contradiction, so it holds and retries rather than costing a
            # live session its automation over one network blip.
            raise CapacityHold(
                f"fresh usage collect failed: {error}") from error
        return snapshot, started

    def _fresh_collect(self, event_time):
        # A SKIPPED collect is not a failed collect, and it is not a fresh one
        # either. run_collect returns the previous snapshot from disk on lock
        # contention (collect.py, `if not locked:`) with no exception and no
        # sentinel, so a skip reads as success here and the stale run_started
        # then disarms a live session — permanently, because a capped child
        # emits no further hook events and nothing ever retries.
        #
        # The skip is INFERRED from run_started rather than reported, because
        # the alternative — a new return contract on run_collect — touches
        # every caller. The inference is commented at both ends; if the
        # snapshot ever stops carrying run_started, this degrades to "always
        # contended", which holds the child armed rather than disarming it.
        for attempt in range(COLLECT_CONTENTION_RETRIES + 1):
            snapshot, started = self._collect_once(
                event_time if attempt == 0 else self.now())
            run_started = snapshot.get("run_started") \
                if isinstance(snapshot, dict) else None
            if isinstance(run_started, (int, float)) \
                    and not isinstance(run_started, bool) \
                    and run_started >= math.floor(started):
                return snapshot, started
            if attempt < COLLECT_CONTENTION_RETRIES:
                self.sleep(POLL_SECONDS)
        raise CapacityHold(
            "fresh usage collect was skipped: another collector holds the lock")

    def _prove_cap(self, child, record):
        message = cap_message(record, child)
        if not message:
            child.pending_cap = None
            return None
        binding = child.binding
        if _subagent_attributed(record) \
                and record["payload"].get("session_id") == binding.session_id \
                and _last_transcript_cap_evidence(
                    binding.transcript_path) is None:
            # Attributed to a background subagent yet naming THIS parent —
            # 27 of 35 live StopFailure records look exactly like this. The
            # refusal is real, but it is not evidence the PARENT session is
            # walled, and the parent transcript will never contain it
            # (subagents write to <session>/subagents/agent-*.jsonl). So the
            # cap-time model lookup below can only come back empty, spend its
            # retries and raise PendingCapTimeout, which _attempt_cap turns
            # into a permanent _lose_supervision. Measured on the real
            # 2026-07-27 timeline: disarmed at +39.5s, and the parent's own
            # genuine cap arrived at +79.5s to find automation already gone.
            #
            # The transcript check is what keeps this from being a new way to
            # lose a real wall: if the PARENT itself refused, that is
            # independent evidence this session is capped and it rotates,
            # whatever the hook was tagged with. Suppression fires only in the
            # case that used to time out — a healthy newest main-chain turn.
            # Say it out loud either way; a suppressed cap is never silent.
            child.pending_cap = None
            why = ("the cap was refused for a background subagent, not this "
                   "session")
            print(f"[headroom] {child.account['name']} hit a subscription cap "
                  f"but NO automatic handoff will run: {why}.",
                  file=sys.stderr)
            notify.emit({"event": "cap_unhandled",
                         "account": child.account.get("name", ""),
                         "reason": why, "bound": True,
                         "agent_id": (record["payload"].get("agent_id")
                                      or record["payload"].get("agent_type"))})
            return None
        received_at = record["received_at"]
        pending = child.pending_cap
        if pending is None or (
                pending.session_id != binding.session_id
                or pending.transcript_path != binding.transcript_path
                or pending.epoch != binding.epoch
                or pending.received_at != received_at):
            pending = PendingCap(
                record, binding.session_id, binding.transcript_path,
                binding.epoch, received_at, received_at + CAP_MODEL_TIMEOUT)
            child.pending_cap = pending
        try:
            self._proof_current(child, pending)
        except SupervisorError:
            child.pending_cap = None
            raise
        try:
            evidence = _last_transcript_cap_evidence(
                binding.transcript_path)
            if evidence is None:
                if self.now() >= pending.deadline:
                    # A timed-out lookup is an ABSENCE of information, not a
                    # contradicted proof: the transcript may simply not be
                    # flushed yet. Give it a bounded number of further
                    # windows before disarming a live session over 6 seconds.
                    if pending.extensions < CAP_MODEL_RETRIES:
                        pending = replace(
                            pending, extensions=pending.extensions + 1,
                            deadline=self.now() + CAP_MODEL_TIMEOUT)
                        child.pending_cap = pending
                        return pending
                    child.pending_cap = None
                    raise PendingCapTimeout(
                        "could not determine the cap-time model before "
                        f"{CAP_MODEL_TIMEOUT * (CAP_MODEL_RETRIES + 1):g}s")
                return pending
            source = handoff.SourceSession(
                binding.session_id, binding.transcript_path,
                child.account, evidence["model"])
            family = handoff.resolve_model_family(source)
            proof = CapProof(record, evidence["message"], family,
                             binding.session_id, binding.transcript_path,
                             binding.epoch, evidence["stat"])
            child.pending_cap = None
            return proof
        except PermanentSupervisorError:
            raise
        except (handoff.HandoffError, registry.RegistryError) as error:
            raise PermanentSupervisorError(str(error)) from error

    def _attempt_cap(self, child, record, announce_non_cap=False):
        try:
            candidate = self._prove_cap(child, record)
            if isinstance(candidate, CapProof):
                return candidate
            if candidate is None and announce_non_cap:
                print("[headroom] rate-limit hook was not a subscription cap; "
                      "child continues", file=sys.stderr)
        except PendingCapTimeout as error:
            _lose_supervision(child, f"cap-time model unavailable: {error}")
            print(f"[headroom] {error}; automatic handoff disabled — /exit then "
                  "`headroom handoff` to move manually", file=sys.stderr)
        except PermanentSupervisorError as error:
            _lose_supervision(child, f"cap not corroborated: {error}")
            child.pending_cap = None
            print(f"[headroom] cap not corroborated ({error}); automatic "
                  "handoff disabled for this child", file=sys.stderr)
        except SupervisorError as error:
            print(f"[headroom] cap not corroborated ({error}); child continues",
                  file=sys.stderr)
        return None

    @staticmethod
    def _proof_current(child, proof):
        binding = child.binding
        if (binding is None or binding.session_id != proof.session_id
                or binding.transcript_path != proof.transcript_path
                or binding.epoch != proof.epoch
                or child.session_epoch != proof.epoch
                or (proof.session_id, proof.epoch) in child.dead_sessions):
            raise SupervisorError("cap proof expired after a session transition")

    @staticmethod
    def _events_pending(child):
        try:
            size = os.path.getsize(child.event_path)
        except FileNotFoundError:
            size = 0
        except OSError as error:
            raise SupervisorError("cannot recheck hook event journal") from error
        if size != child.event_offset:
            raise SupervisorError("cap proof expired after a newer hook event")

    @staticmethod
    def _recorded_scope(child, family, window):
        """The cap the hold recorded, re-read off THIS snapshot.

        Same shape `route.cap_scope` returns, but the key, the window and the
        account-wide flag come from what was corroborated when the hold began
        — only the percentage and the reset are refreshed. That is the whole
        point: the session moves on the cap it proved, cooling the window it
        proved, with this snapshot's reset rather than a stale one."""
        reset = window.get("resets_at")
        return {
            "key": child.cap_scope_key,
            "account_wide": not child.cap_scope_window.startswith("scoped:"),
            "family": family,
            "window": child.cap_scope_window,
            "used_percent": float(window["used_percent"]),
            "reset": reset if _number(reset) else None,
        }

    @staticmethod
    def _scope_window(family, row, key):
        """The window a cap scope key names, in this row, or None."""
        windows = row.get("windows") if isinstance(row, dict) else None
        if not isinstance(windows, dict):
            return None
        if key.startswith("scoped:"):
            return route.scoped_window_for(family, windows)
        return windows.get(key)

    def _preflight(self, child, proof, held=False):
        """The cap path's admission chain.

        `held` says a previous attempt on THIS proof already corroborated the
        cap, and Child.cap_scope_key / .cap_scope_window record exactly which
        scope it corroborated. Those two are written ONCE and read on every
        retry: they decide whether an unreadable snapshot waits or disarms,
        and they are the only cap this proof may ever admit."""
        self._proof_current(child, proof)
        try:
            handoff.guard_source_stable(
                proof.transcript_path, now=self.now(),
                sleep=lambda _seconds: None, quiet_seconds=QUIET_SECONDS)
        except handoff.HandoffError as error:
            if "changed recently" in str(error):
                raise
            raise SupervisorError(str(error)) from error
        try:
            quiet_stat = handoff._transcript_stat(proof.transcript_path)
            if quiet_stat != proof.transcript_stat:
                raise SupervisorError(
                    "cap proof expired after the transcript changed")
            snapshot, started = self._fresh_collect(
                proof.event["received_at"])
            self._proof_current(child, proof)
            self._events_pending(child)
            if handoff._transcript_stat(proof.transcript_path) != quiet_stat:
                raise SupervisorError("source transcript changed during collect")
            reason = _source_row_is_bound(
                child.account, proof.family, snapshot, started)
            if reason:
                # A held cap must reach the HOLD path on an unreadable
                # snapshot, not the disarm path. This gate runs before any of
                # the cap-scope reasoning below, so without this line the one
                # case the whole wait was built for — the corroborating window
                # going expired or malformed mid-hold — walked straight into
                # _lose_supervision, on the dead seat, exactly like the bug
                # the wait replaced. Trust, identity and policy refusals are
                # NOT in this class and disarm as they always did.
                if held and _source_reading_unavailable(reason, proof.family):
                    raise CapacityHold(
                        f"{reason} — holding the proof rather than disarming "
                        "on a snapshot that proves nothing")
                raise SupervisorError(reason)
            scope = route.cap_scope(snapshot, child.account["name"],
                                    proof.family, proof.message)
            if not held:
                # First look: the hook says capped and fresh usage does not.
                # That is a CONTRADICTION and it disarms, unchanged — a proof
                # nobody can corroborate must never move a session.
                if scope is None:
                    raise SupervisorError(
                        "fresh usage is below 99% or the cap scope is ambiguous")
                child.cap_scope_key = scope.get("key") or ""
                child.cap_scope_window = scope.get("window") or ""
            elif ((scope or {}).get("key") != child.cap_scope_key
                    or (scope or {}).get("window") != child.cap_scope_window):
                # A re-attempt may only ever admit THE cap it recorded. A
                # different scope here is a different cap: reading it as this
                # one would cool a window we never corroborated and quietly
                # rewrite what we are holding for (observed: a scoped Fable
                # cap whose pool reset to 4% while the 5h window filled came
                # back as a 5h handoff). And a matching KEY is not a matching
                # cap: both account-wide windows share `source:*`, so a held
                # 5h proof whose window reset while the 7d filled behind it
                # arrived here with the same key, sailed past this guard, and
                # produced a live handoff cooling a week nobody corroborated
                # — with the rotation switch off, even. So interrogate the
                # recorded window whenever EITHER differs. It has THREE
                # answers, not two: a readable reading below 99% means the
                # cap we held for is genuinely over; a readable reading still
                # AT the wall means it is genuinely not over and this attempt
                # should proceed; and only an unreadable one proves nothing
                # and keeps the proof.
                window = self._scope_window(
                    proof.family,
                    _snapshot_row(snapshot, child.account["name"]),
                    child.cap_scope_window)
                used = window.get("used_percent") \
                    if isinstance(window, dict) else None
                readable = isinstance(window, dict) \
                    and window.get("freshness") != "expired_observation" \
                    and _number(used) and 0 <= used <= 100
                if readable and used < 99:
                    raise CapCleared(
                        f"the capped {child.cap_scope_window} window is back "
                        f"to {used:g}% — it reset while we waited for a seat")
                if not readable:
                    raise CapacityHold(
                        f"the capped {child.cap_scope_window} window is not "
                        "readable in fresh usage — holding the proof rather "
                        "than assuming it reset")
                if not CAP_ROTATE_AT_WALL:
                    # The switch's documented meaning (README): a recorded
                    # window still readable and still at the wall KEEPS
                    # WAITING when the operator sets 0 — whichever key fresh
                    # usage now prefers. Round 5 refused the first version of
                    # this branch, which exempted the same-key relabel on the
                    # grounds that it predated the switch; predating the
                    # switch is not an exemption from its contract.
                    raise CapacityHold(
                        f"the capped {child.cap_scope_window} window is "
                        "still at the wall and rotation at the wall is "
                        "disabled — holding the proof")
                if (scope or {}).get("key") == child.cap_scope_key:
                    # Same key, and the recorded window itself is still at
                    # the wall: this is the account-wide RELABEL — the other
                    # account window crossed too and now binds the cooldown.
                    # That was never a scope change and it proceeds on the
                    # fresh scope. What the window comparison above added is
                    # only this: the relabel may no longer swallow a recorded
                    # window that has provably RESET.
                    pass
                else:
                    # Still at the wall under a different key. Rotate on the
                    # RECORDED scope, rebuilt from the recorded window's own
                    # fresh reading — never on the different scope we just
                    # read, which is the cap nobody corroborated.
                    scope = self._recorded_scope(child, proof.family, window)
            reset = scope.get("reset")
            if (not isinstance(reset, (int, float)) or isinstance(reset, bool)
                    or not math.isfinite(reset) or reset <= self.now()):
                # Same rule as the row gate above: on a first look this is an
                # unprovable cap and disarms; mid-hold it is one snapshot's
                # missing metadata about a cap we already corroborated.
                if held:
                    raise CapacityHold(
                        "fresh cap reset is missing or ambiguous — holding "
                        "the proof rather than disarming on it")
                raise SupervisorError("fresh cap reset is missing or ambiguous")
            target, target_family = self._cap_target(
                child, proof.family, snapshot, proof.transcript_path)
            binding = child.binding
            source = handoff.SourceSession(
                proof.session_id, proof.transcript_path, child.account,
                proof.family, int(self.now()))
            cap_proof = {
                "authenticated": True,
                "event_received_at": proof.event["received_at"],
                "session_id": proof.session_id, "epoch": proof.epoch,
            }
            # The plan's family is the family that CAPPED: `commit_handoff`
            # cools that pool and the ledger records it, so naming the
            # downgraded family here would cool Opus over a spent Fable week
            # and leave the exhausted pool routable. `resume_family` carries
            # the tier the successor actually launches on — the seat below is
            # gated on THAT, not on the pool we are moving away from.
            plan = handoff.plan_handoff(
                source, proof.family, target, snapshot, cap_proof,
                binding.cwd, cooldown_scope=scope, automatic=True,
                resume_family=target_family,
                child_generation=child.generation)
            route.preflight_cooldowns()
            try:
                handoff.select_target(
                    child.account["name"], snapshot, target_family,
                    requested=target["name"])
            except handoff.NoHeadroomError as error:
                raise CapacityHold(str(error)) from error
            self._proof_current(child, proof)
            self._events_pending(child)
            if handoff._transcript_stat(proof.transcript_path) \
                    != plan.source_stat:
                raise SupervisorError("source transcript changed before admission")
            if reset <= self.now():
                # the cap ended on its own: there is nothing to move away from
                raise CapCleared("cap reset elapsed before admission")
            handoff.reserve_automatic(
                plan, self.now(), loop_window=LOOP_WINDOW, loop_max=LOOP_MAX)
            self._proof_current(child, proof)
            self._events_pending(child)
            if reset <= self.now():
                # Past the reservation, so release it explicitly: a failure
                # row frees the target slot and costs no loop budget (nothing
                # was ever stopped). Then treat it as what it is — the cap
                # ended, the session is fine, automation stays armed.
                self._failure(plan, "cap_reset_elapsed_before_stop")
                raise CapCleared("cap reset elapsed before stop")
            return plan
        except SupervisorError:
            raise
        except (handoff.HandoffError, registry.RegistryError, RuntimeError,
                OSError, ValueError) as error:
            raise SupervisorError(str(error)) from error

    def _cap_target_unfit(self, family, row):
        """Why a CAPPED session should not be moved onto this seat, or "".

        The preemptive twin of this (`_target_unfit`) asks a harder question,
        because that rotation is optional. This one asks only whether the
        destination is about to refuse too — see CAP_TARGET_WEEKLY_PERCENT.

        Readability stays route.block_reason's job: it has already refused
        every candidate whose windows are missing, invalid, expired or at
        100%, so an unreadable percentage here adds nothing."""
        windows = row.get("windows") if isinstance(row, dict) else None
        if not isinstance(windows, dict):
            return ""
        checks = [("5h", windows.get("5h"), self.preemptive_session_percent),
                  ("7d", windows.get("7d"), CAP_TARGET_WEEKLY_PERCENT)]
        if family in route.SCOPED_FAMILIES:
            checks.append(("scoped:" + family,
                           route.scoped_window_for(family, windows),
                           CAP_TARGET_WEEKLY_PERCENT))
        for key, window, ceiling in checks:
            if not isinstance(window, dict) \
                    or window.get("freshness") == "expired_observation":
                continue
            used = window.get("used_percent")
            if _number(used) and 0 <= used <= 100 and used >= ceiling:
                return f"{key} at {used:g}%"
        return ""

    def _cap_target(self, child, family, snapshot, transcript_path=""):
        """``(target, family)`` — where this capped conversation goes next.

        Tries the family the session was running first. If every seat is
        walled for it, walks DOWN the ladder (fable -> opus -> sonnet ->
        haiku) and takes the first family some healthy seat can serve, so a
        spent weekly pool costs the session its model tier rather than its
        life. Only a fleet with no room for ANY family still raises
        CapacityHold, and the hold reports the family that got closest.

        A transcript that needs the 1M window REPLACES the walk rather than
        trimming it: such a session is re-modelled by _window_fit_argv
        whatever this decides, so the only honest destinations are the
        families that model belongs to (see _fit_bounded). That constraint is
        not a tier preference and is not subject to FAMILY_FALLBACK_ENABLED —
        it is the difference between checking the pool a successor will spend
        and checking a different one."""
        attempts = [family]
        if FAMILY_FALLBACK_ENABLED and family in FAMILY_LADDER:
            attempts += list(FAMILY_LADDER[FAMILY_LADDER.index(family) + 1:])
        attempts = self._fit_bounded(attempts, child, transcript_path)
        # The move is window-fit-driven only when the bound REMOVED the capped
        # family. If that family survived and simply had no seat, the cause is
        # exhausted capacity and saying otherwise would blame the transcript
        # for a full pool.
        fitted = family not in attempts
        first_hold = None
        for attempt in attempts:
            try:
                target = self._cap_target_in_family(child, attempt, snapshot)
            except CapacityHold as hold:
                first_hold = first_hold or hold
                continue
            if attempt != family:
                why = (f"this transcript only fits the 1M window, which {family} "
                       f"cannot serve" if fitted
                       else f"no seat can serve {family}")
                print(f"[headroom] {why}; moving this session to {attempt} on "
                      f"{target['name']} rather than stopping it",
                      file=sys.stderr)
                notify.emit({"event": "family_downgrade",
                             "account": target["name"],
                             "from": family, "to": attempt,
                             "reason": "window_fit" if fitted else "capacity"})
            return target, attempt
        raise first_hold if first_hold is not None else CapacityHold(
            f"no seat has headroom worth moving to for the {family} family")

    @staticmethod
    def _fit_bounded(attempts, child, transcript_path):
        """The families an OVER-LIMIT transcript can actually live in.

        A transcript past the fit limit WILL be re-modelled onto a 1M model by
        _window_fit_argv: the successor cannot load otherwise. So the seat has
        to be gated on THAT model's family, or the gate and the launch name
        two different things — checked for Fable, started on Opus — and the
        rotation spends a pool nobody looked at. Its homes are the child's own
        1M model (which _window_fit_argv keeps when the routed family matches)
        and the configured fit model, in that order.

        This deliberately REPLACES the walk instead of trimming it, and it
        never falls back to the capped family:

        - a home ABOVE the capped family is still a home. That is not the
          ladder promoting — a cap may not do that — it is the gate finally
          naming the model the window fit already forced. Checking the pool
          the successor will spend beats checking one it will not.
        - when NO home is a family this ladder knows (an operator override of
          HEADROOM_CONTEXT_FIT_MODEL to something generic or unrecognised)
          there is nothing safe to gate on, so the cap holds and says why.
          Routing blind is how a "successful" rotation re-caps on its first
          prompt.

        A transcript that FITS is unbounded: no re-modelling will happen, so
        routing is free."""
        if not transcript_path:
            return attempts
        used = _context_used(transcript_path)
        if used is None or used <= CONTEXT_WINDOW_FIT_LIMIT:
            return attempts
        # A home must be BOTH a 1M model (or it cannot hold the transcript at
        # all) and a family this ladder can gate a seat on. A recognised but
        # standard-window override — HEADROOM_CONTEXT_FIT_MODEL=sonnet — is
        # neither one thing nor the other: it names a routable pool and then
        # resumes into a 200k window, so it is not a home.
        candidates = [_model_flag(child.spawn_args), CONTEXT_FIT_MODEL]
        homes = [fam for fam in dict.fromkeys(
            _family_or_blank(name) for name in candidates
            if "[1m]" in str(name or "").lower()) if fam in FAMILY_LADDER]
        if not homes:
            raise CapacityHold(
                f"this transcript needs the 1M window and the fit model "
                f"({CONTEXT_FIT_MODEL}) is not a 1M model on a routable "
                f"family — no seat can be gated on what this session would "
                f"run (set HEADROOM_CONTEXT_FIT_MODEL to something like "
                f"opus[1m])")
        ordered = [fam for fam in attempts if fam in homes]
        if not ordered:
            # NOTHING the walk offered can hold this conversation. Reaching
            # past the walk here is the physical constraint speaking, not a
            # tier preference, so HEADROOM_FAMILY_FALLBACK does not gate it:
            # the alternative is gating a pool the successor will not spend.
            return list(homes)
        if FAMILY_FALLBACK_ENABLED:
            # extra homes beyond the first are ordinary alternatives, and
            # taking one IS a voluntary tier change — so the switch governs it
            ordered += [fam for fam in homes if fam not in ordered]
        return ordered

    def _cap_target_in_family(self, child, family, snapshot):
        """The best routable seat, within ONE family, that is not itself at a
        wall.

        `select_target` alone is not enough here: its gate is the ROUTING
        gate, which is about whether a seat may be used at all, not about
        whether moving a capped conversation onto it is worth the handoff.
        Walk the same ranking the router produces, skip the seats that are
        about to refuse, and put the winner back through the full gate so
        nothing bypasses it.

        Finding nothing raises CapacityHold, not a bare refusal: "every seat
        is at a wall" is the textbook thing to wait out rather than disarm
        for, and the hold is bounded."""
        source = child.account["name"]
        skipped = []
        for account, reason in route.candidates(family, snapshot):
            if account.get("name") == source:
                continue
            if reason is None:
                reason = self._cap_target_unfit(
                    family, _snapshot_row(snapshot, account["name"]))
            if reason:
                # say WHY per seat: this text is what a 3am operator (and the
                # cap_held event) has to reason from
                skipped.append(f"{account['name']} ({reason})")
                continue
            try:
                return handoff.select_target(source, snapshot, family,
                                             requested=account["name"])
            except handoff.NoHeadroomError as error:
                raise CapacityHold(str(error)) from error
        detail = f" (skipped: {', '.join(skipped)})" if skipped else ""
        raise CapacityHold(
            f"no seat has headroom worth moving to for the {family} family"
            f"{detail}")

    # ---- waiting out a cap: hold, don't disarm ---------------------------

    def _cap_hold_clear(self, child):
        child.cap_hold_attempts = 0
        child.cap_hold_next = 0.0
        child.cap_hold_reason = ""
        child.cap_hold_key = ()
        child.cap_scope_key = ""
        child.cap_scope_window = ""

    def _cap_hold_sync(self, child, proof):
        """Bind the hold to ONE proof. A different proof (a later refusal, a
        new session) starts its own hold with its own budget and its own
        corroboration — nothing about the last one may vouch for it."""
        event = getattr(proof, "event", None)
        key = (getattr(proof, "session_id", None),
               getattr(proof, "epoch", None),
               event.get("received_at") if isinstance(event, dict) else None)
        # an unidentifiable proof gets a fresh hold every time: full budget,
        # and nothing inherited from whatever came before it
        if key[0] is None or child.cap_hold_key != key:
            self._cap_hold_clear(child)
            child.cap_hold_key = key

    def _cap_hold(self, child, error):
        """Hold this proof for another interval. False once the budget is
        spent, and the caller then disarms exactly as it always did.

        A hold is a delay, never a promise: the child keeps running with
        automation armed, and every attempt is the same full preflight, so
        nothing is admitted on weaker proof than a first attempt would need."""
        child.cap_hold_attempts += 1
        if child.cap_hold_attempts > CAP_HOLD_MAX:
            return False
        child.cap_hold_next = self.now() + CAP_HOLD_SECONDS
        reason = str(error)
        if child.cap_hold_reason == reason:
            return True
        child.cap_hold_reason = reason
        print(f"[headroom] automatic handoff is waiting for capacity "
              f"({reason}); child continues with the cap handoff still armed, "
              f"retrying every {CAP_HOLD_SECONDS:g}s",
              file=sys.stderr)
        notify.emit({"event": "cap_held",
                     "account": child.account.get("name", ""),
                     "reason": reason})
        return True

    # ---- preemptive rotation: leave BEFORE the wall ----------------------
    #
    # The cap-reactive path can only fire once the provider has already
    # refused a turn. Preemptive rotation watches the same usage feed every
    # other headroom surface uses and moves the conversation while the seat
    # still has room — but ONLY at a safe boundary, and ONLY through the
    # unchanged handoff pipeline (staging, target verification, leases,
    # ledger admission, resume --fork-session). It is strictly an
    # optimisation layered on top: every refusal defers and leaves the
    # cap-reactive guarantee fully armed.

    def _usage_snapshot(self):
        """The freshest usage this supervisor can reach without new deps.

        Prefer the private snapshot every other headroom surface already
        maintains (the same reading the dashboard and the fleet usage feed are
        built from), so a supervised session costs the provider nothing while
        a collector is running; pay for a private collect only once that feed
        has gone stale."""
        snapshot = paths.load_json(paths.private_snapshot_path())
        if route._snapshot_fresh(snapshot, self.now(), PREEMPT_SNAPSHOT_MAX_AGE):
            return snapshot
        try:
            return self.collect_fn(quiet=True)
        except TypeError:
            return self.collect_fn()
        except Exception as error:  # noqa: BLE001 — a failed poll never stops
            raise SupervisorError(f"fresh usage collect failed: {error}") from error

    def _child_family(self, child):
        """The Claude family this child is actually running (raises when it
        cannot be resolved — an unknown family can never be rotated)."""
        binding = child.binding
        model = _transcript_model(binding.transcript_path) or binding.model
        return handoff.resolve_model_family(handoff.SourceSession(
            binding.session_id, binding.transcript_path, child.account, model))

    def _threshold_crossing(self, family, row):
        """``(window key, used percent)`` when this row has crossed a
        preemptive threshold, else None.

        Absence of proof is never a crossing: a missing, malformed, expired,
        or out-of-range reading returns None and the session stays put.

        The 5h window used to be excluded here, on the argument that it heals
        within hours and the cap-reactive path already covers it. That is true
        of a session that will go idle and wait for it, and false of the one
        headroom exists for: continuous autonomous work, where the wall
        arrives mid-task and "it resets by itself in four hours" means four
        hours of nothing. So it IS a trigger now — but the last one checked,
        at its own higher threshold (registry.preemptive_session), off with
        one env var, and only ever acted on when a target with real 5h
        headroom exists (see _target_unfit). A weekly window is reported ahead
        of it because a weekly window does not heal.
        """
        windows = row.get("windows") if isinstance(row, dict) else None
        if not isinstance(windows, dict):
            return None
        scoped = route.scoped_window_for(family, windows) \
            if family in route.SCOPED_FAMILIES else None
        for window, key, threshold in (
                (scoped, "scoped:" + family, self.preemptive_scoped),
                (windows.get("7d"), "7d", self.preemptive_overall),
                (windows.get("5h") if self.preemptive_session else None,
                 "5h", self.preemptive_session_percent)):
            if not isinstance(window, dict) \
                    or window.get("freshness") == "expired_observation":
                continue
            used = window.get("used_percent")
            if _number(used) and 0 <= used <= 100 and used >= threshold:
                return key, float(used)
        return None

    def _target_unfit(self, family, row, window=""):
        """Why this candidate is not worth moving to, or "".

        `window` is the crossing being answered, so the rule can be as strict
        as that crossing requires:

        * ALWAYS — a seat that has itself crossed a preemptive threshold, and
          a seat at or past the 5h threshold whether or not the 5h TRIGGER is
          armed. Rotating into a window that is about to refuse is the one
          move that is worse than staying: it spends a handoff, a restart and
          the loop budget to arrive at the same wall (defect: a 99% 5h seat
          was a legal target, because only the scoped and 7d windows were
          checked).
        * 5h CROSSINGS ONLY — a margin on top, so the move actually buys time.

        Readability is route.block_reason's job, not this one's: it has
        already refused every candidate whose 5h window is missing, invalid,
        expired or at 100%, so an unreadable percentage here means "nothing
        further proven against this seat", not "safe".
        """
        crossing = self._threshold_crossing(family, row)
        if crossing is not None:
            return "%s at %g%%" % crossing
        windows = row.get("windows") if isinstance(row, dict) else None
        session = windows.get("5h") if isinstance(windows, dict) else None
        if not isinstance(session, dict):
            return ""
        used = session.get("used_percent")
        if not _number(used) or not 0 <= used <= 100:
            return ""
        ceiling = self.preemptive_session_percent
        if window == "5h":
            ceiling = max(0.0, ceiling - PREEMPT_SESSION_MARGIN)
        if used >= ceiling:
            return f"5h at {used:g}%"
        return ""

    def _preemptive_observation(self, child):
        """``(proof, snapshot)`` for a live threshold crossing, else None."""
        binding = child.binding
        family = self._child_family(child)
        snapshot = self._usage_snapshot()
        crossing = self._threshold_crossing(
            family, _snapshot_row(snapshot, child.account["name"]))
        if crossing is None:
            return None
        window, used = crossing
        observed_at = self.now()
        proof = PreemptiveProof(
            event={"received_at": observed_at},
            message=f"{window} window at {used:g}%", family=family,
            session_id=binding.session_id,
            transcript_path=binding.transcript_path, epoch=binding.epoch,
            transcript_stat=handoff._transcript_stat(binding.transcript_path),
            window=window, used_percent=used,
            deadline=observed_at + PREEMPT_DECISION_TTL)
        return proof, snapshot

    def _preemptive_target(self, child, family, snapshot, window=""):
        """The best seat that is BOTH routable and not itself near a limit.

        Ranking is Fable-headroom-primary, so for an Opus/Sonnet or overall-7d
        crossing the top-ranked candidate can easily be the one already over
        the relevant threshold — rejecting only that one and backing off would
        strand a session while a healthy seat sat two places down the list.
        Walk the ranking instead, skipping unfit seats (moving onto one would
        just be undone by the next poll), and re-run the full select_target
        gate on the winner so nothing bypasses it.

        When NO seat is fit, this raises and the caller only defers. For a 5h
        crossing that is the right answer and not a failure: if every seat is
        near its own 5h cap, staying put costs one wait and burns nothing,
        while moving costs a restart AND a seat and still hits a wall. Say so
        in the message — a hold nobody can explain gets "fixed" by someone
        raising the threshold."""
        source = child.account["name"]
        skipped = []
        for account, reason in route.candidates(family, snapshot):
            if reason is not None or account.get("name") == source:
                continue
            unfit = self._target_unfit(
                family, _snapshot_row(snapshot, account["name"]), window)
            if unfit:
                skipped.append(f"{account['name']} ({unfit})")
                continue
            return handoff.select_target(source, snapshot, family,
                                         requested=account["name"])
        detail = (f" (skipped, itself near its limit: {', '.join(skipped)})"
                  if skipped else "")
        if window == "5h":
            raise SupervisorError(
                f"no seat has real 5h headroom for the {family} family"
                f"{detail} — holding here: this window heals on its own, so "
                "waiting it out beats spending a seat to land on another wall")
        raise SupervisorError(
            f"no target with proven headroom for the {family} family"
            f"{detail}")

    def _preemptive_due(self, child, proof):
        """True when this tick may attempt a preemptive rotation.

        A proven cap ALWAYS wins — a proof in flight (or a pending one) skips
        the poll entirely — and the child must be enabled, bound, and live.
        Ordered so a disqualifying condition short-circuits before the clock
        is consulted."""
        return (self.preemptive and proof is None and child.automation
                and child.binding is not None and child.pending_cap is None
                and not child.session_ended
                and self.now() >= child.preemptive_next_check
                and self.now() >= self.preemptive_hold_until)

    def _preemptive_defer(self, child, reason, *, backoff=True, announce=True):
        """Hold this rotation without disarming anything.

        Spaces out the retry so a stranded session cannot thrash the poll (or
        an observer command), and reports each DISTINCT hold once. `announce`
        is False for conditions observed before any crossing is known — those
        are diagnostics, not fleet events."""
        child.preemptive_next_check = self.now() + (
            PREEMPT_BACKOFF_SECONDS if backoff else PREEMPT_POLL_SECONDS)
        if child.preemptive_last_hold == reason:
            return
        child.preemptive_last_hold = reason
        print(f"[headroom] preemptive handoff held: {reason}; child continues "
              f"with cap handoff still armed", file=sys.stderr)
        if announce:
            notify.emit({"event": "preemptive_held",
                         "account": child.account.get("name", ""),
                         "reason": reason})

    def _preemptive_cycle(self, child):
        """One preemptive attempt. Returns a Relaunch when the session moved,
        otherwise None.

        Never disarms: preemptive rotation is an optimisation on top of the
        cap-reactive guarantee, so no target, a busy child, or any guard
        refusing simply defers with the child running and automation on.

        The except clauses are deliberately broad (BLE001): an optimisation
        must never take down a supervised session, so every failure degrades
        to "no early rotation this tick"."""
        child.preemptive_next_check = self.now() + PREEMPT_POLL_SECONDS
        try:
            observed = self._preemptive_observation(child)
        except Exception as error:  # noqa: BLE001
            # nothing is known about a crossing yet — hold quietly
            self._preemptive_defer(child, f"usage unreadable: {error}",
                                   announce=False)
            return None
        if observed is None:
            child.preemptive_announced = False
            child.preemptive_last_hold = ""
            return None
        proof, snapshot = observed
        try:
            # reuse the ranked route selection: no proven target, no rotation
            self._preemptive_target(child, proof.family, snapshot,
                                    proof.window)
        except Exception as error:  # noqa: BLE001
            self._preemptive_defer(child, str(error))
            return None
        if not child.preemptive_announced:
            child.preemptive_announced = True
            print(f"[headroom] {child.account['name']} {proof.message} — "
                  f"scheduling a handoff at the next idle boundary",
                  file=sys.stderr)
            notify.emit({"event": "preemptive_scheduled",
                         "account": child.account.get("name", ""),
                         "family": proof.family, "window": proof.window,
                         "used_percent": proof.used_percent})
        try:
            plan = self._preemptive_preflight(child, proof, snapshot)
        except Exception as error:  # noqa: BLE001
            # a child mid-turn is the expected, frequent case: retry on the
            # normal cadence instead of the long backoff
            busy = ("changed recently" in str(error)
                    or "still changing" in str(error))
            self._preemptive_defer(child, str(error), backoff=not busy)
            return None
        relaunch = None
        try:
            relaunch = self._stop_and_commit(child, plan, proof)
            # A RETURN of any kind means the SIGTERM went out: _stop_and_commit
            # raises only BEFORE it (the invariant the except below records).
            # So this is where a rotation says "that death was mine" — without
            # it, a stop whose commit then failed leaves _monitor polling a
            # child WE killed, and the next poll would file it as a killing by
            # somebody else. Stamped at the call site rather than beside the
            # os.kill because _stop_and_commit belongs to another workstream.
            self._requested_stop_at = self.now()
        except Exception as error:  # noqa: BLE001 — a refusal must never disarm
            # every raise out of _stop_and_commit happens BEFORE the SIGTERM,
            # so the child is untouched and cap handoff stays armed
            self._failure(plan, "preemptive_pre_stop_failed: " + str(error))
            self._preemptive_defer(child, str(error))
        # unless we are actually moving to the target, release the lease we
        # took for it (the reservation is released by the failure row the
        # stop path already wrote) so no other launcher is wrongly blocked
        if not (relaunch is not None and relaunch.automatic):
            route.release_slot_lease(plan.target["name"])
        if relaunch is None:
            child.preemptive_next_check = self.now() + PREEMPT_BACKOFF_SECONDS
            return None
        if relaunch.automatic:
            notify.emit({"event": "preemptive_handoff",
                         "account": child.account.get("name", ""),
                         "target": plan.target.get("name", ""),
                         "family": proof.family, "window": proof.window,
                         "used_percent": proof.used_percent,
                         "handoff_id": plan.handoff_id})
        return relaunch

    def _preemptive_preflight(self, child, proof, snapshot):
        """The cap preflight's twin for a threshold crossing.

        The same guards in the same order — proof still current, no unread
        hook event, transcript quiet and unchanged, source row trustworthy,
        target proven twice, atomic ledger admission — with two deliberate
        differences. The quiet window is LONG, because an idle child is the
        entire safety argument for moving without a provider refusal; and
        there is no cap scope, so nothing is cooled and the admission deadline
        is the observation's own short TTL instead of a proven cap reset."""
        self._proof_current(child, proof)
        self._events_pending(child)
        # SAFE BOUNDARY: the transcript is the only in-band evidence of an
        # active turn between hooks, and this is the same stability guard the
        # manual handoff demands — just with a much longer quiet period.
        handoff.guard_source_stable(
            proof.transcript_path, now=self.now(),
            sleep=lambda _seconds: None, quiet_seconds=PREEMPT_IDLE_SECONDS)
        # ...and quiescence is not idleness. The newest conversational record
        # must be a FINISHED assistant turn (or a model thinking silently for
        # longer than the quiet window would be killed mid-response), AND no
        # background subagent may still be writing its own sidechain
        # transcript (the main thread looks idle the moment it backgrounds a
        # long-running agent).
        busy = _idle_refusal(proof.transcript_path, self.now(),
                             PREEMPT_IDLE_SECONDS, since=child.launched_at)
        if busy:
            raise SupervisorError("child is still working: " + busy)
        if handoff._transcript_stat(proof.transcript_path) \
                != proof.transcript_stat:
            raise SupervisorError(
                "preemptive proof expired after the transcript changed")
        reason = _preemptive_row_bound(
            child.account, proof.family,
            _snapshot_row(snapshot, child.account["name"]), self.now())
        if reason:
            raise SupervisorError(reason)
        target = self._preemptive_target(child, proof.family, snapshot,
                                         proof.window)
        binding = child.binding
        source = handoff.SourceSession(
            proof.session_id, proof.transcript_path, child.account,
            proof.family, int(self.now()))
        # cap_proof is NOT authenticated: plan_handoff therefore refuses a
        # transcript that ends mid-tool-call, so an early rotation can never
        # fork an unfinished turn the way an authenticated cap may.
        plan = handoff.plan_handoff(
            source, proof.family, target, snapshot,
            {"authenticated": False, "preemptive": True,
             "window": proof.window, "used_percent": proof.used_percent,
             "observed_at": proof.event["received_at"]},
            binding.cwd, cooldown_scope=None, automatic=True,
            child_generation=child.generation, preemptive=True)
        route.preflight_cooldowns()
        handoff.select_target(child.account["name"], snapshot, proof.family,
                              requested=target["name"])
        self._proof_current(child, proof)
        self._events_pending(child)
        if handoff._transcript_stat(proof.transcript_path) != plan.source_stat:
            raise SupervisorError("source transcript changed before admission")
        if proof.deadline <= self.now():
            raise SupervisorError(
                "preemptive decision window elapsed before admission")
        handoff.reserve_automatic(
            plan, self.now(), loop_window=LOOP_WINDOW, loop_max=LOOP_MAX)
        self._proof_current(child, proof)
        self._events_pending(child)
        if proof.deadline <= self.now():
            raise SupervisorError(
                "preemptive decision window elapsed before stop")
        return plan

    # ---- context backstop: never lose a session to its own window ---------
    #
    # The cooperative path owns everything above the backstop threshold: from
    # 30% remaining the session is told, every turn, to write a baton and
    # refresh itself. That is the intended flow and it produces a far better
    # handoff than any mechanical one, so this code does nothing at all until
    # a session has demonstrably NOT taken it.
    #
    # What it then does is the least destructive thing that can save the
    # conversation: stop the child at a proven-idle boundary and resume the
    # SAME session with `--fork-session` on the SAME seat, re-modelled onto a
    # window that can hold it. No account moves, nothing is cooled, no target
    # is reserved, the source transcript is untouched, and the pre-rotation
    # session id remains on disk. Every refusal only defers — a backstop is
    # worth nothing if it can take a session down.

    def _context_state(self, child):
        """``(used, window, remaining %)`` for this child, or None when its
        context cannot be measured.

        Absence of proof is never a crossing: an unreadable transcript, a tail
        with no usage record, a nonsensical window — all return None and the
        child is left alone."""
        binding = child.binding
        if binding is None:
            return None
        used = _context_used(binding.transcript_path)
        if used is None:
            return None
        window = _context_window(used, _model_flag(child.spawn_args))
        remaining = _context_remaining(used, window)
        if remaining is None:
            return None
        return used, window, remaining

    def _context_backstop_due(self, child, proof):
        """True when this tick may consider a forced context rotation.

        Same admission shape as the preemptive poll — a cap proof in flight
        always wins, the child must be enabled, bound and live — plus the
        backstop's own clock and hold. Automation being ON is required for a
        second reason here: the stop below wants this child's SessionEnd, and
        only a supervised child emits one."""
        return (self.context_backstop and proof is None and child.automation
                and child.binding is not None and child.pending_cap is None
                and not child.session_ended
                and self.now() >= child.context_next_check
                and self.now() >= self.context_hold_until)

    def _context_defer(self, child, reason, *, backoff=True, announce=True):
        """Hold the backstop without disarming anything (see
        `_preemptive_defer`: same contract, separate clock and dedupe)."""
        child.context_next_check = self.now() + (
            PREEMPT_BACKOFF_SECONDS if backoff else PREEMPT_POLL_SECONDS)
        if child.context_last_hold == reason:
            return
        child.context_last_hold = reason
        print(f"[headroom] context backstop held: {reason}; child continues "
              f"with cap handoff still armed", file=sys.stderr)
        if announce:
            notify.emit({"event": "context_backstop_held",
                         "account": child.account.get("name", ""),
                         "reason": reason})

    def _context_budget_spent(self):
        """True once this supervisor has forced its allowance of rotations in
        the current window (the local analogue of the ledger's loop guard)."""
        cutoff = self.now() - LOOP_WINDOW
        self.context_rotations = [when for when in self.context_rotations
                                  if when >= cutoff]
        return len(self.context_rotations) >= CONTEXT_BACKSTOP_MAX

    def _context_observation(self, child):
        """A :class:`ContextProof` for a live crossing, else None."""
        state = self._context_state(child)
        if state is None:
            return None
        used, window, remaining = state
        if remaining > self.context_backstop_percent:
            return None
        binding = child.binding
        observed_at = self.now()
        return ContextProof(
            event={"received_at": observed_at},
            message=(f"context at {remaining:.0f}% remaining "
                     f"({used:,} of {window:,} tokens)"),
            session_id=binding.session_id,
            transcript_path=binding.transcript_path, epoch=binding.epoch,
            transcript_stat=handoff._transcript_stat(binding.transcript_path),
            used=used, window=window, remaining_percent=remaining,
            deadline=observed_at + PREEMPT_DECISION_TTL)

    def _context_backstop_preflight(self, child, proof):
        """Prove the child is at a SAFE BOUNDARY before forcing anything.

        The preemptive preflight's guards, minus everything that only a
        seat-to-seat move needs (usage row, target selection, cooldowns,
        ledger admission): proof still current, no unread hook event, the
        transcript quiet AND idle by the full three-proof machinery (finished
        main-thread turn, no live background agent, no busy sidechain), the
        transcript unchanged since the observation, and the decision still
        inside its short TTL."""
        self._proof_current(child, proof)
        self._events_pending(child)
        handoff.guard_source_stable(
            proof.transcript_path, now=self.now(),
            sleep=lambda _seconds: None, quiet_seconds=PREEMPT_IDLE_SECONDS)
        busy = _idle_refusal(proof.transcript_path, self.now(),
                             PREEMPT_IDLE_SECONDS, since=child.launched_at)
        if busy:
            raise SupervisorError("child is still working: " + busy)
        if handoff._transcript_stat(proof.transcript_path) \
                != proof.transcript_stat:
            raise SupervisorError(
                "context proof expired after the transcript changed")
        if proof.deadline <= self.now():
            raise SupervisorError(
                "context decision window elapsed before stop")

    def _context_backstop_stop(self, child, proof):
        """Stop the child and hand back the resume that continues it.

        Returns a :class:`Relaunch` (the child is gone and MUST be replaced),
        or None when the child ignored SIGTERM and is still running.

        After the signal there is no "refuse" left — the session must come
        back — so a post-stop problem degrades the resume instead of
        abandoning it: a plain `--resume` of the very same session id rather
        than a fork of a conversation we could not prove clean."""
        self._proof_current(child, proof)
        self._events_pending(child)
        if handoff._transcript_stat(proof.transcript_path) \
                != proof.transcript_stat:
            raise SupervisorError("source transcript changed before stop")
        if proof.deadline <= self.now():
            raise SupervisorError("context decision window elapsed before stop")
        rotation_id = str(uuid.uuid4())
        print(f"[headroom] {proof.message}; forcing a lossless rotation of "
              f"this session on {child.account['name']}", file=sys.stderr)
        self.stopped_child_model = _model_flag(child.spawn_args)
        saved = self._save_terminal()
        stop_error = None
        stop_sent_at = 0.0
        signal_sent = False
        child.session_ended = False
        child.session_end_received_at = 0.0
        try:
            with _event_stop_guard(child):
                self._proof_current(child, proof)
                # last-instant idleness, one stat syscall before the kill
                self._idle_stop_edge(child, proof, proof.transcript_stat,
                                     label="context backstop")
                # Durable BEFORE the signal, the same discipline as
                # _stop_and_commit's stop_sent: a crash can never hide a stop,
                # and an external kill must never be indistinguishable from
                # ours. Without this row headroom can terminate a live session
                # and leave a signature identical to somebody else's kill —
                # which is what made the 2026-08-01 07:30:42Z stop cost a
                # forensic dispatch to attribute. append_ledger takes the
                # handoff lock and fsyncs.
                #
                # A raise here is BEFORE the signal, so it propagates: the
                # cycle's except defers and the child is untouched.
                handoff.append_ledger({
                    "schema": handoff.SCHEMA, "ts": self.now(),
                    "handoff_id": rotation_id, "action": "context_stop_sent",
                    "source_slot": child.account["name"],
                    "old_session_id": proof.session_id,
                    "child_generation": child.generation,
                    "used": proof.used, "window": proof.window,
                    "remaining_percent": proof.remaining_percent})
                stop_sent_at = self.now()
                # BEFORE the signal, like the row above: _monitor classifies
                # an exit it did not ask for, and this rotation is one it did
                self._requested_stop_at = self.now()
                os.kill(child.process.pid, signal.SIGTERM)
                signal_sent = True
            returncode = self._wait_stopped(child, proof, stop_sent_at)
        except Exception as error:  # post-signal failures still recover
            if not signal_sent:
                raise SupervisorError(str(error)) from error
            stop_error = error
            # The signal WAS sent, so this child is on its way out and the
            # session has to come back whatever went wrong. Give it the full
            # exit budget instead of sampling poll() once: a racing hook event
            # (a cap landing between SIGTERM and exit, say) would otherwise
            # read as "ignored SIGTERM", disarm supervision and return no
            # relaunch — leaving a stopped session with nothing to replace it.
            returncode = self._await_exit(child)
        finally:
            self._restore_terminal(saved)
        if returncode is None:
            print("[headroom] Claude did not exit after one SIGTERM; automatic "
                  "handoff disabled for this child", file=sys.stderr)
            _lose_supervision(child, "Claude did not exit after one SIGTERM")
            return None
        degraded = ""
        if stop_error is not None:
            degraded = f"the stop transition was not clean: {stop_error}"
        elif not child.session_ended \
                or child.session_end_received_at < stop_sent_at:
            degraded = "SessionEnd proof is missing"
        else:
            try:
                handoff.inspect_transcript(proof.transcript_path,
                                           allow_dangling=False)
            except (handoff.HandoffError, OSError, ValueError) as error:
                degraded = str(error)
        try:
            handoff.append_ledger({
                "schema": handoff.SCHEMA, "ts": self.now(),
                "handoff_id": rotation_id, "action": "context_stopped",
                "source_slot": child.account["name"],
                "old_session_id": proof.session_id,
                "child_generation": child.generation,
                "child_exit_code": returncode,
                "session_end": child.session_ended,
                "degraded": degraded, "forked": not degraded})
        except handoff.HandoffError as error:
            # after the signal: the session MUST still come back
            print(f"[headroom] could not record the context stop: {error}",
                  file=sys.stderr)
        if degraded:
            # never fork a conversation we cannot prove finished — resume the
            # session itself instead, and say so
            print(f"[headroom] context rotation could not fork cleanly "
                  f"({degraded}); resuming the session in place",
                  file=sys.stderr)
            notify.emit({"event": "context_backstop_held",
                         "account": child.account.get("name", ""),
                         "reason": f"forked resume degraded: {degraded}"})
            argv = ["--resume", proof.session_id]
            reason = "context_backstop_recovered"
        else:
            argv = ["--resume", proof.session_id, "--fork-session"]
            reason = "context_backstop"
        # THE POINT OF THE ROTATION: the successor must get a window this
        # conversation fits in. Below the fit limit `_window_fit_argv` would
        # (correctly, for every other resume path) leave the model alone — but
        # a session at 5% of a 200k window is under that limit and would come
        # straight back at 5%, so a backstop resume off the standard window
        # always re-models. A session already on the largest window never gets
        # here (the cycle refuses it) unless the operator forced it.
        if proof.window < CONTEXT_WINDOW_LARGE:
            forced = CONTEXT_FIT_MODEL
            argv = _with_model(argv, forced)
        else:
            argv, forced = _window_fit_argv(
                argv, proof.transcript_path, used=proof.used,
                model=_model_flag(child.spawn_args))
        if forced:
            print(f"[headroom] resuming this conversation on {forced} so its "
                  f"{proof.used:,} tokens have room", file=sys.stderr)
        # What to do if THIS relaunch cannot even be spawned: the plain
        # resume, on the same seat, fitted only where the transcript genuinely
        # demands it. It is deliberately the SIMPLER command — dropping the
        # fork and any model this rotation added — because the added flags are
        # exactly what a spawn failure might be about, and a stopped session
        # with nothing running is the worst outcome this feature can produce.
        #
        # ALWAYS attached, even when it comes out identical to the argv that
        # just failed. Skipping it then looked like a harmless optimisation
        # and was the bug: spawn failures are not always about the argv (a
        # transient fork/exec failure, a momentarily missing binary), so a
        # plain retry is still a recovery — and "identical" is exactly the
        # case for a degraded stop of a transcript that must keep its model,
        # i.e. a session that has ALREADY been stopped and has nothing else
        # left to bring it back.
        fallback, _fitted = _window_fit_argv(
            ["--resume", proof.session_id], proof.transcript_path,
            used=proof.used, model=self.stopped_child_model)
        recovery = Recovery(child.account, fallback, child.binding.cwd,
                            proof.session_id)
        # supervised either way: an elective stop must never cost the
        # cap-reactive guarantee, and this seat is not capped
        return Relaunch(child.account, argv, child.binding.cwd,
                        reason == "context_backstop", reason=reason,
                        supervised=True, recovery=recovery)

    def _context_backstop_cycle(self, child):
        """One backstop attempt. Returns a Relaunch when the session was
        forcibly continued, otherwise None.

        Never disarms: like preemptive rotation this is layered ON TOP of the
        cap-reactive guarantee, so every failure degrades to "no forced
        rotation this tick"."""
        child.context_next_check = self.now() + PREEMPT_POLL_SECONDS
        try:
            proof = self._context_observation(child)
        except Exception as error:  # noqa: BLE001
            self._context_defer(child, f"context unreadable: {error}",
                                announce=False)
            return None
        if proof is None:
            child.context_announced = False
            child.context_last_hold = ""
            return None
        if proof.window >= CONTEXT_WINDOW_LARGE and not CONTEXT_BACKSTOP_ALWAYS:
            # nothing automatic can save this session: say so ONCE (the defer
            # dedupes by reason) and leave it running rather than spending its
            # last minutes on a restart that changes nothing
            self._context_defer(
                child, f"{proof.message} and it is already on the largest "
                f"context window — only the operator can save this session")
            return None
        if self._context_budget_spent():
            self._context_defer(
                child, f"context backstop budget spent "
                f"({CONTEXT_BACKSTOP_MAX} in {LOOP_WINDOW / 60:.0f} minutes)")
            return None
        if not child.context_announced:
            child.context_announced = True
            print(f"[headroom] {child.account['name']} {proof.message} — "
                  f"forcing a handoff at the next idle boundary",
                  file=sys.stderr)
            notify.emit({"event": "context_backstop_scheduled",
                         "account": child.account.get("name", ""),
                         "used": proof.used, "window": proof.window,
                         "remaining_percent": proof.remaining_percent})
        try:
            self._context_backstop_preflight(child, proof)
        except Exception as error:  # noqa: BLE001
            busy = ("changed recently" in str(error)
                    or "still changing" in str(error))
            self._context_defer(child, str(error), backoff=not busy)
            return None
        try:
            relaunch = self._context_backstop_stop(child, proof)
        except Exception as error:  # noqa: BLE001 — a refusal must never disarm
            # every raise before the SIGTERM leaves the child untouched
            self._context_defer(child, str(error))
            return None
        if relaunch is None:
            child.context_next_check = self.now() + PREEMPT_BACKOFF_SECONDS
            return None
        # charge the budget and hold: the forked child INHERITS these usage
        # records, so it will read as the same crossing until it either moved
        # onto a bigger window or wrote a turn of its own
        self.context_rotations.append(self.now())
        self.context_hold_until = self.now() + PREEMPT_BACKOFF_SECONDS
        notify.emit({"event": "context_backstop_rotation",
                     "account": child.account.get("name", ""),
                     "used": proof.used, "window": proof.window,
                     "remaining_percent": proof.remaining_percent,
                     "model": _model_flag(relaunch.argv),
                     "forked": relaunch.reason == "context_backstop"})
        return relaunch

    @staticmethod
    def _save_terminal():
        if termios is None:
            return None
        try:
            if sys.stdin.isatty():
                return termios.tcgetattr(sys.stdin.fileno())
        except (OSError, termios.error):
            pass
        return None

    @staticmethod
    def _restore_terminal(saved):
        if saved is None or termios is None:
            return
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, saved)
        except (OSError, termios.error):
            pass

    def _wait_stopped(self, child, proof, stop_sent_at):
        deadline = self.now() + TERM_TIMEOUT
        while child.process.poll() is None and self.now() < deadline:
            self._consume_stop_events(child, proof, stop_sent_at)
            self.sleep(POLL_SECONDS)
        returncode = child.process.poll()
        self._consume_stop_events(child, proof, stop_sent_at)
        return returncode

    def _await_exit(self, child):
        """Wait out the exit budget WITHOUT consuming hook events.

        `_wait_stopped` doubles as the stop-transition event reader, so it
        cannot be re-entered once one of those events has raised. This is the
        plain half: the signal is already delivered, and all that is left to
        establish is whether the process is gone."""
        deadline = self.now() + TERM_TIMEOUT
        while child.process.poll() is None and self.now() < deadline:
            self.sleep(POLL_SECONDS)
        return child.process.poll()

    def _consume_stop_events(self, child, proof, stop_sent_at):
        _remember_binding(child)
        for record in _read_events(child):
            if not _namespace_matches(record, child):
                continue
            source, cwd = _validated_event(record, child)
            payload = record["payload"]
            hook_name = payload.get("hook_event_name")
            epoch = _event_epoch(child, source)
            session_key = ((source.session_id, epoch)
                           if epoch is not None else None)
            if hook_name == "StopFailure" \
                    and session_key in child.dead_sessions:
                continue
            if not _accept_event_order(child, record):
                # a record this transition has already seen says nothing new
                # about it — and must not be read as a session transition
                continue
            if session_key in child.dead_sessions:
                if hook_name in ("SessionEnd", "StopFailure"):
                    continue
                raise SupervisorError(
                    "cap proof expired after its session ended")
            if hook_name == "CwdChanged" \
                    and source.session_id == proof.session_id \
                    and source.transcript_path == proof.transcript_path:
                binding = child.binding
                child.binding = replace(binding, cwd=cwd)
                continue
            if hook_name == "StopFailure" \
                    and source.session_id == proof.session_id \
                    and source.transcript_path == proof.transcript_path \
                    and epoch == proof.epoch:
                # A cap landing on THIS session while we are already stopping
                # it is corroboration, not contradiction: the handoff in
                # flight is doing exactly what the cap demands, and its target
                # was proven and reserved moments ago. Absorb it. Treating it
                # as an unexpected event aborted a committed stop and left the
                # recovered child unsupervised — losing the cap-reactive
                # guarantee at the one moment it is needed. Most valuable for
                # a preemptive stop (the seat capping mid-rotation is exactly
                # the race the rotation was trying to beat), but the cap path
                # gets the same protection from a repeated StopFailure.
                #
                # NONE of that holds for a context backstop stop: it has no
                # target, and it comes back on the SAME seat. Absorbing the
                # cap there would resume the conversation on a seat that has
                # just been refused — the one outcome a cap must never lead
                # to. So it is never swallowed: it aborts the elective fork
                # (see _context_backstop_stop, which degrades to an in-place
                # SUPERVISED resume) and the cap-reactive path takes the
                # session off this seat on its next refusal, through the
                # pipeline that can actually stage it. Re-driving that
                # pipeline here is not possible: this session is already in
                # `dead_sessions`, so every cap proof against it is expired by
                # construction (`_proof_current`).
                if getattr(proof, "backstop", False) is True:
                    raise SupervisorError(
                        "a subscription cap landed during the context stop")
                child.pending_cap = None
                continue
            if hook_name != "SessionEnd":
                raise SupervisorError(
                    "cap proof expired during the stop transition")
            if (record["received_at"] < stop_sent_at
                    or source.session_id != proof.session_id
                    or source.transcript_path != proof.transcript_path
                    or epoch != proof.epoch):
                raise SupervisorError(
                    "SessionEnd does not prove the stopped session epoch")
            self._proof_current(child, proof)
            child.dead_sessions.add(session_key)
            child.session_ended = True
            child.session_end_received_at = record["received_at"]

    def _post_stop_plan(self, plan, model=""):
        deadline = self.now() + QUIET_SECONDS + 1.0
        while True:
            signature = handoff._transcript_stat(plan.source.transcript_path)
            age = self.now() - (signature[3] / 1_000_000_000)
            if age >= QUIET_SECONDS:
                break
            if self.now() >= deadline:
                raise SupervisorError("final transcript did not become quiet")
            self.sleep(min(POLL_SECONDS, max(0.0, QUIET_SECONDS - age)))
        # A cap stop may only ever produce a dangling transcript (the session
        # was refused mid-turn and there was no alternative), so it is allowed
        # through with the "may re-run on resume" notice. A PREEMPTIVE stop was
        # elective: if it caught a turn after all, refuse to fork a broken
        # conversation and let the caller recover the source instead.
        inspected = handoff.inspect_transcript(
            plan.source.transcript_path,
            allow_dangling=plan.preemptive is not True)
        final_stat = handoff._transcript_stat(plan.source.transcript_path)
        if final_stat[:2] != plan.source_stat[:2] or final_stat != signature:
            raise SupervisorError("final transcript identity or stat changed")
        plan = replace(plan, inspected=inspected, source_stat=final_stat)
        # Stamp the EXACT model the successor launches with, measured on the
        # FINAL transcript, so the ledger's last-resort command is the command
        # that actually works. The family alone is not enough: `--model opus`
        # cannot load a conversation that needs `opus[1m]`, and after a crash
        # here that ledger row is all the operator has left.
        argv, _forced = _resume_argv_for(plan, model)
        return replace(plan, resume_model=_model_flag(argv))

    def _failure(self, plan, reason, **fields):
        try:
            handoff.append_action(
                plan.handoff_id, "failure", automatic=True,
                source_slot=plan.source.account["name"],
                target_slot=plan.target["name"], reason=reason,
                old_session_id=plan.source.session_id,
                child_generation=plan.child_generation, **fields)
        except Exception:  # recovery must proceed even if the ledger is broken
            pass

    def _lease_target(self, plan):
        """Acquire the TARGET account's flock BEFORE stopping the source, so a
        concurrent launch can't double-book the account we're moving to. The
        source lease is deliberately kept until the target child spawns (run()
        reconciliation drops it), and on any failure here the handoff is held
        with the source still running AND still leased. No-op unless
        HEADROOM_SLOT_LEASE=1. (P0-2)"""
        try:
            if not route.acquire_slot_lease(plan.target, plan.target_family):
                raise SupervisorError(
                    "target slot is leased by another live launch")
        except route.LeaseError as error:
            raise SupervisorError(
                f"target slot lease unavailable: {error}") from error

    def _reconcile_leases(self, active_name):
        """Hold exactly the ACTIVE child's lease: release every other lease
        this supervisor took (the old source after a rotation, or a target we
        acquired for a handoff that then failed). No-op unless leasing is on."""
        for name in route.held_lease_names():
            if name != active_name:
                route.release_slot_lease(name)

    @staticmethod
    def _source_relaunch(plan, model=""):
        # Even a RECOVERY resume has to fit the window it resumes into: the
        # session being recovered is the same one whose transcript may already
        # have outgrown the standard window. `model` is what the stopped child
        # was RUNNING, and it must be threaded in here too — recovering a
        # `sonnet[1m]` session without it shrinks the conversation back into a
        # 200k window (a large one lands there already in crisis) or swaps its
        # family for the default fit model when it did not need to change at
        # all.
        argv, _forced = _window_fit_argv(
            ["--resume", plan.source.session_id],
            plan.source.transcript_path, model=model)
        return Relaunch(plan.source.account, argv, plan.cwd, False)

    @staticmethod
    def _print_manual_recovery(plan, model=""):
        # These two lines are the LAST thing between the user and a lost
        # conversation, so they have to be the commands headroom itself would
        # have run — same model, same window fit. A bare `--resume` here would
        # send the operator back to the child's default model, which after a
        # downgrade is the tier that just capped and after a context rotation
        # is a window the transcript no longer fits.
        print("headroom: automatic recovery could not start Claude; run one of:",
              file=sys.stderr)
        target_argv, _forced = _resume_argv_for(plan, model)
        print(f"CLAUDE_CONFIG_DIR={shlex.quote(plan.target['home'])} "
              f"{shlex.join(['claude'] + target_argv)}", file=sys.stderr)
        source_argv, _forced = _window_fit_argv(
            ["--resume", plan.source.session_id],
            plan.source.transcript_path, model=model)
        print(f"CLAUDE_CONFIG_DIR={shlex.quote(plan.source.account['home'])} "
              f"{shlex.join(['claude'] + source_argv)}", file=sys.stderr)

    def _idle_stop_edge(self, child, proof, expected_stat, label="preemptive"):
        """Last-instant idleness proof, immediately before SIGTERM.

        Shared by every ELECTIVE stop (preemptive rotation, context backstop):
        a cap stop has to proceed regardless because the session is refused
        anyway, but an elective one must not catch a turn that started while
        the decision was being written down."""
        if handoff._transcript_stat(proof.transcript_path) != expected_stat:
            raise SupervisorError(
                f"source transcript changed on the edge of a {label} stop")
        busy = _idle_refusal(proof.transcript_path, self.now(),
                             PREEMPT_IDLE_SECONDS, since=child.launched_at)
        if busy:
            raise SupervisorError(
                f"child became busy before the {label} stop: " + busy)

    def _preemptive_stop_edge(self, child, plan, proof):
        self._idle_stop_edge(child, proof, plan.source_stat)

    @staticmethod
    def _commit_deadline(plan, proof):
        """``(deadline, label)``: the instant after which this plan may no
        longer be executed.

        A cap plan may only proceed while its PROVEN cap reset is still in the
        future (unchanged). A preemptive plan may only proceed while its short
        decision window holds — the observation is not a provider refusal, so
        it must not be allowed to go stale in the supervisor's hands. Both
        fail closed on a missing or invalid value."""
        if getattr(proof, "preemptive", False) is True:
            return getattr(proof, "deadline", None), "preemptive decision window"
        return plan.cooldown_scope.get("reset"), "cap reset"

    def _stop_and_commit(self, child, plan, proof):
        self._proof_current(child, proof)
        self._events_pending(child)
        try:
            source_stat = handoff._transcript_stat(proof.transcript_path)
        except (handoff.HandoffError, OSError, RuntimeError) as error:
            raise SupervisorError(str(error)) from error
        if source_stat != plan.source_stat:
            raise SupervisorError("source transcript changed before stop")
        reset, label = self._commit_deadline(plan, proof)
        if (not isinstance(reset, (int, float)) or isinstance(reset, bool)
                or not math.isfinite(reset) or reset <= self.now()):
            raise SupervisorError(f"{label} elapsed before stop")
        try:
            handoff.verify_automatic_reservation(plan)
        except (handoff.HandoffError, registry.RegistryError, RuntimeError,
                OSError, ValueError) as error:
            raise SupervisorError(str(error)) from error
        self._proof_current(child, proof)
        self._events_pending(child)
        if handoff._transcript_stat(proof.transcript_path) != plan.source_stat:
            raise SupervisorError("source transcript changed before stop")
        if reset <= self.now():
            raise SupervisorError(f"{label} elapsed before stop")
        if getattr(proof, "preemptive", False) is True:
            print(f"[headroom] preemptive rotation ({proof.message}); "
                  f"{plan.source.account['name']} -> {plan.target['name']}",
                  file=sys.stderr)
        else:
            print(f"[headroom] cap confirmed; {plan.source.account['name']} -> "
                  f"{plan.target['name']}", file=sys.stderr)
        # take the target lease before we stop the source (P0-2); on failure
        # this raises SupervisorError and the caller keeps the source running
        # and leased
        self._lease_target(plan)
        # what this child is RUNNING, remembered before it dies: every
        # recovery below (and run()'s, which has no Child handle at all) needs
        # it to decide what window the conversation may be resumed into
        self.stopped_child_model = _model_flag(child.spawn_args)
        saved = self._save_terminal()
        stop_error = None
        stop_sent_at = 0.0
        signal_sent = False
        child.session_ended = False
        child.session_end_received_at = 0.0
        try:
            with _event_stop_guard(child):
                self._proof_current(child, proof)
                if handoff._transcript_stat(proof.transcript_path) \
                        != plan.source_stat:
                    raise SupervisorError(
                        "source transcript changed before stop")
                if reset <= self.now():
                    raise SupervisorError(f"{label} elapsed before stop")
                if plan.preemptive is True:
                    # Cheap pre-filter: an already-busy child must not even
                    # get a stop_sent row written for it.
                    self._preemptive_stop_edge(child, plan, proof)
                stop_sent_at = self.now()
                handoff.append_action(
                    plan.handoff_id, "stop_sent", automatic=True,
                    source_slot=plan.source.account["name"],
                    old_session_id=plan.source.session_id,
                    child_generation=plan.child_generation)
                if plan.preemptive is True:
                    # The durable stop_sent append above is a locked, fsync'd
                    # ledger write — milliseconds during which the child may
                    # start a turn. A cap stop has to proceed regardless (the
                    # session is refused anyway), but a preemptive stop is
                    # ELECTIVE, so re-prove idleness on the very edge of the
                    # kill, narrowing the window to a single stat syscall.
                    try:
                        self._preemptive_stop_edge(child, plan, proof)
                    except SupervisorError:
                        # stop_sent is durable (it must be written BEFORE any
                        # signal, so a crash can never hide a stop) but no
                        # signal was ever sent. Mark the row cancelled so the
                        # shared loop budget is not charged for a rotation
                        # that never touched the session — otherwise repeated
                        # near-misses would starve a genuine cap.
                        self._failure(
                            plan, "preemptive_stop_cancelled_on_edge",
                            stop_cancelled=True)
                        raise
                os.kill(child.process.pid, signal.SIGTERM)
                signal_sent = True
            returncode = self._wait_stopped(child, proof, stop_sent_at)
        except Exception as error:  # post-signal failures recover if Claude exited
            if not signal_sent:
                raise SupervisorError(str(error)) from error
            stop_error = error
            returncode = child.process.poll()
        finally:
            self._restore_terminal(saved)
        if returncode is None:
            reason = "sigterm_timeout" if stop_error is None else str(stop_error)
            self._failure(plan, "stop_failed: " + reason)
            print("[headroom] Claude did not exit after one SIGTERM; automatic "
                  "handoff disabled for this child", file=sys.stderr)
            _lose_supervision(child, "Claude did not exit after one SIGTERM")
            return None
        try:
            if stop_error is not None:
                raise stop_error
            handoff.append_action(
                plan.handoff_id, "stopped", automatic=True,
                source_slot=plan.source.account["name"],
                old_session_id=plan.source.session_id,
                child_generation=plan.child_generation,
                child_exit_code=returncode,
                session_end=child.session_ended,
                session_end_received_at=child.session_end_received_at)
            if not child.session_ended \
                    or child.session_end_received_at < stop_sent_at:
                raise SupervisorError("SessionEnd proof is missing")
            plan = self._post_stop_plan(plan, _model_flag(child.spawn_args))
            result = handoff.commit_handoff(plan)
            if plan.inspected["unresolved_tool_ids"]:
                print("[headroom] note: the interrupted tool call may re-run on "
                      "resume", file=sys.stderr)
            # A resume argv names only --resume/--fork-session, so the
            # successor would come back on the child's DEFAULT model. That is
            # right until a cap forced a tier change: a Fable session routed
            # to an Opus seat would resume as Fable on a seat with no Fable
            # left and re-cap on its first prompt, spending loop budget to
            # change nothing. And the conversation only survives if the target
            # can actually LOAD it: a transcript past the fit limit resumed
            # under the standard window dies on its first prompt. Both facts
            # live in _resume_argv_for, which the manual recovery command
            # prints from too.
            argv, forced = _resume_argv_for(
                plan, _model_flag(child.spawn_args))
            if forced:
                print(f"[headroom] this transcript no longer fits a "
                      f"{CONTEXT_WINDOW_STANDARD:,}-token window — resuming it "
                      f"on {forced}", file=sys.stderr)
                notify.emit({"event": "context_window_fit",
                             "account": plan.target.get("name", ""),
                             "model": forced,
                             "handoff_id": plan.handoff_id})
            return Relaunch(plan.target, argv,
                            plan.cwd, True, plan.handoff_id, plan,
                            reason="preemptive" if plan.preemptive else "cap")
        except Exception as error:  # no post-stop failure may strand the user
            self._failure(plan, "post_stop_failed: " + str(error))
            if plan.preemptive is True:
                # An ELECTIVE rotation must never leave the user worse off
                # than not rotating. The source is not capped, so recovering
                # it with supervision OFF (the cap path's correct answer, since
                # a capped source would just try to hand off again) would trade
                # a saved wall for a lost guarantee. Recover it SUPERVISED and
                # hold the poll so the recovered child is not targeted again.
                print(f"[headroom] preemptive handoff aborted after Claude "
                      f"exited ({error}); recovering the session on "
                      f"{plan.source.account['name']} with auto-handoff still "
                      f"armed", file=sys.stderr)
                self.preemptive_hold_until = self.now() + PREEMPT_BACKOFF_SECONDS
                return replace(
                    self._source_relaunch(plan, model=self.stopped_child_model),
                    reason="preemptive_aborted", supervised=True)
            print(f"[headroom] handoff failed after Claude exited ({error}); "
                  "relaunching the source with automation off", file=sys.stderr)
            # the source will be relaunched UNsupervised — notify the loss once
            # so an observer that saw the initial supervised launch knows (P1-5)
            _lose_supervision(
                child, f"handoff failed after Claude exited: {error}")
            return self._source_relaunch(plan, model=self.stopped_child_model)

    def _announce_tail_caps(self, child, remaining):
        """Speak for caps in a batch this handler is about to abandon.

        `_read_events` advanced the cursor for the WHOLE batch before
        returning, so these bytes are gone from the journal whether or not we
        look at them — and every early `return None` below used to drop them
        silently. A cap that shared a batch with one racy or malformed record
        was simply destroyed.

        ANNOUNCE-ONLY. The child is being disarmed on these paths for reasons
        that are still valid, and ACTING on a cap found after a malformed
        event in the same batch would be acting on a journal we have just
        declared untrustworthy.

        `remaining` is the tail in RECEIVED_AT order — `_read_events` sorts
        the batch at the end — which is the order the loop would have
        processed. That is the right definition; do not "fix" it back to
        file order."""
        seen = set()
        for record in remaining:
            received = record.get("received_at")
            if received in seen or not _cap_text(record):
                continue
            seen.add(received)
            why = ("the hook batch was abandoned after an earlier "
                   "malformed event")
            print(f"[headroom] {child.account['name']} hit a subscription cap "
                  f"but NO automatic handoff will run: {why}. Switch model "
                  f"(/model opus) or hand off manually: "
                  f"headroom handoff --to <slot>", file=sys.stderr)
            notify.emit({"event": "cap_unhandled",
                         "account": child.account.get("name", ""),
                         "bound": child.binding is not None,
                         "reason": why})

    def _handle_events(self, child, pending_handoff_id, proof=None):
        try:
            records = _read_events(child)
        except SupervisorError as error:
            # NO tail drain here, and that is not an omission: _read_events
            # raised, so nothing was parsed and the cursor never advanced
            # (it moves only after the parse loop). Every record is still in
            # the journal — there is no abandoned tail to speak for.
            print(f"[headroom] {error}; automatic handoff disabled for this child",
                  file=sys.stderr)
            _lose_supervision(child, f"hook event journal unreadable: {error}")
            child.pending_cap = None
            return None
        _remember_binding(child)
        saw_stop_failure = False
        for index, record in enumerate(records):
            if not _namespace_matches(record, child):
                continue
            try:
                source, cwd = _validated_event(record, child)
                payload = record["payload"]
                hook_name = payload["hook_event_name"]
                epoch = _event_epoch(child, source)
                session_key = ((source.session_id, epoch)
                               if epoch is not None else None)
                if hook_name == "StopFailure" and child.pending_cap is not None \
                        and record["received_at"] \
                        > child.pending_cap.received_at:
                    child.pending_cap = None
                if hook_name == "StopFailure" \
                        and session_key in child.dead_sessions:
                    proof = None
                    continue
                if not _accept_event_order(child, record):
                    # a duplicate of a record already processed at this
                    # frontier: it carries nothing new, and acting on it twice
                    # is the harm. Dropped in silence, supervision untouched.
                    continue
            except SupervisorError as error:
                print(f"[headroom] malformed hook event ({error}); automatic "
                      "handoff disabled for this child", file=sys.stderr)
                _lose_supervision(child, f"malformed hook event: {error}")
                child.pending_cap = None
                self._announce_tail_caps(child, records[index + 1:])
                return None
            if hook_name == "SessionStart":
                try:
                    child.pending_cap = None
                    child.binding = parse_session_start(record, child)
                    child.session_epoch = child.binding.epoch
                    child.session_epochs[
                        (child.binding.session_id,
                         child.binding.transcript_path)] = child.binding.epoch
                    child.session_ended = False
                    child.session_end_received_at = 0.0
                    proof = None
                    if pending_handoff_id and not child.resume_bound:
                        handoff.append_action(
                            pending_handoff_id, "resume_bound", automatic=True,
                            target_slot=child.account["name"],
                            new_session_id=child.binding.session_id,
                            transcript_path=child.binding.transcript_path,
                            child_generation=child.generation)
                        child.resume_bound = True
                except (SupervisorError, handoff.HandoffError, RuntimeError,
                        OSError) as error:
                    _lose_supervision(child, f"session binding failed: {error}")
                    print(f"[headroom] {error}; automatic handoff disabled for "
                          "this child", file=sys.stderr)
                    self._announce_tail_caps(child, records[index + 1:])
                    return None
                continue
            current = child.binding
            same_session = (current is not None
                            and source.session_id == current.session_id
                            and source.transcript_path == current.transcript_path)
            if hook_name == "SessionEnd":
                proof = None
                if child.pending_cap is not None and session_key == (
                        child.pending_cap.session_id, child.pending_cap.epoch):
                    child.pending_cap = None
                if epoch is None:
                    # LOUD, AND NOT A DISARM. Reaching here means no epoch was
                    # ever recorded for this session, so there is nothing this
                    # branch can protect: a SessionEnd's job is to mark a
                    # session dead so a later StopFailure is not acted on, and
                    # an unknown session has no proof to expire.
                    #
                    # Every child that reaches it is one of two things, and
                    # disarming is wrong for both. Either it is ALREADY
                    # disarmed — it lost its SessionStart to the transcript
                    # birth race hours ago, so the epoch map is empty and this
                    # is the child's own goodbye — in which case the disarm
                    # was a no-op on the flag and a second, duplicate row in
                    # the sink, which is precisely what made one failure read
                    # as two independent ones (2026-08-02). Or it is alive,
                    # correctly bound and ARMED, and the epoch went unknown
                    # because the transcript PATH moved under a stable session
                    # id — `session_epochs` is keyed by the pair — in which
                    # case a Claude-side change in transcript placement would
                    # silently disarm the whole fleet.
                    #
                    # "This child never bound at all" is the residual case,
                    # and it keeps its own guard: the BIND_TIMEOUT disarm,
                    # which is the better one because it waits the birth out
                    # instead of racing it.
                    #
                    # `dead_sessions` is deliberately NOT written: the key
                    # would have to be (session_id, None), and every lookup
                    # against it computes `session_key` as a bare None when
                    # the epoch is unknown, so the entry could never match —
                    # while a literal None in that set makes _stop_transition
                    # treat EVERY unknown-epoch event as an expired proof.
                    #
                    # The tail is still abandoned and still announce-only.
                    # `_read_events` moved the cursor past the whole batch, so
                    # those bytes are gone either way, and acting on them
                    # would change when headroom STOPS a child. That is not
                    # this change; this change is only about the latch.
                    print("[headroom] SessionEnd has no known session epoch; "
                          "this child's supervision is unchanged",
                          file=sys.stderr)
                    notify.emit({"event": "session_end_unknown_epoch",
                                 "account": child.account.get("name", ""),
                                 "session": source.session_id,
                                 "armed": child.automation,
                                 "bound": child.binding is not None,
                                 "reason": "SessionEnd has no known session "
                                           "epoch"})
                    self._announce_tail_caps(child, records[index + 1:])
                    return None
                child.dead_sessions.add(session_key)
                if same_session:
                    child.session_ended = True
                    child.session_end_received_at = record["received_at"]
                continue
            if hook_name == "CwdChanged":
                if same_session:
                    child.binding = replace(current, cwd=cwd)
                continue
            if hook_name == "StopFailure":
                saw_stop_failure = True
                proof = None
                if not same_session or not child.automation:
                    # A cap arriving here is the ONE thing this supervisor
                    # exists to act on, and dropping it in silence is how a
                    # session sits at a wall with no rotation and no reason
                    # given (observed live 2026-07-31: the Fable pool ran out,
                    # the hook fired and journaled, automation was already off,
                    # and nothing was printed — the operator learned about it
                    # from the model's own "out of usage credits" line). It is
                    # still not safe to ACT (an unsupervised or foreign session
                    # is not ours to rotate), so say so instead: the human in
                    # this pane gets the wall, the reason, and the manual
                    # remedy, and an observer gets a structured event.
                    # The PAYLOAD's own text, not cap_message: cap_message
                    # returns "" on its binding gate before it ever looks at
                    # the record, so an unbound child — the state any
                    # SessionStart binding failure leaves a live child in for
                    # the whole 30s BIND_TIMEOUT and beyond — announced
                    # nothing at all. No stderr, no notify, no record of the
                    # decision; and _binding_key(None) is None, so the
                    # post-loop "session ended" line stayed quiet too.
                    if _cap_text(record):
                        why = ("this child never bound a session (the "
                               "SessionStart hook did not arrive)"
                               if child.binding is None
                               else "supervision is off for this child"
                               if not child.automation
                               else "the event does not match this child's "
                                    "live session")
                        print(f"[headroom] {child.account['name']} hit a "
                              f"subscription cap but NO automatic handoff will "
                              f"run: {why}. Switch model (/model opus) or hand "
                              f"off manually: headroom handoff --to <slot>",
                              file=sys.stderr)
                        notify.emit({"event": "cap_unhandled",
                                     "account": child.account.get("name", ""),
                                     "bound": child.binding is not None,
                                     "reason": why})
                    continue
                proof = self._attempt_cap(child, record, announce_non_cap=True)
        if not saw_stop_failure and child.pending_cap is not None \
                and child.automation:
            proof = self._attempt_cap(child, child.pending_cap.event)
        if _binding_key(child.binding) in child.dead_sessions:
            child.pending_cap = None
            print("[headroom] current session ended without a replacement "
                  "SessionStart; automatic handoff disabled for this child",
                  file=sys.stderr)
            _lose_supervision(
                child, "current session ended without a replacement "
                "SessionStart")
            # `records` is fully processed by here, so this drains nothing —
            # kept so all four early returns have one uniform shape and a
            # future `break` inside the loop cannot reintroduce the loss.
            self._announce_tail_caps(child, [])
            return None
        return proof

    def _record_unrequested_death(self, child, returncode):
        """The child is gone and this supervisor never asked for it.

        Records; deliberately does NOT restart. Resuming a session a human
        killed on purpose can double-run it, and that is a policy switch of
        its own — this exists so the next operator has something to read.

        Everything here runs AFTER the child is already dead, so there is no
        "refuse" left on any of it: each leg is independent and a failure in
        one must not cost the others. self.unrequested_death is set FIRST and
        unconditionally, because run()'s cleanup gate reads it and the
        forensics are worth more than any of the announcements."""
        self.unrequested_death = (returncode, self.now())
        account = str(child.account.get("name") or "")
        binding = child.binding
        session = str(getattr(binding, "session_id", "") or "")
        try:
            # NO `automatic` key, for P8's reason: _validated_automatic_rows
            # treats a row carrying one as safety-relevant and raises on any
            # action outside _AUTOMATIC_ACTIONS, so an OLDER headroom reading
            # a NEW ledger would disable every automatic handoff on the box.
            # A row without the key is skipped by every version.
            handoff.append_ledger({
                "schema": handoff.SCHEMA, "ts": self.now(),
                "action": "child_died_unrequested", "source_slot": account,
                "old_session_id": session,
                "child_generation": child.generation,
                # REPORTED, never classified on: the exit code is the one
                # thing the follow-up needs and the one thing 39 journals of
                # evidence could not justify deciding by.
                "exit": returncode})
        except Exception as error:  # noqa: BLE001 — the child is already gone
            print(f"[headroom] could not record the unrequested death of "
                  f"{account} in the handoff ledger ({error})",
                  file=sys.stderr)
        print(f"[headroom] {account}: the child exited {returncode} and "
              f"headroom never asked it to stop — keeping its hook journal "
              f"and settings file for whoever has to explain this",
              file=sys.stderr)
        if session:
            # the SIMPLE resume, rendered by Recovery so the quoting and the
            # redaction are the same ones every other printed argv gets
            recovery = Recovery(child.account, ["--resume", session],
                                str(getattr(binding, "cwd", "") or ""),
                                session, reason="unrequested_death")
            print(f"[headroom] to bring that conversation back, run:\n"
                  f"{recovery.command()}", file=sys.stderr)
        notify.emit({"event": "child_died_unrequested", "account": account,
                     "exit": returncode, "session": session})

    def _monitor(self, child, pending_handoff_id=""):
        # REUSE the guard _spawn installed+attached before/around the spawn
        # window, so there is no unguarded instant between spawn-success and
        # here (P1, r7). Fall back to constructing one only for a direct call
        # that did not go through _spawn (tests).
        signals = self._signals
        if signals is None:
            signals = _SignalGuard(child.process)
            signals.install()
            self._signals = signals
        # PER CHILD, not per supervisor: every deliberate stop is sent from
        # inside this loop and observed by this loop, so a stamp left by the
        # generation we just rotated away from would answer for the successor
        # — and the successor is exactly the child a post-rotation external
        # kill lands on. Clearing it here is what keeps the death of every
        # generation after the first visible.
        self._requested_stop_at = 0.0
        proof = None
        try:
            while True:
                signals.poll(child.process)
                if signals.shutdown_signal is not None:
                    # A shutdown signal disarms auto-handoff immediately. But
                    # NO notifier-bearing work may run before the signal is
                    # forwarded to the child (forwarding happens on
                    # _SignalGuard's second poll) — a slow HEADROOM_NOTIFY_CMD,
                    # whether from the loss notice OR from _handle_events'
                    # own supervision_lost paths, must never delay forwarding
                    # (P1-4). So until forwarded, skip _handle_events entirely:
                    # just check for exit and keep polling.
                    child.automation = False
                    if not signals.forwarded:
                        returncode = child.process.poll()
                        if returncode is not None:
                            # the child is already gone, so forwarding is moot
                            # and the notifier can no longer delay it — record
                            # the disarm rather than exiting silently
                            _lose_supervision(child, "shutdown signal received")
                            return returncode
                        self.sleep(POLL_SECONDS)
                        continue
                    # forwarded: safe to run notifiers now — record the loss once
                    _lose_supervision(child, "shutdown signal received")
                proof = self._handle_events(
                    child, pending_handoff_id, proof)
                returncode = child.process.poll()
                if returncode is not None:
                    # Drain the journal ONCE more before classifying. With
                    # SessionEnd-absence as the sole discriminator, a clean
                    # /exit whose SessionEnd landed between the read above and
                    # this poll would otherwise read as a killing — and that
                    # is the commonest exit there is. _read_events advances a
                    # cursor, so this reads the tail, never a replay.
                    try:
                        self._handle_events(child, pending_handoff_id, proof)
                    except SupervisorError:
                        # gathering evidence must never be what turns a child
                        # exit into a supervisor traceback
                        pass
                    if (self._requested_stop_at == 0.0
                            and signals.shutdown_signal is None
                            and not child.session_ended):
                        self._record_unrequested_death(child, returncode)
                    return returncode
                if child.automation and child.binding is None \
                        and self.now() - child.launched_at >= BIND_TIMEOUT:
                    if not child.hint_printed:
                        print("[headroom] no SessionStart handshake within 30s; "
                              "automatic handoff disabled for this child",
                              file=sys.stderr)
                        child.hint_printed = True
                    _lose_supervision(
                        child, "SessionStart hook never bound within "
                        f"{BIND_TIMEOUT:g}s — auto-handoff is not armed")
                # Preemptive rotation runs only when no cap proof is in
                # flight, and it never touches automation — the cap-reactive
                # path below is unchanged whatever it decides.
                if self._preemptive_due(child, proof):
                    outcome = self._preemptive_cycle(child)
                    if outcome is not None:
                        return outcome
                # The context backstop runs LAST and lowest: a seat rotation
                # is preferable (it also gives the conversation a fresh
                # process) and the cooperative baton handoff, which owns
                # everything above 10% remaining, is preferable to both. This
                # only ever fires for a session that took neither.
                if self._context_backstop_due(child, proof):
                    outcome = self._context_backstop_cycle(child)
                    if outcome is not None:
                        return outcome
                if proof is not None and child.automation:
                    self._cap_hold_sync(child, proof)
                if proof is not None and child.automation \
                        and self.now() >= child.cap_hold_next:
                    try:
                        plan = self._preflight(
                            child, proof,
                            held=bool(child.cap_scope_key))
                    except CapCleared as error:
                        # the window reset under us: nothing to rotate away
                        # from, and every reason to stay armed for the next one
                        print(f"[headroom] {error}; the seat is usable again "
                              "and automatic handoff stays armed",
                              file=sys.stderr)
                        notify.emit({"event": "cap_cleared",
                                     "account": child.account.get("name", ""),
                                     "reason": str(error)})
                        self._cap_hold_clear(child)
                        proof = None
                    except CapacityHold as error:
                        # nowhere to go YET. Hold the proof, keep the child
                        # running, keep automation armed — and disarm only
                        # once the budget for waiting is genuinely spent.
                        if not self._cap_hold(child, error):
                            print(f"[headroom] automatic handoff held: {error}; "
                                  f"no seat came free in "
                                  f"{CAP_HOLD_MAX * CAP_HOLD_SECONDS / 3600:g}h "
                                  "— automatic handoff disabled for this child",
                                  file=sys.stderr)
                            _lose_supervision(
                                child, f"automatic handoff held: {error}")
                            self._cap_hold_clear(child)
                            proof = None
                    except handoff.HandoffError as error:
                        # A recent mtime is expected just after StopFailure; keep
                        # polling until the required five quiet seconds pass.
                        if "changed recently" not in str(error):
                            print(f"[headroom] automatic handoff held: {error}; "
                                  "child continues", file=sys.stderr)
                            _lose_supervision(
                                child, f"automatic handoff held: {error}")
                            proof = None
                    except SupervisorError as error:
                        print(f"[headroom] automatic handoff held: {error}; child "
                              "continues", file=sys.stderr)
                        _lose_supervision(
                            child, f"automatic handoff held: {error}")
                        proof = None
                    else:
                        # admitted: whatever we were waiting for arrived
                        self._cap_hold_clear(child)
                        relaunch = None
                        try:
                            relaunch = self._stop_and_commit(child, plan, proof)
                            # the SIGTERM went out — see _preemptive_cycle for
                            # why a return, not the kill site, is the signal
                            self._requested_stop_at = self.now()
                        except Exception as error:
                            self._failure(plan, "pre_stop_failed: " + str(error))
                            print(f"[headroom] automatic handoff held: {error}; "
                                  "automatic handoff disabled for this child",
                                  file=sys.stderr)
                            _lose_supervision(
                                child, f"handoff stop failed: {error}")
                            proof = None
                        # P1-2: unless we are actually moving to the target
                        # (an automatic relaunch), the source keeps running and
                        # the target we leased in _lease_target was never
                        # spawned — release its unused lease so a third launcher
                        # isn't wrongly blocked. (release is a no-op if the
                        # target was never leased or the source is recovering.)
                        if not (relaunch is not None and relaunch.automatic):
                            route.release_slot_lease(plan.target["name"])
                        if relaunch is not None:
                            return relaunch
                        proof = None
                self.sleep(POLL_SECONDS)
        finally:
            signals.restore()
            self._signals = None

    def run(self):
        account = self.account
        args = self.initial_args
        cwd = os.path.realpath(os.getcwd())
        automatic = True
        pending_handoff_id = ""
        pending_plan = None
        recovery_plan = None
        # the planless equivalent of `pending_plan`: how to bring the session
        # back if the replacement for a same-seat context rotation cannot be
        # spawned (see Recovery)
        pending_recovery = None
        manual_resume = ""
        last_exit = 0
        clean_exit = False
        try:
            while True:
                try:
                    child = self._spawn(
                        account, args, cwd, automatic, pending_plan)
                except Exception as error:  # every post-commit spawn must recover
                    if self.spawn_ambiguous:
                        # P0-1: the Popen window was interrupted, so a child
                        # MAY be live on `account`. We have no handle to
                        # monitor it, and starting ANOTHER process (source
                        # recovery) would double-run the session. Stop here and
                        # keep this account's lease bound to the possibly-live
                        # child — never release it, never spawn again.
                        self._ambiguous_account = account["name"]
                        if pending_plan is not None:
                            self._failure(
                                pending_plan,
                                "target_spawn_ambiguous: " + str(error))
                        print(f"headroom: spawn outcome for {account['name']} "
                              f"is ambiguous ({error}); a child may be running "
                              f"— not starting another process. If no claude "
                              f"is running, retry.", file=sys.stderr)
                        # the possibly-live child is unmonitored — notify the
                        # loss directly with the known account name (no Child
                        # handle exists on this path) so observers get more than
                        # stderr+exit127 (P2, r4)
                        notify.emit({
                            "event": "supervision_lost",
                            "account": account["name"],
                            "reason": f"spawn outcome ambiguous ({error}); a "
                            "child may be live but is unmonitored"})
                        return 127
                    if pending_plan is not None:
                        # positively no child (OSError cleared spawn_ambiguous):
                        # the target relaunch started nothing — recover source
                        failed_plan = pending_plan
                        self._failure(
                            failed_plan, "target_relaunch_failed: " + str(error))
                        elective = getattr(failed_plan, "preemptive", False) is True
                        if elective:
                            # An ELECTIVE rotation whose target could not be
                            # started must not cost the cap-reactive
                            # guarantee: the source is not capped, so recover
                            # it SUPERVISED (auto-handoff re-arms on the new
                            # child's SessionStart) and hold the poll so it is
                            # not immediately targeted again. Same reasoning as
                            # the post-stop abort inside _stop_and_commit.
                            print(f"[headroom] preemptive target relaunch "
                                  f"failed ({error}); recovering the session "
                                  f"on {failed_plan.source.account['name']} "
                                  f"with auto-handoff still armed",
                                  file=sys.stderr)
                            self.preemptive_hold_until = \
                                self.now() + PREEMPT_BACKOFF_SECONDS
                            notify.emit({
                                "event": "preemptive_held",
                                "account": failed_plan.source.account["name"],
                                "reason": f"target relaunch failed: {error}"})
                        else:
                            print(f"[headroom] target relaunch failed ({error}); "
                                  "relaunching the source with automation off",
                                  file=sys.stderr)
                            # the recovered session is unsupervised — tell any
                            # observer, since it saw the initial supervised
                            # launch (P1-5)
                            notify.emit({
                                "event": "supervision_lost",
                                "account": failed_plan.source.account["name"],
                                "reason": f"target relaunch failed: {error}"})
                        # the target never started — release its unused lease
                        route.release_slot_lease(failed_plan.target["name"])
                        # the child that was stopped for this plan is gone,
                        # but the model it was running still decides what its
                        # conversation may be resumed into
                        relaunch = self._source_relaunch(
                            failed_plan, model=self.stopped_child_model)
                        account, args, cwd = (relaunch.account, relaunch.argv,
                                              relaunch.cwd)
                        automatic = elective
                        pending_handoff_id = ""
                        pending_plan = None
                        recovery_plan = failed_plan
                        continue
                    if pending_recovery is not None:
                        # A same-seat context rotation reserves nothing, so it
                        # carries no plan and the branch above cannot see it —
                        # but its child was ALREADY STOPPED, so exiting here
                        # would strand exactly the session the rotation exists
                        # to save. Bring it back on its own seat, SUPERVISED
                        # (the seat is not capped; an elective rotation must
                        # never cost the cap-reactive guarantee), and hold the
                        # backstop so the recovered child is not immediately
                        # targeted again.
                        failed = pending_recovery
                        print(f"[headroom] context rotation could not start its "
                              f"replacement ({error}); recovering the session "
                              f"on {failed.account['name']} with auto-handoff "
                              f"still armed", file=sys.stderr)
                        notify.emit({
                            "event": "context_backstop_held",
                            "account": failed.account["name"],
                            "reason": f"replacement spawn failed: {error}"})
                        self.context_hold_until = \
                            self.now() + PREEMPT_BACKOFF_SECONDS
                        account, args, cwd = (failed.account, failed.argv,
                                              failed.cwd)
                        automatic = True
                        pending_handoff_id = ""
                        pending_plan = None
                        pending_recovery = None
                        # the human's last resort must be EXACTLY what the
                        # machine would have run — reconstructing a resume
                        # command instead drops a model the transcript
                        # requires and re-adds a fork that a degraded stop
                        # already ruled unsafe
                        manual_resume = failed.command()
                        continue
                    print(f"headroom: {error}", file=sys.stderr)
                    if recovery_plan is not None:
                        self._print_manual_recovery(
                            recovery_plan, self.stopped_child_model)
                    elif manual_resume:
                        # the recovery above could not start either: leave the
                        # user the one command that gets their conversation back
                        print("headroom: automatic recovery could not start "
                              "Claude; run:", file=sys.stderr)
                        print(manual_resume, file=sys.stderr)
                    clean_exit = True
                    return 127
                # run() has now safely RECEIVED the child and taken ownership:
                # close the ambiguity window HERE (P0-1), outside the recovery
                # try/except above, so any failure between Popen-success and
                # this point kept spawn_ambiguous True and suppressed recovery.
                # spawned_any flips at the same safe point.
                self.spawned_any = True
                self.spawn_ambiguous = False
                pending_plan = None
                recovery_plan = None
                pending_recovery = None
                manual_resume = ""
                # the active child now exists on `child.account`: hold exactly
                # its lease. After a rotation this releases the OLD source
                # lease (kept until the target spawned, per _lease_target);
                # after a failed rotation it releases the unused target lease.
                # (P0-2)
                self._reconcile_leases(child.account["name"])
                if pending_handoff_id:
                    try:
                        handoff.append_action(
                            pending_handoff_id, "resume_spawned", automatic=True,
                            target_slot=account["name"],
                            old_session_id=args[1] if len(args) > 1 else "",
                            child_generation=child.generation)
                    except handoff.HandoffError as error:
                        print(f"[headroom] could not ledger resume spawn: {error}; "
                              "automatic handoff disabled", file=sys.stderr)
                        _lose_supervision(
                            child, f"resume spawn could not be ledgered: {error}")
                        automatic = False
                outcome = self._monitor(child, pending_handoff_id)
                if isinstance(outcome, Relaunch):
                    # the child has exited and the terminal is ours for a
                    # moment: this is the one place the user can actually see
                    # the handoff happen (anything printed earlier is hidden
                    # by Claude's alternate screen)
                    if outcome.reason.startswith("context_backstop"):
                        print(f"[headroom] this session was nearly out of "
                              f"context, continuing it on "
                              f"{outcome.account['name']} without losing the "
                              f"conversation", file=sys.stderr)
                    elif outcome.automatic and outcome.reason == "preemptive":
                        print(f"[headroom] {child.account['name']} is nearly "
                              f"out of headroom, continuing this conversation "
                              f"on {outcome.account['name']} before it caps",
                              file=sys.stderr)
                    elif outcome.automatic:
                        print(f"[headroom] {child.account['name']} hit its "
                              f"limit, continuing this conversation on "
                              f"{outcome.account['name']}",
                              file=sys.stderr)
                    else:
                        print(f"[headroom] recovering your session on "
                              f"{outcome.account['name']}", file=sys.stderr)
                    account, args, cwd = outcome.account, outcome.argv, outcome.cwd
                    automatic = (outcome.automatic if outcome.supervised is None
                                 else bool(outcome.supervised))
                    pending_handoff_id = outcome.handoff_id
                    pending_plan = outcome.plan if outcome.automatic else None
                    pending_recovery = outcome.recovery
                    continue
                last_exit = int(outcome)
                clean_exit = True
                return last_exit
        finally:
            # defensively restore signal handlers if a guard was installed by
            # _spawn but _monitor never got to restore it (P1, r7); normal
            # flow already restored it in _monitor's finally.
            if self._signals is not None:
                self._signals.restore()
                self._signals = None
            # the supervised launch is ending: release every lease this
            # supervisor holds so a waiting launch can take the account —
            # EXCEPT an account whose spawn was left ambiguous, whose lease
            # stays bound to the possibly-live child (P0-1). Crash exits rely
            # on the kernel dropping the flock instead.
            for name in route.held_lease_names():
                if name != self._ambiguous_account:
                    route.release_slot_lease(name)
            # Forensics outlive a death nobody asked for. _cleanup_files
            # unlinks the hook journal and the settings file, which together
            # are the ONLY record of what the child was doing — and on
            # 2026-08-01 at 07:30:42Z an external SIGTERM took this branch, so
            # the two killed lanes matched no journal at all and attributing
            # the incident cost a forensic dispatch. Bounded outside this
            # repo: bin/headroom-reaper.sh prunes a journal only when no live
            # process carries its supervisor id AND it has been idle >7d.
            if clean_exit and self.unrequested_death is None:
                self._cleanup_files()


def _initial_account(family):
    snapshot = route.ensure_fresh_snapshot()
    if snapshot is None:
        return None
    rows = route._snapshot_accounts(snapshot)
    # an explicitly exported CLAUDE_CONFIG_DIR that names a registered account
    # is the caller's routing decision — supervise THAT account instead of
    # re-routing, as long as it still has proven headroom (rotation off it on
    # a cap is unchanged)
    pinned = route.env_pinned_account(family)
    if pinned is not None:
        reason = route.block_reason(pinned, family, rows.get(pinned["name"]),
                                    route.cooldowns(), time.time())
        if reason is None:
            return pinned
        print(f"[headroom] env-selected account {pinned['name']} is not "
              f"routable ({reason}) — picking another", file=sys.stderr)
    account = next((candidate for candidate, reason in route.candidates(
        family, snapshot) if reason is None), None)
    if account is None:
        return None
    reason = route.block_reason(account, family, rows.get(account["name"]),
                                route.cooldowns(), time.time())
    return account if reason is None else None


def _is_inline_document(value):
    """Whether this string IS a settings document rather than naming one."""
    return (value or "").strip().startswith(("{", "["))


def redacted_settings_value(value):
    """A `--settings` value that is safe to print.

    A PATH names a document; an INLINE document IS the document, and a real
    one legitimately carries credentials (apiKeyHelper, an `env` block). The
    refusal diagnostics below go to stderr, which is captured by launchers and
    logs, so the inline form is named and never reproduced."""
    return "<inline JSON>" if _is_inline_document(value) else value


def redacted_argument(arg):
    """One argv TOKEN, safe to print.

    Two shapes carry a document, and only one of them starts with a brace:
    the shell split `--settings {…}` into its own token, but `--settings={…}`
    hides the document behind an `=` and begins with a dash. Testing the first
    character of the token only ever catches the first shape — which is how
    the equals form kept leaking a credential after the space-separated form
    was fixed. Any `--option=<document>` is elided, not just settings: the
    CLI takes JSON on `--agents`, `--json-schema` and `--managed-settings`
    too."""
    if _is_inline_document(arg):
        return "<inline JSON>"
    if arg.startswith("-") and "=" in arg:
        flag, _, value = arg.partition("=")
        if _is_inline_document(value):
            return flag + "=<inline JSON>"
    return arg


def redacted_command(argv):
    """A shell-safe rendering of an argv with every inline document elided."""
    return shlex.join([redacted_argument(arg) for arg in argv])


def _refuse_settings_launch(error):
    """The single refusal voice for an unusable `--settings`, exit code and
    all. Used by every surface that can reach one, so no caller has to invent
    its own — and none of them may answer with an unsupervised launch."""
    print(f"headroom: refusing to launch: {error}", file=sys.stderr)
    print("[headroom] headroom never runs an unsupervised child to work "
          "around a settings file", file=sys.stderr)
    return 2


def cmd_claude(family, args, fallback_argv=None):
    """Supervised launch. `fallback_argv` (opt-in, from
    --headroom-launch-fallback / HEADROOM_LAUNCH_FALLBACK=1) is the bare CLI
    argv to exec in-process when ANYTHING fails strictly BEFORE the first
    child CLI process was successfully spawned. Once a child has started
    (Supervisor.spawned_any) — or while the spawn outcome is even AMBIGUOUS
    (Supervisor.spawn_ambiguous, P0-3) — a later exit or crash is a normal
    supervision/exit path and NEVER triggers the fallback, so a live child is
    never duplicated by a bare relaunch.

    A user `--settings` disarms the fallback itself. Every fallback argv is
    the ORIGINAL argv, `--settings` and all, and a bare CLI is by definition
    unsupervised — so bare-execing one would start precisely the child the
    merge exists to prevent, on the routing failures (no headroom, lease
    unavailable, preparation error) that have nothing to do with the settings
    at all. Those refuse instead, and print the exact command to run by
    hand."""
    # EVERYTHING after the fallback intent is established runs inside the
    # pre-spawn guard — account selection, lease commit, the diagnostic, and
    # Supervisor construction — so any pre-spawn failure (including a
    # constructor error) still bare-execs when the fallback was requested
    # (P1-4). The guard is only for BEFORE the first spawn; runner.run() owns
    # the after-spawn boundary via spawned_any/spawn_ambiguous.
    runner = None
    try:
        _cleaned, raw_settings = split_user_settings(args)
    except UserSettingsError as error:
        return _refuse_settings_launch(error)

    def _fall_back(reason):
        """Take the opt-in bare fallback, or refuse it when the argv carries
        a user `--settings` that only a supervised launch can honour."""
        if raw_settings is None:
            return route.bare_fallback_exec(fallback_argv, reason)
        print(f"headroom: refusing the bare fallback: {reason}",
              file=sys.stderr)
        print(f"[headroom] --settings "
              f"{redacted_settings_value(raw_settings)} was given, and a bare "
              f"CLI cannot be supervised — headroom will not start an "
              f"unsupervised child carrying it. Run it yourself if that is "
              f"what you want:", file=sys.stderr)
        print("  " + redacted_command(fallback_argv), file=sys.stderr)
        return 2

    try:
        account = _initial_account(family)
        # commit: take the slot flock (no-op unless HEADROOM_SLOT_LEASE=1);
        # on the rare claim race, re-pick once — the lease check inside
        # block_reason now skips the account the other launch holds. A
        # LeaseError (infra failure) propagates to fail closed below.
        if account is not None \
                and not route.acquire_slot_lease(account, family):
            print(f"[headroom] {account['name']} is leased by another live "
                  f"launch — picking another", file=sys.stderr)
            account = _initial_account(family)
            if account is not None \
                    and not route.acquire_slot_lease(account, family):
                account = None
        if account is not None:
            print(f"[headroom] {family} -> {account['name']} "
                  f"({account['home']})", file=sys.stderr)
            # the wrapper handshake (route.write_launch_marker) is written
            # inside _spawn, immediately before the first Popen — after
            # settings/argv/env preparation, so a marker can never exist
            # without a child having been given its chance to start
            runner = Supervisor(family, args, account)
    except UserSettingsError as error:
        # The one pre-spawn failure that must NOT bare-exec: the bare argv
        # still carries the user's `--settings`, so falling back here would
        # start exactly the unsupervised child the merge exists to prevent —
        # and silently, since the session would look launched.
        return _refuse_settings_launch(error)
    except route.LeaseError as error:
        # HEADROOM_SLOT_LEASE=1 fails closed: refuse the routed launch. With
        # the explicit fallback opt-in, still degrade to a bare CLI (the
        # caller asked to always run something) — unless that argv carries a
        # user --settings, which no bare CLI can run supervised.
        print(f"[headroom] slot lease unavailable ({error}); refusing to "
              f"launch — HEADROOM_SLOT_LEASE=1 fails closed", file=sys.stderr)
        if fallback_argv is not None:
            return _fall_back(f"slot lease unavailable: {error}")
        return 2
    except Exception as error:  # noqa: BLE001 — opt-in: pre-spawn failures fall back
        if fallback_argv is not None:
            return _fall_back(f"launch preparation failed: {error}")
        raise
    if account is None:
        if fallback_argv is not None:
            return _fall_back(
                f"no account for '{family}' has proven headroom")
        print(f"[headroom] no account for '{family}' has proven headroom; "
              f"try `headroom status {family}`", file=sys.stderr)
        return 2

    def _may_fall_back():
        # strictly before-first-spawn AND the spawn outcome is unambiguous:
        # a live-but-unacknowledged child (spawn_ambiguous) must NOT fall back
        return (fallback_argv is not None and not runner.spawned_any
                and not runner.spawn_ambiguous)

    try:
        result = runner.run()
    except Exception as error:  # noqa: BLE001 — opt-in: pre-spawn failures fall back
        if _may_fall_back():
            return _fall_back(f"failed before Claude started: {error}")
        raise
    if _may_fall_back():
        # run() returned without ever spawning a child (e.g. the very first
        # spawn failed) — strictly before-first-spawn, so fall back
        return _fall_back("Claude never started (details on stderr)")
    return result
