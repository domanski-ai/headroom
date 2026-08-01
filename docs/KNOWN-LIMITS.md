# Known limits and design tradeoffs

Findings from an adversarial cross-model review (GPT-5.6, x-high effort,
2026-07-11) that are deliberate tradeoffs or blocked on upstream, documented
here so users can judge them for their own threat model.

## Windows v1 locking and launch boundaries

Windows uses `msvcrt.locking` on byte zero. Unlike Unix `fcntl.flock`, these
locks are mandatory rather than advisory and Windows has no shared-lock mode,
so the resident supervisor and transactional handoff remain Unix-only. A
Windows lock must be explicitly unlocked before its file is closed. Locks on
both platforms are released when the process dies; after an abrupt Windows
termination, release happens when the OS closes the process handle. The CRT's
blocking `LK_LOCK` retries once per second for ten attempts, then reports an
error instead of waiting indefinitely like Unix `flock`.

Windows v1 therefore routes `headroom claude` through the normal direct launch
path and prints `supervision requires a Unix terminal — launching
unsupervised`. The auto-handoff override cannot enable supervision there; the
opt-in launch-fallback still applies to failures before the unsupervised CLI
starts. Token-log walks keep `followlinks=False`, use no-follow open flags only
when Python exposes them, and retain the realpath containment check on every
platform, including Windows junctions and symlinks.

## Stats/history v1 known limits

- Cap-hit episode counting does not split episodes across provider window
  resets, so the count can be low when a reset occurs during an episode.
- Retention pruning is amortized and can keep up to one extra grace day before
  rewriting the history file.
- Removed-slot rows may persist on disk as private `0600` state until retention
  or an amortized prune removes them. They are never served after removal, and
  a fresh slot generation can never merge with rows from a reused name.
- A `/history.json` request already in flight when a slot removal commits may
  reflect the pre-removal state — a linearizable concurrent read (the response
  is as-of a moment when the slot existed), the same property every feed
  endpoint has against changing state.
- After a clock rollback, an old-timestamped row appended behind a fresh head
  row can delay time-based pruning until the head row ages past the grace day
  or the byte cap triggers. The delay is byte-cap bounded and self-heals.
- `/history.json` rebuilds its aggregations for every request, which is
  acceptable at the current history scale.
- Dashboards with six or more series repeat legend colours.
- Chart end-labels can overlap when there are more series than vertical space.

## Token stats known limits (opt-in)

- Coverage is machine-local. Sessions run on another computer, in a container,
  or under an unregistered CLI home are absent until those session logs exist
  inside a registered home on this machine. The figures therefore describe
  locally visible activity, not provider billing or an account-wide audit.
- Codex `token_count` events are assumed to expose a monotonically cumulative
  `total_token_usage` counter within each rollout file. Headroom assigns
  positive deltas to event days, ignores repeated totals, and treats a counter
  decrease as a reset. A future Codex schema that changes those semantics will
  require a parser update.
- Claude duplicate suppression persists the most recent 512 hashed
  request/message identities and their progressive maxima per file. A
  duplicate repeated after it has fallen out of that bounded tail is accepted
  and can count twice; the bound prevents transcript-sized scanner memory.
- Handoffs created by this version carry a copied-prefix marker and are counted
  exactly once across source and target slots. Historical target copies made
  before that marker existed cannot be distinguished from native records and
  may still double-count their copied prefix. Such copies are expected to be
  rare and recent.
- UTC timestamps define day boundaries and streaks. The current streak remains
  current through the following UTC day so an unfinished day does not erase a
  streak that was active yesterday.
- If provider-managed logs are deleted, moved, or rewritten, the next scan may
  reduce historical totals because the store is an aggregate of the logs that
  remain locally available.
- Project breakdowns require record-level `cwd` (Claude) or `session_meta.cwd`
  (Codex). Missing cwd is unclassified. Only the first directory below the
  operator home is retained, up to 12 project labels per slot; later labels
  fold into `other`.
- Extra-root account stamping is forward-only and scan-time approximate. A
  Claude file is permanently assigned to the uniquely matching registry slot
  whose verified OAuth identity was active when the scanner first saw it. A
  file can predate that scan or span later login changes. Pre-feature and
  unverifiable files remain `earlier`, and these totals stay only on the virtual
  row rather than changing real account totals.

## Supervised-launch residuals (opt-in launch safety)

The opt-in launch-safety features (`--headroom-launch-fallback` /
`HEADROOM_LAUNCH_FALLBACK`, `HEADROOM_SLOT_LEASE`, `HEADROOM_NOTIFY_CMD`; all
off by default) went through ten rounds of adversarial cross-model review.
Two accepted residuals remain, both requiring a signal delivered inside a
sub-millisecond window and both fail-safe in the direction that never
double-books a *monitored* session:

- **Ambiguous spawn with no child handle.** If an asynchronous exception
  interrupts the `Popen` fork window, headroom treats the spawn as ambiguous
  (a child *may* be live), suppresses fallback and rotation, and exits without
  starting a second session — but the possibly-live child was never returned,
  so it cannot be monitored or signalled. Prefer bare-CLI launch if you need a
  supervisor-orphan to be impossible.
- **Signal during handler restore.** A shutdown signal delivered in the exact
  instant CPython swaps the signal-handler table on a pre-spawn failure could,
  in principle, have its Python callback deferred past the point where headroom
  samples the latch. Restore is best-effort per-signal and the latch is sampled
  after restore, so the ordinary before/during-restore cases replay the kill;
  the residual is the untestable sub-instruction delivery race only.

## Auto-handoff is not yet release-proven on macOS

The full auto-handoff path (real cap -> stop -> copy -> same-terminal resume
with history intact) is proven live end-to-end against Claude Code 2.1.x on
Linux. The equivalent end-to-end signal, foreground process-group, terminal
restoration, descendant-cleanup, and resume test has not yet been completed on
macOS. Auto-handoff is on by default on both platforms because every guard
fails closed — missing or ambiguous evidence means headroom leaves the session
alone — but macOS users should know the SIGTERM/TTY contract there rests on
Linux evidence until a real-Mac run confirms it (reports welcome). Set
`routing.auto_handoff: false` to opt out. Headroom never escalates to
`SIGKILL`.

## Managed Claude policy can override injected hooks

The supervisor passes a private settings fragment through Claude's `--settings`
option; it does not rewrite account settings. Managed policy, `disableAllHooks`,
or a future settings-precedence change can suppress or replace those hooks. A
matching `SessionStart` handshake is mandatory. If it is absent for 30 seconds,
headroom disables automation for that child and leaves the child running.

A user-supplied `--settings` is merged under that fragment rather than passed
through beside it (Claude accepts one, and the second replaces the first), so
the supervisor refuses to launch a document that would suppress its hooks:
`disableAllHooks`, `allowManagedHooksOnly`, or an `env` block setting any
`CLAUDE_*` or `HEADROOM_*` variable (or `HOME`/`USERPROFILE`). The namespaces
are refused wholesale, not a list of known-bad names — `CLAUDE_CODE_SHELL`,
`CLAUDE_CODE_SHELL_PREFIX` and `CLAUDE_CODE_PROCESS_WRAPPER` decide what
actually gets executed, `HEADROOM_DIR` and `HOME` decide where the event is
written, and any release can add another. `--managed-settings` is refused
outright: policy settings sit above the merged document, so nothing in the
merge can answer for an `allowManagedHooksOnly` there.

Redirection of the event path does not depend on that check being complete:
the injected hook command pins `HEADROOM_DIR` into the command line itself,
which beats any inherited value. What remains is SUPPRESSION — an environment
that stops the hook running at all (a shell prefix, a broken interpreter, a
sandbox). Headroom cannot prevent that from inside the child, and does not
need to: no handshake arrives, and the 30-second timeout above disables
automation loudly and leaves the child running. A hook that cannot run is a
visible disarm, never a session that looks supervised and is not.

It also refuses the opt-in bare-CLI launch fallback for that run: the
fallback argv still carries `--settings` and a bare CLI is unsupervised, so
headroom prints the command (with any inline document elided — an inline
`--settings` can carry credentials and is never echoed) rather than running
it. The
merge only covers what headroom can see in that one document — managed and
policy settings still sit above it, which is the limit this section opened
with. The user document is read ONCE, at launch: editing the file mid-session
cannot change the live child, exactly like the rotation policy.

## An interrupted tool call may execute again after handoff

A live cross-account test showed that Claude can resume a transcript ending in
an unresolved `tool_use`: Claude re-drives the dangling call and reaches a
usable prompt. Automatic handoff therefore preserves every source record,
adds only the headroom copy-boundary record, and prints
`the interrupted tool call may re-run on resume`.
If the interrupted tool had an external side effect, that side effect may run
twice. All manual handoffs require `--force` for a dangling call: a 99–100%
usage snapshot alone is not an authenticated cap event and does not relax this
guard.

## Nothing re-runs the turn a cap refused

When capacity comes back, headroom moves the conversation and resumes it — see
"waiting for capacity" in the README. The session comes back *idle*: the
prompt the provider refused is not re-sent, and neither headroom nor any
supported Claude Code interface can inject one into a live interactive
session. `--resume` with a prompt means `-p`, which is non-interactive and
incompatible with supervision, and typing into the child's stdin would race
the human at the same terminal. So "the work resumes" means a human or the
session's own operator loop asks again; what headroom guarantees is that
asking again lands on a seat with headroom instead of a wall.

Two consequences worth planning around. A session doing continuous autonomous
work should be driven by something that re-asks (a queue, a loop, a scheduled
prompt) rather than assuming the refused turn is retried. And a supervisor
that is not running cannot revive anything at all: the hold lives in the
supervisor process, so a session launched outside `headroom claude` — or one
whose supervisor exited — has no revival path. Nothing about the wait is
persisted: a supervisor that is killed while holding a cap takes the hold with
it, and the child it was watching keeps running unsupervised on the capped
account.

## Headless supervision inherits stdin; it cannot replay it

`--headroom-auto-handoff` (or `HEADROOM_HEADLESS_SUPERVISION=1`) supervises a
piped, non-TTY `headroom claude` run so it rotates on a cap instead of
stalling. The child inherits the supervisor's own stdin, stdout and stderr —
there is no pty and no buffering layer — so a rotation continues the
*conversation*, not the *stream*. Whatever the pipe already delivered to the
stopped child is gone; the resumed session comes back idle, with the rest of
the pipe (if any) still ahead of it. Drive a headless run from something that
holds the work itself — a queue, a baton file, an operator loop — rather than
from a one-shot prompt on stdin that only the first child will ever see.

A `-p`/`--print` run is not this case: it stays exec-only (no resumable
session exists), so it is never supervised and never rotates.

## Handoff carries conversation state, not process state

The fork preserves conversation continuity, routes for the same model family,
and launches from the latest hook-reported cwd. Background tasks, live MCP
connections, pending MCP or permission approvals, permission mode, extra
directories, IDE state, and other ephemeral launch flags are not migrated.
The local session and handoff JSONL journals are append-only and unbounded in
v0.2; protect the private state directory and compact them manually if needed.

Per-run injected settings files and the supervisor event journal are removed
best-effort when the supervisor exits cleanly — with one deliberate exception.
If the child exits and headroom neither signalled it nor received a shutdown
signal, and the session never journaled a `SessionEnd`, headroom treats the
death as unrequested: it writes a `child_died_unrequested` row to the handoff
ledger, emits the matching notify event, prints the resume command, and **keeps
the journal and settings files**, because they are the only record of what the
child was doing. Nothing prunes them automatically; delete them once no
matching supervisor is running, or have your own housekeeping do it.

A hard crash, `SIGKILL`, power loss, or filesystem error can also leave those
private files under `state/supervisors/`; they contain hook metadata but no
credentials and may be deleted once no matching supervisor is running.
Handoff publication recovery
markers are different: headroom reconciles those under the global handoff lock
on the next handoff operation.

## POSIX ACLs on the state directory survive only if you ask (`HEADROOM_PRESERVE_ACL=1`)

headroom keeps its own directories at `0700` and its own files at `0600`. A
POSIX ACL stores its **mask** in the group bits, so an unconditional
`chmod 0700` silently reduces every named grant on those paths to
`#effective:---` — and because `ensure_private()` runs on every supervisor
tick, a grant an operator had applied and verified decayed minutes later with
no error anywhere. Set `HEADROOM_PRESERVE_ACL=1` and, on Linux, a directory
carrying a POSIX **access** ACL keeps its group bits: headroom enforces the
owner and `other` bits and passes the mask through unchanged.

It is opt-in because headroom cannot tell an ACL you set from one the
directory merely **inherited** from a parent's default ACL — a directory
created under such a parent is born with an access ACL nobody chose. So the
opt-in relaxes more than the grant you had in mind: with it set, and
`~/.headroom` (or wherever `HEADROOM_DIR` points) under a directory carrying a
default ACL, `~/.headroom` itself plus `state/` and its subtrees (history,
token scan state, supervisor journals, the session journal, handoff recovery)
are left at `0770` with that inherited ACL effective. `other` never gains
anything and every file headroom writes is still `0600`, but a group or named
user the inherited ACL grants can list those directories. Leave the variable
unset — the default — and the mode is enforced exactly as it always was,
whatever ACL is on the path.

The per-account credential homes under `homes/` are created once with
`mkdir(0700)` and are not re-chmod'd, so they keep `0700` and any inherited
grant stays `#effective:---` on them either way. The exception is the
temporary login-backup directory `headroom connect` makes inside a home while
re-logging in, which goes through the same call as the state directories — so
with the opt-in set, that one is relaxed too.

Two narrower notes. This is Linux-only: it keys off the
`system.posix_acl_access` xattr, so macOS (NFSv4 ACLs) and every other
platform enforce the mode exactly as before. And an ACL set on one of
headroom's JSON **files** cannot survive: those are written to a fresh temp
inode and swapped in with `os.replace`, so the old inode's ACL goes with it.
Grant on the containing directory instead.

## `headroom ops-status` is Linux-only and reads only local state

The session half of the report walks `/proc`; on macOS it degrades to
`"sessions": null` plus `session_discovery_failed` in `errors`, and the
per-account battery half still works. Container names come from one `tmux`
call with a one-second timeout — a wedged tmux server costs every session its
`container` field (null), not the report. The battery half is read from
headroom's own private snapshot, which is only as fresh as the last
`headroom collect`; the command never collects, never writes, and makes no
network calls. If that snapshot cannot be read, `seats` is `null` with
`seat_snapshot_unreadable` in `errors` — there is no built-in second source,
because a path shipped as a default names a directory this build knows nothing
about on the machine it runs on. If you publish a usage feed of your own
(`{"accounts": [...]}`, the shape `headroom collect` writes), point
`HEADROOM_OPS_FALLBACK_USAGE` at it and the command reads it when the private
snapshot is unreadable. Anything that can write that file can set the numbers
an ops layer sees, so keep it somewhere you own.

## A supervised lane looks like scaffolding in `ps` — ask, don't guess

A supervised child runs as
`claude --settings <state>/supervisors/<supervisor-id>-<generation>.<slot>.settings.json`.
The slot name is in there deliberately: the settings path is the only thing a
live lane says about itself in the process table, and a uuid, a digit and a
directory that reads like scratch space have already been mistaken for debris.
On 2026-08-01 an operator doing memory triage saw two such processes with
multi-day `etime`, read them as stale supervisor scaffolding, killed both, and
took down two live sessions whose panes then sat dark overnight.

**A long `etime` is the normal state of a healthy lane, not evidence of a
leak** — the whole point of supervision is that the child outlives individual
turns. Never decide from the argv alone. `headroom ops-status --json` is the
machine-readable answer to "is this pid a live session?": its `sessions` array
is a `/proc` census of every supervised child on the machine, with the pid,
slot, session id and container for each. If a pid is in there, it is a live
lane. (Linux only — see above.)

Two consequences worth knowing if you automate around this. The slot is a
filename *infix*, so anything globbing `supervisors/*.settings.json` keeps
matching. And a child spawned by an older headroom still carries the previous
`<supervisor-id>-<generation>.settings.json` name; the census accepts both
shapes, so a rolling upgrade never makes a running lane disappear from it.

## Claude usage binding is trust-on-first-use

The Anthropic usage endpoint identifies its organization in a response
header, but a login's *default* org (from `claude auth status`) can
legitimately differ from its *usage* org (multi-org accounts). headroom
therefore pins the usage-org fingerprint per slot on the first successful
read and holds the slot if it ever changes. The first read itself is
unpinned — if an attacker controls your config home *before* first use, TOFU
cannot detect it (they could also just take the credentials). Run
`headroom collect` once right after connecting to close the window.

## Codex reads need a Codex CLI with the app-server

Codex usage is read live from `codex app-server`
(`account/rateLimits/read` + `account/read`), which requires a reasonably
recent Codex CLI. On an older Codex without the app-server, headroom falls
back to a best-effort read of the CLI's on-disk `rate_limits` session
telemetry — which is only current while you're actively using that account
and is held by the router (shown Idle/Waiting on the dashboard) until a fresh
reading appears. Set `HEADROOM_CODEX_ROUTING=0` to force Codex dashboard-only.

## A project's own CLI settings can override the selected provider

headroom scrubs provider-override environment variables before launching a
CLI, but Claude Code and Codex also read their OWN config after startup — a
project `.claude/settings.json` with an `env` block or `apiKeyHelper`, or a
Codex `config.toml` custom provider, is applied by the CLI itself and can send
your session to a different provider/account than the slot headroom selected.
headroom can't override that from outside. If you use alternate-provider
settings (Bedrock/Vertex/custom gateways), headroom's account routing does not
apply to those sessions — use headroom only with direct OAuth/subscription
logins.

## The Codex fallback path (only when the app-server is unavailable)

The primary Codex read is the live app-server call above. If that fails (an
older Codex CLI), headroom falls back to the CLI's on-disk `rate_limits`
session telemetry, which is best-effort:

- an account you're actively using shows **Live**;
- a quiet account shows **Idle — last seen Nh ago** (held by the router);
- an account that has never run Codex shows **Waiting — run Codex once**;
- a rate-limited account shows **Limited — resets …**.

Upstream gaps that make the fallback best-effort: session logs don't reliably
identity-stamp which user a `rate_limits` event belongs to (openai/codex#16323)
and some versions emit `rate_limits: null` (openai/codex#14880). The live
app-server read has none of these problems — it returns identity-bound,
real-time data — so keeping your Codex CLI current is the way to get
first-class Codex tracking.

## `verified_local` identities are routable

When the network or provider CLI is unavailable, identity falls back to
local credential metadata and is labeled `verified_local` (visible in the
snapshot and on the dashboard). This keeps offline/air-gapped setups usable.
If you want provider-verified-only routing, treat `verified_local` as held —
open an issue if you want this as a config flag.

## macOS Keychain (Claude) — read directly; multi-account depends on CLI version

On Claude Code for **macOS**, the OAuth token is stored in the login
**Keychain**, not in `~/.claude/.credentials.json` (and `CLAUDE_CONFIG_DIR`
never moves it to a file on macOS the way it does on Linux/Windows).

headroom reads the Keychain directly via the `security` CLI, so a normal macOS
Claude login is tracked with no extra steps. If your Keychain is locked, macOS
prompts to allow access the first time; approve it (*Always Allow* avoids
repeat prompts).

**Multi-account on macOS — the good news.** Current Claude Code builds
namespace their Keychain item **per config directory**
(`Claude Code-credentials-<hash of CLAUDE_CONFIG_DIR>`), which means each
headroom slot gets its own isolated item and multiple Claude accounts can
coexist on one Mac. headroom probes for this at connect time:

- **Namespaced items found** (current CLI) → additional Claude accounts
  connect normally, each isolated in its own Keychain item.
- **Legacy shared item** (older CLI, or the default no-config-dir login) →
  a second `claude` login would *overwrite* the existing login's token
  machine-wide, so `headroom connect` refuses it up front and tells you to
  update Claude Code. One Claude account per Mac in that case; extra accounts
  belong on a Linux host, and Codex accounts are isolated everywhere.

The namespacing was verified against the official 2.1.207 macOS binary but is
undocumented upstream and could change; headroom fails closed (holds the
account) rather than guessing if the probe stops matching. Override the base
item name with `HEADROOM_CLAUDE_KEYCHAIN_SERVICE` if a future CLI renames it.

- **Codex `cli_auth_credentials_store = "keyring"`** and other non-file stores
  are likewise invisible; such slots show as not logged in.

## Scoped model caps aren't enforced on the generic `claude` route

`headroom claude` routes on the account-wide 5h/7d windows — it can't know
which model the Claude CLI will actually use, so it does NOT hold an account
just because one model's weekly cap (e.g. Opus) is exhausted (that would
wrongly block Sonnet/Haiku work on the same account). To gate on a specific
model's cap, name it: `headroom claude --model opus` holds when the Opus
weekly cap is full.

## `headroom run` retries are for idempotent commands

Rotation replays the whole command on the next account when a run *fails*
with a provider-limit error on stderr. If your command has side effects
before the limit hits, those side effects happen once per attempt. Use
`headroom claude`/`env`/`pick` for non-idempotent work.

Two kinds of limit reach that branch and they are spent differently. A
**cap** cools the account and rotates; a **transient** (429, overload,
`rate_limit_error`) rotates *without* cooling, because the seat is fine and
the CLI has already done its own retrying by the time it exits — a blip
should never take a healthy account out of routing for five hours. The cap's
cooldown follows the wording: `out of usage credits` names the model-scoped
weekly pool, so it cools that one family for seven days (account-wide would
take the other families down with it, and a five-hour window would let the
next launch re-pick the spent family); "week" cools the account for seven
days; anything else cools it for five hours.

## The local dashboard is plain HTTP on 127.0.0.1

`headroom serve` binds loopback only AND validates the `Host` header — a
non-loopback Host is rejected with 403, so a remote page can't reach it via
DNS-rebinding. What it does NOT have is authentication: any process on the
same machine using a normal loopback Host can read the served feed (the
sanitized public snapshot — emails redacted by default). For anything shared
or multi-user, put the static build behind your own web server and auth.
