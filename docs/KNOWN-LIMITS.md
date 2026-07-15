# Known limits and design tradeoffs

Findings from an adversarial cross-model review (GPT-5.6, x-high effort,
2026-07-11) that are deliberate tradeoffs or blocked on upstream, documented
here so users can judge them for their own threat model.

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

## An interrupted tool call may execute again after handoff

A live cross-account test showed that Claude can resume a transcript ending in
an unresolved `tool_use`: Claude re-drives the dangling call and reaches a
usable prompt. Automatic handoff therefore copies the capped transcript
byte-for-byte and prints `the interrupted tool call may re-run on resume`.
If the interrupted tool had an external side effect, that side effect may run
twice. All manual handoffs require `--force` for a dangling call: a 99–100%
usage snapshot alone is not an authenticated cap event and does not relax this
guard.

## Handoff carries conversation state, not process state

The fork preserves conversation continuity, routes for the same model family,
and launches from the latest hook-reported cwd. Background tasks, live MCP
connections, pending MCP or permission approvals, permission mode, extra
directories, IDE state, and other ephemeral launch flags are not migrated.
The local session and handoff JSONL journals are append-only and unbounded in
v0.2; protect the private state directory and compact them manually if needed.

Per-run injected settings files and the supervisor event journal are removed
best-effort when the supervisor exits cleanly. A hard crash, `SIGKILL`, power
loss, or filesystem error can leave those private files under
`state/supervisors/`; they contain hook metadata but no credentials and may be
deleted once no matching supervisor is running. Handoff publication recovery
markers are different: headroom reconciles those under the global handoff lock
on the next handoff operation.

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

## The local dashboard is plain HTTP on 127.0.0.1

`headroom serve` binds loopback only AND validates the `Host` header — a
non-loopback Host is rejected with 403, so a remote page can't reach it via
DNS-rebinding. What it does NOT have is authentication: any process on the
same machine using a normal loopback Host can read the served feed (the
sanitized public snapshot — emails redacted by default). For anything shared
or multi-user, put the static build behind your own web server and auth.
