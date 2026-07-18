# How headroom works

```
                       ┌─────────────────────────────┐
                       │  ~/.headroom/config.json     │  what you EXPECT
                       │  accounts: name→provider→home│  (never trusted blindly)
                       └──────────────┬──────────────┘
                                      │
      every 10 min / on demand        ▼
  ┌────────────┐   OAuth usage API  ┌────────────────┐
  │  Claude     │◄──────────────────│                │
  │  provider   │  (read-only, the  │   collect      │──► state/usage-private.json
  └────────────┘   app's own call)  │  identity-bound│        (0600, full detail)
  ┌────────────┐   session logs     │   fail-closed  │──► state/public/usage.json
  │  Codex CLI  │◄──────────────────│                │        (sanitized, dashboard)
  │  telemetry  │   (on disk, free) └────────────────┘
  └────────────┘                            │
                                            ▼
              ┌──────────────┐      ┌──────────────┐
              │  dashboard   │      │    route     │
              │ index.html + │      │ pick/run/    │──► CLAUDE_CONFIG_DIR /
              │  usage.json  │      │ rotate +     │    CODEX_HOME env for
              │  (5 themes)  │      │ cooldowns    │    the chosen account
              └──────────────┘      └──────────────┘
```

## The identity model

Every account is a *slot*: a name, a provider, and an isolated CLI config
home. The provider's own login flow binds an identity (email + org/account
id) *into* that home. headroom then:

1. reads the bound identity back (via `claude auth status`, the OpenAI
   userinfo endpoint, or Grok's local OIDC metadata, with provider-specific
   local fallbacks),
2. fingerprints the provider account id (SHA-256, truncated — the raw id
   never leaves the private snapshot),
3. verifies the strongest binding each provider exposes at usage-read time
   (Claude returns the organization id in a response header; Grok's billing
   endpoint does not, so its seat fingerprint remains locally bound).

Consequences:

- a login that got clobbered (you logged into the wrong account in the wrong
  terminal) is detected and HELD, not silently mixed in;
- two slots that turn out to be the same login are both held with a
  `duplicate_identity` warning — otherwise the router would "rotate" onto
  the same exhausted quota;
- `expected_email` in config (set automatically by `headroom connect`) pins a
  slot to a specific identity permanently.

## The windows

| window | provider | meaning |
|---|---|---|
| `5h` | Claude; Codex when exposed | rolling session window |
| `7d` | Claude, Codex, Grok | weekly all-models window |
| `scoped:<Model>` | Claude | weekly cap for a specific model tier (e.g. Opus) |

Grok collection is metadata-only and never spends inference tokens. Adopted
Grok CLI homes are read-only. If an isolated home under
`~/.headroom/homes/` has an expiring bearer, the collector serializes a
standard OAuth refresh-token grant and atomically replaces that owned
`auth.json` before binding the snapshot to the new credential digest.

The dashboard and router treat *remaining* capacity (100 − used) as the
primary number. The router additionally honours provider `severity` flags and
holds anything at 100%.

## Stats history

Immediately after each public snapshot publication, the collector may append a
private row to `state/history/usage-history.jsonl`. Each row is built through a
strict whitelist: timestamp, account name, provider, plan/state flags, and each
window's `used_percent` and `resets_at`. It never stores token counts, emails,
raw identities, fingerprints, or credentials, even when dashboard email
redaction is disabled.

Writes are throttled to one sample per 60 seconds by default. On append,
history older than 30 days is pruned with an atomic same-directory rewrite;
the amortized prune may retain up to one extra grace day before it runs.
`HEADROOM_HISTORY_MIN_INTERVAL` and `HEADROOM_HISTORY_RETENTION_DAYS` change
those defaults; `HEADROOM_HISTORY=0` disables both writes and the history feed.
Any history failure is reduced to one warning and cannot fail collection.

`headroom serve` exposes the read-only `/history.json` feed without invoking
collection. The normal static build intentionally remains `index.html` plus
`usage.json`, so its Usage tab keeps working while Stats shows an unavailable
message when no live history endpoint exists.

## Token stats (explicit opt-in)

Token stats are a separate local collector, enabled only when
`dashboard.token_stats` is exactly `true` in `config.json` or
`HEADROOM_TOKEN_STATS=1` is present. The default path returns before transcript
discovery or aggregate-state reads (the private scan lock may still be
created). When enabled, the scan runs after the normal collection lock is
released, uses its own `state/tokens/scan.lock`, and cannot fail the main
collection.

For every live registry slot and valid `dashboard.token_extra_roots` entry, the
collector streams only that provider's local CLI logs:

- Claude Code: `<home>/projects/**/*.jsonl`, using timestamped assistant
  `message.usage` counters. Progressive or repeated records with the same
  request/message identity contribute their final component values once while
  that identity remains in the bounded 512-record dedupe tail.
- Codex: `<home>/sessions/**/rollout-*.jsonl`, using the authoritative
  `total_token_usage` cumulative counter from `token_count` events. Counter
  deltas are assigned to each event's UTC day, so repeated cumulative
  emissions are not summed.

An extra-root entry has `label`, `provider`, and `path` fields. The label is
1–40 characters without `@` and cannot duplicate another extra label or a
registry slot name; provider is `claude` or `codex`; path is an absolute,
existing directory. An invalid or disappeared path is skipped and makes the
token result partial rather than breaking registry collection. Each usable
entry is projected as a virtual slot with stable ID
`x-<first 24 hex characters of sha256(label + NUL + provider + NUL +
canonical-realpath(path))>`. Rebinding any of those three fields produces a
fresh ID. The `x-` namespace cannot collide with registry generation IDs, which
are lowercase hexadecimal only.

The parser necessarily reads each JSONL record to reach its usage block, but
message content is immediately discarded. Extra roots use the same discovery,
containment, symlink, inode-dedupe, cardinality, file-count, and serialized-state
budgets as registry homes; the budgets are shared across the whole scan. Walks
never follow directory symlinks, and every opened file is rechecked against the
real configured home.
`state/tokens/daily.json` contains only slot IDs, UTC dates, numeric token
counts, and bounded `families`, `efforts`, `projects`, and `attributed` numeric
maps. Project labels come from `cwd`, but only as the first path segment below
the operator's home (`~` for the home itself). Labels containing `@`, longer
than 24 characters, or otherwise unsafe fold into `other`; missing cwd data is
skipped. Each slot admits 12 project labels before later labels fold into
`other`. Claude records carry cwd directly; Codex uses the cwd from
`session_meta` when present. The private `scan-state.json` additionally keys
files by slot ID and home-relative path, and stores sizes, mtimes, device and
inode identity, a first-4KB fingerprint, safe byte offsets, per-file numeric
subtotals, bounded hashed dedupe metadata, and last-error status. It contains
no raw cwd values, absolute home paths, emails, or message text. Both files and the
scan lock are mode `0600` under a mode `0700` directory.

`total` is the headline token count: input + output + cache creation. Cache
reads remain separate; `total + cache_read` is all tokens processed. Codex
reports cached input as a subset of input, so headroom splits that amount out
before aggregation. A first scan backfills all files. Later scans, throttled by
`HEADROOM_TOKEN_SCAN_INTERVAL` (900 seconds by default), reuse unchanged
per-file subtotals and read appended byte tails when possible. Only
newline-terminated valid records advance a checkpoint; an incomplete EOF
fragment is retried. Handoff target copies carry one content-free boundary
record, so their copied prefix is attributed only to the source slot.

At payload time, the store is projected through one current config view: live
registry slot IDs plus virtual IDs for the extra-root entries still present and
usable in that view. Removed slot generations and deleted extra-root entries
are never served. A later token scan prunes their private state through the same
dead-ID path. Lifetime, per-row trailing-seven-day totals, peak days, and fleet
streaks are derived then, and every included row contributes to the daily fleet
map capped to the trailing 400 UTC days. The result is embedded in the existing
usage payload; there is no token endpoint or extra network surface. Sessions
whose logs live only on another machine are outside the collector's coverage.
A scan with unreadable files keeps their previous subtotals and marks the
embedded result as partial with a failed-file count.

Project totals are exact for records that carry cwd. Each account row exposes
its top six project labels with `grand_total` and share of that row's total; the
summary exposes the fleet top six on the same basis.

Registry rows remain attributable to isolated slot homes. A virtual Claude
extra-root row adds a separate, forward-only approximation. Once per scan,
headroom calls the same read-only identity probe used by the collector for that
Claude home. If its current verified OAuth email uniquely matches a registry
slot's `expected_email`, every newly discovered session file is stamped with
the slot name. The file keeps that stamp across later identity changes, and its
daily totals accrue to `attributed` under that name. Schema-6 files that existed
before this feature, and files first seen without a unique verified match, are
stamped `earlier`. The payload exposes the totals only as
`attributed_breakdown` on the virtual row; it never moves or merges them into a
real account row.

This boundary is intentional: the stamp records the identity active when the
scanner first saw a file, not necessarily the identity that created every turn
inside it. A long-lived file spanning a login change therefore remains with its
first stamp. The extra-root label still means “activity found under this home.”

## Cooldowns

A limit-hit writes `"<account>:<scope>": <reset-epoch>` into
`state/cooldowns.json`. `<scope>` is `*` for a session or weekly-all limit
(account-wide — every model family on that account is held) and a specific
model family only for a genuine model-scoped cap. The reset epoch comes from
the provider's own `resets_at` when known, else a conservative future floor
(≥15 min for a session hit, ≥6 h for a weekly hit). Cooldowns expire on their
own; `headroom clear <account>` (or `<account>:<scope>`) removes them early,
and `headroom clear` with no argument resets all.

## Session handoff (EXPERIMENTAL)

`headroom handoff` stages a verified copy of one Claude conversation transcript
in another eligible account home, writes an auditable baton to
`state/handoffs.jsonl`, and resumes with `--fork-session` from the same working
directory. The old transcript remains untouched and the target receives a new
session id. This carries conversation history only: background tasks, MCP
connections, and per-session permission approvals must be started again.

## Staleness

Routing decisions require a snapshot younger than `HEADROOM_SNAPSHOT_MAX_AGE`
(default 900s). Older snapshots trigger an inline re-collect. If collection
fails, the router *does not* fall back to the stale data — no account gets
picked on unproven capacity.

## Files

| path | perms | contents |
|---|---|---|
| `~/.headroom/config.json` | 0600 | slots + dashboard preferences |
| `~/.headroom/homes/<name>/` | provider-managed | isolated CLI credentials |
| `~/.headroom/state/usage-private.json` | 0600 | full snapshot incl. identity fingerprints |
| `~/.headroom/state/public/usage.json` | 0644 | sanitized dashboard feed |
| `~/.headroom/state/history/usage-history.jsonl` | 0600 | rolling window percentages; no emails or tokens |
| `~/.headroom/state/tokens/daily.json` | 0600 | opt-in per-slot, per-UTC-day numeric token aggregates |
| `~/.headroom/state/tokens/scan-state.json` | 0600 | opt-in private incremental paths, offsets, counters, and per-file numeric subtotals |
| `~/.headroom/state/tokens/scan.lock` | 0600 | token-scan and slot-purge serialization |
| `~/.headroom/state/cooldowns.json` | 0600 | active cooldowns |
| `~/.headroom/state/provider-backoff.json` | 0600 | usage-endpoint 429 backoff |

## Environment overrides

Everything is overridable for testing or custom layouts: `HEADROOM_DIR`,
`HEADROOM_SNAPSHOT_MAX_AGE`, `HEADROOM_OBSERVATION_MAX_AGE`,
`HEADROOM_CLOCK_SKEW`, `HEADROOM_CODEX_STALE_AFTER`,
`HEADROOM_IDENTITY_TIMEOUT`, `HEADROOM_SERVE_MAX_AGE`, `HEADROOM_HISTORY`,
`HEADROOM_HISTORY_MIN_INTERVAL`, `HEADROOM_HISTORY_RETENTION_DAYS`,
`HEADROOM_HISTORY_MAX_BYTES` (32 MiB default, 1 MiB floor),
`HEADROOM_TOKEN_STATS`, `HEADROOM_TOKEN_SCAN_INTERVAL`,
`HEADROOM_BIN_DIR`.
