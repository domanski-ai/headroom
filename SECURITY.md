# Security

headroom reads local provider credentials and your usage data, so its whole
job is to be trustworthy. Here is exactly what it does and doesn't do.

## What headroom touches

- **Reads** the credential/identity files your `claude`, `codex`, and `grok`
  CLIs already wrote (`~/.claude/.credentials.json`, `~/.codex/auth.json`,
  `~/.grok/auth.json`, etc.) and the Codex session logs. Adopted CLI homes are
  never written. `headroom connect` may run a provider's own login flow inside
  an isolated home; an expiring Grok token in such a Headroom-owned home may be
  refreshed and atomically written there.
- **Sends**, per collection, these provider requests and nothing else:
  - one to `api.anthropic.com/api/oauth/usage` per Claude account (the endpoint
    the Claude apps use for their own usage UI), authenticated with that
    account's existing token;
  - a live read per Codex account via the local `codex app-server`
    (`account/rateLimits/read` + `account/read`), which the Codex CLI itself
    uses; this returns real-time, identity-bound usage. (The older fallback
    path reads usage from disk and hits `auth.openai.com/oauth/userinfo` for
    identity instead.);
  - one metadata-only billing read to
    `grok.com/grok_api_v2.GrokBuildBilling/GetGrokCreditsConfig` per Grok
    account; and, only for an expiring Headroom-owned Grok home, one standard
    refresh grant to `auth.x.ai/oauth2/token`.
  No other outbound traffic.
- **Writes** its own state under `~/.headroom/` (override with `HEADROOM_DIR`):
  the private snapshot and config are `0600`; the sanitized public snapshot is
  `0644`.

## Safety properties (all covered by tests / red-team review)

- **Fail-closed routing.** An account is only routed with a fresh,
  identity-bound, in-range, uncooled reading. Stale, corrupt, unverifiable, or
  cooled state HOLDS routing — it never opens it. See `docs/HOW-IT-WORKS.md`.
- **No credential leakage into the public feed.** The dashboard feed carries
  only a whitelisted set of fields; raw exception text (which can contain local
  paths) is replaced with a generic note; emails are redacted by default.
- **Auth-override env vars scrubbed.** `ANTHROPIC_API_KEY`,
  `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, base-URL overrides, etc. are
  stripped from every provider subprocess so a stray env var can't silently
  redirect a call to the wrong account.
- **Bearer tokens never follow redirects.** Authenticated requests use a
  no-redirect opener, so a token can't be forwarded to another origin.
- **Local dashboard** binds loopback only and validates the `Host` header
  (blocks DNS-rebinding). It has no auth — don't expose it on a shared machine
  without your own layer in front.

## The honest limits

See `docs/KNOWN-LIMITS.md` for the deliberate tradeoffs (trust-on-first-use
org pinning, Codex log-derived best-effort tracking, keyring stores
unsupported). headroom manages accounts you legitimately hold; it doesn't
bypass provider controls.

## Reporting a vulnerability

Open a private security advisory on the GitHub repo, or email the maintainer.
Please don't file public issues for anything that could expose credentials.
