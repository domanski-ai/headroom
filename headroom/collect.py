"""Read every account's usage windows WITHOUT consuming an inference window.

Claude: the same OAuth usage endpoint the Claude Code UI uses
(``/api/oauth/usage``), authenticated with the account's existing login token.
The response is bound to the account by comparing the organization id the
provider returns against the identity bound inside that slot's config home —
a clobbered or swapped login can never report another account's headroom.

Codex: read live from the Codex app-server (``codex app-server`` ->
``account/rateLimits/read`` + ``account/read``), identity-bound to each slot's
CODEX_HOME. Falls back to on-disk ``rate_limits`` session telemetry only when
the app-server is unavailable (older Codex CLI). No inference tokens spent.

Fail-closed rules:
  * an account with unverifiable identity or an out-of-range reading is HELD
    (ok=false) rather than guessed at;
  * a 429 from the usage endpoint sets a provider-wide backoff ledger honoured
    by later runs;
  * snapshots are written atomically, and a sanitized public projection is
    derived for the dashboard (optionally with emails redacted).
"""
import base64
import contextlib
import email.utils
import glob
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

from . import history, locks, paths, registry, tokens

IDENTITY_TIMEOUT = paths.env_int("HEADROOM_IDENTITY_TIMEOUT", 15)
CODEX_STALE_AFTER = paths.env_int("HEADROOM_CODEX_STALE_AFTER", 1800)
# how long a past reading stays serviceable — keep in sync with route.py,
# which enforces the same bound at routing time (collect must not import
# route: route imports collect)
OBSERVATION_MAX_AGE = paths.env_int("HEADROOM_OBSERVATION_MAX_AGE", 1800)
SCHEMA_VERSION = 1

# A fresh claude reading published by the estate's cron collector
# (ai-accounts) is served instead of a second anthropic_usage_api call: the
# usage API rate-limits per account, and two independent collectors tripping
# it is exactly what blinds the widget for the provider's ~51-minute backoff
# window. Empty string disables ingestion entirely (kill switch); the native
# API path remains the automatic fallback whenever the external reading is
# missing, stale, or fails any check below.
EXTERNAL_CLAUDE_SNAPSHOT = os.environ.get(
    "HEADROOM_EXTERNAL_CLAUDE_SNAPSHOT",
    os.path.expanduser("~/ai-accounts/snapshots/usage-private.json"))
EXTERNAL_CLAUDE_MAX_AGE = paths.env_int("HEADROOM_EXTERNAL_CLAUDE_MAX_AGE", 720)
# past this snapshot age the cron pipeline counts as DEAD and the native API
# path takes over; younger than this, its verdict is authoritative — held
# rows DEFER (no API call) rather than triggering a native read, because the
# post-backoff stampede (serve + cron + primer all calling within minutes of
# the retry window opening) is what re-trips the provider and made 2026-08-07
# a day of rolling ~57-minute blind windows
EXTERNAL_CLAUDE_PIPELINE_DEAD = paths.env_int(
    "HEADROOM_EXTERNAL_CLAUDE_PIPELINE_DEAD", 1200)

PUBLIC_FIELDS = {
    "id", "name", "email", "provider", "plan", "ok", "note", "error_code",
    "retry_at",
    "captured_at", "source", "stale", "windows", "identity_verified",
    "identity_method", "trust_state", "routable", "subscription",
    "throttle_carryover",
}


class IdentityBindingError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class UsageUnknown(RuntimeError):
    """The estate cron collector declined to spend a provider call this run
    (its own per-run budget), so this slot has no fresh reading and no
    provider hold. Unreadable under its own name; never a throttle."""


class ProviderThrottleError(RuntimeError):
    def __init__(self, retry_at, provider_response=False):
        self.retry_at = int(retry_at)
        self.provider_response = provider_response
        super().__init__("usage_source_rate_limited")


def iso_ep(value):
    if value is None:
        return None
    # Same unit ambiguity as the oauth expiresAt below, and the same
    # threshold, so the two live as ONE decision rather than two coincidences:
    # 1e11 seconds is the year 5138 and 1e11 milliseconds is 1973, so no real
    # epoch-seconds value can exceed it for ~3000 years and no real
    # epoch-milliseconds value since 1973 can fall below it. `bool` is an int
    # subclass — a flag must not mint a valid-looking 1970 timestamp.
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value / 1000.0) if value > 1e11 else int(value)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp())
    except (TypeError, ValueError):
        return None


def fingerprint(value):
    if not value:  # never mint a valid-looking fingerprint from a missing id
        raise IdentityBindingError("identity_id_missing")
    return hashlib.sha256(str(value).encode()).hexdigest()[:16]


# Auth-override variables that would silently redirect a provider CLI or API
# call to a different account/provider than the slot we selected (see
# anthropics/claude-code#16238). Scrubbed from every subprocess/env we build.
# Covers direct keys/tokens, alternate-provider selectors (Bedrock/Vertex),
# their credentials and base URLs, and Codex's API-key / agent-identity paths.
AUTH_OVERRIDE_VARS = (
    # Anthropic direct
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_OAUTH_TOKEN",
    # Claude Code alternate providers — these reroute Claude off the OAuth slot
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
    "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL",
    "AWS_PROFILE", "AWS_BEARER_TOKEN_BEDROCK", "AWS_REGION",
    "CLOUD_ML_REGION", "ANTHROPIC_VERTEX_PROJECT_ID", "GOOGLE_APPLICATION_CREDENTIALS",
    # OpenAI / Codex
    "OPENAI_API_KEY", "OPENAI_BASE_URL", "CODEX_API_KEY", "CODEX_AGENT_IDENTITY",
)


def scrubbed_env(base=None):
    env = dict(os.environ if base is None else base)
    for var in AUTH_OVERRIDE_VARS:
        env.pop(var, None)
    return env


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Authenticated requests never follow redirects — a redirect would
    forward the bearer token to whatever origin the response names."""

    def redirect_request(self, *args, **kwargs):
        return None


_no_redirect_opener = urllib.request.build_opener(_NoRedirect)


def open_authenticated(request, timeout):
    return _no_redirect_opener.open(request, timeout=timeout)


def retry_after_epoch(headers, now=None):
    now = int(time.time()) if now is None else int(now)
    raw = (headers.get("retry-after") or headers.get("Retry-After")) if headers else None
    if raw:
        try:
            return now + max(1, int(float(raw)))
        except (TypeError, ValueError, OverflowError):
            try:
                parsed = email.utils.parsedate_to_datetime(raw)
                return max(now + 1, int(parsed.timestamp()))
            except (TypeError, ValueError, OverflowError):
                pass
    return now + 300


# ---------------------------------------------------------------- identity

def decode_jwt_payload(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("invalid local identity token") from error


def _claude_metadata_candidates(home):
    """Where Claude Code may keep the oauthAccount block for this home.

    Headroom-managed homes (CLAUDE_CONFIG_DIR pointed at the slot) store
    ``<home>/.claude.json``. The DEFAULT profile — the common Windows and
    single-account layout — uses ``~/.claude`` as the config dir but keeps
    ``.claude.json`` one level up in the profile root, leaving only a stub
    inside the config dir. Yield both, preferred location first.
    """
    yield os.path.join(home, ".claude.json")
    parent = os.path.dirname(os.path.abspath(home))
    if os.path.basename(os.path.abspath(home)) == ".claude":
        yield os.path.join(parent, ".claude.json")


def claude_local_identity(home):
    """Identity bound inside the slot from local metadata only (no network)."""
    oauth = {}
    for candidate in _claude_metadata_candidates(home):
        metadata = paths.load_json(candidate) or {}
        found = metadata.get("oauthAccount") or {}
        if found.get("emailAddress") and found.get("organizationUuid"):
            oauth = found
            break
    email_address = oauth.get("emailAddress")
    org = oauth.get("organizationUuid")
    if not email_address or not org:
        raise IdentityBindingError("claude_local_binding_missing")
    return {
        "verified": False,
        "email": email_address,
        "account_fingerprint": fingerprint(org),
        "method": "claude_local_metadata",
        "plan_type": None,
    }


# The macOS login Keychain item the Claude CLI stores its OAuth token in.
# On macOS the token lives in the Keychain, NOT in `.credentials.json`.
# Current CLI builds (verified against the official 2.1.207 darwin binary)
# NAMESPACE the item per config directory: with CLAUDE_CONFIG_DIR set, the
# service is "Claude Code-credentials-<sha256(NFC(config_dir))[:8]>"; with no
# CLAUDE_CONFIG_DIR it is the legacy shared item below. That namespacing is
# what makes multiple isolated Claude accounts possible on one Mac. Override
# the base name with HEADROOM_CLAUDE_KEYCHAIN_SERVICE if a future CLI changes it.
CLAUDE_KEYCHAIN_SERVICE = "Claude Code-credentials"


def claude_keychain_service(home=None):
    """The Keychain service name the Claude CLI uses for a given config home:
    namespaced per-directory when a home is given, legacy shared otherwise."""
    base = os.environ.get("HEADROOM_CLAUDE_KEYCHAIN_SERVICE",
                          CLAUDE_KEYCHAIN_SERVICE)
    if not home:
        return base
    import unicodedata
    normalized = unicodedata.normalize("NFC", str(home))
    return base + "-" + hashlib.sha256(normalized.encode()).hexdigest()[:8]


def claude_keychain_oauth(service=None, runner=subprocess.run, home=None):
    """Read the `claudeAiOauth` blob out of the macOS login Keychain, or None.

    Tries the per-home namespaced item first (current CLI builds), then the
    legacy shared item. Only meaningful on macOS; returns None everywhere else
    (and on any error, a missing `security` binary, a locked Keychain, or an
    absent item) so callers degrade to the fail-closed 'held' behaviour."""
    if sys.platform != "darwin":
        return None
    security = shutil.which("security")
    if not security:
        return None
    services = [service] if service else []
    if not services:
        if home:
            # the CLI hashes the exact CLAUDE_CONFIG_DIR string it was launched
            # with — cover both the given form and its resolved form (symlinked
            # base dirs would otherwise miss the item)
            for variant in (str(home), os.path.realpath(str(home))):
                candidate = claude_keychain_service(variant)
                if candidate not in services:
                    services.append(candidate)
        services.append(claude_keychain_service())
    for name in services:
        try:
            completed = runner([security, "find-generic-password", "-s", name,
                                "-w"], capture_output=True, text=True,
                               timeout=10)
        except (OSError, subprocess.SubprocessError):
            return None
        raw = (getattr(completed, "stdout", "") or "").strip()
        if getattr(completed, "returncode", 1) != 0 or not raw:
            continue
        try:
            blob = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(blob, dict):
            continue
        # The item stores the same shape as the file
        # (`{"claudeAiOauth": {...}}`); tolerate a bare credential object too.
        oauth = blob.get("claudeAiOauth")
        if isinstance(oauth, dict):
            return oauth
        if blob.get("accessToken"):
            return blob
    return None


def claude_keychain_item_exists(home, runner=subprocess.run):
    """True when the per-home NAMESPACED Keychain item exists (no secret read:
    `-w` omitted). Distinguishes a CLI that namespaces per config dir from a
    legacy build sharing one item — the capability gate for multi-account
    Claude on macOS. False on any error (fail closed)."""
    if sys.platform != "darwin":
        return False
    security = shutil.which("security")
    if not security:
        return False
    try:
        completed = runner([security, "find-generic-password", "-s",
                            claude_keychain_service(home)],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return getattr(completed, "returncode", 1) == 0


def claude_oauth(home, runner=subprocess.run):
    """The `claudeAiOauth` credential the Claude CLI will actually use for this
    home — from `.credentials.json` when present (Linux/Windows, or an isolated
    CLAUDE_CONFIG_DIR home), otherwise the macOS Keychain (per-home namespaced
    item first, legacy shared item as fallback)."""
    oauth = (paths.load_json(os.path.join(home, ".credentials.json"))
             or {}).get("claudeAiOauth")
    if isinstance(oauth, dict) and oauth.get("accessToken"):
        return oauth
    return claude_keychain_oauth(runner=runner, home=home) \
        or (oauth if isinstance(oauth, dict) else {})


def credential_digest(provider, home):
    """A digest of the ACTUAL token the provider CLI will use — the Claude
    `.credentials.json` accessToken or the Codex `auth.json` access_token.
    Binding to this (not just the identity metadata) closes the split-token
    TOCTOU: swapping only the credential file changes this digest even if the
    identity metadata still names the old account."""
    try:
        if provider == "claude":
            token = (claude_oauth(home) or {}).get("accessToken")
        else:
            token = ((paths.load_json(os.path.join(home, "auth.json")) or {})
                     .get("tokens") or {}).get("access_token")
        return hashlib.sha256(token.encode()).hexdigest()[:16] if token else None
    except (OSError, ValueError, AttributeError):
        return None


def local_binding(provider, home):
    """(identity_fingerprint, credential_digest) currently bound in the slot,
    from local files only (no network). The router compares BOTH against the
    snapshot to detect a home re-logged into a different account/token."""
    try:
        if provider == "claude":
            fp = claude_local_identity(home)["account_fingerprint"]
        else:
            auth = paths.load_json(os.path.join(home, "auth.json")) or {}
            claims = decode_jwt_payload((auth.get("tokens") or {}).get("id_token"))
            provider_claims = claims.get("https://api.openai.com/auth") or {}
            fp = fingerprint(provider_claims.get("chatgpt_account_id")
                             or claims.get("sub"))
    except (IdentityBindingError, ValueError, KeyError, OSError):
        fp = None
    return fp, credential_digest(provider, home)


def claude_plan(home):
    oauth = claude_oauth(home) or {}
    subscription = str(oauth.get("subscriptionType") or "").lower()
    if subscription == "team":
        # before the tier checks: team seats carry unreliable per-user tiers
        # (default_claude_max_5x / default_raven, cached at login)
        return "Team"
    tier = str(oauth.get("rateLimitTier") or "").lower()
    if "max_20x" in tier:
        return "Max 20x"
    if "max_5x" in tier:
        return "Max 5x"
    return {"max": "Max", "pro": "Pro", "free": "Free"}.get(subscription)


def claude_bin():
    return shutil.which("claude")


def claude_identity(home, runner=subprocess.run):
    """Provider-verified identity via `claude auth status`; local fallback."""
    binary = claude_bin()
    if binary:
        env = scrubbed_env()
        env["CLAUDE_CONFIG_DIR"] = home
        try:
            process = runner(
                [binary, "auth", "status", "--json"], env=env,
                capture_output=True, text=True, timeout=IDENTITY_TIMEOUT,
            )
            if process.returncode == 0:
                status = json.loads(process.stdout)
                if status.get("loggedIn"):
                    org_id = status.get("orgId")
                    return {
                        "verified": True,
                        "email": status.get("email"),
                        "account_fingerprint": fingerprint(org_id) if org_id else None,
                        "method": "claude_auth_status",
                        "plan_type": status.get("subscriptionType"),
                    }
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            pass
    return claude_local_identity(home)


# Where the Codex CLI is installed on this box when it is not on PATH. The
# serve process runs under systemd --user with the unit's default PATH
# (/usr/local/bin:/usr/bin:/bin and friends), which does not include the
# user's ~/.local/bin, so shutil.which("codex") returned None from serve
# while the same call from an interactive shell found it. That single
# difference made headroom hold codex-gmail as codex_cli_missing (a lie:
# the CLI was installed and the estate cron collector, which carries its
# own fallback, read the seat fine) and Paul saw NO READ in DMUX. Measured
# read-only by the dmux lane 2026-08-17 06:2xZ, root cause confirmed by the
# steward from serve's /proc environ. Order: PATH first, then the standalone
# install symlink, then any nvm-managed copy, newest first.
CODEX_BIN_FALLBACKS = (
    os.path.expanduser("~/.local/bin/codex"),
    os.path.expanduser("~/.codex/packages/standalone/current/bin/codex"),
)


def codex_bin():
    binary = shutil.which("codex")
    if binary:
        return binary
    for candidate in CODEX_BIN_FALLBACKS:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    for candidate in sorted(glob.glob(
            os.path.expanduser("~/.nvm/versions/node/*/bin/codex")),
            reverse=True):
        if os.access(candidate, os.X_OK):
            return candidate
    return None


# App-server failure classification: an explicit auth rejection or protocol
# error must NEVER degrade into routable local telemetry, so each outcome gets
# a distinct hold code. Only genuine transport unavailability (older Codex CLI
# without the app-server) may fall back — and that fallback is display-only.
CODEX_AUTH_ERROR_MARKERS = (
    "token_invalidated", "refresh token", "invalid_grant", "unauthorized",
    "401", "login required", "not logged in", "re-login", "login again",
)
CODEX_THROTTLE_MARKERS = (
    "429", "too many requests", "overload", "throttl",
    "temporarily unavailable", "503", "retry later",
)
CODEX_DASHBOARD_FALLBACK_CODES = frozenset({
    "codex_app_server_spawn_failed",
    "codex_app_server_no_response",
    "codex_app_server_io_failed",
})
CODEX_HOLD_NOTES = {
    "codex_auth_rejected": (
        "codex login rejected by the provider (token invalidated / re-login "
        "required); run `headroom connect` to re-login"),
    "codex_capacity_unavailable": (
        "API-key Codex seat — no subscription capacity windows; excluded "
        "from capacity routing"),
    "codex_capacity_unrecognized": (
        "codex app-server returned no recognized 5h/7d capacity window; "
        "seat held"),
    "codex_app_server_protocol_error": (
        "codex app-server protocol/malformed response; seat held (no local "
        "fallback after a protocol error)"),
}


def classify_codex_appserver_error(error):
    """Map a JSON-RPC error object from the codex app-server to a distinct
    hold code instead of collapsing everything into one generic error:
    explicit auth rejection, overload/throttle, or protocol error."""
    try:
        text = json.dumps(error).lower()
    except (TypeError, ValueError):
        text = str(error).lower()
    if any(marker in text for marker in CODEX_AUTH_ERROR_MARKERS):
        return "codex_auth_rejected"
    if any(marker in text for marker in CODEX_THROTTLE_MARKERS):
        return "codex_app_server_throttled"
    return "codex_app_server_protocol_error"


def codex_auth_mode(auth):
    """How this Codex home authenticates: "chatgpt" (subscription login with
    usage windows), "apikey" (metered — no subscription capacity to route),
    or "unknown"."""
    explicit = str(auth.get("auth_mode")
                   or auth.get("preferred_auth_method") or "").lower()
    if explicit == "apikey":
        return "apikey"
    if (auth.get("tokens") or {}).get("id_token"):
        return "chatgpt"
    if auth.get("OPENAI_API_KEY"):
        return "apikey"
    return "unknown"


def codex_lineage_digest(home):
    """NON-SECRET digest of the refresh-token lineage bound in this slot.

    The access token rotates on every normal refresh (credential_digest
    changes), but the refresh token only changes on a fresh login — so a
    lineage change distinguishes "same login, refreshed" from "someone
    re-logged this account in somewhere" (a desktop re-login invalidating a
    seat on another machine). None when unreadable (callers hold)."""
    try:
        tokens = (paths.load_json(os.path.join(home, "auth.json"))
                  or {}).get("tokens") or {}
        refresh = tokens.get("refresh_token")
        return hashlib.sha256(refresh.encode()).hexdigest()[:16] \
            if refresh else None
    except (OSError, ValueError, AttributeError):
        return None


def codex_app_server_read(home, timeout=None):
    """Live Codex read via the codex app-server (`codex app-server`, JSON-RPC
    over stdio): real-time rate limits AND the network-verified logged-in
    account, both bound to this slot's CODEX_HOME. This replaces stale
    session-log scraping — Codex usage becomes as live as Claude's.

    Returns {"account": {...email, planType...}, "rate_limits": {...}} or
    raises IdentityBindingError."""
    import threading
    timeout = int(os.environ.get("HEADROOM_CODEX_APPSERVER_TIMEOUT", "25")) \
        if timeout is None else timeout
    binary = codex_bin()
    if not binary:
        raise IdentityBindingError("codex_cli_missing")
    env = scrubbed_env()
    env["CODEX_HOME"] = home
    try:
        proc = subprocess.Popen(
            [binary, "app-server"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            env=env, bufsize=1)
    except OSError as error:
        raise IdentityBindingError("codex_app_server_spawn_failed") from error
    stdin, stdout = proc.stdin, proc.stdout
    if stdin is None or stdout is None:
        raise IdentityBindingError("codex_app_server_spawn_failed")
    responses = {}

    def reader():
        for line in stdout:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue
            if isinstance(message, dict) and "id" in message:
                responses[message["id"]] = message

    threading.Thread(target=reader, daemon=True).start()

    def send(obj):
        stdin.write(json.dumps(obj) + "\n")
        stdin.flush()

    deadline = time.time() + timeout
    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"clientInfo": {"name": "headroom", "version": "0.1"}}})
        while 1 not in responses and time.time() < deadline:
            time.sleep(0.05)
        send({"jsonrpc": "2.0", "method": "initialized", "params": {}})
        send({"jsonrpc": "2.0", "id": 2,
              "method": "account/rateLimits/read", "params": {}})
        send({"jsonrpc": "2.0", "id": 3, "method": "account/read", "params": {}})
        while (2 not in responses or 3 not in responses) \
                and time.time() < deadline:
            time.sleep(0.05)
    except (OSError, ValueError):
        raise IdentityBindingError("codex_app_server_io_failed")
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except (subprocess.SubprocessError, OSError):
            proc.kill()
    if 2 not in responses or 3 not in responses:
        raise IdentityBindingError("codex_app_server_no_response")
    for request_id in (2, 3):
        error = responses[request_id].get("error")
        if error:
            # classify: auth rejection / throttle / protocol — each holds
            # distinctly and NONE may fall back to routable local telemetry
            raise IdentityBindingError(classify_codex_appserver_error(error))
    account = (responses[3].get("result") or {}).get("account") or {}
    result = responses[2].get("result") or {}
    # Prefer the canonical per-limit bucket; fall back to the backward-compatible
    # single-bucket view. Both carry primary/secondary RateLimitWindow objects.
    by_id = result.get("rateLimitsByLimitId") or {}
    rate_limits = by_id.get("codex") or result.get("rateLimits") or {}
    # Non-"codex" buckets are model-scoped limits (e.g. GPT-5.3-Codex-Spark);
    # carry them so codex_windows can surface each as a scoped:<name> row.
    scoped_limits = {lid: lim for lid, lim in by_id.items()
                     if lid != "codex" and isinstance(lim, dict)}
    return {"account": account, "rate_limits": rate_limits,
            "scoped_limits": scoped_limits}


def codex_window(window, now):
    """Map an app-server RateLimitWindow to a headroom usage window (live)."""
    if not isinstance(window, dict):
        return None
    used = window.get("usedPercent")
    if not isinstance(used, (int, float)) or isinstance(used, bool) \
            or not 0 <= used <= 100:
        return None
    return {
        "used_percent": float(used),
        "resets_at": iso_ep(window.get("resetsAt")),
        "window_minutes": window.get("windowDurationMins"),
        "observed_at": now,
        "freshness": "fresh",
    }


# The app-server reports each rate-limit window by its actual duration and OMITS
# any window that is not currently a constraint: a freshly reset 5-hour window at
# ~0% comes back as a null secondary, and the "primary" slot can then hold the
# weekly window instead. So we must NOT assume primary==5h / secondary==7d.
CODEX_STANDARD_WINDOWS = {300: "5h", 10080: "7d"}


def codex_scoped_window(bucket, now):
    """Map a model-scoped rate-limit bucket (e.g. GPT-5.3-Codex-Spark) to a
    ``(display_name, weekly-window)`` pair, or None when it carries no usable
    weekly reading. The bucket has the same shape as the codex bucket
    (primary/secondary RateLimitWindow) plus a ``limitName``; display_name is
    the limitName's trailing codename ("Spark"), not the full verbose string."""
    if not isinstance(bucket, dict):
        return None
    name = bucket.get("limitName")
    # limitName MUST be a non-empty string: a truthy non-str (e.g. the int 5)
    # would pass a bare `if not name` and then blow up on "scoped:" + name,
    # holding the WHOLE codex seat via collect()'s outer except. Guard the type.
    if not isinstance(name, str) or not name:
        return None
    # OpenAI reports a verbose scoped limit name ("GPT-5.3-Codex-Spark"); show
    # only the trailing model codename ("Spark") so the row reads like Claude's
    # short scoped labels ("Fable"). Assumes a single-word codename: a
    # hyphenated one keeps only its last segment, and two limits sharing a
    # codename would collide on one scoped:<codename> key (same latent
    # constraint Claude's already-short names carry).
    label = name.rsplit("-", 1)[-1]
    for slot in ("primary", "secondary"):
        mapped = codex_window(bucket.get(slot), now)
        if mapped and mapped.get("window_minutes") == 10080:
            return label, mapped
    return None


def codex_windows(rate_limits, now, scoped_limits=None):
    """Build headroom's usage windows from an app-server rate-limits payload,
    robust to the server reordering or omitting windows.

    Windows are bucketed by their real ``windowDurationMins`` rather than their
    primary/secondary position, and ONLY the windows the server actually
    reported are returned — an absent standard window is OMITTED, never
    synthesized as 0%. (OpenAI lifted the 5-hour limit in 2026-07: the codex
    bucket now reports the weekly window alone, and faking an absent 5h as 0%
    would invent capacity for a limit that no longer exists. validate_required_
    windows(require_5h=False) keeps the weekly mandatory for codex while
    tolerating the missing 5h.) An EMPTY or unrecognized payload proves nothing,
    so it raises and the seat is HELD.

    ``scoped_limits`` maps model-scoped buckets to their RateLimitWindow
    payloads; each usable one becomes a ``scoped:<name>`` weekly row, mirroring
    Claude's weekly_scoped handling so the dashboard renders it for free."""
    windows = {}
    for slot in ("primary", "secondary"):
        mapped = codex_window(rate_limits.get(slot), now)
        if mapped is None:
            continue
        key = CODEX_STANDARD_WINDOWS.get(mapped.get("window_minutes"))
        if key and key not in windows:
            windows[key] = mapped
    if not windows:
        raise IdentityBindingError("codex_capacity_unrecognized")
    for bucket in (scoped_limits or {}).values():
        entry = codex_scoped_window(bucket, now)
        if entry:
            name, window = entry
            windows["scoped:" + name] = window
    return windows


def codex_live(home, expected_email=None, now=None):
    """Full live Codex read: network-verified identity + real-time windows.
    account_fingerprint/credential come from the local id token (stable);
    email/plan/usage come live from the app-server."""
    now = int(time.time()) if now is None else now
    auth = paths.load_json(os.path.join(home, "auth.json"))
    if not auth:
        raise IdentityBindingError("codex_auth_missing")
    if codex_auth_mode(auth) == "apikey":
        # metered API-key seat: no subscription windows exist to route on
        raise IdentityBindingError("codex_capacity_unavailable")
    claims = decode_jwt_payload((auth.get("tokens") or {}).get("id_token"))
    provider_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = provider_claims.get("chatgpt_account_id") or claims.get("sub")
    read = codex_app_server_read(home)
    account = read["account"]
    email = account.get("email") or claims.get("email")
    if not email:
        raise IdentityBindingError("codex_identity_email_missing")
    if expected_email and email.lower() != expected_email.lower():
        raise IdentityBindingError("slot_bound_to_unexpected_email")
    plan_type = account.get("planType") or provider_claims.get("chatgpt_plan_type")
    rate_limits = read["rate_limits"]
    identity = {
        "verified": True,
        "email": email,
        "account_fingerprint": fingerprint(account_id),
        "method": "codex_app_server",
        "plan_type": plan_type,
        "credential_digest": credential_digest("codex", home),
        # lineage distinguishes a normal access refresh from a fresh login
        # (a fresh login elsewhere invalidates this seat — see route gate)
        "lineage_digest": codex_lineage_digest(home),
        "auth_mode": "chatgpt",
        "subscription": codex_subscription(provider_claims),
    }
    windows = codex_windows(rate_limits, now, read.get("scoped_limits"))
    return identity, plan_type, windows


def codex_identity(home, opener=open_authenticated):
    auth = paths.load_json(os.path.join(home, "auth.json"))
    if not auth:
        raise IdentityBindingError("codex_auth_missing")
    tokens = auth.get("tokens") or {}
    claims = decode_jwt_payload(tokens.get("id_token"))
    # An expired id_token still names the right identity (Codex refreshes
    # access tokens separately) — it lowers trust to local-only rather than
    # holding the slot, and the userinfo call below can re-verify live.
    expires = claims.get("exp")
    token_stale = isinstance(expires, (int, float)) \
        and expires < time.time() - 300
    provider_claims = claims.get("https://api.openai.com/auth") or {}
    record = {
        "verified": False,
        "email": claims.get("email"),
        "account_fingerprint": fingerprint(
            provider_claims.get("chatgpt_account_id") or claims.get("sub")
        ),
        "method": "openai_local_id_token_expired" if token_stale
                  else "openai_local_id_token",
        "plan_type": provider_claims.get("chatgpt_plan_type"),
        "subscription": codex_subscription(provider_claims),
    }
    try:
        request = urllib.request.Request(
            "https://auth.openai.com/oauth/userinfo",
            headers={"authorization": "Bearer " + tokens["access_token"]},
        )
        with opener(request, timeout=IDENTITY_TIMEOUT) as response:
            userinfo = json.load(response)
        if userinfo.get("sub") == claims.get("sub"):
            record["verified"] = True
            record["email"] = userinfo.get("email") or record["email"]
            record["method"] = "openai_userinfo"
    except (OSError, KeyError, ValueError, urllib.error.URLError):
        pass  # identity stays local-only; usage still reported, trust reduced
    if not record["email"]:
        raise IdentityBindingError("codex_identity_email_missing")
    return record


def codex_subscription(provider_claims, now=None):
    now = int(time.time()) if now is None else int(now)
    active_until = iso_ep(provider_claims.get("chatgpt_subscription_active_until"))
    checked_at = iso_ep(provider_claims.get("chatgpt_subscription_last_checked"))
    if (active_until is None or checked_at is None or checked_at > now + 300
            or active_until <= checked_at):
        return {"status": "unknown", "source": "provider_not_exposed"}
    return {
        "status": "active_through",
        "active_until": active_until,
        "checked_at": checked_at,
        "source": "openai_id_token_claim",
    }


# ------------------------------------------------------------------ limits

def limit_entry(limit, minutes):
    percent = limit.get("percent")
    if percent is not None:
        percent = float(percent)
        if not 0 <= percent <= 100:
            raise ValueError(f"usage percentage out of range: {percent}")
    return {
        "used_percent": None if percent is None else round(percent, 1),
        "resets_at": iso_ep(limit.get("resets_at")),
        "severity": limit.get("severity"),
        "is_active": limit.get("is_active"),
        "window_minutes": minutes,
    }


# Source-collector codes that mean the SEAT is held, not the reading. Only
# these travel through the ingest as their own hold; everything else the
# estate cron collector can stamp (its own deferrals, rate limits, transport
# errors) keeps the defer verdict because it is an absence of a reading that
# heals on the next collect. Each entry has a matching literal raise at the
# call site, which is what the classification test actually reads.
EXTERNAL_HELD_CODES = (
    "auth_rotated_out",               # IdentityBindingError("auth_rotated_out")
    "claude_identity_check_failed",   # IdentityBindingError("claude_identity_check_failed")
    "usage_http_401",                 # IdentityBindingError("usage_http_401")
    "usage_http_403",                 # IdentityBindingError("usage_http_403")
)


def _auth_resident(home):
    """The account whose credentials LIVE in this home right now, per the
    auth_resident@1 marker seat-auth-rotate.sh writes, or None when the home
    is unrotated. Mirrors ai-accounts/bin/collect.py so the two chains read
    ONE declaration. A malformed marker is no marker."""
    if not home:
        return None
    try:
        with open(os.path.join(home, "auth-resident.json")) as handle:
            marker = json.load(handle)
        if marker.get("schema") != "auth_resident@1":
            return None
        resident = marker.get("account")
        return resident if isinstance(resident, str) and resident else None
    except (OSError, ValueError, AttributeError):
        return None


def resident_homes(accounts):
    """slot name -> the ONE foreign home whose marker names that slot's
    account, for claude slots only. Two claimants is ambiguous and yields no
    entry, so the slot is read from its registry home as before.

    RESIDENCY (2026-08-17, steward, readings repair phase two). The estate
    moves an account's live credentials INTO another seat's home in place and
    leaves the origin home holding a parked stub. Reading the origin home then
    fails identity for the life of the rotation, and this chain reported that
    as usage_source_rate_limited (a lie: nothing was rate limited) while the
    widget showed the moved account's usage under the DONOR slot's label.
    Marker names are ai-accounts roster names, "claude-<slot>", so the slot
    key is derived by stripping that prefix."""
    claims = {}
    for row in accounts:
        if row.get("provider") != "claude":
            continue
        resident = _auth_resident(row.get("home"))
        if not resident or not resident.startswith("claude-"):
            continue
        slot = resident[len("claude-"):]
        if slot == row.get("name"):
            continue
        claims.setdefault(slot, []).append(row.get("home"))
    return {slot: homes[0] for slot, homes in claims.items() if len(homes) == 1}


def external_claude_limits(name, identity, now):
    """The estate cron collector's verdict for this slot: a three-way ruling.

    Returns ``(verdict, value)``:
      - ``("ingest", payload)`` — the cron pipeline has a fresh verified
        reading; ``payload`` has the same shape as :func:`claude_limits` so
        the caller's row assembly, trust derivation and window validation run
        unchanged. Served only when the external row's login email matches
        the identity bound in THIS slot's credential, so a reading can never
        cross accounts. No ``source_identity_fingerprint`` — org pinning
        stays with real API reads.
      - ``("defer", retry_at)`` — the cron pipeline is ALIVE but its reading
        for this slot is held/carryover/stale. Do NOT call the API: one held
        pipeline means the provider is throttling, and independent callers
        rushing the retry window is what re-trips it. The caller raises the
        throttle path with ``retry_at`` so headroom's own carryover keeps the
        last verified reading serviceable.
      - ``("native", None)`` — ingestion disabled, pipeline dead (snapshot
        missing or older than EXTERNAL_CLAUDE_PIPELINE_DEAD), the slot is
        untracked there, or the reading belongs to a different login. The
        native API path is the lawful fallback.
    """
    if not EXTERNAL_CLAUDE_SNAPSHOT:
        return ("native", None)
    try:
        with open(EXTERNAL_CLAUDE_SNAPSHOT) as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return ("native", None)
    rows = document.get("accounts") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        return ("native", None)
    generated = document.get("generated")
    if isinstance(generated, bool) \
            or not isinstance(generated, (int, float)) \
            or now - generated > EXTERNAL_CLAUDE_PIPELINE_DEAD \
            or generated > now + 60:
        return ("native", None)
    row = next((entry for entry in rows if isinstance(entry, dict)
                and entry.get("name") == "claude-" + name), None)
    if row is None or row.get("provider") != "claude":
        return ("native", None)

    def defer():
        retry_at = row.get("retry_at")
        if isinstance(retry_at, bool) \
                or not isinstance(retry_at, (int, float)) \
                or retry_at <= now:
            retry_at = now + 600
        return ("defer", int(retry_at))

    if row.get("ok") is not True or row.get("stale") is True \
            or row.get("throttle_carryover") is True:
        # HONEST REASONS (2026-08-17). A source row that is not ok because
        # its IDENTITY is held (logged out, rotated out, token refused) is
        # not a throttle, and calling it one made every credential outage in
        # the estate wear a rate-limit mask with a retry_at that re-minted
        # itself forever. Only rows the source itself marks as throttled or
        # stale/carried keep the defer verdict; identity-shaped codes travel
        # through as their own hold so the widget and router say what is
        # actually wrong.
        code = row.get("error_code")
        if row.get("ok") is not True and code in EXTERNAL_HELD_CODES:
            return ("held", code)
        if row.get("ok") is not True and code == "usage_unknown":
            # The estate declined to spend a provider call this run (its own
            # per-run budget), so there is no reading and no provider hold.
            # It is unreadable, and it says so under its own name rather
            # than wearing the rate-limit mask: route.py already classifies
            # usage_unknown as UNREADABLE (wait, do not disarm).
            return ("unknown", None)
        return defer()
    row_email = row.get("email")
    our_email = identity.get("email") if isinstance(identity, dict) else None
    if not isinstance(row_email, str) or not isinstance(our_email, str) \
            or row_email.lower() != our_email.lower():
        # a reading for a different login must not defer OR serve — only the
        # native path can establish this slot's own truth
        return ("native", None)
    captured = row.get("captured_at")
    if isinstance(captured, bool) or not isinstance(captured, (int, float)):
        return defer()
    if captured > now + 60 or now - captured > EXTERNAL_CLAUDE_MAX_AGE:
        return defer()
    raw_windows = row.get("windows")
    if not isinstance(raw_windows, dict):
        return defer()
    windows = {}
    for key, raw_window in raw_windows.items():
        if not isinstance(key, str) or not isinstance(raw_window, dict):
            continue
        used = raw_window.get("used_percent")
        if isinstance(used, bool) or not isinstance(used, (int, float)) \
                or not 0 <= used <= 100:
            continue
        window = dict(raw_window)
        window.setdefault("observed_at", int(captured))
        # VOCABULARY NORMALISATION — the bug Paul hunted for two days
        # (2026-08-08). The two collectors name model-scoped weekly windows
        # DIFFERENTLY: ai-accounts writes a bare model key ("fable",
        # collect.py:494 `{"5h":…, "7d":…, "fable": scoped.get("Fable")}`)
        # while headroom's native path and the widget contract use
        # "scoped:<Name>" (widget.py:204 passes through ONLY keys starting
        # "scoped:"). While headroom collected natively the widget showed a
        # FABLE row; the moment this ingest bridge landed (2026-08-07 12:58Z)
        # every Fable reading arrived under a key the projection silently
        # DROPS — so Paul's Fable gauges vanished estate-wide with the data
        # sitting right there in the snapshot. Normalise at the boundary,
        # which is the only place both vocabularies are known. Canonical
        # casing is restored from a known-model map so "fable" becomes
        # "scoped:Fable" (the exact string the widget and statusline read);
        # an unknown bare model is title-cased rather than dropped.
        if key not in ("5h", "7d") and not key.startswith("scoped:"):
            canonical = {"fable": "Fable", "opus": "Opus", "sonnet": "Sonnet",
                         "haiku": "Haiku", "spark": "Spark"}.get(
                             key.lower(), key[:1].upper() + key[1:])
            key = "scoped:" + canonical
        windows[key] = window
    try:
        validate_required_windows(windows)
    except Exception:  # noqa: BLE001 — malformed external data defers
        return defer()
    return ("ingest", {
        "captured_at": int(captured),
        "source": "ai_accounts_snapshot",
        "stale": False,
        "windows": windows,
    })


def external_codex_limits(name, expected_email, now):
    """The estate cron collector's codex reading for this slot, or a refusal.

    Mirror of external_claude_limits for codex seats (2026-08-08). Same
    fail-closed discipline: the row must exist, be ok, be fresh, and be bound
    to the SAME login we expect — an unverifiable row returns ("native", None)
    so the live app-server path decides, never a silent wrong number."""
    if not EXTERNAL_CLAUDE_SNAPSHOT:
        return ("native", None)
    try:
        with open(EXTERNAL_CLAUDE_SNAPSHOT) as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return ("native", None)
    rows = payload.get("accounts") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return ("native", None)
    row = next((entry for entry in rows if isinstance(entry, dict)
                and entry.get("name") == name), None)
    if row is None or row.get("provider") != "codex" or row.get("ok") is not True:
        return ("native", None)
    row_email = row.get("email")
    if expected_email and (not isinstance(row_email, str)
                           or row_email.lower() != str(expected_email).lower()):
        return ("native", None)
    captured = row.get("captured_at")
    if isinstance(captured, bool) or not isinstance(captured, (int, float)):
        return ("native", None)
    if captured > now + 60 or now - captured > EXTERNAL_CLAUDE_MAX_AGE:
        return ("native", None)
    raw_windows = row.get("windows")
    if not isinstance(raw_windows, dict) or not raw_windows:
        return ("native", None)
    windows = {}
    for key, raw_window in raw_windows.items():
        if not isinstance(key, str) or not isinstance(raw_window, dict):
            continue
        used = raw_window.get("used_percent")
        if isinstance(used, bool) or not isinstance(used, (int, float)) \
                or not 0 <= used <= 100:
            continue
        window = dict(raw_window)
        window.setdefault("observed_at", int(captured))
        if key not in ("5h", "7d") and not key.startswith("scoped:"):
            key = "scoped:" + (key[:1].upper() + key[1:])
        windows[key] = window
    try:
        validate_required_windows(windows, require_5h=False)
    except Exception:  # noqa: BLE001 — malformed external data falls back
        return ("native", None)
    value = {
        "captured_at": int(captured),
        "source": "ai_accounts_snapshot",
        "stale": False,
        "windows": windows,
        "identity_verified": True,
        "identity_method": "ai_accounts_snapshot",
        "email": row_email,
    }
    for key in ("identity", "subscription", "plan"):
        if row.get(key) is not None:
            value[key] = row[key]
    return ("ingest", value)


def claude_limits(home, expected_fingerprint, opener=open_authenticated):
    oauth = claude_oauth(home) or {}
    if not oauth.get("accessToken"):
        raise IdentityBindingError("claude_credentials_missing")
    # The CACHED access token may have expired since the CLI last refreshed
    # it (headroom never refreshes credentials itself — racing the CLI's own
    # rotation could invalidate its session). An expired token would 401
    # below and read as an opaque collector error; hold with an actionable
    # code instead. expiresAt is milliseconds in current CLI builds — accept
    # a plain-seconds value too, so a unit change can never mark every fresh
    # token as expired.
    expires_at = oauth.get("expiresAt")
    if isinstance(expires_at, (int, float)) and not isinstance(expires_at, bool):
        expires_epoch = expires_at / 1000.0 if expires_at > 1e11 else expires_at
        if expires_epoch <= time.time():
            raise IdentityBindingError("claude_usage_token_expired")
    request = urllib.request.Request(
        "https://api.anthropic.com/api/oauth/usage",
        headers={
            "authorization": "Bearer " + oauth["accessToken"],
            "anthropic-beta": "oauth-2025-04-20",
            "anthropic-version": "2023-06-01",
        },
    )
    try:
        response = opener(request, timeout=30)
    except urllib.error.HTTPError as error:
        if error.code == 429:
            raise ProviderThrottleError(
                retry_after_epoch(error.headers), provider_response=True
            ) from error
        if error.code in (401, 403):
            # auth rejection is not capacity and not a rate limit: hold the
            # slot with a distinct, actionable code instead of letting a raw
            # HTTPError surface as a generic collector error
            raise IdentityBindingError("claude_usage_token_rejected") from error
        raise
    with response:
        response_org = response.headers.get("anthropic-organization-id")
        response_fingerprint = fingerprint(response_org) if response_org else None
        # The usage org can legitimately differ from the login's default org
        # (multi-org accounts), so binding is trust-on-first-use per slot:
        # the caller pins this fingerprint and holds the slot if it CHANGES.
        # Once pinned, a response with NO org header can't be verified against
        # the pin, so it must hold rather than silently accept.
        # require the org header on EVERY response (including the first, before
        # any pin) — without it the usage can't be bound to the login at all
        if not response_fingerprint:
            raise IdentityBindingError("claude_usage_org_unverifiable")
        if (expected_fingerprint
                and response_fingerprint != expected_fingerprint):
            raise IdentityBindingError("claude_usage_org_changed")
        data = json.load(response)
    session = weekly = None
    scoped = {}
    for limit in data.get("limits") or []:
        kind = limit.get("kind")
        if kind == "session":
            session = limit_entry(limit, 300)
        elif kind == "weekly_all":
            weekly = limit_entry(limit, 10080)
        elif kind == "weekly_scoped":
            name = (((limit.get("scope") or {}).get("model") or {})
                    .get("display_name")) or "Scoped"
            scoped[name] = limit_entry(limit, 10080)
    if session is None and isinstance(data.get("five_hour"), dict) \
            and data["five_hour"].get("utilization") is not None:
        session = {"used_percent": round(float(data["five_hour"]["utilization"]), 1),
                   "resets_at": iso_ep(data["five_hour"].get("resets_at")),
                   "window_minutes": 300}
    if weekly is None and isinstance(data.get("seven_day"), dict) \
            and data["seven_day"].get("utilization") is not None:
        weekly = {"used_percent": round(float(data["seven_day"]["utilization"]), 1),
                  "resets_at": iso_ep(data["seven_day"].get("resets_at")),
                  "window_minutes": 10080}
    windows = {"5h": session, "7d": weekly}
    for name, window in scoped.items():
        windows["scoped:" + name] = window
    return {
        "captured_at": int(time.time()),
        "source": "anthropic_usage_api",
        "source_identity_fingerprint": response_fingerprint,
        "stale": False,
        "windows": windows,
    }


def _find_rate_limits(value):
    if isinstance(value, dict):
        limits = value.get("rate_limits")
        if isinstance(limits, dict):
            return limits
        for child in value.values():
            found = _find_rate_limits(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_rate_limits(child)
            if found:
                return found
    return None


def codex_limits(home, now=None):
    now = time.time() if now is None else now
    files = glob.glob(os.path.join(home, "sessions", "2*", "*", "*", "*.jsonl"))
    if not files:
        return {"note": "no Codex telemetry yet — run one Codex turn on this account"}
    files.sort(key=os.path.getmtime, reverse=True)
    newest = None
    for path in files[:15]:
        file_mtime = int(os.path.getmtime(path))
        try:
            with open(path, "rb") as raw:
                # bound the scan: only the tail of each session log
                raw.seek(max(0, os.fstat(raw.fileno()).st_size - 512 * 1024))
                tail = raw.read().decode("utf-8", errors="ignore")
            for line_number, line in enumerate(tail.splitlines()):
                if '"rate_limits"' not in line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                limits = _find_rate_limits(event)
                if not limits or not isinstance(limits.get("primary"), dict) \
                        and not isinstance(limits.get("secondary"), dict):
                    continue
                event_ts = iso_ep(event.get("timestamp"))
                # the event's OWN timestamp attests when the provider observed
                # the limit; file mtime only locates the log. Without a real
                # timestamp we can order candidates but must not call it fresh.
                captured_at = event_ts if event_ts is not None else file_mtime
                if captured_at > now + 300:
                    captured_at = file_mtime
                order = (captured_at, file_mtime, path, line_number)
                if newest is None or order > newest[0]:
                    newest = (order, captured_at, limits, event_ts is not None)
        except OSError:
            continue
    if newest is None:
        return {"note": "no rate_limits event in recent Codex sessions"}
    _, captured_at, limits, has_timestamp = newest
    stale = (not has_timestamp) or (now - captured_at) > CODEX_STALE_AFTER

    def window(key):
        value = limits.get(key) or {}
        used = value.get("used_percent")
        if used is not None:
            used = float(used)
            if not 0 <= used <= 100:
                raise ValueError(f"Codex {key} percentage out of range: {used}")
        reset = iso_ep(value.get("resets_at"))
        result = {
            "used_percent": used,
            "window_minutes": value.get("window_minutes"),
            "resets_at": reset,
            "observed_at": captured_at,
        }
        if stale and reset is not None and reset <= now:
            result["last_observed_used_percent"] = used
            result["used_percent"] = None
            result["freshness"] = "expired_observation"
        else:
            result["freshness"] = "stale_observation" if stale else "fresh"
        return result

    return {
        "captured_at": captured_at,
        "source": "codex_session_telemetry",
        "stale": stale,
        "windows": {"5h": window("primary"), "7d": window("secondary")},
        "plan_type": limits.get("plan_type"),
    }


# ---------------------------------------------------------------- snapshot

def validate_required_windows(windows, require_5h=True):
    # codex passes require_5h=False: OpenAI lifted the 5h limit, so a codex
    # seat legitimately reports only the weekly window (see codex_windows).
    for key in (("5h", "7d") if require_5h else ("7d",)):
        window = windows.get(key)
        if not isinstance(window, dict):
            raise ValueError(f"missing required {key} usage window")
        if window.get("used_percent") is None \
                and window.get("freshness") != "expired_observation":
            raise ValueError(f"missing required {key} usage window")
        if window.get("freshness") == "expired_observation":
            continue
        percent = window["used_percent"]
        if not isinstance(percent, (int, float)) or not 0 <= percent <= 100:
            raise ValueError(f"invalid {key} usage percentage")


def empty_backoff():
    return {"schema_version": 1, "providers": {}}


def persist_provider_backoff(provider, retry_at):
    """Record a provider-wide backoff (e.g. codex app-server overload seen at
    launch time) in the shared ledger honoured by later collect runs. Backoff
    is a PROVIDER state, never an account cooldown. No secrets stored."""
    document = paths.load_json(paths.backoff_path())
    if not isinstance(document, dict):
        document = empty_backoff()
    document.setdefault("providers", {})[provider] = {
        "retry_at": int(retry_at),
        "observed_at": min(int(time.time()), int(retry_at) - 1),
    }
    paths.write_json_atomic(paths.backoff_path(), document)


def active_backoff(document, provider, now):
    if not isinstance(document, dict):
        return 0
    entry = (document.get("providers") or {}).get(provider) or {}
    retry_at = entry.get("retry_at", 0)
    if not isinstance(retry_at, (int, float)) or isinstance(retry_at, bool) \
            or not math.isfinite(retry_at):
        return 0
    return int(retry_at) if retry_at > now else 0


def apply_integrity(accounts):
    """Trust states + duplicate-identity detection across the fleet."""
    fingerprints = {}
    warnings = []
    for result in accounts:
        identity = result.get("identity") or {}
        if result.get("trust_state") == "dashboard_only":
            # codex display-only telemetry: visible on the dashboard, never
            # routable — keep the explicit state instead of a generic "held"
            result["routable"] = False
        elif not result.get("ok"):
            result["trust_state"] = "held"
        elif result.get("stale"):
            result["trust_state"] = "stale_observation"
        elif identity.get("verified"):
            result["trust_state"] = "verified"
        else:
            result["trust_state"] = "verified_local"
        result["routable"] = result["trust_state"] in ("verified", "verified_local")

        key = (result.get("provider"), identity.get("account_fingerprint"))
        # A DECLARED donor slot is not a duplicate login (2026-08-17). When a
        # home is auth-rotated, its slot row is held as auth_rotated_out and
        # its identity read reports the RESIDENT account, so it shares a
        # fingerprint with the resident's own row by construction. That is
        # the declared state, not a stolen login, and stamping both rows
        # duplicate_identity de-routed the one healthy account in the pair.
        # A held slot has already lost routing; it must not also veto the
        # account whose credentials it lawfully holds.
        if key[1] and result.get("error_code") != "auth_rotated_out":
            if key in fingerprints:
                other = fingerprints[key]
                for account in (other, result):
                    account["trust_state"] = "duplicate_identity"
                    account["routable"] = False
                warnings.append(
                    f"duplicate {key[0]} identity: {other['name']} and "
                    f"{result['name']} are the same login; routing held"
                )
            else:
                fingerprints[key] = result
    return warnings


def _throttle_carryover(previous, account, now, fresh_identity):
    """The account's row from the previous snapshot, if it is still a live,
    verified, in-age reading worth serving through a usage-source throttle.

    A 429 from the usage endpoint says the METER is busy, not that capacity
    changed — so the last verified reading keeps the slot routable instead of
    stranding launches (every consumer still age-bounds it via captured_at
    against OBSERVATION_MAX_AGE, so this can never outlive a real reading's
    normal service window). Returns a copy, or None (fail-closed) when the
    previous row is anything less than a fresh verified success — including
    when the slot's CURRENT identity/credential binding (read locally moments
    ago, no network) no longer matches the old row: a relogged slot must
    never republish the prior identity's reading."""
    rows = previous.get("accounts") if isinstance(previous, dict) else None
    if not isinstance(rows, list):
        return None
    row = next((entry for entry in rows if isinstance(entry, dict)
                and entry.get("name") == account["name"]), None)
    if row is None or row.get("ok") is not True \
            or row.get("routable") is not True:
        return None
    if row.get("provider") != account.get("provider"):
        return None
    if row.get("trust_state") not in ("verified", "verified_local"):
        return None
    old_identity = row.get("identity")
    old_identity = old_identity if isinstance(old_identity, dict) else {}
    fresh_identity = fresh_identity if isinstance(fresh_identity, dict) else {}
    for key in ("account_fingerprint", "credential_digest"):
        if not old_identity.get(key) or not fresh_identity.get(key) \
                or old_identity[key] != fresh_identity[key]:
            return None
    captured = row.get("captured_at")
    if isinstance(captured, bool) or not isinstance(captured, (int, float)):
        return None
    if captured > now or now - captured > OBSERVATION_MAX_AGE:
        return None
    return json.loads(json.dumps(row))


def collect(accounts, backoff=None, persist_backoff=None, previous=None):
    now = int(time.time())
    backoff = empty_backoff() if backoff is None else backoff
    claude_backoff_until = active_backoff(backoff, "anthropic_usage_api", now)
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "run_id": uuid.uuid4().hex,
        "run_started": now,
        "generated": None,
        "generated_iso": None,
        "accounts": [],
    }
    _resident = resident_homes(accounts)
    for account in accounts:
        result = {"id": account.get("id"), "name": account["name"],
                  "provider": account["provider"]}
        try:
            if account["provider"] == "claude":
                read_home = _resident.get(account["name"], account["home"])
                if read_home != account["home"]:
                    result["read_home_resident"] = True
                identity = claude_identity(read_home)
                identity["credential_digest"] = credential_digest(
                    "claude", read_home)
                result["identity"] = identity
                result["identity_verified"] = identity["verified"]
                result["identity_method"] = identity["method"]
                result["email"] = identity["email"]
                result["plan"] = claude_plan(account["home"]) or "Unknown"
                result["subscription"] = {"status": "unknown",
                                          "source": "provider_not_exposed"}
                expected = account.get("expected_email")
                if expected and identity["email"] \
                        and identity["email"].lower() != expected.lower():
                    # AUTH-ROTATED HOMES ARE NOT BREACHES (2026-08-17, mirror
                    # of ai-accounts collect.py). When this slot's own home
                    # carries a marker naming a DIFFERENT roster account, the
                    # unexpected email is the declared resident and the slot
                    # is honestly parked, not stolen. Held, not routable, and
                    # never entered in the duplicate-fingerprint map, so the
                    # resident account's own row is not de-routed by it.
                    declared = _auth_resident(account["home"])
                    if declared and declared != "claude-" + account["name"]:
                        raise IdentityBindingError("auth_rotated_out")
                    raise IdentityBindingError("slot_bound_to_unexpected_email")
                # the estate cron collector's verdict rules this slot: a
                # fresh reading serves without touching the usage API (a file
                # read works straight through a provider backoff window), a
                # held pipeline DEFERS (calling into the provider's retry
                # window from a second process is what re-trips it), and only
                # a dead pipeline unlocks the native API path
                verdict, value = external_claude_limits(account["name"],
                                                        identity, now)
                if verdict == "ingest":
                    result.update(value)
                elif verdict == "defer":
                    raise ProviderThrottleError(value)
                elif verdict == "unknown":
                    raise UsageUnknown()
                elif verdict == "held":
                    # One literal raise per code the ingest can pass through,
                    # so the AST-walking classification test in
                    # tests/test_headroom.py sees each one and route.py has to
                    # classify it. A raise of the variable would be invisible
                    # to that test and let a new source code slip past.
                    if value == "auth_rotated_out":
                        raise IdentityBindingError("auth_rotated_out")
                    if value == "claude_identity_check_failed":
                        raise IdentityBindingError("claude_identity_check_failed")
                    # A 401 or 403 from the usage endpoint is the provider
                    # refusing the CREDENTIAL, a standing fact that only a
                    # re-login cures. Not a throttle: claude-ops sat behind a
                    # 403 wall from 2026-08-15 while every surface called it
                    # rate-limited and waited for a retry that could not come.
                    if value == "usage_http_401":
                        raise IdentityBindingError("usage_http_401")
                    if value == "usage_http_403":
                        raise IdentityBindingError("usage_http_403")
                    raise IdentityBindingError(value)
                else:
                    if claude_backoff_until > now:
                        raise ProviderThrottleError(claude_backoff_until)
                    result.update(claude_limits(
                        read_home, account.get("pinned_usage_org")))
                if not account.get("pinned_usage_org") \
                        and result.get("source_identity_fingerprint"):
                    # trust-on-first-use: remember which org this slot's
                    # usage feed belongs to; a later change means the login
                    # underneath was swapped and the slot must be held
                    result["pin_usage_org"] = result["source_identity_fingerprint"]
                validate_required_windows(result["windows"])
                result["ok"] = True
            else:
                expected = account.get("expected_email")
                # SAME SINGLE-CALLER RULE AS CLAUDE (2026-08-08). The estate
                # cron reads every codex seat successfully via its own
                # app-server call; headroom making a SECOND independent call
                # buys nothing and, while the app-server is in backoff, left
                # Paul's widget showing codex seats "stale" for hours with
                # correct numbers sitting one file away (measured: collector
                # ok=True at 4%/62% weekly while the widget carried 1h34m-old
                # values). Ingest the cron's reading first; the live path below
                # remains the automatic fallback whenever the ingest is
                # missing, stale, or fails any check.
                codex_verdict, codex_value = external_codex_limits(
                    account["name"], expected, now)
                if codex_verdict == "ingest":
                    result.update(codex_value)
                    result["ok"] = True
                    snapshot["accounts"].append(result)
                    continue
                codex_retry_at = active_backoff(backoff, "codex_app_server", now)
                if codex_retry_at:
                    # transient app-server overload holds the seat; it never
                    # becomes "available", and we don't hammer the server
                    result["ok"] = False
                    result["error_code"] = "codex_provider_backoff"
                    result["retry_at"] = codex_retry_at
                    result["note"] = ("codex app-server in provider backoff; "
                                      "seat held until the retry window")
                    snapshot["accounts"].append(result)
                    continue
                try:
                    # PRIMARY: live, identity-bound read via the codex app-server
                    identity, plan_type, windows = codex_live(
                        account["home"], expected, now)
                    result["identity"] = identity
                    result["identity_verified"] = True
                    result["identity_method"] = identity["method"]
                    result["email"] = identity["email"]
                    result["subscription"] = identity.get("subscription")
                    result["source"] = "codex_app_server"
                    result["stale"] = False
                    result["captured_at"] = now
                    result["windows"] = windows
                    result["plan"] = {
                        "pro": "ChatGPT Pro", "plus": "ChatGPT Plus",
                        "prolite": "ChatGPT Pro Lite", "free": "Free",
                    }.get(str(plan_type or ""), plan_type or "Unknown")
                    validate_required_windows(result["windows"],
                                              require_5h=False)
                    result["ok"] = True
                except IdentityBindingError as app_error:
                    code = str(app_error.code)
                    if code == "codex_app_server_throttled":
                        # overload/throttle: provider-wide backoff, seat held
                        # as transient — NOT an auth or capacity signal
                        retry_at = now + 300
                        if persist_backoff is not None:
                            persist_backoff(retry_at, "codex_app_server")
                        result["ok"] = False
                        result["error_code"] = code
                        result["retry_at"] = retry_at
                        result["note"] = (
                            "codex app-server overloaded/throttled; seat "
                            "held (transient — not a capacity signal)")
                        snapshot["accounts"].append(result)
                        continue
                    if code not in CODEX_DASHBOARD_FALLBACK_CODES:
                        # explicit auth rejection, protocol/malformed error,
                        # apikey seat, unrecognized capacity: NEVER fall back
                        # to local telemetry — hold with the distinct code
                        raise
                    # DISPLAY-ONLY fallback for an unavailable app-server
                    # (older Codex CLI): session-log telemetry can be stale
                    # and proves nothing live, so it is never routable.
                    identity = codex_identity(account["home"])
                    identity["credential_digest"] = credential_digest(
                        "codex", account["home"])
                    identity["lineage_digest"] = codex_lineage_digest(
                        account["home"])
                    result["identity"] = identity
                    result["identity_verified"] = identity["verified"]
                    result["identity_method"] = identity["method"]
                    result["email"] = identity["email"]
                    result["subscription"] = identity.get("subscription")
                    if expected and identity["email"].lower() != expected.lower():
                        raise IdentityBindingError("slot_bound_to_unexpected_email")
                    telemetry = codex_limits(account["home"], now=now)
                    plan_type = str(telemetry.pop("plan_type", None)
                                    or identity.get("plan_type") or "")
                    result["plan"] = {
                        "pro": "ChatGPT Pro", "plus": "ChatGPT Plus",
                        "prolite": "ChatGPT Pro Lite", "free": "Free",
                    }.get(plan_type, plan_type or "Unknown")
                    result.update(telemetry)
                    result["ok"] = False
                    result["error_code"] = "codex_dashboard_only"
                    result["routable"] = False
                    result["trust_state"] = "dashboard_only"
                    result["note"] = (
                        "codex app-server unavailable — session-log telemetry "
                        "is display-only; seat not capacity-routable")
        except UsageUnknown:
            carried = _throttle_carryover(previous, account, now,
                                          result.get("identity"))
            if carried is not None:
                result = carried
                result["throttle_carryover"] = True
                result["note"] = ("no fresh reading this run (the estate "
                                  "held its provider call); serving the "
                                  "last verified reading")
            else:
                result["ok"] = False
                result["error_code"] = "usage_unknown"
                result["note"] = ("no fresh reading this run: the estate "
                                  "held its provider call and nothing is "
                                  "carried")
        except ProviderThrottleError as error:
            claude_backoff_until = max(claude_backoff_until, error.retry_at)
            if error.provider_response and persist_backoff is not None:
                persist_backoff(claude_backoff_until)
            carried = _throttle_carryover(previous, account, now,
                                          result.get("identity"))
            if carried is not None:
                # the rate-limit CHECK being rate-limited is not evidence of
                # missing capacity: keep serving the last verified reading
                # (age-bounded everywhere) instead of holding the slot
                result = carried
                result["throttle_carryover"] = True
                result["retry_at"] = error.retry_at
                result["note"] = ("usage source rate-limited; serving the "
                                  "last verified reading until the provider "
                                  "retry window")
            else:
                result["ok"] = False
                result["error_code"] = "usage_source_rate_limited"
                result["retry_at"] = error.retry_at
                result["note"] = ("usage source temporarily rate-limited; "
                                  "account held until provider retry window")
        except IdentityBindingError as error:
            result["ok"] = False
            result["error_code"] = error.code
            if error.code in CODEX_HOLD_NOTES:
                result["note"] = CODEX_HOLD_NOTES[error.code]
            elif error.code in ("claude_usage_token_expired",
                                "claude_usage_token_rejected"):
                what = ("has expired" if error.code.endswith("expired")
                        else "was rejected by the usage API (expired or "
                             "revoked)")
                result["note"] = (
                    f"cached Claude token {what} — headroom never refreshes "
                    "credentials itself. Run one Claude Code turn on this "
                    "account (the CLI refreshes its token) or `headroom auth "
                    f"refresh {account['name']}` to re-login; readings held "
                    "until then.")
            elif error.code == "auth_rotated_out":
                result["note"] = ("auth-rotated by declaration: this seat's "
                                  "credentials currently serve another "
                                  "account; not a re-auth condition")
            elif error.code == "claude_identity_check_failed":
                result["note"] = ("the Claude login in this seat cannot be "
                                  "verified (logged out or parked); sign in "
                                  "again on this seat")
            elif error.code in ("usage_http_401", "usage_http_403"):
                result["note"] = ("the usage endpoint refused this seat's "
                                  "credential (HTTP %s); re-authenticate on "
                                  "this seat, waiting will not clear it"
                                  % error.code[-3:])
            elif error.code == "claude_credentials_missing":
                # verified identity but the token couldn't be read. On macOS the
                # token is in the login Keychain (headroom reads it via
                # `security`) — this path means the Keychain was locked or the
                # item name differs; elsewhere it means no file-based login yet.
                result["note"] = ("Claude login found but its token could not "
                                  "be read. On macOS unlock the login Keychain "
                                  "and allow `security` access when prompted "
                                  "(set HEADROOM_CLAUDE_KEYCHAIN_SERVICE if your "
                                  "CLI uses a different item name); on "
                                  "Linux/Windows run `headroom auth refresh "
                                  f"{account['name']}` to log in.")
            else:
                result["note"] = ("identity could not be bound to this slot; "
                                  "account held — run `headroom connect` "
                                  "to re-login")
        except Exception as error:  # noqa: BLE001 — every account must report
            result["ok"] = False
            # `error` is PRIVATE-only (may contain local paths / usernames).
            # `note` is published, so it must stay generic.
            result["error"] = type(error).__name__ + ": " + str(error)[:120]
            result["note"] = "collector error; see private snapshot for detail"
        snapshot["accounts"].append(result)
    snapshot["integrity_warnings"] = apply_integrity(snapshot["accounts"])
    completed = int(time.time())
    snapshot["generated"] = completed
    snapshot["generated_iso"] = datetime.fromtimestamp(
        completed, timezone.utc
    ).isoformat().replace("+00:00", "Z")
    return snapshot


def redact_email(address):
    if not address:
        return address
    if "@" not in address:
        return "***"  # redaction must never pass an unrecognized value through
    local, _, domain = address.partition("@")
    return (local[0] if local else "") + "***@" + domain


SESSION_TRUTH_DIR = "/home/paulsportsza/ai-accounts/state/session-truth"


def _fold_session_truth(row):
    """2026-08-11 usage-truth unification (census item 0, Paul's ruling that
    the widget and statusline must never disagree): a live session's provider
    rate_limits headers, teed per account by the statusline, are ground truth
    and beat any collector carry. Newest-wins per row, snapshots older than
    30 minutes prove nothing, and total failure of this fold must never
    break a projection."""
    try:
        name = str(row.get("name") or "")
        truth = None
        for cand in (name, "claude-" + name):
            tp = os.path.join(SESSION_TRUTH_DIR, cand + ".json")
            if os.path.exists(tp):
                with open(tp) as fh:
                    truth = json.load(fh)
                break
        if not truth:
            return row
        t_cap = float(truth.get("captured_at") or 0)
        if t_cap <= float(row.get("captured_at") or 0):
            return row
        if time.time() - t_cap > 1800:
            return row
        wins = row.setdefault("windows", {})
        changed = False
        for key in ("5h", "7d"):
            t_w = (truth.get("windows") or {}).get(key) or {}
            if t_w.get("used_percent") is None:
                continue
            d_w = wins.setdefault(key, {})
            d_w["used_percent"] = float(t_w["used_percent"])
            if t_w.get("resets_at"):
                d_w["resets_at"] = float(t_w["resets_at"])
            changed = True
        if changed:
            row["captured_at"] = int(t_cap)
            row["truth_source"] = "session_header"
            row["stale"] = False
    except Exception:
        pass
    return row


def public_snapshot(snapshot, redact_emails=False):
    accounts = []
    for account in snapshot["accounts"]:
        public = {k: v for k, v in account.items() if k in PUBLIC_FIELDS}
        if account.get("error"):
            # never publish raw exception text, whatever `note` already holds
            public["note"] = "collector error; see private snapshot"
        if redact_emails:
            public["email"] = redact_email(public.get("email"))
        accounts.append(_fold_session_truth(public))
    return {
        "schema_version": snapshot["schema_version"],
        "run_id": snapshot["run_id"],
        "generated": snapshot["generated"],
        "generated_iso": snapshot["generated_iso"],
        "integrity_warnings": snapshot.get("integrity_warnings", []),
        "accounts": accounts,
    }


@contextlib.contextmanager
def collection_lock(blocking=True):
    """Serialize collection with commands that remove collection state.

    A nonblocking collector skips rather than queues behind another collector;
    destructive state changes wait so a collector can never republish a slot
    after it was removed.
    """
    lock_path = paths.collect_lock_path()
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    with open(lock_path, "a+") as lock:
        if not locks.exclusive(lock, blocking=blocking):
            yield False
            return
        try:
            yield True
        finally:
            locks.unlock(lock)


def _run_token_scan(scan):
    try:
        scan()
    except Exception as error:  # token telemetry must never break collection
        try:
            print(f"headroom: token stats scan failed: {error}",
                  file=sys.stderr)
        except Exception:
            pass


def _trigger_token_scan(synchronous):
    """Run CLI-owned scans inline; dashboard-owned scans are daemon work."""
    scan = tokens.collect
    if synchronous:
        _run_token_scan(scan)
        return None
    try:
        worker = threading.Thread(
            target=_run_token_scan, args=(scan,),
            name="headroom-token-scan", daemon=True)
        worker.start()
        return worker
    except Exception as error:  # thread startup is optional and fail-safe
        try:
            print(f"headroom: token stats scan failed: {error}",
                  file=sys.stderr)
        except Exception:
            pass
        return None


def run_collect(quiet=False):
    """Full collect run: lock, read, write both snapshots. Returns snapshot."""
    with collection_lock(blocking=False) as locked:
        if not locked:
            # A SKIP, returned as the previous run's snapshot: no exception and
            # no sentinel, so a caller that needs a reading NEWER than some
            # event cannot tell this apart from a successful run except by
            # `run_started`. supervisor._fresh_collect infers exactly that and
            # retries; keep `run_started` in the snapshot, or that inference
            # silently degrades. (It degrades SAFE — every read looks contended
            # and the cap path holds instead of disarming — but it degrades.)
            if not quiet:
                print("collector already running; skipped")
            return paths.load_json(paths.private_snapshot_path())
        # Load only after the collection lock: a concurrent remove must not
        # race a stale registry into a freshly written snapshot.
        config = registry.load()
        backoff = paths.load_json(paths.backoff_path()) or empty_backoff()

        def persist(retry_at, provider="anthropic_usage_api"):
            backoff.setdefault("providers", {})[provider] = {
                "retry_at": int(retry_at),
                "observed_at": min(int(time.time()), int(retry_at) - 1),
            }
            paths.write_json_atomic(paths.backoff_path(), backoff)

        previous = paths.load_json(paths.private_snapshot_path())
        snapshot = collect(registry.accounts(config), backoff, persist,
                           previous=previous)
        pins = {a["name"]: a.pop("pin_usage_org")
                for a in snapshot["accounts"] if a.get("pin_usage_org")}
        # Merge pins and backfill IDs under the config lock against the LATEST
        # registry, so concurrent account additions are preserved. The returned
        # view is also the authority for this collection's live history IDs.
        live_accounts = registry.apply_pins(pins)
        live_by_name = {account["name"]: account["id"]
                        for account in live_accounts}
        for account in snapshot["accounts"]:
            if account["name"] in live_by_name:
                account["id"] = live_by_name[account["name"]]
        # carryover rows count as throttled for the backoff ledger: only a
        # run with NO throttle evidence at all may clear the provider backoff
        if any(a.get("provider") == "claude" and a.get("ok")
               for a in snapshot["accounts"]) \
                and not any(a.get("error_code") == "usage_source_rate_limited"
                            or a.get("throttle_carryover")
                            for a in snapshot["accounts"]):
            (backoff.get("providers") or {}).pop("anthropic_usage_api", None)
            paths.write_json_atomic(paths.backoff_path(), backoff)
        paths.write_json_atomic(paths.private_snapshot_path(), snapshot)
        # reload settings fresh (not the config loaded at collect start) so a
        # redaction change made mid-collect governs the published projection,
        # and default to redacted if unset
        settings = registry.dashboard_settings()
        public = public_snapshot(snapshot, settings.get("redact_emails", True))
        paths.write_json_atomic(
            paths.public_snapshot_path(),
            public,
            mode=0o644,
        )
        try:
            history.append_snapshot(
                public,
                live_ids={account["id"] for account in live_accounts},
            )
        except Exception as error:  # history must never break collection
            try:
                print(f"headroom: history append failed: {error}",
                      file=sys.stderr)
            except Exception:
                pass
    if not quiet:
        print_snapshot(snapshot)
    return snapshot


def _warning_mentions_slot(warning, name):
    """Whether an integrity-warning name token refers to this exact slot."""
    return (isinstance(warning, str)
            and name in re.findall(r"[a-z0-9_-]+", warning))


def _prune_snapshot_slot(snapshot, name):
    """Remove only one slot's rows and duplicate warning references in-place."""
    if not isinstance(snapshot, dict):
        return False
    changed = False
    accounts = snapshot.get("accounts")
    if isinstance(accounts, list):
        kept = [row for row in accounts
                if not (isinstance(row, dict) and row.get("name") == name)]
        if len(kept) != len(accounts):
            snapshot["accounts"] = kept
            changed = True
    warnings = snapshot.get("integrity_warnings")
    if isinstance(warnings, list):
        kept = [warning for warning in warnings
                if not _warning_mentions_slot(warning, name)]
        if len(kept) != len(warnings):
            snapshot["integrity_warnings"] = kept
            changed = True
    return changed


def _load_snapshot_for_removal(path):
    snapshot = paths.load_json(path)
    if snapshot is None and os.path.exists(path):
        raise RuntimeError(f"snapshot unreadable — inspect {path}")
    return snapshot


def remove_slot(name):
    """Remove a registry slot and its per-slot collection/routing state.

    Credential homes are intentionally out of scope: removal only un-registers
    a slot, preserving any provider login for the operator to manage directly.
    """
    from . import route

    with collection_lock():
        private = _load_snapshot_for_removal(paths.private_snapshot_path())
        public = _load_snapshot_for_removal(paths.public_snapshot_path())
        # Refuse before mutating the registry if a protective ledger cannot be
        # read and therefore cannot be safely scrubbed.
        route.preflight_remove_slot_state()
        # remove_account reloads under the registry lock, revalidating that the
        # slot still exists before the first mutation.  The collection lock
        # covers the full sequence, so a collector cannot later republish it.
        removed = registry.remove_account(name)
        failures = []
        warnings = []
        try:
            try:
                if _prune_snapshot_slot(private, name):
                    paths.write_json_atomic(
                        paths.private_snapshot_path(), private)
            except Exception as error:
                failures.append(("private snapshot cleanup", error))
            try:
                if _prune_snapshot_slot(public, name):
                    paths.write_json_atomic(
                        paths.public_snapshot_path(), public, mode=0o644)
            except Exception as error:
                failures.append(("public snapshot cleanup", error))
            try:
                history.remove_account(removed.get("id"), name)
            except Exception as error:
                warnings.append((
                    f"history purge for {paths.history_path()}", error))
            try:
                tokens.remove_account(removed.get("id"))
            except Exception as error:
                warnings.append((
                    f"token purge for {paths.tokens_dir()}", error))
        finally:
            try:
                route.remove_slot_state(name)
            except Exception as error:
                failures.append(("route cleanup", error))
        if failures:
            details = "; ".join(
                f"{operation}: {error}"
                for operation, error in failures + warnings)
            raise RuntimeError(
                f"the slot is removed; cleanup failed for account {name!r}: "
                f"{details}") from failures[0][1]
        if warnings:
            details = "; ".join(
                f"{operation}: {error}" for operation, error in warnings)
            try:
                print(f"headroom: warning: the slot is removed; {details}",
                      file=sys.stderr)
            except Exception:
                pass
        return removed


def cmd_remove(args):
    """CLI: `headroom remove <slot> [--yes]`."""
    yes = False
    if len(args) == 2 and args[1] == "--yes" and not args[0].startswith("-"):
        name, yes = args[0], True
    elif len(args) == 1 and not args[0].startswith("-"):
        name = args[0]
    else:
        print("usage: headroom remove <slot> [--yes]", file=sys.stderr)
        return 2
    accounts = registry.accounts()
    if not any(account["name"] == name for account in accounts):
        print(f"headroom: no connected account named {name!r}", file=sys.stderr)
        return 2
    if len(accounts) == 1:
        print("headroom: refusing to remove the final connected account",
              file=sys.stderr)
        return 2
    if not sys.stdin.isatty() and not yes:
        print("headroom: --yes is required when stdin is not a TTY",
              file=sys.stderr)
        return 2
    if not yes:
        answer = input(
            f"Remove slot '{name}' from Headroom? Its credential home will be kept. "
            "[y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("remove cancelled")
            return 1
    try:
        remove_slot(name)
    except registry.RegistryError as error:
        print(f"headroom: {error}", file=sys.stderr)
        return 2
    print(f"removed: {name} (credential home kept)")
    return 0


def display_percent(window):
    if not window or window.get("used_percent") is None:
        return "-"
    return "%d%%" % round(window["used_percent"])


def display_left(window):
    """Remaining percent, the way the statusline batteries read.

    The provider reports USED and the statusline shows LEFT, so the two
    surfaces disagreed on what a bare number meant: `7d=99%` was one percent
    of a week remaining, while `7d=34%` was two thirds remaining. Capacity is
    read the way a battery is read — how much is left — and deciding where to
    work should not require arithmetic under pressure. Anything human-facing
    prints LEFT and says so; `display_percent` stays for anything that
    genuinely means used.
    """
    if not window or window.get("used_percent") is None:
        return "-"
    used = window["used_percent"]
    try:
        return "%d%% left" % round(100 - float(used))
    except (TypeError, ValueError):
        return "-"


def print_snapshot(snapshot):
    # PAUL LAW 2026-08-10 (locked): status batteries show how much is LEFT,
    # never how much is used. This table printed USED for a month while
    # `headroom status` printed LEFT, and the two contradicting each other is
    # where the recurring inversion misreads came from. No parser consumes
    # these rows (swept 2026-08-10); the values self-label with "left".
    for account in snapshot["accounts"]:
        windows = account.get("windows") or {}
        scoped = " ".join(
            "%s=%s" % (key.split(":", 1)[1], display_left(windows[key]))
            for key in windows if key.startswith("scoped:")
        )
        if account.get("ok"):
            print("%-16s %-14s 5h=%-9s 7d=%-9s %s%s" % (
                account["name"], account.get("plan", ""),
                display_left(windows.get("5h")),
                display_left(windows.get("7d")),
                scoped, " STALE" if account.get("stale") else ""))
        else:
            print("%-16s HELD: %s" % (
                account["name"],
                account.get("note") or account.get("error") or "unknown"))
    for warning in snapshot.get("integrity_warnings", []):
        print("WARNING", warning)
