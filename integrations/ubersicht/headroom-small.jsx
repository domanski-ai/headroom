// headroom-small.jsx — Übersicht desktop widget: the Small (206×206)
// liquid-glass headroom card, fed by the real headroom_widget@1 projection
// over the loopback tunnel (`headroom serve`, default http://127.0.0.1:8377).
//
// Design + state mapping are copied from dashboard/template.html so the
// desktop card is byte-parity with the served /widget?size=small surface.
//
// FAIL-CLOSED IS SACRED (same rules as the served widget):
//   - the ONLY branch that can produce a live tone is a "current" account
//     window carrying a finite left_percent inside a "current" snapshot;
//   - stale/held accounts render the grey unknown tone at their
//     last-observed value and are never promoted to live;
//   - an expired, future-dated, or timing-less snapshot is demoted client-side
//     and renders the grey stale/held card — readings held, never live;
//   - a failed curl, non-loopback URL, malformed JSON, or a feed that fails
//     the headroom_widget@1 shape check renders the grey "feed unreachable"
//     card.
//
// Configuration ------------------------------------------------------------
// THEME: one of "midnight" | "minimal" | "chrome" | "paper" | "terminal".
const THEME = "midnight";
// Position on the desktop (Übersicht `className` export, plain CSS).
export const className = `
  top: 24px;
  left: 24px;
`;
// Must match the served widget's snapshot freshness budget (seconds).
const SNAPSHOT_MAX_AGE = 900;

export const refreshFrequency = 60000; // 60s, matching the served widget

// Loopback-only data source. HEADROOM_WIDGET_URL may override the origin but
// is validated exactly like integrations/swiftbar: only http://127.0.0.1:PORT
// or http://localhost:PORT (port 1-65535) is accepted. The port is the EXACT
// remainder after the loopback prefix and must be all digits (no leading
// zero), so userinfo/path/;-suffix tricks (http://127.0.0.1:8377@evil:80,
// .../path:80, ...;ignored:80) are rejected instead of being silently
// rewritten, and the URL is rebuilt canonically before curl sees it. The curl
// is hermetic and fail-closed: -q ignores any ~/.curlrc, --noproxy '*' keeps
// the loopback request off proxies, and --fail refuses to render an HTTP
// error body. Nothing else is ever executed; no secrets or auth files are
// read.
export const command = `
url="\${HEADROOM_WIDGET_URL:-http://127.0.0.1:8377}"
url="\${url%/}"
case "$url" in
  http://127.0.0.1:*) port="\${url#http://127.0.0.1:}" ;;
  http://localhost:*) port="\${url#http://localhost:}" ;;
  *) echo "headroom: HEADROOM_WIDGET_URL must be a loopback origin" >&2; exit 1 ;;
esac
case "$port" in
  ""|0*|*[!0-9]*) echo "headroom: bad port in HEADROOM_WIDGET_URL" >&2; exit 1 ;;
esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || exit 1
exec curl -q --fail --silent --show-error --noproxy '*' --max-time 4 "http://127.0.0.1:$port/widget.json"
`;

/* ------------------------------------------------------------- helpers
   Ported verbatim from dashboard/template.html (widget section). */
function esc(v) {
  return String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
function clamp(v, lo, hi) { return Math.min(hi, Math.max(lo, v)); }
function hrTone(left) {
  return left == null ? "unknown"
    : left <= 10 ? "red" : left <= 30 ? "orange" : left <= 50 ? "yellow" : "green";
}
function hrPct(v) { return Number.isFinite(v) ? clamp(v, 0, 100) : null; }

/* projection -> tone/value mapping. The ONLY live-color branch requires the
   window to be state "current" AND carry a finite left_percent. */
function hrWindow(w) {
  const st = w && typeof w.state === "string" ? w.state : "held";
  const live = hrPct(w && w.left_percent);
  if (st === "current" && live != null)
    return { tone: hrTone(live), fill: live, value: Math.round(live) + "%", live: true };
  const last = hrPct(w && w.last_observed_left_percent);
  if (st === "limited")
    return { tone: "red", fill: last == null ? 0 : last, value: (last == null ? 0 : Math.round(last)) + "%", live: false };
  if (st === "stale" && last != null)
    return { tone: "unknown", fill: last, value: Math.round(last) + "%", live: false };
  return { tone: "unknown", fill: null, value: "n/a", live: false };
}
/* offline / noncurrent feed: every reading is shown grey at its last-observed
   value — a demoted window can never yield anything but the unknown tone. */
function hrDemoteWindow(w) {
  const left = w && Number.isFinite(w.left_percent) ? w.left_percent
    : (w && w.last_observed_left_percent);
  const last = hrPct(left);
  if (last != null)
    return { tone: "unknown", fill: last, value: Math.round(last) + "%", live: false };
  return { tone: "unknown", fill: null, value: "n/a", live: false };
}
function hrFreshness(data) {
  const f = data && data.freshness && typeof data.freshness === "object" ? data.freshness : {};
  /* client-side fail-closed guard: "current" is trusted ONLY with complete
     timing — a finite, non-negative age inside the freshness budget. Client
     clock drift only ever ADDS age (a future-dated evaluation can never
     subtract age or stay current); missing timing holds, never promotes. */
  const now = Date.now() / 1e3;
  const evaluatedAt = Number.isFinite(f.evaluated_at) ? f.evaluated_at : null;
  let age = Number.isFinite(f.age_seconds) && f.age_seconds >= 0 ? f.age_seconds : null;
  if (age != null && evaluatedAt != null) age += Math.max(0, now - evaluatedAt);
  let state = f.state === "current" || f.state === "stale" ? f.state : "held";
  if (state === "current" && (age == null || evaluatedAt == null)) state = "held";
  if (state === "current" && age > SNAPSHOT_MAX_AGE) state = "stale";
  if (evaluatedAt != null && evaluatedAt > now) state = "held";
  return { state: state, age: age };
}
function hrAccount(raw, demote) {
  const a = raw && typeof raw === "object" ? raw : {};
  const name = typeof a.name === "string" ? a.name : "unknown";
  let st = ["current", "limited", "stale", "held"].includes(a.state) ? a.state : "held";
  if (demote && st !== "held") st = "stale";
  const w5 = (a.windows && a.windows["5h"]) || null;
  const v5 = demote ? hrDemoteWindow(w5) : hrWindow(w5);
  return { name: name, state: st, v5: v5 };
}
function hrView(data) {
  const fresh = hrFreshness(data);
  const demote = fresh.state !== "current";
  const rawAccounts = Array.isArray(data.accounts) ? data.accounts : [];
  const accts = rawAccounts.map((a) => hrAccount(a, demote));
  /* headline: never trust the feed's number — derive the fullest tank from an
     account whose state AND 5h window are BOTH current with a finite reading;
     if none qualifies the headline is the held "—", whatever the feed claims. */
  const total = accts.length;
  const cur = demote ? 0 : accts.filter((a) => a.state === "current").length;
  let fullest = null;
  if (!demote) rawAccounts.forEach((a) => {
    const w = (a && a.windows && a.windows["5h"]) || {};
    const l = a && a.state === "current" && w.state === "current" ? hrPct(w.left_percent) : null;
    if (l != null && (fullest == null || l > fullest)) fullest = l;
  });
  const hl = fullest != null
    ? { value: Math.round(fullest) + "%", tone: hrTone(fullest) }
    : { value: "—", tone: "dim" };
  const limited = accts.filter((a) => a.state === "limited");
  const liveLine = fresh.state === "stale" ? "0/" + total + " live · feed stale"
    : fresh.state === "held" ? "0/" + total + " live · feed held"
    : limited.length ? cur + "/" + total + " live · " + limited.length + " at limit"
    : cur + "/" + total + " accounts live";
  const dotc = fresh.state === "current" ? "var(--green)"
    : fresh.state === "stale" ? "var(--orange)" : "var(--unknown)";
  return { offline: false, fresh: fresh, accts: accts, hl: hl,
           liveLine: liveLine, dotc: dotc };
}
function hrOfflineView() {
  return { offline: true, fresh: { state: "held" }, accts: [],
           hl: { value: "—", tone: "dim" },
           liveLine: "feed unreachable", dotc: "var(--unknown)" };
}
/* headroom_widget@1 structural validation: anything missing or mistyped is
   rejected before it can render — the OFFLINE view, never a live card.
   Strict by design: a MISSING field is not null — the projection always emits
   every contract field explicitly, so absence means a foreign/broken feed. */
function hrFiniteOrNull(v) {
  return v === null || (typeof v === "number" && Number.isFinite(v));
}
function hrValidWindow(w) {
  if (!w || typeof w !== "object" || Array.isArray(w)) return false;
  if (!["current", "limited", "stale", "held"].includes(w.state)) return false;
  if (!hrFiniteOrNull(w.left_percent) || !hrFiniteOrNull(w.last_observed_left_percent)
      || !hrFiniteOrNull(w.resets_at) || !hrFiniteOrNull(w.observed_at)) return false;
  if (w.left_percent != null && (w.left_percent < 0 || w.left_percent > 100)) return false;
  if (w.last_observed_left_percent != null
      && (w.last_observed_left_percent < 0 || w.last_observed_left_percent > 100)) return false;
  /* value invariant: only a current window may carry a live left_percent */
  return w.state === "current" ? Number.isFinite(w.left_percent) : w.left_percent == null;
}
function hrValidFeed(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  if (data.schema !== "headroom_widget@1") return false;
  const f = data.freshness;
  if (!f || typeof f !== "object" || Array.isArray(f)) return false;
  if (!["current", "stale", "held"].includes(f.state)) return false;
  if (typeof f.reason !== "string") return false;
  if (!Number.isFinite(f.evaluated_at)) return false;
  if (f.age_seconds !== null
      && !(Number.isInteger(f.age_seconds) && f.age_seconds >= 0)) return false;
  if (f.state !== "held" && f.age_seconds === null) return false;
  if (!Array.isArray(data.accounts)) return false;
  if (!data.accounts.every((a) => a && typeof a === "object" && !Array.isArray(a)
      && typeof a.name === "string" && typeof a.provider === "string"
      && ["current", "limited", "stale", "held"].includes(a.state)
      && a.windows && typeof a.windows === "object" && !Array.isArray(a.windows)
      && hrValidWindow(a.windows["5h"]) && hrValidWindow(a.windows["7d"]))) return false;
  const h = data.headline;
  if (!h || typeof h !== "object" || Array.isArray(h)) return false;
  if (!Number.isInteger(h.current_accounts) || h.current_accounts < 0) return false;
  if (!Number.isInteger(h.total_accounts) || h.total_accounts < 0) return false;
  return h.fullest_5h_left_percent === null
    || (Number.isFinite(h.fullest_5h_left_percent)
        && h.fullest_5h_left_percent >= 0 && h.fullest_5h_left_percent <= 100);
}
function parseFeed(output) {
  if (typeof output !== "string" || !output.trim()) return null;
  let data = null;
  try { data = JSON.parse(output); } catch (e) { return null; }
  return hrValidFeed(data) ? data : null;
}

/* ---- markup builders (names escaped; values are code-built) ----
   Copied from dashboard/template.html hrSmallMarkup/hrBarsMarkup. */
function hrDotMarkup(v) {
  return '<span class="hr-dot' + (v.fresh.state === "current" && !v.offline ? " is-live" : "") +
    '" style="--dotc:' + v.dotc + '" aria-hidden="true"></span>';
}
function hrBarsMarkup(v) {
  return v.accts.map((a) => {
    const last = a.v5.fill == null ? 6 : Math.max(6, a.v5.fill);
    if (a.state === "current") return '<span class="hr-bar hr-tone-' + a.v5.tone + '" style="--h:' + last + '%" title="' + esc(a.name) + '"></span>';
    if (a.state === "limited") return '<span class="hr-bar hr-tone-red" style="--h:6%" title="' + esc(a.name) + '"></span>';
    if (a.state === "stale") return '<span class="hr-bar hr-tone-unknown is-dim" style="--h:' + last + '%" title="' + esc(a.name) + '"></span>';
    return '<span class="hr-bar hr-tone-unknown is-held" style="--h:100%" title="' + esc(a.name) + '"></span>';
  }).join("");
}
function hrSmallMarkup(v) {
  return '<div class="hr-card small hr-glass glowable">' +
    '<div class="hr-chead"><span class="hr-mark">hr</span><span class="hr-brand">headroom</span><span class="hr-sp"></span>' + hrDotMarkup(v) + '</div>' +
    '<div class="hr-cmid"><div class="hr-cval hr-tone-' + v.hl.tone + '">' + esc(v.hl.value) + '</div>' +
      '<div class="hr-clabel">Fullest 5h tank</div></div>' +
    '<div><div class="hr-bars" role="img" aria-label="session headroom per account">' + hrBarsMarkup(v) + '</div>' +
      '<div class="hr-liveline">' + esc(v.liveLine) + "</div></div></div>";
}

/* --------------------------------------------------------------- styles
   Exact liquid-glass token sets (all five themes) + card CSS copied from
   dashboard/template.html. Only the page-shell layout (fixed overlay, wall,
   blobs) is dropped — the desktop wallpaper is the wall here. */
const CSS = `
.hr, .hr * { box-sizing: border-box; }
.hr {
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --pop-radius: 18px; --widget-radius: 26px; --cell-gap: 3px; --cell-radius: 1px;
  --bg: #0b0e14; --bg-grid: rgba(255,255,255,.025); --panel: #11151f; --panel-2: #0e1219;
  --line: #1e2430; --line-strong: #2a3242; --ink: #e8ecf4; --ink-2: #8b93a5; --ink-3: #5a6274;
  --accent: #7aa2ff; --green: #3ddc84; --yellow: #ffd54a; --orange: #ff9640; --red: #ff5d5d;
  --unknown: #454c5c; --cell-bg: #1a1f2b; --cell-glow: 0 0 6px;
  --glass: rgba(19,23,34,.6); --glass-2: rgba(13,16,25,.55);
  --glass-line: rgba(255,255,255,.14); --glass-hi: 0 1px 0 rgba(255,255,255,.1) inset;
  --sep: rgba(255,255,255,.07); --row-hov: rgba(255,255,255,.06);
  --shadow-pop: 0 28px 70px rgba(0,0,0,.5), 0 3px 10px rgba(0,0,0,.4);
  --wall: linear-gradient(160deg,#1a2757 0%,#0e1430 48%,#0a0d18 100%);
  --blob-a: rgba(122,162,255,.4); --blob-b: rgba(61,220,132,.28);
}
.hr[data-theme="minimal"] {
  --cell-gap: 2px; --cell-glow: none;
  --bg: #ffffff; --bg-grid: transparent; --panel: #ffffff; --panel-2: #fafafa;
  --line: #ececec; --line-strong: #d8d8d8; --ink: #111111; --ink-2: #6f6f6f; --ink-3: #a3a3a3;
  --accent: #111111; --green: #1db954; --yellow: #e6b800; --orange: #f07c22; --red: #e5484d;
  --unknown: #d0d0d0; --cell-bg: #ececec;
  --glass: rgba(255,255,255,.55); --glass-2: rgba(250,250,250,.5);
  --glass-line: rgba(0,0,0,.1); --glass-hi: 0 1px 0 rgba(255,255,255,.75) inset;
  --sep: rgba(0,0,0,.07); --row-hov: rgba(0,0,0,.045);
  --shadow-pop: 0 24px 55px rgba(20,20,25,.18), 0 2px 8px rgba(20,20,25,.1);
  --wall: linear-gradient(165deg,#eceff2 0%,#f8f8f9 55%,#e4e6ea 100%);
  --blob-a: rgba(29,185,84,.22); --blob-b: rgba(80,120,255,.14);
}
.hr[data-theme="chrome"] {
  --cell-radius: 2px; --cell-glow: none;
  --bg: #c9cdd3; --bg-grid: transparent;
  --panel: linear-gradient(180deg,#f4f6f8 0%,#dfe3e8 55%,#d2d7dd 100%);
  --panel-2: linear-gradient(180deg,#e8ebef,#d8dce2);
  --line: #aeb4bc; --line-strong: #8f96a0; --ink: #23262b; --ink-2: #565c66; --ink-3: #7d838d;
  --accent: #2f6fed; --green: #1e9e55; --yellow: #d3a10a; --orange: #e2711d; --red: #cf3f3f;
  --unknown: #a6acb5; --cell-bg: #b9bec6;
  --glass: rgba(240,243,246,.55); --glass-2: rgba(224,228,233,.5);
  --glass-line: rgba(0,0,0,.14); --glass-hi: 0 1px 0 rgba(255,255,255,.85) inset;
  --sep: rgba(0,0,0,.09); --row-hov: rgba(30,35,42,.06);
  --shadow-pop: 0 26px 60px rgba(30,35,42,.32), 0 2px 8px rgba(30,35,42,.2);
  --wall: linear-gradient(170deg,#dde1e7 0%,#c0c6ce 52%,#a9b0b9 100%);
  --blob-a: rgba(47,111,237,.26); --blob-b: rgba(30,158,85,.2);
}
.hr[data-theme="paper"] {
  --widget-radius: 22px; --cell-glow: none;
  --bg: #f5efe6; --bg-grid: rgba(21,18,16,.035); --panel: #fbf6eb; --panel-2: #f3ecdd;
  --line: #c5ac85; --line-strong: #a98f68; --ink: #151210; --ink-2: #3a2f25; --ink-3: #6e5e4d;
  --accent: #c87555; --green: #3f7d4e; --yellow: #c59b24; --orange: #c76a31; --red: #b0413a;
  --unknown: #8b8277; --cell-bg: #e6d2ba;
  --glass: rgba(251,246,235,.6); --glass-2: rgba(243,236,221,.55);
  --glass-line: rgba(90,70,40,.22); --glass-hi: 0 1px 0 rgba(255,255,255,.6) inset;
  --sep: rgba(21,18,16,.1); --row-hov: rgba(21,18,16,.05);
  --shadow-pop: 0 24px 50px rgba(61,45,28,.28), 0 2px 8px rgba(61,45,28,.16);
  --wall: linear-gradient(165deg,#eee2cb 0%,#f6f0e4 55%,#e0d0b3 100%);
  --blob-a: rgba(200,117,85,.3); --blob-b: rgba(63,125,78,.22);
}
.hr[data-theme="terminal"] {
  --sans: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --pop-radius: 14px; --widget-radius: 18px;
  --bg: #050805; --bg-grid: rgba(51,255,102,.04); --panel: #070b07; --panel-2: #060906;
  --line: #123c1c; --line-strong: #1d5a2b; --ink: #33ff66; --ink-2: #1fae47; --ink-3: #157a32;
  --accent: #33ff66; --green: #33ff66; --yellow: #e8ff47; --orange: #ffb347; --red: #ff4747;
  --unknown: #1d5a2b; --cell-bg: #0a140c; --cell-glow: 0 0 8px;
  --glass: rgba(7,12,8,.62); --glass-2: rgba(5,9,6,.55);
  --glass-line: rgba(51,255,102,.24); --glass-hi: 0 1px 0 rgba(51,255,102,.1) inset;
  --sep: rgba(51,255,102,.12); --row-hov: rgba(51,255,102,.07);
  --shadow-pop: 0 28px 70px rgba(0,0,0,.7), 0 0 26px rgba(51,255,102,.09);
  --wall: radial-gradient(120% 130% at 30% 0%,#08130a 0%,#040704 60%,#020402 100%);
  --blob-a: rgba(51,255,102,.2); --blob-b: rgba(232,255,71,.1);
}
.hr[data-theme="terminal"] .glowable { text-shadow: 0 0 4px rgba(51,255,102,.35); }

.hr { position: relative; font-family: var(--mono); color: var(--ink);
      line-height: 1.45; -webkit-font-smoothing: antialiased; }

/* liquid glass card */
.hr-glass { background: var(--glass);
            backdrop-filter: blur(38px) saturate(170%);
            -webkit-backdrop-filter: blur(38px) saturate(170%);
            border: 1px solid var(--glass-line);
            box-shadow: var(--shadow-pop), var(--glass-hi); overflow: hidden; }

.hr-sp { flex: 1 1 auto; }
.hr-dot { position: relative; flex: none; width: 7px; height: 7px; border-radius: 50%;
          background: var(--dotc, var(--unknown)); }
.hr-dot.is-live::after { content: ""; position: absolute; inset: -4px;
                         border: 1px solid var(--dotc, var(--unknown));
                         border-radius: 50%; }

/* fail-closed tone classes: unknown/dim carry NO live color, ever */
.hr-tone-green { --wtone: var(--green); color: var(--green); }
.hr-tone-yellow { --wtone: var(--yellow); color: var(--yellow); }
.hr-tone-orange { --wtone: var(--orange); color: var(--orange); }
.hr-tone-red { --wtone: var(--red); color: var(--red); }
.hr-tone-unknown { --wtone: var(--unknown); color: var(--ink-3); }
.hr-tone-dim { --wtone: var(--unknown); color: var(--ink-3); }

/* desktop widget: small (206x206) and medium (438x206) */
.hr-card { padding: 16px; display: flex; flex-direction: column;
           border-radius: var(--widget-radius); }
.hr-card.small { width: 206px; height: 206px; }
.hr-card.medium { width: 438px; height: 206px; padding: 14px 18px; display: grid;
                  grid-template-columns: 140px 1fr; gap: 20px; }
.hr-chead { display: flex; align-items: center; gap: 6px; }
.hr-mark { font: 700 10px var(--mono); color: var(--accent); }
.hr-brand { font: 600 7.5px var(--mono); letter-spacing: .14em;
            text-transform: uppercase; color: var(--ink-3); }
.hr-cmid { flex: 1 1 auto; display: flex; flex-direction: column;
           justify-content: center; }
.hr-cval { font: 700 46px/1 var(--mono); letter-spacing: -.03em; }
.hr-card.medium .hr-cval { font-size: 38px; }
.hr-clabel { margin-top: 7px; font: 600 8px var(--mono); letter-spacing: .13em;
             text-transform: uppercase; color: var(--ink-3); }
.hr-bars { display: flex; align-items: flex-end; gap: 3px; height: 30px; }
.hr-bar { flex: 1 1 0; border-radius: 2px; height: var(--h, 4%);
          background: var(--wtone, var(--unknown));
          box-shadow: var(--cell-glow) var(--wtone, transparent); }
.hr-bar.is-dim { opacity: .55; box-shadow: none; }
.hr-bar.is-held { opacity: .3; box-shadow: none; }
.hr-liveline { margin-top: 8px; font: 500 8.5px var(--mono); color: var(--ink-2); }
.hr-mleft { display: flex; flex-direction: column; min-width: 0; }
.hr-mcol { display: flex; flex-direction: column; justify-content: center; gap: 6px;
           min-width: 0; }
.hr-mrow { display: grid; grid-template-columns: 110px 1fr 36px; gap: 9px;
           align-items: center; }
.hr-mname { font: 600 9px var(--mono); color: var(--ink-2); white-space: nowrap;
            overflow: hidden; text-overflow: ellipsis; }
.hr-mbar { position: relative; height: 4px; border-radius: 2px;
           background: var(--cell-bg); overflow: hidden; }
.hr-mfill { position: absolute; top: 0; bottom: 0; left: 0; width: var(--fill, 0%);
            background: var(--wtone, var(--unknown));
            box-shadow: var(--cell-glow) var(--wtone, transparent); }
.hr-mbar.is-dim .hr-mfill { opacity: .55; box-shadow: none; }
.hr-mval { font: 700 9.5px var(--mono); text-align: right; }

@media (prefers-reduced-motion: no-preference) {
  .hr-dot.is-live::after { animation: hr-pulse 1.8s ease-out infinite; }
}
@keyframes hr-pulse { from { opacity: .6; transform: scale(.6); }
                      to { opacity: 0; transform: scale(1.7); } }
`;

/* --------------------------------------------------------------- render */
export const render = ({ output, error }) => {
  const data = error ? null : parseFeed(output);
  const v = data ? hrView(data) : hrOfflineView();
  return (
    <div className="hr" data-theme={THEME}>
      <style dangerouslySetInnerHTML={{ __html: CSS }} />
      <div dangerouslySetInnerHTML={{ __html: hrSmallMarkup(v) }} />
    </div>
  );
};
