# headroom · Übersicht desktop widgets

Two [Übersicht](https://tracesof.net/uebersicht/) widgets that pin the
headroom liquid-glass cards straight onto the macOS desktop, fed by the real
`headroom serve` fleet feed over loopback:

| Widget | Size | Shows |
| --- | --- | --- |
| `headroom-small.jsx` | 206×206 | fullest current 5h tank, per-account session bars, `N/N accounts live`, freshness dot |
| `headroom-medium.jsx` | 438×206 | the same headline plus a labelled per-account 5h bar row |

The layout, the five liquid-glass themes, and — most importantly — the
fail-closed state mapping are copied from `dashboard/template.html`, so the
desktop cards look and behave exactly like the served
`/widget?compact=1&size=small|medium` surfaces.

## Install

```sh
brew install --cask ubersicht
```

Übersicht loads every widget it finds in its widgets folder (menu bar icon →
*Open Widgets Folder*, normally
`~/Library/Application Support/Übersicht/widgets/`). Copy one or both files in:

```sh
cp headroom-small.jsx headroom-medium.jsx \
  ~/Library/Application\ Support/Übersicht/widgets/
```

That's it — no build step, no dependencies. Each `.jsx` file is fully
self-contained (inline CSS/JS, system fonts only, no external hosts).

## Data source (loopback only)

Each widget runs one command every 60 s:

```sh
curl -q --fail --silent --show-error --noproxy '*' --max-time 4 \
  "$HEADROOM_WIDGET_URL/widget.json"   # default http://127.0.0.1:8377
```

The curl is hermetic and fail-closed: `-q` ignores any `~/.curlrc`,
`--noproxy '*'` keeps the loopback request off proxy environment variables,
and `--fail` refuses to render the body of an HTTP error response.

- If `headroom serve` runs on the same Mac, nothing to configure.
- If it runs on another machine, forward the dashboard over SSH so the feed
  stays loopback-only, exactly like the main README's Widgets section:

  ```sh
  ssh -N -L 8377:127.0.0.1:8377 user@headroom-host
  ```

- To use a different local port, set the origin for GUI apps (plain shell
  exports don't reach Übersicht) — or just edit the default inside the
  `command` string at the top of the widget:

  ```sh
  launchctl setenv HEADROOM_WIDGET_URL http://127.0.0.1:8377
  ```

  The override is validated the same way as the SwiftBar client: only
  `http://127.0.0.1:PORT` / `http://localhost:PORT` origins (port 1–65535)
  are accepted, and the URL is rebuilt canonically before curl runs. Anything
  else fails closed to the grey offline card. No other command is ever
  executed and no secrets/auth files are read.

## Fail-closed honesty

Same contract as the served widget — the only branch that can produce a live
color is a `current` account window with a finite `left_percent` inside a
`current` snapshot:

- **stale / held** accounts render the grey unknown tone (dimmed bars, `n/a`
  or last-observed value) and are never promoted to live;
- a **stale or held snapshot** demotes *every* account to grey and pins the
  live line to `0/N live · feed stale|held`;
- an **expired, future-dated, or timing-less snapshot** is demoted by the
  client freshness guard and renders the same grey stale/held card — readings
  held, never live (a skewed clock can only *add* age, never subtract it);
- the **headline % is derived, not trusted**: it comes from an account whose
  state and 5h window are both `current` with a finite `left_percent`; if
  none qualifies the headline is the grey `—`, whatever number the feed
  carries;
- a **failed curl, malformed JSON, wrong schema, or a feed that fails the
  `headroom_widget@1` shape check** renders the grey "feed unreachable"
  card — never a stale-looking live one;
- the freshness dot pulses only while the snapshot is verifiably current.

## Theme

Set the `THEME` constant at the top of each widget file to one of
`midnight` (default) · `minimal` · `chrome` · `paper` · `terminal`,
then save — Übersicht reloads the widget automatically.

## Position

Defaults: small at top-left (`top: 24px; left: 24px`), medium stacked below it
(`top: 254px; left: 24px`). Adjust the `className` export in each file — it is
plain CSS on the widget root, e.g. right-aligned:

```js
export const className = `
  top: 24px;
  right: 24px;
`;
```

## Preview / screenshots

`preview.html` is a self-contained static page (no Übersicht, no network)
that renders both cards in all five themes plus the fail-closed grey states,
using the exact CSS and state-mapping code shipped in the widgets. Render it
with headless Chrome:

```sh
chrome --headless --screenshot=ubersicht-preview.png \
       --window-size=820,4400 --hide-scrollbars preview.html
```
