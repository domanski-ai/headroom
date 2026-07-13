#!/bin/sh
# SwiftBar display client for headroom. Remote use assumes an SSH-forwarded
# loopback dashboard; fetched bytes are printed only after version validation.

sentinel='headroom_widget_txt@1'
dashboard='http://127.0.0.1:8377/'

offline() {
    printf '%s\n' \
        'hr OFFLINE | color=gray' \
        '---' \
        'Headroom feed unavailable | color=gray' \
        'Refresh | refresh=true' \
        "Open dashboard | href=$dashboard"
}

tmp=$(mktemp "${TMPDIR:-/tmp}/headroom-swiftbar.XXXXXX") || {
    offline
    exit 0
}
trap 'rm -f "$tmp"' EXIT HUP INT TERM

if [ -n "${HEADROOM_WIDGET_URL:-}" ]; then
    # accept either the serve base URL or the full /widget.txt URL
    base=${HEADROOM_WIDGET_URL%/}
    case "$base" in
        */widget.txt) url=$base; base=${base%/widget.txt} ;;
        *) url=$base/widget.txt ;;
    esac
    dashboard=$base/
    if ! curl --fail --silent --max-time 3 \
        --max-filesize 65536 --output "$tmp" "$url"
    then
        offline
        exit 0
    fi
else
    # HEADROOM_BIN overrides for nonstandard installs; a local binary the
    # user configured, never fetched content
    if ! ${HEADROOM_BIN:-headroom} widget-feed --swiftbar >"$tmp" 2>/dev/null
    then
        offline
        exit 0
    fi
fi

bytes=$(wc -c <"$tmp" | tr -d ' ')
lines=$(wc -l <"$tmp" | tr -d ' ')
IFS= read -r first <"$tmp"
if [ "$bytes" -gt 65536 ] || [ "$lines" -lt 2 ] || [ "$first" != "$sentinel" ]
then
    offline
    exit 0
fi

sed '1d' "$tmp"
