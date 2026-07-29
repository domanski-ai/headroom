# Claude Code integration

Two plug-ins, both optional, both 30-second installs.

## 1. Live headroom in your status line

Shows the account your session is running on with its color-coded 5h/7d usage
(percent *used*, green→red as it fills), and who the rotator would pick next
when you're running low:

```
work · 5h 82% · 7d 47% · next: personal
```

(the `next:` hint appears once the current account's 5h window passes 75%.)

Add to `~/.claude/settings.json`:

```json
{
  "statusLine": {
    "type": "command",
    "command": "headroom statusline"
  }
}
```

(If `headroom` isn't on your PATH, use the absolute path to `bin/headroom`.)

## 2. The /rotator skill

Lets Claude Code rotate accounts for you: when a session dies on a usage
limit, say "rotate the account" (or type `/rotator`) and Claude runs the
headroom engine, cools the exhausted login down, and hands you the next one.

Install by copying the skill into your personal skills directory:

```bash
mkdir -p ~/.claude/skills
cp -r integrations/claude-code/skills/rotator ~/.claude/skills/
```

Restart Claude Code and type `/rotator`.

## 3. Automatic handoff (on by default)

Automatic handoff is on unless you turn it off — `headroom setup` asks, and
`{"routing": {"auto_handoff": false}}` in `~/.headroom/config.json` disables
it. Launch interactive sessions through `headroom claude`. Headroom injects
private per-run hooks through `--settings`; it does not edit this file. A
missing hook handshake leaves Claude running and disables automation. Your own
`--settings` is merged under those hooks and launches supervised; a document
that would suppress them refuses the launch instead.

Conversation history, model-family routing, and the latest cwd carry. Background
tasks, MCP connections/approvals, permission approvals/mode, and other
ephemeral launch flags do not. See `docs/KNOWN-LIMITS.md`, especially the
interrupted-tool double-execution warning and the pending macOS E2E gate.

## 4. Keeping usage fresh in the background (optional)

`headroom serve` refreshes on demand, and `headroom status`/`pick` refresh
automatically when the snapshot is stale — cron is NOT required. But if you
want the dashboard warm at all times:

```bash
# crontab -e   (Linux)
*/10 * * * * /path/to/headroom/bin/headroom collect >/dev/null 2>&1
```

macOS: `launchctl` works the same way, or just keep a `headroom serve` tab open.
