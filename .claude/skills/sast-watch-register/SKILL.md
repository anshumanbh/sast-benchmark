---
name: sast-watch-register
description: Register a new upstream GitHub repo as a sast-watch target. Validates the repo, seeds the state file from the current manifest, writes a per-target launchd plist to ~/Library/LaunchAgents/, and bootstraps it. Invoke as `/sast-watch-register OWNER/REPO`.
argument-hint: "OWNER/REPO"
disable-model-invocation: true
allowed-tools: Bash(gh *) Bash(git *) Bash(python3 *) Bash(python3.11 *) Bash(launchctl *) Bash(ls *) Bash(cat *) Bash(mkdir *) Bash(test *) Read Write
---

# /sast-watch-register — install the launchd job for one target

`$ARGUMENTS` must be a single GitHub identifier `OWNER/REPO`. The skill installs a recurring 24h launchd agent that fires `/sast-watch $ARGUMENTS` and seeds the state file so the first fire isn't a flood.

This skill has side effects (writes a file to `~/Library/LaunchAgents/`, calls `launchctl bootstrap`). It is `disable-model-invocation: true`; only invoke it deliberately.

## Step 0 — Validate

```bash
REPO="$ARGUMENTS"
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "usage: /sast-watch-register OWNER/REPO"; exit 2; }
test -f manifest.json && test -d cases || { echo "must be run from sast-benchmark root"; exit 2; }
which gh launchctl python3.11 >/dev/null || { echo "missing one of: gh launchctl python3.11"; exit 2; }
gh api "repos/$REPO" >/dev/null || { echo "no such GitHub repo: $REPO"; exit 2; }
```

## Step 1 — Seed the state file from the current manifest

```bash
SLUG="${REPO/\//__}"
STATE_DIR=".claude/skills/sast-watch/state"
STATE="$STATE_DIR/${SLUG}.json"
mkdir -p "$STATE_DIR"
python3.11 .claude/skills/sast-watch/scripts/state.py seed \
  --manifest manifest.json --cases-dir cases \
  --repository "$REPO" --state-file "$STATE"
echo "seeded $STATE with $(python3.11 -c "import json; print(len(json.load(open('$STATE'))['ghsa_ids']))") GHSA IDs"
```

If `$REPO` isn't yet in `manifest.repositories`, the seed will be empty — that's fine; the first sast-watch fire will pick up everything published in the trailing 24h.

## Step 2 — Write the launchd plist

```bash
LABEL="com.sast-benchmark.watch.${SLUG//[._]/-}"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
REPO_ROOT="$(pwd)"
CLAUDE_BIN="$(which claude)"
LOG_DIR="$HOME/Library/Logs/sast-watch"
mkdir -p "$LOG_DIR"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTD/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>-lc</string>
    <string>cd "${REPO_ROOT}" &amp;&amp; "${CLAUDE_BIN}" -p "/sast-watch ${REPO}" --permission-mode acceptEdits --output-format text</string>
  </array>
  <key>StartInterval</key>
  <integer>86400</integer>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/${SLUG}.out.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/${SLUG}.err.log</string>
  <key>RunAtLoad</key>
  <false/>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>${PATH}</string>
  </dict>
</dict>
</plist>
EOF
echo "wrote $PLIST"
```

Notes on the plist choices:
- **`StartInterval` 86400** — every 24h from agent load time. If the Mac is asleep at the fire moment, launchd queues the run and fires on wake. For a strict wall-clock cadence (e.g. 03:00 local every day), swap `StartInterval` for `StartCalendarInterval` with `Hour`/`Minute` keys.
- **`--permission-mode acceptEdits`** — required for unattended runs; the skill's `allowed-tools` already pre-approves the shell commands it needs.
- **`RunAtLoad: false`** — avoids firing immediately on `launchctl bootstrap`; the first fire is one interval after load.

## Step 3 — Bootstrap the agent

```bash
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "bootstrapped"
```

If `bootstrap` reports "service already loaded", run `launchctl bootout "gui/$(id -u)" "$PLIST"` first then re-bootstrap. This is the right move only when re-registering — never on a healthy first install.

## Step 4 — Verify

```bash
launchctl list | grep "$LABEL" || { echo "ERROR: agent not loaded"; exit 1; }
launchctl print "gui/$(id -u)/${LABEL}" | sed -n '/^state =/p; /^last exit code/p; /^next run/p'
echo "registered $LABEL for $REPO"
```

The `print` output shows the agent's state and the next scheduled fire — quote those two lines back to the user so they can see when the first run will happen.

## To deregister

```bash
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/${LABEL}.plist"
rm "$HOME/Library/LaunchAgents/${LABEL}.plist"
# leave the state file in .claude/skills/sast-watch/state/ so re-registering picks up where we left off
```

If you also want to forget what's been seen, delete the state file.

## Trade-offs (the choice, briefly)

launchd was picked because it (a) runs without an open Claude Code session, (b) has full local filesystem access (sibling clones, `~/Library/Logs`), (c) survives reboots, (d) has no slot cap. Two alternatives were considered and rejected:

- **Cloud Routines** (`claude.ai/code/routines`) — runs on Anthropic infra without a local machine, but the env only clones declared repos at session start; the seven sibling-repo clones the timeline derivation needs would have to be re-cloned each run (slow + costly). Minimum interval is 1h.
- **Desktop scheduled tasks** — equivalent capability to launchd for this use case, but the per-target configuration lives inside the Desktop app rather than in a versionable `~/Library/LaunchAgents/` plist. Less ergonomic for scripting `register`/`deregister`.

See `.claude/skills/sast-watch/README.md` for the longer rationale.
