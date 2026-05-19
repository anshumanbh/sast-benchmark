# sast-watch — automated advisory watcher for sast-benchmark

Watches one or more upstream GitHub repos for new HIGH/CRITICAL Security Advisories, adds each as a benchmark case following the [PR #5](https://github.com/anshumanbh/sast-benchmark/pull/5) methodology, opens a PR, and runs [securevibes-agent](https://github.com/anshumanbh/securevibes-agent) against the new cases to report detection results with root-cause analysis on misses.

This skill ships as two `/`-invokable skills plus a small set of Python helpers:

| Path | Purpose |
| --- | --- |
| `sast-watch/SKILL.md` | Per-fire work: detect → build cases → validate → PR → sv-agent + RCA. Takes `OWNER/REPO`. |
| `sast-watch-register/SKILL.md` | One-shot bootstrap per target: seed state file, write launchd plist, `launchctl bootstrap`. |
| `sast-watch/scripts/state.py` | State-file CRUD (seed from manifest, add a GHSA). |
| `sast-watch/scripts/filter_advisories.py` | Pure filter: severity + cutoff + state. |
| `sast-watch/scripts/build_case.py` | Pure data-shaping: advisory + timeline → `case.json` dict, applies the CWE bridge. |
| `sast-watch/state/<owner>__<repo>.json` | Per-target state (checked in). |

## Scheduling — why launchd

The goal-prompt requires (i) running without an open Claude Code session, (ii) local file access to sibling repo clones, (iii) shelling out to `gh`/`git`/`python3`/`npm`. Four options were considered:

| Option | Runs without session | Local clones | Min interval | Verdict |
| --- | --- | --- | --- | --- |
| **macOS launchd → `claude -p`** | yes | yes | seconds | **picked** — native, per-target plist, no slot cap, survives reboots, ergonomic to script. |
| Cloud Routines (`/schedule`) | yes | no (fresh clone of declared repos only) | 1h | Rejected: would need to re-clone all seven sibling upstream repos on every fire (slow + costly), and the per-target plist model maps better to `register`/`deregister` flows. |
| Desktop scheduled tasks | yes | yes | 1m | Viable, but config lives inside the Desktop app instead of a versionable plist. Harder to script. |
| `/loop` | **no — needs an open session** | yes | 1m | Rejected on the session requirement. |

The `sast-watch-register` skill writes one plist per target to `~/Library/LaunchAgents/com.sast-benchmark.watch.<slug>.plist` and bootstraps it. Each plist runs:

```bash
cd <sast-benchmark> && claude -p "/sast-watch OWNER/REPO" --permission-mode acceptEdits
```

The skill's `allowed-tools` frontmatter pre-approves `gh`/`git`/`python3`/`npm`/`jq` and the write tools, so the unattended run doesn't stall on permission prompts.

## State file shape

`.claude/skills/sast-watch/state/<owner>__<repo>.json`:

```json
{
  "repository": "openclaw/openclaw",
  "ghsa_ids": ["GHSA-aaaa-bbbb-cccc", "GHSA-..."],
  "last_seen": "2026-05-15T00:00:00Z"
}
```

`ghsa_ids` is the source of truth for "what has this watcher already added to the benchmark." A GHSA gets added to the list both when the seed runs (from existing `manifest.json` entries) and when `sast-watch` successfully writes a new `cases/<GHSA>/case.json`. The skill is idempotent: a GHSA in the list is filtered out before any work begins.

## Quick start

Prerequisites: all the sibling clones listed in [`CLAUDE.md` § Prerequisites](../../../CLAUDE.md), plus a clone of `anshumanbh/securevibes-agent` at `../securevibes-agent` with `npm install` run.

```bash
# 1. Register a target (one-time per repo)
claude
> /sast-watch-register openclaw/openclaw

# Verify the agent loaded
launchctl list | grep sast-benchmark.watch
```

From then on, the watcher fires every 24h. To dry-run without waiting:

```bash
launchctl kickstart "gui/$(id -u)/com.sast-benchmark.watch.openclaw-openclaw"
tail -f ~/Library/Logs/sast-watch/openclaw__openclaw.out.log
```

Or invoke directly inside an interactive Claude Code session:

```bash
claude
> /sast-watch openclaw/openclaw
```

## Deregistering a target

```bash
LABEL=com.sast-benchmark.watch.openclaw-openclaw
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/${LABEL}.plist"
rm "$HOME/Library/LaunchAgents/${LABEL}.plist"
```

The state file at `.claude/skills/sast-watch/state/<slug>.json` is intentionally left behind so re-registering picks up where you left off. Delete it if you also want to forget what's been seen.

## securevibes-agent prerequisite

Install once:

```bash
git clone https://github.com/anshumanbh/securevibes-agent.git ../securevibes-agent
cd ../securevibes-agent
npm install
npm run typecheck
```

The skill shells into `../securevibes-agent` for every new case it adds. If the install is missing, `sast-watch` still opens the PR with the new cases but marks each report block as `detected: unknown — sv-agent exited <code>`. Add the install and re-run with `launchctl kickstart` (or rerun the slash command interactively) to fill in the detection results as a follow-up comment.

## Testing the helpers

```bash
python3.11 -m pytest tests/test_sast_watch_helpers.py -v
```

15 unit tests cover state-file CRUD, the filter, the CWE bridge, and a round-trip schema-validation check on a built case.

## File layout

```
.claude/skills/
├── sast-watch/
│   ├── SKILL.md
│   ├── README.md
│   ├── scripts/
│   │   ├── state.py
│   │   ├── filter_advisories.py
│   │   └── build_case.py
│   └── state/
│       └── <owner>__<repo>.json    # seeded per target, then appended to
└── sast-watch-register/
    └── SKILL.md
```
