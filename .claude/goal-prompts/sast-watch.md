# Goal prompt: SAST Benchmark advisory watcher

Paste the block below after `/goal ` (one goal per session). It is self-contained per the [`/goal` best practices](https://code.claude.com/docs/en/goal): one measurable end state, stated checks, constraints, and a turn cap.

---

Build an unattended scheduled watcher that detects new HIGH/CRITICAL GitHub Security Advisories on configured upstream repos and, for each new one, opens a PR in this repo (sast-benchmark) adding it as a benchmark case using the exact methodology proved in PR #5, then runs `anshumanbh/securevibes-agent` against the new case and reports detection results with a root-cause analysis on misses. Also build a one-shot bootstrap to register new target repos.

REQUIRED READING (do this first, do not skip):
- `gh pr view 5 --json title,body,commits,files` and `gh pr diff 5` — replicate this methodology exactly: `timeline.{baselineCommit, introducingCommits[0], vulnerableHead}` with all three `git merge-base --is-ancestor` checks recorded in `verification.checks`; append a CWE bridge (CWE-400 for `abuse`, CWE-863 for `brokenauthz`) when the advisory CWE does not already map via `scripts/taxonomy.py`; set `verification.confidence: high` only when a discrete bug-introducing commit is found (via `git log -S` / blame on patch-touched lines), else `medium` with the reason in `timeline.notes`; HackerOne-only reports are skipped because the schema requires a GHSA ID.
- `CLAUDE.md`, `schema/case.schema.json`, `scripts/validate.py`, `scripts/taxonomy.py`, `manifest.json`, and one existing case (e.g. `cases/GHSA-p22h-3m2v-cmgh/case.json`) for shape.
- https://code.claude.com/docs/en/scheduled-tasks and https://code.claude.com/docs/en/routines. Pick the option that (i) runs without an open CLI session, (ii) has local file access to sibling repo clones, (iii) can shell out to `git`/`gh`/`python3`/`npm`. Write the choice and a 5-line rationale to `.claude/skills/sast-watch/README.md`.
- https://github.com/anshumanbh/securevibes-agent README — capture install steps and the exact `npm run runtime -- pr ...` invocation.

DELIVERABLES — three files under `.claude/skills/`:

(A) `sast-watch/SKILL.md` (model-invocable, takes one arg `OWNER/REPO`):
  1. Load `.claude/skills/sast-watch/state/<owner>__<repo>.json`; seed from current `manifest.json` GHSAs for that repo if missing.
  2. `gh api "repos/$REPO/security-advisories" --paginate` → keep advisories where severity ∈ {high, critical} AND `published_at` is within the last 24h AND the GHSA is not in the state file AND no `cases/<GHSA>/case.json` exists. If none remain, print `NEW_ADVISORIES_COUNT=0` and exit 0. Do not branch, commit, or open a PR.
  3. For each new advisory, build `cases/<GHSA>/case.json` per the PR #5 recipe above; update `manifest.json`; append the GHSA to the state file.
  4. Gate: `python3 scripts/validate.py --repo …` (every sibling repo path from CLAUDE.md) AND `python3 -m pytest tests/` must both exit 0. If either fails, abort — do not open a PR with a failing case.
  5. Branch `sast-watch/<YYYY-MM-DD>-<owner>-<repo>`, commit, push, `gh pr create` against `main`.
  6. For each new case, run securevibes-agent: `npm run runtime -- pr --repo <clone> --base <baselineCommit> --head <vulnerableHead> --analysis-mode llm`. Append a report block to the PR body: `detected: yes/no`, evidence (rule IDs, paths, severity). On misses, RCA — did the broad-LLM layer miss the pattern? Is one of the existing specialists (sandbox-boundary, approval-binding, path-boundary, redirect-leakage, channel-scope-authz) the right fit? If none, propose the shape of a new specialist in 2-3 sentences.
  7. Print `NEW_ADVISORIES_COUNT=<n>` as the final line.

(B) `sast-watch-register/SKILL.md` with `disable-model-invocation: true`, takes one arg `OWNER/REPO`: validate (`gh api repos/$REPO`), seed the state file from the current manifest, install the chosen schedule for that target (write the launchd plist / print the `/schedule` line / write the Desktop task config — whichever was chosen in the rationale), and print verification output proving the schedule is registered.

(C) `sast-watch/README.md`: scheduling rationale + state-file format + manual-fire instructions + securevibes-agent install prereq + deregister steps.

SMOKE TESTS — every one must produce the stated output in the transcript before this goal is met:
- `ls .claude/skills/sast-watch/SKILL.md .claude/skills/sast-watch-register/SKILL.md .claude/skills/sast-watch/README.md` lists all three.
- `python3 -m pytest tests/` prints `passed` and exits 0.
- Invoke skill (A) against `cosmos/cosmos-sdk`: must print `NEW_ADVISORIES_COUNT=0` (PR #5 covered everything published through 2026-05-15), and `git status` is clean afterward.
- Invoke skill (B) against an untracked repo like `prometheus/prometheus`: prints the schedule-registration verification output and the state file exists.

CONSTRAINTS:
- TDD per the user's global CLAUDE.md: write a failing test for any new Python helper before implementing it.
- Idempotent: re-invoking skill (A) within 24h prints `NEW_ADVISORIES_COUNT=0`.
- Do not modify existing files under `cases/`, `schema/`, `scripts/run.py`, `scripts/validate.py`, `scripts/taxonomy.py`, or any test that currently passes.
- Stdlib + pytest only for any new Python. Shell out to `gh`, `git`, `python3`, `npm` — no new pip deps.

Stop after 35 turns or once every smoke-test command above has produced the stated output in the transcript.
