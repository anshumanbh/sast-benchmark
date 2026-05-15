---
name: sast-watch
description: Watch one upstream GitHub repo for new HIGH/CRITICAL Security Advisories in the last 24h, add each as a sast-benchmark case following the PR #5 methodology, open a PR, then run securevibes-agent against each new case and report detection results with root-cause analysis on misses. Invoke as `/sast-watch OWNER/REPO`.
argument-hint: "OWNER/REPO"
allowed-tools: Bash(gh *) Bash(git *) Bash(python3 *) Bash(python3.11 *) Bash(npm *) Bash(node *) Bash(ls *) Bash(cat *) Bash(jq *) Bash(test *) Bash(mkdir *) Read Write Edit Grep Glob
---

# /sast-watch — single-target advisory watcher

`$ARGUMENTS` must be a single GitHub identifier in `OWNER/REPO` form. If empty or malformed, print an error and exit non-zero.

`${CLAUDE_SKILL_DIR}` resolves to this skill's directory. The repo root is the current working directory. Always run from the repo root.

## Step 0 — Validate input and environment

```bash
REPO="$ARGUMENTS"
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "usage: /sast-watch OWNER/REPO"; exit 2; }
test -f manifest.json && test -d cases || { echo "must be run from sast-benchmark root"; exit 2; }
which gh git python3.11 jq >/dev/null || { echo "missing one of: gh git python3.11 jq"; exit 2; }
```

Pick `python3.11` (the version the repo's tests use). Replace with `python3` only if 3.11 isn't on PATH.

## Step 1 — Load (or seed) the state file

```bash
SLUG="${REPO/\//__}"
STATE="${CLAUDE_SKILL_DIR}/state/${SLUG}.json"
if [ ! -f "$STATE" ]; then
  python3.11 "${CLAUDE_SKILL_DIR}/scripts/state.py" seed \
    --manifest manifest.json --cases-dir cases \
    --repository "$REPO" --state-file "$STATE"
fi
```

State file shape: `{"repository": "...", "ghsa_ids": [...], "last_seen": "..." | null}`.

## Step 2 — Fetch advisories from GitHub

```bash
gh api "repos/$REPO/security-advisories" --paginate \
  | jq -s 'add // .' > /tmp/advisories.json
```

`gh api --paginate` emits one JSON array per page; `jq -s 'add'` flattens. The `// .` fallback handles single-page responses that aren't wrapped.

## Step 3 — Filter to new high/critical published in last 24h

```bash
CUTOFF=$(python3.11 -c "from datetime import datetime,timedelta,timezone; print((datetime.now(timezone.utc)-timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ'))")
python3.11 "${CLAUDE_SKILL_DIR}/scripts/filter_advisories.py" \
  --state-file "$STATE" --cutoff-iso "$CUTOFF" \
  --input /tmp/advisories.json > /tmp/new_advisories.json
NEW_COUNT=$(jq 'length' /tmp/new_advisories.json)
```

**Short-circuit when nothing is new:**

```bash
if [ "$NEW_COUNT" = "0" ]; then
  echo "no new advisories for $REPO"
  echo "NEW_ADVISORIES_COUNT=0"
  exit 0
fi
```

Do not create a branch, commit, or PR when count is zero.

## Step 4 — Per-advisory: derive timeline + build case (PR #5 methodology)

For each advisory in `/tmp/new_advisories.json`, perform the following inside the upstream clone (resolved from `--repo OWNER/NAME=PATH` in `CLAUDE.md`'s prerequisites — e.g. `../openclaw` for `openclaw/openclaw`).

Replicate the PR #5 recipe exactly. The skill (you, Claude) is responsible for the judgment calls; the helper scripts handle deterministic data-shaping.

1. **`vulnerableHead`** = commit SHA of the last release tag in the advisory's vulnerable range (e.g. the last vulnerable tag on the highest affected minor line).
   - `git -C $CLONE tag --sort=-version:refname` and pick the highest tag inside `vulnerableRange`.
   - `git -C $CLONE rev-parse <tag>^{commit}` → the SHA.

2. **Identify the affected files**: diff the last vulnerable tag against the patched tag, optionally cross-reference an explicit security commit (`Merge pull request from GHSA-...` or `Merge commit from fork`):
   ```bash
   git -C $CLONE diff --name-only <vh-tag>..<patched-tag>
   ```
   The list of files becomes `expectedOutcome.expectedPaths`.

3. **`introducingCommits[0]`** = earliest commit on an affected file that is an ancestor of `vulnerableHead` AND contains the vulnerable pattern. Use `git log -S` and blame on the lines the patch touches:
   ```bash
   git -C $CLONE log -S '<vulnerable-line-fragment>' --reverse \
       --ancestry-path <vh>..<affected-file>
   ```
   - If you find a **discrete bug-introducing commit** (e.g. a refactor that dropped a check, or a feature commit that introduced an unguarded dereference), set `verification.confidence = "high"` and put the commit SHA there.
   - If the vulnerable pattern is **present at file creation** (bug-since-inception), use the file-creation commit and set `verification.confidence = "medium"`. Document the reason in `timeline.notes`.
   - **Never** use a directory rename / tree-establishment refactor as the intro commit. PR #5 history shows this exact mistake being corrected in commit `11cd411`.

4. **`baselineCommit`** = parent of `introducingCommits[0]`:
   ```bash
   git -C $CLONE rev-parse <intro-sha>^
   ```

5. **Ancestry checks** — all three must pass:
   ```bash
   git -C $CLONE merge-base --is-ancestor $BASELINE $INTRO && echo baseline->intro=ok
   git -C $CLONE merge-base --is-ancestor $INTRO $VH       && echo intro->vh=ok
   git -C $CLONE merge-base --is-ancestor $BASELINE $VH    && echo baseline->vh=ok
   ```
   If any fails, abort this advisory and surface the failure — do not write a case with a broken ancestry chain.

6. **Pick `vulnerabilityClass`** from `scripts/taxonomy.py`. Most advisories map cleanly via the first CWE. For `abuse` and `brokenauthz` outcomes whose advisory CWE doesn't map (e.g. CWE-190 for `abuse`), `apply_cwe_bridge` will append a bridge CWE automatically.

7. **Write the timeline JSON to `/tmp/timeline-<GHSA>.json`** with this shape:
   ```json
   {
     "baselineCommit": "<40-hex>",
     "introducingCommits": [{"sha":"<40-hex>","authoredAt":"<iso>","subject":"<commit-subject>"}],
     "vulnerableHead": "<40-hex>",
     "notes": "<why-confidence-is-what-it-is + any file-renames noted>"
   }
   ```

8. **Build the case dict** and write `cases/<GHSA>/case.json`:
   ```bash
   mkdir -p "cases/$GHSA"
   python3.11 "${CLAUDE_SKILL_DIR}/scripts/build_case.py" \
     --advisory /tmp/advisory-$GHSA.json \
     --timeline /tmp/timeline-$GHSA.json \
     --repository "$REPO" \
     --vulnerability-class "$CLASS" \
     --expected-path "<file1>" --expected-path "<file2>" \
     --confidence "$CONFIDENCE" \
     > cases/$GHSA/case.json
   ```

9. **Append the six `verification.checks` entries** (the three boolean prose checks + the three machine-checked ancestry checks with `ancestor`/`descendant` fields). Use `jq` to splice them in:
   ```bash
   jq '.verification.checks = $checks' --argjson checks "$CHECKS" \
     cases/$GHSA/case.json > /tmp/_c && mv /tmp/_c cases/$GHSA/case.json
   ```
   The six checks (names, in order): `advisory_published`, `vulnerable_head_in_advisory_range`, `baseline_is_parent_of_earliest_intro`, `baseline_ancestor_of_intro`, `intro_ancestor_of_vulnerable_head`, `baseline_ancestor_of_vulnerable_head`. The last three include `ancestor` and `descendant` SHAs.

10. **Update `manifest.json`** — append a new entry mirroring the shape of the existing entries (id/severity/title/vulnerabilityClass/baselineCommit/vulnerableHead/verificationStatus/confidence) and bump `caseCount`. If `manifest.repositories` doesn't already include `$REPO`, add it.

11. **Append the GHSA to the state file**:
    ```bash
    python3.11 "${CLAUDE_SKILL_DIR}/scripts/state.py" add --state-file "$STATE" --ghsa-id "$GHSA"
    ```

**HackerOne-only reports**: if you discover one while researching the advisory, do not invent a synthetic GHSA. Skip it — the schema enforces the `GHSA-XXXX-XXXX-XXXX` pattern, and PR #5 documents the precedent.

## Step 5 — Validate before any PR work

```bash
python3.11 scripts/validate.py \
  --repo openclaw/openclaw=../openclaw \
  --repo TryGhost/Ghost=../ghost \
  --repo cosmos/cosmos-sdk=../cosmos-sdk \
  --repo CosmWasm/wasmd=../wasmd \
  --repo cosmos/ibc-go=../ibc-go \
  --repo cosmos/evm=../cosmos-evm \
  --repo cometbft/cometbft=../cometbft || { echo "validate.py failed; aborting"; exit 1; }
python3.11 -m pytest tests/ -q || { echo "pytest failed; aborting"; exit 1; }
```

Run with `--strict` only if every new case has `confidence: high`. If any are `medium`, omit `--strict` (matching PR #5's behavior for tree-establishment cases).

## Step 6 — Branch, commit, push, open the PR

```bash
TODAY=$(date -u +%Y-%m-%d)
BRANCH="sast-watch/${TODAY}-${SLUG}"
git checkout -b "$BRANCH"
git add cases/ manifest.json "$STATE"
git commit -m "Add $NEW_COUNT new $REPO advisory case(s)

$(jq -r '.[] | "- \(.ghsa_id) — \(.summary) (\(.severity))"' /tmp/new_advisories.json)
"
git push -u origin "$BRANCH"
gh pr create --base main --title "sast-watch: add $NEW_COUNT $REPO advisory case(s)" \
  --body "$(cat /tmp/pr-body.md)"
```

The PR body is built in Step 7 below.

## Step 7 — Run securevibes-agent against each new case + RCA

Securevibes-agent must be cloned and installed at `../securevibes-agent` (see README prerequisites). For each new case:

```bash
cd ../securevibes-agent
npm run runtime -- pr \
  --repo "$CLONE" \
  --base "$BASELINE_COMMIT" \
  --head "$VULNERABLE_HEAD" \
  --analysis-mode llm \
  --llm-model openai-codex/gpt-5.3-codex \
  > "/tmp/sv-${GHSA}.json" 2>&1
cd - >/dev/null
```

Parse the run output: did sv-agent report a finding whose `path` is in `expectedPaths` AND whose CWE maps to `vulnerabilityClass`? That mirrors `scripts/run.py`'s detection logic.

**Append a report block per case to the PR body:**

```markdown
### $GHSA — $TITLE

- detected: **yes** | **no**
- evidence: `<rule-id>` at `<file>:<line>`, severity=`<sev>`, cwe=`<CWE-id>` (when detected)
- broad-LLM layer: hit / miss
- specialist match: sandbox-boundary | approval-binding | path-boundary | redirect-leakage | channel-scope-authz | none
- root cause (on miss): <2-3 sentences>
- proposed new specialist (when no existing one fits): <2-3 sentences sketching the detector shape>
```

For misses, the RCA should answer concretely:
- Did the broad-LLM pass surface anything in the affected file at all? If yes, was the finding mis-classified or below the severity floor?
- Which specialist category (from the five listed in the securevibes-agent README) is the closest fit? If none — propose one in 2-3 sentences, naming the bug-class invariant the detector would check.

After writing all per-case blocks, push an empty commit + `gh pr comment` to attach the RCA, or edit the PR body in place with `gh pr edit --body-file /tmp/pr-body.md`.

## Step 8 — Final line

```bash
echo "NEW_ADVISORIES_COUNT=$NEW_COUNT"
```

This is the line the goal-prompt evaluator and the launchd log scanner watch for.

## Idempotence guarantees

- Re-invoking with the same state file: every advisory whose GHSA is in `state.ghsa_ids` is filtered out before any work begins.
- Branch name embeds the date, so a same-day re-invocation appends to the existing branch rather than colliding.
- `manifest.json` and `state.json` updates are JSON-key-keyed; duplicate-key writes are no-ops.

## Failure modes — abort cleanly, do NOT open a PR

- gh API rate-limited → exit 75 (`EX_TEMPFAIL`). The launchd plist's `KeepAlive` retries.
- Any ancestry check fails → log and skip that advisory; still process the rest.
- `validate.py` or `pytest` fails → roll back the branch (`git reset --hard origin/main`) and exit 1.
- securevibes-agent fails to run → still open the PR with the case, but mark each report as `detected: unknown — sv-agent exited <code>`.

## Where the state file lives

`${CLAUDE_SKILL_DIR}/state/<owner>__<repo>.json`. These files **are** checked in. They are the source of truth for "what has this watcher already seen" and they need to survive across launchd job restarts.
