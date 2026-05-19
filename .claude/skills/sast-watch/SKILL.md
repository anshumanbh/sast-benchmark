---
name: sast-watch
description: Watch one upstream GitHub repo for new HIGH/CRITICAL Security Advisories in the last 24h, add each as a sast-benchmark case following the PR #5 methodology, open a PR, then run securevibes-agent against each new case and report detection results with root-cause analysis on misses. Invoke as `/sast-watch OWNER/REPO`.
argument-hint: "OWNER/REPO"
allowed-tools: Bash(gh *) Bash(git *) Bash(python3 *) Bash(python3.11 *) Bash(npm *) Bash(node *) Bash(ls *) Bash(cat *) Bash(jq *) Bash(test *) Bash(mkdir *) Bash(mktemp *) Bash(rm *) Bash(mv *) Bash(cp *) Bash(basename *) Bash(tr *) Bash(printf *) Bash(date *) Bash(which *) Bash(trap *) Bash(sed *) Bash(sleep *) Read Write Edit Grep Glob
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

# Refuse to run on a dirty checkout. Step 6's cleanup_working_tree calls
# `git reset --hard "$PRE_WORK_HEAD"` on a validate/pytest failure; if the
# user has uncommitted tracked-file edits in the shared launchd checkout,
# that reset would silently erase them.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "working tree has uncommitted tracked changes; refusing to run"
  echo "commit or stash before invoking /sast-watch"
  git status --short
  exit 2
fi

# Derive paths used by the pending-RCA retry below (and by Steps 1, 2, 8).
SLUG="${REPO/\//__}"
BASE_BRANCH="main"
PENDING_RCA_DIR="${CLAUDE_SKILL_DIR}/pending-rca"
PENDING_RCA_BODY="$PENDING_RCA_DIR/${SLUG}.md"
PENDING_RCA_BRANCH="$PENDING_RCA_DIR/${SLUG}.branch"
# Legacy format from an earlier implementation that persisted a PR number.
# Every place that removes the body file must also remove this, otherwise a
# stale .pr from a previously failed legacy retry would redirect a future
# branch-format RCA to the wrong PR.
PENDING_RCA_PR_LEGACY="$PENDING_RCA_DIR/${SLUG}.pr"

# resolve_clone_path probes sibling directories for a clone whose origin URL
# matches a manifest repo. Defined here (not inside Step 6) because Steps 5
# and 8 also need $CLONE — the watched repo's local checkout path.
resolve_clone_path() {
  local repo="$1"
  local owner="${repo%%/*}"
  local name="${repo#*/}"
  local owner_lc name_lc
  owner_lc=$(printf '%s' "$owner" | tr '[:upper:]' '[:lower:]')
  name_lc=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')
  local candidates=(
    "../$name_lc"
    "../${owner_lc}-${name_lc}"
    "../$(printf '%s' "$repo" | tr '/' '-' | tr '[:upper:]' '[:lower:]')"
    "../$name"
    "../$repo"
  )
  for candidate in "${candidates[@]}"; do
    [ -d "$candidate/.git" ] || continue
    local url url_lc
    url=$(git -C "$candidate" config --get remote.origin.url 2>/dev/null) || continue
    url_lc=$(printf '%s' "$url" | tr '[:upper:]' '[:lower:]')
    case "$url_lc" in
      *":$owner_lc/$name_lc"|*":$owner_lc/$name_lc.git"|*"/$owner_lc/$name_lc"|*"/$owner_lc/$name_lc.git")
        printf '%s' "$candidate"; return 0 ;;
    esac
  done
  return 1
}

# Resolve $CLONE for the watched $REPO BEFORE Step 5 (per-advisory work)
# needs it for timeline derivation and BEFORE Step 6 puts $REPO=$CLONE into
# REPO_FLAGS. An unset $CLONE would make REPO_FLAGS "$REPO=" — validate.py
# rejects that as an invalid mapping, and Step 8's sv-agent would get an
# empty --repo. Abort early with a clear message rather than letting that
# cascade into less-obvious errors deeper in the pipeline.
CLONE=$(resolve_clone_path "$REPO") \
  || { echo "could not locate local clone for watched repo '$REPO'"; \
       echo "clone it as a sibling directory (e.g. ../$(printf '%s' "${REPO#*/}" | tr '[:upper:]' '[:lower:]')) and re-run"; \
       exit 2; }

# Retry any pending RCA push left over from a prior run that failed Step 8.
# The case+state commit was already pushed by that prior run, so without this
# retry the GHSA's filter-out behavior in Step 4 of subsequent runs would
# mean the PR body never receives the detection/RCA blocks. We do this BEFORE
# Step 1's branch handling because `gh pr edit <pr-number>` operates on the
# PR directly and doesn't care what local branch is checked out.

# Try branch-format FIRST; fall back to legacy ${SLUG}.pr only if no
# ${SLUG}.branch file exists. A leftover legacy file from a failed earlier
# retry must never override a current branch-format body — Step 8 may have
# rewritten ${SLUG}.md with new content destined for a different PR.

if [ -f "$PENDING_RCA_BODY" ] && [ -f "$PENDING_RCA_BRANCH" ]; then
  # Current format: branch name persisted to ${SLUG}.branch — re-resolve the
  # PR for that branch each time. This is more resilient than storing a PR
  # number, because if Step 8 couldn't even resolve the PR, we still managed
  # to persist the body and a branch label, and recovery is possible whenever
  # gh comes back online.
  pending_branch=$(cat "$PENDING_RCA_BRANCH")
  # Use --state all so we can still update the body if the PR was merged or
  # closed between the original failed push and now. gh pr edit accepts a
  # merged/closed PR number and edits its body just fine; restricting to
  # --state open would strand the RCA body forever after merge.
  pending_pr=$(gh pr list --head "$pending_branch" --base "$BASE_BRANCH" \
                          --state all --json number --jq '.[0].number // empty' 2>/dev/null || true)
  if [ -n "$pending_pr" ]; then
    echo "retrying pending RCA push to PR #$pending_pr (branch '$pending_branch') from prior run"
    if gh pr edit "$pending_pr" --body-file "$PENDING_RCA_BODY"; then
      rm -f "$PENDING_RCA_BODY" "$PENDING_RCA_BRANCH" "$PENDING_RCA_PR_LEGACY"
      echo "pending RCA pushed successfully"
    else
      echo "WARNING: pending RCA push still failing; will retry on next watcher fire"
      # Do not abort — letting new advisories accumulate is worse than missing
      # an RCA on an already-merged-or-mergeable PR.
    fi
  else
    echo "WARNING: pending RCA body exists for branch '$pending_branch' but no PR (open/merged/closed) found; leaving files in place"
  fi
elif [ -f "$PENDING_RCA_BODY" ] && [ -f "$PENDING_RCA_PR_LEGACY" ]; then
  # Legacy fallback: only consulted when no ${SLUG}.branch exists. Prior
  # implementations persisted a PR number to ${SLUG}.pr instead.
  legacy_pr=$(cat "$PENDING_RCA_PR_LEGACY")
  echo "retrying legacy-format pending RCA push to PR #$legacy_pr from prior run"
  if gh pr edit "$legacy_pr" --body-file "$PENDING_RCA_BODY"; then
    rm -f "$PENDING_RCA_BODY" "$PENDING_RCA_PR_LEGACY"
    echo "legacy pending RCA pushed successfully"
  else
    echo "WARNING: legacy pending RCA push still failing; leaving files in place"
  fi
fi
```

Pick `python3.11` (the version the repo's tests use). Replace with `python3` only if 3.11 isn't on PATH.

## Step 1 — Reuse same-day branch if it exists

The same-day branch may already exist from a partial earlier run or an earlier batch of advisories on the same UTC day. It may also exist **only on the remote** — e.g. a different machine ran the watcher earlier today and pushed, but this checkout never pulled the branch. **Check it out before doing anything that reads or writes files** — otherwise Step 5's case writes and `manifest.json` edits will conflict with the branch's committed changes, and the state file the filter reads in Step 2 will be the stale `main` copy instead of the branch's up-to-date copy. Without the origin-side check, Step 7 would create the branch from `main` and `git push -u` would fail every run because the remote already has divergent history.

```bash
# $SLUG and $BASE_BRANCH were set in Step 0; reuse them here.
TODAY=$(date -u +%Y-%m-%d)
BRANCH="sast-watch/${TODAY}-${SLUG}"

# Capture the branch the watcher was launched from. launchd jobs share this
# checkout across targets, so every exit path must restore it — otherwise a
# later run for a different target inherits the wrong branch.
ORIGINAL_BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null) || ORIGINAL_BRANCH=""

# Authoritatively check whether origin has $BRANCH. `git ls-remote --exit-code`
# returns 0 on match, 2 on definitive no-match, and other codes on transient
# failure (network, auth, etc.). We MUST distinguish those: treating a
# transient failure as "branch missing" would prune the tracking ref and the
# stale-local-only path below would then delete a valid local same-day branch.
git ls-remote --heads --exit-code origin "$BRANCH" >/dev/null 2>&1
LS_REMOTE_RC=$?
case "$LS_REMOTE_RC" in
  0)
    # Remote has the branch — refresh the tracking ref.
    git fetch origin "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH" \
      || { echo "fetch of '$BRANCH' failed; aborting to avoid acting on stale tracking ref"; exit 1; }
    ;;
  2)
    # Remote definitively does not have the branch — safe to prune any
    # stale tracking ref left from a previous fetch.
    git update-ref -d "refs/remotes/origin/$BRANCH" 2>/dev/null || true
    ;;
  *)
    echo "git ls-remote origin '$BRANCH' failed with exit $LS_REMOTE_RC"
    echo "transient network/auth error — aborting rather than risk pruning a valid branch"
    exit 1
    ;;
esac

# Refresh the base branch so any "create from base" path in Step 7 starts from
# the latest commit. Without this, after a prior same-day PR is merged, local
# $BASE_BRANCH is missing the merge commit; a new branch from stale base would
# re-introduce the just-merged manifest/state changes and fail validation.
# All commands below abort the run on failure rather than silently
# continuing on stale base — a diverged local $BASE_BRANCH would otherwise
# go unnoticed and the watcher would open PRs from outdated history.
git fetch origin "$BASE_BRANCH" \
  || { echo "fetch of origin/$BASE_BRANCH failed (network/auth?); aborting"; exit 1; }

# Explicitly check the relationship between local and remote base. `git merge
# --ff-only origin/$BASE_BRANCH` returns success when origin is an *ancestor*
# of local (local is ahead) — that path would leave local-only commits on the
# checkout, and Step 7 would branch from a base that includes them.
if git show-ref --verify --quiet "refs/heads/$BASE_BRANCH"; then
  LOCAL_BASE=$(git rev-parse "$BASE_BRANCH")
  REMOTE_BASE=$(git rev-parse "origin/$BASE_BRANCH")
  if [ "$LOCAL_BASE" = "$REMOTE_BASE" ]; then
    : # in sync; no action needed
  elif git merge-base --is-ancestor "$LOCAL_BASE" "$REMOTE_BASE"; then
    # Local is behind remote — fast-forward it.
    if [ "$ORIGINAL_BRANCH" = "$BASE_BRANCH" ]; then
      git merge --ff-only "origin/$BASE_BRANCH" \
        || { echo "ff-merge of origin/$BASE_BRANCH into '$BASE_BRANCH' failed; aborting"; exit 1; }
    else
      git fetch origin "$BASE_BRANCH:$BASE_BRANCH" \
        || { echo "could not fast-forward local '$BASE_BRANCH'; aborting"; exit 1; }
    fi
  else
    # Local is ahead of or diverged from origin — refuse to proceed.
    echo "local '$BASE_BRANCH' has commits not in origin/$BASE_BRANCH (ahead or diverged)"
    echo "the watcher must run from a base in sync with origin; manual intervention required"
    exit 1
  fi
fi

if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
  if git show-ref --verify --quiet "refs/remotes/origin/$BRANCH"; then
    # Both local and remote exist — normal same-day reuse. Fast-forward local
    # to match remote before Step 2 reads $STATE; another machine may have
    # pushed an earlier same-day batch whose state additions we'd otherwise miss.
    git checkout "$BRANCH" \
      || { echo "failed to checkout existing '$BRANCH'; aborting"; exit 1; }
    git merge --ff-only "origin/$BRANCH" \
      || { echo "local '$BRANCH' has diverged from origin; manual intervention needed"; exit 1; }
    BRANCH_EXISTED_BEFORE=1
  else
    # Local-only — the remote branch was deleted, typically because the PR was
    # merged or closed and GitHub auto-deleted the head ref. The local branch
    # holds post-PR state that no longer reflects $BASE_BRANCH; reusing it
    # would mean committing a same-day second batch on top of stale, already-
    # merged work. Discard the stale local branch and fall through to the
    # "no branch" path so Step 7 creates a fresh branch from $BASE_BRANCH.
    echo "local '$BRANCH' has no remote counterpart (PR likely merged); discarding stale local branch"
    # If we're currently ON $BRANCH (launchd inherited a checkout from a prior
    # same-day run, or ORIGINAL_BRANCH itself is $BRANCH), we cannot delete it
    # while checked out. Switch to the freshly-synced $BASE_BRANCH and rewrite
    # ORIGINAL_BRANCH so the end-of-run restore_original_branch doesn't try to
    # return to the about-to-be-deleted branch.
    CURRENT=$(git symbolic-ref --short HEAD 2>/dev/null || echo "")
    if [ "$CURRENT" = "$BRANCH" ] || [ "$ORIGINAL_BRANCH" = "$BRANCH" ] || [ -z "$ORIGINAL_BRANCH" ]; then
      git checkout "$BASE_BRANCH"
      ORIGINAL_BRANCH="$BASE_BRANCH"
    elif [ "$CURRENT" != "$ORIGINAL_BRANCH" ]; then
      git checkout "$ORIGINAL_BRANCH" 2>/dev/null || git checkout "$BASE_BRANCH"
    fi
    git branch -D "$BRANCH" 2>/dev/null || true
    BRANCH_EXISTED_BEFORE=0
  fi
elif git show-ref --verify --quiet "refs/remotes/origin/$BRANCH"; then
  # Remote-only — create a local branch tracking the remote so subsequent
  # commits land on the same history and `git push` is a fast-forward.
  git checkout -b "$BRANCH" --track "origin/$BRANCH" \
    || { echo "failed to create tracking branch for '$BRANCH'; aborting"; exit 1; }
  BRANCH_EXISTED_BEFORE=1
else
  BRANCH_EXISTED_BEFORE=0
fi

# When falling through to "create from base" (BRANCH_EXISTED_BEFORE=0), make
# sure we're actually on $BASE_BRANCH so Step 7's `git checkout -b "$BRANCH"`
# branches from the refreshed base. Otherwise launchd starting on a feature
# branch or a different stale watcher branch would seed the new PR with
# unrelated commits.
if [ "$BRANCH_EXISTED_BEFORE" = "0" ]; then
  if [ "$(git symbolic-ref --short HEAD 2>/dev/null)" != "$BASE_BRANCH" ]; then
    git checkout "$BASE_BRANCH" \
      || { echo "could not switch to '$BASE_BRANCH'; aborting"; exit 1; }
  fi
fi

# Capture the working-tree baseline. Step 6 (validate/pytest) and Step 7
# (push/PR) both use it to roll back partial edits on failure.
PRE_WORK_HEAD=$(git rev-parse HEAD)
```

If neither local nor remote has the branch, stay on the current branch (typically `main`). Step 7 creates the branch only when there are advisories to commit, so a no-advisories run leaves no unused branch behind. `BRANCH_EXISTED_BEFORE` controls Step 7's rollback path: a brand-new branch can be deleted outright on failure, while a pre-existing branch (local or remote-tracking) must be force-reset so prior batch commits aren't destroyed.

Define a helper that returns the checkout to `$ORIGINAL_BRANCH`. Every clean exit (no-op short-circuit, end of Step 9) calls it. Failure paths that delete the branch (`rollback_branch` for brand-new) already switch off the branch on their own; failure paths that exit on a pre-existing branch leave that branch checked out because there is no "previous branch" semantics worth restoring after a partial run aborts mid-flight, and a human investigating will see exactly where the failure happened.

```bash
restore_original_branch() {
  [ -z "$ORIGINAL_BRANCH" ] && return 0
  local current
  current=$(git symbolic-ref --short HEAD 2>/dev/null || echo "")
  [ "$current" = "$ORIGINAL_BRANCH" ] && return 0
  git checkout "$ORIGINAL_BRANCH" \
    || { echo "WARNING: could not restore checkout to '$ORIGINAL_BRANCH' from '$current'"; return 1; }
}
```

## Step 2 — Load (or seed) the state file

```bash
STATE="${CLAUDE_SKILL_DIR}/state/${SLUG}.json"
STATE_CREATED_THIS_RUN=0
if [ ! -f "$STATE" ]; then
  python3.11 "${CLAUDE_SKILL_DIR}/scripts/state.py" seed \
    --manifest manifest.json --cases-dir cases \
    --repository "$REPO" --state-file "$STATE"
  STATE_CREATED_THIS_RUN=1
fi
```

State file shape: `{"repository": "...", "ghsa_ids": [...], "last_seen": "..." | null}`. Because Step 1 already switched to the same-day branch when it exists, `$STATE` here is the branch-local copy (which includes GHSAs from earlier same-day batches), so Step 4's filter correctly drops them.

`STATE_CREATED_THIS_RUN` records whether this run seeded a brand-new state file (only true on the very first run for a target). Step 6's cleanup uses it to decide whether to remove `$STATE` on a failure path; if a prior run already committed the file, we must leave it alone.

## Step 3 — Fetch advisories from GitHub

```bash
gh api "repos/$REPO/security-advisories" --paginate \
  | jq -s 'add // .' > /tmp/advisories.json
```

`gh api --paginate` emits one JSON array per page; `jq -s 'add'` flattens. The `// .` fallback handles single-page responses that aren't wrapped.

## Step 4 — Filter to new high/critical published in last 24h

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
  # Before declaring success, detect an orphaned branch: a prior run may
  # have pushed the case+state commit but died before gh pr create succeeded
  # (process killed, OOM, shutdown). In that case the GHSA is in $STATE on
  # the branch — so the filter dropped it — yet no PR exists. Without this
  # check the watcher would exit success forever and the advisory would
  # never get a PR.
  #
  # The check is "no PR of ANY state AND branch tip not in base", not just
  # "no open PR". If a PR was merged or closed, the branch is already
  # handled — GitHub may have left the head ref in place (auto-delete off).
  # Likewise, if the branch tip is already an ancestor of origin/$BASE_BRANCH,
  # the work landed via a merge and the branch isn't really orphaned.
  if [ "$BRANCH_EXISTED_BEFORE" = "1" ]; then
    # Lookup with retry: a transient gh/API failure must NOT be treated as
    # "no PR" — that would mis-diagnose an existing branch with a real open
    # PR as orphaned and abort.
    any_pr_state=""
    lookup_ok=0
    for attempt in 1 2 3; do
      if any_pr_state=$(gh pr list --head "$BRANCH" --base "$BASE_BRANCH" --state all \
                                   --json state --jq '.[0].state // empty' 2>&1); then
        lookup_ok=1
        break
      fi
      echo "gh pr list attempt $attempt/3 (orphan check for '$BRANCH') failed; retrying in $((attempt * 2))s"
      sleep $((attempt * 2))
    done
    if [ "$lookup_ok" = "0" ]; then
      echo "gh pr list failed after 3 attempts; cannot determine PR state for '$BRANCH'"
      echo "  aborting to avoid mis-diagnosing as orphaned; next run will retry"
      restore_original_branch
      exit 1
    fi
    case "$any_pr_state" in
      OPEN|MERGED|CLOSED)
        : # PR exists in some state — branch is handled, not orphaned.
        ;;
      *)
        # No PR of any state found. Check if branch tip is already merged
        # into base (manual merge without a PR — uncommon but possible).
        branch_tip=$(git rev-parse "$BRANCH" 2>/dev/null || echo "")
        if [ -n "$branch_tip" ] \
           && git merge-base --is-ancestor "$branch_tip" "origin/$BASE_BRANCH" 2>/dev/null; then
          : # branch already in base — not orphaned.
        else
          echo "ERROR: branch '$BRANCH' exists with pushed state but has no PR (open/closed/merged)"
          echo "  and its tip is not in origin/$BASE_BRANCH"
          echo "  this suggests a prior run was killed between 'git push' and PR creation"
          echo "  investigate and recover manually, e.g.:"
          echo "    gh pr create --base $BASE_BRANCH --head $BRANCH --title '...' --body-file ..."
          restore_original_branch
          exit 1
        fi
        ;;
    esac
  fi
  restore_original_branch
  echo "NEW_ADVISORIES_COUNT=0"
  exit 0
fi
```

Do not create a branch, commit, or PR when count is zero. `restore_original_branch` is essential here: Step 1 may have checked out the same-day branch already, and exiting without restoring would leave the shared launchd checkout on the wrong branch for the next target's run.

## Step 5 — Per-advisory: derive timeline + build case (PR #5 methodology)

Allocate two per-run staging files **before** the loop begins. A fixed path like `/tmp/processed_ghsas.txt` would let a stale file from a prior failed run — or a concurrent run for another target — leak GHSAs into the wrong state file:

```bash
PROCESSED_FILE=$(mktemp -t sast-watch-processed.XXXXXX)
CREATED_CASES_FILE=$(mktemp -t sast-watch-created-cases.XXXXXX)
trap 'rm -f "$PROCESSED_FILE" "$CREATED_CASES_FILE"' EXIT
```

`$PROCESSED_FILE` records GHSAs successfully built (used by Step 7 to write state). `$CREATED_CASES_FILE` records only the case directories this run *created from scratch* — used by `cleanup_working_tree` so it never deletes a restored pre-existing tracked case directory (e.g. when state is stale or missing and Step 5 re-processes a GHSA whose `cases/$GHSA/` already exists from a prior merged PR).

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

3. **`introducingCommits[0]`** = earliest commit on an affected file that is an ancestor of `vulnerableHead` AND contains the vulnerable pattern. Use `git log -S` and blame on the lines the patch touches. The file path must come after `--` as a pathspec — never inside a revision range:
   ```bash
   git -C $CLONE log -S '<vulnerable-line-fragment>' --reverse \
       "$VH" -- "<affected-file>"
   ```
   When you already have a baseline candidate to bound the search, use a real revision range plus the pathspec:
   ```bash
   git -C $CLONE log -S '<vulnerable-line-fragment>' --reverse \
       --ancestry-path "<baseline-candidate>..$VH" -- "<affected-file>"
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

8. **Build the case dict** and write `cases/<GHSA>/case.json`. **Before** `mkdir -p`, record whether the directory pre-existed — if not, add this GHSA to `$CREATED_CASES_FILE` so cleanup can safely remove it later:
   ```bash
   [ -d "cases/$GHSA" ] || echo "$GHSA" >> "$CREATED_CASES_FILE"
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
   If `cases/$GHSA/` already exists (e.g. a prior merged PR added it and state is stale), the GHSA is **not** recorded in `$CREATED_CASES_FILE` — `git reset --hard "$PRE_WORK_HEAD"` will restore the original `case.json`, and cleanup must leave the directory intact.

9. **Append the six `verification.checks` entries** (the three boolean prose checks + the three machine-checked ancestry checks with `ancestor`/`descendant` fields). Use `jq` to splice them in:
   ```bash
   jq '.verification.checks = $checks' --argjson checks "$CHECKS" \
     cases/$GHSA/case.json > /tmp/_c && mv /tmp/_c cases/$GHSA/case.json
   ```
   The six checks (names, in order): `advisory_published`, `vulnerable_head_in_advisory_range`, `baseline_is_parent_of_earliest_intro`, `baseline_ancestor_of_intro`, `intro_ancestor_of_vulnerable_head`, `baseline_ancestor_of_vulnerable_head`. The last three include `ancestor` and `descendant` SHAs.

10. **Update `manifest.json`** — append a new entry mirroring the shape of the existing entries (id/severity/title/vulnerabilityClass/baselineCommit/vulnerableHead/verificationStatus/confidence) and bump `caseCount`. If `manifest.repositories` doesn't already include `$REPO`, add it.

11. **Stage the GHSA for state update** by appending the ID to `$PROCESSED_FILE` (the per-run mktemp path allocated at the top of this step). **Do not** write to `$STATE` yet — that happens only after Step 7 confirms the PR is open. If validation, branch, push, or `gh pr create` fails, the state stays untouched and the next scheduled run retries this advisory.

**HackerOne-only reports**: if you discover one while researching the advisory, do not invent a synthetic GHSA. Skip it — the schema enforces the `GHSA-XXXX-XXXX-XXXX` pattern, and PR #5 documents the precedent.

## Step 6 — Validate before any PR work

Build the `--repo` flag list dynamically so any target registered after this skill was written still validates. Always include the resolved `$REPO=$CLONE` for the watched target; for every other repository in `manifest.repositories`, use the sibling-clone convention `../<lowercase-basename>`. Override per repo if your local layout differs.

If validation or the test suite fails, **clean up Step 5's partial edits before exiting** — otherwise a reused same-day branch carries the half-written cases and modified `manifest.json` into the next run, where Step 5 would re-write them and produce duplicate entries that `validate.py` rejects. `PRE_WORK_HEAD` was captured in Step 1, before any writes.

The cleanup must be **scoped to this run's artefacts only**. A broad `git clean -fd cases/` would also delete untracked case directories left by another target's concurrent run (the watcher can fire for multiple targets) or an unrelated work-in-progress case the user has on disk. Same with `git clean -fd "$(dirname "$STATE")"` — it would wipe other watchers' state files. Use `$CREATED_CASES_FILE` (case dirs this run created from scratch — *not* `$PROCESSED_FILE`, which also contains GHSAs whose dirs pre-existed) and `STATE_CREATED_THIS_RUN` (set in Step 2) to remove exactly what this run brought into being:

```bash
cleanup_working_tree() {
  echo "rolling back partial Step 5 edits to $PRE_WORK_HEAD"
  # Revert tracked files (manifest.json, any tracked cases/<GHSA>/case.json
  # from prior batches that Step 5 might have re-touched).
  git reset --hard "$PRE_WORK_HEAD"
  # Remove only the case directories this run created from scratch.
  # Dirs that pre-existed (e.g. prior merged PR + stale $STATE causing
  # re-processing) are NOT in $CREATED_CASES_FILE — git reset already
  # restored their original contents and rm -rf'ing them would be a data loss.
  if [ -s "$CREATED_CASES_FILE" ]; then
    while IFS= read -r ghsa; do
      [ -n "$ghsa" ] && rm -rf "cases/$ghsa"
    done < "$CREATED_CASES_FILE"
  fi
  # Remove $STATE only if this run seeded it; otherwise it's a committed
  # file from a prior batch and git reset --hard already restored it.
  if [ "$STATE_CREATED_THIS_RUN" = "1" ]; then
    rm -f "$STATE"
  fi
  # Return the shared launchd checkout to its original branch so the next
  # target's run starts from a known baseline.
  restore_original_branch
}

# $CLONE was resolved in Step 0 via resolve_clone_path; reuse it here.
# For every other manifest repo, probe sibling directories the same way.
REPO_FLAGS=("--repo" "$REPO=$CLONE")
while IFS= read -r r; do
  [ "$r" = "$REPO" ] && continue
  path=$(resolve_clone_path "$r") \
    || { echo "could not locate local clone for '$r'; checked ../basename, ../owner-name, ../owner-name-slug"; \
         echo "clone the repo as a sibling directory and re-run, or pre-set a matching path"; \
         cleanup_working_tree; exit 1; }
  REPO_FLAGS+=("--repo" "$r=$path")
done < <(jq -r '.repositories[]' manifest.json)

python3.11 scripts/validate.py "${REPO_FLAGS[@]}" \
  || { echo "validate.py failed; aborting"; cleanup_working_tree; exit 1; }
python3.11 -m pytest tests/ -q \
  || { echo "pytest failed; aborting"; cleanup_working_tree; exit 1; }
```

Run with `--strict` only if every new case has `confidence: high`. If any are `medium`, omit `--strict` (matching PR #5's behavior for tree-establishment cases).

## Step 7 — Commit, push, open (or update) the PR

Step 1 already switched to `$BRANCH` if it existed. If we're still on the base branch (no same-day branch yet), create it now — we know there are advisories because Step 4's short-circuit didn't fire.

**Apply the state updates to the working tree first, then commit cases + manifest + state as one atomic commit.** Folding the state file into the case commit means a single `git push` covers all three; if the push (or the later PR step) fails, the `rollback_branch` helper resets the whole commit and the working-tree state file together. The earlier two-step "case commit, then state commit" design left a window where the state could diverge from the PR branch — if the second push failed, `$STATE` was locally ahead of the remote PR, and a later merge to `main` would silently drop the processed-GHSA record.

**Capture the pre-commit HEAD before committing**, so any later failure can roll the branch back to a clean state. Without this rollback, the pushed case commit and `manifest.json` entry would remain on the branch with `$STATE` reverted; the next scheduled run would re-process the same GHSA and append a duplicate manifest entry, blowing up `validate.py`.

```bash
if [ "$(git rev-parse --abbrev-ref HEAD)" != "$BRANCH" ]; then
  # Step 1 ensured we're on $BASE_BRANCH whenever BRANCH_EXISTED_BEFORE=0,
  # so HEAD == PRE_WORK_HEAD == refreshed origin/$BASE_BRANCH tip.
  git checkout -b "$BRANCH"
fi

# Apply processed-GHSA updates to the on-disk state file BEFORE staging.
# Failure here must revert ALL of Step 5's edits — cases, manifest.json, and
# the state file — not just $STATE; otherwise the next run inherits dirty
# partial cases that Step 5 would re-write into duplicate manifest entries.
while IFS= read -r ghsa; do
  python3.11 "${CLAUDE_SKILL_DIR}/scripts/state.py" add \
    --state-file "$STATE" --ghsa-id "$ghsa" \
    || { echo "state.py add failed for $ghsa; cleaning up Step 5 edits"; \
         cleanup_working_tree; \
         exit 1; }
done < "$PROCESSED_FILE"

git add cases/ manifest.json "$STATE"
git commit -m "Add $NEW_COUNT new $REPO advisory case(s) + state

$(jq -r '.[] | "- \(.ghsa_id) — \(.summary) (\(.severity))"' /tmp/new_advisories.json)
"
git push -u origin "$BRANCH" || {
  echo "git push failed; resetting local branch and working tree to pre-commit HEAD"
  git reset --hard "$PRE_WORK_HEAD"
  # If $STATE was untracked before this commit, the reset removed it; re-seed on next run.
  # Restore the launchd-shared checkout to its original branch. For a brand-new
  # local branch (BRANCH_EXISTED_BEFORE=0, no remote because push failed),
  # also delete the local ref — otherwise the next run inherits it as
  # ORIGINAL_BRANCH and Step 1's branch logic gets confused.
  restore_original_branch
  if [ "$BRANCH_EXISTED_BEFORE" = "0" ]; then
    git branch -D "$BRANCH" 2>/dev/null || true
  fi
  exit 1
}
```

Build an initial PR body **before** opening or updating the PR. Per-case detection reports are appended in Step 8 via `gh pr edit --body-file`, so the PR is never opened with an empty `--body`:

```bash
cat > /tmp/pr-body.md <<EOF
## Summary

sast-watch found $NEW_COUNT new HIGH/CRITICAL advisory case(s) for \`$REPO\` on $TODAY.

$(jq -r '.[] | "- \(.ghsa_id) — \(.summary) (\(.severity))"' /tmp/new_advisories.json)

Per-case detection reports and root-cause analysis are appended below once securevibes-agent finishes (Step 8).
EOF
```

Define a rollback helper used by every PR-step failure path. It restores the local branch to `$PRE_WORK_HEAD` and reconciles the remote so the next run sees a clean state:

```bash
rollback_branch() {
  echo "rolling back branch '$BRANCH' to pre-commit HEAD"
  git reset --hard "$PRE_WORK_HEAD"
  if [ "$BRANCH_EXISTED_BEFORE" = "1" ]; then
    # Pre-existing branch — force-reset the remote so prior-batch commits
    # before our commit stay intact, but our orphaned commit is undone.
    git push --force-with-lease origin "$BRANCH" \
      || { echo "force-reset of remote failed; manual cleanup needed"; exit 1; }
    restore_original_branch
  else
    # Brand-new branch — delete it locally and remotely; next run starts fresh.
    # Switch off via $ORIGINAL_BRANCH (not `git checkout -`, which could land
    # on an unrelated branch the launchd-shared checkout was previously on),
    # then drop the local ref before attempting the remote delete.
    restore_original_branch
    git branch -D "$BRANCH" 2>/dev/null || true
    # The remote delete is NOT optional: the atomic case+state commit was
    # already pushed, so if the remote branch survives, the next run's Step 1
    # would check it out (via origin/$BRANCH tracking), Step 2 would read a
    # $STATE that already contains the GHSA, and Step 4 would filter it out
    # silently — no PR, but the advisory is recorded as processed.
    git push origin --delete "$BRANCH" \
      || { echo "ERROR: failed to delete remote '$BRANCH'; pushed state commit is orphaned"; \
           echo "       run 'git push origin --delete $BRANCH' manually before the next watcher fire"; \
           exit 1; }
  fi
  exit 1
}
```

If a PR is already open against `$BRANCH` (a partial earlier run, or a same-day second batch), `gh pr create` would fail with "a pull request for branch ... already exists". Detect and reuse it; when reusing, **prepend** the existing PR body so earlier batch summaries and Step 8 RCA blocks aren't dropped. Any failure inside this block invokes `rollback_branch`:

```bash
EXISTING_PR=$(gh pr list --head "$BRANCH" --base main --state open \
  --json number --jq '.[0].number // empty') \
  || { echo "gh pr list failed"; rollback_branch; }
if [ -n "$EXISTING_PR" ]; then
  echo "reusing existing PR #$EXISTING_PR on $BRANCH"
  gh pr view "$EXISTING_PR" --json body --jq .body > /tmp/pr-body.prior.md \
    || { echo "gh pr view failed"; rollback_branch; }
  {
    cat /tmp/pr-body.prior.md
    printf '\n\n---\n\n'
    cat /tmp/pr-body.md
  } > /tmp/pr-body.merged.md
  mv /tmp/pr-body.merged.md /tmp/pr-body.md
  gh pr edit "$EXISTING_PR" --body-file /tmp/pr-body.md \
    || { echo "gh pr edit failed"; rollback_branch; }
else
  gh pr create --base main \
    --title "sast-watch: add $NEW_COUNT $REPO advisory case(s)" \
    --body-file /tmp/pr-body.md \
    || { echo "gh pr create failed"; rollback_branch; }
fi
```

After this block, `/tmp/pr-body.md` holds the full PR body (prior content + this batch). Step 8 appends per-case reports to that same file and pushes them with `gh pr edit --body-file /tmp/pr-body.md`, so RCA from earlier batches is preserved across same-day runs.

State is already persisted — it went out in the atomic commit pushed above. There is no separate state commit, so there is no separate push that could fail and leave the branch out of sync with `$STATE`. If `gh pr create`/`gh pr edit` fails, `rollback_branch` reverts the case+state commit (local and remote) and exits, so the next scheduled run starts from a clean slate and reprocesses the same advisories.

## Step 8 — Run securevibes-agent against each new case + RCA

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

**Append a report block per case to `/tmp/pr-body.md` (the same file the PR was opened with):**

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

After writing all per-case blocks, replace the PR body in place. The state+case commit is already pushed at this point, so the next watcher run's Step 4 filter will drop these GHSAs — meaning if this `gh pr edit` fails and we exit, the RCA never reaches the PR. To avoid that:

1. **Persist the body and the branch name BEFORE any `gh` calls.** A transient `gh pr view` / `gh pr list` failure could otherwise exit before anything is persisted, leaving the next run with nothing to retry.
2. Resolve the PR number from the branch (with retry).
3. Retry the body push inline up to three times with exponential backoff (handles transient `gh`/network errors).
4. On total failure, leave the persisted files in place, restore the original branch (so the shared launchd checkout isn't stranded on the watch branch), and exit non-zero — Step 0 of the next run will resolve the PR by branch and retry.

```bash
# Persist body + branch FIRST so any subsequent gh failure still leaves a
# recoverable artifact for Step 0 of the next run.
#
# Also remove any stale legacy ${SLUG}.pr from a prior failed-legacy retry:
# without this, the next run's Step 0 would still see ${SLUG}.pr alongside
# the new body. Even though Step 0 now prefers .branch over .pr, deleting
# the stale file removes the ambiguity entirely.
mkdir -p "$PENDING_RCA_DIR"
cp /tmp/pr-body.md "$PENDING_RCA_BODY"
printf '%s\n' "$BRANCH" > "$PENDING_RCA_BRANCH"
rm -f "$PENDING_RCA_PR_LEGACY"

# Resolve the PR for $BRANCH (retry transient failures). Use --state all so
# we still find and update the body if the PR was merged or closed during
# the sv-agent run — gh pr edit accepts a non-open PR number.
PR_NUMBER=""
for attempt in 1 2 3; do
  PR_NUMBER=$(gh pr list --head "$BRANCH" --base "$BASE_BRANCH" --state all \
                         --json number --jq '.[0].number // empty' 2>/dev/null || true)
  [ -n "$PR_NUMBER" ] && break
  echo "gh pr list attempt $attempt/3 (resolving PR for '$BRANCH') failed or empty; retrying in $((attempt * 2))s"
  sleep $((attempt * 2))
done

if [ -z "$PR_NUMBER" ]; then
  echo "could not resolve open PR for branch '$BRANCH' after 3 attempts"
  echo "  body persisted to:   $PENDING_RCA_BODY"
  echo "  branch persisted to: $PENDING_RCA_BRANCH"
  echo "  next watcher run's Step 0 will retry resolving the PR and pushing"
  restore_original_branch
  exit 1
fi

# Push the body with retry.
RCA_OK=0
for attempt in 1 2 3; do
  if gh pr edit "$PR_NUMBER" --body-file "$PENDING_RCA_BODY"; then
    RCA_OK=1
    rm -f "$PENDING_RCA_BODY" "$PENDING_RCA_BRANCH" "$PENDING_RCA_PR_LEGACY"
    break
  fi
  echo "gh pr edit attempt $attempt/3 failed; retrying in $((attempt * 2))s"
  sleep $((attempt * 2))
done

if [ "$RCA_OK" = "0" ]; then
  echo "gh pr edit (final RCA push to PR #$PR_NUMBER) failed after 3 attempts"
  echo "  body persisted to:   $PENDING_RCA_BODY"
  echo "  branch persisted to: $PENDING_RCA_BRANCH"
  echo "  next watcher run's Step 0 will retry pushing"
  restore_original_branch
  exit 1
fi
```

## Step 9 — Final line

Restore the checkout to `$ORIGINAL_BRANCH` so the shared launchd workspace is clean for the next target's run, then emit the marker line:

```bash
restore_original_branch
echo "NEW_ADVISORIES_COUNT=$NEW_COUNT"
```

This is the line the goal-prompt evaluator and the launchd log scanner watch for.

## Idempotence guarantees

- Re-invoking with the same state file: every advisory whose GHSA is in `state.ghsa_ids` is filtered out before any work begins.
- Branch name embeds the date; same-day re-invocation reuses the existing branch (Step 1 checks `git show-ref` and switches before any file edits).
- Cases, `manifest.json`, and `$STATE` go out in **one atomic commit + push** in Step 7. There is no second state commit, so there is no state-vs-PR-branch drift to worry about.
- If `git push` of that atomic commit fails, `git reset --hard "$PRE_WORK_HEAD"` reverts the local commit and working tree (including `$STATE`); the remote was never updated. The next run reseeds `$STATE` if needed and reprocesses cleanly.
- If the PR step fails after the atomic commit was pushed, `rollback_branch` resets the local branch to its pre-commit HEAD and reconciles the remote (force-reset for a pre-existing branch, delete for a brand-new branch). Without this, the pushed case + manifest entry would survive while a fresh checkout's `$STATE` doesn't include the GHSA, causing the next run to write a duplicate manifest entry that fails `validate.py`.
- `manifest.json` and `state.json` updates are JSON-key-keyed; duplicate-key writes are no-ops.

## Failure modes — abort cleanly, do NOT open a PR

- gh API rate-limited → exit 75 (`EX_TEMPFAIL`). The launchd plist's `KeepAlive` retries. State is untouched.
- Any ancestry check fails → log and skip that advisory; still process the rest. Its GHSA is never written to `$PROCESSED_FILE`, so the next run retries it.
- `validate.py` or `pytest` fails → `cleanup_working_tree` resets tracked files to `$PRE_WORK_HEAD` (preserving any prior same-day batch commits on the branch) and removes this run's untracked artefacts (case dirs listed in `$CREATED_CASES_FILE` — *not* `$PROCESSED_FILE`, which would also include GHSAs whose `cases/$GHSA/` already existed and was just restored by the reset — and `$STATE` only if `STATE_CREATED_THIS_RUN=1`), then exit 1. Never `git reset --hard origin/main` — that would erase prior batch commits on a reused same-day branch.
- `state.py add` fails for a GHSA → `cleanup_working_tree` (same as above) reverts cases, manifest, and `$STATE` together, then exit 1. Reverting only `$STATE` would leave Step 5's case writes on disk for the next run to trip over.
- `git push` of the atomic case+state commit fails → reset local branch to `$PRE_WORK_HEAD` (this also reverts `$STATE` in the working tree) and exit 1. No remote cleanup needed because the push didn't happen.
- `gh pr create`, `gh pr edit`, `gh pr view`, or `gh pr list` fails → `rollback_branch` resets local to `$PRE_WORK_HEAD` (reverts case + manifest + state together) and reconciles the remote: force-reset for a pre-existing branch, **mandatory delete** for a brand-new branch. If the brand-new-branch remote delete fails, the script exits non-zero with a manual-cleanup message — silently swallowing the error would orphan a pushed state commit that future runs would silently filter out.
- securevibes-agent fails to run → the PR is already open, the state already records the advisories; amend the body to mark each report as `detected: unknown — sv-agent exited <code>`.

## Where the state file lives

`${CLAUDE_SKILL_DIR}/state/<owner>__<repo>.json`. These files **are** checked in. They are the source of truth for "what has this watcher already seen" and they need to survive across launchd job restarts.
