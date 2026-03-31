# OpenClaw Advisory Benchmark

33 real-world security advisories from [OpenClaw](https://github.com/openclaw/openclaw) and [Ghost](https://github.com/TryGhost/Ghost), packaged as a scanner-agnostic benchmark. Each case includes the exact commit timeline — baseline and introducing commit(s) — so any security scanner can test whether it would have detected these vulnerabilities at the point they were introduced.

Detection note: benchmark detection is based on path match + class match. Severity is still recorded as `severityMatch`, but it no longer gates whether a case counts as detected.

## Quick Start

```bash
# 1. Clone the repos you want to benchmark
git clone https://github.com/openclaw/openclaw.git ../openclaw
git clone https://github.com/TryGhost/Ghost.git ../ghost

# 2. Pick a case
cat cases/GHSA-3c6h-g97w-fg78/case.json | jq '{repository, vulnerableHead: .timeline.vulnerableHead}'

# 3. Checkout the vulnerable commit in the matching repo
cd ../openclaw
git checkout <vulnerableHead>

# 4. Run your scanner
your-scanner scan .

# 5. Compare results against expectedOutcome
cat ../openclaw-advisory-benchmark/cases/GHSA-3c6h-g97w-fg78/case.json | jq '.expectedOutcome'
```

## Benchmarking Workflow

For each case in `cases/GHSA-*/case.json`:

1. **Baseline scan** (optional) — checkout `timeline.baselineCommit`, scan. This is the pre-vulnerability clean state; findings here are false positives for this advisory.
2. **Vulnerable scan** — checkout `timeline.vulnerableHead`, scan. Compare results against `expectedOutcome`:
   - Does the scanner report a finding with a matching `vulnerabilityClass`?
   - Does at least one finding path overlap with `expectedPaths`?
   - Does the finding also meet `minimumSeverity`? The runner records this separately as `severityMatch`, but detection is based on path + class.

## Case Schema (`case.json`)

Each case directory contains a single `case.json` with these sections:

| Section | Description |
|---------|-------------|
| `repository` | Canonical source repository ID (`OWNER/NAME`) used by the runner and validator to select the right local checkout |
| `advisory` | Title, severity, CVSS, CWEs, affected package ranges from the GHSA |
| `timeline` | Baseline commit, introducing commit(s), vulnerable head |
| `expectedOutcome` | Vulnerability class, minimum severity, expected file paths, description |
| `verification` | Verification evidence and ancestry checks for baseline → intro → vulnerableHead relationships |

See `schema/case.schema.json` for the full JSON Schema (draft-07).

For `--strict` validation, the required ancestry checks in `verification.checks` are:

- `baseline_ancestor_of_intro`
- `intro_ancestor_of_vulnerable_head`
- `baseline_ancestor_of_vulnerable_head`

Those checks should carry machine-readable `ancestor` and `descendant` SHAs.

## Manifest

`manifest.json` is the checked-in summary index for the benchmark. Each entry in `manifest.cases` should include:

- `id`
- `severity`
- `title`
- `vulnerabilityClass`
- `baselineCommit`
- `vulnerableHead`
- `verificationStatus`
- `confidence`

Validation checks these summary fields against the corresponding `case.json`. When `manifest.repositories` is present, validation also checks that it matches the set of repositories referenced by the loaded cases.

## Vulnerability Class Taxonomy

| Class | Description |
|-------|-------------|
| `authbypass` | Authentication bypass |
| `brokenauthz` | Broken authorization / privilege escalation |
| `commandinjection` | Command injection / argument injection |
| `codeexec` | Arbitrary code execution |
| `csrf` | Cross-site request forgery / request-origin binding failure |
| `pathtraversal` | Path traversal / directory traversal |
| `sandboxescape` | Sandbox escape / isolation bypass |
| `secretdisclosure` | Secret / credential disclosure |
| `sqlinjection` | SQL injection |
| `ssrf` | Server-side request forgery |
| `abuse` | Resource exhaustion / denial of service |
| `xss` | Cross-site scripting |

## Running the Benchmark

The runner automates the full loop: checkout each vulnerable commit, run your scanner, parse results, and produce a scorecard.

If the scanner emits parseable SARIF/simple JSON, the benchmark evaluates that output even when the scanner exits non-zero. This accommodates tools that use exit status to signal findings.

```bash
# Run with SARIF against both OpenClaw and Ghost cases
python3 scripts/run.py \
  --repo openclaw/openclaw=../openclaw \
  --repo TryGhost/Ghost=../ghost \
  --scanner-cmd "semgrep scan --sarif ."

# Run with a custom JSON-producing scanner
python3 scripts/run.py \
  --repo openclaw/openclaw=../openclaw \
  --repo TryGhost/Ghost=../ghost \
  --scanner-cmd "my-scanner scan --json ." \
  --format simple

# Run a subset of cases
python3 scripts/run.py \
  --repo TryGhost/Ghost=../ghost \
  --scanner-cmd "semgrep scan --sarif ." \
  --filter GHSA-w52v-v783-gw97 GHSA-cgc2-rcrh-qr5x

# Custom timeout and output path
python3 scripts/run.py \
  --repo openclaw/openclaw=../openclaw \
  --repo TryGhost/Ghost=../ghost \
  --scanner-cmd "codeql database analyze ." \
  --timeout 600 \
  --output my-results.json
```

### Runner Options

| Flag | Description |
|------|-------------|
| `--repo` | `OWNER/NAME=PATH` mapping from case repository to local git checkout; repeat for multiple repos |
| `--openclaw-repo` | Legacy alias for `--repo openclaw/openclaw=PATH` |
| `--scanner-cmd` | Scanner command to run in the checked-out worktree; must write SARIF or simple JSON to stdout |
| `--format` | Force `auto`, `sarif`, or `simple` output parsing |
| `--cases-dir` | Override the default `cases/` directory |
| `--filter` | Run only specific GHSA IDs |
| `--timeout` | Per-case timeout for the main scanner command |
| `--output` | Path for the JSON results file |
| `--baseline-cmd` | Optional setup command to run at `timeline.baselineCommit` before the vulnerable scan |
| `--baseline-timeout` | Timeout for `--baseline-cmd` (defaults to `--timeout`) |

### Diff-aware Scanners

`--baseline-cmd` exists for scanners that need to warm caches, build indexes, or prepare context from the pre-vulnerability commit before scanning `vulnerableHead`.

It runs a setup command at `timeline.baselineCommit`, discards that command's stdout, then checks out `timeline.vulnerableHead` and runs the main scanner command.

```bash
python3 scripts/run.py \
  --repo openclaw/openclaw=../openclaw \
  --repo TryGhost/Ghost=../ghost \
  --scanner-cmd "my-scanner scan --json ." \
  --baseline-cmd "my-scanner index ." \
  --baseline-timeout 600 \
  --format simple
```

`--baseline-cmd` does not compare baseline findings against vulnerable-scan findings. The README's earlier "baseline scan" workflow describes a larger false-positive-diffing feature that the runner still does not implement.

### Scanner Output Formats

The runner accepts two output formats (auto-detected by default):

**SARIF 2.1.0** (recommended) — Industry standard. Severity is derived from `security-severity` rule properties when available, otherwise from the result `level` or the rule's `defaultConfiguration.level`. CWE IDs are extracted from result properties or rule tags.

**Simple JSON** — Minimal format for scanners without SARIF support:
```json
{
  "findings": [
    {
      "path": "src/foo.ts",
      "severity": "high",
      "ruleId": "command-injection",
      "message": "Command injection via user input",
      "cweIds": ["CWE-78"]
    }
  ]
}
```

`expectedOutcome.vulnerabilityClass` is matched from the finding's CWE metadata. Findings without CWE/class metadata cannot satisfy the class-match requirement.

Some checked-in cases intentionally keep `advisory.cweIds` empty because the upstream GHSA did not publish CWE metadata, and the benchmark does not synthesize replacement advisory CWEs. Those cases still define an expected benchmark class in `expectedOutcome.vulnerabilityClass`, but scanners must emit their own CWE metadata for the runner to award a class match.

### Results

The runner writes a JSON results file (default: `results.json`) and prints a console scorecard:

```
  Case ID                      Class                Sev    Result     Path  Cls  Sev    #
  --------------------------------------------------------------------------------------
  GHSA-3c6h-g97w-fg78          commandinjection     high   DETECTED      Y    Y    Y   12
  GHSA-474h-prjg-mmw3          sandboxescape        high   MISSED        -    -    -    0
  ...
  --------------------------------------------------------------------------------------
  Detected: 15/24 (62.5%)
```

When `--baseline-cmd` is provided, the scorecard adds a `Base` column that shows whether baseline setup for each case was `OK` or `FAIL`.

Each entry in the JSON results payload includes the case `repository` alongside `caseId`, `detected`, `pathMatch`, `classMatch`, `severityMatch`, and scanner metadata.

## Validation

```bash
# Structural validation (schema + manifest consistency; requires: pip install jsonschema)
python3 scripts/validate.py

# Strict metadata validation (offline)
# If jsonschema is missing, schema checks are skipped with a warning.
python3 scripts/validate.py --strict

# Semantic validation (commit SHAs resolve, ancestry checks pass in git history)
# If jsonschema is missing, schema checks are skipped with a warning.
python3 scripts/validate.py \
  --repo openclaw/openclaw=../openclaw \
  --repo TryGhost/Ghost=../ghost

# Full validation (strict metadata + semantic git checks)
# If jsonschema is missing, schema checks are skipped with a warning.
python3 scripts/validate.py \
  --repo openclaw/openclaw=../openclaw \
  --repo TryGhost/Ghost=../ghost \
  --strict
```

## Outcome Matching Criteria

A scanner "detects" a case when scanning `vulnerableHead` if:

1. **Class match** — reported vulnerability class matches `expectedOutcome.vulnerabilityClass`
   - For SARIF/simple JSON inputs, this is derived from the finding's CWE metadata.
2. **Path overlap** — at least one finding path overlaps with `expectedOutcome.expectedPaths`
3. **Severity floor** — reported severity >= `expectedOutcome.minimumSeverity`, recorded as `severityMatch` but not required for detection

The runner evaluates severity and class matching only across findings on matching paths. Class matching is derived from all relevant findings on those paths, even when the matching finding is below the configured severity floor.
