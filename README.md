# OpenClaw Advisory Benchmark

24 real-world [OpenClaw](https://github.com/openclaw/openclaw) security advisories (GHSAs) packaged as a scanner-agnostic benchmark. Each case includes the exact commit timeline — baseline and introducing commit(s) — so any security scanner can test whether it would have detected these vulnerabilities at the point they were introduced.

## Quick Start

```bash
# 1. Clone the openclaw repo (needed for checkout)
git clone https://github.com/openclaw/openclaw.git ../openclaw

# 2. Pick a case
cat cases/GHSA-qrq5-wjgg-rvqw/case.json | jq '.timeline.vulnerableHead'

# 3. Checkout the vulnerable commit
cd ../openclaw
git checkout <vulnerableHead>

# 4. Run your scanner
your-scanner scan .

# 5. Compare results against expectedOutcome
cat ../openclaw-advisory-benchmark/cases/GHSA-qrq5-wjgg-rvqw/case.json | jq '.expectedOutcome'
```

## Benchmarking Workflow

For each case in `cases/GHSA-*/case.json`:

1. **Baseline scan** (optional) — checkout `timeline.baselineCommit`, scan. This is the pre-vulnerability clean state; findings here are false positives for this advisory.
2. **Vulnerable scan** — checkout `timeline.vulnerableHead`, scan. Compare results against `expectedOutcome`:
   - Does the scanner report a finding with a matching `vulnerabilityClass`?
   - Does at least one finding path overlap with `expectedPaths`?
   - Is the reported severity >= `minimumSeverity`?

## Case Schema (`case.json`)

Each case directory contains a single `case.json` with these sections:

| Section | Description |
|---------|-------------|
| `advisory` | Title, severity, CVSS, CWEs, affected package ranges from the GHSA |
| `timeline` | Baseline commit, introducing commit(s), vulnerable head |
| `expectedOutcome` | Vulnerability class, minimum severity, expected file paths, description |
| `verification` | Ancestry check results (baseline → intro ordering) |
| `provenance` | Which source datasets contributed to this case |

See `schema/case.schema.json` for the full JSON Schema (draft-07).

## Vulnerability Class Taxonomy

| Class | Description |
|-------|-------------|
| `authbypass` | Authentication bypass |
| `brokenauthz` | Broken authorization / privilege escalation |
| `commandinjection` | Command injection / argument injection |
| `codeexec` | Arbitrary code execution |
| `pathtraversal` | Path traversal / directory traversal |
| `sandboxescape` | Sandbox escape / isolation bypass |
| `secretdisclosure` | Secret / credential disclosure |
| `ssrf` | Server-side request forgery |
| `abuse` | Resource exhaustion / denial of service |

## Running the Benchmark

The runner automates the full loop: checkout each vulnerable commit, run your scanner, parse results, and produce a scorecard.

If the scanner emits parseable SARIF/simple JSON, the benchmark evaluates that output even when the scanner exits non-zero. This accommodates tools that use exit status to signal findings.

```bash
# Run with a SARIF-producing scanner
python3 scripts/run.py \
  --openclaw-repo ../openclaw \
  --scanner-cmd "semgrep scan --sarif ."

# Run with a custom JSON-producing scanner
python3 scripts/run.py \
  --openclaw-repo ../openclaw \
  --scanner-cmd "my-scanner scan --json ." \
  --format simple

# Run a subset of cases
python3 scripts/run.py \
  --openclaw-repo ../openclaw \
  --scanner-cmd "semgrep scan --sarif ." \
  --filter GHSA-qrq5-wjgg-rvqw GHSA-4rj2-gpmh-qq5x

# Custom timeout and output path
python3 scripts/run.py \
  --openclaw-repo ../openclaw \
  --scanner-cmd "codeql database analyze ." \
  --timeout 600 \
  --output my-results.json
```

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

## Validation

```bash
# Structural validation (full schema conformance requires: pip install jsonschema)
python3 scripts/validate.py

# Semantic validation (commit SHAs resolve, ancestry checks pass)
# If jsonschema is missing, schema checks are skipped with a warning.
python3 scripts/validate.py --openclaw-repo ../openclaw

# Strict mode (all cases must pass verification with high confidence)
# If jsonschema is missing, schema checks are skipped with a warning.
python3 scripts/validate.py --openclaw-repo ../openclaw --strict
```

## Regenerating Cases

```bash
python3 scripts/migrate.py \
  --agent-manifest ../securevibes-agent/docs/testing/openclaw-advisory-ground-truth.json \
  --openclaw-repo ../openclaw \
  --output-dir .
```

No `securevibes` checkout is required. The checked-in `cases/` directory is the canonical source for the 10 historical benchmark cases already in this repo, and regeneration refreshes the manifest plus the agent-derived cases from `securevibes-agent` ground truth. `--openclaw-repo` is still required because agent-only cases need exact commit timeline resolution.

`--advisories-file` is optional when refreshing the current dataset in-place: if omitted, the script reuses advisory metadata from the checked-in `cases/` directory for agent-only cases. It is still recommended when adding or refreshing advisory metadata from an external cache.

## Outcome Matching Criteria

A scanner "detects" a case when scanning `vulnerableHead` if:

1. **Class match** — reported vulnerability class matches `expectedOutcome.vulnerabilityClass`
   - For SARIF/simple JSON inputs, this is derived from the finding's CWE metadata.
2. **Path overlap** — at least one finding path overlaps with `expectedOutcome.expectedPaths`
3. **Severity floor** — reported severity >= `expectedOutcome.minimumSeverity`
