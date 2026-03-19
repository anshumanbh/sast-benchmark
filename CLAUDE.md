# OpenClaw Advisory Benchmark

## What this repo is

A benchmark for security scanners. 24 real vulnerabilities from the [OpenClaw](https://github.com/openclaw/openclaw) project, each with the exact commit where the vulnerability was introduced. The question: **can a scanner detect the vulnerability at that commit?**

## Repository structure

```
cases/GHSA-*/case.json   — 24 ground-truth cases (commit SHAs, expected findings)
manifest.json            — Index of all cases
schema/case.schema.json  — JSON Schema for case files
scripts/run.py           — Benchmark runner (checkout → scan → score)
scripts/validate.py      — Case file validation
tests/                   — pytest tests (run with: python3 -m pytest tests/)
```

## Running the benchmark

### Prerequisites

1. The openclaw repo must be cloned locally:
   ```bash
   git clone https://github.com/openclaw/openclaw.git ../openclaw
   ```
2. The scanner must be installed and available on PATH.
3. The scanner must produce **SARIF 2.1.0** or simple JSON on **stdout**.

### Command

```bash
python3 scripts/run.py \
  --openclaw-repo ../openclaw \
  --scanner-cmd "<scanner command that outputs SARIF to stdout>"
```

The runner loops through all 24 cases. For each one it:
1. Checks out the vulnerable commit in the openclaw repo
2. Runs the scanner command in that directory
3. Parses the SARIF/JSON output
4. Scores: did the scanner find a finding at the right path, with sufficient severity?
5. Prints a scorecard and writes `results.json`

### Scanner command examples

The `--scanner-cmd` is run with `cwd` set to the openclaw repo directory. It must write results to stdout.

| Scanner | Command |
|---------|---------|
| Semgrep | `semgrep scan --sarif --quiet .` |
| CodeQL (pre-built DB) | `codeql database analyze --format=sarif-latest --output=/dev/stdout db` |
| Bandit (Python) | `bandit -r . -f sarif` |
| Custom / wrapper | `my-scanner scan --json .` with `--format simple` |

If a scanner writes to a file instead of stdout, wrap it:
```bash
--scanner-cmd "my-scanner scan -o /tmp/out.sarif . && cat /tmp/out.sarif"
```

If a scanner doesn't produce SARIF, use the simple JSON format (`--format simple`). The scanner must output:
```json
{
  "findings": [
    {"path": "src/foo.ts", "severity": "high", "ruleId": "rule-1", "message": "...", "cweIds": ["CWE-78"]}
  ]
}
```

### Runner options

| Flag | Default | Description |
|------|---------|-------------|
| `--openclaw-repo` | (required) | Path to openclaw git checkout |
| `--scanner-cmd` | (required) | Scanner command to run |
| `--format` | `auto` | Output format: `auto`, `sarif`, or `simple` |
| `--output` | `results.json` | Path for JSON results file |
| `--timeout` | `300` | Seconds per case before killing the scanner |
| `--filter` | (all) | Space-separated GHSA IDs to run a subset |

### Interpreting results

A case is **DETECTED** when all three match:
- **Path** — scanner flagged a file listed in `expectedPaths`
- **Severity** — finding severity >= `minimumSeverity`
- **Class** — finding's CWE maps to the expected vulnerability class (skipped if scanner doesn't report CWEs)

The scorecard shows per-case results and an overall detection rate.

## Development

- Tests: `python3 -m pytest tests/`
- Validation: `python3 scripts/validate.py`
- Semantic validation (needs openclaw clone): `python3 scripts/validate.py --openclaw-repo ../openclaw`

## Key conventions

- Python 3.11+, no external dependencies (stdlib + pytest only)
- All scripts use `argparse`, `subprocess.run(check=False)`, `pathlib.Path`
- JSON files use 2-space indent with trailing newline
- Case data uses camelCase keys; Python code uses snake_case
