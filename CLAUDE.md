# OpenClaw Advisory Benchmark

## What this repo is

A benchmark for security scanners. 33 real vulnerabilities from [OpenClaw](https://github.com/openclaw/openclaw) and [Ghost](https://github.com/TryGhost/Ghost), each with the exact commit where the vulnerability was introduced. The question: **can a scanner detect the vulnerability at that commit?**

## Repository structure

```
cases/GHSA-*/case.json   — 33 ground-truth cases (repository, commit SHAs, expected findings)
manifest.json            — Index of all cases
schema/case.schema.json  — JSON Schema for case files
scripts/run.py           — Benchmark runner (checkout → scan → score)
scripts/validate.py      — Case file validation
scripts/repositories.py  — Shared repository config parsing
scripts/taxonomy.py      — Vulnerability class and CWE mappings
tests/                   — pytest tests (run with: python3 -m pytest tests/)
```

## Running the benchmark

### Prerequisites

1. The openclaw repo must be cloned locally:
   ```bash
   git clone https://github.com/openclaw/openclaw.git ../openclaw
   ```
2. If you want to run Ghost cases too, clone Ghost locally:
   ```bash
   git clone https://github.com/TryGhost/Ghost.git ../ghost
   ```
3. The scanner must be installed and available on PATH.
4. The scanner must produce **SARIF 2.1.0** or simple JSON on **stdout**.

### Command

```bash
python3 scripts/run.py \
  --repo openclaw/openclaw=../openclaw \
  --repo TryGhost/Ghost=../ghost \
  --scanner-cmd "<scanner command that outputs SARIF to stdout>"
```

The runner loops through all selected cases. For each one it:
1. Checks out the vulnerable commit in the repository configured for that case
2. Runs the scanner command in that directory
3. Parses the SARIF/JSON output
4. Scores: did the scanner find a finding at the right path, with the expected class?
5. Prints a scorecard and writes `results.json`

### Scanner command examples

The `--scanner-cmd` is run with `cwd` set to the checked-out worktree for the case's repository. It must write results to stdout.

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
| `--repo` | (repeatable) | `OWNER/NAME=PATH` mapping from case repository to local git checkout |
| `--openclaw-repo` | (optional) | Legacy alias for `--repo openclaw/openclaw=PATH` |
| `--scanner-cmd` | (required) | Scanner command to run |
| `--format` | `auto` | Output format: `auto`, `sarif`, or `simple` |
| `--output` | `results.json` | Path for JSON results file |
| `--timeout` | `300` | Seconds per case before killing the scanner |
| `--filter` | (all) | Space-separated GHSA IDs to run a subset |

### Interpreting results

A case is **DETECTED** when these two match:
- **Path** — scanner flagged a file listed in `expectedPaths`
- **Class** — finding's CWE maps to the expected vulnerability class (skipped if scanner doesn't report CWEs)

`severityMatch` is still tracked and shown in the scorecard, but it does not gate detection.

The scorecard shows per-case results, repository, and an overall detection rate.

## Development

- Tests: `python3 -m pytest tests/`
- Validation: `python3 scripts/validate.py`
- Semantic validation:
  `python3 scripts/validate.py --repo openclaw/openclaw=../openclaw --repo TryGhost/Ghost=../ghost`

## Key conventions

- Python 3.11+, no external dependencies (stdlib + pytest only)
- All scripts use `argparse`, `subprocess.run(check=False)`, `pathlib.Path`
- JSON files use 2-space indent with trailing newline
- Case data uses camelCase keys; Python code uses snake_case
- Vulnerability classes currently include `authbypass`, `brokenauthz`, `codeexec`, `commandinjection`, `csrf`, `pathtraversal`, `sandboxescape`, `secretdisclosure`, `sqlinjection`, `ssrf`, `abuse`, and `xss`
