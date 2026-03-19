#!/usr/bin/env python3
"""Run the OpenClaw Advisory Benchmark against a security scanner.

For each case, checks out the vulnerable commit in the openclaw repo,
runs the scanner, and compares findings against expected outcomes.

Usage:
    python3 scripts/run.py \\
        --openclaw-repo ../openclaw \\
        --scanner-cmd "semgrep scan --sarif ." \\
        --output results.json
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from taxonomy import CWE_TO_VULN_CLASS


# ── Data types ─────────────────────────────────────────────────────────────────


@dataclasses.dataclass
class Finding:
    """A single normalized scanner finding."""

    path: str
    severity: str
    rule_id: str = ""
    cwe_ids: list[str] = dataclasses.field(default_factory=list)
    message: str = ""


@dataclasses.dataclass
class BenchmarkWorktree:
    """A temporary worktree used to run benchmark scans safely."""

    source_repo: Path
    path: Path
    tempdir: tempfile.TemporaryDirectory


# ── Constants ──────────────────────────────────────────────────────────────────

SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

SARIF_LEVEL_TO_SEVERITY: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "low",
}

ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ROOT / "cases"
CWE_ID_RE = re.compile(r"(?i)\bCWE-(\d+)\b")


# ── Path normalization ─────────────────────────────────────────────────────────


def normalize_path(path: str) -> str:
    """Normalize a file path for comparison."""
    if not path:
        return ""
    path = path.replace("\\", "/")
    if path.startswith("file://"):
        path = path[7:]
    path = path.lstrip("/")
    while path.startswith("./"):
        path = path[2:]
    return path


# ── Severity ───────────────────────────────────────────────────────────────────


def severity_gte(reported: str, minimum: str) -> bool:
    """Check if reported severity meets the minimum threshold."""
    return SEVERITY_ORDER.get(reported.lower(), 0) >= SEVERITY_ORDER.get(
        minimum.lower(), 0
    )


def _security_severity_to_level(score: float) -> str:
    """Map a numeric security-severity score to a severity level."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def extract_cwe_ids(values: Any) -> list[str]:
    """Extract normalized CWE IDs from scanner metadata."""
    if values is None:
        return []

    if isinstance(values, str):
        raw_values = [values]
    else:
        try:
            raw_values = list(values)
        except TypeError:
            return []

    cwe_ids: list[str] = []
    seen: set[str] = set()
    for value in raw_values:
        if not isinstance(value, str):
            continue
        for match in CWE_ID_RE.finditer(value):
            normalized = f"CWE-{match.group(1)}"
            if normalized not in seen:
                seen.add(normalized)
                cwe_ids.append(normalized)
    return cwe_ids


# ── Path overlap ──────────────────────────────────────────────────────────────


def paths_overlap(
    expected_paths: list[str], finding_paths: list[str]
) -> list[str]:
    """Return expected paths that appear in finding paths.

    Uses suffix matching to handle absolute paths from scanners.
    """
    if not expected_paths or not finding_paths:
        return []

    norm_findings = [normalize_path(p) for p in finding_paths]
    matched = []
    for ep in expected_paths:
        norm_ep = normalize_path(ep)
        for nf in norm_findings:
            if nf == norm_ep or nf.endswith("/" + norm_ep):
                matched.append(ep)
                break
    return matched


# ── Format detection ──────────────────────────────────────────────────────────


def detect_format(raw: str) -> str:
    """Detect whether scanner output is SARIF or simple JSON.

    Returns "sarif", "simple", or "unknown".
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return "unknown"

    return _detect_format_from_data(data)


def _detect_format_from_data(data: Any) -> str:
    """Detect format from an already-parsed JSON value."""
    if not isinstance(data, dict):
        return "unknown"

    if data.get("version") and "runs" in data:
        return "sarif"
    if "$schema" in data and "runs" in data:
        return "sarif"
    if "findings" in data and isinstance(data["findings"], list):
        return "simple"

    return "unknown"


# ── SARIF parsing ─────────────────────────────────────────────────────────────


def _build_sarif_rule_lookup(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Collect SARIF rules from the driver and extension components."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    tool = run.get("tool", {})
    if not isinstance(tool, dict):
        return rules_by_id

    components: list[Any] = [tool.get("driver")]
    extensions = tool.get("extensions", [])
    if isinstance(extensions, list):
        components.extend(extensions)

    for component in components:
        if not isinstance(component, dict):
            continue
        rules = component.get("rules", [])
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rule_id = rule.get("id")
            if isinstance(rule_id, str) and rule_id and rule_id not in rules_by_id:
                rules_by_id[rule_id] = rule

    return rules_by_id


def _resolve_sarif_base_uri(
    base_id: str, original_uri_base_ids: dict[str, Any], seen: set[str] | None = None
) -> str:
    """Resolve a SARIF uriBaseId through originalUriBaseIds."""
    if not base_id:
        return ""

    if seen is None:
        seen = set()
    if base_id in seen:
        return ""
    seen.add(base_id)

    base_entry = original_uri_base_ids.get(base_id)
    if not isinstance(base_entry, dict):
        return ""

    base_uri = base_entry.get("uri")
    if not isinstance(base_uri, str) or not base_uri:
        return ""

    parent_base_id = base_entry.get("uriBaseId")
    if isinstance(parent_base_id, str) and parent_base_id:
        parent_base_uri = _resolve_sarif_base_uri(
            parent_base_id, original_uri_base_ids, seen
        )
        if parent_base_uri:
            return urljoin(parent_base_uri, base_uri)

    return base_uri


def _resolve_sarif_artifact_uri(
    artifact_location: dict[str, Any], original_uri_base_ids: dict[str, Any]
) -> str:
    """Resolve a SARIF artifact URI, including uriBaseId references."""
    uri = artifact_location.get("uri", "")
    if not isinstance(uri, str) or not uri:
        return ""

    uri_base_id = artifact_location.get("uriBaseId")
    if isinstance(uri_base_id, str) and uri_base_id:
        base_uri = _resolve_sarif_base_uri(uri_base_id, original_uri_base_ids)
        if base_uri:
            return urljoin(base_uri, uri)

    return uri


def parse_sarif(data: dict[str, Any]) -> list[Finding]:
    """Parse SARIF 2.1.0 into normalized Findings."""
    findings: list[Finding] = []

    for run in data.get("runs", []):
        rules_by_id = _build_sarif_rule_lookup(run)
        original_uri_base_ids = run.get("originalUriBaseIds", {})
        if not isinstance(original_uri_base_ids, dict):
            original_uri_base_ids = {}

        for result in run.get("results", []):
            locations = result.get("locations", [])
            if not locations:
                continue

            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")

            # Severity: prefer security-severity from rule, else map level
            rule_def = rules_by_id.get(rule_id, {})
            sec_sev = (rule_def.get("properties") or {}).get("security-severity")
            if sec_sev is not None:
                try:
                    severity = _security_severity_to_level(float(sec_sev))
                except (TypeError, ValueError) as exc:
                    rule_label = rule_id or "<unknown>"
                    raise ValueError(
                        f"invalid security-severity for rule {rule_label}: {sec_sev!r}"
                    ) from exc
            else:
                level = (
                    result.get("level")
                    or (rule_def.get("defaultConfiguration") or {}).get("level")
                    or "warning"
                )
                severity = SARIF_LEVEL_TO_SEVERITY.get(str(level).lower(), "medium")

            # CWE IDs: from result properties, then rule tags
            cwe_ids = extract_cwe_ids((result.get("properties") or {}).get("cweIds", []))
            if not cwe_ids:
                tags = (rule_def.get("properties") or {}).get("tags", [])
                cwe_ids = extract_cwe_ids(tags)

            for loc in locations:
                phys = loc.get("physicalLocation", {})
                artifact_location = phys.get("artifactLocation", {})
                if not isinstance(artifact_location, dict):
                    continue
                uri = _resolve_sarif_artifact_uri(
                    artifact_location, original_uri_base_ids
                )
                if not uri:
                    continue

                findings.append(
                    Finding(
                        path=normalize_path(uri),
                        severity=severity,
                        rule_id=rule_id,
                        cwe_ids=cwe_ids,
                        message=message,
                    )
                )

    return findings


# ── Simple JSON parsing ───────────────────────────────────────────────────────


def parse_simple(data: dict[str, Any]) -> list[Finding]:
    """Parse simple JSON format into normalized Findings."""
    findings: list[Finding] = []
    for item in data.get("findings", []):
        findings.append(
            Finding(
                path=normalize_path(item.get("path", "")),
                severity=item.get("severity", "medium").lower(),
                rule_id=item.get("ruleId", ""),
                cwe_ids=extract_cwe_ids(item.get("cweIds", [])),
                message=item.get("message", ""),
            )
        )
    return findings


# ── Unified parser ────────────────────────────────────────────────────────────


def parse_findings(raw: str, format: str = "auto") -> list[Finding]:
    """Parse scanner output into Findings.

    Format: "auto" (detect), "sarif", or "simple".
    Returns empty list on parse failure.
    """
    findings, _ = parse_findings_checked(raw, format)
    return findings


def parse_findings_checked(
    raw: str, format: str = "auto"
) -> tuple[list[Finding], str | None]:
    """Parse scanner output into Findings, returning an error on parse failure."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return [], "output is not valid JSON"

    if format == "auto":
        format = _detect_format_from_data(data)
        if format == "unknown":
            return [], "output format is not recognized"
    elif format == "sarif" and _detect_format_from_data(data) != "sarif":
        return [], "output is not valid SARIF"
    elif format == "simple" and _detect_format_from_data(data) != "simple":
        return [], "output is not valid simple JSON"

    try:
        if format == "sarif":
            return parse_sarif(data), None
        if format == "simple":
            return parse_simple(data), None
    except (AttributeError, TypeError, ValueError) as exc:
        if format == "sarif":
            return [], f"output is not valid SARIF: {exc}"
        if format == "simple":
            return [], f"output is not valid simple JSON: {exc}"
    return [], "output format is not recognized"


# ── Case evaluation ───────────────────────────────────────────────────────────


def _vuln_classes_from_cwes(cwe_ids: list[str]) -> set[str]:
    """Map all recognized CWE IDs to vulnerability classes."""
    return {
        cls
        for cwe in extract_cwe_ids(cwe_ids)
        if cwe in CWE_TO_VULN_CLASS
        for cls in CWE_TO_VULN_CLASS[cwe]
    }


def evaluate_case(
    case_id: str,
    findings: list[Finding],
    expected_outcome: dict[str, Any],
    error: str | None = None,
) -> dict[str, Any]:
    """Evaluate findings against a case's expectedOutcome.

    Detection requires: path overlap AND severity >= minimum AND class match.
    Class match requires at least one relevant finding to map to the expected
    vulnerability class.
    Path match defaults to True if expectedPaths is empty.
    """
    expected_class = expected_outcome["vulnerabilityClass"]
    min_severity = expected_outcome["minimumSeverity"]
    expected_paths = expected_outcome.get("expectedPaths", [])

    finding_paths = [f.path for f in findings]

    # Path matching
    if not expected_paths:
        path_match = True
        matched_paths: list[str] = []
    else:
        matched_paths = paths_overlap(expected_paths, finding_paths)
        path_match = len(matched_paths) > 0

    # Find findings that match on path (or all findings if no expected paths)
    if expected_paths and path_match:
        norm_expected = {normalize_path(p) for p in expected_paths}
        relevant = [
            f
            for f in findings
            if any(
                f.path == ne or f.path.endswith("/" + ne)
                for ne in norm_expected
            )
        ]
    else:
        relevant = list(findings)

    # Severity matching — at least one relevant finding meets the threshold
    severity_match = any(severity_gte(f.severity, min_severity) for f in relevant)

    # Class matching — require at least one relevant+severe finding to map to
    # the expected vulnerability class.
    severe_relevant = [f for f in relevant if severity_gte(f.severity, min_severity)]
    derived_classes = {
        mapped_class
        for f in severe_relevant
        for mapped_class in _vuln_classes_from_cwes(f.cwe_ids)
    }
    class_match = expected_class in derived_classes

    detected = False if error else path_match and severity_match and class_match

    return {
        "caseId": case_id,
        "detected": detected,
        "pathMatch": path_match,
        "severityMatch": severity_match,
        "classMatch": class_match,
        "matchedPaths": matched_paths,
        "findingCount": len(findings),
        "error": error,
    }


# ── Results ───────────────────────────────────────────────────────────────────


def build_results(
    case_results: list[dict[str, Any]], scanner_cmd: str
) -> dict[str, Any]:
    """Build the final results payload."""
    total = len(case_results)
    detected = sum(1 for r in case_results if r.get("detected"))
    return {
        "runAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scannerCommand": scanner_cmd,
        "totalCases": total,
        "detected": detected,
        "detectionRate": detected / total if total > 0 else 0.0,
        "results": case_results,
    }


# ── Git operations ────────────────────────────────────────────────────────────


def checkout_commit(repo: Path, sha: str) -> None:
    """Check out a commit in the openclaw repo."""
    proc = subprocess.run(
        ["git", "-C", str(repo), "checkout", sha, "--force", "--quiet"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git checkout {sha[:12]} failed: {proc.stderr.strip()}")


def clean_worktree(repo: Path) -> None:
    """Remove untracked files and nested repos from the worktree."""
    proc = subprocess.run(
        ["git", "-C", str(repo), "clean", "-ffdx", "-q"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            proc.stderr.strip() or f"git clean failed ({proc.returncode})"
        )


def create_benchmark_worktree(repo: Path) -> BenchmarkWorktree:
    """Create a detached temp worktree so the benchmark never mutates the source checkout."""
    head_proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if head_proc.returncode != 0:
        raise RuntimeError(f"git rev-parse HEAD failed: {head_proc.stderr.strip()}")

    tempdir = tempfile.TemporaryDirectory(prefix="openclaw-benchmark-")
    worktree_path = Path(tempdir.name) / "repo"
    add_proc = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "worktree",
            "add",
            "--detach",
            str(worktree_path),
            head_proc.stdout.strip(),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if add_proc.returncode != 0:
        tempdir.cleanup()
        raise RuntimeError(f"git worktree add failed: {add_proc.stderr.strip()}")

    return BenchmarkWorktree(source_repo=repo, path=worktree_path, tempdir=tempdir)


def cleanup_benchmark_worktree(worktree: BenchmarkWorktree) -> None:
    """Remove the detached temp worktree created for the benchmark run."""
    remove_proc = subprocess.run(
        [
            "git",
            "-C",
            str(worktree.source_repo),
            "worktree",
            "remove",
            "--force",
            str(worktree.path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    worktree.tempdir.cleanup()
    if remove_proc.returncode != 0:
        raise RuntimeError(
            f"git worktree remove failed: {remove_proc.stderr.strip()}"
        )


# ── Scanner execution ─────────────────────────────────────────────────────────


def run_scanner(cmd: str, cwd: Path, timeout: int = 300) -> tuple[str, str, int]:
    """Run scanner command and return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return stdout, stderr, -1


# ── Case loading ──────────────────────────────────────────────────────────────


def load_cases(
    cases_dir: Path | None = None, case_filter: list[str] | None = None
) -> list[dict[str, Any]]:
    """Load case.json files from cases/GHSA-*/case.json."""
    cdir = cases_dir or CASES_DIR
    cases = []
    for d in sorted(cdir.iterdir()):
        if not d.is_dir() or not d.name.startswith("GHSA-"):
            continue
        if case_filter and d.name not in case_filter:
            continue
        case_path = d / "case.json"
        if case_path.exists():
            cases.append(json.loads(case_path.read_text(encoding="utf-8")))
    return cases


# ── Reporting ─────────────────────────────────────────────────────────────────


def print_scorecard(
    case_results: list[dict[str, Any]], show_baseline: bool = False
) -> None:
    """Print a console scorecard table."""
    base_header = f" {'Base':>5s}" if show_baseline else ""
    separator_width = 92 if show_baseline else 86

    # Header
    print(
        f"  {'Case ID':<28s} {'Class':<20s} {'Sev':<6s} "
        f"{'Result':<10s} {'Path':>4s} {'Cls':>4s} {'Sev':>4s} {'#':>4s}"
        f"{base_header}"
    )
    print("  " + "-" * separator_width)

    for r in case_results:
        case_id = r["caseId"]
        vuln_class = r.get("vulnerabilityClass", "")
        min_sev = r.get("minimumSeverity", "")
        detected = "DETECTED" if r["detected"] else "MISSED"
        err = r.get("error")
        base_col = (
            f" {r.get('baselineStatus', '').upper():>5s}" if show_baseline else ""
        )

        if err:
            print(f"  {case_id:<28s} {'ERROR':<20s} {'':<6s} {err}{base_col}")
            continue

        pm = "Y" if r["pathMatch"] else "-"
        cm = "Y" if r["classMatch"] else "-"
        sm = "Y" if r["severityMatch"] else "-"
        fc = r.get("findingCount", 0)

        print(
            f"  {case_id:<28s} {vuln_class:<20s} {min_sev:<6s} "
            f"{detected:<10s} {pm:>4s} {cm:>4s} {sm:>4s} {fc:>4d}{base_col}"
        )

    # Summary
    total = len(case_results)
    detected_count = sum(1 for r in case_results if r["detected"])
    errors = sum(1 for r in case_results if r.get("error"))
    pct = (detected_count / total * 100) if total > 0 else 0
    print("  " + "-" * separator_width)
    print(f"  Detected: {detected_count}/{total} ({pct:.1f}%)")
    if errors:
        print(f"  Errors:   {errors}")


# ── Orchestration ─────────────────────────────────────────────────────────────


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    """Run the full benchmark."""
    repo = Path(args.openclaw_repo).resolve()
    cases_dir = Path(args.cases_dir).resolve() if args.cases_dir else None
    case_filter = args.filter if args.filter else None
    scanner_cmd = args.scanner_cmd
    timeout = args.timeout
    fmt = args.format
    baseline_cmd = getattr(args, "baseline_cmd", None)
    bt = getattr(args, "baseline_timeout", None)
    baseline_timeout = bt if bt is not None else timeout

    cases = load_cases(cases_dir, case_filter)
    if not cases:
        print("No cases found.", file=sys.stderr)
        sys.exit(1)

    try:
        worktree = create_benchmark_worktree(repo)
    except RuntimeError as exc:
        print(f"Failed to prepare benchmark worktree: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"  Scanner:   {scanner_cmd}")
    print(f"  Repo:      {repo}")
    print(f"  Worktree:  {worktree.path}")
    print(f"  Cases:     {len(cases)}")
    print()

    case_results: list[dict[str, Any]] = []

    try:
        for case in cases:
            case_id = case["id"]
            baseline_commit = case["timeline"].get("baselineCommit")
            vuln_head = case["timeline"]["vulnerableHead"]
            expected = case["expectedOutcome"]

            error = None
            findings: list[Finding] = []
            scanner_exit_code: int | None = None
            baseline_status: str | None = None
            t0 = time.monotonic()

            try:
                clean_worktree(worktree.path)
            except RuntimeError as e:
                error = f"worktree cleanup failed: {e}"
                if baseline_cmd:
                    baseline_status = "fail"

            if not error and baseline_cmd and baseline_commit:
                baseline_status = "ok"
                try:
                    checkout_commit(worktree.path, baseline_commit)
                except RuntimeError as e:
                    error = f"baseline checkout failed: {e}"
                    baseline_status = "fail"

                if not error:
                    _, baseline_stderr, baseline_exit = run_scanner(
                        baseline_cmd, worktree.path, baseline_timeout
                    )
                    if baseline_exit == -1:
                        error = "baseline timeout"
                        baseline_status = "fail"
                    elif baseline_exit != 0:
                        error = f"baseline failed (exit code {baseline_exit})"
                        baseline_status = "fail"

                    if error and baseline_stderr.strip():
                        error = f"{error}: {baseline_stderr.strip()}"

            if not error:
                try:
                    checkout_commit(worktree.path, vuln_head)
                except RuntimeError as e:
                    error = f"checkout failed: {e}"

            if not error:
                stdout, stderr, scanner_exit_code = run_scanner(
                    scanner_cmd, worktree.path, timeout
                )
                if scanner_exit_code == -1:
                    error = "timeout"
                elif not stdout.strip():
                    error = f"no output (exit code {scanner_exit_code})"
                else:
                    findings, parse_error = parse_findings_checked(stdout, fmt)
                    if parse_error:
                        error = f"{parse_error} (exit code {scanner_exit_code})"

                if error and stderr.strip():
                    error = f"{error}: {stderr.strip()}"

            elapsed = time.monotonic() - t0
            result = evaluate_case(case_id, findings, expected, error=error)
            result["vulnerabilityClass"] = expected["vulnerabilityClass"]
            result["minimumSeverity"] = expected["minimumSeverity"]
            result["scannerExitCode"] = scanner_exit_code
            result["elapsed"] = round(elapsed, 1)
            if baseline_cmd:
                result["baselineStatus"] = baseline_status or "skip"
            case_results.append(result)
    finally:
        cleanup_benchmark_worktree(worktree)

    print_scorecard(case_results, show_baseline=bool(baseline_cmd))
    print()

    results = build_results(case_results, scanner_cmd)

    output_path = Path(args.output) if args.output else ROOT / "results.json"
    output_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"  Results written to {output_path}")

    return results


# ── CLI ───────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the openclaw-advisory-benchmark against a security scanner."
    )
    parser.add_argument(
        "--openclaw-repo",
        type=str,
        required=True,
        help="Path to local openclaw git checkout.",
    )
    parser.add_argument(
        "--scanner-cmd",
        type=str,
        required=True,
        help="Scanner command to run in the repo directory. "
        "Must produce SARIF or simple JSON on stdout.",
    )
    parser.add_argument(
        "--format",
        type=str,
        default="auto",
        choices=["auto", "sarif", "simple"],
        help="Scanner output format (default: auto-detect).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to write JSON results file (default: results.json).",
    )
    parser.add_argument(
        "--cases-dir",
        type=str,
        default=None,
        help="Path to cases directory (default: <repo-root>/cases).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Scanner timeout per case in seconds (default: 300).",
    )
    parser.add_argument(
        "--filter",
        type=str,
        nargs="*",
        default=None,
        help="Only run specific GHSA IDs.",
    )
    parser.add_argument(
        "--baseline-cmd",
        type=str,
        default=None,
        help="Optional setup command to run at baselineCommit before the scanner. "
        "Stdout is discarded; use this to warm caches or build context for "
        "diff-aware scanners.",
    )
    parser.add_argument(
        "--baseline-timeout",
        type=int,
        default=None,
        help="Baseline command timeout in seconds (default: same as --timeout).",
    )
    args = parser.parse_args()
    run_benchmark(args)


if __name__ == "__main__":
    main()
