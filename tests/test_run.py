"""Tests for the benchmark runner."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run import (
    Finding,
    extract_cwe_ids,
    normalize_path,
    detect_format,
    parse_sarif,
    parse_simple,
    parse_findings,
    parse_findings_checked,
    severity_gte,
    paths_overlap,
    evaluate_case,
    build_results,
    run_benchmark,
)


# ── Helpers ────────────────────────────────────────────────────────────────────


def _finding(
    path: str = "src/foo.ts",
    severity: str = "high",
    rule_id: str = "rule-1",
    cwe_ids: list[str] | None = None,
    message: str = "",
) -> Finding:
    return Finding(
        path=path,
        severity=severity,
        rule_id=rule_id,
        cwe_ids=cwe_ids or [],
        message=message,
    )


def _sarif(results: list[dict], rules: list[dict] | None = None) -> dict:
    """Build a minimal SARIF 2.1.0 envelope."""
    tool = {"driver": {"name": "test-scanner", "rules": rules or []}}
    return {"version": "2.1.0", "runs": [{"tool": tool, "results": results}]}


def _sarif_result(
    rule_id: str = "rule-1",
    level: str = "error",
    uri: str = "src/foo.ts",
    message: str = "found something",
    cwe_ids: list[str] | None = None,
) -> dict:
    result: dict = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        ],
    }
    if cwe_ids:
        result["properties"] = {"cweIds": cwe_ids}
    return result


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args],
        text=True,
    ).strip()


def _init_git_repo(repo: Path) -> None:
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test User"],
        check=True,
    )


def _write_case(
    cases_dir: Path,
    vulnerable_head: str,
    *,
    baseline_commit: str | None = None,
    case_id: str = "GHSA-test-test-test",
    repository: str = "openclaw/openclaw",
) -> None:
    timeline = {"vulnerableHead": vulnerable_head}
    if baseline_commit is not None:
        timeline["baselineCommit"] = baseline_commit

    case_dir = cases_dir / case_id
    case_dir.mkdir(parents=True)
    (case_dir / "case.json").write_text(
        json.dumps(
            {
                "id": case_id,
                "repository": repository,
                "timeline": timeline,
                "expectedOutcome": {
                    "vulnerabilityClass": "pathtraversal",
                    "minimumSeverity": "high",
                    "expectedPaths": ["src/foo.ts"],
                },
            }
        ),
        encoding="utf-8",
    )


def _simple_scanner_cmd(
    *,
    path: str = "src/foo.ts",
    severity: str = "high",
    cwe_id: str = "CWE-22",
    exit_code: int = 0,
) -> str:
    payload = json.dumps(
        {
            "findings": [
                {
                    "path": path,
                    "severity": severity,
                    "cweIds": [cwe_id],
                }
            ]
        }
    )
    return (
        "python3 -c "
        f"'import sys; print(\"\"\"{payload}\"\"\"); sys.exit({exit_code})'"
    )


def _benchmark_args(
    tmp_path: Path,
    source_repo: Path,
    cases_dir: Path,
    scanner_cmd: str,
    **overrides: object,
) -> Namespace:
    args = {
        "openclaw_repo": str(source_repo),
        "repo": None,
        "scanner_cmd": scanner_cmd,
        "output": str(tmp_path / "results.json"),
        "cases_dir": str(cases_dir),
        "timeout": 10,
        "format": "auto",
        "filter": None,
        "baseline_cmd": None,
        "baseline_timeout": None,
    }
    args.update(overrides)
    return Namespace(**args)


def _run_benchmark_captured(args: Namespace) -> tuple[dict, str]:
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        results = run_benchmark(args)
    return results, stdout.getvalue()


# ── Path normalization ─────────────────────────────────────────────────────────


class TestNormalizePath:
    def test_strip_dot_slash(self):
        assert normalize_path("./src/foo.ts") == "src/foo.ts"

    def test_strip_double_dot_slash(self):
        assert normalize_path("././src/foo.ts") == "src/foo.ts"

    def test_strip_file_protocol(self):
        assert normalize_path("file:///home/user/repo/src/foo.ts") == "home/user/repo/src/foo.ts"

    def test_strip_leading_slash(self):
        assert normalize_path("/src/foo.ts") == "src/foo.ts"

    def test_already_normalized(self):
        assert normalize_path("src/foo.ts") == "src/foo.ts"

    def test_backslashes_converted(self):
        assert normalize_path("src\\foo.ts") == "src/foo.ts"

    def test_empty_string(self):
        assert normalize_path("") == ""


# ── Format detection ───────────────────────────────────────────────────────────


class TestDetectFormat:
    def test_sarif_with_version_and_runs(self):
        data = json.dumps({"version": "2.1.0", "runs": []})
        assert detect_format(data) == "sarif"

    def test_sarif_with_schema(self):
        data = json.dumps({"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": []})
        assert detect_format(data) == "sarif"

    def test_simple_with_findings(self):
        data = json.dumps({"findings": []})
        assert detect_format(data) == "simple"

    def test_invalid_json(self):
        assert detect_format("not json at all") == "unknown"

    def test_empty_object(self):
        assert detect_format("{}") == "unknown"


# ── SARIF parsing ──────────────────────────────────────────────────────────────


class TestParseSarif:
    def test_single_result(self):
        data = _sarif([_sarif_result(uri="src/foo.ts", level="error")])
        findings = parse_sarif(data)
        assert len(findings) == 1
        assert findings[0].path == "src/foo.ts"
        assert findings[0].severity == "high"
        assert findings[0].rule_id == "rule-1"

    def test_level_error_maps_to_high(self):
        data = _sarif([_sarif_result(level="error")])
        assert parse_sarif(data)[0].severity == "high"

    def test_level_warning_maps_to_medium(self):
        data = _sarif([_sarif_result(level="warning")])
        assert parse_sarif(data)[0].severity == "medium"

    def test_level_note_maps_to_low(self):
        data = _sarif([_sarif_result(level="note")])
        assert parse_sarif(data)[0].severity == "low"

    def test_security_severity_critical(self):
        rules = [{"id": "rule-1", "properties": {"security-severity": "9.5"}}]
        data = _sarif([_sarif_result(rule_id="rule-1")], rules=rules)
        assert parse_sarif(data)[0].severity == "critical"

    def test_security_severity_high(self):
        rules = [{"id": "rule-1", "properties": {"security-severity": "7.5"}}]
        data = _sarif([_sarif_result(rule_id="rule-1")], rules=rules)
        assert parse_sarif(data)[0].severity == "high"

    def test_security_severity_medium(self):
        rules = [{"id": "rule-1", "properties": {"security-severity": "5.0"}}]
        data = _sarif([_sarif_result(rule_id="rule-1")], rules=rules)
        assert parse_sarif(data)[0].severity == "medium"

    def test_security_severity_low(self):
        rules = [{"id": "rule-1", "properties": {"security-severity": "2.0"}}]
        data = _sarif([_sarif_result(rule_id="rule-1")], rules=rules)
        assert parse_sarif(data)[0].severity == "low"

    def test_default_configuration_level_used_when_result_level_missing(self):
        rules = [{"id": "rule-1", "defaultConfiguration": {"level": "error"}}]
        data = _sarif(
            [
                {
                    "ruleId": "rule-1",
                    "message": {"text": "found something"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/foo.ts"}
                            }
                        }
                    ],
                }
            ],
            rules=rules,
        )
        assert parse_sarif(data)[0].severity == "high"

    def test_result_level_overrides_default_configuration_level(self):
        rules = [{"id": "rule-1", "defaultConfiguration": {"level": "error"}}]
        data = _sarif([_sarif_result(rule_id="rule-1", level="note")], rules=rules)
        assert parse_sarif(data)[0].severity == "low"

    def test_cwe_from_result_properties(self):
        data = _sarif([_sarif_result(cwe_ids=["CWE-78"])])
        assert parse_sarif(data)[0].cwe_ids == ["CWE-78"]

    def test_cwe_from_descriptive_result_properties(self):
        data = _sarif([_sarif_result(cwe_ids=["CWE-78: OS Command Injection"])])
        assert parse_sarif(data)[0].cwe_ids == ["CWE-78"]

    def test_cwe_from_rule_tags(self):
        rules = [{"id": "rule-1", "properties": {"tags": ["security", "CWE-22", "owasp"]}}]
        data = _sarif([_sarif_result(rule_id="rule-1")], rules=rules)
        assert "CWE-22" in parse_sarif(data)[0].cwe_ids

    def test_cwe_from_prefixed_rule_tags(self):
        rules = [{"id": "rule-1", "properties": {"tags": ["external/cwe/cwe-78"]}}]
        data = _sarif([_sarif_result(rule_id="rule-1")], rules=rules)
        assert parse_sarif(data)[0].cwe_ids == ["CWE-78"]

    def test_uri_base_id_is_resolved_for_path_matching(self):
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "test-scanner",
                            "rules": [
                                {
                                    "id": "rule-1",
                                    "properties": {"tags": ["CWE-78"]},
                                }
                            ],
                        }
                    },
                    "originalUriBaseIds": {
                        "%SRCROOT%": {"uri": "file:///repo/src/"}
                    },
                    "results": [
                        {
                            "ruleId": "rule-1",
                            "level": "error",
                            "message": {"text": "found something"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "foo.ts",
                                            "uriBaseId": "%SRCROOT%",
                                        }
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        findings = parse_sarif(data)
        assert findings[0].path == "repo/src/foo.ts"
        result = evaluate_case(
            "GHSA-test-test-test",
            findings,
            {
                "vulnerabilityClass": "commandinjection",
                "minimumSeverity": "high",
                "expectedPaths": ["src/foo.ts"],
                "description": "test",
            },
        )
        assert result["detected"] is True

    def test_extension_rules_supply_severity_and_cwe_metadata(self):
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "test-scanner", "rules": []},
                        "extensions": [
                            {
                                "name": "ext",
                                "rules": [
                                    {
                                        "id": "rule-1",
                                        "properties": {
                                            "security-severity": "9.5",
                                            "tags": ["CWE-78"],
                                        },
                                    }
                                ],
                            }
                        ],
                    },
                    "results": [_sarif_result(rule_id="rule-1")],
                }
            ],
        }

        findings = parse_sarif(data)
        assert findings[0].severity == "critical"
        assert findings[0].cwe_ids == ["CWE-78"]

    def test_empty_results(self):
        data = _sarif([])
        assert parse_sarif(data) == []

    def test_multiple_runs_merged(self):
        data = {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "a", "rules": []}}, "results": [_sarif_result(uri="src/a.ts")]},
                {"tool": {"driver": {"name": "b", "rules": []}}, "results": [_sarif_result(uri="src/b.ts")]},
            ],
        }
        findings = parse_sarif(data)
        assert len(findings) == 2

    def test_path_normalization(self):
        data = _sarif([_sarif_result(uri="./src/foo.ts")])
        assert parse_sarif(data)[0].path == "src/foo.ts"

    def test_result_without_locations(self):
        result = {"ruleId": "r1", "level": "error", "message": {"text": "x"}}
        data = _sarif([result])
        assert parse_sarif(data) == []


# ── Simple JSON parsing ───────────────────────────────────────────────────────


class TestParseSimple:
    def test_basic_finding(self):
        data = {
            "findings": [
                {
                    "path": "src/foo.ts",
                    "severity": "high",
                    "ruleId": "cmd-injection",
                    "message": "found it",
                    "cweIds": ["CWE-78"],
                }
            ]
        }
        findings = parse_simple(data)
        assert len(findings) == 1
        assert findings[0].path == "src/foo.ts"
        assert findings[0].severity == "high"
        assert findings[0].cwe_ids == ["CWE-78"]

    def test_missing_optional_fields(self):
        data = {"findings": [{"path": "src/foo.ts", "severity": "high"}]}
        findings = parse_simple(data)
        assert len(findings) == 1
        assert findings[0].cwe_ids == []
        assert findings[0].rule_id == ""

    def test_normalizes_descriptive_cwe_ids(self):
        data = {
            "findings": [
                {
                    "path": "src/foo.ts",
                    "severity": "high",
                    "cweIds": ["CWE-78: OS Command Injection"],
                }
            ]
        }
        assert parse_simple(data)[0].cwe_ids == ["CWE-78"]

    def test_empty_findings(self):
        assert parse_simple({"findings": []}) == []

    def test_path_normalized(self):
        data = {"findings": [{"path": "./src/foo.ts", "severity": "medium"}]}
        assert parse_simple(data)[0].path == "src/foo.ts"


# ── parse_findings dispatch ───────────────────────────────────────────────────


class TestParseFindings:
    def test_auto_sarif(self):
        raw = json.dumps(_sarif([_sarif_result()]))
        findings = parse_findings(raw, "auto")
        assert len(findings) == 1

    def test_auto_simple(self):
        raw = json.dumps({"findings": [{"path": "src/a.ts", "severity": "high"}]})
        findings = parse_findings(raw, "auto")
        assert len(findings) == 1

    def test_forced_sarif(self):
        raw = json.dumps(_sarif([_sarif_result()]))
        findings = parse_findings(raw, "sarif")
        assert len(findings) == 1

    def test_forced_simple(self):
        raw = json.dumps({"findings": [{"path": "src/a.ts", "severity": "high"}]})
        findings = parse_findings(raw, "simple")
        assert len(findings) == 1

    def test_invalid_returns_empty(self):
        assert parse_findings("not json", "auto") == []

    def test_invalid_sarif_security_severity_reports_error(self):
        raw = json.dumps(
            _sarif(
                [_sarif_result(rule_id="rule-1")],
                rules=[
                    {
                        "id": "rule-1",
                        "properties": {"security-severity": "not-a-number"},
                    }
                ],
            )
        )
        findings, error = parse_findings_checked(raw, "auto")
        assert findings == []
        assert (
            error
            == "output is not valid SARIF: invalid security-severity for rule "
            "rule-1: 'not-a-number'"
        )


class TestExtractCweIds:
    def test_extracts_common_sarif_cwe_formats(self):
        assert extract_cwe_ids(
            ["CWE-78: OS Command Injection", "external/cwe/cwe-22", "owasp"]
        ) == ["CWE-78", "CWE-22"]


# ── Severity comparison ───────────────────────────────────────────────────────


class TestSeverityGte:
    def test_equal(self):
        assert severity_gte("high", "high") is True

    def test_higher(self):
        assert severity_gte("critical", "high") is True

    def test_lower(self):
        assert severity_gte("medium", "high") is False

    def test_lowest_vs_highest(self):
        assert severity_gte("low", "critical") is False

    def test_case_insensitive(self):
        assert severity_gte("HIGH", "high") is True

    def test_unknown_reported(self):
        assert severity_gte("unknown", "high") is False

    def test_all_combos(self):
        levels = ["low", "medium", "high", "critical"]
        for i, reported in enumerate(levels):
            for j, minimum in enumerate(levels):
                assert severity_gte(reported, minimum) == (i >= j)


# ── Path overlap ──────────────────────────────────────────────────────────────


class TestPathsOverlap:
    def test_exact_match(self):
        assert paths_overlap(["src/foo.ts"], ["src/foo.ts"]) == ["src/foo.ts"]

    def test_no_overlap(self):
        assert paths_overlap(["src/foo.ts"], ["src/bar.ts"]) == []

    def test_suffix_match(self):
        assert paths_overlap(
            ["src/foo.ts"], ["/home/user/openclaw/src/foo.ts"]
        ) == ["src/foo.ts"]

    def test_normalization(self):
        assert paths_overlap(["src/foo.ts"], ["./src/foo.ts"]) == ["src/foo.ts"]

    def test_multiple_expected_partial(self):
        result = paths_overlap(
            ["src/a.ts", "src/b.ts"], ["src/b.ts"]
        )
        assert result == ["src/b.ts"]

    def test_empty_expected(self):
        assert paths_overlap([], ["src/foo.ts"]) == []

    def test_empty_findings(self):
        assert paths_overlap(["src/foo.ts"], []) == []


# ── Case evaluation ──────────────────────────────────────────────────────────


class TestEvaluateCase:
    def _expected(
        self,
        vuln_class: str = "commandinjection",
        severity: str = "high",
        paths: list[str] | None = None,
    ) -> dict:
        return {
            "vulnerabilityClass": vuln_class,
            "minimumSeverity": severity,
            "expectedPaths": ["src/foo.ts"] if paths is None else paths,
            "description": "test",
        }

    def test_full_detection(self):
        findings = [_finding(path="src/foo.ts", severity="high", cwe_ids=["CWE-78"])]
        result = evaluate_case("GHSA-test-test-test", findings, self._expected())
        assert result["detected"] is True
        assert result["pathMatch"] is True
        assert result["severityMatch"] is True
        assert result["classMatch"] is True

    def test_path_miss(self):
        findings = [_finding(path="src/bar.ts", severity="high", cwe_ids=["CWE-78"])]
        result = evaluate_case("GHSA-test-test-test", findings, self._expected())
        assert result["detected"] is False
        assert result["pathMatch"] is False

    def test_severity_too_low(self):
        findings = [_finding(path="src/foo.ts", severity="medium", cwe_ids=["CWE-78"])]
        result = evaluate_case("GHSA-test-test-test", findings, self._expected())
        assert result["detected"] is False
        assert result["severityMatch"] is False

    def test_class_mismatch(self):
        findings = [_finding(path="src/foo.ts", severity="high", cwe_ids=["CWE-22"])]
        result = evaluate_case("GHSA-test-test-test", findings, self._expected())
        assert result["detected"] is False
        assert result["classMatch"] is False

    def test_no_findings(self):
        result = evaluate_case("GHSA-test-test-test", [], self._expected())
        assert result["detected"] is False

    def test_no_cwe_does_not_satisfy_class_match(self):
        findings = [_finding(path="src/foo.ts", severity="high", cwe_ids=[])]
        result = evaluate_case("GHSA-test-test-test", findings, self._expected())
        assert result["detected"] is False
        assert result["classMatch"] is False

    def test_unknown_cwe_does_not_satisfy_class_match(self):
        findings = [_finding(path="src/foo.ts", severity="high", cwe_ids=["CWE-999"])]
        result = evaluate_case("GHSA-test-test-test", findings, self._expected())
        assert result["detected"] is False
        assert result["classMatch"] is False

    def test_descriptive_cwe_ids_still_satisfy_class_match(self):
        findings = [
            _finding(
                path="src/foo.ts",
                severity="high",
                cwe_ids=["CWE-78: OS Command Injection"],
            )
        ]
        result = evaluate_case("GHSA-test-test-test", findings, self._expected())
        assert result["detected"] is True
        assert result["classMatch"] is True

    def test_multiple_cwes_match_any_expected_class(self):
        findings = [
            _finding(
                path="src/foo.ts",
                severity="high",
                cwe_ids=["CWE-200", "CWE-918"],
            )
        ]
        result = evaluate_case(
            "GHSA-test-test-test",
            findings,
            self._expected(vuln_class="ssrf"),
        )
        assert result["detected"] is True
        assert result["classMatch"] is True

    def test_multiple_findings_one_matches(self):
        findings = [
            _finding(path="src/bar.ts", severity="low"),
            _finding(path="src/foo.ts", severity="high", cwe_ids=["CWE-78"]),
        ]
        result = evaluate_case("GHSA-test-test-test", findings, self._expected())
        assert result["detected"] is True

    def test_empty_expected_paths_treated_as_match(self):
        findings = [_finding(path="src/anything.ts", severity="high", cwe_ids=["CWE-78"])]
        result = evaluate_case(
            "GHSA-test-test-test", findings, self._expected(paths=[])
        )
        assert result["pathMatch"] is True
        assert result["detected"] is True


# ── Results builder ───────────────────────────────────────────────────────────


class TestBuildResults:
    def test_structure(self):
        case_results = [
            {"caseId": "GHSA-aaaa-aaaa-aaaa", "detected": True},
            {"caseId": "GHSA-bbbb-bbbb-bbbb", "detected": False},
        ]
        results = build_results(case_results, "test-scanner scan .")
        assert results["scannerCommand"] == "test-scanner scan ."
        assert results["totalCases"] == 2
        assert results["detected"] == 1
        assert results["detectionRate"] == 0.5
        assert "runAt" in results
        assert len(results["results"]) == 2

    def test_all_detected(self):
        case_results = [{"caseId": "a", "detected": True}]
        assert build_results(case_results, "")["detectionRate"] == 1.0

    def test_none_detected(self):
        case_results = [{"caseId": "a", "detected": False}]
        assert build_results(case_results, "")["detectionRate"] == 0.0

    def test_empty(self):
        assert build_results([], "")["detectionRate"] == 0.0


class TestRunBenchmark:
    def test_uses_temp_worktree_and_preserves_source_repo(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("committed\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "initial"],
            check=True,
        )
        head_before = _git(repo, "rev-parse", "HEAD")
        branch_before = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")

        tracked.write_text("local change\n", encoding="utf-8")
        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, head_before)

        results = run_benchmark(
            _benchmark_args(tmp_path, repo, cases_dir, _simple_scanner_cmd())
        )

        assert results["results"][0]["detected"] is True
        assert results["results"][0]["error"] is None
        assert tracked.read_text(encoding="utf-8") == "local change\n"
        assert _git(repo, "rev-parse", "HEAD") == head_before
        assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == branch_before
        assert _git(repo, "status", "--short") == "M tracked.txt"

    def test_invalid_json_output_is_reported_as_error(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("committed\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "initial"],
            check=True,
        )
        head = _git(repo, "rev-parse", "HEAD")
        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, head)

        results = run_benchmark(
            _benchmark_args(
                tmp_path,
                repo,
                cases_dir,
                'python3 -c "import sys; print(\'not-json\'); sys.exit(2)"',
            )
        )

        assert results["results"][0]["error"] == "output is not valid JSON (exit code 2)"
        assert results["results"][0]["detected"] is False

    def test_nonzero_exit_code_with_parseable_output_is_evaluated(
        self, tmp_path: Path
    ):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("committed\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "initial"],
            check=True,
        )
        head = _git(repo, "rev-parse", "HEAD")
        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, head)

        results = run_benchmark(
            _benchmark_args(
                tmp_path, repo, cases_dir, _simple_scanner_cmd(exit_code=2)
            )
        )

        assert results["results"][0]["error"] is None
        assert results["results"][0]["detected"] is True
        assert results["results"][0]["scannerExitCode"] == 2

    def test_selects_worktree_from_case_repository(self, tmp_path: Path):
        openclaw_repo = tmp_path / "openclaw"
        openclaw_repo.mkdir()
        _init_git_repo(openclaw_repo)
        (openclaw_repo / "tracked.txt").write_text("openclaw\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(openclaw_repo), "add", "tracked.txt"], check=True
        )
        subprocess.run(
            ["git", "-C", str(openclaw_repo), "commit", "-q", "-m", "initial"],
            check=True,
        )
        openclaw_head = _git(openclaw_repo, "rev-parse", "HEAD")

        ghost_repo = tmp_path / "ghost"
        ghost_repo.mkdir()
        _init_git_repo(ghost_repo)
        (ghost_repo / "tracked.txt").write_text("ghost\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(ghost_repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(ghost_repo), "commit", "-q", "-m", "initial"],
            check=True,
        )
        ghost_head = _git(ghost_repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(
            cases_dir,
            openclaw_head,
            case_id="GHSA-aaaa-aaaa-aaaa",
            repository="openclaw/openclaw",
        )
        _write_case(
            cases_dir,
            ghost_head,
            case_id="GHSA-bbbb-bbbb-bbbb",
            repository="TryGhost/Ghost",
        )

        results = run_benchmark(
            _benchmark_args(
                tmp_path,
                openclaw_repo,
                cases_dir,
                _simple_scanner_cmd(),
                openclaw_repo=None,
                repo=[
                    f"openclaw/openclaw={openclaw_repo}",
                    f"TryGhost/Ghost={ghost_repo}",
                ],
            )
        )

        assert [result["caseId"] for result in results["results"]] == [
            "GHSA-aaaa-aaaa-aaaa",
            "GHSA-bbbb-bbbb-bbbb",
        ]
        assert [result["repository"] for result in results["results"]] == [
            "openclaw/openclaw",
            "TryGhost/Ghost",
        ]
        assert [result["detected"] for result in results["results"]] == [True, True]


class TestBaselineCmd:
    def test_baseline_cmd_runs_at_baseline_commit(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"],
            check=True,
        )
        baseline = _git(repo, "rev-parse", "HEAD")

        tracked.write_text("vulnerable\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "vulnerable"],
            check=True,
        )
        vulnerable = _git(repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, vulnerable, baseline_commit=baseline)

        scanner_cmd = (
            "python3 -c "
            "\"import json, pathlib; "
            "sha = pathlib.Path('.baseline-sha').read_text(encoding='utf-8').strip(); "
            f"assert sha == '{baseline}'; "
            "print(json.dumps({'findings': "
            "[{'path': 'src/foo.ts', 'severity': 'high', 'cweIds': ['CWE-22']}]}))\""
        )

        results = run_benchmark(
            _benchmark_args(
                tmp_path,
                repo,
                cases_dir,
                scanner_cmd,
                baseline_cmd="git rev-parse HEAD > .baseline-sha",
                baseline_timeout=10,
            )
        )

        assert results["results"][0]["detected"] is True
        assert results["results"][0]["error"] is None
        assert results["results"][0]["baselineStatus"] == "ok"

    def test_baseline_cmd_stdout_discarded(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"],
            check=True,
        )
        baseline = _git(repo, "rev-parse", "HEAD")

        tracked.write_text("vulnerable\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "vulnerable"],
            check=True,
        )
        vulnerable = _git(repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, vulnerable, baseline_commit=baseline)

        baseline_cmd = (
            "python3 -c "
            '\'print("baseline stdout that should be ignored")\''
        )

        results = run_benchmark(
            _benchmark_args(
                tmp_path,
                repo,
                cases_dir,
                _simple_scanner_cmd(),
                baseline_cmd=baseline_cmd,
                baseline_timeout=10,
            )
        )

        assert results["results"][0]["detected"] is True
        assert results["results"][0]["error"] is None
        assert results["results"][0]["findingCount"] == 1
        assert results["results"][0]["baselineStatus"] == "ok"

    def test_baseline_cmd_nonzero_exit_records_failure(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"],
            check=True,
        )
        baseline = _git(repo, "rev-parse", "HEAD")

        tracked.write_text("vulnerable\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "vulnerable"],
            check=True,
        )
        vulnerable = _git(repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, vulnerable, baseline_commit=baseline)

        results = run_benchmark(
            _benchmark_args(
                tmp_path,
                repo,
                cases_dir,
                _simple_scanner_cmd(),
                baseline_cmd=(
                    'python3 -c "import sys; '
                    "print('baseline boom', file=sys.stderr); sys.exit(1)\""
                ),
                baseline_timeout=10,
            )
        )

        assert results["results"][0]["baselineStatus"] == "fail"
        assert results["results"][0]["scannerExitCode"] is None
        assert (
            results["results"][0]["error"]
            == "baseline failed (exit code 1): baseline boom"
        )

    def test_baseline_cmd_timeout_records_error(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"],
            check=True,
        )
        baseline = _git(repo, "rev-parse", "HEAD")

        tracked.write_text("vulnerable\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "vulnerable"],
            check=True,
        )
        vulnerable = _git(repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, vulnerable, baseline_commit=baseline)

        results = run_benchmark(
            _benchmark_args(
                tmp_path,
                repo,
                cases_dir,
                _simple_scanner_cmd(),
                baseline_cmd='python3 -c "import time; time.sleep(2)"',
                baseline_timeout=1,
            )
        )

        assert results["results"][0]["baselineStatus"] == "fail"
        assert results["results"][0]["scannerExitCode"] is None
        assert results["results"][0]["error"] == "baseline timeout"

    def test_baseline_cmd_checkout_failure_records_error(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("vulnerable\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "vulnerable"],
            check=True,
        )
        vulnerable = _git(repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, vulnerable, baseline_commit="0" * 40)

        results = run_benchmark(
            _benchmark_args(
                tmp_path,
                repo,
                cases_dir,
                _simple_scanner_cmd(),
                baseline_cmd="echo baseline",
                baseline_timeout=10,
            )
        )

        assert results["results"][0]["baselineStatus"] == "fail"
        assert results["results"][0]["scannerExitCode"] is None
        assert "baseline checkout failed" in results["results"][0]["error"]

    def test_no_baseline_cmd_skips_baseline(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"],
            check=True,
        )
        baseline = _git(repo, "rev-parse", "HEAD")

        tracked.write_text("vulnerable\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "vulnerable"],
            check=True,
        )
        vulnerable = _git(repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, vulnerable, baseline_commit=baseline)

        results = run_benchmark(
            _benchmark_args(tmp_path, repo, cases_dir, _simple_scanner_cmd())
        )

        assert results["results"][0]["detected"] is True
        assert results["results"][0]["error"] is None
        assert "baselineStatus" not in results["results"][0]

    def test_untracked_files_cleaned_between_cases(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        phase = repo / "phase.txt"

        phase.write_text("first-baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "phase.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "first baseline"],
            check=True,
        )
        first_baseline = _git(repo, "rev-parse", "HEAD")

        phase.write_text("first-vulnerable\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "first vulnerable"],
            check=True,
        )
        first_vulnerable = _git(repo, "rev-parse", "HEAD")

        phase.write_text("second-baseline\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "second baseline"],
            check=True,
        )
        second_baseline = _git(repo, "rev-parse", "HEAD")

        phase.write_text("second-vulnerable\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "second vulnerable"],
            check=True,
        )
        second_vulnerable = _git(repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(
            cases_dir,
            first_vulnerable,
            baseline_commit=first_baseline,
            case_id="GHSA-aaaa-aaaa-aaaa",
        )
        _write_case(
            cases_dir,
            second_vulnerable,
            baseline_commit=second_baseline,
            case_id="GHSA-bbbb-bbbb-bbbb",
        )

        baseline_cmd = (
            "python3 - <<'PY'\n"
            "import pathlib\n"
            "import subprocess\n"
            "import sys\n"
            "\n"
            "phase = pathlib.Path('phase.txt').read_text(encoding='utf-8').strip()\n"
            "marker = pathlib.Path('.marker')\n"
            "subrepo = pathlib.Path('subrepo')\n"
            "\n"
            "if phase == 'first-baseline':\n"
            "    marker.write_text('marker', encoding='utf-8')\n"
            "    subprocess.run(['git', 'init', '-q', 'subrepo'], check=True)\n"
            "elif phase == 'second-baseline':\n"
            "    if marker.exists() or subrepo.exists():\n"
            "        print('leaked artifacts', file=sys.stderr)\n"
            "        sys.exit(1)\n"
            "else:\n"
            "    print(f'unexpected phase: {phase}', file=sys.stderr)\n"
            "    sys.exit(1)\n"
            "PY"
        )

        results = run_benchmark(
            _benchmark_args(
                tmp_path,
                repo,
                cases_dir,
                _simple_scanner_cmd(),
                baseline_cmd=baseline_cmd,
                baseline_timeout=10,
            )
        )

        assert [r["baselineStatus"] for r in results["results"]] == ["ok", "ok"]
        assert [r["detected"] for r in results["results"]] == [True, True]

    def test_scorecard_shows_baseline_column(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"],
            check=True,
        )
        baseline = _git(repo, "rev-parse", "HEAD")

        tracked.write_text("vulnerable\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "vulnerable"],
            check=True,
        )
        vulnerable = _git(repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, vulnerable, baseline_commit=baseline)

        _, stdout = _run_benchmark_captured(
            _benchmark_args(
                tmp_path,
                repo,
                cases_dir,
                _simple_scanner_cmd(),
                baseline_cmd="echo baseline",
                baseline_timeout=10,
            )
        )

        case_line = next(
            line for line in stdout.splitlines() if "GHSA-test-test-test" in line
        )
        assert "Base" in stdout
        assert "OK" in case_line

    def test_scorecard_hides_baseline_column(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("vulnerable\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "vulnerable"],
            check=True,
        )
        vulnerable = _git(repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, vulnerable)

        _, stdout = _run_benchmark_captured(
            _benchmark_args(tmp_path, repo, cases_dir, _simple_scanner_cmd())
        )

        assert "Base" not in stdout

    def test_scorecard_baseline_fail_on_error_row(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("vulnerable\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "vulnerable"],
            check=True,
        )
        vulnerable = _git(repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, vulnerable, baseline_commit="0" * 40)

        _, stdout = _run_benchmark_captured(
            _benchmark_args(
                tmp_path,
                repo,
                cases_dir,
                _simple_scanner_cmd(),
                baseline_cmd="echo baseline",
                baseline_timeout=10,
            )
        )

        case_line = next(
            line for line in stdout.splitlines() if "GHSA-test-test-test" in line
        )
        assert "FAIL" in case_line

    def test_scorecard_baseline_ok_on_scanner_error_row(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"],
            check=True,
        )
        baseline = _git(repo, "rev-parse", "HEAD")

        tracked.write_text("vulnerable\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "vulnerable"],
            check=True,
        )
        vulnerable = _git(repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, vulnerable, baseline_commit=baseline)

        _, stdout = _run_benchmark_captured(
            _benchmark_args(
                tmp_path,
                repo,
                cases_dir,
                'python3 -c "print(\'not-json\')"',
                baseline_cmd="echo baseline",
                baseline_timeout=10,
            )
        )

        case_line = next(
            line for line in stdout.splitlines() if "GHSA-test-test-test" in line
        )
        assert "OK" in case_line

    def test_cleanup_failure_skips_baseline_and_scanner(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        tracked = repo / "tracked.txt"
        tracked.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"],
            check=True,
        )
        baseline = _git(repo, "rev-parse", "HEAD")

        tracked.write_text("vulnerable\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "vulnerable"],
            check=True,
        )
        vulnerable = _git(repo, "rev-parse", "HEAD")

        cases_dir = tmp_path / "cases"
        _write_case(cases_dir, vulnerable, baseline_commit=baseline)

        with patch("run.clean_worktree", side_effect=RuntimeError("boom")):
            with patch("run.run_scanner") as run_scanner_mock:
                results = run_benchmark(
                    _benchmark_args(
                        tmp_path,
                        repo,
                        cases_dir,
                        _simple_scanner_cmd(),
                        baseline_cmd="echo baseline",
                        baseline_timeout=10,
                    )
                )

        assert results["results"][0]["baselineStatus"] == "fail"
        assert results["results"][0]["scannerExitCode"] is None
        assert "worktree cleanup failed: boom" in results["results"][0]["error"]
        run_scanner_mock.assert_not_called()
