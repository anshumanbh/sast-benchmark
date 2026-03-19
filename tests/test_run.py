"""Tests for the benchmark runner."""

from __future__ import annotations

import json
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest

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
    SEVERITY_ORDER,
    CWE_TO_VULN_CLASS,
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


def _write_case(cases_dir: Path, vulnerable_head: str) -> None:
    case_dir = cases_dir / "GHSA-test-test-test"
    case_dir.mkdir(parents=True)
    (case_dir / "case.json").write_text(
        json.dumps(
            {
                "id": "GHSA-test-test-test",
                "timeline": {"vulnerableHead": vulnerable_head},
                "expectedOutcome": {
                    "vulnerabilityClass": "pathtraversal",
                    "minimumSeverity": "high",
                    "expectedPaths": ["src/foo.ts"],
                },
            }
        ),
        encoding="utf-8",
    )


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
            Namespace(
                openclaw_repo=str(repo),
                scanner_cmd=(
                    "python3 -c "
                    "\"import json; print(json.dumps({'findings': "
                    "[{'path': 'src/foo.ts', 'severity': 'high', "
                    "'cweIds': ['CWE-22']}]}))\""
                ),
                output=str(tmp_path / "results.json"),
                cases_dir=str(cases_dir),
                timeout=10,
                format="auto",
                filter=None,
            )
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
            Namespace(
                openclaw_repo=str(repo),
                scanner_cmd='python3 -c "import sys; print(\'not-json\'); sys.exit(2)"',
                output=str(tmp_path / "results.json"),
                cases_dir=str(cases_dir),
                timeout=10,
                format="auto",
                filter=None,
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
            Namespace(
                openclaw_repo=str(repo),
                scanner_cmd=(
                    "python3 -c "
                    "\"import json, sys; print(json.dumps({'findings': "
                    "[{'path': 'src/foo.ts', 'severity': 'high', "
                    "'cweIds': ['CWE-22']}]})); sys.exit(2)\""
                ),
                output=str(tmp_path / "results.json"),
                cases_dir=str(cases_dir),
                timeout=10,
                format="auto",
                filter=None,
            )
        )

        assert results["results"][0]["error"] is None
        assert results["results"][0]["detected"] is True
        assert results["results"][0]["scannerExitCode"] == 2
