"""Tests for the validation script."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from argparse import Namespace
from pathlib import Path

import pytest

# Ensure scripts/ is importable
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import validate as validate_module
from validate import (
    load_schema,
    validate_case_against_schema,
    validate_case_semantic,
    validate_case_strict,
    validate_manifest_consistency,
    validate_no_duplicate_ids,
    run_validation,
    ValidationError,
)


@pytest.fixture
def schema():
    schema_path = Path(__file__).resolve().parents[1] / "schema" / "case.schema.json"
    return load_schema(schema_path)


def _minimal_case(overrides: dict | None = None) -> dict:
    """Return a minimal valid case.json payload."""
    case = {
        "schemaVersion": "1.0.0",
        "id": "GHSA-test-test-test",
        "advisoryUrl": "https://github.com/openclaw/openclaw/security/advisories/GHSA-test-test-test",
        "repository": "openclaw/openclaw",
        "advisory": {
            "title": "Test vulnerability",
            "severity": "high",
            "publishedAt": "2026-02-14T21:48:57Z",
            "description": "A test vulnerability.",
            "cweIds": ["CWE-22"],
        },
        "timeline": {
            "baselineCommit": "a" * 40,
            "introducingCommits": [
                {
                    "sha": "b" * 40,
                    "authoredAt": "2026-01-12T01:16:39Z",
                    "subject": "feat: introduce vulnerability",
                }
            ],
            "vulnerableHead": "b" * 40,
        },
        "expectedOutcome": {
            "vulnerabilityClass": "pathtraversal",
            "minimumSeverity": "high",
            "expectedPaths": ["src/plugins/install.ts"],
            "description": "Scanner should detect path traversal.",
        },
        "verification": {
            "status": "pass",
            "confidence": "high",
            "checks": [
                {
                    "name": "baseline_ancestor_of_all_intro",
                    "pass": True,
                    "details": "baseline precedes intro",
                }
            ],
        },
        "provenance": {
            "sources": ["securevibes"],
        },
    }
    if overrides:
        _deep_merge(case, overrides)
    return case


def _deep_merge(base: dict, override: dict) -> None:
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


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


class TestSchemaValidation:
    def test_valid_case_passes(self, schema):
        case = _minimal_case()
        errors = validate_case_against_schema(case, schema)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_missing_required_field(self, schema):
        case = _minimal_case()
        del case["id"]
        errors = validate_case_against_schema(case, schema)
        assert len(errors) > 0
        assert any("id" in str(e) for e in errors)

    def test_invalid_ghsa_id_pattern(self, schema):
        case = _minimal_case({"id": "not-a-ghsa-id"})
        errors = validate_case_against_schema(case, schema)
        assert len(errors) > 0

    def test_invalid_severity(self, schema):
        case = _minimal_case()
        case["advisory"]["severity"] = "extreme"
        errors = validate_case_against_schema(case, schema)
        assert len(errors) > 0

    def test_invalid_vulnerability_class(self, schema):
        case = _minimal_case()
        case["expectedOutcome"]["vulnerabilityClass"] = "xss"
        errors = validate_case_against_schema(case, schema)
        assert len(errors) > 0

    def test_invalid_sha_pattern(self, schema):
        case = _minimal_case()
        case["timeline"]["baselineCommit"] = "not-a-sha"
        errors = validate_case_against_schema(case, schema)
        assert len(errors) > 0

    def test_invalid_uri_and_datetime_formats(self, schema):
        case = _minimal_case(
            {
                "advisoryUrl": "not-a-uri",
                "advisory": {"publishedAt": "not-a-date"},
            }
        )
        errors = validate_case_against_schema(case, schema)
        assert any("advisoryUrl" in error.message and "uri" in error.message for error in errors)
        assert any(
            "publishedAt" in error.message and "date-time" in error.message
            for error in errors
        )

    def test_optional_cvss_allowed(self, schema):
        case = _minimal_case()
        case["advisory"]["cvss"] = {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:H",
            "score": 9.3,
        }
        errors = validate_case_against_schema(case, schema)
        assert errors == []

    def test_optional_affected_packages(self, schema):
        case = _minimal_case()
        case["advisory"]["affectedPackages"] = [
            {
                "ecosystem": "npm",
                "name": "openclaw",
                "vulnerableRange": ">= 2026.1.29-beta.1, < 2026.2.1",
                "patchedVersions": ">= 2026.2.1",
            }
        ]
        errors = validate_case_against_schema(case, schema)
        assert errors == []

    def test_extra_field_rejected(self, schema):
        case = _minimal_case()
        case["extraField"] = "should fail"
        errors = validate_case_against_schema(case, schema)
        assert len(errors) > 0

    def test_provenance_invalid_source(self, schema):
        case = _minimal_case()
        case["provenance"]["sources"] = ["unknown-source"]
        errors = validate_case_against_schema(case, schema)
        assert len(errors) > 0

    def test_missing_jsonschema_returns_validation_error(self, monkeypatch, schema):
        def _raise() -> None:
            raise RuntimeError(
                "jsonschema is required for schema validation. "
                "Install with: pip install jsonschema"
            )

        monkeypatch.setattr(validate_module, "_get_jsonschema_validator", _raise)
        errors = validate_case_against_schema(_minimal_case(), schema)
        assert len(errors) == 1
        assert errors[0].check == "schema_dependency"


class TestManifestConsistency:
    def test_matching_manifest(self):
        manifest = {
            "caseCount": 1,
            "cases": [{"id": "GHSA-test-test-test"}],
        }
        case_dirs = ["GHSA-test-test-test"]
        errors = validate_manifest_consistency(manifest, case_dirs)
        assert errors == []

    def test_manifest_missing_case_dir(self):
        manifest = {
            "caseCount": 2,
            "cases": [
                {"id": "GHSA-aaaa-aaaa-aaaa"},
                {"id": "GHSA-bbbb-bbbb-bbbb"},
            ],
        }
        case_dirs = ["GHSA-aaaa-aaaa-aaaa"]
        errors = validate_manifest_consistency(manifest, case_dirs)
        assert len(errors) > 0
        assert any("GHSA-bbbb-bbbb-bbbb" in str(e) for e in errors)

    def test_extra_case_dir_not_in_manifest(self):
        manifest = {
            "caseCount": 1,
            "cases": [{"id": "GHSA-aaaa-aaaa-aaaa"}],
        }
        case_dirs = ["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"]
        errors = validate_manifest_consistency(manifest, case_dirs)
        assert len(errors) > 0

    def test_wrong_case_count(self):
        manifest = {
            "caseCount": 5,
            "cases": [{"id": "GHSA-aaaa-aaaa-aaaa"}],
        }
        case_dirs = ["GHSA-aaaa-aaaa-aaaa"]
        errors = validate_manifest_consistency(manifest, case_dirs)
        assert len(errors) > 0

    def test_duplicate_manifest_case_ids_rejected(self):
        manifest = {
            "caseCount": 2,
            "cases": [
                {"id": "GHSA-aaaa-aaaa-aaaa"},
                {"id": "GHSA-aaaa-aaaa-aaaa"},
            ],
        }
        case_dirs = ["GHSA-aaaa-aaaa-aaaa"]
        errors = validate_manifest_consistency(manifest, case_dirs)
        assert any("Duplicate manifest entry" in error.message for error in errors)

    def test_boolean_case_count_rejected(self):
        manifest = {
            "caseCount": True,
            "cases": [{"id": "GHSA-aaaa-aaaa-aaaa"}],
        }
        case_dirs = ["GHSA-aaaa-aaaa-aaaa"]
        errors = validate_manifest_consistency(manifest, case_dirs)
        assert len(errors) == 1
        assert errors[0].check == "caseCount"
        assert "must be an integer" in errors[0].message

    def test_manifest_fields_must_match_case_payload(self):
        case = _minimal_case()
        manifest = {
            "caseCount": 1,
            "cases": [
                {
                    "id": case["id"],
                    "severity": "low",
                    "title": "Wrong title",
                    "vulnerabilityClass": "abuse",
                    "baselineCommit": "0" * 40,
                    "vulnerableHead": "1" * 40,
                    "verificationStatus": "unverified",
                    "confidence": "low",
                }
            ],
        }

        errors = validate_manifest_consistency(manifest, [case["id"]], [case])

        assert any("severity does not match case.json" in error.message for error in errors)
        assert any("title does not match case.json" in error.message for error in errors)


class TestNoDuplicateIds:
    def test_no_duplicates(self):
        cases = [
            {"id": "GHSA-aaaa-aaaa-aaaa"},
            {"id": "GHSA-bbbb-bbbb-bbbb"},
        ]
        errors = validate_no_duplicate_ids(cases)
        assert errors == []

    def test_duplicates_detected(self):
        cases = [
            {"id": "GHSA-aaaa-aaaa-aaaa"},
            {"id": "GHSA-aaaa-aaaa-aaaa"},
        ]
        errors = validate_no_duplicate_ids(cases)
        assert len(errors) > 0


class TestStrictValidation:
    def test_requires_high_confidence(self):
        case = _minimal_case({"verification": {"confidence": "medium"}})
        errors = validate_case_strict(case)
        assert any("expected 'high'" in str(error) for error in errors)

    def test_requires_non_empty_verification_checks(self):
        case = _minimal_case({"verification": {"checks": []}})
        errors = validate_case_strict(case)
        assert any(
            "verification.checks must contain at least one check" in str(error)
            for error in errors
        )

    def test_run_validation_reports_dependency_when_jsonschema_missing_for_structural_only(
        self, monkeypatch, tmp_path: Path
    ):
        case = _minimal_case()
        case_dir = tmp_path / "cases" / case["id"]
        case_dir.mkdir(parents=True)
        (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")
        (tmp_path / "manifest.json").write_text(
            json.dumps({"caseCount": 1, "cases": [{"id": case["id"]}]}),
            encoding="utf-8",
        )

        def _raise() -> None:
            raise RuntimeError(
                "jsonschema is required for schema validation. "
                "Install with: pip install jsonschema"
            )

        monkeypatch.setattr(validate_module, "_get_jsonschema_validator", _raise)
        errors = run_validation(
            Namespace(openclaw_repo=None, strict=False, output_dir=str(tmp_path))
        )
        assert len(errors) == 1
        assert errors[0].check == "dependency"

    def test_run_validation_reports_manifest_field_mismatch(self, tmp_path: Path):
        case = _minimal_case()
        case_dir = tmp_path / "cases" / case["id"]
        case_dir.mkdir(parents=True)
        (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")
        (tmp_path / "manifest.json").write_text(
            json.dumps(
                {
                    "caseCount": 1,
                    "cases": [
                        {
                            "id": case["id"],
                            "severity": "low",
                            "title": case["advisory"]["title"],
                            "vulnerabilityClass": case["expectedOutcome"][
                                "vulnerabilityClass"
                            ],
                            "baselineCommit": case["timeline"]["baselineCommit"],
                            "vulnerableHead": case["timeline"]["vulnerableHead"],
                            "verificationStatus": case["verification"]["status"],
                            "confidence": case["verification"]["confidence"],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        errors = run_validation(
            Namespace(openclaw_repo=None, strict=False, output_dir=str(tmp_path))
        )

        assert any("severity does not match case.json" in error.message for error in errors)

    def test_run_validation_skips_schema_when_jsonschema_missing_for_semantic_mode(
        self, monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
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

        tracked.write_text("introducing change\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "introduce vuln"],
            check=True,
        )
        intro = _git(repo, "rev-parse", "HEAD")

        case = _minimal_case(
            {
                "timeline": {
                    "baselineCommit": baseline,
                    "introducingCommits": [
                        {
                            "sha": intro,
                            "authoredAt": "2026-01-12T01:16:39Z",
                            "subject": "feat: introduce vulnerability",
                        }
                    ],
                    "vulnerableHead": intro,
                }
            }
        )
        case_dir = tmp_path / "cases" / case["id"]
        case_dir.mkdir(parents=True)
        (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")
        (tmp_path / "manifest.json").write_text(
            json.dumps({"caseCount": 1, "cases": [{"id": case["id"]}]}),
            encoding="utf-8",
        )

        def _raise() -> None:
            raise RuntimeError(
                "jsonschema is required for schema validation. "
                "Install with: pip install jsonschema"
            )

        monkeypatch.setattr(validate_module, "_get_jsonschema_validator", _raise)
        errors = run_validation(
            Namespace(openclaw_repo=str(repo), strict=False, output_dir=str(tmp_path))
        )
        captured = capsys.readouterr()

        assert errors == []
        assert "Skipping schema validation" in captured.err

    def test_run_validation_reports_semantic_shape_error_when_schema_missing(
        self, monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        case = _minimal_case({"timeline": None})
        case_dir = tmp_path / "cases" / case["id"]
        case_dir.mkdir(parents=True)
        (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")
        (tmp_path / "manifest.json").write_text(
            json.dumps({"caseCount": 1, "cases": [{"id": case["id"]}]}),
            encoding="utf-8",
        )
        repo = tmp_path / "repo"
        repo.mkdir()

        def _raise() -> None:
            raise RuntimeError(
                "jsonschema is required for schema validation. "
                "Install with: pip install jsonschema"
            )

        monkeypatch.setattr(validate_module, "_get_jsonschema_validator", _raise)
        errors = run_validation(
            Namespace(openclaw_repo=str(repo), strict=False, output_dir=str(tmp_path))
        )
        captured = capsys.readouterr()

        assert len(errors) == 1
        assert errors[0].check == "semantic"
        assert "timeline must be an object" in errors[0].message
        assert "Skipping schema validation" in captured.err

    def test_run_validation_reports_missing_intro_commit_when_schema_missing(
        self, monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
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

        tracked.write_text("next\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "next"],
            check=True,
        )
        vulnerable_head = _git(repo, "rev-parse", "HEAD")

        case = _minimal_case(
            {
                "timeline": {
                    "baselineCommit": baseline,
                    "introducingCommits": [],
                    "vulnerableHead": vulnerable_head,
                }
            }
        )
        case_dir = tmp_path / "cases" / case["id"]
        case_dir.mkdir(parents=True)
        (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")
        (tmp_path / "manifest.json").write_text(
            json.dumps({"caseCount": 1, "cases": [{"id": case["id"]}]}),
            encoding="utf-8",
        )

        def _raise() -> None:
            raise RuntimeError(
                "jsonschema is required for schema validation. "
                "Install with: pip install jsonschema"
            )

        monkeypatch.setattr(validate_module, "_get_jsonschema_validator", _raise)
        errors = run_validation(
            Namespace(openclaw_repo=str(repo), strict=False, output_dir=str(tmp_path))
        )
        captured = capsys.readouterr()

        assert len(errors) == 1
        assert errors[0].check == "semantic"
        assert "must contain at least one commit" in errors[0].message
        assert "Skipping schema validation" in captured.err

    def test_run_validation_reports_missing_intro_commit_metadata_when_schema_missing(
        self, monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
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

        tracked.write_text("introducing change\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "introduce vuln"],
            check=True,
        )
        intro = _git(repo, "rev-parse", "HEAD")

        case = _minimal_case(
            {
                "timeline": {
                    "baselineCommit": baseline,
                    "introducingCommits": [{"sha": intro}],
                    "vulnerableHead": intro,
                }
            }
        )
        case_dir = tmp_path / "cases" / case["id"]
        case_dir.mkdir(parents=True)
        (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")
        (tmp_path / "manifest.json").write_text(
            json.dumps({"caseCount": 1, "cases": [{"id": case["id"]}]}),
            encoding="utf-8",
        )

        def _raise() -> None:
            raise RuntimeError(
                "jsonschema is required for schema validation. "
                "Install with: pip install jsonschema"
            )

        monkeypatch.setattr(validate_module, "_get_jsonschema_validator", _raise)
        errors = run_validation(
            Namespace(openclaw_repo=str(repo), strict=False, output_dir=str(tmp_path))
        )
        captured = capsys.readouterr()

        assert len(errors) == 2
        assert errors[0].check == "semantic"
        assert (
            "timeline.introducingCommits[0].authoredAt must be a string"
            in errors[0].message
        )
        assert (
            "timeline.introducingCommits[0].subject must be a string"
            in errors[1].message
        )
        assert "Skipping schema validation" in captured.err

    def test_run_validation_reports_commit_sha_shape_errors_when_schema_missing(
        self, monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
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
        tracked.write_text("introducing change\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-qam", "introduce vuln"],
            check=True,
        )

        case = _minimal_case(
            {
                "timeline": {
                    "baselineCommit": "HEAD~1",
                    "introducingCommits": [
                        {
                            "sha": "HEAD",
                            "authoredAt": "2026-01-12T01:16:39Z",
                            "subject": "feat: introduce vulnerability",
                        }
                    ],
                    "vulnerableHead": "HEAD",
                }
            }
        )
        case_dir = tmp_path / "cases" / case["id"]
        case_dir.mkdir(parents=True)
        (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")
        (tmp_path / "manifest.json").write_text(
            json.dumps({"caseCount": 1, "cases": [{"id": case["id"]}]}),
            encoding="utf-8",
        )

        def _raise() -> None:
            raise RuntimeError(
                "jsonschema is required for schema validation. "
                "Install with: pip install jsonschema"
            )

        monkeypatch.setattr(validate_module, "_get_jsonschema_validator", _raise)
        errors = run_validation(
            Namespace(openclaw_repo=str(repo), strict=False, output_dir=str(tmp_path))
        )
        captured = capsys.readouterr()

        assert len(errors) == 3
        assert errors[0].check == "semantic"
        assert "timeline.baselineCommit must be a 40-character" in errors[0].message
        assert (
            "timeline.vulnerableHead must be a 40-character" in errors[1].message
        )
        assert (
            "timeline.introducingCommits[0].sha must be a 40-character"
            in errors[2].message
        )
        assert "Skipping schema validation" in captured.err

    def test_run_validation_reports_strict_shape_error_when_schema_missing(
        self, monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        case = _minimal_case({"verification": None})
        case_dir = tmp_path / "cases" / case["id"]
        case_dir.mkdir(parents=True)
        (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")
        (tmp_path / "manifest.json").write_text(
            json.dumps({"caseCount": 1, "cases": [{"id": case["id"]}]}),
            encoding="utf-8",
        )

        def _raise() -> None:
            raise RuntimeError(
                "jsonschema is required for schema validation. "
                "Install with: pip install jsonschema"
            )

        monkeypatch.setattr(validate_module, "_get_jsonschema_validator", _raise)
        errors = run_validation(
            Namespace(openclaw_repo=None, strict=True, output_dir=str(tmp_path))
        )
        captured = capsys.readouterr()

        assert len(errors) == 1
        assert errors[0].check == "strict"
        assert "verification must be an object" in errors[0].message
        assert "Skipping schema validation" in captured.err

    def test_run_validation_reports_strict_check_type_errors_when_schema_missing(
        self, monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ):
        case = _minimal_case(
            {
                "verification": {
                    "checks": [{"name": 123, "pass": "yes", "details": None}]
                }
            }
        )
        case_dir = tmp_path / "cases" / case["id"]
        case_dir.mkdir(parents=True)
        (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")
        (tmp_path / "manifest.json").write_text(
            json.dumps({"caseCount": 1, "cases": [{"id": case["id"]}]}),
            encoding="utf-8",
        )

        def _raise() -> None:
            raise RuntimeError(
                "jsonschema is required for schema validation. "
                "Install with: pip install jsonschema"
            )

        monkeypatch.setattr(validate_module, "_get_jsonschema_validator", _raise)
        errors = run_validation(
            Namespace(openclaw_repo=None, strict=True, output_dir=str(tmp_path))
        )
        captured = capsys.readouterr()

        assert len(errors) == 3
        assert errors[0].check == "strict"
        assert "verification.checks[0].name must be a string" in errors[0].message
        assert "verification.checks[0].pass must be a boolean" in errors[1].message
        assert "verification.checks[0].details must be a string" in errors[2].message
        assert "Skipping schema validation" in captured.err

    def test_run_validation_reports_invalid_case_json(self, tmp_path: Path):
        case_dir = tmp_path / "cases" / "GHSA-test-test-test"
        case_dir.mkdir(parents=True)
        (case_dir / "case.json").write_text("{not json", encoding="utf-8")
        (tmp_path / "manifest.json").write_text(
            json.dumps({"caseCount": 1, "cases": [{"id": "GHSA-test-test-test"}]}),
            encoding="utf-8",
        )

        errors = run_validation(
            Namespace(openclaw_repo=None, strict=False, output_dir=str(tmp_path))
        )

        assert len(errors) == 1
        assert errors[0].check == "case_file"
        assert "not valid JSON" in errors[0].message


class TestSemanticValidation:
    def test_intro_commit_must_reach_vulnerable_head(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            _init_git_repo(repo)

            tracked = repo / "tracked.txt"
            tracked.write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"],
                check=True,
            )
            baseline = _git(repo, "rev-parse", "HEAD")

            tracked.write_text("introducing change\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-qam", "introduce vuln"],
                check=True,
            )
            intro = _git(repo, "rev-parse", "HEAD")

            subprocess.run(
                ["git", "-C", str(repo), "checkout", "-q", baseline],
                check=True,
            )
            (repo / "other.txt").write_text("different branch\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "other.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-q", "-m", "other branch"],
                check=True,
            )
            vulnerable_head = _git(repo, "rev-parse", "HEAD")

            case = _minimal_case(
                {
                    "timeline": {
                        "baselineCommit": baseline,
                        "introducingCommits": [
                            {
                                "sha": intro,
                                "authoredAt": "2026-01-12T01:16:39Z",
                                "subject": "feat: introduce vulnerability",
                            }
                        ],
                        "vulnerableHead": vulnerable_head,
                    }
                }
            )

            errors = validate_case_semantic(case, repo)

        assert any("intro → vulnerableHead" in str(error) for error in errors)
