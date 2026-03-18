"""Tests for the validation script."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

# Ensure scripts/ is importable
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from validate import (
    load_schema,
    validate_case_against_schema,
    validate_manifest_consistency,
    validate_no_duplicate_ids,
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
