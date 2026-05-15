"""Unit tests for sast-watch skill helpers."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HELPERS_DIR = (
    Path(__file__).resolve().parents[1]
    / ".claude" / "skills" / "sast-watch" / "scripts"
)
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

import build_case  # noqa: E402
import filter_advisories  # noqa: E402
import state  # noqa: E402


# ---------- state.py ----------


def test_load_state_returns_seed_when_missing(tmp_path):
    state_path = tmp_path / "missing.json"
    result = state.load_state(state_path, repository="openclaw/openclaw")
    assert result == {
        "repository": "openclaw/openclaw",
        "ghsa_ids": [],
        "last_seen": None,
    }


def test_load_state_raises_when_missing_and_no_repo(tmp_path):
    state_path = tmp_path / "missing.json"
    with pytest.raises(FileNotFoundError):
        state.load_state(state_path)


def test_seed_state_from_manifest_picks_only_target_repo(tmp_path):
    manifest = {
        "name": "Test",
        "schemaVersion": "1.0.0",
        "generatedAt": "2026-01-01T00:00:00Z",
        "repositories": ["openclaw/openclaw", "TryGhost/Ghost"],
        "caseCount": 3,
        "cases": [
            {"id": "GHSA-aaaa-bbbb-cccc"},
            {"id": "GHSA-dddd-eeee-ffff"},
            {"id": "GHSA-gggg-hhhh-iiii"},
        ],
    }
    cases_dir = tmp_path / "cases"
    for ghsa, repo in [
        ("GHSA-aaaa-bbbb-cccc", "openclaw/openclaw"),
        ("GHSA-dddd-eeee-ffff", "TryGhost/Ghost"),
        ("GHSA-gggg-hhhh-iiii", "openclaw/openclaw"),
    ]:
        d = cases_dir / ghsa
        d.mkdir(parents=True)
        (d / "case.json").write_text(json.dumps({"id": ghsa, "repository": repo}))
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    state_path = tmp_path / "state.json"

    result = state.seed_state_from_manifest(
        manifest_path=manifest_path,
        cases_dir=cases_dir,
        repository="openclaw/openclaw",
        state_path=state_path,
    )

    assert result["repository"] == "openclaw/openclaw"
    assert set(result["ghsa_ids"]) == {
        "GHSA-aaaa-bbbb-cccc",
        "GHSA-gggg-hhhh-iiii",
    }
    saved = json.loads(state_path.read_text())
    assert saved == result


def test_add_ghsa_to_state_is_idempotent(tmp_path):
    state_path = tmp_path / "state.json"
    state.save_state(
        state_path,
        {
            "repository": "openclaw/openclaw",
            "ghsa_ids": ["GHSA-aaaa-bbbb-cccc"],
            "last_seen": None,
        },
    )
    state.add_ghsa_to_state(state_path, "GHSA-aaaa-bbbb-cccc")
    state.add_ghsa_to_state(state_path, "GHSA-dddd-eeee-ffff")
    saved = json.loads(state_path.read_text())
    assert sorted(saved["ghsa_ids"]) == [
        "GHSA-aaaa-bbbb-cccc",
        "GHSA-dddd-eeee-ffff",
    ]


# ---------- filter_advisories.py ----------


def test_filter_new_advisories_keeps_high_and_critical_only():
    advisories = [
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "severity": "high",
            "published_at": "2026-05-15T00:00:00Z",
        },
        {
            "ghsa_id": "GHSA-dddd-eeee-ffff",
            "severity": "critical",
            "published_at": "2026-05-15T00:00:00Z",
        },
        {
            "ghsa_id": "GHSA-gggg-hhhh-iiii",
            "severity": "medium",
            "published_at": "2026-05-15T00:00:00Z",
        },
        {
            "ghsa_id": "GHSA-jjjj-kkkk-llll",
            "severity": "low",
            "published_at": "2026-05-15T00:00:00Z",
        },
    ]
    out = filter_advisories.filter_new_advisories(
        advisories, known_ghsa_ids=set(), cutoff_iso="2026-05-14T00:00:00Z"
    )
    assert [a["ghsa_id"] for a in out] == [
        "GHSA-aaaa-bbbb-cccc",
        "GHSA-dddd-eeee-ffff",
    ]


def test_filter_new_advisories_drops_older_than_cutoff():
    advisories = [
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "severity": "high",
            "published_at": "2026-05-15T00:00:00Z",
        },
        {
            "ghsa_id": "GHSA-old1-old1-old1",
            "severity": "high",
            "published_at": "2026-05-13T23:59:59Z",
        },
    ]
    out = filter_advisories.filter_new_advisories(
        advisories, known_ghsa_ids=set(), cutoff_iso="2026-05-14T00:00:00Z"
    )
    assert [a["ghsa_id"] for a in out] == ["GHSA-aaaa-bbbb-cccc"]


def test_filter_new_advisories_drops_known():
    advisories = [
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "severity": "high",
            "published_at": "2026-05-15T00:00:00Z",
        },
        {
            "ghsa_id": "GHSA-dddd-eeee-ffff",
            "severity": "critical",
            "published_at": "2026-05-15T00:00:00Z",
        },
    ]
    out = filter_advisories.filter_new_advisories(
        advisories,
        known_ghsa_ids={"GHSA-aaaa-bbbb-cccc"},
        cutoff_iso="2026-05-14T00:00:00Z",
    )
    assert [a["ghsa_id"] for a in out] == ["GHSA-dddd-eeee-ffff"]


def test_filter_new_advisories_handles_uppercase_severity():
    advisories = [
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "severity": "HIGH",
            "published_at": "2026-05-15T00:00:00Z",
        },
    ]
    out = filter_advisories.filter_new_advisories(
        advisories, known_ghsa_ids=set(), cutoff_iso="2026-05-14T00:00:00Z"
    )
    assert [a["ghsa_id"] for a in out] == ["GHSA-aaaa-bbbb-cccc"]


# ---------- build_case.py ----------


def test_cwe_bridge_appends_for_abuse_when_no_mapping_cwe():
    bridged = build_case.apply_cwe_bridge(
        ["CWE-190"], vulnerability_class="abuse"
    )
    assert bridged == ["CWE-190", "CWE-400"]


def test_cwe_bridge_no_op_when_commandinjection():
    bridged = build_case.apply_cwe_bridge(
        ["CWE-78"], vulnerability_class="commandinjection"
    )
    assert bridged == ["CWE-78"]


def test_cwe_bridge_no_op_when_brokenauthz_already_maps():
    bridged = build_case.apply_cwe_bridge(
        ["CWE-285"], vulnerability_class="brokenauthz"
    )
    assert bridged == ["CWE-285"]


def test_cwe_bridge_appends_for_brokenauthz_when_no_mapping_cwe():
    bridged = build_case.apply_cwe_bridge(
        ["CWE-99999"], vulnerability_class="brokenauthz"
    )
    assert bridged == ["CWE-99999", "CWE-863"]


def test_cwe_bridge_does_not_duplicate_bridge_cwe():
    bridged = build_case.apply_cwe_bridge(
        ["CWE-400"], vulnerability_class="abuse"
    )
    assert bridged == ["CWE-400"]


def test_build_case_emits_required_keys_and_applies_bridge():
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "summary": "Test vuln",
        "severity": "high",
        "published_at": "2026-05-15T00:00:00Z",
        "description": "A test vulnerability.",
        "cwes": [{"cwe_id": "CWE-190"}],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "go", "name": "github.com/example/repo"},
                "vulnerable_version_range": ">= 1.0.0, <= 1.0.5",
                "patched_versions": "1.0.6",
            }
        ],
    }
    case = build_case.build_case(
        advisory=advisory,
        repository="example/repo",
        timeline={
            "baselineCommit": "a" * 40,
            "introducingCommits": [
                {
                    "sha": "b" * 40,
                    "authoredAt": "2024-01-01T00:00:00Z",
                    "subject": "Add feature",
                }
            ],
            "vulnerableHead": "c" * 40,
            "notes": "test notes",
        },
        vulnerability_class="abuse",
        expected_paths=["src/foo.go"],
        confidence="high",
    )
    assert case["schemaVersion"] == "1.0.0"
    assert case["id"] == "GHSA-aaaa-bbbb-cccc"
    assert case["repository"] == "example/repo"
    assert case["advisory"]["severity"] == "high"
    assert case["advisory"]["cweIds"] == ["CWE-190", "CWE-400"]
    assert case["expectedOutcome"]["vulnerabilityClass"] == "abuse"
    assert case["expectedOutcome"]["expectedPaths"] == ["src/foo.go"]
    assert case["timeline"]["baselineCommit"] == "a" * 40
    assert case["verification"]["confidence"] == "high"
    assert case["verification"]["status"] == "pass"


def test_build_case_validates_against_repo_schema():
    """Built case must satisfy the repo's JSON Schema (with checks added)."""
    import importlib.util
    repo_root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "validate_mod", repo_root / "scripts" / "validate.py"
    )
    validate_mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(repo_root / "scripts"))
    spec.loader.exec_module(validate_mod)
    schema = validate_mod.load_schema()

    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "html_url": "https://github.com/example/repo/security/advisories/GHSA-aaaa-bbbb-cccc",
        "summary": "Test vuln",
        "severity": "high",
        "published_at": "2026-05-15T00:00:00Z",
        "description": "A test vulnerability.",
        "cwes": [{"cwe_id": "CWE-22"}],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "go", "name": "github.com/example/repo"},
                "vulnerable_version_range": ">= 1.0.0, <= 1.0.5",
                "patched_versions": "1.0.6",
            }
        ],
    }
    case = build_case.build_case(
        advisory=advisory,
        repository="example/repo",
        timeline={
            "baselineCommit": "a" * 40,
            "introducingCommits": [
                {
                    "sha": "b" * 40,
                    "authoredAt": "2024-01-01T00:00:00Z",
                    "subject": "Add feature",
                }
            ],
            "vulnerableHead": "c" * 40,
            "notes": "test notes",
        },
        vulnerability_class="pathtraversal",
        expected_paths=["src/foo.go"],
        confidence="high",
    )
    case["verification"]["checks"] = [
        {"name": "advisory_published", "pass": True, "details": "ok"},
    ]

    errors = validate_mod.validate_case_against_schema(case, schema)
    assert errors == [], f"Schema errors: {[str(e) for e in errors]}"
