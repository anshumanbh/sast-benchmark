"""Tests for the migration script."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from migrate import (
    CWE_TO_CLASS,
    AGENT_ONLY_CASE_MAPPING,
    CASE_RESEARCH_OVERRIDES,
    SECUREVIBES_CASE_IDS,
    AGENT_CASE_IDS,
    OVERLAP_IDS,
    load_securevibes_case,
    load_agent_scenarios,
    build_unified_case,
    build_manifest,
)


class TestConstants:
    def test_24_unique_cases(self):
        all_ids = set(SECUREVIBES_CASE_IDS) | set(AGENT_CASE_IDS)
        assert len(all_ids) == 24

    def test_3_overlapping(self):
        assert len(OVERLAP_IDS) == 3
        for oid in OVERLAP_IDS:
            assert oid in SECUREVIBES_CASE_IDS
            assert oid in AGENT_CASE_IDS

    def test_14_agent_only(self):
        agent_only = set(AGENT_CASE_IDS) - set(SECUREVIBES_CASE_IDS)
        assert len(agent_only) == 14
        for cid in agent_only:
            assert cid in AGENT_ONLY_CASE_MAPPING

    def test_cwe_mapping_covers_known_cwes(self):
        assert CWE_TO_CLASS["CWE-22"] == "pathtraversal"
        assert CWE_TO_CLASS["CWE-78"] == "commandinjection"
        assert CWE_TO_CLASS["CWE-918"] == "ssrf"
        assert CWE_TO_CLASS["CWE-94"] == "codeexec"
        assert CWE_TO_CLASS["CWE-287"] == "authbypass"
        assert CWE_TO_CLASS["CWE-863"] == "brokenauthz"

    def test_gv46_research_override_present(self):
        override = CASE_RESEARCH_OVERRIDES["GHSA-gv46-4xfq-jv58"]
        assert override["verification_confidence"] == "high"
        assert any(
            check["name"] == "intro_contains_approval_bypass"
            for check in override["verification_checks"]
        )


class TestLoadAgentScenarios:
    def test_parse_ground_truth(self):
        data = {
            "suite": "test",
            "version": "1.0.0",
            "scenarios": [
                {
                    "id": "GHSA-test-test-test",
                    "advisoryUrl": "https://example.com",
                    "title": "Test vuln",
                    "vulnerableRef": "aaa^",
                    "fixedRef": "aaa",
                    "expectedVulnerabilityClass": "authbypass",
                    "expectedPathContains": ["src/foo.ts"],
                    "minimumSeverity": "high",
                }
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            scenarios = load_agent_scenarios(Path(f.name))

        assert len(scenarios) == 1
        assert scenarios[0]["id"] == "GHSA-test-test-test"
        assert scenarios[0]["expectedVulnerabilityClass"] == "authbypass"


class TestBuildUnifiedCase:
    def _make_advisory_data(self, ghsa_id="GHSA-test-test-test"):
        return {
            "ghsa_id": ghsa_id,
            "severity": "high",
            "published_at": "2026-02-14T21:48:57Z",
            "updated_at": "2026-02-14T21:56:15Z",
            "summary": "Test vulnerability",
            "description": "A test vuln description",
            "html_url": f"https://github.com/openclaw/openclaw/security/advisories/{ghsa_id}",
            "cwe_ids": ["CWE-22"],
            "cvss_severities": {
                "cvss_v3": {
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:H",
                    "score": 9.3,
                }
            },
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "openclaw"},
                    "vulnerable_version_range": ">= 1.0, < 2.0",
                    "patched_versions": ">= 2.0",
                }
            ],
        }

    def test_build_securevibes_only_case(self):
        advisory_data = self._make_advisory_data()
        timeline_data = {
            "baseline_commit": "a" * 40,
            "introducing_commits": [
                {
                    "sha": "b" * 40,
                    "short": "bbbbbbbbb",
                    "authored_at": "2026-01-12T01:16:39Z",
                    "subject": "feat: introduce vulnerability",
                }
            ],
            "vulnerable_head": "b" * 40,
            "notes": "Test notes",
        }
        verification_data = {
            "verification_pass": True,
            "confidence": "high",
            "checks": [
                {
                    "name": "baseline_ancestor_of_all_intro",
                    "pass": True,
                    "details": "ok",
                }
            ],
        }

        case = build_unified_case(
            ghsa_id="GHSA-test-test-test",
            advisory_data=advisory_data,
            timeline_data=timeline_data,
            verification_data=verification_data,
            agent_scenario=None,
            vuln_class_override="pathtraversal",
            expected_paths_override=["src/test.ts"],
        )

        assert case["schemaVersion"] == "1.0.0"
        assert case["id"] == "GHSA-test-test-test"
        assert case["repository"] == "openclaw/openclaw"
        assert case["advisory"]["severity"] == "high"
        assert case["timeline"]["baselineCommit"] == "a" * 40
        assert "fixCommits" not in case["timeline"]
        assert "fixHead" not in case["timeline"]
        assert "scanRanges" not in case["timeline"]
        assert case["expectedOutcome"]["vulnerabilityClass"] == "pathtraversal"
        assert case["verification"]["status"] == "pass"
        assert "securevibes" in case["provenance"]["sources"]

    def test_build_merged_case(self):
        advisory_data = self._make_advisory_data()
        timeline_data = {
            "baseline_commit": "a" * 40,
            "introducing_commits": [
                {
                    "sha": "b" * 40,
                    "short": "bbbbbbbbb",
                    "authored_at": "2026-01-12T01:16:39Z",
                    "subject": "feat: introduce vulnerability",
                }
            ],
            "vulnerable_head": "b" * 40,
            "notes": "Test notes",
        }
        verification_data = {
            "verification_pass": True,
            "confidence": "high",
            "checks": [],
        }
        agent_scenario = {
            "id": "GHSA-test-test-test",
            "expectedVulnerabilityClass": "sandboxescape",
            "expectedPathContains": ["src/sandbox.ts"],
            "minimumSeverity": "high",
        }

        case = build_unified_case(
            ghsa_id="GHSA-test-test-test",
            advisory_data=advisory_data,
            timeline_data=timeline_data,
            verification_data=verification_data,
            agent_scenario=agent_scenario,
        )

        # Vuln class and paths from agent
        assert case["expectedOutcome"]["vulnerabilityClass"] == "sandboxescape"
        assert case["expectedOutcome"]["expectedPaths"] == ["src/sandbox.ts"]
        # No fix fields in timeline
        assert "fixCommits" not in case["timeline"]
        assert "fixHead" not in case["timeline"]
        assert "scanRanges" not in case["timeline"]
        # Both sources
        assert "securevibes" in case["provenance"]["sources"]
        assert "securevibes-agent" in case["provenance"]["sources"]

    def test_research_override_upgrades_gv46_confidence(self):
        advisory_data = self._make_advisory_data("GHSA-gv46-4xfq-jv58")
        timeline_data = {
            "baseline_commit": "a" * 40,
            "introducing_commits": [
                {
                    "sha": "b" * 40,
                    "short": "bbbbbbbbb",
                    "authored_at": "2026-01-12T01:16:39Z",
                    "subject": "feat: introduce vulnerability",
                }
            ],
            "vulnerable_head": "b" * 40,
            "notes": "Original note",
        }
        verification_data = {
            "verification_pass": True,
            "confidence": "medium",
            "checks": [
                {
                    "name": "baseline_ancestor_of_all_intro",
                    "pass": True,
                    "details": "ok",
                }
            ],
        }
        agent_scenario = {
            "id": "GHSA-gv46-4xfq-jv58",
            "expectedVulnerabilityClass": "commandinjection",
            "expectedPathContains": ["src/gateway/server-methods/nodes.ts"],
            "minimumSeverity": "high",
        }

        case = build_unified_case(
            ghsa_id="GHSA-gv46-4xfq-jv58",
            advisory_data=advisory_data,
            timeline_data=timeline_data,
            verification_data=verification_data,
            agent_scenario=agent_scenario,
        )

        assert case["verification"]["confidence"] == "high"
        assert "public history contains a matching remediation train" in case["timeline"]["notes"]
        assert any(
            check["name"] == "public_fix_train_reaches_patched_tag"
            for check in case["verification"]["checks"]
        )


class TestBuildManifest:
    def test_manifest_structure(self):
        cases = [
            {
                "id": "GHSA-aaaa-aaaa-aaaa",
                "advisory": {"severity": "high", "title": "Test"},
                "timeline": {
                    "baselineCommit": "a" * 40,
                    "vulnerableHead": "b" * 40,
                },
                "expectedOutcome": {
                    "vulnerabilityClass": "pathtraversal",
                },
                "verification": {"status": "pass", "confidence": "high"},
            }
        ]
        manifest = build_manifest(cases)
        assert manifest["name"] == "openclaw-advisory-benchmark"
        assert manifest["caseCount"] == 1
        assert manifest["cases"][0]["id"] == "GHSA-aaaa-aaaa-aaaa"
        assert manifest["cases"][0]["severity"] == "high"
        assert "fixHead" not in manifest["cases"][0]
