#!/usr/bin/env python3
"""Migrate and consolidate benchmark data from securevibes and securevibes-agent.

Produces 24 unified case.json files + manifest.json from:
- securevibes/docs/benchmarks/openclaw-ghsa-batch1/cases/ (10 cases)
- securevibes-agent/docs/testing/openclaw-advisory-ground-truth.json (17 scenarios)
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── IDs ────────────────────────────────────────────────────────────────────────

SECUREVIBES_CASE_IDS = [
    "GHSA-qrq5-wjgg-rvqw",
    "GHSA-4rj2-gpmh-qq5x",
    "GHSA-gv46-4xfq-jv58",
    "GHSA-3c6h-g97w-fg78",
    "GHSA-r5fq-947m-xm57",
    "GHSA-943q-mwmv-hhvh",
    "GHSA-g8p2-7wf7-98mq",
    "GHSA-mc68-q9jw-2h3v",
    "GHSA-x22m-j5qq-j49m",
    "GHSA-g55j-c2v4-pjcg",
]

AGENT_CASE_IDS = [
    "GHSA-4rj2-gpmh-qq5x",
    "GHSA-mwxv-35wr-4vvj",
    "GHSA-6f6j-wx9w-ff4j",
    "GHSA-474h-prjg-mmw3",
    "GHSA-q399-23r3-hfx4",
    "GHSA-mgrq-9f93-wpp5",
    "GHSA-gp3q-wpq4-5c5h",
    "GHSA-4jpw-hj22-2xmc",
    "GHSA-gv46-4xfq-jv58",
    "GHSA-qrq5-wjgg-rvqw",
    "GHSA-5wcw-8jjv-m286",
    "GHSA-6mgf-v5j7-45cr",
    "GHSA-jq3f-vjww-8rq7",
    "GHSA-63f5-hhc7-cx6p",
    "GHSA-rqpp-rjj8-7wv8",
    "GHSA-99qw-6mr3-36qr",
    "GHSA-r7vr-gr74-94p8",
]

OVERLAP_IDS = ["GHSA-4rj2-gpmh-qq5x", "GHSA-gv46-4xfq-jv58", "GHSA-qrq5-wjgg-rvqw"]

# ── CWE-to-vulnerability-class mapping ────────────────────────────────────────

CWE_TO_CLASS: dict[str, str] = {
    "CWE-22": "pathtraversal",
    "CWE-78": "commandinjection",
    "CWE-918": "ssrf",
    "CWE-94": "codeexec",
    "CWE-287": "authbypass",
    "CWE-306": "authbypass",
    "CWE-863": "brokenauthz",
    "CWE-20": "commandinjection",
    "CWE-441": "commandinjection",
}

# Override table for ambiguous cases
VULN_CLASS_OVERRIDES: dict[str, str] = {
    "GHSA-gv46-4xfq-jv58": "commandinjection",
    "GHSA-g8p2-7wf7-98mq": "secretdisclosure",
    "GHSA-mc68-q9jw-2h3v": "commandinjection",
    "GHSA-x22m-j5qq-j49m": "ssrf",
    "GHSA-g55j-c2v4-pjcg": "codeexec",
    "GHSA-3c6h-g97w-fg78": "commandinjection",
    "GHSA-r5fq-947m-xm57": "pathtraversal",
    "GHSA-943q-mwmv-hhvh": "brokenauthz",
}

CASE_RESEARCH_OVERRIDES: dict[str, dict[str, Any]] = {
    "GHSA-gv46-4xfq-jv58": {
        "timeline_notes": (
            "Advisory text lists non-resolving full SHAs for the initial gateway "
            "fixes, but the local public history contains a matching remediation "
            "train on the vulnerable path: "
            "318379cdba1804eb840896f6ebd4dd6dd0fb53cb, "
            "a7af646fdfc5cff077c04a7abb7c9e7a9c0b9f70, "
            "c15946274ed62cce3846f0feea723bc83404b462, "
            "0af76f5f0e93540efbdf054895216c398692afcd, followed by "
            "cb3290fca32593956638f161d9776266b90ab891 and "
            "01b3226ecbea6f5aa2a433237dae87d181d8790f before tag "
            "v2026.2.14 (b5ab92eef4e4f6099c98817e0917c99ec9e03045). "
            "The introducing commit 2f8206862a684d14f7ca92e9fe0dbce627c5d82b "
            "forwards raw node.invoke params to the node host, whose runner trusts "
            "params.approved === true; the parent baseline still used socket-"
            "mediated approvals and lacks this bypass."
        ),
        "verification_confidence": "high",
        "verification_checks": [
            {
                "name": "intro_contains_approval_bypass",
                "pass": True,
                "details": (
                    "intro=2f8206862a684d14f7ca92e9fe0dbce627c5d82b forwards raw "
                    "node.invoke params via context.nodeRegistry.invoke({params: p.params}); "
                    "node-host runner at that commit treats params.approved === true "
                    "as approval. baseline parent 3467b0ba074cba456cf20d2178faff96bacaeafb "
                    "still uses requestExecApprovalViaSocket."
                ),
            },
            {
                "name": "public_fix_train_reaches_patched_tag",
                "pass": True,
                "details": (
                    "public_fix_train="
                    "318379cdba1804eb840896f6ebd4dd6dd0fb53cb,"
                    "a7af646fdfc5cff077c04a7abb7c9e7a9c0b9f70,"
                    "c15946274ed62cce3846f0feea723bc83404b462,"
                    "0af76f5f0e93540efbdf054895216c398692afcd,"
                    "cb3290fca32593956638f161d9776266b90ab891,"
                    "01b3226ecbea6f5aa2a433237dae87d181d8790f "
                    "patched_tag=v2026.2.14 "
                    "tag_commit=b5ab92eef4e4f6099c98817e0917c99ec9e03045"
                ),
            },
        ],
    }
}

# ── Researched agent-only case mapping ─────────────────────────────────────────
# Each entry contains the introducing commit(s), notes, confidence, and baseline
# derived from git blame/log analysis against the openclaw repo.

AGENT_ONLY_CASE_MAPPING: dict[str, dict[str, Any]] = {
    "GHSA-mwxv-35wr-4vvj": {
        "introducing_commits": [
            "258d615c4d952926dc552be7776635f870ef3c9f",
            "08e3357480ffabb1623bd56735bc8961d3b4938c",
            "53d10f8688b467a9290990e86c496063158affa3",
            "cef5fae0a25eb43524fcefa7514773fbc91e4528",
        ],
        "confidence": "high",
        "notes": "Plugin auth path canonicalization introduced across gateway security refactors left encoded dot-segment traversal bypass.",
    },
    "GHSA-6f6j-wx9w-ff4j": {
        "introducing_commits": ["a7d56e3554d088d437477d97d2c967754b9b1f5d"],
        "confidence": "high",
        "notes": "ACP thread-bound agents feature introduced Windows cmd wrapper with shell fallback vulnerable to cwd injection.",
    },
    "GHSA-474h-prjg-mmw3": {
        "introducing_commits": ["a7d56e3554d088d437477d97d2c967754b9b1f5d"],
        "confidence": "high",
        "notes": "ACP thread-bound agents feature added sessions_spawn ACP runtime path without sandbox inheritance enforcement.",
    },
    "GHSA-q399-23r3-hfx4": {
        "introducing_commits": [
            "cb3290fca32593956638f161d9776266b90ab891",
            "6007941f04df1edcca679dd6c95949744fdbd4df",
            "9a4b2266ccb9eaf011014d86b6a559b0a78b39ea",
            "10481097f8e6dd0346db9be0b5f27570e1bdfcfa",
        ],
        "confidence": "high",
        "notes": "system.run approval binding evolved across several security refactors without pinning PATH-token executable identity, allowing symlink rebind.",
    },
    "GHSA-mgrq-9f93-wpp5": {
        "introducing_commits": ["de61e9c9771899d76710251c2f445a75d6488644"],
        "confidence": "high",
        "notes": "Path alias guard policy unification left workspace boundary bypass for non-existent out-of-root symlink leaf.",
    },
    "GHSA-gp3q-wpq4-5c5h": {
        "introducing_commits": [
            "c96ffa7186a43cda7aa5e2b865a194f94c24d42e",
            "2493455f08d0dabd570f69ac1a460fc3f85a0b17",
            "8bdda7a651c21e98faccdbbd73081e79cffe8be0",
            "bce643a0bd145d3e9cb55400af33bd1b85baeb02",
            "9a5bfb1fe56d9000a6e089bf0c3fca8081710bb0",
        ],
        "confidence": "high",
        "notes": "LINE plugin and webhook evolution introduced DM pairing-store entries that could bypass group allowlist scope checks.",
    },
    "GHSA-4jpw-hj22-2xmc": {
        "introducing_commits": [
            "73e9e787b4df7705556f199f5f3e00580fab38c3",
            "9dbc1435a6cac576d5fd71f4e4bff11a5d9d43ba",
            "d88b239d3c8a5683a1375affae008191e81d3923",
            "e5f7435d9f941822d7fbf6f050ab725237eb2632",
        ],
        "confidence": "high",
        "notes": "Device auth/pairing unification and token rotation allowed scope escalation beyond caller-held scopes.",
    },
    "GHSA-5wcw-8jjv-m286": {
        "introducing_commits": ["20c2db21035e8706ccbd63d553e8042c19bbf8f1"],
        "confidence": "high",
        "notes": "Browser auth hardening path split allowed trusted-proxy WebSocket handshakes to bypass origin validation.",
    },
    "GHSA-6mgf-v5j7-45cr": {
        "introducing_commits": [
            "81c68f582d4a9a20d9cca9f367d2da9edc5a65ae",
            "9bd64c8a1f91dda602afc1d5246a2ff2be164647",
        ],
        "confidence": "high",
        "notes": "SSRF guard implementation did not strip custom authorization headers on cross-origin redirects.",
    },
    "GHSA-jq3f-vjww-8rq7": {
        "introducing_commits": ["ee594e2fdb718da52e87a41d0414b16c322a9af6"],
        "confidence": "high",
        "notes": "Telegram webhook fix read request bodies before secret validation, enabling unauthenticated resource exhaustion.",
    },
    "GHSA-63f5-hhc7-cx6p": {
        "introducing_commits": ["bf89947a8e9ec5d278b71a8c438ce414dd04a2d6"],
        "confidence": "high",
        "notes": "Bootstrap token implementation allowed setup code replay to escalate pending pairing scopes before approval.",
    },
    "GHSA-rqpp-rjj8-7wv8": {
        "introducing_commits": [
            "51149fcaf15a04872965ae80137b1d88f918d189",
            "9c142993b89dd3f75360552c3bdf9fa2e1e76546",
        ],
        "confidence": "high",
        "notes": "WebSocket connect/role policy extraction and shared-auth operator scope preservation allowed scope self-declaration.",
    },
    "GHSA-99qw-6mr3-36qr": {
        "introducing_commits": ["e8775cda932fbe8c949cba925abdc8e419bb7829"],
        "confidence": "high",
        "notes": "Re-exposing configured tools under restrictive profiles allowed workspace plugin auto-discovery to execute code from cloned repos.",
    },
    "GHSA-r7vr-gr74-94p8": {
        "introducing_commits": ["08e020881d6e1c868ec59e5d0b7d040a60afcec7"],
        "confidence": "high",
        "notes": "Command gating unification allowed command-authorized non-owners to reach owner-only /config and /debug surfaces.",
    },
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def git_cmd(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo)] + list(args),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git command failed: git -C {repo} {' '.join(args)}\n{proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def commit_meta(repo: Path, sha: str) -> dict[str, str]:
    out = git_cmd(repo, "show", "-s", "--format=%H\t%cI\t%s", sha)
    full, authored_at, subject = out.split("\t", 2)
    return {"sha": full, "authoredAt": authored_at, "subject": subject}


def is_ancestor(repo: Path, a: str, b: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", a, b],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# ── Loaders ────────────────────────────────────────────────────────────────────

def load_securevibes_case(case_dir: Path) -> dict[str, Any]:
    """Load advisory.json, timeline.json, verification.json from a securevibes case dir."""
    advisory = json.loads((case_dir / "advisory.json").read_text(encoding="utf-8"))
    timeline = json.loads((case_dir / "timeline.json").read_text(encoding="utf-8"))
    verification = json.loads(
        (case_dir / "verification.json").read_text(encoding="utf-8")
    )
    return {
        "advisory": advisory,
        "timeline": timeline,
        "verification": verification,
    }


def load_agent_scenarios(manifest_path: Path) -> list[dict[str, Any]]:
    """Load scenarios from the securevibes-agent ground truth manifest."""
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return data.get("scenarios", [])


# ── Case builders ──────────────────────────────────────────────────────────────

def _derive_vuln_class(ghsa_id: str, cwe_ids: list[str]) -> str:
    """Derive vulnerability class from CWE IDs with override table."""
    if ghsa_id in VULN_CLASS_OVERRIDES:
        return VULN_CLASS_OVERRIDES[ghsa_id]
    for cwe in cwe_ids:
        if cwe in CWE_TO_CLASS:
            return CWE_TO_CLASS[cwe]
    return "abuse"  # fallback


def _build_advisory_block(advisory_data: dict[str, Any]) -> dict[str, Any]:
    """Build the advisory block from raw advisory API data."""
    published_at = advisory_data.get("published_at")
    if not isinstance(published_at, str) or not published_at:
        ghsa_id = advisory_data.get("ghsa_id", "<unknown>")
        raise ValueError(
            f"Missing advisory published_at for {ghsa_id}. "
            "Provide advisory metadata via --advisories-file."
        )

    block: dict[str, Any] = {
        "title": advisory_data.get("summary", ""),
        "severity": advisory_data.get("severity", "high"),
        "publishedAt": published_at,
        "description": advisory_data.get("description", ""),
        "cweIds": advisory_data.get("cwe_ids", []),
    }

    cvss_data = (
        (advisory_data.get("cvss_severities") or {}).get("cvss_v3")
        or advisory_data.get("cvss_v3")
        or {}
    )
    if cvss_data.get("score") is not None:
        block["cvss"] = {
            "version": "3.1",
            "vectorString": cvss_data.get("vector_string", ""),
            "score": cvss_data["score"],
        }

    vulns = advisory_data.get("vulnerabilities") or advisory_data.get(
        "affected_packages", []
    )
    if vulns:
        packages = []
        for v in vulns:
            pkg = v.get("package", {})
            packages.append(
                {
                    "ecosystem": pkg.get("ecosystem", "npm"),
                    "name": pkg.get("name", "openclaw"),
                    "vulnerableRange": v.get("vulnerable_version_range", ""),
                    "patchedVersions": v.get("patched_versions", ""),
                }
            )
        block["affectedPackages"] = packages

    return block


def _build_timeline_from_securevibes(
    timeline_data: dict[str, Any],
) -> dict[str, Any]:
    """Build timeline block from securevibes timeline.json data."""
    intro_commits = [
        {
            "sha": c["sha"],
            "authoredAt": c["authored_at"],
            "subject": c["subject"],
        }
        for c in timeline_data["introducing_commits"]
    ]

    result: dict[str, Any] = {
        "baselineCommit": timeline_data["baseline_commit"],
        "introducingCommits": intro_commits,
        "vulnerableHead": timeline_data["vulnerable_head"],
    }
    if timeline_data.get("notes"):
        result["notes"] = timeline_data["notes"]
    return result


def _build_timeline_from_research(
    mapping: dict[str, Any], repo: Path
) -> dict[str, Any]:
    """Build timeline block from researched case mapping + openclaw repo."""
    intro_shas = mapping["introducing_commits"]

    intro_metas = sorted(
        [commit_meta(repo, sha) for sha in intro_shas],
        key=lambda x: x["authoredAt"],
    )

    earliest_intro = intro_metas[0]["sha"]
    baseline = git_cmd(repo, "rev-parse", f"{earliest_intro}^")
    vulnerable_head = intro_metas[-1]["sha"]

    result: dict[str, Any] = {
        "baselineCommit": baseline,
        "introducingCommits": intro_metas,
        "vulnerableHead": vulnerable_head,
    }
    if mapping.get("notes"):
        result["notes"] = mapping["notes"]
    return result


def _build_verification(
    timeline: dict[str, Any],
    confidence: str,
    checks: list[dict[str, Any]] | None = None,
    repo: Path | None = None,
) -> dict[str, Any]:
    """Build verification block, optionally running live ancestry checks."""
    if checks is not None:
        # Use existing checks from securevibes
        normalized_checks = [
            {"name": c["name"], "pass": c["pass"], "details": c["details"]}
            for c in checks
        ]
        all_pass = bool(normalized_checks) and all(
            c.get("pass", False) for c in normalized_checks
        )
        return {
            "status": "pass" if all_pass else "unverified",
            "confidence": confidence,
            "checks": normalized_checks,
        }

    if repo is None:
        return {
            "status": "unverified",
            "confidence": confidence,
            "checks": [],
        }

    # Run live ancestry checks
    baseline = timeline["baselineCommit"]
    vulnerable_head = timeline["vulnerableHead"]
    live_checks = []

    for ic in timeline["introducingCommits"]:
        intro_sha = ic["sha"]
        ok = is_ancestor(repo, baseline, intro_sha)
        live_checks.append(
            {
                "name": "baseline_ancestor_of_intro",
                "pass": ok,
                "details": f"baseline={baseline[:12]} intro={intro_sha[:12]}",
            }
        )

        ok = is_ancestor(repo, intro_sha, vulnerable_head)
        live_checks.append(
            {
                "name": "intro_ancestor_of_vulnerable_head",
                "pass": ok,
                "details": (
                    f"intro={intro_sha[:12]} "
                    f"vulnerable_head={vulnerable_head[:12]}"
                ),
            }
        )

    live_checks.append(
        {
            "name": "baseline_ancestor_of_vulnerable_head",
            "pass": is_ancestor(repo, baseline, vulnerable_head),
            "details": (
                f"baseline={baseline[:12]} "
                f"vulnerable_head={vulnerable_head[:12]}"
            ),
        }
    )

    all_pass = all(c["pass"] for c in live_checks)
    return {
        "status": "pass" if all_pass else "unverified",
        "confidence": confidence,
        "checks": live_checks,
    }


def build_unified_case(
    ghsa_id: str,
    advisory_data: dict[str, Any],
    timeline_data: dict[str, Any] | None = None,
    verification_data: dict[str, Any] | None = None,
    agent_scenario: dict[str, Any] | None = None,
    vuln_class_override: str | None = None,
    expected_paths_override: list[str] | None = None,
    timeline_block: dict[str, Any] | None = None,
    verification_block: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a unified case.json payload."""
    # Advisory block
    advisory_block = _build_advisory_block(advisory_data)

    # Timeline block
    if timeline_block is not None:
        tl = timeline_block
    elif timeline_data is not None:
        tl = _build_timeline_from_securevibes(timeline_data)
    else:
        raise ValueError(f"No timeline data for {ghsa_id}")

    # Verification block
    if verification_block is not None:
        vf = verification_block
    elif verification_data is not None:
        checks = verification_data.get("checks", [])
        confidence = verification_data.get("confidence", "high")
        vf = _build_verification(tl, confidence, checks=checks)
    else:
        vf = {"status": "unverified", "confidence": "low", "checks": []}

    case_override = CASE_RESEARCH_OVERRIDES.get(ghsa_id)
    if case_override:
        if case_override.get("timeline_notes"):
            tl = {**tl, "notes": case_override["timeline_notes"]}
        vf = dict(vf)
        if case_override.get("verification_confidence"):
            vf["confidence"] = case_override["verification_confidence"]
        override_checks = case_override.get("verification_checks", [])
        if override_checks:
            merged_checks = list(vf.get("checks", []))
            seen_names = {check.get("name") for check in merged_checks}
            for check in override_checks:
                if check["name"] not in seen_names:
                    merged_checks.append(check)
            vf["checks"] = merged_checks
            vf["status"] = "pass" if all(c.get("pass", False) for c in merged_checks) else "unverified"

    # Expected outcome
    cwe_ids = advisory_data.get("cwe_ids", [])

    if agent_scenario:
        vuln_class = agent_scenario["expectedVulnerabilityClass"]
        expected_paths = agent_scenario["expectedPathContains"]
        min_severity = agent_scenario.get("minimumSeverity", "high")
    elif vuln_class_override:
        vuln_class = vuln_class_override
        expected_paths = expected_paths_override or []
        min_severity = "high"
    else:
        vuln_class = _derive_vuln_class(ghsa_id, cwe_ids)
        expected_paths = expected_paths_override or []
        min_severity = "high"

    expected_outcome = {
        "vulnerabilityClass": vuln_class,
        "minimumSeverity": min_severity,
        "expectedPaths": expected_paths,
        "description": f"Scanner should detect {vuln_class} when scanning vulnerableHead.",
    }

    # Provenance
    sources = []
    if timeline_data is not None:
        sources.append("securevibes")
    if agent_scenario is not None:
        sources.append("securevibes-agent")
    if not sources:
        sources.append("securevibes-agent")

    merge_notes = None
    if len(sources) > 1:
        merge_notes = "Timeline from securevibes; vuln class/paths from securevibes-agent."

    provenance: dict[str, Any] = {"sources": sources}
    if merge_notes:
        provenance["mergeNotes"] = merge_notes

    return {
        "schemaVersion": "1.0.0",
        "id": ghsa_id,
        "advisoryUrl": advisory_data.get(
            "html_url",
            advisory_data.get(
                "url",
                f"https://github.com/openclaw/openclaw/security/advisories/{ghsa_id}",
            ),
        ),
        "repository": "openclaw/openclaw",
        "advisory": advisory_block,
        "timeline": tl,
        "expectedOutcome": expected_outcome,
        "verification": vf,
        "provenance": provenance,
    }


def build_manifest(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Build manifest.json from a list of case payloads."""
    return {
        "name": "openclaw-advisory-benchmark",
        "schemaVersion": "1.0.0",
        "generatedAt": datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "repository": "openclaw/openclaw",
        "caseCount": len(cases),
        "cases": [
            {
                "id": c["id"],
                "severity": c["advisory"]["severity"],
                "title": c["advisory"]["title"],
                "vulnerabilityClass": c["expectedOutcome"]["vulnerabilityClass"],
                "baselineCommit": c["timeline"]["baselineCommit"],
                "vulnerableHead": c["timeline"]["vulnerableHead"],
                "verificationStatus": c["verification"]["status"],
                "confidence": c["verification"]["confidence"],
            }
            for c in cases
        ],
    }


# ── Expected paths derivation for securevibes-only cases ───────────────────────

def derive_expected_paths(
    repo: Path, reference_commits: list[dict[str, Any]]
) -> list[str]:
    """Derive expected paths from the files changed in the given commits.

    At migration time this is called with the fix commits from the securevibes
    source data — the fix diff is the best signal for which files are
    security-relevant, even though fix metadata is not included in the output.
    """
    paths: list[str] = []
    for fc in reference_commits:
        sha = fc["sha"] if isinstance(fc, dict) else fc
        out = git_cmd(repo, "diff-tree", "--no-commit-id", "-r", "--name-only", sha)
        for p in out.split("\n"):
            if (
                p
                and not p.startswith("CHANGELOG")
                and not p.endswith(".test.ts")
                and not p.endswith(".test.tsx")
                and not p.startswith("docs/")
                and (
                    p.startswith("src/")
                    or p.startswith("extensions/")
                    or p.startswith("ui/src/")
                )
            ):
                if p not in paths:
                    paths.append(p)
    return paths


# ── Main ───────────────────────────────────────────────────────────────────────

def run_migration(args: argparse.Namespace) -> None:
    sv_dir = Path(args.securevibes_dir).resolve()
    agent_manifest = Path(args.agent_manifest).resolve()
    output_dir = Path(args.output_dir).resolve()
    repo = Path(args.openclaw_repo).resolve() if args.openclaw_repo else None

    # Load advisory data from GitHub API cache
    advisories_file = Path(args.advisories_file).resolve() if args.advisories_file else None
    if advisories_file and advisories_file.exists():
        all_advisories = json.loads(advisories_file.read_text(encoding="utf-8"))
        advisory_by_id = {a["ghsa_id"]: a for a in all_advisories}
    else:
        advisory_by_id = {}

    # Load securevibes cases
    sv_cases_dir = sv_dir / "docs" / "benchmarks" / "openclaw-ghsa-batch1" / "cases"

    # Load agent scenarios
    agent_scenarios = load_agent_scenarios(agent_manifest)
    agent_by_id = {s["id"]: s for s in agent_scenarios}

    if repo is None:
        raise ValueError(
            "--openclaw-repo is required to build the full benchmark because "
            "agent-only cases need exact commit timeline resolution."
        )

    # Build all 24 cases
    all_cases: list[dict[str, Any]] = []
    all_ids = sorted(set(SECUREVIBES_CASE_IDS) | set(AGENT_CASE_IDS))

    for ghsa_id in all_ids:
        is_sv = ghsa_id in SECUREVIBES_CASE_IDS
        is_agent = ghsa_id in AGENT_CASE_IDS
        agent_scenario = agent_by_id.get(ghsa_id)

        if is_sv:
            # Load from securevibes
            sv_case = load_securevibes_case(sv_cases_dir / ghsa_id)
            advisory_data = sv_case["advisory"]
            # Supplement with API data if available
            if ghsa_id in advisory_by_id:
                api_adv = advisory_by_id[ghsa_id]
                advisory_data.setdefault("cwe_ids", api_adv.get("cwe_ids", []))

            timeline_data = sv_case["timeline"]
            verification_data = sv_case["verification"]

            # For securevibes-only cases, derive vuln class and paths
            vuln_class_override = None
            expected_paths_override = None
            if not is_agent:
                vuln_class_override = _derive_vuln_class(
                    ghsa_id, advisory_data.get("cwe_ids", [])
                )
                if repo:
                    expected_paths_override = derive_expected_paths(
                        repo,
                        timeline_data["fix_commits"],
                    )

            case = build_unified_case(
                ghsa_id=ghsa_id,
                advisory_data=advisory_data,
                timeline_data=timeline_data,
                verification_data=verification_data,
                agent_scenario=agent_scenario if is_agent else None,
                vuln_class_override=vuln_class_override,
                expected_paths_override=expected_paths_override,
            )
        else:
            # Agent-only case
            mapping = AGENT_ONLY_CASE_MAPPING[ghsa_id]
            advisory_data = advisory_by_id.get(ghsa_id, {})
            if not advisory_data:
                advisory_data = {
                    "ghsa_id": ghsa_id,
                    "severity": "high",
                    "summary": agent_scenario["title"] if agent_scenario else "",
                    "description": "",
                    "html_url": agent_scenario["advisoryUrl"]
                    if agent_scenario
                    else "",
                    "cwe_ids": [],
                    "published_at": "",
                }

            timeline_block = _build_timeline_from_research(mapping, repo)
            verification_block = _build_verification(
                timeline_block,
                mapping.get("confidence", "high"),
                repo=repo,
            )

            case = build_unified_case(
                ghsa_id=ghsa_id,
                advisory_data=advisory_data,
                agent_scenario=agent_scenario,
                timeline_block=timeline_block,
                verification_block=verification_block,
            )

        all_cases.append(case)

    # Sort by GHSA ID for deterministic output
    all_cases.sort(key=lambda c: c["id"])

    # Write case files
    cases_dir = output_dir / "cases"
    for case in all_cases:
        case_dir = cases_dir / case["id"]
        write_json(case_dir / "case.json", case)

    # Write manifest
    manifest = build_manifest(all_cases)
    write_json(output_dir / "manifest.json", manifest)

    print(f"Generated {len(all_cases)} cases + manifest.json in {output_dir}")
    for case in all_cases:
        status = case["verification"]["status"]
        print(f"  {case['id']}: {case['advisory']['severity']:8s} {status}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--securevibes-dir",
        type=str,
        required=True,
        help="Path to securevibes repo root",
    )
    parser.add_argument(
        "--agent-manifest",
        type=str,
        required=True,
        help="Path to securevibes-agent ground truth JSON",
    )
    parser.add_argument(
        "--openclaw-repo",
        type=str,
        default=None,
        help=(
            "Path to local OpenClaw git checkout. Required to resolve exact "
            "commit timelines for full benchmark generation."
        ),
    )
    parser.add_argument(
        "--advisories-file",
        type=str,
        default=None,
        help="Path to cached GitHub API advisories JSON. Required for complete agent-only advisory metadata.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        required=True,
        help="Output directory for benchmark artifacts",
    )
    args = parser.parse_args()
    try:
        run_migration(args)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
