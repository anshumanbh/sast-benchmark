"""Build a case.json dict from a GitHub advisory + verified timeline.

The skill is responsible for deriving the timeline (baselineCommit,
introducingCommits[0], vulnerableHead) and the expected_paths from the upstream
repo. This helper only does the deterministic data-shaping:
  * apply the CWE bridge for `abuse`/`brokenauthz` classes
  * map advisory JSON fields onto the schema
  * assemble the final dict

Verification.checks is left empty; the skill fills it after running the three
`git merge-base --is-ancestor` checks.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve()
_REPO_ROOT = _HERE.parents[4]
_SCRIPTS = _REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from taxonomy import CWE_TO_VULN_CLASS  # noqa: E402


_BRIDGE_CWE_FOR_CLASS = {
    "abuse": "CWE-400",
    "brokenauthz": "CWE-863",
}


def apply_cwe_bridge(
    cwe_ids: list[str], vulnerability_class: str
) -> list[str]:
    bridge = _BRIDGE_CWE_FOR_CLASS.get(vulnerability_class)
    if bridge is None:
        return list(cwe_ids)
    for cwe in cwe_ids:
        if vulnerability_class in CWE_TO_VULN_CLASS.get(cwe, []):
            return list(cwe_ids)
    if bridge in cwe_ids:
        return list(cwe_ids)
    return list(cwe_ids) + [bridge]


def _affected_packages_from_advisory(advisory: dict) -> list[dict]:
    out = []
    for v in advisory.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        entry: dict[str, Any] = {
            "ecosystem": pkg.get("ecosystem", ""),
            "name": pkg.get("name", ""),
        }
        rng = v.get("vulnerable_version_range")
        if rng:
            entry["vulnerableRange"] = rng
        patched = v.get("patched_versions")
        if not patched:
            fpv = v.get("first_patched_version") or {}
            patched = fpv.get("identifier")
        if patched:
            entry["patchedVersions"] = patched
        out.append(entry)
    return out


def build_case(
    advisory: dict,
    repository: str,
    timeline: dict,
    vulnerability_class: str,
    expected_paths: list[str],
    confidence: str = "medium",
) -> dict:
    cwe_ids = [
        c.get("cwe_id")
        for c in (advisory.get("cwes") or [])
        if c.get("cwe_id")
    ]
    cwe_ids = apply_cwe_bridge(cwe_ids, vulnerability_class)
    severity = (advisory.get("severity") or "").lower()
    title = advisory.get("summary") or advisory["ghsa_id"]
    description = (
        advisory.get("description")
        or advisory.get("summary")
        or f"Advisory {advisory['ghsa_id']}"
    )
    advisory_url = advisory.get("html_url") or (
        f"https://github.com/{repository}/security/advisories/{advisory['ghsa_id']}"
    )

    return {
        "schemaVersion": "1.0.0",
        "id": advisory["ghsa_id"],
        "advisoryUrl": advisory_url,
        "repository": repository,
        "advisory": {
            "title": title,
            "severity": severity,
            "publishedAt": advisory.get("published_at", ""),
            "description": description,
            "cweIds": cwe_ids,
            "affectedPackages": _affected_packages_from_advisory(advisory),
        },
        "timeline": timeline,
        "expectedOutcome": {
            "vulnerabilityClass": vulnerability_class,
            "minimumSeverity": severity,
            "expectedPaths": expected_paths,
            "description": (
                f"Scanner should flag the {vulnerability_class} pattern "
                f"described in {advisory['ghsa_id']}."
            ),
        },
        "verification": {
            "status": "pass",
            "confidence": confidence,
            "checks": [],
        },
    }


def main() -> int:
    import argparse

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--advisory", required=True)
    p.add_argument("--timeline", required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--vulnerability-class", required=True)
    p.add_argument(
        "--expected-path",
        action="append",
        required=True,
        dest="expected_paths",
    )
    p.add_argument(
        "--confidence", default="medium", choices=["high", "medium", "low"]
    )
    args = p.parse_args()

    advisory = json.loads(Path(args.advisory).read_text())
    timeline = json.loads(Path(args.timeline).read_text())
    case = build_case(
        advisory=advisory,
        repository=args.repository,
        timeline=timeline,
        vulnerability_class=args.vulnerability_class,
        expected_paths=args.expected_paths,
        confidence=args.confidence,
    )
    json.dump(case, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
