#!/usr/bin/env python3
"""Validate openclaw-advisory-benchmark case files.

Structural validation: JSON Schema conformance, manifest consistency, no duplicates.
Semantic validation (with --openclaw-repo): commit SHAs resolve, ancestry checks pass.
Strict mode (--strict): all cases must have verification.status == "pass" with high confidence.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


class ValidationError:
    """A single validation error."""

    def __init__(self, case_id: str, check: str, message: str) -> None:
        self.case_id = case_id
        self.check = check
        self.message = message

    def __str__(self) -> str:
        return f"[{self.case_id}] {self.check}: {self.message}"

    def __repr__(self) -> str:
        return f"ValidationError({self.case_id!r}, {self.check!r}, {self.message!r})"


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "case.schema.json"
CASES_DIR = ROOT / "cases"
MANIFEST_PATH = ROOT / "manifest.json"


def load_schema(path: Path | None = None) -> dict:
    """Load the JSON Schema for case.json."""
    schema_path = path or SCHEMA_PATH
    return json.loads(schema_path.read_text(encoding="utf-8"))


def validate_case_against_schema(case: dict, schema: dict) -> list[ValidationError]:
    """Validate a case dict against the JSON Schema."""
    try:
        import jsonschema
    except ImportError:
        print(
            "WARNING: jsonschema not installed, skipping schema validation. "
            "Install with: pip install jsonschema",
            file=sys.stderr,
        )
        return []

    validator = jsonschema.Draft7Validator(schema)
    errors = []
    for error in validator.iter_errors(case):
        case_id = case.get("id", "unknown")
        errors.append(
            ValidationError(case_id, "schema", f"{error.json_path}: {error.message}")
        )
    return errors


def validate_manifest_consistency(
    manifest: dict, case_dirs: list[str]
) -> list[ValidationError]:
    """Check manifest matches case directories."""
    errors = []
    manifest_ids = {c["id"] for c in manifest.get("cases", [])}
    dir_ids = set(case_dirs)

    for mid in manifest_ids - dir_ids:
        errors.append(
            ValidationError(mid, "manifest", f"Listed in manifest but no case directory found")
        )
    for did in dir_ids - manifest_ids:
        errors.append(
            ValidationError(did, "manifest", f"Case directory exists but not in manifest")
        )

    declared_count = manifest.get("caseCount", len(manifest.get("cases", [])))
    actual_count = len(manifest.get("cases", []))
    if declared_count != actual_count:
        errors.append(
            ValidationError(
                "manifest",
                "caseCount",
                f"Declared caseCount={declared_count} but {actual_count} cases listed",
            )
        )

    return errors


def validate_no_duplicate_ids(cases: list[dict]) -> list[ValidationError]:
    """Check for duplicate GHSA IDs."""
    seen: dict[str, int] = {}
    errors = []
    for case in cases:
        cid = case.get("id", "unknown")
        seen[cid] = seen.get(cid, 0) + 1

    for cid, count in seen.items():
        if count > 1:
            errors.append(
                ValidationError(cid, "duplicate", f"Appears {count} times")
            )
    return errors


def _git_cmd(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def validate_commit_exists(
    case_id: str, repo: Path, sha: str, label: str
) -> list[ValidationError]:
    """Check that a commit SHA exists in the repo."""
    result = _git_cmd(repo, "cat-file", "-e", f"{sha}^{{commit}}")
    if result.returncode != 0:
        return [
            ValidationError(case_id, "commit_exists", f"{label} {sha[:12]} not found in repo")
        ]
    return []


def validate_ancestry(
    case_id: str, repo: Path, ancestor: str, descendant: str, label: str
) -> list[ValidationError]:
    """Check that ancestor is an ancestor of descendant."""
    result = _git_cmd(repo, "merge-base", "--is-ancestor", ancestor, descendant)
    if result.returncode != 0:
        return [
            ValidationError(
                case_id,
                "ancestry",
                f"{label}: {ancestor[:12]} is not ancestor of {descendant[:12]}",
            )
        ]
    return []


def validate_case_semantic(case: dict, repo: Path) -> list[ValidationError]:
    """Run semantic validation requiring the openclaw repo."""
    errors = []
    case_id = case.get("id", "unknown")
    timeline = case.get("timeline", {})

    baseline = timeline.get("baselineCommit", "")
    vulnerable_head = timeline.get("vulnerableHead", "")

    # Check all commits exist
    errors.extend(validate_commit_exists(case_id, repo, baseline, "baselineCommit"))
    errors.extend(validate_commit_exists(case_id, repo, vulnerable_head, "vulnerableHead"))

    for ic in timeline.get("introducingCommits", []):
        errors.extend(
            validate_commit_exists(case_id, repo, ic["sha"], "introducingCommit")
        )

    # Ancestry checks (only if commits exist)
    if not errors:
        for ic in timeline.get("introducingCommits", []):
            errors.extend(
                validate_ancestry(
                    case_id, repo, baseline, ic["sha"], "baseline → intro"
                )
            )

    return errors


def validate_case_strict(case: dict) -> list[ValidationError]:
    """Strict mode: all cases must pass verification with high confidence."""
    errors = []
    case_id = case.get("id", "unknown")
    verification = case.get("verification", {})

    if verification.get("status") != "pass":
        errors.append(
            ValidationError(
                case_id,
                "strict",
                f"verification.status is '{verification.get('status')}', expected 'pass'",
            )
        )

    if verification.get("confidence") not in ("high", "medium"):
        errors.append(
            ValidationError(
                case_id,
                "strict",
                f"verification.confidence is '{verification.get('confidence')}', expected 'high' or 'medium'",
            )
        )

    for check in verification.get("checks", []):
        if not check.get("pass"):
            errors.append(
                ValidationError(
                    case_id,
                    "strict",
                    f"verification check '{check.get('name')}' failed: {check.get('details')}",
                )
            )

    return errors


def run_validation(args: argparse.Namespace) -> list[ValidationError]:
    """Run all validation checks and return errors."""
    all_errors: list[ValidationError] = []
    cases_dir = Path(args.output_dir) / "cases" if args.output_dir else CASES_DIR
    manifest_path = Path(args.output_dir) / "manifest.json" if args.output_dir else MANIFEST_PATH
    schema = load_schema()

    # Load manifest
    if not manifest_path.exists():
        all_errors.append(
            ValidationError("manifest", "exists", f"manifest.json not found at {manifest_path}")
        )
        return all_errors

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Find case directories
    if not cases_dir.exists():
        all_errors.append(
            ValidationError("cases", "exists", f"cases/ directory not found at {cases_dir}")
        )
        return all_errors

    case_dir_names = [
        d.name for d in sorted(cases_dir.iterdir()) if d.is_dir() and d.name.startswith("GHSA-")
    ]

    # Manifest consistency
    all_errors.extend(validate_manifest_consistency(manifest, case_dir_names))

    # Load and validate each case
    loaded_cases: list[dict] = []
    for dir_name in case_dir_names:
        case_path = cases_dir / dir_name / "case.json"
        if not case_path.exists():
            all_errors.append(
                ValidationError(dir_name, "case_file", "case.json not found")
            )
            continue

        case = json.loads(case_path.read_text(encoding="utf-8"))
        loaded_cases.append(case)

        # Schema validation
        all_errors.extend(validate_case_against_schema(case, schema))

        # Semantic validation
        if args.openclaw_repo:
            repo = Path(args.openclaw_repo).resolve()
            all_errors.extend(validate_case_semantic(case, repo))

        # Strict validation
        if args.strict:
            all_errors.extend(validate_case_strict(case))

    # Duplicate check
    all_errors.extend(validate_no_duplicate_ids(loaded_cases))

    return all_errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--openclaw-repo",
        type=str,
        default=None,
        help="Path to local OpenClaw git checkout for semantic validation",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Require all cases to pass verification with high confidence",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Path to the benchmark output directory (default: repo root)",
    )
    args = parser.parse_args()
    errors = run_validation(args)

    if errors:
        print(f"\nValidation FAILED with {len(errors)} error(s):\n", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        sys.exit(1)
    else:
        print("Validation PASSED")


if __name__ == "__main__":
    main()
