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


def _case_id(case: Any, fallback: str = "unknown") -> str:
    """Return a stable case ID for error reporting."""
    if isinstance(case, dict):
        case_id = case.get("id")
        if isinstance(case_id, str) and case_id:
            return case_id
    return fallback


def _json_object(value: Any) -> dict[str, Any] | None:
    """Return a JSON object value if present."""
    if isinstance(value, dict):
        return value
    return None


def _json_array(value: Any) -> list[Any] | None:
    """Return a JSON array value if present."""
    if isinstance(value, list):
        return value
    return None


def _non_empty_string(value: Any) -> str | None:
    """Return a non-empty string if present."""
    if isinstance(value, str) and value:
        return value
    return None


def _get_jsonschema_validator() -> Any:
    """Return the Draft 7 validator class or raise if the dependency is missing."""
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError(
            "jsonschema is required for schema validation. "
            "Install with: pip install jsonschema"
        ) from exc
    return jsonschema.Draft7Validator


def load_schema(path: Path | None = None) -> dict:
    """Load the JSON Schema for case.json."""
    schema_path = path or SCHEMA_PATH
    return json.loads(schema_path.read_text(encoding="utf-8"))


def validate_case_against_schema(case: Any, schema: dict) -> list[ValidationError]:
    """Validate a case dict against the JSON Schema."""
    case_id = _case_id(case)
    try:
        validator_cls = _get_jsonschema_validator()
    except RuntimeError as exc:
        return [ValidationError(case_id, "schema_dependency", str(exc))]

    validator = validator_cls(schema)
    errors = []
    for error in validator.iter_errors(case):
        errors.append(
            ValidationError(case_id, "schema", f"{error.json_path}: {error.message}")
        )
    return errors


def validate_manifest_consistency(
    manifest: Any, case_dirs: list[str]
) -> list[ValidationError]:
    """Check manifest matches case directories."""
    manifest_obj = _json_object(manifest)
    if manifest_obj is None:
        return [
            ValidationError(
                "manifest", "manifest", "manifest.json must contain a JSON object"
            )
        ]

    errors: list[ValidationError] = []
    manifest_cases = _json_array(manifest_obj.get("cases"))
    if manifest_cases is None:
        return [
            ValidationError("manifest", "manifest", "manifest.cases must be a list")
        ]

    manifest_ids: set[str] = set()
    for index, case in enumerate(manifest_cases):
        case_obj = _json_object(case)
        if case_obj is None:
            errors.append(
                ValidationError(
                    "manifest", "manifest", f"cases[{index}] must be an object"
                )
            )
            continue

        case_id = _non_empty_string(case_obj.get("id"))
        if case_id is None:
            errors.append(
                ValidationError(
                    "manifest",
                    "manifest",
                    f"cases[{index}].id must be a non-empty string",
                )
            )
            continue
        manifest_ids.add(case_id)

    dir_ids = set(case_dirs)

    for mid in manifest_ids - dir_ids:
        errors.append(
            ValidationError(mid, "manifest", f"Listed in manifest but no case directory found")
        )
    for did in dir_ids - manifest_ids:
        errors.append(
            ValidationError(did, "manifest", f"Case directory exists but not in manifest")
        )

    declared_count = manifest_obj.get("caseCount", len(manifest_cases))
    actual_count = len(manifest_cases)
    if not isinstance(declared_count, int):
        errors.append(
            ValidationError(
                "manifest", "caseCount", "Declared caseCount must be an integer"
            )
        )
    elif declared_count != actual_count:
        errors.append(
            ValidationError(
                "manifest",
                "caseCount",
                f"Declared caseCount={declared_count} but {actual_count} cases listed",
            )
        )

    return errors


def validate_no_duplicate_ids(cases: list[Any]) -> list[ValidationError]:
    """Check for duplicate GHSA IDs."""
    seen: dict[str, int] = {}
    errors = []
    for case in cases:
        cid = _case_id(case)
        seen[cid] = seen.get(cid, 0) + 1

    for cid, count in seen.items():
        if cid != "unknown" and count > 1:
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


def validate_case_semantic(case: Any, repo: Path) -> list[ValidationError]:
    """Run semantic validation requiring the openclaw repo."""
    if not isinstance(case, dict):
        return [
            ValidationError(
                "unknown", "semantic", "case.json must contain a JSON object"
            )
        ]

    errors: list[ValidationError] = []
    case_id = _case_id(case)
    timeline = _json_object(case.get("timeline"))
    if timeline is None:
        return [ValidationError(case_id, "semantic", "timeline must be an object")]

    baseline = _non_empty_string(timeline.get("baselineCommit"))
    if baseline is None:
        errors.append(
            ValidationError(
                case_id,
                "semantic",
                "timeline.baselineCommit must be a non-empty string",
            )
        )

    vulnerable_head = _non_empty_string(timeline.get("vulnerableHead"))
    if vulnerable_head is None:
        errors.append(
            ValidationError(
                case_id,
                "semantic",
                "timeline.vulnerableHead must be a non-empty string",
            )
        )

    introducing_commits = _json_array(timeline.get("introducingCommits"))
    if introducing_commits is None:
        errors.append(
            ValidationError(
                case_id,
                "semantic",
                "timeline.introducingCommits must be a list",
            )
        )
        introducing_commits = []

    introducing_shas: list[str] = []
    for index, commit in enumerate(introducing_commits):
        commit_obj = _json_object(commit)
        if commit_obj is None:
            errors.append(
                ValidationError(
                    case_id,
                    "semantic",
                    f"timeline.introducingCommits[{index}] must be an object",
                )
            )
            continue

        sha = _non_empty_string(commit_obj.get("sha"))
        if sha is None:
            errors.append(
                ValidationError(
                    case_id,
                    "semantic",
                    f"timeline.introducingCommits[{index}].sha must be a non-empty string",
                )
            )
            continue
        introducing_shas.append(sha)

    # Check all commits exist
    if baseline is not None:
        errors.extend(validate_commit_exists(case_id, repo, baseline, "baselineCommit"))
    if vulnerable_head is not None:
        errors.extend(
            validate_commit_exists(case_id, repo, vulnerable_head, "vulnerableHead")
        )

    for sha in introducing_shas:
        errors.extend(
            validate_commit_exists(case_id, repo, sha, "introducingCommit")
        )

    # Ancestry checks (only if commits exist)
    if not errors:
        assert baseline is not None
        assert vulnerable_head is not None
        errors.extend(
            validate_ancestry(
                case_id,
                repo,
                baseline,
                vulnerable_head,
                "baseline → vulnerableHead",
            )
        )
        for sha in introducing_shas:
            errors.extend(
                validate_ancestry(
                    case_id, repo, baseline, sha, "baseline → intro"
                )
            )
            errors.extend(
                validate_ancestry(
                    case_id,
                    repo,
                    sha,
                    vulnerable_head,
                    "intro → vulnerableHead",
                )
            )

    return errors


def validate_case_strict(case: Any) -> list[ValidationError]:
    """Strict mode: all cases must pass verification with high confidence."""
    if not isinstance(case, dict):
        return [
            ValidationError("unknown", "strict", "case.json must contain a JSON object")
        ]

    errors: list[ValidationError] = []
    case_id = _case_id(case)
    verification = _json_object(case.get("verification"))
    if verification is None:
        return [ValidationError(case_id, "strict", "verification must be an object")]

    if verification.get("status") != "pass":
        errors.append(
            ValidationError(
                case_id,
                "strict",
                f"verification.status is '{verification.get('status')}', expected 'pass'",
            )
        )

    if verification.get("confidence") != "high":
        errors.append(
            ValidationError(
                case_id,
                "strict",
                f"verification.confidence is '{verification.get('confidence')}', expected 'high'",
            )
        )

    checks = _json_array(verification.get("checks"))
    if checks is None:
        errors.append(
            ValidationError(case_id, "strict", "verification.checks must be a list")
        )
        return errors

    for index, check in enumerate(checks):
        check_obj = _json_object(check)
        if check_obj is None:
            errors.append(
                ValidationError(
                    case_id,
                    "strict",
                    f"verification.checks[{index}] must be an object",
                )
            )
            continue

        if not check_obj.get("pass"):
            errors.append(
                ValidationError(
                    case_id,
                    "strict",
                    f"verification check '{check_obj.get('name')}' failed: {check_obj.get('details')}",
                )
            )

    return errors


def run_validation(args: argparse.Namespace) -> list[ValidationError]:
    """Run all validation checks and return errors."""
    all_errors: list[ValidationError] = []
    cases_dir = Path(args.output_dir) / "cases" if args.output_dir else CASES_DIR
    manifest_path = Path(args.output_dir) / "manifest.json" if args.output_dir else MANIFEST_PATH

    # Load manifest
    if not manifest_path.exists():
        all_errors.append(
            ValidationError("manifest", "exists", f"manifest.json not found at {manifest_path}")
        )
        return all_errors

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        all_errors.append(
            ValidationError(
                "manifest",
                "json",
                f"manifest.json is not valid JSON: {exc.msg}",
            )
        )
        return all_errors

    # Find case directories
    if not cases_dir.exists():
        all_errors.append(
            ValidationError("cases", "exists", f"cases/ directory not found at {cases_dir}")
        )
        return all_errors

    schema = load_schema()
    schema_validation_enabled = True
    try:
        _get_jsonschema_validator()
    except RuntimeError as exc:
        schema_validation_enabled = False
        if args.openclaw_repo or args.strict:
            print(
                f"WARNING: {exc}. Skipping schema validation.",
                file=sys.stderr,
            )
        else:
            all_errors.append(ValidationError("schema", "dependency", str(exc)))

    case_dir_names = [
        d.name for d in sorted(cases_dir.iterdir()) if d.is_dir() and d.name.startswith("GHSA-")
    ]

    # Manifest consistency
    all_errors.extend(validate_manifest_consistency(manifest, case_dir_names))

    # Load and validate each case
    loaded_cases: list[Any] = []
    for dir_name in case_dir_names:
        case_path = cases_dir / dir_name / "case.json"
        if not case_path.exists():
            all_errors.append(
                ValidationError(dir_name, "case_file", "case.json not found")
            )
            continue

        try:
            case = json.loads(case_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            all_errors.append(
                ValidationError(
                    dir_name,
                    "case_file",
                    f"case.json is not valid JSON: {exc.msg}",
                )
            )
            continue

        loaded_cases.append(case)

        # Schema validation
        if schema_validation_enabled:
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
