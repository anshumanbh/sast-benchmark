"""State-file management for sast-watch.

Each target repo has one state file at
`.claude/skills/sast-watch/state/<owner>__<repo>.json` with shape:

    {
      "repository": "openclaw/openclaw",
      "ghsa_ids": ["GHSA-...", ...],
      "last_seen": "2026-05-15T00:00:00Z" | null
    }
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_state(state_path: Path, repository: str | None = None) -> dict[str, Any]:
    if not state_path.exists():
        if repository is None:
            raise FileNotFoundError(
                f"State file {state_path} not found and no repository given to seed"
            )
        return {"repository": repository, "ghsa_ids": [], "last_seen": None}
    return json.loads(state_path.read_text())


def save_state(state_path: Path, state: dict[str, Any]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2) + "\n")


def seed_state_from_manifest(
    manifest_path: Path,
    cases_dir: Path,
    repository: str,
    state_path: Path,
) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text())
    ghsa_ids: list[str] = []
    for case_entry in manifest.get("cases", []):
        cid = case_entry.get("id")
        if not cid:
            continue
        case_file = cases_dir / cid / "case.json"
        if not case_file.exists():
            continue
        case_data = json.loads(case_file.read_text())
        if case_data.get("repository") == repository:
            ghsa_ids.append(cid)
    out = {
        "repository": repository,
        "ghsa_ids": sorted(set(ghsa_ids)),
        "last_seen": None,
    }
    save_state(state_path, out)
    return out


def add_ghsa_to_state(state_path: Path, ghsa_id: str) -> None:
    s = load_state(state_path)
    ids = set(s.get("ghsa_ids", []))
    ids.add(ghsa_id)
    s["ghsa_ids"] = sorted(ids)
    save_state(state_path, s)


def main() -> int:
    import argparse

    p = argparse.ArgumentParser(description="Manage sast-watch state files")
    sub = p.add_subparsers(dest="cmd", required=True)

    seed = sub.add_parser("seed", help="Seed a state file from the current manifest")
    seed.add_argument("--manifest", required=True)
    seed.add_argument("--cases-dir", required=True)
    seed.add_argument("--repository", required=True)
    seed.add_argument("--state-file", required=True)

    show = sub.add_parser("show", help="Print state file contents")
    show.add_argument("--state-file", required=True)

    add = sub.add_parser("add", help="Add a GHSA ID to the state file")
    add.add_argument("--state-file", required=True)
    add.add_argument("--ghsa-id", required=True)

    args = p.parse_args()

    if args.cmd == "seed":
        out = seed_state_from_manifest(
            manifest_path=Path(args.manifest),
            cases_dir=Path(args.cases_dir),
            repository=args.repository,
            state_path=Path(args.state_file),
        )
        print(json.dumps(out, indent=2))
        return 0
    if args.cmd == "show":
        print(json.dumps(load_state(Path(args.state_file)), indent=2))
        return 0
    if args.cmd == "add":
        add_ghsa_to_state(Path(args.state_file), args.ghsa_id)
        print(json.dumps(load_state(Path(args.state_file)), indent=2))
        return 0
    return 2


if __name__ == "__main__":
    import sys

    sys.exit(main())
