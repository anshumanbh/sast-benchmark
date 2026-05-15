"""Filter GitHub Security Advisories down to those new + high/critical + recent.

Input: list of advisory JSON objects (output of `gh api repos/$REPO/security-advisories
--paginate`). On stdin or via --input.

Output: same list, filtered to advisories where:
  * severity in {high, critical}
  * published_at >= cutoff_iso
  * ghsa_id is NOT in the state file's ghsa_ids

Use `--cutoff-iso "$(python3 -c 'from datetime import datetime,timedelta,timezone;
print((datetime.now(timezone.utc)-timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"`
for the 24-hour window in the skill.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path


def _parse_iso(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def filter_new_advisories(
    advisories: list[dict],
    known_ghsa_ids: set[str],
    cutoff_iso: str,
) -> list[dict]:
    cutoff = _parse_iso(cutoff_iso)
    out: list[dict] = []
    for adv in advisories:
        sev = (adv.get("severity") or "").lower()
        if sev not in {"high", "critical"}:
            continue
        ghsa = adv.get("ghsa_id")
        if not ghsa or ghsa in known_ghsa_ids:
            continue
        pub = adv.get("published_at")
        if not pub:
            continue
        if _parse_iso(pub) < cutoff:
            continue
        out.append(adv)
    return out


def main() -> int:
    import argparse

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state-file", required=True)
    p.add_argument(
        "--cutoff-iso",
        required=True,
        help="ISO datetime; advisories published before this are dropped",
    )
    p.add_argument(
        "--input",
        default="-",
        help="Path to advisories JSON list, or - for stdin",
    )
    args = p.parse_args()

    state_path = Path(args.state_file)
    if state_path.exists():
        state_data = json.loads(state_path.read_text())
        known = set(state_data.get("ghsa_ids", []))
    else:
        known = set()

    if args.input == "-":
        advisories = json.load(sys.stdin)
    else:
        advisories = json.loads(Path(args.input).read_text())

    if not isinstance(advisories, list):
        advisories = [advisories]

    out = filter_new_advisories(
        advisories, known_ghsa_ids=known, cutoff_iso=args.cutoff_iso
    )
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
