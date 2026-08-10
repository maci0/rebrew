"""verify_baseline.py — committed-baseline regression gate for rebrew verify.

``rebrew verify --compare`` detects regressions against the *last saved*
report in the project; this tool pins the gate to a **committed** baseline so
CI (or a human) can fail when the byte-matched count drops below a known-good
number, independent of local history.

Usage (from a rebrew project root)::

    rebrew verify --json -o db/verify_results.json
    python tools/verify_baseline.py --snapshot baselines/smygb.json     # record current
    python tools/verify_baseline.py --check baselines/smygb.json        # gate (exit 1 on drop)

Exit codes: 0 = at/above baseline (or no prior run), 1 = regression,
2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _read_report(project_root: Path) -> dict:
    """Load the latest verify report (db/verify_results.json)."""
    candidates = [
        project_root / "db" / "verify_results.json",
        Path.cwd() / "db" / "verify_results.json",
    ]
    for path in candidates:
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    return {}


def snapshot(report: dict) -> dict:
    """Reduce a verify report to the baseline-relevant numbers."""
    return {
        "byte_matched": int(report.get("byte_matched", 0)),
        "exact": int(report.get("exact", 0)),
        "reloc": int(report.get("reloc", 0)),
        "total": int(report.get("total", 0)),
        "target": str(report.get("target", "")),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--snapshot", type=Path, help="Write the baseline from the current report")
    parser.add_argument("--check", type=Path, help="Gate: fail when byte_matched dropped")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Project root")
    args = parser.parse_args(argv)

    if args.snapshot and args.check:
        print("--snapshot and --check are mutually exclusive")
        return 2
    if not args.snapshot and not args.check:
        print("pass --snapshot PATH or --check PATH")
        return 2

    report = _read_report(args.root)
    if not report:
        print("no verify report found (run 'rebrew verify --json -o db/verify_results.json' first)")
        return 2

    if args.snapshot:
        baseline = snapshot(report)
        args.snapshot.parent.mkdir(parents=True, exist_ok=True)
        args.snapshot.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
        print(f"baseline written: {baseline}")
        return 0

    baseline_path = args.check
    if not baseline_path.is_file():
        print(f"baseline {baseline_path} not found — run --snapshot first")
        return 2
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    current = snapshot(report)

    base_matched = int(baseline.get("byte_matched", 0))
    cur_matched = current["byte_matched"]
    delta = cur_matched - base_matched
    print(
        f"byte_matched: {cur_matched} vs baseline {base_matched} "
        f"({'+' if delta >= 0 else ''}{delta})"
    )
    if cur_matched < base_matched:
        print(f"REGRESSION: matched bytes dropped by {-delta}")
        return 1
    print("at or above baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
