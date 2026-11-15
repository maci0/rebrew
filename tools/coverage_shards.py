"""coverage_shards.py: the coverage gate, as parallel serial slipcover shards.

``make coverage`` runs this.  One slipcover process over the whole suite took
8 minutes in CI.  slipcover's pytest-xdist mode is faster but reported 85.2%
against 89.5% serially: workers miss lines.  Each shard here is a plain serial
slipcover run over a subset of the test files, so its counts are exact, and
``slipcover --merge`` unions the shards and applies the floor.

Files are assigned largest first to the least loaded shard by byte size, a
proxy for run time: four shards of this suite ran 99-159 s each.

Usage: coverage_shards.py --fail-under PERCENT [--shards N] [--out-dir DIR]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def _project_root() -> Path:
    for directory in Path(__file__).resolve().parents:
        if (directory / "pyproject.toml").is_file():
            return directory
    raise SystemExit("coverage_shards.py: no pyproject.toml above this file")


def partition(files: list[Path], count: int) -> list[list[Path]]:
    """*files* in at most *count* non-empty shards, balanced by byte size."""
    shards: list[list[Path]] = [[] for _ in range(min(count, len(files)))]
    loads = [0] * len(shards)
    for path in sorted(files, key=lambda p: (-p.stat().st_size, p.name)):
        lightest = loads.index(min(loads))
        shards[lightest].append(path)
        loads[lightest] += path.stat().st_size
    return [sorted(shard) for shard in shards]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fail-under", type=float, required=True, help="line coverage floor")
    parser.add_argument("--shards", type=int, default=os.cpu_count() or 1, help="parallel shards")
    parser.add_argument("--out-dir", type=Path, default=Path("build/coverage"))
    args = parser.parse_args()
    if args.shards < 1:
        parser.error("--shards must be at least 1")
    root = _project_root()
    out_dir = args.out_dir if args.out_dir.is_absolute() else root / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("shard-*"):
        stale.unlink()
    shards = partition(sorted((root / "tests").glob("test_*.py")), args.shards)
    # A separate interpreter per shard: slipcover instruments the process it
    # starts, so in-process parallelism would not be measured.
    runs = []
    for index, files in enumerate(shards):
        log = (out_dir / f"shard-{index}.log").open("wb")
        command = [
            sys.executable, "-m", "slipcover", "--json",
            "--out", str(out_dir / f"shard-{index}.json"),
            "-m", "pytest", *map(str, files), "-q", "--tb=short", "-p", "no:xdist",
        ]  # fmt: skip
        runs.append((index, log, subprocess.Popen(command, cwd=root, stdout=log, stderr=log)))
    failed = []
    for index, log, process in runs:
        if process.wait() != 0:
            failed.append(index)
        log.close()
        sys.stdout.write(f"--- shard {index} ({len(shards[index])} files) ---\n")
        sys.stdout.write((out_dir / f"shard-{index}.log").read_text(errors="replace"))
    if failed:
        print(f"coverage_shards.py: shards {failed} failed", file=sys.stderr)
        return 1
    merge = [
        sys.executable, "-m", "slipcover", "--merge",
        *(str(out_dir / f"shard-{index}.json") for index in range(len(shards))),
        "--out", str(out_dir / "coverage.txt"), "--fail-under", str(args.fail_under),
    ]  # fmt: skip
    return subprocess.run(merge, cwd=root, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
