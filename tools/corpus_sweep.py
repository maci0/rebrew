"""corpus_sweep.py — run the full read-only toolchain across every corpus project.

Discovers ``*-rebrew`` projects under a corpus root and runs the same
read-only ``--json`` commands a human gap-hunt would, failing loudly on any
non-clean result.  Each failing project is a queue item: fix the toolchain
bug, add a regression test, re-run the sweep until it is green.

Commands per project (all read-only, no wine needed for these):

    rebrew doctor --json               # toolchain/config health (exit 0 = clean)
    rebrew analyze --json              # dossier (must be pure JSON, exit 0)
    rebrew identify-library --dry-run --json
    rebrew status --json

Exit 0 when every project passes every command; 1 otherwise.  A project whose
``rebrew-project.toml`` is missing is skipped (not a failure).

Usage::

    python tools/corpus_sweep.py                          # siblings of this repo
    python tools/corpus_sweep.py --root ../               # explicit corpus root
    python tools/corpus_sweep.py --rebrew /path/to/rebrew # which rebrew to run
    python tools/corpus_sweep.py --project smygb-rebrew   # single project
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_COMMANDS = [
    "doctor --json",
    "analyze --json",
    "identify-library --dry-run --json",
    "status --json",
    "lint --json",
]


def discover_projects(root: Path) -> list[Path]:
    """Return *-rebrew project dirs under *root* (with rebrew-project.toml)."""
    projects: list[Path] = []
    for child in sorted(root.iterdir()):
        if (
            child.is_dir()
            and child.name.endswith("-rebrew")
            and (child / "rebrew-project.toml").is_file()
        ):
            projects.append(child)
    return projects


def is_skipped(project: Path) -> bool:
    """True when the project's AGENTS.md marks it deliberately skipped.

    The corpus sweep must not fail a project that was intaked, documented,
    and explicitly skipped (e.g. an InstallShield installer stub) or blocked
    on toolchain grounds (e.g. a Delphi/Watcom binary no rebrew profile can
    byte-match) — its toolchain was intentionally never linked / its
    alignment mismatch is documented, not a defect.
    """
    agents = project / "AGENTS.md"
    if not agents.is_file():
        return False
    try:
        head = agents.read_text(encoding="utf-8", errors="replace")[:800]
    except OSError:
        return False
    if "SKIPPED" in head and ("not a decomp target" in head or "skipped" in head.lower()):
        return True
    # Documented toolchain blocker: "Status: BLOCKED" + an unmatchable family.
    return "BLOCKED" in head.upper() and any(
        fam in head.lower() for fam in ("delphi", "watcom", "borland")
    )


def check_project(rebrew: str, project: Path) -> list[tuple[str, int, str]]:
    """Run every read-only command in *project*; return (cmd, exit, stdout).

    A command that crashes, exits non-zero, or emits non-JSON stdout is a
    failure.  ``doctor`` with warnings still exits 0 — only real failures
    count (doctor's contract: FAIL → non-zero, WARN → zero).
    """
    results: list[tuple[str, int, str]] = []
    for cmd in _COMMANDS:
        try:
            proc = subprocess.run(
                [rebrew, *cmd.split()],
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            results.append((cmd, 2, f"<cannot run: {exc}>"))
            continue
        ok = proc.returncode == 0
        if ok:
            try:
                json.loads(proc.stdout)
            except json.JSONDecodeError:
                ok = False
                proc.stdout = f"<stdout is not pure JSON>\n{proc.stdout[:200]}"
        results.append((cmd, proc.returncode if ok else 1, proc.stdout))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT.parent,
        help="Corpus root (default: siblings of this repo)",
    )
    parser.add_argument(
        "--rebrew", default="rebrew", help="Which rebrew binary to run (default: PATH 'rebrew')"
    )
    parser.add_argument("--project", default=None, help="Only sweep this one project directory")
    parser.add_argument(
        "--json", action="store_true", dest="json_out", help="Emit a machine-readable report"
    )
    args = parser.parse_args(argv)

    projects = discover_projects(args.root)
    if args.project:
        p = args.root / args.project if not Path(args.project).is_absolute() else Path(args.project)
        projects = [p] if p.is_dir() and (p / "rebrew-project.toml").is_file() else []

    if not projects:
        print(f"No *-rebrew projects found under {args.root}")
        return 2

    failures: list[tuple[Path, list[tuple[str, int, str]]]] = []
    report: list[dict[str, object]] = []
    for project in projects:
        if is_skipped(project):
            print(f"[SKIP] {project.name} (documented SKIPPED project)")
            report.append({"project": project.name, "skipped": True, "commands": []})
            continue
        results = check_project(args.rebrew, project)
        bad = [(cmd, code, out) for cmd, code, out in results if code != 0]
        report.append(
            {
                "project": project.name,
                "skipped": False,
                "commands": [{"cmd": cmd, "ok": code == 0} for cmd, code, _ in results],
            }
        )
        if bad:
            failures.append((project, bad))
            for cmd, code, out in bad:
                print(f"[FAIL] {project.name}: {cmd} (exit {code})")
                print(f"       {out.strip()[:300]}")
        else:
            print(f"[PASS] {project.name} ({len(results)} commands)")

    if args.json_out:
        print(
            json.dumps(
                {"total": len(projects), "failed": len(failures), "projects": report}, indent=2
            )
        )

    if failures:
        print(f"\n{len(failures)}/{len(projects)} project(s) failed.")
        return 1
    print(f"\nAll {len(projects)} project(s) clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
