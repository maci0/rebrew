"""rebrew document-unmatched — document every not-yet-reversed function.

Standalone version of the "document-unmatched" step that ``rebrew intake``
runs during onboarding (it used to be a per-project classify script —
bench/cpubench/makehm/openmiles each carried a near-duplicate).  For an
existing project this is the re-discovery workflow: new functions added to
the function list get a STUB ``.c`` skeleton plus a BLOCKER + STATUS=STUB
in ``rebrew-function.toml``, without re-running init/toolchain-link/rizin.

Already-documented functions are left untouched: a VA is considered
documented when a ``fcn_<va>.c`` file exists in the reversed dir or any
source file carries a FUNCTION/STUB marker for it (covers renamed files).

Shared logic lives in ``rebrew.intake.classify_all`` / ``blocker_reason``
(the canonical writers) — this command only decides *which* VAs are
unmatched and feeds them in.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.catalog.loaders import parse_function_list
from rebrew.cli import (
    TargetOption,
    error_exit,
    iter_annotations,
    iter_sources,
    json_print,
    require_config,
)
from rebrew.intake import classify_all

console = Console(stderr=True)

app = typer.Typer(
    help="Document unmatched functions as STUB skeletons + blockers.",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew document-unmatched --dry-run  Preview how many functions are undocumented\n\n"
        "  rebrew document-unmatched · · · · · · Write STUB .c + blocker for every unmatched function\n\n"
        "[dim]Skips VAs that already have a fcn_<va>.c file or a FUNCTION/STUB marker. "
        "Idempotent — re-running after documenting reports zero unmatched.[/dim]"
    ),
)

#: compiler profile -> blocker family ("" = generic application code).
_PROFILE_FAMILY: dict[str, str] = {
    "gcc-pe": "mingw",
    "delphi": "delphi",
}


def _documented_vas(src_dir: Path, cfg: Any) -> set[int]:
    """VAs already covered by a stub file or a FUNCTION/STUB marker."""
    documented: set[int] = set()
    for _path, anns in iter_annotations(iter_sources(src_dir, cfg)):
        for ann in anns:
            documented.add(ann["va"])
    # Intake's stub convention — also covers files the annotation parser
    # could not read (e.g. a stale/corrupt source) so we never double-write.
    for stub in src_dir.glob("fcn_*.c"):
        try:
            documented.add(int(stub.stem[len("fcn_") :], 16))
        except ValueError:
            continue
    return documented


@app.callback(invoke_without_command=True)
def main(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    backfill_blockers: bool = typer.Option(
        False,
        "--backfill-blockers",
        help="Write a BLOCKER for every existing STUB function that lacks one "
        "(the lint W005 class — stubs documented before document-unmatched existed)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Run the document-unmatched step in the current project."""
    cfg = require_config(target=target, json_mode=json_output)

    funcs = parse_function_list(cfg.function_list)
    src_dir = cfg.reversed_dir
    if not src_dir.is_dir():
        error_exit(f"reversed dir not found: {src_dir}", json_mode=json_output)

    family = _PROFILE_FAMILY.get(cfg.compiler_profile, "")

    if backfill_blockers:
        from rebrew.intake import blocker_reason
        from rebrew.metadata import get_entry, set_field
        from rebrew.naming import load_data

        _ghidra, existing, _covered = load_data(cfg)
        backfilled = 0
        for va, info in existing.items():
            module = info.get("module") or cfg.marker
            if info.get("status") == "STUB" and not get_entry(cfg.metadata_dir, va, module).get(
                "blocker"
            ):
                size = int(info.get("size") or 0)
                reason = blocker_reason(family, size, "")
                if not dry_run:
                    set_field(cfg.metadata_dir, va, "blocker", reason, module=module)
                backfilled += 1
        payload = {
            "functions": len(funcs),
            "backfilled_blockers": backfilled,
            "dry_run": dry_run,
        }
        if json_output:
            json_print(payload)
        else:
            action = "Would backfill" if dry_run else "Backfilled"
            console.print(
                f"{action} BLOCKER for {backfilled} STUB function(s) "
                f"({len(existing)} total documented)"
            )
        return

    documented = _documented_vas(src_dir, cfg)
    unmatched = [
        (f["va"], f["size"], f.get("name", "")) for f in funcs if f["va"] not in documented
    ]

    if dry_run:
        payload = {
            "functions": len(funcs),
            "documented": len(funcs) - len(unmatched),
            "unmatched": len(unmatched),
            "written": 0,
            "dry_run": True,
        }
        if json_output:
            json_print(payload)
        else:
            console.print(
                f"[dim]Would document {len(unmatched)} unmatched function(s) "
                f"({len(funcs) - len(unmatched)} already documented)[/dim]"
            )
        return

    written = classify_all(
        cfg.root,
        src_dir,
        cfg.marker,
        unmatched,
        family,
        "",
        metadata_dir=cfg.metadata_dir,
    )

    payload = {
        "functions": len(funcs),
        "documented": len(funcs) - len(unmatched),
        "unmatched": len(unmatched),
        "written": written,
        "dry_run": False,
    }
    if json_output:
        json_print(payload)
    else:
        console.print(
            f"[green]Documented {written} unmatched function(s)[/green] "
            f"({len(funcs) - len(unmatched)} already documented)"
        )
        if written:
            console.print("  next: rebrew doctor && rebrew status --json")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
