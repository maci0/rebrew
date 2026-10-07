"""check-tu-data — flag linked objects whose data breaks the MSVC6 one-TU shape.

MSVC 6 emits one translation unit's initialized data as its plain ``.data`` /
``.rdata`` contribution followed by the string-literal COMDATs it references
(``??_C@...``, and ``__real@...`` floating-point constants).  Reading the
built image's link map per object, in VA order:

* plain data after a literal means a TU boundary inside that object: the
  following data belongs to the next TU;
* named string arrays (``s_*``) after the object's last plain datum look like
  its literal pool spelled as globals.

Usage:
    rebrew build check-tu-data [--link-map build/<target>.map] [--json]
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import typer

from rebrew.cli import (
    EXIT_MISMATCH,
    TargetOption,
    console,
    error_exit,
    json_print,
    option_default,
    require_config,
    untrusted_ident,
)
from rebrew.data_ownership import LinkSymbol, is_compiler_literal, parse_link_map

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew build check-tu-data · · · · · · · · · · Check the active target's build map\n\n"
    "  rebrew build check-tu-data --link-map build/game.map --json · Per-object JSON\n"
)

#: Initialized-data sections whose per-object order carries the TU shape.
_CHECKED_SECTIONS = (".data", ".rdata")

#: Decorated prefix of a named string array (``char s_Foo[]`` is ``_s_Foo``).
_NAMED_STRING_PREFIX = "_s_"

KIND_DATA = "D"
KIND_LITERAL = "L"
KIND_NAMED_STRING = "S"


def symbol_kind(name: str) -> str:
    """Classify a data symbol as plain data, compiler literal, or named string."""
    if is_compiler_literal(name):
        return KIND_LITERAL
    if name.startswith(_NAMED_STRING_PREFIX):
        return KIND_NAMED_STRING
    return KIND_DATA


def _run_length(kinds: list[str]) -> str:
    """``DDDLL`` -> ``D3L2``."""
    out: list[str] = []
    for kind in kinds:
        if out and out[-1][0] == kind:
            out[-1] = f"{kind}{int(out[-1][1:]) + 1}"
        else:
            out.append(f"{kind}1")
    return "".join(out)


def tu_data_shapes(symbols: list[LinkSymbol]) -> list[dict[str, Any]]:
    """Per project object and section, its data symbols in VA order and shape findings.

    Library members, COMMON storage, functions, and sections outside
    ``.data``/``.rdata`` are left out. Rows are ordered by first VA.
    """
    groups: dict[tuple[str, str], list[LinkSymbol]] = defaultdict(list)
    for sym in symbols:
        if sym.is_function or not sym.object or sym.section not in _CHECKED_SECTIONS:
            continue
        groups[(sym.object, sym.section)].append(sym)
    rows: list[dict[str, Any]] = []
    for (obj, section), members in groups.items():
        members.sort(key=lambda s: s.va)
        kinds = [symbol_kind(s.name) for s in members]
        issues: list[dict[str, Any]] = []
        for index in range(1, len(members)):
            if kinds[index] == KIND_DATA and kinds[index - 1] == KIND_LITERAL:
                issues.append(
                    {
                        "kind": "data_after_literals",
                        "va": f"0x{members[index].va:08x}",
                        "symbol": members[index].name,
                    }
                )
        last_data = max((i for i, k in enumerate(kinds) if k == KIND_DATA), default=-1)
        trailing = [
            s.name for i, s in enumerate(members) if i > last_data and kinds[i] == KIND_NAMED_STRING
        ]
        if trailing:
            issues.append({"kind": "named_strings", "count": len(trailing), "symbols": trailing})
        rows.append(
            {
                "object": obj,
                "section": section,
                "first_va": f"0x{members[0].va:08x}",
                "symbols": len(members),
                "shape": _run_length(kinds),
                "issues": issues,
            }
        )
    rows.sort(key=lambda row: int(row["first_va"], 16))
    return rows


def _describe(issue: dict[str, Any]) -> str:
    if issue["kind"] == "data_after_literals":
        return f"TU boundary before {untrusted_ident(issue['symbol'])} at {issue['va']}"
    return f"{issue['count']} trailing named string(s)"


app = typer.Typer(
    help="Flag linked objects whose .data/.rdata breaks the MSVC6 one-TU shape.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    link_map: Path | None = typer.Option(
        None, "--link-map", help="MSVC link map of the build (default: build/<target>.map)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Order each object's data symbols by VA and flag TU-shape breaks."""
    cfg = require_config(target=target, json_mode=json_output)
    root = Path(cfg.root)
    map_path = option_default(link_map, None)
    if map_path is None:
        map_path = (Path("build") / cfg.target_name).with_suffix(".map")
    if not map_path.is_absolute():
        map_path = root / map_path
    try:
        text = map_path.read_bytes().decode("utf-8", errors="surrogateescape")
    except OSError as exc:
        error_exit(f"cannot read link map {map_path}: {exc}", json_mode=json_output)
        return
    rows = tu_data_shapes(parse_link_map(text))
    flagged = [row for row in rows if row["issues"]]
    if json_output:
        json_print(
            {
                "link_map": str(map_path),
                "objects": rows,
                "checked": len(rows),
                "flagged": len(flagged),
            }
        )
    else:
        for row in flagged:
            console.print(
                f"{row['first_va']} {row['section']:6} "
                f"{untrusted_ident(Path(row['object']).name):32} {row['shape']:24} "
                + "; ".join(_describe(issue) for issue in row["issues"])
            )
        console.print(f"checked {len(rows)} object section(s), {len(flagged)} flagged")
    if flagged:
        raise typer.Exit(code=EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
