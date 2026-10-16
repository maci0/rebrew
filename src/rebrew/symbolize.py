"""symbolize.py - Rewrite raw data addresses in a C source to the globals the reference relocates.

A source that spells an operand as a bare address (``*(int *) 0x10034618``)
can match the instruction bytes while the image lacks the base relocation the
reference has at that operand: the original code named a symbol there. For
each of the file's functions, the reference's base relocations are compared
with the raw link's at the same function offsets. A site the build lacks whose
target lies inside a named data row the link defines becomes ``&name``, or
``((char *) &name + 0xOFF)`` for an interior address.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any

import typer

from rebrew.cli import TargetOption, console, error_exit, json_print, require_config

app = typer.Typer(
    help="Rewrite raw (T *) 0xVA casts to the data symbols the reference relocates.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source symbolize src/game/net.c --dry-run  # Preview the rewrites\n\n"
        "  # Leave one body alone\n"
        "  rebrew source symbolize src/game/net.c --skip LoadTables\n\n"
        "  # Declare a missing global\n"
        "  rebrew source symbolize src/game/net.c --declare g_table\n\n"
        "[dim]Needs the raw link and its .map (\\[targets.<name>] raw_link). Re-test the file afterwards: a symbol can change register allocation, and a loop needs both bounds symbolized with their original signedness.[/dim]"
    ),
)


# ---------------------------------------------------------------------------
# Relocation sites
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DataRow:
    """A named data row the link defines: reference VA, extent, and its C name."""

    va: int
    size: int
    name: str


def defined_data_rows(cfg: Any, link_symbols: set[str]) -> list[DataRow]:
    """Named data rows whose native symbol the link defines, sorted by VA.

    ``link_symbol`` wins over ``_`` + ``name``. Layout spans and import slots
    are skipped: neither is a symbol the source can name.
    """
    from rebrew.metadata.data import load_data_metadata, module_visible_to_target
    from rebrew.utils import is_safe_c_ident

    rows: list[DataRow] = []
    for (module, va), fields in load_data_metadata(cfg.metadata_dir).items():
        name = str(fields.get("name") or "")
        if (
            not name
            or not module_visible_to_target(module, cfg)
            or fields.get("storage_kind") in ("span", "import")
        ):
            continue
        symbol = str(fields.get("link_symbol") or f"_{name}")
        c_name = symbol[1:]
        if symbol not in link_symbols or not symbol.startswith("_") or not is_safe_c_ident(c_name):
            continue
        rows.append(DataRow(va, max(int(fields.get("size") or 1), 1), c_name))
    return sorted(rows, key=lambda row: (row.va, row.name))


def symbolic_expression(value: int, rows: list[DataRow], starts: list[int]) -> str | None:
    """``&name`` or ``((char *) &name + 0xOFF)`` for *value*, from the nearest row containing it."""
    for index in range(bisect.bisect_right(starts, value) - 1, -1, -1):
        row = rows[index]
        if value < row.va + row.size:
            offset = value - row.va
            return f"&{row.name}" if offset == 0 else f"((char *) &{row.name} + {offset:#x})"
    return None


def _sites_in(spans: list[tuple[int, int]], starts: list[int], va: int, size: int) -> set[int]:
    """Offsets from *va* of the fixups inside ``[va, va + size)``."""
    lo, hi = bisect.bisect_left(starts, va), bisect.bisect_left(starts, va + size)
    return {spans[i][0] - va for i in range(lo, hi)}


def object_names(source: Path) -> set[str]:
    """Object file names a build gives *source*: ``net.c.obj`` (CMake) and ``net.obj``."""
    return {f"{source.name}.obj".casefold(), f"{source.stem}.obj".casefold()}


@dataclass
class SiteReport:
    """What the reference relocates in a file's functions and the build does not."""

    targets: dict[str, dict[int, str]]  # function -> target value -> expression
    unresolved: list[dict[str, Any]]
    unlinked: list[str]


def missing_relocations(cfg: Any, source: Path, built: Path, link_map: Path) -> SiteReport:
    """Reference-relocated operands the raw link lacks in *source*'s functions.

    A function counts when its row names *source* and the map places its
    symbol in *source*'s object. Fixups are compared by offset from each
    function's start, so a build whose layout drifted is compared correctly.
    """
    from rebrew.config import target_module
    from rebrew.data_ownership import parse_link_map
    from rebrew.formats.binary_loader import extract_bytes_at_va, load_binary
    from rebrew.formats.relocations import relocation_spans
    from rebrew.metadata.bindings import read_source_bindings
    from rebrew.rename_ops import c_name_from_symbol

    symbols = parse_link_map(link_map.read_text(encoding="utf-8", errors="replace"))
    objects = object_names(source)
    built_functions = {
        sym.name: sym.va
        for sym in symbols
        if sym.is_function and PureWindowsPath(sym.object).name.casefold() in objects
    }
    rows = defined_data_rows(cfg, {sym.name for sym in symbols if not sym.is_function})
    row_starts = [row.va for row in rows]

    reference = load_binary(Path(cfg.target_binary))
    ref_spans = relocation_spans(reference)
    got_spans = relocation_spans(load_binary(built))
    ref_starts = [address for address, _ in ref_spans]
    got_starts = [address for address, _ in got_spans]
    widths = dict(ref_spans)

    report = SiteReport({}, [], [])
    annotations = read_source_bindings(
        source,
        target_name=target_module(cfg),
        base_dir=cfg.root,
        metadata_dir=cfg.metadata_dir,
        project_root=getattr(cfg, "root", None),
    )
    for ann in annotations:
        if not ann.is_function or ann.size <= 0:
            continue
        symbol = ann.symbol or (f"_{ann.name}" if ann.name else "")
        built_va = built_functions.get(symbol)
        if built_va is None:
            report.unlinked.append(symbol or f"0x{ann.va:08x}")
            continue
        function = c_name_from_symbol(symbol)
        missing = _sites_in(ref_spans, ref_starts, ann.va, ann.size) - _sites_in(
            got_spans, got_starts, built_va, ann.size
        )
        for offset in sorted(missing):
            site = ann.va + offset
            raw = extract_bytes_at_va(reference, site, widths[site], trim_padding=False)
            if raw is None:
                continue
            value = int.from_bytes(raw, "little")
            expression = symbolic_expression(value, rows, row_starts)
            if expression is None:
                report.unresolved.append(
                    {"function": function, "site": f"0x{site:08x}", "value": f"0x{value:08x}"}
                )
                continue
            report.targets.setdefault(function, {})[value] = expression
    return report


# ---------------------------------------------------------------------------
# Source rewrite
# ---------------------------------------------------------------------------


def rewrite_casts(
    text: str, targets: dict[str, dict[int, str]], skip: set[str]
) -> tuple[str, list[dict[str, Any]]]:
    """Replace each targeted ``(T *) 0xVA`` constant inside its own function's body.

    Returns the new text and one ``{function, value, expression, count}`` row
    per target. A function in *skip* keeps its body.
    """
    from rebrew.c_parser import pointer_cast_literals

    counts: dict[tuple[str, int], int] = {
        (function, value): 0 for function, values in targets.items() for value in values
    }
    raw = text.encode("utf-8", errors="surrogateescape")
    edits = [
        lit
        for lit in pointer_cast_literals(text)
        if lit.function not in skip and lit.value in targets.get(lit.function, {})
    ]
    for lit in sorted(edits, key=lambda item: item.start, reverse=True):
        expression = targets[lit.function][lit.value]
        raw = raw[: lit.start] + expression.encode("ascii") + raw[lit.end :]
        counts[(lit.function, lit.value)] += 1
    rows = [
        {
            "function": function,
            "value": f"0x{value:08x}",
            "expression": targets[function][value],
            "count": count,
            "skipped": function in skip,
        }
        for (function, value), count in sorted(counts.items())
    ]
    return raw.decode("utf-8", errors="surrogateescape"), rows


def declare_externs(text: str, names: list[str]) -> tuple[str, list[str]]:
    """Append ``extern char NAME[];`` to the file's first one-line top-level extern.

    A new line would shift every later line number, which was measured to
    change MSVC6 code generation in some translation units. A name already
    declared or defined at file scope is left out. Returns the new text and
    the names declared.
    """
    from rebrew.c_parser import find_extern_variables

    lines = text.splitlines(keepends=True)
    variables = [
        var
        for var in find_extern_variables(text, include_definitions=True)
        if not lines[var.line - 1][:1].isspace()
    ]
    declared = {var.name for var in variables}
    wanted = [name for name in dict.fromkeys(names) if name not in declared]
    if not wanted:
        return text, []
    anchor = next(
        (
            var.line
            for var in variables
            if var.line == var.end_line
            and lines[var.line - 1].startswith("extern")
            and lines[var.line - 1].rstrip().endswith(";")
        ),
        None,
    )
    if anchor is None:
        raise ValueError("no one-line top-level extern declaration to append declarations to")
    line = lines[anchor - 1]
    body = line.rstrip("\r\n")
    lines[anchor - 1] = (
        body.rstrip() + "".join(f" extern char {name}[];" for name in wanted) + line[len(body) :]
    )
    return "".join(lines), wanted


def symbolize_file(
    cfg: Any,
    source: Path,
    *,
    skip: list[str],
    declare: list[str],
    dry_run: bool = False,
) -> dict[str, Any]:
    """Rewrite *source*'s raw relocated addresses; returns the report row."""
    from rebrew.c_parser import find_c_function_definitions
    from rebrew.utils import is_safe_c_ident, rel_display_path

    raw_link = getattr(cfg, "raw_link", None)
    if raw_link is None:
        raise ValueError("no raw_link configured for this target; symbolize reads its .map")
    built = Path(raw_link)
    link_map = built.with_suffix(".map")
    for path, what in ((built, "raw link"), (link_map, "link map")):
        if not path.is_file():
            raise ValueError(f"{what} {path} not found; build the target first")
    bad = [name for name in declare if not is_safe_c_ident(name)]
    if bad:
        raise ValueError(f"--declare wants C identifiers, got {', '.join(bad)}")
    text = source.read_text(encoding="utf-8", errors="surrogateescape")
    defined = {name for name, _ in find_c_function_definitions(text)}
    unknown = sorted(set(skip) - defined)
    if unknown:
        raise ValueError(f"--skip names no function defined in {source.name}: {', '.join(unknown)}")

    sites = missing_relocations(cfg, source, built, link_map)
    text, rewrites = rewrite_casts(text, sites.targets, set(skip))
    text, declared = declare_externs(text, declare) if declare else (text, [])
    changed = sum(row["count"] for row in rewrites)
    if not dry_run and (changed or declared):
        source.write_text(text, encoding="utf-8", errors="surrogateescape")
    return {
        "file": rel_display_path(source, cfg.root),
        "dry_run": dry_run,
        "changed": changed,
        "rewrites": rewrites,
        "declared": declared,
        "unresolved": sites.unresolved,
        "unlinked": sites.unlinked,
    }


@app.callback(invoke_without_command=True)
def main(
    source: Path = typer.Argument(..., help="C source to rewrite"),
    skip: list[str] = typer.Option(
        [], "--skip", metavar="FUNC", help="Leave this function's body unchanged (repeatable)"
    ),
    declare: list[str] = typer.Option(
        [],
        "--declare",
        metavar="NAME",
        help="Append 'extern char NAME[];' to the first top-level extern line (repeatable)",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Rewrite raw (T *) 0xVA casts to the data symbols the reference relocates."""
    cfg = require_config(target=target, json_mode=json_output)
    path = source if source.is_absolute() else Path.cwd() / source
    if not path.is_file():
        error_exit(f"{source} is not a file", json_mode=json_output)
    try:
        report = symbolize_file(cfg, path, skip=skip, declare=declare, dry_run=dry_run)
    except (OSError, ValueError, NotImplementedError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
        return
    for row in report["rewrites"]:
        note = " (skipped)" if row["skipped"] else ""
        console.print(
            f"{row['value']} {row['expression']} in {row['function']}: {row['count']}{note}",
            markup=False,
        )
    for row in report["unresolved"]:
        console.print(
            f"{row['site']} -> {row['value']} in {row['function']}: no defined data row",
            style="yellow",
            markup=False,
        )
    for symbol in report["unlinked"]:
        console.print(
            f"{symbol}: not in this file's object in the link map", style="yellow", markup=False
        )
    for name in report["declared"]:
        console.print(f"declared {name}", markup=False)
    verb = "would rewrite" if report["dry_run"] else "rewrote"
    console.print(f"{verb} {report['changed']} operands in {report['file']}", markup=False)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
