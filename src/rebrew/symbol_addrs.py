"""symbol-addrs: export function symbols as a splat-style ``symbol_addrs`` file.

The decomp-scene's splat ecosystem uses ``symbol_addrs`` as the interchange
format between the binary splitter, m2c, and the diff tooling.  Rebrew keeps
the same information in per-directory ``rebrew-functions.toml`` +
annotations, but there is no portable export: Ghidra imports, splat-style
tooling, and third-party viewers all expect it.  This command writes it.

Output modes (one per run, all sorted by VA):

- **rich** (default): the splat symbol format
  ``name = 0x00100000; // type:func size:0x2A``.  The comment carries the
  symbol's type (``func`` / ``u32``), its size when known, and, for a symbol
  named from a PE data directory, where it came from.  A forwarded export has
  no address in this image, so it is written as a ``// name -> target`` note
  line rather than a symbol line.
- **bare CSV** (``--csv``): the original two-column ``0xVA,name`` lines.
- **symbols dump** (``--references``): a CSV with a header and a
  ``referenced_by`` column naming the symbols that address each one (the splat
  ``dump_symbols`` idea).  References come from the shared disassembly xref
  scan (:func:`rebrew.analysis.scan_references`).

``--pe-symbols`` extends either mode with symbols named from the target PE's
data directories (:mod:`rebrew.pe_symbols`): the entry point, exports,
``__imp_<dll>_<name>`` IAT slots, delay-load slots, TLS callbacks, SafeSEH
handlers, ``/guard:cf`` targets, and the security cookie.

When a PE symbol collides with an annotation this command already knows, the
annotation wins: the PE symbol is dropped and the collision is reported in the
``--json`` payload and on stderr.  A collision is either the same VA under a
different name or the same name at a different VA.

Usage:
    rebrew symbol-addrs --output symbol_addrs.csv
    rebrew symbol-addrs --pe-symbols --output symbol_addrs.csv
    rebrew symbol-addrs --references --output symbols.csv
    rebrew symbol-addrs --csv -t mygame --output build/symbol_addrs.csv
"""

from __future__ import annotations

import bisect
import csv
import io
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import TargetOption, error_exit, iter_annotations, json_print, require_config
from rebrew.pe_symbols import KIND_FUNC, PeSymbolTable, pe_symbols
from rebrew.sources import iter_sources, target_marker
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

#: Trailing-comment markers the rich format uses inside ``// ...`` comments.
_TYPE_PREFIX = "type:"
_SIZE_PREFIX = "size:"
_DETAIL_SEPARATOR = " -- "

#: CSV header of the symbols dump (``--references``).
_DUMP_HEADER: tuple[str, ...] = ("va", "name", "type", "size", "referenced_by")

app = typer.Typer(
    help="Export annotations as a splat-style symbol_addrs file.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew symbol-addrs · · · · · · · Annotations only\n\n"
        "  rebrew symbol-addrs --pe-symbols · IAT slots, exports, TLS callbacks, ...\n\n"
        "  rebrew symbol-addrs --references · Symbols dump with referenced_by\n\n"
        "  rebrew symbol-addrs --csv · · · · · The bare 0xVA,name CSV\n\n"
        "[dim]Output is sorted by VA and idempotent: re-running produces the\n"
        "same bytes.  An annotation always wins a collision with a symbol\n"
        "named from the PE, and the collision is reported.[/dim]"
    ),
)


# ---------------------------------------------------------------------------
# Record type and formatting
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SymbolRow:
    """One exported symbol.

    ``va`` is absolute, or ``None`` for a forwarded export (which lives in
    another module).  ``kind`` is the splat type name, ``size`` the byte size
    when one is known, and ``detail`` optional provenance text appended to the
    rich format's trailing comment.
    """

    va: int | None
    name: str
    kind: str = KIND_FUNC
    size: int | None = None
    detail: str = ""
    forwarder: str | None = None
    origin: str = ""


def format_symbol(row: SymbolRow) -> str:
    """One rich-format line for *row* (a ``//`` note line for a forwarder)."""
    if row.va is None:
        target = row.forwarder or "?"
        return f"// {row.name} -> {target} (forwarded export)"
    comment = f"{_TYPE_PREFIX}{row.kind}"
    if row.size is not None:
        comment += f" {_SIZE_PREFIX}0x{row.size:X}"
    if row.detail:
        comment += f"{_DETAIL_SEPARATOR}{row.detail}"
    return f"{row.name} = 0x{row.va:08X}; // {comment}"


def parse_symbol_addrs(text: str) -> list[SymbolRow]:
    """Parse the rich format back into rows.

    A ``name = 0xVA;`` line is the symbol form; the trailing ``//`` comment
    carries ``type:`` / ``size:`` / provenance text.  Bare ``0xVA,name`` CSV
    lines (the ``--csv`` output) parse too, as ``func`` rows.  Comment-only and
    blank lines are skipped, which is what drops the forwarded-export notes.
    """
    rows: list[SymbolRow] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if "=" in stripped and ";" in stripped:
            name, _, rest = stripped.partition("=")
            address_text, _, comment = rest.partition(";")
            va = _parse_hex(address_text.strip())
            if va is None or not name.strip():
                continue
            rows.append(_row_from_comment(name.strip(), va, comment.strip()))
            continue
        address_text, _, name = stripped.partition(",")
        va = _parse_hex(address_text.strip())
        if va is None or not name.strip():
            continue
        rows.append(SymbolRow(va=va, name=name.strip()))
    return rows


def _row_from_comment(name: str, va: int, comment: str) -> SymbolRow:
    """Build a row from a rich line's name, VA, and trailing comment."""
    body = comment[2:].strip() if comment.startswith("//") else comment
    kind = KIND_FUNC
    size: int | None = None
    detail = ""
    if body:
        head, _, tail = body.partition(_DETAIL_SEPARATOR)
        detail = tail.strip()
        for token in head.split():
            if token.startswith(_TYPE_PREFIX):
                kind = token[len(_TYPE_PREFIX) :] or KIND_FUNC
            elif token.startswith(_SIZE_PREFIX):
                size = _parse_hex(token[len(_SIZE_PREFIX) :])
    return SymbolRow(va=va, name=name, kind=kind, size=size, detail=detail)


def _parse_hex(text: str) -> int | None:
    """Parse a ``0x``-prefixed or decimal integer, or ``None``."""
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None


def format_csv(rows: list[SymbolRow], references: dict[int, list[str]]) -> str:
    """The symbols-dump CSV: ``va,name,type,size,referenced_by``."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_DUMP_HEADER)
    for row in rows:
        writer.writerow(
            [
                "" if row.va is None else f"0x{row.va:08X}",
                row.name,
                row.kind,
                "" if row.size is None else f"0x{row.size:X}",
                "|".join(references.get(row.va or -1, ())),
            ]
        )
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Symbol sources
# ---------------------------------------------------------------------------


def merge_pe_symbols(
    rows: list[SymbolRow], table: PeSymbolTable
) -> tuple[list[SymbolRow], list[str]]:
    """Add *table*'s symbols to *rows*, dropping those that collide.

    An annotation (an entry already in *rows*) wins both collisions: the same
    VA under a different name, and the same name at a different VA.  A PE
    symbol that collides with an earlier PE symbol (two export names for one
    address, say) is dropped too, since one name and one address must each map
    to a single symbol.  Returns the merged rows and one message per dropped
    symbol.
    """
    known_vas = {row.va for row in rows if row.va is not None}
    known_names = {row.name for row in rows}
    pe_vas: set[int] = set()
    pe_names: set[str] = set()
    merged = list(rows)
    collisions: list[str] = []
    for symbol in table.symbols:
        address = f"0x{symbol.va:08X}" if symbol.va is not None else "(forwarded)"
        if symbol.va is not None and symbol.va in known_vas:
            collisions.append(
                f"{symbol.name} ({address}, {symbol.origin}) collides with an "
                "annotation at the same VA"
            )
            continue
        if symbol.name in known_names:
            collisions.append(
                f"{symbol.name} ({address}, {symbol.origin}) collides with an "
                "annotation of the same name"
            )
            continue
        if (symbol.va is not None and symbol.va in pe_vas) or symbol.name in pe_names:
            collisions.append(
                f"{symbol.name} ({address}, {symbol.origin}) collides with another PE symbol"
            )
            continue
        if symbol.va is not None:
            pe_vas.add(symbol.va)
        pe_names.add(symbol.name)
        merged.append(
            SymbolRow(
                va=symbol.va,
                name=symbol.name,
                kind=symbol.kind,
                size=symbol.size,
                detail=symbol.detail,
                forwarder=symbol.forwarder,
                origin=symbol.origin,
            )
        )
    return merged, collisions


def build_references(rows: list[SymbolRow], binary: Path) -> dict[int, list[str]]:
    """Map each symbol VA to the sorted names of the symbols referencing it.

    Uses :func:`rebrew.analysis.scan_references`, the shared disassembly xref
    scan, rather than re-walking the image here.  A reference site that falls
    in no known symbol is named ``fcn_<VA>`` (the dossier's convention), so an
    unresolved caller is visible instead of dropped.
    """
    from rebrew.analysis import scan_references
    from rebrew.binary_loader import load_binary

    targets = {row.va for row in rows if row.va is not None}
    if not targets:
        return {}
    info = load_binary(binary)
    resolve = _site_resolver(rows)
    refs: dict[int, set[str]] = {}
    for xref in scan_references(info):
        if xref.to_va in targets:
            refs.setdefault(xref.to_va, set()).add(resolve(xref.from_va))
    return {va: sorted(names) for va, names in refs.items()}


def _site_resolver(rows: list[SymbolRow]) -> Callable[[int], str]:
    """A callable mapping a reference site's VA to the enclosing symbol name."""
    exact = {row.va: row.name for row in rows if row.va is not None}
    ranges = sorted(
        (row.va, row.va + row.size, row.name) for row in rows if row.va is not None and row.size
    )
    starts = [lo for lo, _hi, _name in ranges]

    def resolve(va: int) -> str:
        name = exact.get(va)
        if name:
            return name
        index = bisect.bisect_right(starts, va) - 1
        if index >= 0:
            lo, hi, candidate = ranges[index]
            if lo <= va < hi:
                return candidate
        return f"fcn_{va:08x}"

    return resolve


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    output: Path = typer.Option(Path("symbol_addrs.csv"), "--output", "-o", help="Output path"),
    csv_output: bool = typer.Option(
        False, "--csv", help="Write the bare 0xVA,name CSV instead of the rich symbol format"
    ),
    references: bool = typer.Option(
        False, "--references", help="Write the CSV symbols dump with a referenced_by column"
    ),
    pe_symbol_output: bool = typer.Option(
        False, "--pe-symbols", help="Include symbols named from the target PE's data directories"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Write the annotated functions (and optionally the PE's own) as symbols."""
    cfg = require_config(target=target, json_mode=json_output)
    from rebrew.annotation import min_valid_va_for

    if csv_output and references:
        error_exit(
            "--csv and --references select different output formats; pass one.",
            json_mode=json_output,
            code=2,
        )

    va_floor = min_valid_va_for(cfg)
    sources = list(iter_sources(cfg.reversed_dir, cfg))
    marker = target_marker(cfg)
    rows: list[SymbolRow] = []
    skipped = 0
    skipped_va = 0
    for _path, annos in iter_annotations(sources, target=marker, metadata_dir=cfg.metadata_dir):
        for a in annos:
            if a.marker_type in ("GLOBAL", "DATA"):
                continue
            name = a.symbol or a.name or ""
            if not name:
                skipped += 1
                continue
            if int(a.va) < va_floor:
                skipped_va += 1
                continue
            rows.append(SymbolRow(va=a.va, name=name, size=a.size or None))

    notes: list[str] = []
    collisions: list[str] = []
    pe_count = 0
    binary = Path(cfg.target_binary)
    if (pe_symbol_output or references) and not binary.exists():
        error_exit(f"target binary missing: {binary}", json_mode=json_output, code=2)
    if pe_symbol_output:
        table = pe_symbols(binary)
        pe_count = len(table.symbols)
        notes = list(table.notes)
        rows, collisions = merge_pe_symbols(rows, table)

    rows.sort(key=_row_sort_key)
    if references:
        body = format_csv(rows, build_references(rows, binary))
        mode = "references"
    elif csv_output:
        body = "\n".join(f"0x{row.va:08X},{row.name}" for row in rows if row.va is not None) + "\n"
        mode = "csv"
    else:
        body = "\n".join(format_symbol(row) for row in rows) + "\n"
        mode = "rich"
    atomic_write_text(output, body, encoding="utf-8")

    for collision in collisions:
        console.print(f"[yellow]PE symbol dropped:[/yellow] {collision}")
    for note in notes:
        console.print(f"[dim]pe-symbols: {note}[/dim]")

    if json_output:
        json_print(
            {
                "output": str(output),
                "symbols": len(rows),
                "skipped_unnamed": skipped,
                "skipped_invalid_va": skipped_va,
                "format": mode,
                "pe_symbols": pe_count,
                "pe_collisions": collisions,
                "pe_notes": notes,
            }
        )
        return
    console.print(
        f"[green]Wrote {len(rows)} symbol(s) to {output}[/green]"
        + (f" ({skipped} unnamed skipped)" if skipped else "")
        + (f" ({skipped_va} below-VA-floor skipped)" if skipped_va else "")
        + (f" ({len(collisions)} PE collision(s) dropped)" if collisions else "")
    )


def _row_sort_key(row: SymbolRow) -> tuple[int, int, str]:
    """Sort by VA, then name; forwarded exports (no VA) come last."""
    if row.va is None:
        return (1, 0, row.name)
    return (0, row.va, row.name)


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
