"""text-audit — post-edit check: compare .text function VAs vs the markers.

The linked ``.text`` section is the concatenation of per-TU contributions in
link order.  After editing sources, this command walks the link's object
files (objdump on each obj, in link order), computes every function's current
``.text`` VA, and compares it against the ``// FUNCTION:`` marker VA in the
sources.  Misplaced functions mean the object order or a TU's own layout
drifted — the position-alignment gate ``postlink`` assumes but never checks.
When objects are unavailable, actual VAs fall back to exported-symbol lookup
on the built binary.

Usage:
    rebrew text-audit [--built build/server.dll] [--limit 15] [--json]
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import (
    EXIT_MISMATCH,
    TargetOption,
    error_exit,
    iter_annotations,
    json_print,
    require_config,
)
from rebrew.data_layout import built_text_va
from rebrew.sources import iter_sources, target_marker

console = Console(stderr=True)

app = typer.Typer(
    help="Compare .text function VAs of the current build against the source markers.",
    rich_markup_mode="rich",
)


def _expected_functions(cfg: Any) -> dict[str, int]:
    """``{symbol: marker VA}`` for every annotated function."""
    marker = target_marker(cfg)
    out: dict[str, int] = {}
    for path, annos in iter_annotations(
        iter_sources(cfg.reversed_dir, cfg), target=marker, metadata_dir=cfg.metadata_dir
    ):
        for ann in annos:
            sym = ann.symbol if ann.symbol and ann.symbol != "?" else "_" + path.stem
            out.setdefault(sym.lstrip("_"), ann.va)
    return out


def exported_symbol_vas(binary: Path) -> dict[str, int]:
    """``{name: VA}`` for the exported symbols of *binary* (LIEF).

    Tolerates non-PE files and missing export tables by returning an empty
    map — the caller reports every function MISSING instead of crashing.
    """
    import lief

    try:
        pe = lief.PE.parse(str(binary))
    except Exception:  # parse failures degrade to "no exports"
        return {}
    if pe is None:
        return {}
    try:
        image_base = int(pe.optional_header.imagebase)
    except (AttributeError, TypeError, ValueError):
        image_base = 0
    out: dict[str, int] = {}
    for func in getattr(pe, "exported_functions", []):
        name = getattr(func, "name", "")
        if name:
            out.setdefault(str(name).lstrip("_"), image_base + int(func.address))
    return out


def collect_actual_vas(root: Path, binary: Path) -> dict[str, int]:
    """``{symbol: .text VA}`` of the current build, in link order.

    Walks the link's object files (objdump, link order) onto the built
    binary's ``.text`` base VA.  Falls back to exported-symbol lookup on the
    built binary when no objects are inventoried (raises on objdump errors —
    same as ``verify-placement``: a partial walk reports wrong VAs instead
    of honest MISSING rows).
    """
    from rebrew.data_layout import link_objects, obj_text_symbol_offsets

    text_base = built_text_va(binary)
    try:
        objects = link_objects(root)
    except FileNotFoundError:
        return exported_symbol_vas(binary)
    here: dict[str, int] = {}
    tot = 0
    for obj in objects:
        tsize, syms = obj_text_symbol_offsets(obj)
        for sym, off in syms.items():
            here.setdefault(sym.lstrip("_"), text_base + tot + off)
        tot += tsize
    return here


def audit_text(
    expected: dict[str, int], actual: dict[str, int]
) -> tuple[list[dict[str, Any]], int, int, int]:
    """Classify each expected function as OK / MISPLACED / MISSING.

    Returns ``(rows, n_ok, n_misplaced, n_missing)``; rows sort misplaced
    first by |delta|, then missing, then OK.
    """
    rows: list[dict[str, Any]] = []
    for name, exp in sorted(expected.items(), key=lambda kv: kv[1]):
        act = actual.get(name)
        if act is None:
            rows.append(
                {
                    "symbol": name,
                    "status": "MISSING",
                    "expected": f"0x{exp:x}",
                    "actual": None,
                    "delta": None,
                }
            )
        elif act == exp:
            rows.append(
                {
                    "symbol": name,
                    "status": "OK",
                    "expected": f"0x{exp:x}",
                    "actual": f"0x{act:x}",
                    "delta": 0,
                }
            )
        else:
            rows.append(
                {
                    "symbol": name,
                    "status": "MISPLACED",
                    "expected": f"0x{exp:x}",
                    "actual": f"0x{act:x}",
                    "delta": act - exp,
                }
            )
    n_ok = sum(1 for r in rows if r["status"] == "OK")
    n_bad = sum(1 for r in rows if r["status"] == "MISPLACED")
    n_missing = sum(1 for r in rows if r["status"] == "MISSING")
    order = {"MISPLACED": 0, "MISSING": 1, "OK": 2}
    rows.sort(
        key=lambda r: (
            order[r["status"]],
            -abs(r["delta"]) if isinstance(r["delta"], int) else 0,
        )
    )
    return rows, n_ok, n_bad, n_missing


@app.callback(invoke_without_command=True)
def main(
    built: Path = typer.Option(
        Path("build/server.dll"),
        "--built",
        help="Built binary to inspect (default: build/server.dll)",
    ),
    limit: int = typer.Option(15, "--limit", help="Max misplaced functions to print"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Build-then-compare: .text function VAs of the current build vs the markers."""
    cfg = require_config(target=target, json_mode=json_output)
    root = Path(cfg.root)
    dll = built if built.is_absolute() else root / built
    if not dll.exists():
        error_exit(
            f"{dll} not found — build the project first (or pass --built <path>)",
            json_mode=json_output,
        )
    try:
        actual = collect_actual_vas(root, dll)
    except (RuntimeError, OSError, ValueError) as exc:
        error_exit(f"cannot inventory build objects: {exc}", json_mode=json_output)

    expected = _expected_functions(cfg)
    rows, n_ok, n_bad, n_missing = audit_text(expected, actual)
    shown = [r for r in rows if r["status"] != "OK"][:limit]

    if json_output:
        json_print(
            {
                "functions": len(expected),
                "found": n_ok + n_bad,
                "correct": n_ok,
                "misplaced": n_bad,
                "missing": n_missing,
                "misplaced_list": shown,
            }
        )
    else:
        console.print(
            f"functions: {len(expected)}  found: {n_ok + n_bad}  "
            f"correct-VA: {n_ok}  misplaced: {n_bad}  missing: {n_missing}"
        )
        for r in shown:
            if r["status"] == "MISPLACED":
                console.print(
                    f"  {r['symbol']:32} exp {int(r['expected'], 16):#010x}  "
                    f"our {int(r['actual'], 16):#010x}  d {r['delta']:+#x}"
                )
            else:
                console.print(f"  {r['symbol']:32} exp {r['expected']}  MISSING from build")
    if n_bad:
        raise typer.Exit(code=EXIT_MISMATCH)


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
