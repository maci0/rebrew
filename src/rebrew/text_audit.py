"""Compare linked .text function addresses against the source bindings.

The built image's sibling MSVC map takes precedence over object contributions:
linker retention and archive extraction can change the actual placement. Without
a map, retain the object-walk estimate and exported-symbol fallback.

Usage:
    rebrew build check-text-placement [--built build/<target>] [--limit 15] [--json]
    rebrew build check-text-placement --rounding  # extent deviation audit
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
lazy from collections.abc import Iterable
lazy from pathlib import Path

import typer

from rebrew.cli import (
    BUILT_IMAGE_HELP,
    EXIT_MISMATCH,
    TargetOption,
    console,
    error_exit,
    json_print,
    option_default,
    require_config,
    require_non_negative,
)
lazy from rebrew.data_layout import built_text_va
lazy from rebrew.verify_hash import expected_text_function_extents as _expected_extents
lazy from rebrew.verify_hash import expected_text_functions as _expected_functions

if TYPE_CHECKING:
    from rebrew.data_ownership import LinkSymbol

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  # Compare built .text VAs against metadata addresses\n"
    "  rebrew build check-text-placement\n\n"
    "  rebrew build check-text-placement --json  # Machine-readable mismatch list\n\n"
    "  # Report linked extents shorter than the reference rounding\n"
    "  rebrew build check-text-placement --rounding\n"
)


app = typer.Typer(
    help="Compare .text function VAs of the current build against metadata addresses.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def exported_symbol_vas(binary: Path) -> dict[str, int]:
    """``{name: VA}`` for the exported symbols of *binary* (LIEF).

    Tolerates non-PE files and missing export tables by returning an empty
    map — the caller reports every function MISSING instead of crashing.

    A parse *failure* is not that: it means the binary was never read, so the
    empty map would be a confident "every function is MISSING" verdict on a
    build this tool cannot see (a truncated output, a LIEF version that
    rejects the format).  It raises instead, and the caller exits on it.
    """
    import lief

    from rebrew.rename_ops import c_name_from_symbol

    try:
        pe = lief.PE.parse(str(binary))
    except Exception as exc:  # re-raised: the caller cannot audit what was never parsed
        raise ValueError(f"could not parse the built binary {binary}: {exc}") from exc
    if pe is None:
        return {}
    try:
        image_base = int(pe.optional_header.imagebase)
    except AttributeError, TypeError, ValueError:
        image_base = 0
    out: dict[str, int] = {}
    for func in getattr(pe, "exported_functions", []):
        name = getattr(func, "name", "")
        if name:
            out.setdefault(c_name_from_symbol(str(name)), image_base + int(func.address))
    return out


def map_function_vas(symbols: Iterable[LinkSymbol]) -> dict[str, int]:
    """C function names and linked VAs from the parsed MSVC map."""
    from rebrew.rename_ops import c_name_from_symbol

    actual: dict[str, int] = {}
    for symbol in symbols:
        if symbol.is_function:
            actual.setdefault(c_name_from_symbol(symbol.name), symbol.va)
    return actual


def collect_actual_vas(root: Path, binary: Path) -> dict[str, int]:
    """``{symbol: .text VA}`` from the sibling map, then objects or exports.

    A present map is authoritative even when it has no matching functions.
    The object fallback estimates placement by concatenating contributions;
    missing objects fall back to exports. Read failures remain errors.
    """
    from rebrew.data_layout import link_objects, obj_text_symbol_offsets

    text_base = built_text_va(binary)
    link_map = binary.with_suffix(".map")
    if link_map.is_file():
        from rebrew.data_ownership import parse_link_map

        return map_function_vas(
            parse_link_map(link_map.read_text(encoding="utf-8", errors="replace"))
        )

    try:
        objects = link_objects(root)
    except FileNotFoundError:
        return exported_symbol_vas(binary)
    here: dict[str, int] = {}
    tot = 0
    for obj in objects:
        tsize, syms = obj_text_symbol_offsets(obj)
        for sym, off in syms.items():
            # ``obj_text_symbol_offsets`` already returns the C name.
            # Stripping again turned ``_foo`` (from ``__foo``) into ``foo``.
            here.setdefault(sym, text_base + tot + off)
        tot += tsize
    return here


def correct_entries(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rows for functions the build already places at their expected VA.

    ``misplaced_list`` names what to fix; this is the complement a caller needs
    to know which rows can be edited without touching layout.
    """
    return [
        {"symbol": r["symbol"], "expected": r["expected"], "actual": r["actual"]}
        for r in rows
        if r["status"] == "OK"
    ]


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
        else:
            rows.append(
                {
                    "symbol": name,
                    "status": "OK" if act == exp else "MISPLACED",
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


def audit_rounding(expected: dict[str, tuple[int, int]], actual: dict[str, int]) -> dict[str, Any]:
    """Compare linked extents with reference sizes rounded up to 16 bytes.

    Only functions already at their expected VA are classified, because a
    misplaced function has no meaningful linked extent. Only shorter extents are
    reported: a linked body shorter than the reference extent makes every later
    function sit that many bytes early, while a longer extent usually means
    layout data between two functions. ``following_shifted`` counts later
    functions whose own offset equals the deviation, which is exactly the set a
    corrected extent would put back on its reference VA.
    """
    ordered = sorted(actual.items(), key=lambda kv: kv[1])
    extents: dict[str, int] = {}
    for i, (name, va) in enumerate(ordered):
        if i + 1 == len(ordered):
            continue  # no following symbol, so the extent is unknown
        extents[name] = ordered[i + 1][1] - va
    deviations: list[dict[str, Any]] = []
    for name, va in ordered:
        ref = expected.get(name)
        if ref is None:
            continue
        ref_va, ref_size = ref
        if va != ref_va:
            continue
        if name not in extents:
            continue
        padded = (ref_size + 15) & ~15
        deviation = extents[name] - padded
        if deviation >= 0:
            continue
        deviations.append(
            {
                "symbol": name,
                "expected": f"0x{ref_va:x}",
                "actual": f"0x{va:x}",
                "reference_size": ref_size,
                "reference_padded": padded,
                "linked_extent": extents[name],
                "deviation": deviation,
                "following_shifted": 0,
            }
        )
    for row in deviations:
        deviation = row["deviation"]
        actual_va = int(row["actual"], 16)
        row["following_shifted"] = sum(
            1
            for name, va in ordered
            if va > actual_va and name in expected and va - expected[name][0] == deviation
        )
    earliest = deviations[0] if deviations else None
    return {
        "deviations": deviations,
        "earliest": earliest,
        "following_shifted": earliest["following_shifted"] if earliest else 0,
    }


@app.callback(invoke_without_command=True)
def main(
    built: Path | None = typer.Option(
        None,
        "--built",
        help=BUILT_IMAGE_HELP,
    ),
    limit: int = typer.Option(15, "--limit", help="Max misplaced functions to print (0 = none)"),
    list_correct: bool = typer.Option(
        False,
        "--list-correct",
        help="Include the functions already at their expected VA in --json output",
    ),
    rounding: bool = typer.Option(
        False,
        "--rounding",
        help="Also report functions whose linked extent is shorter than the reference rounding",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Compare built .text function addresses with metadata; build the project first."""
    limit = require_non_negative(option_default(limit, 15), "--limit", json_mode=json_output)
    cfg = require_config(target=target, json_mode=json_output)
    root = Path(cfg.root)
    if built is None:
        built = Path("build") / cfg.target_name
    dll = built if built.is_absolute() else root / built
    if not dll.exists():
        error_exit(
            f"{dll} not found — build the project first (or pass --built <path>)",
            json_mode=json_output,
        )
    try:
        actual = collect_actual_vas(root, dll)
    except (RuntimeError, OSError, ValueError) as exc:
        error_exit(f"cannot read the build's .text layout: {exc}", json_mode=json_output)

    expected = _expected_functions(cfg)
    rows, n_ok, n_bad, n_missing = audit_text(expected, actual)
    shown = [r for r in rows if r["status"] != "OK"][:limit]
    rounding_report = audit_rounding(_expected_extents(cfg), actual) if rounding else None

    if json_output:
        payload: dict[str, Any] = {
            "functions": len(expected),
            "found": n_ok + n_bad,
            "correct": n_ok,
            "misplaced": n_bad,
            "missing": n_missing,
            "misplaced_list": shown,
        }
        if list_correct:
            payload["correct_list"] = correct_entries(rows)
        if rounding_report is not None:
            payload["rounding"] = rounding_report
        json_print(payload)
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
        if rounding_report is not None:
            deviations = rounding_report["deviations"]
            console.print(
                f"extent deviations: {len(deviations)}"
                + (
                    f", earliest {deviations[0]['symbol']} "
                    f"{deviations[0]['linked_extent']}B vs padded "
                    f"{deviations[0]['reference_padded']}B "
                    f"({deviations[0]['deviation']:+#x}); "
                    f"{rounding_report['following_shifted']} later functions share that offset"
                    if deviations
                    else ""
                )
            )
            for r in deviations[:limit]:
                console.print(
                    f"  {r['symbol']:32} extent {r['linked_extent']:5}B  "
                    f"padded {r['reference_padded']:5}B  d {r['deviation']:+#x}  "
                    f"later {r['following_shifted']}"
                )
    if n_bad or n_missing:
        raise typer.Exit(code=EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
