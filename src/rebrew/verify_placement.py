"""verify-placement — post-edit check: compare .data symbol VAs vs the metadata.

The linked ``.data`` section is the concatenation of per-TU contributions in
link order.  After editing sources, this command walks the link's object
files (objdump on each obj, in link order), computes every symbol's current
``.data`` VA, and compares it against the data metadata
(``src/rebrew-data.toml``).  Misplaced symbols mean the object order or a
TU's own layout drifted — the reccmp "0 aligned" symptom.

Usage:
    rebrew verify-placement [--data-metadata src/rebrew-data.toml] [--json]
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import error_exit, json_print
from rebrew.data_layout import built_data_va

console = Console(stderr=True)

app = typer.Typer(
    help="Compare .data symbol VAs of the current build against the data metadata.",
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def main(
    data_metadata: Path = typer.Option(
        Path("src/rebrew-data.toml"), "--data-metadata", help="Data metadata toml path"
    ),
    built: Path = typer.Option(
        Path("build/server.dll"),
        "--built",
        help="Built binary to inspect (default: build/server.dll)",
    ),
    limit: int = typer.Option(15, "--limit", help="Max misplaced symbols to print"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Build-then-compare: .data symbol VAs of the current build vs the metadata."""
    root = Path.cwd()
    metadata = data_metadata if data_metadata.is_absolute() else root / data_metadata
    if not metadata.exists():
        error_exit(f"data metadata not found: {metadata}")
    dll = built if built.is_absolute() else root / built
    if not dll.exists():
        error_exit(f"{dll} not found — build the project first (or pass --built <path>)")
    from rebrew.data_layout import data_symbols, link_objects, obj_data_symbol_offsets

    data_va = built_data_va(dll)
    expected = data_symbols(metadata)

    here: dict[str, int] = {}
    tot = 0
    try:
        for obj in link_objects(root):
            dsize, syms = obj_data_symbol_offsets(obj)
            for sym, off in syms.items():
                here.setdefault(sym, data_va + tot + off)
            tot += dsize
    except (RuntimeError, OSError) as exc:
        error_exit(f"cannot inventory build objects: {exc}")

    good = bad = 0
    bads: list[tuple[str, int, int]] = []
    for sym, addr in here.items():
        if sym in expected:
            if addr == expected[sym]:
                good += 1
            else:
                bad += 1
                bads.append((sym, expected[sym], addr))
    bads.sort(key=lambda t: -abs(t[1] - t[2]))

    if json_output:
        json_print(
            {
                "symbols": len(here),
                "matched": good + bad,
                "correct": good,
                "misplaced": bad,
                "misplaced_list": [
                    {"symbol": s, "expected": f"0x{e:x}", "actual": f"0x{a:x}", "delta": a - e}
                    for s, e, a in bads[:limit]
                ],
            }
        )
        return
    console.print(
        f"symbols: {len(here)}  toml-matched: {good + bad}  correct-VA: {good}  misplaced: {bad}"
    )
    for sym, exp, act in bads[:limit]:
        console.print(f"  {sym:32} exp {exp:#010x}  our {act:#010x}  d {act - exp:+#x}")


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
