"""solutions_db.py — query the GA solutions database and run history.

``rebrew solutions`` lists the winning fingerprints (``.rebrew/solutions.json``)
and, with ``--best``, the best-known GA outcome per function from the
append-only run history (``.rebrew/ga_runs.jsonl``).  Read-only.
"""

from __future__ import annotations

from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import TargetOption, json_print, require_config

console = Console(stderr=True)

app = typer.Typer(
    help="Query the GA solutions database (winning fingerprints + run history).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew solutions · · · · · · · · · · · · · · List winning solutions\n\n"
        "  rebrew solutions --symbol malloc · · · · · · Filter by symbol\n\n"
        "  rebrew solutions --best --json · · · · · · · Best GA score per function\n\n"
        "[dim]Reads .rebrew/solutions.json and .rebrew/ga_runs.jsonl.[/dim]"
    ),
)


def _collect_solutions(cfg: Any) -> list[dict[str, Any]]:
    """List winning solution fingerprints."""
    from rebrew.matcher import load_solutions

    out: list[dict[str, Any]] = []
    for e in load_solutions(cfg.root):
        out.append(
            {
                "target": e.target,
                "symbol": e.symbol,
                "size": e.size,
                "cflags": e.cflags,
                "score": e.score,
                "solved_at": e.solved_at,
                "generations": e.generations,
                "source_file": e.source_file,
            }
        )
    return out


def _collect_best(cfg: Any) -> list[dict[str, Any]]:
    """Best-known GA outcome per function (latest score wins on ties)."""
    from rebrew.matcher import load_ga_runs

    best: dict[tuple[str, str], dict[str, Any]] = {}
    for rec in load_ga_runs(cfg.root, limit=100000):
        key = (str(rec.get("target", "")), str(rec.get("va", "")))
        cur = best.get(key)
        score = rec.get("score")
        if cur is None or (
            score is not None and (cur.get("score") is None or score < cur["score"])
        ):
            best[key] = dict(rec)
    return [best[k] for k in sorted(best)]


@app.callback(invoke_without_command=True)
def main(
    symbol: str | None = typer.Option(
        None, "--symbol", help="Only list solutions whose symbol contains this substring"
    ),
    min_size: int = typer.Option(0, "--min-size", help="Minimum function size"),
    max_size: int = typer.Option(0, "--max-size", help="Maximum function size (0 = no cap)"),
    best: bool = typer.Option(
        False, "--best", help="Show best-known GA score per function (run history)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Query the GA solutions database."""
    cfg = require_config(target=target, json_mode=json_output)

    if best:
        rows = _collect_best(cfg)
    else:
        rows = _collect_solutions(cfg)
        if symbol:
            needle = symbol.lower()
            rows = [r for r in rows if needle in r["symbol"].lower()]
        if min_size > 0:
            rows = [r for r in rows if r["size"] >= min_size]
        if max_size > 0:
            rows = [r for r in rows if r["size"] <= max_size]

    if json_output:
        json_print({"count": len(rows), "best": best, "rows": rows})
        return

    if not rows:
        console.print("[dim]No solutions found.[/dim]")
        return

    table = Table(
        title="Best GA outcome per function" if best else "Winning solutions",
        box=None,
    )
    if best:
        table.add_column("Target")
        table.add_column("VA")
        table.add_column("Symbol")
        table.add_column("Matched")
        table.add_column("Score", justify="right")
        table.add_column("When")
        for r in rows:
            table.add_row(
                r.get("target", ""),
                str(r.get("va", "")),
                str(r.get("symbol", "")),
                "yes" if r.get("matched") else "no",
                f"{r.get('score', '')}" if r.get("score") is not None else "-",
                str(r.get("ts", ""))[:16],
            )
    else:
        table.add_column("Target")
        table.add_column("Symbol")
        table.add_column("Size", justify="right")
        table.add_column("CFLAGS")
        table.add_column("Score", justify="right")
        table.add_column("Solved")
        for r in rows:
            table.add_row(
                r["target"] or "-",
                r["symbol"],
                str(r["size"]),
                r["cflags"],
                f"{r['score']:.2f}" if r["score"] else "-",
                r["solved_at"][:16],
            )
    console.print(table)
    console.print(f"[dim]{len(rows)} entr{'y' if len(rows) == 1 else 'ies'}[/dim]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
