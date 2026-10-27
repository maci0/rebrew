"""Look up address-keyed findings in a project's documents without changing them."""

import re
lazy from pathlib import Path
lazy from typing import Any

import typer

from rebrew.cli import RootOption, console, error_exit, json_print, parse_va, require_root

app = typer.Typer(
    help="Find prior documented findings mentioning a native address or address range.",
    context_settings={"allow_interspersed_args": True},
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source findings 0x10009838 --window 64 --json\n\n"
        "  rebrew source findings 0x100093a0 0x10009936 --context 2\n\n"
        "  rebrew source findings 0x10001000 --doc goal.md\n\n"
        "Document mentions are evidence pointers, not verified native bindings."
    ),
)

_ADDRESS = re.compile(r"\b0x([0-9a-f]{1,16})\b", re.IGNORECASE)
_HEADING = re.compile(r"^#{1,6}\s+(.+)$")


def find_documented_addresses(
    root: Path,
    addresses: list[int],
    *,
    window: int = 0,
    documents: list[Path] | None = None,
    context: int = 0,
) -> list[dict[str, Any]]:
    """Return line/heading citations for hexadecimal mentions in the requested span.

    Defaults to Markdown under the project's docs directory. Explicit paths
    resolve against the project root. Every mention in the inclusive span is
    returned; the selected target does not establish a document's ownership.
    """
    if not addresses or any(va < 0 for va in addresses):
        raise ValueError("give at least one non-negative address")
    if window < 0 or context < 0:
        raise ValueError("window and context must be non-negative")
    lo, hi = min(addresses) - window, max(addresses) + window
    paths = documents if documents is not None else sorted((root / "docs").rglob("*.md"))
    hits: list[dict[str, Any]] = []
    for document in dict.fromkeys(paths):
        path = document if document.is_absolute() else root / document
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        try:
            display = path.relative_to(root).as_posix()
        except ValueError:
            display = str(path)
        heading = "(no heading)"
        for index, line in enumerate(lines):
            if match := _HEADING.match(line):
                heading = match.group(1).strip()
            found = sorted(
                {int(m[1], 16) for m in _ADDRESS.finditer(line) if lo <= int(m[1], 16) <= hi}
            )
            if not found:
                continue
            hit: dict[str, Any] = {
                "doc": display,
                "line": index + 1,
                "va": [f"0x{va:x}" for va in found],
                "section": heading,
                "text": line.strip(),
            }
            if context:
                hit["context"] = [
                    {"line": i + 1, "text": lines[i]}
                    for i in range(max(0, index - context), min(len(lines), index + context + 1))
                ]
            hits.append(hit)
    return hits


@app.callback(invoke_without_command=True)
def main(
    addresses: list[str] = typer.Argument(..., help="Native address, or the endpoints of a range"),
    window: int = typer.Option(0, min=0, help="Widen the address span by this many bytes"),
    context: int = typer.Option(0, min=0, help="Include this many surrounding document lines"),
    documents: list[Path] | None = typer.Option(
        None, "--doc", help="Document to search (repeatable; default: docs/**/*.md)"
    ),
    root: Path | None = RootOption,
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Find prior findings before repeating a native-address experiment."""
    root = require_root(root, json_mode=json_output)
    vas = [parse_va(value, json_mode=json_output) for value in addresses]
    try:
        hits = find_documented_addresses(
            root, vas, window=window, documents=documents, context=context
        )
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print({"vas": [f"0x{va:x}" for va in vas], "window": window, "hits": hits})
        return
    console.print(f"{len(hits)} documented mention(s)", markup=False)
    for hit in hits:
        console.print(f"{hit['doc']}:{hit['line']} [{hit['section']}]", markup=False)
        for line in hit.get("context", [{"line": hit["line"], "text": hit["text"]}]):
            console.print(f"  {line['line']}: {line['text']}", markup=False)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
