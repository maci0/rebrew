"""strings.py — Extract printable strings from a binary, with cross-references.

Scans data-ish sections (``.rdata`` / ``.data`` / ``.rodata`` by default, or
an explicit ``--section`` list) for printable ASCII and UTF-16LE runs and
reports each with its VA, section, kind, and size.  With ``--xref`` the
referencing code addresses are resolved via :mod:`rebrew.analysis` (``push``
/ ``mov`` / ``lea`` immediates, absolute memory operands, IAT calls) — the
"which function uses this string" recon pass.

Architecture notes:

- One ``BinaryInfo`` load (lazy LIEF) serves extraction, filtering, and
  cross-references, so a run parses the binary exactly once.
- String and reference scanning live in :mod:`rebrew.analysis`; this module
  only selects sections, filters, formats, and prints.  Section defaults are
  mirrored here so the "nothing to scan" note can be detected locally.

Usage:
    rebrew strings [binary] [--min-len N] [--section NAME] [--filter RE] [--xref] [--json]
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from rebrew.analysis import Xref, iter_strings, string_refs
from rebrew.binary_loader import BinaryInfo, load_binary
from rebrew.cli import EXIT_ERROR, TargetOption, error_exit, json_print, require_config

console = Console(stderr=True)

# Data-ish sections scanned when --section is not given; mirrors the
# analysis.py default so the "nothing to scan" note can be detected here.
DEFAULT_SECTIONS = (".rdata", ".data", ".rodata")

#: Default minimum string length when ``--min-len`` is not given.
DEFAULT_MIN_LEN = 4

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _data_sections(info: BinaryInfo) -> list[str]:
    """Return the data-ish section names present in *info* (default scan set)."""
    return [name for name in DEFAULT_SECTIONS if name in info.sections]


def _format_xrefs(refs: list[dict[str, Any]]) -> str:
    """Format *refs* as ``count: first 3 addresses (+N more)`` for the table."""
    if not refs:
        return "0"
    shown = ", ".join(f"0x{x['from_va']:08x}" for x in refs[:3])
    extra = f" +{len(refs) - 3} more" if len(refs) > 3 else ""
    return f"{len(refs)}: {shown}{extra}"


def collect_strings(
    binary: Path,
    *,
    min_len: int = DEFAULT_MIN_LEN,
    section_names: list[str] | None = None,
    filter_regex: str | None = None,
    xref: bool = False,
    json_output: bool = False,
) -> dict[str, Any]:
    """Extract strings from *binary* and return the CLI's ``--json`` payload.

    Loads the binary once, scans *section_names* (or the data-ish default
    set), applies the case-insensitive *filter_regex*, and, with *xref*,
    resolves each string's referencing code addresses.  Returns
    ``{"binary", "count", "strings"}`` — the exact object ``rebrew strings
    --json`` prints, with one record per string (``va`` / ``section`` /
    ``kind`` / ``size`` / ``text`` / ``xrefs``).

    An empty result is valid; when *json_output* is false the matching
    "nothing to scan" note is printed to stderr, mirroring the CLI.

    Raises:
        OSError, ValueError, KeyError: The binary cannot be loaded.
        RuntimeError: String analysis failed (e.g. capstone unavailable).
        re.error: *filter_regex* is not a valid regular expression.
    """
    info = load_binary(binary)
    no_data_sections = section_names is None and not _data_sections(info)

    strings = iter_strings(info, min_len=min_len, section_names=section_names)
    refs: dict[int, list[Xref]] = {}
    if xref:
        refs = string_refs(info, strings)

    if filter_regex is not None:
        matcher = re.compile(filter_regex, re.IGNORECASE)
        strings = [s for s in strings if matcher.search(s.text)]

    if not strings and not json_output:
        if no_data_sections:
            console.print(
                f"[yellow]No data sections (.rdata/.data/.rodata) in {binary}; nothing to scan.[/]"
            )
        else:
            console.print(f"[yellow]No strings found in {binary}.[/]")

    return {
        "binary": str(binary),
        "count": len(strings),
        "strings": [
            {
                "va": s.va,
                "section": s.section,
                "kind": s.kind,
                "size": s.size,
                "text": s.text,
                "xrefs": [{"kind": x.kind, "from_va": x.from_va} for x in refs.get(s.va, [])],
            }
            for s in strings
        ],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Extract strings from a binary, optionally with cross-references.",
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def main(
    binary: Path | None = typer.Argument(None, help="Binary path (default: project target)"),
    min_len: int = typer.Option(DEFAULT_MIN_LEN, "--min-len", help="Minimum string length"),
    section: list[str] = typer.Option(
        None, "--section", help="Section to scan (repeatable; default .rdata/.data/.rodata)"
    ),
    filter_regex: str | None = typer.Option(
        None, "--filter", help="Case-insensitive regex filter on string text"
    ),
    xref: bool = typer.Option(False, "--xref", help="Show referencing code addresses"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Scan a binary for printable strings and, with --xref, their code references."""
    cfg: Any = None
    if binary is None:
        cfg = require_config(target=target, json_mode=json_output)
        binary = cfg.target_binary
        if not binary.exists():
            error_exit(f"target binary missing: {binary}", json_mode=json_output, code=2)
    if not binary.exists():
        error_exit(f"binary not found: {binary}", json_mode=json_output)

    try:
        payload = collect_strings(
            binary,
            min_len=min_len,
            section_names=section or None,
            filter_regex=filter_regex,
            xref=xref,
            json_output=json_output,
        )
    except re.error as exc:
        error_exit(f"invalid --filter regex: {exc}", json_mode=json_output, code=EXIT_ERROR)
    except (OSError, ValueError, KeyError) as exc:
        error_exit(f"cannot load binary: {exc}", json_mode=json_output, code=EXIT_ERROR)
    except RuntimeError as exc:
        # analysis.py surfaces a missing capstone as RuntimeError.
        error_exit(f"string analysis failed: {exc}", json_mode=json_output, code=EXIT_ERROR)

    if json_output:
        json_print(payload)
        return

    if payload["count"] == 0:
        return

    table = Table(title=f"Strings in {binary.name}", show_header=True, header_style="bold")
    table.add_column("VA", justify="right", style="cyan")
    table.add_column("Section")
    table.add_column("Kind")
    table.add_column("Size", justify="right")
    table.add_column("Text")
    if xref:
        table.add_column("Xrefs")
    for s in payload["strings"]:
        row = [f"0x{s['va']:08x}", s["section"], s["kind"], str(s["size"]), escape(s["text"])]
        if xref:
            row.append(_format_xrefs(s["xrefs"]))
        table.add_row(*row)
    console.print(table)


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
