"""describe.py - Per-function recon dossier (callers, callees, strings, globals, imports).

Builds a one-screen intelligence summary for a single target function by
merging source annotations with whole-binary cross-references:

* Identity - name/status/size/cflags from source annotations (metadata-merged),
  falling back to ``fcn_%08x`` / "unknown" for unannotated functions.
* Callers  - direct ``call``/``jmp`` sites targeting the function.
* Callees  - direct calls plus IAT calls/jumps inside the function body,
  resolved to source names / import names.
* Strings  - printable runs referenced from inside the function.
* Globals  - absolute data references (reads/writes/address-takes) leaving .text.
* Imports  - IAT slots referenced from inside the function.

Every section is best-effort: a failure in one analysis step degrades that
section to empty rather than aborting the whole command.

Usage:
    rebrew describe 0x401000
    rebrew describe 0x401000 --json
"""

from __future__ import annotations

from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rebrew.analysis import (
    StringEntry,
    Xref,
    is_inside,
    iter_instructions,
    iter_strings,
    scan_references,
    section_range,
    string_refs,
)
from rebrew.annotation import Annotation, parse_c_file_multi
from rebrew.binary_loader import BinaryInfo, load_binary
from rebrew.catalog.loaders import parse_function_list
from rebrew.cli import (
    TargetOption,
    error_exit,
    iter_sources,
    json_print,
    parse_va,
    require_config,
    target_marker,
)
from rebrew.config import ProjectConfig
from rebrew.imports import parse_import_table

console = Console(stderr=True)

# Xref kinds that count as a caller of the probe function.
_CALLER_KINDS = frozenset({"call", "jmp"})

# Xref kinds that go through an IAT slot (``call [slot]`` / ``jmp [slot]``).
_IAT_KINDS = frozenset({"iat_call", "iat_jmp"})

# Cap for the fallback disassembly window when the function size is unknown.
_MAX_FALLBACK_SIZE = 4096

# Keys of the JSON contract.  ``blocker``/``note`` are terminal-only.
_JSON_KEYS = (
    "va",
    "name",
    "status",
    "size",
    "cflags",
    "callers",
    "callees",
    "strings",
    "globals",
    "imports",
)

# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


def _collect_annotations(cfg: ProjectConfig) -> list[Annotation]:
    """Parse every function annotation under ``cfg.reversed_dir``."""
    annos: list[Annotation] = []
    for cfile in iter_sources(cfg.reversed_dir, cfg):
        try:
            annos.extend(
                parse_c_file_multi(
                    cfile,
                    target_name=target_marker(cfg),
                    metadata_dir=cfg.metadata_dir,
                )
            )
        except (OSError, KeyError, ValueError, TypeError):
            continue
    return annos


def _build_lookup(
    cfg: ProjectConfig,
) -> tuple[dict[int, Annotation], dict[int, str], list[tuple[int, int, str]]]:
    """Build VA lookups from source annotations and the function list.

    Returns:
        annotations: VA -> Annotation, for the probe function's own metadata.
        names: VA -> display name for every known function.
        ranges: sorted ``(start, end, name)`` tuples for resolving which known
            function contains an arbitrary address (e.g. a call site).
    """
    annotations: dict[int, Annotation] = {}
    names: dict[int, str] = {}
    ranges: list[tuple[int, int, str]] = []
    for ann in _collect_annotations(cfg):
        annotations[ann.va] = ann
        name = ann.name or (ann.symbol or "").lstrip("_")
        if name:
            names[ann.va] = name
            if ann.size > 0:
                ranges.append((ann.va, ann.va + ann.size, name))
    try:
        for f in parse_function_list(cfg.function_list):
            va = int(f["va"])
            size = int(f["size"])
            name = str(f["name"])
            names.setdefault(va, name)
            if size > 0:
                ranges.append((va, va + size, name))
    except (OSError, ValueError, KeyError):
        pass
    ranges.sort(key=lambda r: r[0])
    return annotations, names, ranges


def _containing_name(va: int, names: dict[int, str], ranges: list[tuple[int, int, str]]) -> str:
    """Resolve *va* to a function name, falling back to ``fcn_%08x``.

    An exact function-start match wins; otherwise the smallest known function
    range containing *va* is used so a call site inside a function body reports
    its enclosing function.
    """
    name = names.get(va)
    if name:
        return name
    for start, end, candidate in ranges:
        if start <= va < end:
            return candidate
    return f"fcn_{va:08x}"


# ---------------------------------------------------------------------------
# Dossier sections
# ---------------------------------------------------------------------------


def _function_range(info: BinaryInfo, va: int, size: int | None) -> tuple[int, int]:
    """Return ``(start, end)`` covering the function body at *va*.

    Uses the annotated size when known; otherwise disassembles forward from
    *va* until the first ``ret`` (capped at ``_MAX_FALLBACK_SIZE`` bytes).
    """
    if size and size > 0:
        return va, va + size
    end = va
    try:
        for insn in iter_instructions(info, va, _MAX_FALLBACK_SIZE):
            end = insn.va + insn.size
            if insn.mnemonic == "ret":
                break
    except Exception:  # noqa: BLE001 — best-effort fallback sizing
        pass
    return va, end


def _dossier_strings(info: BinaryInfo) -> list[StringEntry]:
    """Printable strings from data sections, falling back to .text.

    ``analysis.iter_strings`` skips .text by default because embedded
    immediates are noise; binaries with no data sections (e.g. single-section
    test PEs) would otherwise report zero strings.  .text is scanned only
    when the data-ish sections produced nothing.
    """
    strings = iter_strings(info, min_len=4)
    if not strings and section_range(info, ".text") is not None:
        strings = iter_strings(info, min_len=4, section_names=[".text"])
    return strings


def _import_table(cfg: ProjectConfig) -> dict[int, str]:
    """Return ``{iat_slot_va: api_name}`` for the target binary (best-effort)."""
    try:
        return parse_import_table(cfg.target_binary)
    except Exception:  # noqa: BLE001 — import parsing is best-effort
        return {}


def _safe_section(compute: Any, default: Any) -> Any:
    """Run a dossier section computation, degrading to *default* on failure."""
    try:
        return compute()
    except Exception:  # noqa: BLE001 — a failing section must not kill the dossier
        return default


def _compute_callers(
    refs: list[Xref],
    va: int,
    names: dict[int, str],
    ranges: list[tuple[int, int, str]],
) -> list[dict[str, Any]]:
    """Direct call/jmp sites targeting *va*."""
    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for xref in refs:
        if xref.kind not in _CALLER_KINDS or xref.to_va != va or xref.from_va in seen:
            continue
        seen.add(xref.from_va)
        out.append({"from_va": xref.from_va, "name": _containing_name(xref.from_va, names, ranges)})
    out.sort(key=lambda c: c["from_va"])
    return out


def _compute_callees(
    refs: list[Xref],
    start: int,
    end: int,
    names: dict[int, str],
    import_table: dict[int, str],
) -> list[dict[str, Any]]:
    """Direct calls and IAT calls/jumps inside the function range."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for xref in refs:
        if not (start <= xref.from_va < end):
            continue
        if xref.kind not in _CALLER_KINDS and xref.kind not in _IAT_KINDS:
            continue
        key = (xref.to_va, xref.kind)
        if key in seen:
            continue
        seen.add(key)
        name = import_table.get(xref.to_va) if xref.kind in _IAT_KINDS else names.get(xref.to_va)
        out.append({"to_va": xref.to_va, "name": name, "kind": xref.kind})
    out.sort(key=lambda c: (c["to_va"], c["kind"]))
    return out


def _compute_strings(info: BinaryInfo, start: int, end: int) -> list[dict[str, Any]]:
    """Strings referenced from inside the function range."""
    strings = _dossier_strings(info)
    refs = string_refs(info, strings)
    out: list[dict[str, Any]] = []
    for s in sorted(strings, key=lambda s: s.va):
        if any(start <= r.from_va < end for r in refs.get(s.va, [])):
            out.append({"va": s.va, "text": s.text})
    return out


def _compute_globals(
    info: BinaryInfo, refs: list[Xref], start: int, end: int
) -> list[dict[str, Any]]:
    """Absolute data references (to non-.text addresses) inside the range."""
    text = section_range(info, ".text")
    out: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for xref in refs:
        if not (start <= xref.from_va < end):
            continue
        if xref.kind in _CALLER_KINDS or xref.kind in _IAT_KINDS:
            continue
        if text is not None and text[0] <= xref.to_va < text[0] + text[1]:
            continue
        key = (xref.to_va, xref.kind)
        if key in seen:
            continue
        seen.add(key)
        out.append({"va": xref.to_va, "kind": xref.kind})
    out.sort(key=lambda g: (g["va"], g["kind"]))
    return out


def _compute_imports(
    refs: list[Xref], start: int, end: int, import_table: dict[int, str]
) -> list[dict[str, Any]]:
    """IAT slots referenced from inside the function range."""
    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for xref in refs:
        if not (start <= xref.from_va < end):
            continue
        if xref.kind not in _IAT_KINDS:
            continue
        name = import_table.get(xref.to_va)
        if name is None or xref.to_va in seen:
            continue
        seen.add(xref.to_va)
        out.append({"slot": xref.to_va, "name": name})
    out.sort(key=lambda i: i["slot"])
    return out


def build_dossier(cfg: ProjectConfig, info: BinaryInfo, va: int) -> dict[str, Any]:
    """Compute the recon dossier for the function at *va*.

    Returns the dossier dict: the JSON contract keys plus terminal-only
    ``blocker``/``note`` entries (``_JSON_KEYS`` names the JSON subset).
    """
    try:
        annotations, names, ranges = _build_lookup(cfg)
    except Exception:  # noqa: BLE001 — lookup failures degrade to empty lookups
        annotations, names, ranges = {}, {}, []
    ann = annotations.get(va)
    if ann is None:
        name = f"fcn_{va:08x}"
        size: int | None = None
        status: str | None = None
        cflags: str | None = None
        blocker: str | None = None
        note: str | None = None
    else:
        name = ann.name or f"fcn_{va:08x}"
        size = ann.size if ann.size > 0 else None
        status = ann.status or None
        cflags = ann.cflags or None
        blocker = ann.blocker or None
        note = ann.note or None
    start, end = _function_range(info, va, size)

    all_refs = _safe_section(lambda: scan_references(info), [])
    import_table = _import_table(cfg)

    return {
        "va": va,
        "name": name,
        "status": status,
        "size": size,
        "cflags": cflags,
        "blocker": blocker,
        "note": note,
        "callers": _safe_section(lambda: _compute_callers(all_refs, va, names, ranges), []),
        "callees": _safe_section(
            lambda: _compute_callees(all_refs, start, end, names, import_table), []
        ),
        "strings": _safe_section(lambda: _compute_strings(info, start, end), []),
        "globals": _safe_section(lambda: _compute_globals(info, all_refs, start, end), []),
        "imports": _safe_section(lambda: _compute_imports(all_refs, start, end, import_table), []),
    }


# ---------------------------------------------------------------------------
# Terminal rendering
# ---------------------------------------------------------------------------


def _print_section(title: str, columns: tuple[str, ...], rows: list[tuple[Any, ...]]) -> None:
    """Print one dossier section as a rich table (or a dim "none" line)."""
    if not rows:
        console.print(f"[dim]{title}: none[/]")
        return
    table = Table(title=title, show_header=True, header_style="bold")
    for column in columns:
        table.add_column(column)
    for row in rows:
        table.add_row(*(str(cell) for cell in row))
    console.print(table)


def _print_terminal(dossier: dict[str, Any]) -> None:
    """Render the dossier as rich panel/tables on stderr."""
    va = int(dossier["va"])
    identity = [
        f"  VA:     [cyan]0x{va:08x}[/]",
        f"  Name:   [bold]{dossier['name']}[/]",
    ]
    if dossier.get("status"):
        identity.append(f"  Status: {dossier['status']}")
    if dossier.get("size") is not None:
        identity.append(f"  Size:   {dossier['size']} bytes")
    else:
        identity.append("  Size:   [dim]unknown[/]")
    if dossier.get("cflags"):
        identity.append(f"  CFLAGS: {dossier['cflags']}")
    if dossier.get("blocker"):
        identity.append(f"  BLOCKER: {dossier['blocker']}")
    if dossier.get("note"):
        identity.append(f"  NOTE:   {dossier['note']}")
    console.print(Panel("\n".join(identity), title="Function", border_style="cyan"))
    console.print()

    callers = [(f"0x{c['from_va']:08x}", c["name"]) for c in dossier["callers"]]
    _print_section("Callers", ("from", "name"), callers)
    callees = [(f"0x{c['to_va']:08x}", c["name"] or "-", c["kind"]) for c in dossier["callees"]]
    _print_section("Callees", ("target", "name", "kind"), callees)
    strings = [(f"0x{s['va']:08x}", s["text"]) for s in dossier["strings"]]
    _print_section("Strings", ("va", "text"), strings)
    globals_rows = [(f"0x{g['va']:08x}", g["kind"]) for g in dossier["globals"]]
    _print_section("Globals", ("va", "kind"), globals_rows)
    imports = [(f"0x{i['slot']:08x}", i["name"]) for i in dossier["imports"]]
    _print_section("Imports", ("slot", "name"), imports)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew describe 0x401000 · · · · · · Recon dossier for one function\n\n"
    "  rebrew describe 0x401000 --json · · Machine-readable dossier\n\n"
    "[dim]Scans the target binary for cross-references and merges source "
    "annotations to build the dossier.[/dim]"
)

app = typer.Typer(
    help="Per-function recon dossier: callers, callees, strings, globals, imports.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    va: str = typer.Argument(..., help="Function address (hex or int)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Build a per-function recon dossier (callers, callees, strings, globals, imports)."""
    cfg = require_config(target=target, json_mode=json_output)
    bin_path = cfg.target_binary
    if not bin_path.exists():
        error_exit(f"Binary not found at {bin_path}", json_mode=json_output)
    va_int = parse_va(va, json_mode=json_output)
    try:
        info = load_binary(bin_path)
    except Exception as exc:  # noqa: BLE001 — LIEF parse errors are fatal here
        error_exit(f"Failed to load binary: {exc}", json_mode=json_output)
    if not is_inside(info, va_int):
        error_exit(f"VA 0x{va_int:08x} is outside the binary image", json_mode=json_output)
    dossier = build_dossier(cfg, info, va_int)
    if json_output:
        json_print({key: dossier[key] for key in _JSON_KEYS})
        return
    _print_terminal(dossier)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
