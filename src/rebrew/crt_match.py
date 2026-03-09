"""CRT source cross-reference matcher.

Searches configured reference source directories (CRT, zlib, etc.) for
functions matching reversed binary functions. Uses name matching, function
extraction from C source, and known ASM-only function detection.

Usage:
    rebrew crt-match 0x10006c00              Match a single VA
    rebrew crt-match --all                   Match all LIBRARY-marker functions
    rebrew crt-match --fix-source            Auto-write // SOURCE: annotations
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.annotation import Annotation, parse_c_file_multi, update_annotation_key
from rebrew.cli import (
    TargetOption,
    error_exit,
    iter_sources,
    json_print,
    parse_va,
    require_config,
)
from rebrew.config import ProjectConfig
from rebrew.naming import normalize_name

console = Console(stderr=True)


@dataclass
class CrtSourceEntry:
    """A function found in a reference source file."""

    name: str
    file: str
    line: int
    is_asm: bool
    module: str


@dataclass
class CrtMatch:
    """A match between a binary function and reference source."""

    va: int
    binary_name: str
    binary_size: int
    source: CrtSourceEntry
    confidence: float
    reason: str
    is_asm_only: bool


# MSVC6 CRT functions implemented in hand-written ASM (from VC98/CRT/SRC/PLATFORM/).
# These CANNOT be matched from C source — they use x86 string/memory instructions.
_MSVC6_ASM_FUNCTIONS: set[str] = {
    # Memory operations
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "memchr",
    "memccpy",
    "_memicmp",
    "memicmp",
    # String operations
    "strlen",
    "strcat",
    "strchr",
    "strcmp",
    "_stricmp",
    "stricmp",
    "strncmp",
    "strncpy",
    "strncat",
    "_strnicmp",
    "strnicmp",
    "_strnset",
    "strnset",
    "strpbrk",
    "strrchr",
    "_strrev",
    "strrev",
    "_strset",
    "strset",
    "strspn",
    "strstr",
    "strcspn",
    # 64-bit integer helpers
    "__allmul",
    "__alldiv",
    "__allrem",
    "__allshl",
    "__allshr",
    "__aulldiv",
    "__aullrem",
    "__aullshr",
    # Compiler support
    "__chkstk",
    "_chkstk",
    "_alloca_probe",
    "_enable",
    "_disable",
    "_inp",
    "_inpw",
    "_inpd",
    "_outp",
    "_outpw",
    "_outpd",
}

_C_FUNCTION_RE = re.compile(
    r"^\s*(?:[\w\s\*]+?)\s+(?:__cdecl|__stdcall|__fastcall|WINAPI|_CRTIMP)?\s*\b(\w+)\s*\([^{]*?\)\s*(?:\{|$)",
    re.MULTILINE,
)
_ASM_PROC_RE = re.compile(r"^\s*_?(\w+)\s+PROC\b", re.MULTILINE)


def build_crt_index(source_dir: Path, module: str) -> list[CrtSourceEntry]:
    """Build an index of C and ASM functions from a reference source directory."""
    if not source_dir.exists() or not source_dir.is_dir():
        return []

    entries: list[CrtSourceEntry] = []

    for file_path in sorted(source_dir.rglob("*")):
        if not file_path.is_file():
            continue

        suffix = file_path.suffix.lower()
        if suffix not in {".c", ".cpp", ".asm"}:
            continue

        rel_file = str(file_path.relative_to(source_dir)).replace("\\", "/")

        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if suffix in {".c", ".cpp"}:
            for match in _C_FUNCTION_RE.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                entries.append(
                    CrtSourceEntry(
                        name=match.group(1),
                        file=rel_file,
                        line=line,
                        is_asm=False,
                        module=module,
                    )
                )

            stem_name = file_path.stem.lower()
            entries.append(
                CrtSourceEntry(
                    name=stem_name,
                    file=rel_file,
                    line=0,
                    is_asm=False,
                    module=module,
                )
            )
        else:
            for match in _ASM_PROC_RE.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                entries.append(
                    CrtSourceEntry(
                        name=match.group(1),
                        file=rel_file,
                        line=line,
                        is_asm=True,
                        module=module,
                    )
                )

    return entries


_ASM_FUNCTIONS_NORMALIZED = {normalize_name(name) for name in _MSVC6_ASM_FUNCTIONS}


def is_asm_only(name: str) -> bool:
    """Return True when a function is known to be ASM-only in MSVC6 CRT."""
    return normalize_name(name) in _ASM_FUNCTIONS_NORMALIZED


def _match_reason(base_reason: str, asm_only: bool) -> str:
    if asm_only:
        return f"{base_reason}; known ASM-only CRT function"
    return base_reason


def match_function(
    name: str, size: int, module: str, index: list[CrtSourceEntry], *, va: int = 0
) -> list[CrtMatch]:
    """Match a single binary function name against a source index."""
    binary_raw = name.strip().lower()
    binary_norm = normalize_name(name)
    asm_only = is_asm_only(name)

    matches: list[CrtMatch] = []
    for source_entry in index:
        if source_entry.module.upper() != module.upper():
            continue

        source_raw = source_entry.name.strip().lower()
        source_norm = normalize_name(source_entry.name)

        if source_raw == binary_raw:
            matches.append(
                CrtMatch(
                    va=va,
                    binary_name=name,
                    binary_size=size,
                    source=source_entry,
                    confidence=0.95,
                    reason=_match_reason("exact name match", asm_only),
                    is_asm_only=asm_only,
                )
            )
            continue

        if source_norm == binary_norm and source_entry.line != 0:
            matches.append(
                CrtMatch(
                    va=va,
                    binary_name=name,
                    binary_size=size,
                    source=source_entry,
                    confidence=0.90,
                    reason=_match_reason("normalized name match", asm_only),
                    is_asm_only=asm_only,
                )
            )
            continue

        if source_entry.line == 0 and source_norm == binary_norm:
            matches.append(
                CrtMatch(
                    va=va,
                    binary_name=name,
                    binary_size=size,
                    source=source_entry,
                    confidence=0.85,
                    reason=_match_reason("filename-based source match", asm_only),
                    is_asm_only=asm_only,
                )
            )

    return sorted(matches, key=lambda item: (item.confidence, item.source.line), reverse=True)


def _collect_library_annotations(
    cfg: ProjectConfig,
) -> list[tuple[Path, Annotation]]:
    """Collect LIBRARY-marker annotations from source files."""
    annotations: list[tuple[Path, Annotation]] = []
    library_modules = {m.upper() for m in getattr(cfg, "library_modules", [])}

    for source_path in iter_sources(cfg.reversed_dir, cfg):
        for ann in parse_c_file_multi(
            source_path, target_name=cfg.marker, sidecar_dir=source_path.parent
        ):
            module_upper = (ann.module or "").upper()
            if ann.marker_type != "LIBRARY" and module_upper not in library_modules:
                continue
            annotations.append((source_path, ann))

    return annotations


def _build_indexes(cfg: ProjectConfig) -> dict[str, list[CrtSourceEntry]]:
    indexes: dict[str, list[CrtSourceEntry]] = {}
    for module_name, rel_path in cfg.crt_sources.items():
        source_dir = Path(rel_path)
        if not source_dir.is_absolute():
            source_dir = cfg.root / source_dir
        indexes[module_name.upper()] = build_crt_index(source_dir, module_name.upper())
    return indexes


def match_all(cfg: ProjectConfig) -> list[CrtMatch]:
    """Match all LIBRARY-marker functions against configured CRT source indices."""
    indexes = _build_indexes(cfg)
    all_matches: list[CrtMatch] = []

    for _, ann in _collect_library_annotations(cfg):
        module_upper = (ann.module or "").upper()
        index = indexes.get(module_upper, [])
        if not index:
            continue

        binary_name = ann.symbol or ann.name
        if not binary_name:
            continue

        matches = match_function(binary_name, ann.size, module_upper, index, va=ann.va)
        all_matches.extend(matches)

    return all_matches


def _match_to_dict(match: CrtMatch) -> dict[str, Any]:
    return {
        "va": f"0x{match.va:08x}",
        "binary_name": match.binary_name,
        "binary_size": match.binary_size,
        "module": match.source.module,
        "source_file": match.source.file,
        "source_line": match.source.line,
        "source_is_asm": match.source.is_asm,
        "confidence": match.confidence,
        "reason": match.reason,
        "is_asm_only": match.is_asm_only,
    }


def _source_ref(entry: CrtSourceEntry) -> str:
    if entry.is_asm or entry.line <= 0:
        return entry.file
    return f"{entry.file}:{entry.line}"


def _render_index_table(entries: list[CrtSourceEntry]) -> None:
    table = Table(title="CRT Source Index")
    table.add_column("Module")
    table.add_column("Name")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("ASM", justify="center")

    for entry in entries:
        table.add_row(
            entry.module,
            entry.name,
            entry.file,
            str(entry.line),
            "yes" if entry.is_asm else "no",
        )

    console.print(table)


def _render_match_table(matches: list[CrtMatch]) -> None:
    table = Table(title="CRT Match Results")
    table.add_column("VA")
    table.add_column("Binary")
    table.add_column("Module")
    table.add_column("Source")
    table.add_column("Confidence", justify="right")
    table.add_column("Reason")

    for match in matches:
        src = _source_ref(match.source)
        table.add_row(
            f"0x{match.va:08x}",
            match.binary_name,
            match.source.module,
            src,
            f"{match.confidence:.2f}",
            match.reason,
        )

    console.print(table)


_EPILOG = """\
[bold]Examples:[/bold]

rebrew crt-match 0x10006c00                     Match a single VA

rebrew crt-match --all                          Match all LIBRARY-marker functions

rebrew crt-match --fix-source --all             Auto-write // SOURCE: annotations

rebrew crt-match --index                        Show CRT source index

rebrew crt-match --json                         JSON output
"""

app = typer.Typer(
    help="CRT source cross-reference matcher.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    va: str | None = typer.Argument(None, help="Virtual address to match (hex, e.g. 0x10006c00)"),
    all_funcs: bool = typer.Option(False, "--all", help="Match all LIBRARY-marker functions"),
    fix_source: bool = typer.Option(
        False,
        "--fix-source",
        help="Auto-write // SOURCE: annotations",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    index_only: bool = typer.Option(
        False, "--index", help="Show CRT source index without matching"
    ),
    target: str | None = TargetOption,
) -> None:
    """CRT source cross-reference matcher."""
    cfg = require_config(target=target, json_mode=json_output)

    if not cfg.crt_sources:
        error_exit(
            "No crt_sources configured. Add entries like "
            'crt_sources.MSVCRT = "tools/MSVC600/VC98/CRT/SRC" in rebrew-project.toml.',
            json_mode=json_output,
        )

    indexes = _build_indexes(cfg)
    flat_index = [entry for entries in indexes.values() for entry in entries]

    if index_only:
        if json_output:
            json_print(
                {
                    "count": len(flat_index),
                    "entries": [
                        {
                            "module": entry.module,
                            "name": entry.name,
                            "file": entry.file,
                            "line": entry.line,
                            "is_asm": entry.is_asm,
                        }
                        for entry in flat_index
                    ],
                }
            )
        else:
            _render_index_table(flat_index)
        return

    if va is None and not all_funcs:
        error_exit("Provide a VA or use --all", json_mode=json_output)

    annotation_map = {
        ann.va: (source_path, ann) for source_path, ann in _collect_library_annotations(cfg)
    }

    matches: list[CrtMatch] = []
    if va is not None:
        va_int = parse_va(va, json_mode=json_output)
        pair = annotation_map.get(va_int)
        if pair is None:
            error_exit(f"No library annotation found for VA 0x{va_int:08x}", json_mode=json_output)

        _, ann = pair
        function_name = ann.symbol or ann.name
        if not function_name:
            error_exit(f"Annotation at 0x{va_int:08x} has no symbol/name", json_mode=json_output)

        module_upper = (ann.module or "").upper()
        index = indexes.get(module_upper, [])
        if not index:
            error_exit(
                f"No CRT index configured for module '{ann.module}'",
                json_mode=json_output,
            )

        matches = match_function(function_name, ann.size, module_upper, index, va=va_int)

    if all_funcs:
        all_matches = match_all(cfg)
        seen_keys: set[tuple[int, str, float]] = {
            (m.va, m.source.file, m.confidence) for m in matches
        }
        for m in all_matches:
            key = (m.va, m.source.file, m.confidence)
            if key not in seen_keys:
                matches.append(m)
                seen_keys.add(key)

    if fix_source:
        updates = 0
        best_by_va: dict[int, CrtMatch] = {}
        for match in matches:
            best = best_by_va.get(match.va)
            if best is None or match.confidence > best.confidence:
                best_by_va[match.va] = match

        for match in sorted(best_by_va.values(), key=lambda m: m.va):
            if match.confidence < 0.85:
                continue
            pair = annotation_map.get(match.va)
            if pair is None:
                continue
            source_path, _ = pair
            if update_annotation_key(source_path, match.va, "SOURCE", _source_ref(match.source)):
                updates += 1

        if not json_output:
            typer.echo(f"Updated SOURCE annotations: {updates}", err=True)

    if json_output:
        json_print(
            {
                "match_count": len(matches),
                "matches": [_match_to_dict(match) for match in matches],
            }
        )
        return

    if not matches:
        typer.echo("No matches found.")
        return

    _render_match_table(matches)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
