"""lib-match — byte-compare reversed functions against linked static libraries.

Statically linked library code sits in the target's .text looking exactly like
game code, and a decompiler names it ``fcn_XXXX`` like anything else. Reversing
it is wasted effort: the linker supplies those bytes anyway. The existing
detectors do not settle it:

- ``rebrew flirt`` matches short byte signatures against prebuilt .pat files.
  A signature set built from a different library build misses real matches
  (measured: 9 of 68 CRT functions on one MSVC6 project), and short patterns
  cannot cover every function.
- ``rebrew crt-match`` compares against reference *source*, which exists only
  for the CRT/zlib families.

This command compares **whole function bodies** against the archives the
project actually links (.lib / .a), masking each object's relocation slots.
Whatever is identical outside those slots is library code. That is what a
linked-in object looks like, so the check has no false negatives from naming
or signature coverage.

Two details matter, both learned the hard way:

- MSVC marks CRT helpers such as ``_initterm`` and ``_parse_cmdline`` static
  (COFF storage class 3). They never appear in the archive symbol index, so an
  index built from external symbols alone reports them absent. The archive
  index here comes from ``gen_flirt_pat.parse_coff_obj``, which covers both
  classes.
- A body that is mostly relocation slots (a pointer table such as
  ``__sys_errlist``) "matches" anything once its slots are masked. Candidates
  must be at least half fixed bytes.

Usage::

    rebrew lib-match --lib LIBCMT.LIB                  # scan all reversed funcs
    rebrew lib-match --lib LIBCMT.LIB --va 0x1001a7f7  # one function
    rebrew lib-match --lib a.lib --lib b.lib --allow libcode_allowlist.txt

Exit status is 0 when nothing matches, 1 when a reversed function's bytes come
from one of the given libraries, 2 on config/library errors, so this works as
a pre-commit or CI gate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import (
    EXIT_ERROR,
    EXIT_MISMATCH,
    EXIT_OK,
    TargetOption,
    error_exit,
    json_print,
    require_config,
)
from rebrew.gen_flirt_pat import parse_archive, parse_coff_obj

console = Console(stderr=True)

MIN_BYTES = 8
MIN_FIXED_FRACTION = 0.5
PREFIX_BYTES = 32

Index = dict[str, list[tuple[str, bytes, set[int]]]]

app = typer.Typer(
    help=(
        "Byte-compare reversed functions against linked static libraries "
        "(.lib/.a). Flags code the linker supplies, so it is not worth reversing."
    ),
    rich_markup_mode="rich",
    no_args_is_help=True,
)


def index_library(path: Path) -> Index:
    """Index every code symbol in *path* by name -> [(object, body, relocs)]."""
    index: Index = {}
    try:
        members = parse_archive(str(path))
        for _member_name, obj in members:
            for sym, code, relocs in parse_coff_obj(obj):
                index.setdefault(sym, []).append((path.name, code, relocs))
    except Exception as exc:  # bad archive / unparsable member
        error_exit(f"cannot index {path}: {exc}", code=EXIT_ERROR)
    return index


def match_bytes(index: Index, data: bytes) -> tuple[str, str] | None:
    """Return ``(symbol, object)`` when *data* is a library body, else None."""
    if len(data) < MIN_BYTES:
        return None
    for sym, entries in index.items():
        for obj_name, body, relocs in entries:
            if len(body) < len(data):
                continue
            if len(data) - len(relocs) < MIN_FIXED_FRACTION * len(data):
                continue  # a mostly-relocation table trivially matches anything
            fixed = {i for i in range(len(data)) if i not in relocs}
            if all(data[i] == body[i] for i in fixed):
                return sym, obj_name
    return None


def _merge_libraries(libs: list[Path]) -> Index:
    """Index each library, merging duplicate symbol names across archives."""
    merged: Index = {}
    for p in libs:
        for sym, entries in index_library(p).items():
            merged.setdefault(sym, []).extend(entries)
    return merged


def load_allowlist(path: Path | None) -> set[int]:
    if path is None:
        return set()
    out: set[int] = set()
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.add(int(line, 16))
    return out


def _findings(cfg: Any, index: Index, allow: set[int]) -> list[dict[str, str]]:
    from rebrew.catalog.loaders import scan_reversed_dir

    found: list[dict[str, str]] = []
    for entry in scan_reversed_dir(cfg.reversed_dir, cfg=cfg):
        module = getattr(entry, "module", "") or ""
        va = int(getattr(entry, "va", 0) or 0)
        if not module or not va or va in allow:
            continue
        # A marker of GLOBAL/DATA is not a reversed function body.
        if getattr(entry, "marker_type", "FUNCTION") not in ("FUNCTION", "STUB"):
            continue
        try:
            data = extract_raw_bytes(cfg.target_binary, va, entry.size or PREFIX_BYTES)
        except Exception:
            continue
        hit = match_bytes(index, data)
        if hit is None and (entry.size or 0) > PREFIX_BYTES:
            # A wrong SIZE in the metadata overruns the function and hides a
            # real match; retry on a fixed prefix.
            try:
                hit = match_bytes(index, extract_raw_bytes(cfg.target_binary, va, PREFIX_BYTES))
            except Exception:
                hit = None
        if hit is not None:
            sym, obj_name = hit
            found.append(
                {
                    "va": f"0x{va:08x}",
                    "module": module,
                    "file": entry.filepath,
                    "symbol": sym,
                    "object": obj_name,
                }
            )
    return found


@app.callback(invoke_without_command=True)
def main(
    lib: list[Path] = typer.Option(
        ...,
        "--lib",
        help="Static library to check against (repeatable).",
    ),
    va: str | None = typer.Option(
        None, "--va", help="Check a single VA (hex) instead of every reversed function."
    ),
    allow: Path | None = typer.Option(
        None, "--allow", help="File of VAs known library code, one hex VA per line (# comments)."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Flag reversed functions whose bytes come from a linked library."""
    cfg = require_config(target=target, json_mode=json_output)
    if not lib:
        error_exit(
            "no --lib given. Point it at the archive(s) the target links, "
            "e.g. the toolchain's LIBCMT.LIB.",
            json_mode=json_output,
            code=EXIT_ERROR,
        )
    if va is not None:
        from rebrew.cli import parse_va
        from rebrew.metadata import get_entry

        va_int = parse_va(va)
        module = getattr(cfg, "marker", None) or "SERVER"
        size = (get_entry(cfg.metadata_dir, va_int, module) or {}).get("size") or 0
        index = _merge_libraries(lib)
        data = extract_raw_bytes(cfg.target_binary, va_int, size or PREFIX_BYTES)
        hit = match_bytes(index, data)
        if hit is None and (size or 0) > PREFIX_BYTES:
            hit = match_bytes(index, extract_raw_bytes(cfg.target_binary, va_int, PREFIX_BYTES))
        if hit is not None:
            sym, obj_name = hit
            if json_output:
                json_print(
                    {"va": f"0x{va_int:08x}", "library": True, "symbol": sym, "object": obj_name}
                )
            else:
                console.print(
                    f"[yellow]0x{va_int:08x} is library code:[/yellow] {sym} in {obj_name}"
                )
                console.print("Do not reverse it; the linker supplies these bytes.")
            raise typer.Exit(code=EXIT_MISMATCH)
        if json_output:
            json_print({"va": f"0x{va_int:08x}", "library": False})
        else:
            console.print(
                f"[green]0x{va_int:08x} is not in the given libraries.[/green] Safe to reverse."
            )
        raise typer.Exit(code=EXIT_OK)

    found = _findings(cfg, _merge_libraries(lib), load_allowlist(allow))
    if json_output:
        json_print({"findings": found, "count": len(found)})
    else:
        if not found:
            console.print("[green]No reversed function matches a linked library.[/green]")
        else:
            console.print("Reversed functions whose bytes come from a linked library:\n")
            for f in found:
                console.print(f"  [yellow]{f['va']}[/yellow]  {f['file']}")
                console.print(f"              {f['symbol']} in {f['object']}")
            console.print(
                f"\n{len(found)} function(s). These do not need reversing: the linker supplies "
                "them. Delete the source, or add the VA to the --allow file with a reason "
                "if the file must stay for link reasons."
            )
    raise typer.Exit(code=EXIT_MISMATCH if found else EXIT_OK)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
