"""objdiff-project — generate an objdiff project for GUI byte-diffing.

objdiff (https://github.com/encounter/objdiff) is the decomp-scene's diffing
GUI: it shows per-function byte diffs between a *target* object (from the
original binary) and a *base* object (compiled from current source), with
instruction-level rendering.  It fully supports x86/x86_64 COFF/ELF objects,
so rebrew's MSVC/gcc-pe targets fit natively.

This module provides two entry points:

- ``rebrew objdiff --out objdiff.json`` — synthesize one target COFF object
  per annotated source file (the functions' bytes from the reference binary
  at their original VAs, with the annotation symbols) and emit an objdiff
  project configuration with one unit per file.  Opening ``objdiff.json`` in
  the objdiff GUI shows the project's match state immediately.
- ``rebrew-objdiff-build <target> <base-object>`` — the ``custom_make``
  shim objdiff invokes to rebuild a base object: maps the object path back
  to its source file and compiles it with the project's per-file toolchain
  and flags (the same resolution ``rebrew test``/``verify`` use).

Target objects carry no relocations (the reference binary gives raw bytes);
objdiff diffs them byte-wise, which is exactly the rebrew matching model.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import TargetOption, error_exit, iter_annotations, require_config
from rebrew.sources import iter_sources, target_marker

console = Console(stderr=True)

app = typer.Typer(
    help="Generate an objdiff project (target objects + objdiff.json) for GUI diffing.",
    rich_markup_mode="rich",
)

# COFF constants (i386, little-endian).
_IMAGE_FILE_MACHINE_I386 = 0x014C
_IMAGE_SCN_CNT_CODE = 0x00000020
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SYM_CLASS_EXTERNAL = 2
_SECTION_CHARS = _IMAGE_SCN_CNT_CODE | _IMAGE_SCN_MEM_EXECUTE | _IMAGE_SCN_MEM_READ


def write_coff_object(
    path: Path,
    functions: list[tuple[str, int, bytes]],
    *,
    base_offset: int = 0,
    machine: int = _IMAGE_FILE_MACHINE_I386,
) -> None:
    """Write a minimal COFF object with one ``.text`` section.

    *functions* is ``(symbol_name, offset_in_section, bytes)`` — the caller
    places each function at its file-relative offset (usually
    ``va - min_va``) so symbol offsets mirror the original addresses.
    Relocations are omitted (target objects are raw-byte references).

    *machine* defaults to i386; pass another COFF machine constant when
    rebrew grows a non-x86 target (e.g. ``0x01C0`` ARM — the multi-arch
    path is a parameter, not a fork).
    """
    body = b""
    symbols: list[tuple[str, int]] = []  # (name, section offset)
    for name, offset, blob in functions:
        pad = offset - len(body)
        if pad > 0:
            body += b"\x00" * pad
        elif pad < 0:
            # Overlapping placements: clamp to the current end (keeps the
            # object valid; the symbol still points at the caller's offset).
            body += blob
            continue
        body += blob
        symbols.append((name, offset))

    # --- section header ---
    raw_offset = 20 + 40  # file header + one section header
    sec_name = b".text"
    sec_hdr = sec_name.ljust(8, b"\x00") + struct.pack(
        "<IIIIIIHHI", len(body), 0, len(body), raw_offset, 0, 0, 0, 0, _SECTION_CHARS
    )

    # --- symbol table ---
    sym_entries: list[bytes] = []
    long_names: list[bytes] = []

    def _name_field(name: str) -> bytes:
        raw = name.encode("utf-8", errors="replace")
        if len(raw) <= 8:
            return raw.ljust(8, b"\x00")
        long_names.append(raw + b"\x00")
        return struct.pack("<II", 0, 4 + sum(len(n) for n in long_names[:-1]))

    for name, offset in symbols:
        # COFF symbol: Name[8] Value(4) Section(2) Type(2) Class(1) Aux(1) = 18
        # bytes.  Type is a 2-byte field — packing it as 1 shifted every
        # subsequent symbol and corrupted the string-table offset.
        sym_entries.append(
            _name_field(name) + struct.pack("<IHHBB", offset, 1, 0x20, _IMAGE_SYM_CLASS_EXTERNAL, 0)
        )
    string_table = struct.pack("<I", 4 + sum(len(n) for n in long_names)) + b"".join(long_names)

    sym_offset = raw_offset + len(body)
    n_syms = len(sym_entries)
    file_hdr = struct.pack(
        "<HHIIIHH",
        machine,
        1,  # NumberOfSections
        0,  # TimeDateStamp
        sym_offset,
        n_syms,
        0,  # SizeOfOptionalHeader
        0,  # Characteristics (relocatable object)
    )
    path.write_bytes(file_hdr + sec_hdr + body + b"".join(sym_entries) + string_table)


def _synthesize_target_objects(cfg: Any, out_dir: Path) -> list[dict[str, Any]]:
    """Write one target COFF object per annotated source file.

    Returns the unit descriptors (name, target_path, base_path).
    """
    sources = list(iter_sources(cfg.reversed_dir, cfg))
    marker = target_marker(cfg)
    units: list[dict[str, Any]] = []
    out_dir.mkdir(parents=True, exist_ok=True)

    from rebrew.binary_loader import extract_raw_bytes

    for path, annos in iter_annotations(sources, target=marker, metadata_dir=cfg.metadata_dir):
        fns: list[tuple[str, int, bytes]] = []
        min_va: int | None = None
        for a in annos:
            if a.marker_type in ("GLOBAL", "DATA"):
                continue
            va = int(a.va)
            size = int(a.size or 0)
            if size <= 0:
                continue
            raw = extract_raw_bytes(cfg.target_binary, va, size)
            if not raw:
                continue
            fns.append((a.symbol or a.name or f"func_{va:08x}", va, raw))
            min_va = va if min_va is None else min(min_va, va)
        if not fns:
            continue
        # Place functions at their (va - min_va) offsets so the object's
        # address space mirrors the binary layout.
        placed = [(name, va - (min_va or va), raw) for name, va, raw in fns]
        file_rel = str(path.relative_to(cfg.reversed_dir))
        target_path = out_dir / f"{file_rel}.o"
        target_path.parent.mkdir(parents=True, exist_ok=True)
        write_coff_object(target_path, placed)
        base_path = Path("build/objdiff/current") / f"{file_rel}.o"
        units.append(
            {
                "name": file_rel,
                "target_path": str(target_path),
                "base_path": str(base_path),
            }
        )
    return units


def _build_one_object(cfg: Any, base_object: Path) -> None:
    """Compile the source file behind *base_object* and write the object.

    The object path is ``build/objdiff/current/<filepath>.o``; the source is
    ``<reversed_dir>/<filepath>``.  Compiles with the same per-file
    toolchain/flag resolution as ``rebrew test``/``verify``.
    """
    rel = base_object.as_posix()
    marker = "build/objdiff/current/"
    idx = rel.find(marker)
    if idx >= 0:
        # Strip the base dir whether the path arrived relative
        # ("build/objdiff/current/funcs/a.c.o") or absolute — objdiff
        # passes the configured base_path verbatim, which may be either.
        rel = rel[idx + len(marker) :]
    if not rel.endswith(".o"):
        error_exit(f"rebrew-objdiff-build: unexpected object path {base_object}")
    source_rel = rel[: -len(".o")]
    source = cfg.reversed_dir / source_rel
    if not source.exists():
        error_exit(f"rebrew-objdiff-build: no source file for {source_rel} ({source})")

    from rebrew.cli import resolve_compile_overrides
    from rebrew.compile import compile_to_obj

    toolchain, cflags = resolve_compile_overrides(cfg, source.parent, "", "", "")
    obj_path, err = compile_to_obj(
        cfg,
        source,
        cflags.split(),
        base_object.parent,
        obj_name=base_object.name,
        toolchain=toolchain,
        use_cache=False,
    )
    if obj_path is None:
        error_exit(f"rebrew-objdiff-build: compile failed: {err}")
    console.print(f"[green]Built {base_object}[/green]")


@app.callback(invoke_without_command=True)
def main(
    out: Path = typer.Option(Path("objdiff.json"), "--out", help="Output objdiff config path"),
    target_dir: Path = typer.Option(
        Path("build/objdiff/target"),
        "--target-dir",
        help="Where synthesized target objects are written",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Generate an objdiff project: target objects + objdiff.json."""
    cfg = require_config(target=target, json_mode=json_output)
    units = _synthesize_target_objects(cfg, target_dir)
    if not units:
        error_exit("no annotated functions found — nothing to diff", json_mode=json_output)

    doc: dict[str, Any] = {
        "min_version": "2.0.0",
        "custom_make": "rebrew-objdiff-build",
        "custom_args": [cfg.target_name],
        "build_base": True,
        "units": units,
        "watch_patterns": ["src/**/*.c", "src/**/*.h"],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    if json_output:
        from rebrew.cli import json_print

        json_print({"out": str(out), "units": len(units)})
        return
    console.print(f"[green]Wrote objdiff project: {out}[/green]")
    console.print(
        f"  [dim]{len(units)} unit(s), {len(units)} target object(s) in {target_dir}[/dim]"
    )
    console.print(
        "[dim]Open objdiff.json in the objdiff GUI; it rebuilds base objects "
        "via `rebrew-objdiff-build` on demand.[/dim]"
    )


def objdiff_build_entry() -> None:
    """Console-script entry for the objdiff custom_make shim.

    argv: ``rebrew-objdiff-build <target> <base-object>``
    """
    if len(sys.argv) < 3:
        error_exit("usage: rebrew-objdiff-build <target> <base-object>")
    target_name = sys.argv[1]
    base_object = Path(sys.argv[2])
    cfg = require_config(target=target_name)
    _build_one_object(cfg, base_object)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
