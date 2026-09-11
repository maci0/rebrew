"""layout_map.py — reference-side binary measurement dump.

The byte-identity build reads the reference binary through ``gen-layout``
(scaffolding) and ``postlink`` (fixers), but nothing dumps the reference's
own measurable layout in one place.  This command emits that manifest:
section-table geometry, the ``.text`` function-start alignment histogram,
inter-function gap classes, ``.reloc`` HIGHLOW density per 4K page, IAT slot
order, export rows, the Rich-header toolchain guess, and the linker version
plus key header flags.

Output is JSON (default) or a human summary.  ``--output DIR`` additionally
writes the committed text-map files (``sections.txt``, ``gaps.txt``,
``iat.txt``, ``exports.txt``) under ``DIR`` — conventionally
``layout/<target>/text-map/`` — mirroring the ``gen-layout`` package style
(``#`` comment headers, hex values, never hand-edited).

Usage::

    rebrew layout-map --target game.dll
    rebrew layout-map --target game.dll --output layout/game.dll/text-map/
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import lief
import typer
from rich.console import Console
from rich.table import Table

from rebrew.binary_loader import BinaryInfo, extract_bytes_at_va, load_binary
from rebrew.catalog.loaders import parse_function_list
from rebrew.catalog.registry import RegistryEntry, build_function_registry
from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig
from rebrew.cu_map import _classify_gap
from rebrew.toolchain_detect import detect_toolchain
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

app = typer.Typer(
    help="Dump reference-side layout measurements (sections, gaps, IAT, exports).",
    rich_markup_mode="rich",
)

#: JSON manifest type.
Manifest = dict[str, Any]

#: Gap classes, in stable histogram order (cu_map's four plus the degenerate cases).
_GAP_CLASSES: tuple[str, ...] = (
    "padding",
    "jump_table",
    "small_nonpadding",
    "large_nonpadding",
    "overlap",
    "adjacent",
)

#: IMAGE_REL_BASED_HIGHLOW — the only relocation type the linker emits for
#: absolute 32-bit addresses in a 32-bit PE.
_RELOC_HIGHLOW = 3


# ---------------------------------------------------------------------------
# Binary access
# ---------------------------------------------------------------------------


def _lief_pe(path: Path) -> lief.PE.Binary | None:
    """The LIEF PE object for *path*, or ``None`` for non-PE binaries."""
    try:
        parsed = lief.parse(str(path))
    except Exception:
        return None
    if isinstance(parsed, lief.PE.Binary):
        return parsed
    return None


def _lief_str(raw: str | bytes | None) -> str | None:
    """A LIEF name (``str`` or ``bytes``) as ``str``, or ``None`` when empty."""
    if raw is None:
        return None
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
    return text or None


# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------


def _section_rows(info: BinaryInfo, pe: lief.PE.Binary | None) -> list[dict[str, Any]]:
    """Section geometry rows; characteristics come from the LIEF parse."""
    chars: dict[str, int] = {}
    if pe is not None:
        for sec in pe.sections:
            chars[(_lief_str(sec.name) or "").rstrip("\x00")] = int(sec.characteristics)
    return [
        {
            "name": name,
            "va": sec.va,
            "virtual_size": sec.size,
            "raw_size": sec.raw_size,
            "file_offset": sec.file_offset,
            "characteristics": chars.get(name, 0),
        }
        for name, sec in info.sections.items()
    ]


def _catalog_vas(cfg: ProjectConfig) -> dict[int, RegistryEntry]:
    """Function VAs from the catalog registry (list + Ghidra + exports)."""
    funcs: list[dict[str, Any]] = []
    if cfg.function_list and Path(cfg.function_list).exists():
        funcs = parse_function_list(Path(cfg.function_list))
    reversed_dir = cfg.reversed_dir
    ghidra_path = reversed_dir / FUNCTION_STRUCTURE_JSON if reversed_dir else None
    return build_function_registry(funcs, cfg, ghidra_path=ghidra_path, bin_path=cfg.target_binary)


def _text_functions(registry: dict[int, RegistryEntry], info: BinaryInfo) -> list[tuple[int, int]]:
    """``(va, canonical_size)`` for registry functions inside ``.text``."""
    lo = info.text_va
    hi = info.text_va + info.text_size if info.text_size > 0 else (1 << 64) - 1
    out: list[tuple[int, int]] = []
    for va in sorted(registry):
        if not lo <= va < hi:
            continue
        entry = registry[va]
        if entry.get("is_thunk"):
            continue
        out.append((va, int(entry.get("canonical_size", 0))))
    return out


def _alignment_histogram(vas: list[int]) -> dict[int, int]:
    """Count of function-start VAs per ``va % 16`` bucket."""
    hist = dict.fromkeys(range(16), 0)
    for va in vas:
        hist[va % 16] += 1
    return hist


def _gap_rows(
    info: BinaryInfo, funcs: list[tuple[int, int]]
) -> tuple[dict[str, int], list[dict[str, Any]]]:
    """Classify every inter-function gap; sizeless entries carry no extent."""
    sized = [(va, size) for va, size in funcs if size > 0]
    hist = dict.fromkeys(_GAP_CLASSES, 0)
    rows: list[dict[str, Any]] = []
    for i in range(len(sized) - 1):
        va, size = sized[i]
        next_va = sized[i + 1][0]
        start = va + size
        length = next_va - start
        if length < 0:
            cls = "overlap"
        elif length == 0:
            cls = "adjacent"
        else:
            data = extract_bytes_at_va(info, start, length, trim_padding=False)
            cls = (
                "large_nonpadding"
                if data is None
                else _classify_gap(data, info.text_va, info.text_size)
            )
        hist[cls] += 1
        rows.append({"start": start, "end": next_va, "length": length, "class": cls})
    return hist, rows


def _reloc_pages(pe: lief.PE.Binary | None, image_base: int) -> tuple[list[dict[str, int]], int]:
    """HIGHLOW counts per 4K page (keyed by page RVA) plus the total."""
    counts: dict[int, int] = {}
    total = 0
    if pe is not None:
        for block in pe.relocations:
            page = int(block.virtual_address) & ~0xFFF
            for entry in block.entries:
                if int(entry.type) == _RELOC_HIGHLOW:
                    counts[page] = counts.get(page, 0) + 1
                    total += 1
    pages = [
        {
            "page_rva": rva,
            "page_va": (image_base + rva) & 0xFFFFFFFF,
            "highlow": count,
        }
        for rva, count in sorted(counts.items())
    ]
    return pages, total


def _iat_rows(pe: lief.PE.Binary | None, image_base: int) -> list[dict[str, Any]]:
    """IAT slots in descriptor order as ``dll`` / ``name`` / ``slot_va`` rows."""
    rows: list[dict[str, Any]] = []
    if pe is None:
        return rows
    for lib in pe.imports:
        dll = _lief_str(lib.name) or "?"
        for imp in lib.entries:
            name = _lief_str(imp.name)
            rows.append(
                {
                    "dll": dll,
                    "name": name,
                    "ordinal": int(imp.ordinal) if name is None else None,
                    "slot_va": (image_base + int(imp.iat_address)) & 0xFFFFFFFF,
                }
            )
    return rows


def _export_rows(pe: lief.PE.Binary | None, image_base: int) -> list[dict[str, Any]]:
    """Export directory rows as ``name`` / ``ordinal`` / ``va``."""
    rows: list[dict[str, Any]] = []
    if pe is None:
        return rows
    exp = pe.get_export()
    if exp is None:
        return rows
    for entry in exp.entries:
        rows.append(
            {
                "name": _lief_str(entry.name),
                "ordinal": int(entry.ordinal),
                "va": (image_base + int(entry.address)) & 0xFFFFFFFF,
            }
        )
    return rows


def _pe_header(pe: lief.PE.Binary | None) -> dict[str, Any]:
    """Linker version plus the key linker-stamped header flags (PE only)."""
    if pe is None:
        return {}
    oh = pe.optional_header
    return {
        "machine": int(pe.header.machine),
        "characteristics": int(pe.header.characteristics),
        "timestamp": int(pe.header.time_date_stamps),
        "checksum": int(oh.checksum),
        "linker_version": f"{int(oh.major_linker_version)}.{int(oh.minor_linker_version)}",
        "section_alignment": int(oh.section_alignment),
        "file_alignment": int(oh.file_alignment),
        "size_of_image": int(oh.sizeof_image),
        "subsystem": int(oh.subsystem),
        "dll_characteristics": int(oh.dll_characteristics),
    }


def _toolchain_row(path: Path) -> dict[str, Any]:
    """The Rich-header toolchain guess for *path*."""
    info = detect_toolchain(path)
    return {
        "family": info.family,
        "version_hint": info.version_hint,
        "confidence": info.confidence,
        "detected_by": info.detected_by,
        "suggested_profiles": list(info.suggested_profiles),
        "evidence": list(info.evidence),
    }


def build_manifest(cfg: ProjectConfig, info: BinaryInfo) -> Manifest:
    """Measure the reference binary and return the layout manifest."""
    pe = _lief_pe(info.path)
    funcs = _text_functions(_catalog_vas(cfg), info)
    align = _alignment_histogram([va for va, _ in funcs])
    gap_hist, gap_rows = _gap_rows(info, funcs)
    pages, total_highlow = _reloc_pages(pe, info.image_base)
    return {
        "target": cfg.target_name,
        "binary": str(cfg.target_binary),
        "format": info.format,
        "arch": info.arch,
        "image_base": info.image_base,
        "functions": len(funcs),
        "sections": _section_rows(info, pe),
        "alignment": {"histogram": align, "total": sum(align.values())},
        "gaps": {
            "histogram": gap_hist,
            "total": sum(gap_hist.values()),
            "rows": gap_rows,
        },
        "reloc_density": {"pages": pages, "total_highlow": total_highlow},
        "iat": _iat_rows(pe, info.image_base),
        "exports": _export_rows(pe, info.image_base),
        "toolchain": _toolchain_row(info.path),
        "pe_header": _pe_header(pe),
    }


# ---------------------------------------------------------------------------
# Text-map package (write mode)
# ---------------------------------------------------------------------------


def write_text_map(manifest: Manifest, out_dir: Path) -> list[str]:
    """Write ``sections.txt`` / ``gaps.txt`` / ``iat.txt`` / ``exports.txt``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    target = manifest["target"]

    def _write(name: str, text: str) -> None:
        path = out_dir / name
        atomic_write_text(path, text)
        written.append(str(path))

    head = f"# {target} - {{what}}\n# generated by rebrew layout-map; do not hand-edit\n"
    _write(
        "sections.txt",
        head.format(
            what="section table: 'name va virtual_size raw_size file_offset characteristics'"
        )
        + "".join(
            f"{s['name']} 0x{s['va']:x} 0x{s['virtual_size']:x} "
            f"0x{s['raw_size']:x} 0x{s['file_offset']:x} 0x{s['characteristics']:08x}\n"
            for s in manifest["sections"]
        ),
    )
    gaps = manifest["gaps"]
    _write(
        "gaps.txt",
        head.format(what="inter-function gaps: 'start_va end_va length class'")
        + "# histogram: "
        + " ".join(f"{cls}={gaps['histogram'][cls]}" for cls in _GAP_CLASSES)
        + "\n"
        + "".join(
            f"0x{g['start']:x} 0x{g['end']:x} 0x{g['length']:x} {g['class']}\n"
            for g in gaps["rows"]
        ),
    )
    _write(
        "iat.txt",
        head.format(what="IAT slots in descriptor order: 'slot_va dll!symbol'")
        + "".join(
            f"0x{s['slot_va']:x} {s['dll']}!{s['name'] if s['name'] else '#' + str(s['ordinal'])}\n"
            for s in manifest["iat"]
        ),
    )
    _write(
        "exports.txt",
        head.format(what="exports: 'name @ordinal va'")
        + "".join(
            f"{e['name'] or 'ORDINAL_' + str(e['ordinal'])} @{e['ordinal']} 0x{e['va']:x}\n"
            for e in manifest["exports"]
        ),
    )
    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_summary(manifest: Manifest) -> None:
    """Human summary of the manifest on stderr."""
    align = manifest["alignment"]
    gaps = manifest["gaps"]
    reloc = manifest["reloc_density"]
    toolchain = manifest["toolchain"]
    console.print(
        f"[bold]layout-map[/bold] {manifest['target']} "
        f"({manifest['format']}/{manifest['arch']}) "
        f"{len(manifest['sections'])} sections, {manifest['functions']} functions"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("section", justify="left")
    for col in ("va", "vsize", "raw", "chars"):
        table.add_column(col, justify="right")
    for s in manifest["sections"]:
        table.add_row(
            s["name"],
            f"0x{s['va']:x}",
            f"0x{s['virtual_size']:x}",
            f"0x{s['raw_size']:x}",
            f"0x{s['characteristics']:08x}",
        )
    console.print(table)
    hist = align["histogram"]
    console.print(
        f"alignment(mod16): {align['total']} functions "
        f"(mod0={hist[0]}, mod4={hist[4]}, mod8={hist[8]}, mod12={hist[12]})"
    )
    console.print(
        "gaps: "
        + ", ".join(f"{cls}={gaps['histogram'][cls]}" for cls in _GAP_CLASSES)
        + f" ({gaps['total']} total)"
    )
    console.print(f".reloc HIGHLOW: {reloc['total_highlow']} across {len(reloc['pages'])} pages")
    console.print(f"iat slots: {len(manifest['iat'])}  exports: {len(manifest['exports'])}")
    console.print(
        f"toolchain: {toolchain['family']} {toolchain['version_hint']} "
        f"({toolchain['confidence']}, via {toolchain['detected_by']})"
    )
    header = manifest["pe_header"]
    if header:
        console.print(
            f"pe: linker {header['linker_version']} machine=0x{header['machine']:x} "
            f"subsystem={header['subsystem']} chars=0x{header['characteristics']:04x}"
        )


@app.callback(invoke_without_command=True)
def main(
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Write text-map files (sections.txt, gaps.txt, iat.txt, exports.txt) into DIR",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Dump reference-side layout measurements for the target binary."""
    cfg = require_config(target=target, json_mode=json_output)
    if not cfg.target_binary.exists():
        error_exit(f"binary not found: {cfg.target_binary}", json_mode=json_output)
    try:
        info = load_binary(cfg.target_binary)
    except (FileNotFoundError, ValueError) as exc:
        error_exit(f"cannot parse {cfg.target_binary}: {exc}", json_mode=json_output)
    manifest = build_manifest(cfg, info)
    written: list[str] = []
    if output is not None:
        written = write_text_map(manifest, output)
        manifest["written"] = written
    if json_output:
        json_print(manifest)
        return
    _print_summary(manifest)
    for w in written:
        console.print(f"  wrote {w}")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
