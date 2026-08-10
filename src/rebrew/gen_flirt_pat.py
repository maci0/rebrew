"""Generate FLIRT .pat files from COFF .lib archives.

This reads the object files inside a .lib archive, extracts every
public function symbol with its COFF relocations, and emits a
.pat-format line for each one with relocation bytes masked as '..'.
"""

import bisect
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import error_exit, json_print

console = Console(stderr=True)

app = typer.Typer(
    help="Generate FLIRT .pat files from COFF .lib archives.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew gen-flirt-pat tools/MSVC600/VC98/Lib/LIBCMT.LIB\n\n"
        "  rebrew gen-flirt-pat LIBCMT.LIB -o flirt_sigs/libcmt_vc6.pat\n\n"
        "[dim]Reads COFF .obj members from a .lib archive, extracts public function "
        "symbols with relocations, and emits FLIRT .pat-format signatures.[/dim]"
    ),
)


def parse_archive(lib_path: str) -> Iterator[tuple[str, bytes]]:
    """Parse a COFF archive (.lib) and yield (member_name, obj_data) tuples."""
    data = Path(lib_path).read_bytes()

    if not data.startswith(b"!<arch>\n"):
        raise ValueError(f"{lib_path} is not a valid archive")

    pos = 8
    while pos < len(data):
        if pos % 2 == 1:
            pos += 1
        if pos + 60 > len(data):
            break

        header = data[pos : pos + 60]
        name_field = header[0:16].rstrip(b" ")
        try:
            size = int(header[48:58].strip())
        except ValueError:
            break

        pos += 60
        member_data = data[pos : pos + size]
        pos += size

        name = name_field.decode("ascii", errors="replace").rstrip("/")

        if name in ("", "/", "//"):
            continue

        yield name, member_data


def parse_coff_obj(obj_data: bytes) -> Iterator[tuple[str, bytes, set[int]]]:
    """Parse a COFF .obj and yield (symbol_name, code_bytes, reloc_offsets).

    Uses LIEF for parsing. ``obj_data`` is raw bytes of a COFF .obj file.
    ``reloc_offsets`` is a set of individual *byte* positions that are
    covered by relocations (expanded to cover the full fixup width).
    """
    import tempfile

    import lief

    if len(obj_data) < 20:
        return

    # LIEF needs a file path, so write to a temp file
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".obj", delete=False) as f:
            f.write(obj_data)
            tmp_path = Path(f.name)
        coff = lief.COFF.parse(str(tmp_path))
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)

    if coff is None:
        return

    # Pre-build per-section sorted symbol offsets to avoid O(n^2) scans
    section_sym_offsets: dict[str, list[int]] = {}
    for sym in coff.symbols:
        sym_name = str(sym.name)
        if sym.section is not None and not sym_name.startswith("$"):
            section_sym_offsets.setdefault(str(sym.section.name), []).append(sym.value)
    for offsets in section_sym_offsets.values():
        offsets.sort()

    for sym in coff.symbols:
        # Only external function symbols in code sections
        if sym.storage_class != lief.COFF.Symbol.STORAGE_CLASS.EXTERNAL or sym.section is None:
            continue

        section = sym.section
        # Check if this is a code section (IMAGE_SCN_CNT_CODE = 0x20)
        if not (section.characteristics & 0x20):
            continue

        content = bytes(section.content)
        func_start = sym.value
        func_end = len(content)

        # Find the next symbol in the same section via sorted offsets (O(log n))
        offsets = section_sym_offsets.get(str(section.name), [])
        idx = bisect.bisect_right(offsets, func_start)
        if idx < len(offsets):
            func_end = offsets[idx]

        if func_start >= func_end or func_end > len(content):
            continue

        code = content[func_start:func_end]

        # Collect relocation byte offsets (expanded to cover full fixup width)
        reloc_offsets = set()
        for reloc in section.relocations:
            rva = reloc.address
            if func_start <= rva < func_end:
                func_rel = rva - func_start
                fixup_bytes = _reloc_fixup_width(reloc)
                for k in range(fixup_bytes):
                    reloc_offsets.add(func_rel + k)

        if len(code) >= 4:
            yield str(sym.name), code, reloc_offsets


# x86 COFF fixup widths by relocation type (bytes).  LIEF reports
# ``reloc.size == 0`` for MSVC6 objects, so the width cannot come from the
# size field — a DIR32/REL32 fixup occupies 4 bytes on x86.
_I386_FIXUP_WIDTHS: dict[str, int] = {
    "I386_DIR16": 2,
    "I386_REL16": 2,
    "I386_SEG12": 2,
    "I386_DIR32": 4,
    "I386_DIR32NB": 4,
    "I386_REL32": 4,
    "I386_SECREL": 4,
    "I386_SECTION": 2,  # 16-bit section index
    "I386_SECREL7": 2,  # 16-bit "offset minus 1" (debug-info-only on x86)
}


def _reloc_fixup_width(reloc: Any) -> int:
    """Fixup width in bytes for a COFF relocation, derived from its type.

    Falls back to the LIEF ``size`` field (bits) when the type is unknown.
    """
    name = str(reloc.type).rsplit(".", 1)[-1]
    width = _I386_FIXUP_WIDTHS.get(name)
    if width is not None:
        return width
    return max(int(reloc.size) // 8, 1)


def _crc16_flirt(buf: bytes) -> int:
    """IDA's FLIRT CRC16 — the exact variant sigmake emits and python-flirt
    verifies (ported from flair/crc16.cpp as in lancelot's flirt crate):
    reflected poly 0x8408, init 0xFFFF, final bitwise invert, byte-swapped.
    """
    if not buf:
        return 0
    crc = 0xFFFF
    for b in buf:
        for _ in range(8):
            if (crc ^ b) & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
            b >>= 1
        crc &= 0xFFFF
    crc = (~crc) & 0xFFFF
    return ((crc & 0xFF) << 8) | (crc >> 8)


def bytes_to_pat_line(
    name: str, code_bytes: bytes, reloc_offsets: set[int], max_lead: int = 32
) -> str:
    """Convert function name + bytes into a FLIRT .pat format line.

    Relocation bytes are masked with '..' in the leading portion; the CRC
    window covers the tail up to the first tail relocation (sigmake rule).
    """
    lead_len = min(len(code_bytes), max_lead)
    lead_parts: list[str] = [
        ".." if i in reloc_offsets else f"{code_bytes[i]:02X}" for i in range(lead_len)
    ]
    lead = "".join(lead_parts)

    # CRC16 of non-reloc bytes after the leading portion.  Uses IDA's exact
    # CRC variant; see _crc16_flirt.
    #
    # The window stops BEFORE the first relocation in the tail (sigmake
    # behavior): a reloc byte holds a linker-filled address in the binary, so
    # including it in the CRC would guarantee a mismatch — the matcher CRCs
    # the real bytes, and the object's reloc slot is zeroed.  Truncating the
    # window is what makes functions with tail relocs (e.g. MSVC6 isalpha,
    # which references __pctype at offset 0x20) matchable at all.
    crc_start = lead_len
    tail_relocs = sorted(r for r in reloc_offsets if r >= crc_start)
    crc_end = tail_relocs[0] if tail_relocs else len(code_bytes)
    crc_len = min(max(crc_end - crc_start, 0), len(code_bytes) - crc_start, 255)

    crc_window = bytes(code_bytes[i] for i in range(crc_start, crc_start + crc_len))
    crc = _crc16_flirt(crc_window)

    total_size = len(code_bytes)

    return f"{lead} {crc_len:02X} {crc:04X} {total_size:04X} :0000 {name}"


# IDA's guidance: a .pat signature without CRC protection needs at least 16
# non-wildcard lead bytes to be discriminative.  Below that, the sig matches
# any function sharing the same generic prolog — mass false positives.
_MIN_LITERAL_LEAD_BYTES = 16


def _is_weak_signature(line: str) -> bool:
    """True when a generated .pat line is too weak to be useful.

    A line is weak when its lead has fewer than 16 literal bytes AND the CRC
    window is empty or nearly so (< 8 bytes) — nothing meaningfully protects
    the tail.  Observed in practice: one such libc sig matched 30 unrelated
    offsets in a real DLL.
    """
    parts = line.split()
    if len(parts) < 6:
        return False
    lead = parts[0]
    literal = sum(1 for i in range(0, len(lead), 2) if lead[i : i + 2] != "..")
    if literal >= _MIN_LITERAL_LEAD_BYTES:
        return False
    return int(parts[1], 16) < 8


def generate_pat(lib_file: Path, out_path: Path) -> dict[str, int]:
    """Generate a FLIRT .pat file from one COFF .lib archive.

    Returns ``{"signatures": n, "skipped_members": n, "skipped_weak": n}``.
    Shared by ``rebrew gen-flirt-pat`` and ``rebrew identify-library
    --build-sigs`` (batch over a toolchain Lib dir).
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)

    pat_lines: list[str] = []
    seen: set[str] = set()

    skipped = 0
    weak_skipped = 0
    for _member_name, obj_data in parse_archive(str(lib_file)):
        try:
            for sym_name, code, relocs in parse_coff_obj(obj_data):
                if sym_name not in seen and len(code) >= 4:
                    seen.add(sym_name)
                    line = bytes_to_pat_line(sym_name, code, relocs)
                    if _is_weak_signature(line):
                        # Generic-prolog-only sigs would false-positive across
                        # the whole binary — drop them rather than emit noise.
                        weak_skipped += 1
                        continue
                    pat_lines.append(line)
        except (OSError, KeyError, ValueError, struct.error):
            skipped += 1

    out_path.write_text(
        "".join(line + "\n" for line in pat_lines) + "---\n",
        encoding="utf-8",
    )
    return {
        "signatures": len(pat_lines),
        "skipped_members": skipped,
        "skipped_weak": weak_skipped,
    }


@app.callback(invoke_without_command=True)
def main(
    lib_path: str = typer.Argument(..., help="Path to .lib file"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output .pat file path"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Generate FLIRT .pat files from COFF .lib archives."""
    lib_file = Path(lib_path)
    if not lib_file.exists():
        error_exit(f"{lib_file} not found", json_mode=json_output)

    lib_name = lib_file.stem.lower()
    out_path = Path(output) if output else Path(f"flirt_sigs/{lib_name}_vc6.pat")

    stats = generate_pat(lib_file, out_path)
    skipped = stats["skipped_members"]
    weak_skipped = stats["skipped_weak"]
    if json_output:
        json_print(
            {
                "output": str(out_path),
                "signatures": stats["signatures"],
                "source": str(lib_file),
                "skipped_members": skipped,
                "skipped_weak": weak_skipped,
            }
        )
        return

    msg = f"Generated {out_path}: {stats['signatures']} signatures from {lib_file}"
    if skipped:
        msg += f" ({skipped} corrupt members skipped)"
    if weak_skipped:
        msg += f" ({weak_skipped} weak signatures skipped)"
    console.print(msg)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
