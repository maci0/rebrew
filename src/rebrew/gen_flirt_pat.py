#!/usr/bin/env python3
"""Generate FLIRT .pat files from MSVC6 COFF .lib archives.

This reads the object files inside a .lib archive, extracts every
public function symbol with its COFF relocations, and emits a
.pat-format line for each one with relocation bytes masked as '..'.

Usage: uv run python tools/gen_flirt_pat.py tools/MSVC600/VC98/Lib/LIBCMT.LIB -o flirt_sigs/libcmt_vc6.pat
"""

import argparse
import struct
import sys
from collections.abc import Iterator
from pathlib import Path


def parse_archive(lib_path: str) -> Iterator[tuple[str, bytes]]:
    """Parse a COFF archive (.lib) and yield (member_name, obj_data) tuples."""
    with open(lib_path, "rb") as f:
        data = f.read()

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
        size = int(header[48:58].strip())

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
    with tempfile.NamedTemporaryFile(suffix=".obj", delete=False) as f:
        f.write(obj_data)
        tmp_path = Path(f.name)

    try:
        coff = lief.COFF.parse(str(tmp_path))
    finally:
        tmp_path.unlink(missing_ok=True)

    if coff is None:
        return

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

        # Find the next symbol in the same section to bound this function
        for other in coff.symbols:
            if (
                other.section is not None
                and other.section.name == section.name
                and other.value > func_start
                and other.value < func_end
                and not other.name.startswith("$")
            ):
                func_end = other.value

        if func_start >= func_end or func_end > len(content):
            continue

        code = content[func_start:func_end]

        # Collect relocation byte offsets (expanded to cover full fixup width)
        reloc_offsets = set()
        for reloc in section.relocations:
            rva = reloc.address
            if func_start <= rva < func_end:
                func_rel = rva - func_start
                # reloc.size gives the fixup width in bits
                fixup_bytes = max(reloc.size // 8, 1)
                for k in range(fixup_bytes):
                    reloc_offsets.add(func_rel + k)

        if len(code) >= 4:
            yield sym.name, code, reloc_offsets


def bytes_to_pat_line(
    name: str, code_bytes: bytes, reloc_offsets: set[int], max_lead: int = 32
) -> str:
    """Convert function name + bytes into a FLIRT .pat format line.

    Relocation bytes are masked with '..' in the leading portion.
    """
    lead_len = min(len(code_bytes), max_lead)
    lead = ""
    for i in range(lead_len):
        if i in reloc_offsets:
            lead += ".."
        else:
            lead += f"{code_bytes[i]:02X}"

    # CRC16 of non-reloc bytes after the leading portion
    crc_start = lead_len
    crc_len = min(len(code_bytes) - crc_start, 255)

    crc = 0
    for i in range(crc_start, crc_start + crc_len):
        b = 0 if i in reloc_offsets else code_bytes[i]
        crc ^= b << 8
        for _ in range(8):
            crc = crc << 1 ^ 32773 if crc & 32768 else crc << 1
            crc &= 0xFFFF

    total_size = len(code_bytes)

    return f"{lead} {crc_len:02X} {crc:04X} {total_size:04X} :0000 {name}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate FLIRT .pat from COFF .lib")
    parser.add_argument("lib_path", help="Path to .lib file")
    parser.add_argument("-o", "--output", help="Output .pat file path")
    args = parser.parse_args()

    lib_path = Path(args.lib_path)
    if not lib_path.exists():
        print(f"ERROR: {lib_path} not found", file=sys.stderr)
        sys.exit(1)

    lib_name = lib_path.stem.lower()
    out_path = Path(args.output) if args.output else Path(f"flirt_sigs/{lib_name}_vc6.pat")

    if out_path.parent != Path("."):
        out_path.parent.mkdir(parents=True, exist_ok=True)

    pat_lines = []
    seen = set()

    for _member_name, obj_data in parse_archive(str(lib_path)):
        try:
            for sym_name, code, relocs in parse_coff_obj(obj_data):
                if sym_name not in seen and len(code) >= 4:
                    seen.add(sym_name)
                    line = bytes_to_pat_line(sym_name, code, relocs)
                    pat_lines.append(line)
        except (OSError, KeyError, ValueError, struct.error):
            pass

    out_path.write_text(
        "".join(line + "\n" for line in pat_lines) + "---\n",
        encoding="utf-8",
    )

    print(f"Generated {out_path}: {len(pat_lines)} signatures from {lib_path}")


if __name__ == "__main__":
    main()
