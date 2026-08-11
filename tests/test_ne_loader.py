"""Tests for rebrew.ne_loader — 16-bit Windows NE parsing.

Builds synthetic NE executables (MZ stub + NE header + segment table) so
the parser is exercised without depending on any real 16-bit binary.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from rebrew.ne_loader import (
    parse_exports,
    parse_imports,
    parse_ne_header,
    parse_segments,
    probe_is_code,
)


def _build_ne(
    *,
    segments: list[tuple[bytes, int]] | None = None,
    exports: list[tuple[str, int]] | None = None,
    modules: list[str] | None = None,
    autodata: int = 0,
) -> bytes:
    """Assemble a minimal NE file.

    *segments*: list of (content, flags); each becomes a segment aligned to
    the 16-byte logical sector.  *exports*: (name, ordinal) resident-name
    entries.  *modules*: imported module names (module reference table +
    imported names table).
    """
    sector_shift = 4  # 16-byte sectors
    sector = 1 << sector_shift

    segs = segments or []
    seg_table = bytearray()
    seg_blobs: list[bytes] = []
    for content, flags in segs:
        # pad content to sector alignment
        padded = content + b"\x00" * ((-len(content)) % sector)
        seg_blobs.append(padded)
        seg_table += struct.pack("<HHHH", 0, len(content), flags, len(content))

    # Resident names (exports) and import tables are assembled first so their
    # sizes are known; offsets are then laid out sequentially.
    resnames = bytearray()
    for name, ordinal in exports or []:
        resnames += bytes([len(name)]) + name.encode("ascii")
        resnames += struct.pack("<H", ordinal)

    impnames_payload = bytearray()
    for m in modules or []:
        impnames_payload += bytes([len(m)]) + m.encode("ascii")
    modtab = bytearray()
    if modules:
        for m in modules:
            # The module ref table offset points AT the length byte of the
            # module's Pascal name in the imported names table.
            modtab += struct.pack("<H", impnames_payload.index(bytes([len(m)]) + m.encode()))

    # Layout: header | segment table | resource (0) | entry (0) | resident
    # names | module ref table | imported names table | segment data.
    ne_off = 0x100
    header_size = 0x40
    segtab_off = header_size
    restab_off = segtab_off + len(seg_table)
    entry_off = restab_off  # empty entry table
    resnames_off = entry_off
    modtab_off = resnames_off + len(resnames)
    impnames_off = modtab_off + len(modtab)
    # Segment data must start on a sector boundary (offsets are in sectors
    # relative to the file start), so pad the pre-data prefix.
    prefix = ne_off + impnames_off + len(impnames_payload)
    data_start = (prefix + sector - 1) // sector * sector

    # Segment table sector offsets are relative to the START OF THE FILE;
    # the first segment sits at data_start.
    off = data_start // sector
    for i in range(len(segs)):
        struct.pack_into("<H", seg_table, i * 8, off)
        off += len(seg_blobs[i]) // sector

    # NE header
    ne = bytearray(0x40)
    ne[0:2] = b"NE"
    ne[2] = 3  # linker version
    ne[3] = 2
    struct.pack_into("<H", ne, 0x04, entry_off)
    struct.pack_into("<H", ne, 0x06, 0)  # entry table length
    struct.pack_into("<H", ne, 0x0E, autodata)
    struct.pack_into("<H", ne, 0x1C, len(segs))
    struct.pack_into("<H", ne, 0x1E, len(modules or []))
    struct.pack_into("<H", ne, 0x22, segtab_off)
    struct.pack_into("<H", ne, 0x24, restab_off)
    struct.pack_into("<H", ne, 0x26, resnames_off)
    struct.pack_into("<H", ne, 0x28, modtab_off)
    struct.pack_into("<H", ne, 0x2A, impnames_off)
    struct.pack_into("<H", ne, 0x32, sector_shift)

    # MZ stub
    mz = bytearray(0x100)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, ne_off)

    out = bytes(mz) + bytes(ne) + bytes(seg_table) + bytes(resnames) + bytes(modtab)
    out += bytes(impnames_payload)
    out += b"\x00" * (data_start - len(out))  # pad to the sector-aligned data start
    for content, _flags in segs:
        padded = content + b"\x00" * ((-len(content)) % sector)
        out += padded
    return out


_CODE = bytes.fromhex(
    "55 8b ec 83 ec 02 8b 46 04 30 e4 8b 5e 06 03 d8 89 5e fc 5d c3"  # push bp; mov bp,sp; ... ; pop bp; ret (9 insns)
)
_DATA = b"\x0dHoliday Island\x00\x00\x00\x00"  # Pascal string + padding


class TestParseNeHeader:
    def test_header_fields(self) -> None:
        raw = _build_ne(segments=[(_CODE, 0x01)], exports=[("HOLIDAY", 0)])
        hdr = parse_ne_header(raw, 0x100)
        assert hdr.segment_count == 1
        assert hdr.sector_size == 16
        assert hdr.module_reference_count == 0  # no modules in this build

    def test_not_ne_raises(self) -> None:
        from rebrew.ne_loader import NeParseError

        with pytest.raises(NeParseError):
            parse_ne_header(b"MZ" + b"\x00" * 0x40 + b"XX", 0x40)


class TestParseSegments:
    def test_sector_offsets(self) -> None:
        raw = _build_ne(segments=[(_CODE, 0x01), (_DATA, 0x00)])
        hdr = parse_ne_header(raw, 0x100)
        segs = parse_segments(raw, 0x100, hdr)
        assert len(segs) == 2
        # Segment 1's file offset = after headers/tables; both sectors align.
        assert segs[0].file_offset % 16 == 0
        assert segs[1].file_offset % 16 == 0
        assert segs[1].file_offset >= segs[0].file_offset + len(_CODE)


class TestParseExports:
    def test_resident_names(self) -> None:
        raw = _build_ne(segments=[(_CODE, 0x01)], exports=[("HOLIDAY", 0), ("InitApp", 7)])
        hdr = parse_ne_header(raw, 0x100)
        exps = parse_exports(raw, 0x100, hdr)
        assert [(e.name, e.ordinal) for e in exps] == [("HOLIDAY", 0), ("InitApp", 7)]


class TestParseImports:
    def test_module_names(self) -> None:
        raw = _build_ne(segments=[(_CODE, 0x01)], modules=["KERNEL", "USER"])
        hdr = parse_ne_header(raw, 0x100)
        mods = parse_imports(raw, 0x100, hdr)
        assert [m.module for m in mods] == ["KERNEL", "USER"]

    def test_garbage_import_table_degrades_to_modules(self) -> None:
        """Regression: a misplaced/absent import table (MSVC-built NEs like
        the 1991 SkiFree put the non-resident name table where the classic
        import table should be) must not fabricate ordinal garbage — the
        parser degrades to module names only."""
        raw = _build_ne(segments=[(_CODE, 0x01)], modules=["KERNEL"])
        hdr = parse_ne_header(raw, 0x100)
        # Give the entry table a nonzero length so the "import table" position
        # lands past the module ref + imported names tables, then overwrite it
        # with a Pascal string ("Ski Free") whose first two bytes 0x08 0x53
        # read as an absurd import count (0x5308).
        blob = bytearray(raw)
        blob[0x106:0x108] = (0x10).to_bytes(2, "little")  # entry table length
        pos = 0x100 + hdr.entry_table_offset + 0x10
        blob[pos : pos + 8] = b"\x08Ski Free"
        mods = parse_imports(bytes(blob), 0x100, hdr)
        assert [m.module for m in mods] == ["KERNEL"]
        assert all(m.imports == [] for m in mods)


class TestLoadNeBinary:
    def test_binary_info_shape(self, tmp_path: Path) -> None:
        from rebrew.binary_loader import BinaryInfo, load_binary

        raw = _build_ne(segments=[(_CODE, 0x01), (_DATA, 0x00)], modules=["KERNEL"])
        p = tmp_path / "app.ne"
        p.write_bytes(raw)
        info = load_binary(p)
        assert isinstance(info, BinaryInfo)
        assert info.format == "ne"
        assert set(info.sections) == {"SEG1", "SEG2"}
        assert info.sections["SEG1"].va == 0x10000  # segment 1 → 0x10000
        assert info.sections["SEG2"].va == 0x20000
        assert info.ne_segments[0].base_va == 0x10000  # type: ignore[attr-defined]
        # text_size aggregates code segments (catalog coverage needs it)
        assert info.text_size > 0
        assert info.text_va == info.sections["SEG1"].va


class TestProbeIsCode:
    def test_code_segment(self) -> None:
        # Real NE segments carry a 2-byte index marker before their content.
        assert probe_is_code(b"\x01\x00" + _CODE, 0, len(_CODE) + 2) is True

    def test_data_segment(self) -> None:
        assert probe_is_code(b"\x02\x00" + _DATA, 0, len(_DATA) + 2) is False

    def test_markerless_code_segment(self) -> None:
        # MSVC 16-bit NE segments have no [index\x00] marker — code starts
        # directly at offset 0 (e.g. ``push ds/pop ax/nop/inc bp``).
        entry = bytes.fromhex("1e 58 90 45 55 8b ec") + _CODE
        assert probe_is_code(entry, 0, len(entry)) is True

    def test_marker_only_skipped_with_index(self) -> None:
        # With the segment index supplied, the [index\x00] marker is skipped
        # so a data segment that merely resembles the marker is not code.
        assert probe_is_code(b"\x01\x00" + _DATA, 0, len(_DATA) + 2, index=1) is False


class TestEnumerateFunctions:
    def test_finds_function(self, tmp_path: Path) -> None:
        from rebrew.binary_loader import load_binary
        from rebrew.ne_loader import enumerate_ne_functions

        code = (
            b"\x01\x00"  # Borland segment index marker
            + bytes.fromhex(
                "55 8b ec 83 ec 04 8b 46 06 5d c3"  # fn1: push bp; ...; pop bp; ret
                "90 90 90 90"  # padding
                "c8 10 00 00 33 c0 89 46 fc 5d c3"  # fn2: enter 0x10,0; ...; ret
            )
        )
        raw = _build_ne(segments=[(code, 0x01)])
        p = tmp_path / "app.ne"
        p.write_bytes(raw)
        info = load_binary(p)
        funcs = enumerate_ne_functions(info)
        assert len(funcs) >= 2
        # Both functions must terminate with a ret epilog.
        import capstone

        from rebrew.binary_loader import extract_bytes_at_va

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        for f in funcs[:2]:
            body = extract_bytes_at_va(info, f.va, f.size, trim_padding=False) or b""
            insns = list(md.disasm(body, f.va))
            assert insns and insns[-1].mnemonic in ("ret", "retf", "retn")

    def test_markerless_segment_entry_recovered(self, tmp_path: Path) -> None:
        # An MSVC-style segment (no Borland marker) starts directly with the
        # entry function, even when it opens with push ds/pop ax/nop/inc bp
        # rather than a push bp prolog.  The entry function must be found.
        from rebrew.binary_loader import load_binary
        from rebrew.ne_loader import enumerate_ne_functions

        entry = bytes.fromhex("1e 58 90 45 55 8b ec 83 ec 02 5d c3")  # entry + ret
        code = entry + bytes.fromhex("90 90 90 90") + _CODE
        raw = _build_ne(segments=[(code, 0x01)])
        p = tmp_path / "app.ne"
        p.write_bytes(raw)
        info = load_binary(p)
        funcs = enumerate_ne_functions(info)
        assert any(f.va == 0x10000 for f in funcs), [hex(f.va) for f in funcs]
