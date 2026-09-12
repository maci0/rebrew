"""Tests for rebrew.layout_meta — PE layout extraction.

Regression for the tooling-sweep round: ``extract_layout`` used bare
``next()`` over the section table, so a PE missing one of
.text/.data/.rdata/.reloc (e.g. notepad.exe — relocations stripped, only
.text/.data/.rsrc present) crashed ``rebrew gen-layout`` with an
unhandled ``StopIteration`` traceback instead of a clean error.
"""

from __future__ import annotations

import struct

import pytest

from rebrew.layout_meta import extract_layout

_IMAGE_BASE = 0x400000
_SEC_ALIGN = 0x1000
_FILE_ALIGN = 0x200
_HEADERS = 0x200


def _make_pe(section_names: list[bytes], opt_chars: int = 0x0102) -> bytes:
    """Build a minimal PE with the given section names (no real content).

    extract_layout parses the headers and the data directories before it
    resolves the section objects, so a structurally-valid PE with any
    section set reaches the section lookup.
    """
    nsec = len(section_names)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack("<HHIIIHH", 0x14C, nsec, 0, 0, 0, 0xE0, opt_chars)

    opt = bytearray(struct.pack("<H", 0x10B))  # PE32
    opt += struct.pack("<BB", 8, 0)
    opt += struct.pack("<I", 0x1000)  # code size
    opt += struct.pack("<I", 0x2000)  # init data size
    opt += struct.pack("<I", 0)  # uninit data size
    opt += struct.pack("<I", 0x1000)  # entry
    opt += struct.pack("<I", 0x1000)  # code base
    opt += struct.pack("<I", 0x3000)  # data base
    opt += struct.pack("<I", _IMAGE_BASE)
    opt += struct.pack("<I", _SEC_ALIGN)
    opt += struct.pack("<I", _FILE_ALIGN)
    opt += struct.pack("<HH", 6, 0)
    opt += struct.pack("<HH", 0, 0)
    opt += struct.pack("<HH", 6, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<I", 0x5000)  # size of image
    opt += struct.pack("<I", _HEADERS)
    opt += struct.pack("<I", 0)  # checksum
    opt += struct.pack("<H", 3)  # subsystem
    opt += struct.pack("<H", 0)
    opt += struct.pack("<I", 0x100000)  # stack reserve
    opt += struct.pack("<I", 0x1000)
    opt += struct.pack("<I", 0x100000)  # heap reserve
    opt += struct.pack("<I", 0x1000)
    opt += struct.pack("<I", 0)  # loader flags
    opt += struct.pack("<I", 16)  # number of data directories
    opt += b"\x00" * (16 * 8)  # empty data directories
    assert len(opt) == 0xE0

    secs = b""
    for i, name in enumerate(section_names):
        secs += struct.pack(
            "<8sIIIIIIHHI",
            name,
            0x1000,  # virtual size
            0x1000 * (3 + i),  # virtual address
            0x200,  # raw size
            _HEADERS + 0x200 * i,  # raw ptr
            0,
            0,
            0,
            0,
            0x60000020,  # code|init-data|read|write chars
        )

    hdrs = dos + b"PE\x00\x00" + coff + opt + secs
    hdrs += b"\x00" * (_HEADERS - len(hdrs))
    return bytes(hdrs) + b"\x00" * (0x2000)


class TestExtractLayoutMissingSection:
    def test_missing_reloc_raises_valueerror(self) -> None:
        """A PE without .reloc (relocations stripped — notepad.exe has only
        .text/.data/.rsrc) must raise a clean ValueError naming the missing
        section, not StopIteration."""
        pe = _make_pe([b".text\x00\x00\x00", b".data\x00\x00\x00", b".rsrc\x00\x00\x00"])
        with pytest.raises(ValueError, match=r"missing section '\.reloc'"):
            extract_layout(pe)

    def test_missing_rdata_raises_valueerror(self) -> None:
        pe = _make_pe([b".text\x00\x00\x00", b".data\x00\x00\x00", b".reloc\x00\x00"])
        with pytest.raises(ValueError, match=r"missing section '\.rdata'"):
            extract_layout(pe)

    def test_missing_section_is_not_stopiteration(self) -> None:
        pe = _make_pe([b".text\x00\x00\x00"])
        with pytest.raises(ValueError):
            extract_layout(pe)
        # the guard: ValueError (handled by gen-layout's error_exit) not the
        # bare StopIteration that used to escape as a traceback
        assert not issubclass(ValueError, StopIteration)


def _make_import_pe() -> bytes:
    """A PE with .text/.rdata/.data/.reloc, one import DLL, and OFT bound."""
    from test_postlink import make_full_pe

    return make_full_pe(imports=[("KERNEL32.dll", ["GetLocalTime", "WriteFile"])])


class TestOftZeroUsesIat:
    def test_oft_zero_falls_back_to_iat(self) -> None:
        """A descriptor with OFT=0 (unbound) is bound by the IAT itself:
        extraction must read the entries from the IAT array, not parse the
        header region at oft(0) as hint/names."""
        ref = _make_import_pe()
        e = struct.unpack_from("<I", ref, 0x3C)[0]
        opt = e + 24
        imp_rva, _ = struct.unpack_from("<II", ref, opt + 96 + 8)
        raw = bytearray(ref)
        struct.pack_into("<I", raw, imp_rva, 0)  # OFT = 0 on the descriptor
        meta = extract_layout(bytes(raw), "t.dll")
        assert [(i.dll, i.name) for i in meta.imports] == [
            ("KERNEL32.dll", "GetLocalTime"),
            ("KERNEL32.dll", "WriteFile"),
        ]
        assert all(i.ordinal is None for i in meta.imports)

    def test_oft_zero_does_not_emit_header_garbage(self) -> None:
        """Pre-fix the oft(0) file offset (the DOS header) parsed as
        hint/name entries, yielding garbage or zero imports."""
        ref = _make_import_pe()
        e = struct.unpack_from("<I", ref, 0x3C)[0]
        opt = e + 24
        imp_rva, _ = struct.unpack_from("<II", ref, opt + 96 + 8)
        raw = bytearray(ref)
        struct.pack_into("<I", raw, imp_rva, 0)
        meta = extract_layout(bytes(raw), "t.dll")
        assert len(meta.imports) == 2
        assert all(i.name for i in meta.imports)


class TestExtractLayoutTruncatedSectionTable:
    def test_truncated_section_table_raises_valueerror(self) -> None:
        """A PE cut before its section table must raise a clean ValueError,
        not struct.error from the section reader."""
        e = 0x40
        opt = e + 24
        optsz = 0xE0
        buf = bytearray(opt + optsz)
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, e)
        buf[e : e + 4] = b"PE\x00\x00"
        struct.pack_into("<H", buf, e + 6, 2)  # NumberOfSections = 2
        struct.pack_into("<H", buf, e + 20, optsz)
        struct.pack_into("<H", buf, opt, 0x10B)  # PE32
        struct.pack_into("<I", buf, opt + 28, _IMAGE_BASE)
        with pytest.raises(ValueError, match="truncated section table"):
            extract_layout(bytes(buf), "t.dll")


_SECTIONS = [b".text\x00\x00\x00", b".rdata\x00\x00\x00", b".data\x00\x00\x00", b".reloc\x00\x00"]


class TestSparseMapBounds:
    """The .text sparse maps must include the last valid scan position."""

    def test_last_dword_is_scanned(self) -> None:
        pe = bytearray(_make_pe(_SECTIONS))
        # .text raw 0x200 at file 0x200; an image-relative dword at the very end.
        struct.pack_into("<I", pe, 0x200 + 0x1FC, _IMAGE_BASE + 0x4000)  # -> .rdata
        meta = extract_layout(bytes(pe), "t.dll")
        assert 0x1FC in meta.operands

    def test_last_call_site_is_scanned(self) -> None:
        pe = bytearray(_make_pe(_SECTIONS))
        # E8 at index 505, its 4-byte rel32 at 506..509, suffix at 510..511 —
        # the last call site that fits entirely in .text.
        struct.pack_into("<B", pe, 0x200 + 505, 0xE8)
        struct.pack_into("<I", pe, 0x200 + 506, 0x00000010)
        meta = extract_layout(bytes(pe), "t.dll")
        assert 506 in meta.calls


class TestExportNameOffsets:
    """Export name strings and forwarder entries."""

    def _pe_with_one_export(self, func_rva: int, name: bytes) -> bytes:
        """One-export PE whose name string has no terminating NUL in the file."""
        pe = bytearray(_make_pe(_SECTIONS))
        exp_file, exp_rva = 0x200, 0x3000  # export dir inside .text
        name_off = exp_file + 0x70
        e = struct.unpack_from("<I", pe, 0x3C)[0]
        opt = e + 24
        struct.pack_into("<II", pe, opt + 96, exp_rva, 0x14)  # data directory 0
        struct.pack_into("<I", pe, exp_file + 16, 1)  # Base
        struct.pack_into("<I", pe, exp_file + 20, 1)  # NumberOfFunctions
        struct.pack_into("<I", pe, exp_file + 24, 1)  # NumberOfNames
        struct.pack_into("<I", pe, exp_file + 28, exp_rva + 0x40)  # AddressOfFunctions
        struct.pack_into("<I", pe, exp_file + 32, exp_rva + 0x50)  # AddressOfNames
        struct.pack_into("<I", pe, exp_file + 36, exp_rva + 0x60)  # AddressOfNameOrdinals
        struct.pack_into("<I", pe, exp_file + 0x40, func_rva)
        struct.pack_into("<I", pe, exp_file + 0x50, exp_rva + 0x70)  # name RVA
        struct.pack_into("<H", pe, exp_file + 0x60, 0)  # name ordinal index
        pe[name_off : name_off + len(name)] = name
        return bytes(pe[: name_off + len(name)])  # cut right after the name

    def test_unterminated_export_name_read_to_eof(self) -> None:
        """A name string running to EOF must not be sliced with -1 (which
        dropped its last character)."""
        meta = extract_layout(self._pe_with_one_export(0x1000, b"StraightName"), "t.dll")
        assert [ex["name"] for ex in meta.exports] == ["StraightName"]
        assert meta.exports[0]["va"] == _IMAGE_BASE + 0x1000

    def test_forwarder_export_is_dropped(self) -> None:
        """An export whose RVA points inside the export directory is a
        forwarder string, not code — gen_layout.parse_pe drops those, and
        recording one would claim a function at a .rdata VA."""
        meta = extract_layout(self._pe_with_one_export(0x3000, b"Fwd"), "t.dll")
        assert meta.exports == []


class TestNoExportsBookkeeping:
    def test_bookkeeping_empty_without_export_dir(self) -> None:
        """Imports + no exports makes exp_rva 0, so `exp_rva - imp_rva` is
        negative; the slice then returned a huge wrong region that postlink
        copies over the built binary."""
        ref = _make_import_pe()
        e = struct.unpack_from("<I", ref, 0x3C)[0]
        opt = e + 24
        exp_rva, _ = struct.unpack_from("<II", ref, opt + 96)
        assert exp_rva != 0  # fixture sanity: the export dir exists by default
        raw = bytearray(ref)
        # Move .rdata's raw pointer below its RVA, so `off(imp_rva) < imp_rva`
        # and the buggy negative size produces a NON-empty slice (an explicit
        # stop of exactly 0 is empty, which would hide the defect).
        nsec = struct.unpack_from("<H", raw, e + 6)[0]
        opt_size = struct.unpack_from("<H", raw, e + 20)[0]
        base = e + 24 + opt_size
        for i in range(nsec):
            hdr = base + 40 * i
            if bytes(raw[hdr : hdr + 8]).rstrip(b"\x00").startswith(b".rdata"):
                struct.pack_into("<I", raw, hdr + 20, 0)  # PointerToRawData
        struct.pack_into("<II", raw, opt + 96, 0, 0)  # zero the export dir entry
        meta = extract_layout(bytes(raw), "t.dll")
        assert meta.bookkeeping == b""
