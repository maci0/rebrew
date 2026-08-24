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
