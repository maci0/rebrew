"""Property-based fuzz tests for the byte-level PE directory readers.

``pe_symbols`` reads the delay-import directory and the load config's SafeSEH
and ``/guard:cf`` tables from raw image bytes rather than through LIEF, so a
crafted target binary reaches hand-written pointer chasing.  These tests build
a valid PE32 whose directory contents are drawn by hypothesis: pointers aimed
into the section (as VA or RVA), at arbitrary dwords, or at nothing.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import make_pe
from test_pe_symbols import (
    _DIR_DELAY_IMPORT,
    _DIR_LOAD_CONFIG,
    _LC_GUARD_CF_COUNT,
    _LC_GUARD_CF_TABLE,
    _LC_LENGTH,
    _LC_SECURITY_COOKIE,
    _LC_SEH_COUNT,
    _LC_SEH_TABLE,
    _LC_SIZE,
    IMAGE_BASE,
    TEXT_VA,
    _append_section,
    _patch_directory,
)

from rebrew.pe_symbols import PeDirectories, pe_directories, pe_symbols

#: Bytes of fuzzed section body; small enough that every walk ends quickly.
_BODY_SIZE = 256


_u32 = st.integers(min_value=0, max_value=0xFFFFFFFF)


def _pointer(section_rva: int) -> st.SearchStrategy[int]:
    """A dword field: an in-section VA or RVA, an ordinal-flagged value, or noise."""
    offset = st.one_of(
        st.sampled_from(_PREFIX_OFFSETS), st.integers(min_value=0, max_value=_BODY_SIZE + 8)
    )
    return st.one_of(
        offset.map(lambda o: IMAGE_BASE + section_rva + o),
        offset.map(lambda o: section_rva + o),
        st.integers(min_value=0, max_value=0xFFFF).map(lambda o: 0x80000000 | o),
        st.just(0),
        _u32,
    )


def _section_rva() -> int:
    """RVA the first appended section lands at in ``make_pe``'s layout."""
    _pe, rva, _raw = _append_section(_base_pe(), ".probe", b"\x00")
    return rva


def _base_pe() -> bytes:
    return make_pe(b"\x90" * 16, image_base=IMAGE_BASE, text_va=TEXT_VA)


_SECTION_RVA = _section_rva()

#: Delay-section prefix: a hint/name entry, a DLL name, and a name table (the
#: hint/name VA, ordinal 7, terminator), so drawn pointers often land on
#: readable structures and the walk reaches the per-slot code.
_PREFIX = b"\x00\x00FuzzApi\x00FUZZ.dll\x00\x00" + struct.pack(
    "<3I", IMAGE_BASE + _SECTION_RVA, 0x80000007, 0
)
_PREFIX_OFFSETS = (0, 10, 20)


@st.composite
def _section_body(draw: st.DrawFn) -> bytes:
    """Section bytes mixing section-aimed pointers, hint/name text and noise."""
    words = draw(st.lists(_pointer(_SECTION_RVA), max_size=_BODY_SIZE // 4))
    body = bytearray(struct.pack(f"<{len(words)}I", *words))
    for _ in range(draw(st.integers(min_value=0, max_value=4))):
        at = draw(st.integers(min_value=0, max_value=_BODY_SIZE - 1))
        text = draw(st.binary(max_size=24))
        body[at : at + len(text)] = text
    body = body[:_BODY_SIZE]
    return bytes(body) + b"\x00" * (_BODY_SIZE - len(body))


def _write(pe: bytes) -> PeDirectories:
    """Run both public readers on *pe*; return the directories after checking them."""
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / "fuzz.exe"
        path.write_bytes(pe)
        first = pe_directories(path)
        symbols = pe_symbols(path)
        assert pe_directories(path) == first  # deterministic
    assert all(isinstance(note, str) and note for note in first.notes)
    assert all(isinstance(note, str) for note in symbols.notes)
    return first


def _assert_mapped(table: PeDirectories, section_end: int) -> None:
    """Every reported address lies inside the image, never a fabricated one."""
    lo = IMAGE_BASE + TEXT_VA
    for va in (*table.safe_seh_handlers, *table.cfg_targets):
        assert lo <= va < section_end
    for record in table.delay_imports:
        assert lo <= record.va < section_end
        assert record.dll
        assert record.name or record.ordinal is not None
        assert record.ordinal is None or 0 <= record.ordinal <= 0xFFFF


@st.composite
def _delay_descriptors(draw: st.DrawFn) -> bytes:
    """One or two ``IMAGE_DELAYLOAD_DESCRIPTOR`` records with drawn fields.

    Fields usually follow the encoding the ``Attributes`` bit declares (RVA or
    VA) so the slot walk runs; any field may instead be an arbitrary pointer.
    """
    out = b""
    for _ in range(draw(st.integers(min_value=1, max_value=2))):
        rva_based = draw(st.booleans())
        base = _SECTION_RVA if rva_based else IMAGE_BASE + _SECTION_RVA
        declared = st.one_of(
            st.sampled_from(_PREFIX_OFFSETS),
            st.integers(min_value=len(_PREFIX), max_value=_BODY_SIZE),
        ).map(base.__add__)
        field = st.one_of(declared, _pointer(_SECTION_RVA))
        attributes = draw(st.one_of(st.just(int(rva_based)), _u32))
        name = draw(st.one_of(st.just(base + _PREFIX_OFFSETS[1]), field))
        iat, names = draw(field), draw(field)
        out += struct.pack("<8I", attributes, name, 0, iat, names, 0, 0, 0)
    return out


class TestDelayImportFuzz:
    @settings(max_examples=150, deadline=None)
    @given(_delay_descriptors(), _section_body())
    def test_fuzzed_delay_directory_never_raises(self, descriptors: bytes, tail: bytes) -> None:
        body = _PREFIX + descriptors + tail
        pe, rva, _raw = _append_section(_base_pe(), ".didata", body)
        assert rva == _SECTION_RVA
        pe = _patch_directory(pe, _DIR_DELAY_IMPORT, rva + len(_PREFIX), len(descriptors))
        table = _write(pe)
        _assert_mapped(table, IMAGE_BASE + rva + len(body))


class TestLoadConfigFuzz:
    @settings(max_examples=150, deadline=None)
    @given(
        _section_body(),
        _pointer(_SECTION_RVA),
        _pointer(_SECTION_RVA),
        _pointer(_SECTION_RVA),
        _u32,
        _u32,
    )
    def test_fuzzed_load_config_never_raises(
        self,
        body: bytes,
        seh_table: int,
        cfg_table: int,
        cookie: int,
        seh_count: int,
        cfg_count: int,
    ) -> None:
        config = bytearray(_LC_LENGTH)
        struct.pack_into("<I", config, _LC_SIZE, _LC_LENGTH)
        struct.pack_into("<I", config, _LC_SECURITY_COOKIE, cookie)
        struct.pack_into("<I", config, _LC_SEH_TABLE, seh_table)
        struct.pack_into("<I", config, _LC_SEH_COUNT, seh_count)
        struct.pack_into("<I", config, _LC_GUARD_CF_TABLE, cfg_table)
        struct.pack_into("<I", config, _LC_GUARD_CF_COUNT, cfg_count)
        pe, rva, _raw = _append_section(_base_pe(), ".rdata", body + bytes(config))
        pe = _patch_directory(pe, _DIR_LOAD_CONFIG, rva + len(body), _LC_LENGTH)
        table = _write(pe)
        _assert_mapped(table, IMAGE_BASE + rva + len(body) + _LC_LENGTH)
        assert len(table.safe_seh_handlers) <= seh_count
        assert len(table.cfg_targets) <= cfg_count
