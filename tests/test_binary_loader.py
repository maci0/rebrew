"""Tests for rebrew.binary_loader — data classes and format detection."""

from pathlib import Path

import pytest

from rebrew.binary_loader import (
    BinaryInfo,
    SectionInfo,
    _detect_format,
    extract_bytes_at_va,
    va_to_file_offset,
)

# -------------------------------------------------------------------------
# SectionInfo
# -------------------------------------------------------------------------


class TestSectionInfo:
    def test_creation(self) -> None:
        s = SectionInfo(name=".text", va=0x1000, size=0x2000, file_offset=0x400, raw_size=0x2000)
        assert s.name == ".text"
        assert s.va == 0x1000
        assert s.size == 0x2000
        assert s.file_offset == 0x400
        assert s.raw_size == 0x2000


# -------------------------------------------------------------------------
# BinaryInfo
# -------------------------------------------------------------------------


class TestBinaryInfo:
    def test_creation(self) -> None:
        info = BinaryInfo(
            path=Path("/tmp/test.exe"),
            format="pe",
            image_base=0x10000000,
            text_va=0x10001000,
            text_size=0x5000,
            text_raw_offset=0x400,
        )
        assert info.format == "pe"
        assert info.image_base == 0x10000000

    def test_data_lazy_load(self, tmp_path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 100)
        info = BinaryInfo(path=f, format="pe")
        assert info._data is None
        data = info.data
        assert len(data) == 100

    def test_sections_default_empty(self) -> None:
        info = BinaryInfo(path=Path("/tmp/test"), format="pe")
        assert info.sections == {}


# -------------------------------------------------------------------------
# extract_bytes_at_va
# -------------------------------------------------------------------------


class TestExtractBytesAtVa:
    def test_basic_extraction(self, tmp_path) -> None:
        # Create a fake binary with known bytes
        f = tmp_path / "test.bin"
        content = b"\x00" * 0x400 + b"\xab\xcd\xef\x12" + b"\x00" * 100
        f.write_bytes(content)

        info = BinaryInfo(
            path=f,
            format="pe",
            image_base=0x10000000,
            text_va=0x10001000,
            text_size=0x1000,
            text_raw_offset=0x400,
            sections={
                ".text": SectionInfo(
                    name=".text", va=0x10001000, size=0x1000, file_offset=0x400, raw_size=0x1000
                )
            },
        )
        result = extract_bytes_at_va(info, 0x10001000, 4)
        assert result is not None
        assert len(result) == 4
        assert result == b"\xab\xcd\xef\x12"

    def test_clamps_to_raw_size(self, tmp_path) -> None:
        """extract_bytes_at_va should not read beyond section raw_size."""
        f = tmp_path / "test.bin"
        # 0x400 bytes of header + 0x100 bytes of real section data + sentinel
        content = b"\x00" * 0x400 + b"\xaa" * 0x100 + b"\xbb" * 0x100
        f.write_bytes(content)

        info = BinaryInfo(
            path=f,
            format="pe",
            image_base=0x10000000,
            text_va=0x10001000,
            text_size=0x1000,  # virtual size much larger than raw
            text_raw_offset=0x400,
            sections={
                ".text": SectionInfo(
                    name=".text", va=0x10001000, size=0x1000, file_offset=0x400, raw_size=0x100
                )
            },
        )
        # Request 0x200 bytes but only 0x100 of raw data available
        result = extract_bytes_at_va(info, 0x10001000, 0x200)
        assert result is not None
        assert len(result) <= 0x100  # clamped to raw_size

    def test_trim_padding_default(self, tmp_path) -> None:
        """Default behavior strips trailing 0xCC/0x90 padding bytes."""
        f = tmp_path / "test.bin"
        # 4 real bytes + 4 INT3 padding bytes
        content = b"\x00" * 0x400 + b"\x55\x8b\xec\xc3" + b"\xcc" * 4
        f.write_bytes(content)

        info = BinaryInfo(
            path=f,
            format="pe",
            image_base=0x10000000,
            text_va=0x10001000,
            text_size=0x1000,
            text_raw_offset=0x400,
            sections={
                ".text": SectionInfo(
                    name=".text", va=0x10001000, size=0x1000, file_offset=0x400, raw_size=0x1000
                )
            },
        )
        result = extract_bytes_at_va(info, 0x10001000, 8)
        assert result is not None
        assert result == b"\x55\x8b\xec\xc3"  # padding stripped

    def test_trim_padding_false_preserves_bytes(self, tmp_path) -> None:
        """trim_padding=False returns exact bytes including trailing padding.

        Regression test for Phase 1 fix: callers doing byte-level scoring
        need exact fidelity, not trimmed output.
        """
        f = tmp_path / "test.bin"
        content = b"\x00" * 0x400 + b"\x55\x8b\xec\xc3" + b"\xcc" * 4
        f.write_bytes(content)

        info = BinaryInfo(
            path=f,
            format="pe",
            image_base=0x10000000,
            text_va=0x10001000,
            text_size=0x1000,
            text_raw_offset=0x400,
            sections={
                ".text": SectionInfo(
                    name=".text", va=0x10001000, size=0x1000, file_offset=0x400, raw_size=0x1000
                )
            },
        )
        result = extract_bytes_at_va(info, 0x10001000, 8, trim_padding=False)
        assert result is not None
        assert len(result) == 8
        assert result == b"\x55\x8b\xec\xc3" + b"\xcc" * 4  # padding preserved

    def test_va_not_in_section(self, tmp_path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 100)
        info = BinaryInfo(
            path=f,
            format="pe",
            image_base=0x10000000,
            text_va=0x10001000,
            text_size=0x10,
            text_raw_offset=0x10,
        )
        # VA way outside known sections
        result = extract_bytes_at_va(info, 0x90000000, 4)
        assert result is None


# -------------------------------------------------------------------------
# va_to_file_offset
# -------------------------------------------------------------------------


class TestVaToFileOffset:
    def test_basic(self) -> None:
        info = BinaryInfo(
            path=Path("/tmp/test"),
            format="pe",
            image_base=0x10000000,
            text_va=0x10001000,
            text_size=0x5000,
            text_raw_offset=0x400,
            sections={
                ".text": SectionInfo(
                    name=".text", va=0x10001000, size=0x5000, file_offset=0x400, raw_size=0x5000
                )
            },
        )
        offset = va_to_file_offset(info, 0x10001000)
        assert offset == 0x400

    def test_with_offset(self) -> None:
        info = BinaryInfo(
            path=Path("/tmp/test"),
            format="pe",
            image_base=0x10000000,
            text_va=0x10001000,
            text_size=0x5000,
            text_raw_offset=0x400,
            sections={
                ".text": SectionInfo(
                    name=".text", va=0x10001000, size=0x5000, file_offset=0x400, raw_size=0x5000
                )
            },
        )
        offset = va_to_file_offset(info, 0x10001100)
        assert offset == 0x500


# -------------------------------------------------------------------------
# _detect_format
# -------------------------------------------------------------------------


def _make_pe_stub(path: Path, machine: int = 0x14C) -> Path:
    """Build a minimal PE file that LIEF recognises (MZ + PE signature)."""
    import struct

    buf = bytearray(256)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 60, 128)  # e_lfanew
    buf[128:132] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 132, machine)
    struct.pack_into("<H", buf, 148, 96)  # SizeOfOptionalHeader
    struct.pack_into("<H", buf, 152, 0x10B)  # PE32
    path.write_bytes(bytes(buf))
    return path


class TestDetectFormat:
    def test_pe(self, tmp_path: Path) -> None:
        f = _make_pe_stub(tmp_path / "test.exe")
        assert _detect_format(f) == "pe"

    def test_elf(self, tmp_path: Path) -> None:
        f = tmp_path / "test.elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        assert _detect_format(f) == "elf"

    def test_macho_32(self, tmp_path: Path) -> None:
        f = tmp_path / "test.macho"
        f.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        assert _detect_format(f) == "macho"

    def test_macho_64(self, tmp_path: Path) -> None:
        f = tmp_path / "test.macho"
        f.write_bytes(b"\xfe\xed\xfa\xcf" + b"\x00" * 100)
        assert _detect_format(f) == "macho"

    def test_macho_fat(self, tmp_path: Path) -> None:
        f = tmp_path / "test.macho"
        f.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 100)
        assert _detect_format(f) == "macho"

    def test_macho_fat_cigam(self, tmp_path: Path) -> None:
        f = tmp_path / "test.macho"
        f.write_bytes(b"\xbe\xba\xfe\xca" + b"\x00" * 100)
        assert _detect_format(f) == "macho"

    def test_unknown(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 100)
        with pytest.raises(ValueError):
            _detect_format(f)
