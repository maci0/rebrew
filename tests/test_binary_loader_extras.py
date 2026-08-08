"""Tests for binary_loader.py internals — PE/ELF loaders and size guard."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import rebrew.binary_loader as bl


def _mock_section(
    name: str, va: int, vsize: int, raw_offset: int, raw_size: int
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        virtual_address=va,
        virtual_size=vsize,
        pointerto_raw_data=raw_offset,
        sizeof_raw_data=raw_size,
    )


def _mock_elf_section(name: str, va: int, size: int, offset: int) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        virtual_address=va,
        size=size,
        original_size=size,
        offset=offset,
    )


class TestLoadPe:
    def test_sections_and_text(self) -> None:
        pe = SimpleNamespace(
            optional_header=SimpleNamespace(imagebase=0x400000),
            sections=[
                _mock_section(".text", 0x1000, 0x200, 0x400, 0x200),
                _mock_section(".data", 0x2000, 0x100, 0x600, 0x100),
            ],
        )
        info = bl._load_pe(pe, Path("/tmp/x.exe"))
        assert info.format == "pe"
        assert info.image_base == 0x400000
        assert info.text_va == 0x401000
        assert info.text_size == 0x200
        assert info.text_raw_offset == 0x400
        assert info.sections[".text"].va == 0x401000
        assert info.sections[".data"].va == 0x402000

    def test_no_text_section(self) -> None:
        pe = SimpleNamespace(
            optional_header=SimpleNamespace(imagebase=0x400000),
            sections=[_mock_section(".data", 0x2000, 0x100, 0x600, 0x100)],
        )
        info = bl._load_pe(pe, Path("/tmp/x.exe"))
        assert info.text_va == 0x400000  # falls back to image base
        assert info.text_size == 0


class TestLoadElf:
    def test_sections_and_image_base(self) -> None:
        elf = SimpleNamespace(
            segments=[SimpleNamespace(type=1, virtual_address=0x1000)],  # PT_LOAD
            sections=[_mock_elf_section(".text", 0x1000, 0x200, 0x400)],
        )
        info = bl._load_elf(elf, Path("/tmp/x.so"))
        assert info.format == "elf"
        assert info.image_base == 0x1000  # lowest PT_LOAD VA
        assert info.text_va == 0x1000
        assert info.text_size == 0x200

    def test_load_segment_image_base(self) -> None:
        elf = SimpleNamespace(
            segments=[
                SimpleNamespace(type=2, virtual_address=0x1000),  # PT_DYNAMIC, not LOAD
                SimpleNamespace(type=1, virtual_address=0x5000),  # PT_LOAD
            ],
            sections=[],
        )
        info = bl._load_elf(elf, Path("/tmp/x.so"))
        assert info.image_base == 0x5000

    def test_empty_name_section_skipped(self) -> None:
        elf = SimpleNamespace(
            segments=[],
            sections=[SimpleNamespace(name="", virtual_address=0, size=0, offset=0)],
        )
        info = bl._load_elf(elf, Path("/tmp/x.so"))
        assert info.sections == {}


class TestBinaryInfoData:
    def test_oversized_file_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        f = tmp_path / "big.bin"
        f.write_bytes(b"\x00" * 16)
        info = bl.BinaryInfo(
            path=f,
            format="raw",
            image_base=0,
            text_va=0,
            text_size=0,
            text_raw_offset=0,
            sections={},
        )
        monkeypatch.setattr(bl, "_MAX_BINARY_SIZE", 4)  # 16-byte file exceeds 4
        with pytest.raises(ValueError, match="too large"):
            _ = info.data
