"""Tests for the synthetic ELF fixture (tests/bin_util.make_elf)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import make_elf

from rebrew.binary_loader import load_binary
from rebrew.catalog.sections import sections_from_info

CODE = b"\x55\x8b\xec\x5d\xc3\x90" * 8


class TestMakeElf:
    def test_load_binary_roundtrip(self, tmp_path: Path) -> None:
        path = tmp_path / "game.elf"
        path.write_bytes(make_elf(CODE))
        info = load_binary(path)
        assert info.format == "elf"
        assert info.image_base == 0x8048000
        assert info.text_va == 0x8049000
        assert info.text_size == len(CODE)
        assert info.text_raw_offset == 0x1000

    def test_sections_from_info(self, tmp_path: Path) -> None:
        path = tmp_path / "game.elf"
        path.write_bytes(make_elf(CODE))
        sections = sections_from_info(load_binary(path))
        assert sections[".text"] == {
            "va": 0x8049000,
            "size": len(CODE),
            "fileOffset": 0x1000,
        }

    def test_custom_layout(self, tmp_path: Path) -> None:
        path = tmp_path / "game.elf"
        path.write_bytes(make_elf(CODE, image_base=0x1000, text_va=0x2000, text_offset=0x400))
        info = load_binary(path)
        assert info.image_base == 0x1000
        assert info.text_va == 0x2000
        assert info.text_raw_offset == 0x400

    def test_deterministic(self) -> None:
        assert make_elf(CODE) == make_elf(CODE)

    def test_pe_fixture_unaffected(self, tmp_path: Path) -> None:
        """The existing PE builder still round-trips unchanged."""
        from bin_util import make_pe

        path = tmp_path / "game.exe"
        path.write_bytes(make_pe(CODE))
        info = load_binary(path)
        assert info.format == "pe"
        assert info.text_va == 0x401000
