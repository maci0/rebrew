"""Tests for catalog/sections.py — section parsing, globals scan, x86 utils."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.catalog.sections import (
    get_globals,
    get_text_section_size,
    has_back_jumps,
    trim_trailing_padding,
)


class TestTrimTrailingPadding:
    def test_strips_padding(self) -> None:
        assert trim_trailing_padding(b"\x55\x89\xe5\xcc\xcc") == 3

    def test_all_padding(self) -> None:
        assert trim_trailing_padding(b"\xcc\xcc\xcc") == 0

    def test_no_padding(self) -> None:
        assert trim_trailing_padding(b"\x55") == 1

    def test_empty(self) -> None:
        assert trim_trailing_padding(b"") == 0


class TestHasBackJumps:
    def test_near_jmp_back_into_range(self) -> None:
        # E9 rel=-5 at offset 0 with base 0x1000 → target 0x1000 (in range).
        assert has_back_jumps(b"\xe9\xfb\xff\xff\xff", 0x1000, 0x1005, 0x1000) is True

    def test_short_jmp_forward_out_of_range(self) -> None:
        # EB rel=+0 → target 0x1002 (outside [0x1000, 0x1001)).
        assert has_back_jumps(b"\xeb\x00", 0x1000, 0x1001, 0x1000) is False

    def test_near_jcc_back_into_range(self) -> None:
        # 0F 85 rel=-6 at offset 0 with base 0x1000 → target 0x1000.
        assert has_back_jumps(b"\x0f\x85\xfa\xff\xff\xff", 0x1000, 0x1006, 0x1000) is True

    def test_short_jcc_back_into_range(self) -> None:
        # 75 rel=-2 → target base+0+2-2 = base.
        assert has_back_jumps(b"\x75\xfe", 0x1000, 0x1002, 0x1000) is True

    def test_no_jumps(self) -> None:
        assert has_back_jumps(b"\x55\x89\xe5", 0x1000, 0x1003, 0x1000) is False


class TestGetTextSectionSize:
    def test_returns_text_size(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.binary_loader.load_binary",
            lambda _p: SimpleNamespace(text_size=0x1234),
        )
        assert get_text_section_size(Path("/tmp/fake.dll")) == 0x1234

    def test_failure_returns_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.binary_loader.load_binary",
            lambda _p: (_ for _ in ()).throw(RuntimeError("bad")),
        )
        assert get_text_section_size(Path("/tmp/nope.dll")) == 0


class TestGetGlobals:
    def _scan(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, src: str) -> dict[int, dict]:
        f = tmp_path / "data.c"
        f.write_text(src, encoding="utf-8")
        monkeypatch.setattr("rebrew.catalog.sections.iter_sources", lambda _d, _c: [f])
        return get_globals(tmp_path)

    def test_int_global(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        globals_dict = self._scan(
            tmp_path, monkeypatch, "// GLOBAL: SERVER 0x10001000\nint g_counter;\n"
        )
        assert globals_dict[0x10001000]["name"] == "g_counter"
        assert globals_dict[0x10001000]["module"] == "SERVER"
        assert globals_dict[0x10001000]["size"] == 4

    def test_char_array_global(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        globals_dict = self._scan(
            tmp_path, monkeypatch, "// GLOBAL: SERVER 0x10002000\nchar g_name[32];\n"
        )
        assert globals_dict[0x10002000]["name"] == "g_name"
        assert globals_dict[0x10002000]["size"] == 32

    def test_short_and_double_sizes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        src = (
            "// GLOBAL: SERVER 0x10003000\nshort g_s;\n// GLOBAL: SERVER 0x10004000\ndouble g_d;\n"
        )
        globals_dict = self._scan(tmp_path, monkeypatch, src)
        assert globals_dict[0x10003000]["size"] == 2
        assert globals_dict[0x10004000]["size"] == 8

    def test_duplicate_va_merges_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        f1 = tmp_path / "a.c"
        f2 = tmp_path / "b.c"
        f1.write_text("// GLOBAL: SERVER 0x10005000\nint g;\n", encoding="utf-8")
        f2.write_text("// GLOBAL: SERVER 0x10005000\n", encoding="utf-8")
        monkeypatch.setattr("rebrew.catalog.sections.iter_sources", lambda _d, _c: [f1, f2])
        globals_dict = get_globals(tmp_path)
        assert sorted(globals_dict[0x10005000]["files"]) == ["a.c", "b.c"]

    def test_missing_decl_defaults_unknown(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        globals_dict = self._scan(tmp_path, monkeypatch, "// GLOBAL: GAME 0x10006000\n")
        assert globals_dict[0x10006000]["name"] == "unknown"
        assert globals_dict[0x10006000]["size"] == 4


class TestBackJumpsForward:
    def test_near_jmp_forward_out_of_range(self) -> None:
        from rebrew.catalog.sections import has_back_jumps

        # E9 rel32 jmp far forward → target 0x1060+5+0x100=0x1165 (outside range)
        data = b"\xe9\x00\x01\x00\x00"
        assert has_back_jumps(data, 0x1060, 0x1080, base_offset=0x1060) is False

    def test_near_jcc_forward_out_of_range(self) -> None:
        from rebrew.catalog.sections import has_back_jumps

        # 0F 85 rel32 = jnz far forward → target outside the range
        data = b"\x0f\x85\x00\x01\x00\x00"
        assert has_back_jumps(data, 0x1060, 0x1080, base_offset=0x1060) is False


class TestGetGlobalsSizes:
    def _scan(self, tmp_path: Path, decl: str) -> dict:
        from rebrew.catalog.sections import get_globals

        p = tmp_path / "g.c"
        p.write_text(f"// GLOBAL: SERVER 0x1000\n{decl}\n", encoding="utf-8")
        return get_globals(tmp_path)

    def test_char_array_size(self, tmp_path: Path) -> None:
        globals_dict = self._scan(tmp_path, "extern char g_buf[16];")
        assert globals_dict[0x1000]["size"] == 16

    def test_short_size(self, tmp_path: Path) -> None:
        globals_dict = self._scan(tmp_path, "extern short g_s;")
        assert globals_dict[0x1000]["size"] == 2

    def test_char_size(self, tmp_path: Path) -> None:
        globals_dict = self._scan(tmp_path, "extern char g_c;")
        assert globals_dict[0x1000]["size"] == 1

    def test_double_size(self, tmp_path: Path) -> None:
        globals_dict = self._scan(tmp_path, "extern double g_d;")
        assert globals_dict[0x1000]["size"] == 8

    def test_default_pointer_size(self, tmp_path: Path) -> None:
        globals_dict = self._scan(tmp_path, "extern int g_i;")
        assert globals_dict[0x1000]["size"] == 4


class TestSectionsFromInfo:
    """The .data → .data + .bss split mirrors the loader's BSS model."""

    @staticmethod
    def _info(**sections: object) -> Any:
        from rebrew.binary_loader import BinaryInfo, SectionInfo

        info = BinaryInfo(path=Path("/fake/x.dll"), format="pe")
        for name, (va, size, raw, off) in sections.items():  # type: ignore[union-attr]
            info.sections[name] = SectionInfo(
                name=name, va=va, size=size, file_offset=off, raw_size=raw
            )
        return info

    def test_data_without_bss_tail_passes_through(self) -> None:
        from rebrew.catalog.sections import sections_from_info

        info = self._info(
            **{".text": (0x1000, 0x40, 0x40, 0x400), ".data": (0x2000, 0x20, 0x20, 0x800)}
        )
        sections = sections_from_info(info)
        assert set(sections) == {".text", ".data"}
        assert sections[".data"] == {"va": 0x2000, "size": 0x20, "fileOffset": 0x800}

    def test_data_splits_bss_zero_fill_tail(self) -> None:
        from rebrew.catalog.sections import sections_from_info

        # raw 0x10 of 0x30 virtual: 0x20 zero-fill tail becomes .bss.
        info = self._info(**{".data": (0x2000, 0x30, 0x10, 0x800)})
        sections = sections_from_info(info)
        assert sections[".data"] == {"va": 0x2000, "size": 0x10, "fileOffset": 0x800}
        assert sections[".bss"] == {"va": 0x2010, "size": 0x20, "fileOffset": 0}

    def test_raw_larger_than_virtual_never_splits(self) -> None:
        from rebrew.catalog.sections import sections_from_info

        info = self._info(**{".data": (0x2000, 0x10, 0x30, 0x800)})
        assert set(sections_from_info(info)) == {".data"}
