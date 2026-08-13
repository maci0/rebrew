"""Tests for binary_loader — Mach-O loader, load_binary fmt dispatch, language detection."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import rebrew.binary_loader as bl


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


class TestLoadMacho:
    def test_thin_binary(self, tmp_path: Path) -> None:
        macho = SimpleNamespace(
            segments=[
                SimpleNamespace(name="__TEXT", virtual_address=0x1000),
                SimpleNamespace(name="__DATA", virtual_address=0x2000),
            ],
            sections=[
                SimpleNamespace(
                    segment_name="__TEXT",
                    name="__text",
                    virtual_address=0x1000,
                    size=0x200,
                    offset=0x400,
                ),
                SimpleNamespace(
                    segment_name="",
                    name="__cstring",
                    virtual_address=0x1200,
                    size=0x10,
                    offset=0x600,
                ),
            ],
        )
        info = bl._load_macho(macho, tmp_path / "x")  # type: ignore[arg-type]
        assert info.format == "macho"
        assert info.image_base == 0x1000
        assert info.text_va == 0x1000
        assert info.text_size == 0x200
        assert "__TEXT.__text" in info.sections
        assert "__cstring" in info.sections  # empty segment name → bare section name

    def test_no_text_section(self, tmp_path: Path) -> None:
        macho = SimpleNamespace(
            segments=[SimpleNamespace(name="__DATA", virtual_address=0x2000)],
            sections=[
                SimpleNamespace(
                    segment_name="__DATA", name="__data", virtual_address=0x2000, size=8, offset=0
                )
            ],
        )
        info = bl._load_macho(macho, tmp_path / "x")  # type: ignore[arg-type]
        assert info.text_size == 0


class TestLoadBinaryFmtDispatch:
    def setup_method(self) -> None:
        bl._load_binary_cache.clear()
        bl._iat_slot_cache.clear()

    def teardown_method(self) -> None:
        bl._load_binary_cache.clear()
        bl._iat_slot_cache.clear()

    def test_fmt_pe(self, tmp_path: Path) -> None:
        f = _make_pe_stub(tmp_path / "x.exe")
        info = bl.load_binary(f, fmt="pe")
        assert info.format == "pe"

    def test_fmt_elf(self, tmp_path: Path) -> None:
        f = tmp_path / "x.elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        info = bl.load_binary(f, fmt="elf")
        assert info.format == "elf"

    def test_fmt_macho_parse_failure(self, tmp_path: Path) -> None:
        f = tmp_path / "x.macho"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)  # not a Mach-O
        with pytest.raises(ValueError, match="Failed to parse Mach-O"):
            bl.load_binary(f, fmt="macho")

    def test_unknown_fmt(self, tmp_path: Path) -> None:
        f = tmp_path / "x.bin"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        with pytest.raises(ValueError, match="(Unknown binary format|invalid MZ header)"):
            bl.load_binary(f, fmt="wat")

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            bl.load_binary(tmp_path / "nope.exe")


class TestDetectSourceLanguage:
    def _bin(self, tmp_path: Path) -> Path:
        f = tmp_path / "x.bin"
        f.write_bytes(b"\x00" * 16)
        return f

    def _patch_lief(self, monkeypatch: pytest.MonkeyPatch, fake: object) -> None:
        monkeypatch.setattr(bl.lief, "parse", lambda *a, **k: fake)

    def test_missing_file(self, tmp_path: Path) -> None:
        assert bl.detect_source_language(tmp_path / "nope") == ("C", ".c")

    def test_parse_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_lief(monkeypatch, None)
        assert bl.detect_source_language(self._bin(tmp_path)) == ("C", ".c")

    def test_parse_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(*a: object, **k: object) -> object:
            raise OSError("bad")

        monkeypatch.setattr(bl.lief, "parse", _boom)
        assert bl.detect_source_language(self._bin(tmp_path)) == ("C", ".c")

    def test_go_sections(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = SimpleNamespace(
            sections=[SimpleNamespace(name=".gopclntab")], symbols=[], exported_functions=[]
        )
        self._patch_lief(monkeypatch, fake)
        assert bl.detect_source_language(self._bin(tmp_path)) == ("Go", ".go")

    def test_objc_sections(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = SimpleNamespace(
            sections=[SimpleNamespace(name="__objc_selrefs")], symbols=[], exported_functions=[]
        )
        self._patch_lief(monkeypatch, fake)
        assert bl.detect_source_language(self._bin(tmp_path)) == ("Objective-C", ".m")

    def test_go_symbols(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = SimpleNamespace(
            sections=[],
            symbols=[SimpleNamespace(name="go.foo")] * 3,
            exported_functions=[],
        )
        self._patch_lief(monkeypatch, fake)
        assert bl.detect_source_language(self._bin(tmp_path)) == ("Go", ".go")

    def test_rust_symbols(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = SimpleNamespace(
            sections=[],
            symbols=[SimpleNamespace(name="_RNvC")] * 3,
            exported_functions=[],
        )
        self._patch_lief(monkeypatch, fake)
        assert bl.detect_source_language(self._bin(tmp_path)) == ("Rust", ".rs")

    def test_d_symbols(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = SimpleNamespace(
            sections=[],
            symbols=[SimpleNamespace(name="_D3foo")] * 3,
            exported_functions=[],
        )
        self._patch_lief(monkeypatch, fake)
        assert bl.detect_source_language(self._bin(tmp_path)) == ("D", ".d")

    def test_cpp_msvc_symbols(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = SimpleNamespace(
            sections=[],
            symbols=[SimpleNamespace(name="?foo@bar@@")] * 3,
            exported_functions=[],
        )
        self._patch_lief(monkeypatch, fake)
        assert bl.detect_source_language(self._bin(tmp_path)) == ("C++", ".cpp")

    def test_cpp_itanium_symbols(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = SimpleNamespace(
            sections=[],
            symbols=[SimpleNamespace(name="_Z3foov")] * 3,
            exported_functions=[],
        )
        self._patch_lief(monkeypatch, fake)
        assert bl.detect_source_language(self._bin(tmp_path)) == ("C++", ".cpp")

    def test_c_fallback(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = SimpleNamespace(
            sections=[],
            symbols=[SimpleNamespace(name="plain_func")],
            exported_functions=[SimpleNamespace(name="exported")],
        )
        self._patch_lief(monkeypatch, fake)
        assert bl.detect_source_language(self._bin(tmp_path)) == ("C", ".c")

    def test_section_collection_error_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _BadSections:
            @property
            def sections(self) -> object:
                raise AttributeError("no sections")

        fake = _BadSections()
        self._patch_lief(monkeypatch, fake)
        assert bl.detect_source_language(self._bin(tmp_path)) == ("C", ".c")
