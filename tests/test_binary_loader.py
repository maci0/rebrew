"""Tests for rebrew.binary_loader — data classes and format detection."""

from pathlib import Path

import pytest

from rebrew.binary_loader import (
    BinaryInfo,
    SectionInfo,
    detect_format_and_arch,
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

    def test_data_lazy_load(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 100)
        info = BinaryInfo(path=f, format="pe")
        assert info._data is None
        data1 = info.data
        assert len(data1) == 100
        data2 = info.data
        assert data1 is data2  # cached, not reloaded

    def test_sections_default_empty(self) -> None:
        info = BinaryInfo(path=Path("/tmp/test"), format="pe")
        assert info.sections == {}


# -------------------------------------------------------------------------
# extract_bytes_at_va
# -------------------------------------------------------------------------


class TestExtractBytesAtVa:
    def test_basic_extraction(self, tmp_path: Path) -> None:
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

    def test_clamps_to_raw_size(self, tmp_path: Path) -> None:
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
        assert len(result) == 0x100  # clamped to raw_size

    def test_trim_padding_default(self, tmp_path: Path) -> None:
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

    def test_trim_padding_false_preserves_bytes(self, tmp_path: Path) -> None:
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

    def test_va_not_in_section(self, tmp_path: Path) -> None:
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
# detect_format_and_arch
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
        fmt, arch = detect_format_and_arch(f)
        assert fmt == "pe"

    def test_elf(self, tmp_path: Path) -> None:
        f = tmp_path / "test.elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        fmt, arch = detect_format_and_arch(f)
        assert fmt == "elf"

    def test_unknown(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 100)
        with pytest.raises(ValueError):
            detect_format_and_arch(f)


# ---------------------------------------------------------------------------
# load_binary bounded cache
# ---------------------------------------------------------------------------


class TestLoadBinaryCache:
    def setup_method(self) -> None:
        from rebrew.binary_loader import _load_binary_cache

        _load_binary_cache.clear()

    def teardown_method(self) -> None:
        from rebrew.binary_loader import _load_binary_cache

        _load_binary_cache.clear()

    def test_cache_hit(self, tmp_path: Path) -> None:
        from rebrew.binary_loader import load_binary

        f = _make_pe_stub(tmp_path / "test.exe")
        info1 = load_binary(f)
        info2 = load_binary(f)
        assert info1 is info2

    def test_cache_stores_entry(self, tmp_path: Path) -> None:
        from rebrew.binary_loader import _load_binary_cache, load_binary

        f = _make_pe_stub(tmp_path / "test.exe")
        load_binary(f)
        assert len(_load_binary_cache) == 1

    def test_cache_eviction(self, tmp_path: Path) -> None:
        from rebrew.binary_loader import _LOAD_BINARY_CACHE_MAX, _load_binary_cache, load_binary

        paths = []
        for i in range(_LOAD_BINARY_CACHE_MAX):
            p = _make_pe_stub(tmp_path / f"test_{i}.exe")
            paths.append(p)
            load_binary(p)
        assert len(_load_binary_cache) == _LOAD_BINARY_CACHE_MAX
        overflow = _make_pe_stub(tmp_path / "overflow.exe")
        load_binary(overflow)
        assert len(_load_binary_cache) == _LOAD_BINARY_CACHE_MAX
        first_key = (str(paths[0].resolve()), "auto")
        assert first_key not in _load_binary_cache
        overflow_key = (str(overflow.resolve()), "auto")
        assert overflow_key in _load_binary_cache


class TestMalformedInputRobustness:
    """Arbitrary bytes must never crash load_binary — a clean ValueError /
    FileNotFoundError, or a usable BinaryInfo (LIEF leniency on partial
    headers)."""

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"\x00" * 64,
            b"\xff" * 64,
            b"MZ" + b"\x00" * 62,
            b"\x7fELF" + b"\x00" * 60,
            b"PK\x03\x04" + b"\x00" * 60,
            b"<html><body>not a binary</body></html>",
        ],
    )
    def test_garbage_bytes_no_crash(self, tmp_path: Path, data: bytes) -> None:
        from rebrew.binary_loader import load_binary

        p = tmp_path / "garbage.bin"
        p.write_bytes(data)
        try:
            info = load_binary(p)
        except (ValueError, FileNotFoundError):
            return  # clean rejection is the expected path for most garbage
        # LIEF may tolerate partial headers — the result must be usable.
        assert isinstance(info, BinaryInfo)
        # Touching the basic fields must not raise.
        _ = info.sections

    def test_hypothesis_random_bytes_no_crash(self, tmp_path: Path) -> None:
        """Property: random bytes (incl. truncated PE/ELF/Mach-O headers)
        never crash load_binary."""
        from hypothesis import given, settings
        from hypothesis import strategies as st

        from rebrew.binary_loader import load_binary

        @given(st.binary(min_size=0, max_size=512))
        @settings(max_examples=100, deadline=None)
        def _probe(data: bytes) -> None:
            p = tmp_path / f"fuzz_{len(data)}.bin"
            p.write_bytes(data)
            try:
                info = load_binary(p)
            except (ValueError, FileNotFoundError):
                return
            assert isinstance(info, BinaryInfo)
            _ = info.sections

        _probe()


class TestNEDetection:
    """16-bit Windows NE executables are detected and parsed natively
    (Borland Delphi / Turbo Pascal Windows targets)."""

    @staticmethod
    def _write_ne(tmp_path: Path, e_lfanew: int = 0x100) -> Path:
        p = tmp_path / "sixteen.ne"
        data = bytearray(0x200)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = e_lfanew.to_bytes(4, "little")
        data[e_lfanew : e_lfanew + 2] = b"NE"
        p.write_bytes(bytes(data))
        return p

    def test_is_ne_recognizes_mz_ne(self, tmp_path: Path) -> None:
        from rebrew.binary_loader import is_ne

        assert is_ne(self._write_ne(tmp_path)) is True
        assert is_ne(tmp_path / "missing.bin") is False

    def test_is_ne_rejects_pe(self, tmp_path: Path) -> None:
        from rebrew.binary_loader import is_ne

        pe = tmp_path / "real_pe.exe"
        pe.write_bytes(b"MZ" + b"\x00" * 0x40 + b"\x00" * 0x40 + b"PE\x00\x00")
        assert is_ne(pe) is False

    def test_load_binary_parses_ne(self, tmp_path: Path) -> None:
        """A minimal NE loads as format='ne' with parsed tables (the old
        behavior rejected NE outright — the 16-bit path is now supported)."""
        from rebrew.binary_loader import BinaryInfo, load_binary

        ne = self._write_ne(tmp_path)
        info = load_binary(ne)
        assert isinstance(info, BinaryInfo)
        assert info.format == "ne"
        assert info.sections == {}


class TestFunctionExtentFromDisasm:
    """function_extent_from_disasm finds the authoritative function end —
    the disassembly terminator — independent of discovery-derived sizes."""

    def _run(self, monkeypatch, text: bytes, tmp_path: Path) -> int | None:
        from types import SimpleNamespace as NS

        import rebrew.binary_loader as bl

        exe = tmp_path / "x.exe"
        exe.write_bytes(b"MZ" + text)
        monkeypatch.setattr(
            bl,
            "load_binary",
            lambda *a, **k: NS(text_va=0x1000, text_size=len(text), data=text),
        )
        monkeypatch.setattr(
            bl,
            "extract_bytes_at_va",
            lambda info, va, size, trim_padding=True: text[:size],
        )
        return bl.function_extent_from_disasm(exe, 0x1000)

    def test_thunk_ends_at_tail_jmp(self, monkeypatch, tmp_path: Path) -> None:
        # mov ecx,0x103d9d8; jmp 0x1014469  → 10 bytes
        text = bytes.fromhex("b9 d8 d9 03 01 e9 8a 0f 00 00")
        assert self._run(monkeypatch, text, tmp_path) == 10

    def test_plain_function_ends_at_ret(self, monkeypatch, tmp_path: Path) -> None:
        # mov eax,[esp+4]; push 1; push eax; call; add esp,8; ret → 16 bytes
        text = bytes.fromhex("8b 44 24 04 6a 01 50 e8 00 00 00 00 83 c4 08 c3")
        assert self._run(monkeypatch, text, tmp_path) == 16

    def test_ret_n_terminator(self, monkeypatch, tmp_path: Path) -> None:
        # mov eax,[esp+4]; mov [g],eax; ret 4 → 12 bytes (0x103da20)
        text = bytes.fromhex("8b 44 24 04 a3 20 da 03 01 c2 04 00")
        assert self._run(monkeypatch, text, tmp_path) == 12

    def test_conditional_branch_continues_to_ret(self, monkeypatch, tmp_path: Path) -> None:
        # cmp [esp+4],0 (5); je +2 (2); mov eax,1 (5); ret (1) → 13 bytes
        text = bytes.fromhex("83 7c 24 04 00 74 02 b8 01 00 00 00 c3")
        assert self._run(monkeypatch, text, tmp_path) == 13

    def test_int3_padding_terminates(self, monkeypatch, tmp_path: Path) -> None:
        text = bytes.fromhex("c3 cc cc cc")
        assert self._run(monkeypatch, text, tmp_path) == 1

    def test_unterminated_returns_none(self, monkeypatch, tmp_path: Path) -> None:
        text = bytes.fromhex("90 90 90 90")
        assert self._run(monkeypatch, text, tmp_path) is None
