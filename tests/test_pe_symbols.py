"""Tests for pe_symbols.py: PE data directories as records and symbol names."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import append_pe_section, make_pe

from rebrew.pe_symbols import (
    delay_import_symbol_name,
    iat_symbol_name,
    pe_directories,
    pe_symbols,
)

FIXTURES = Path(__file__).parent / "fixtures"
MINI_PE = FIXTURES / "mini_pe.exe"

IMAGE_BASE = 0x400000
TEXT_VA = 0x1000

# Optional-header field offsets, relative to the start of the optional header.
_DATA_DIRECTORIES = 0x60
_DATA_DIRECTORY_ENTRY = 8
_FILE_ALIGNMENT = 0x24

# Data directory indices (winnt.h order).
_DIR_LOAD_CONFIG = 10
_DIR_DELAY_IMPORT = 13

# IMAGE_LOAD_CONFIG_DIRECTORY32 field offsets, for the minimal layout below.
_LC_SIZE = 0x00
_LC_SECURITY_COOKIE = 0x3C
_LC_SEH_TABLE = 0x40
_LC_SEH_COUNT = 0x44
_LC_GUARD_CF_TABLE = 0x50
_LC_GUARD_CF_COUNT = 0x54
_LC_LENGTH = 0x5C


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _append_section(pe: bytes, name: str, data: bytes) -> tuple[bytes, int, int]:
    """Append a file-aligned section; returns ``(pe, rva, raw_offset)``.

    ``bin_util.append_pe_section`` declares a file-aligned ``SizeOfRawData``
    but writes only the bytes it is given, leaving the file shorter than the
    section declares; the container readers then refuse the read as truncated.
    This pads the raw data and reports where the section landed, so a fixture
    whose content depends on its own address can be patched in place.
    """
    lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    file_align = struct.unpack_from("<I", pe, lfanew + 24 + _FILE_ALIGNMENT)[0]
    padded = data + b"\x00" * (-len(data) % file_align)
    out = append_pe_section(pe, name, padded)
    lfanew = struct.unpack_from("<I", out, 0x3C)[0]
    count = struct.unpack_from("<H", out, lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", out, lfanew + 20)[0]
    header = lfanew + 24 + opt_size + (count - 1) * 40
    rva = struct.unpack_from("<I", out, header + 12)[0]
    raw_offset = struct.unpack_from("<I", out, header + 20)[0]
    return out, rva, raw_offset


def _patch_directory(pe: bytes, index: int, rva: int, size: int) -> bytes:
    """Point data directory *index* at ``(rva, size)``."""
    out = bytearray(pe)
    lfanew = struct.unpack_from("<I", out, 0x3C)[0]
    offset = lfanew + 24 + _DATA_DIRECTORIES + index * _DATA_DIRECTORY_ENTRY
    struct.pack_into("<II", out, offset, rva, size)
    return bytes(out)


def _load_config_pe(tmp_path: Path) -> tuple[Path, list[int], list[int], int]:
    """A PE32 whose load config names a cookie, SafeSEH handlers and CFG targets.

    Returns the path plus the handler VAs, the CFG target VAs and the cookie
    VA the fixture stored, so a test can assert the reader recovered exactly
    the addresses the image declares.
    """
    handlers = [TEXT_VA + 0x10, TEXT_VA + 0x20]
    targets = [TEXT_VA + 0x30, TEXT_VA + 0x40]
    cookie = 0x11223344
    base = make_pe(b"\x90" * 16, image_base=IMAGE_BASE, text_va=TEXT_VA)
    data = struct.pack("<2I", *handlers) + struct.pack("<2I", *targets) + struct.pack("<I", cookie)
    pe, rdata_rva, _offset = _append_section(base, ".rdata", data)

    config = bytearray(_LC_LENGTH)
    struct.pack_into("<I", config, _LC_SIZE, _LC_LENGTH)
    struct.pack_into("<I", config, _LC_SECURITY_COOKIE, rdata_rva + 16)
    struct.pack_into("<I", config, _LC_SEH_TABLE, rdata_rva)
    struct.pack_into("<I", config, _LC_SEH_COUNT, len(handlers))
    struct.pack_into("<I", config, _LC_GUARD_CF_TABLE, rdata_rva + 8)
    struct.pack_into("<I", config, _LC_GUARD_CF_COUNT, len(targets))

    pe, lc_rva, _offset = _append_section(pe, ".lc", bytes(config))
    pe = _patch_directory(pe, _DIR_LOAD_CONFIG, lc_rva, _LC_LENGTH)

    path = tmp_path / "load_config.exe"
    path.write_bytes(pe)
    return (
        path,
        [IMAGE_BASE + va for va in handlers],
        [IMAGE_BASE + va for va in targets],
        IMAGE_BASE + rdata_rva + 16,
    )


def _delay_import_pe(tmp_path: Path, *, rva_based: bool = False) -> tuple[Path, list[int]]:
    """A PE32 with a delay-import descriptor for one DLL and three slots.

    The descriptor's ``Attributes`` word selects the field encoding: 0 means
    VAs (what MSVC writes and what LIEF misreads), 1 means RVAs.  The slots are
    two named imports and one ordinal.
    """
    base = make_pe(b"\x90" * 16, image_base=IMAGE_BASE, text_va=TEXT_VA)

    descriptor_size = 32
    int_table = descriptor_size
    int_size = 3 * 4
    iat_table = int_table + int_size
    iat_size = 3 * 4
    names = iat_table + iat_size
    first_name = names + 2
    second_name = first_name + 2 + len(b"DelayApiA") + 1
    if second_name % 2:
        second_name += 1
    dll_name = second_name + 2 + len(b"DelayApiB") + 1
    if dll_name % 2:
        dll_name += 1
    total = dll_name + len(b"DELAYDLL.dll") + 1

    # Placeholder first: the descriptor's fields are absolute addresses inside
    # the section being appended, so its RVA must be known before it is built.
    pe, section_rva, raw_offset = _append_section(base, ".didata", b"\x00" * total)

    def field(rva: int) -> int:
        return section_rva + rva if rva_based else IMAGE_BASE + section_rva + rva

    blob = bytearray(total)
    struct.pack_into(
        "<8I",
        blob,
        0,
        1 if rva_based else 0,  # Attributes (dlattrRva)
        field(dll_name),  # DllName
        0,  # ModuleHandle
        field(iat_table),  # ImportAddressTable
        field(int_table),  # ImportNameTable
        0,  # BoundImportAddressTable
        0,  # UnloadInformationTable
        0,  # TimeDateStamp
    )
    # Name table: two hint/name RVAs then an ordinal entry.
    struct.pack_into("<I", blob, int_table, field(names))
    struct.pack_into("<I", blob, int_table + 4, field(second_name))
    struct.pack_into("<I", blob, int_table + 8, 0x80000000 | 7)
    blob[names : names + 2] = struct.pack("<H", 0)
    blob[names + 2 : names + 2 + len(b"DelayApiA")] = b"DelayApiA"
    blob[second_name : second_name + 2] = struct.pack("<H", 0)
    blob[second_name + 2 : second_name + 2 + len(b"DelayApiB")] = b"DelayApiB"
    blob[dll_name : dll_name + len(b"DELAYDLL.dll")] = b"DELAYDLL.dll"

    written = bytearray(pe)
    written[raw_offset : raw_offset + total] = blob
    pe = _patch_directory(bytes(written), _DIR_DELAY_IMPORT, section_rva, descriptor_size)
    path = tmp_path / "delay.exe"
    path.write_bytes(pe)
    slots = [IMAGE_BASE + section_rva + iat_table + 4 * index for index in range(3)]
    return path, slots


def _unreadable_load_config_pe(tmp_path: Path) -> Path:
    """A PE32 whose SafeSEH table address points outside the image."""
    base = make_pe(b"\x90" * 16, image_base=IMAGE_BASE, text_va=TEXT_VA)
    config = bytearray(_LC_LENGTH)
    struct.pack_into("<I", config, _LC_SIZE, _LC_LENGTH)
    struct.pack_into("<I", config, _LC_SEH_TABLE, 0x900000)
    struct.pack_into("<I", config, _LC_SEH_COUNT, 4)
    pe, lc_rva, _offset = _append_section(base, ".lc", bytes(config))
    pe = _patch_directory(pe, _DIR_LOAD_CONFIG, lc_rva, _LC_LENGTH)
    path = tmp_path / "broken.exe"
    path.write_bytes(pe)
    return path


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


class TestPeDirectories:
    def test_missing_binary_is_a_note(self, tmp_path: Path) -> None:
        table = pe_directories(tmp_path / "nope.exe")
        assert table.entrypoint is None
        assert table.exports == ()
        assert "binary not found" in table.notes[0]

    def test_non_pe_is_a_note(self, tmp_path: Path) -> None:
        path = tmp_path / "not_a_pe.bin"
        path.write_bytes(b"\x7fELF" + b"\x00" * 64)
        table = pe_directories(path)
        assert table.imports == ()
        assert any("not a PE" in note for note in table.notes)

    def test_entrypoint_and_imports(self) -> None:
        table = pe_directories(MINI_PE)
        assert table.entrypoint == IMAGE_BASE + TEXT_VA
        assert [record.name for record in table.imports] == ["GetTickCount"]
        assert table.imports[0].va >= IMAGE_BASE
        assert table.notes == ()

    def test_load_config_tables(self, tmp_path: Path) -> None:
        path, handlers, targets, cookie = _load_config_pe(tmp_path)
        table = pe_directories(path)
        assert list(table.safe_seh_handlers) == handlers
        assert list(table.cfg_targets) == targets
        assert table.security_cookie == cookie

    def test_unreadable_table_records_nothing_and_notes(self, tmp_path: Path) -> None:
        table = pe_directories(_unreadable_load_config_pe(tmp_path))
        assert table.safe_seh_handlers == ()
        assert any("SafeSEH handler table" in note for note in table.notes)

    def test_delay_imports_from_va_descriptor(self, tmp_path: Path) -> None:
        path, slots = _delay_import_pe(tmp_path)
        records = pe_directories(path).delay_imports
        assert [record.va for record in records] == slots
        assert [record.name for record in records] == ["DelayApiA", "DelayApiB", ""]
        assert records[2].ordinal == 7
        assert all(record.dll == "DELAYDLL.dll" for record in records)

    def test_delay_imports_from_rva_descriptor(self, tmp_path: Path) -> None:
        path, slots = _delay_import_pe(tmp_path, rva_based=True)
        records = pe_directories(path).delay_imports
        assert [record.va for record in records] == slots
        assert records[0].name == "DelayApiA"

    def test_directories_are_deterministic(self, tmp_path: Path) -> None:
        path, _handlers, _targets, _cookie = _load_config_pe(tmp_path)
        assert pe_directories(path) == pe_directories(path)


class TestPeSymbols:
    def test_entrypoint_and_iat_symbols(self) -> None:
        table = pe_symbols(MINI_PE)
        names = {symbol.name for symbol in table.symbols}
        assert "entrypoint" in names
        assert "__imp_kernel32_GetTickCount" in names
        assert table.symbols[0].origin == "entrypoint"

    def test_symbols_sorted_by_address(self, tmp_path: Path) -> None:
        path, _handlers, _targets, _cookie = _load_config_pe(tmp_path)
        addresses = [symbol.va for symbol in pe_symbols(path).symbols if symbol.va is not None]
        assert addresses == sorted(addresses)

    def test_security_cookie_symbol(self, tmp_path: Path) -> None:
        path, _handlers, _targets, cookie = _load_config_pe(tmp_path)
        cookies = [s for s in pe_symbols(path).symbols if s.origin == "security_cookie"]
        assert [symbol.va for symbol in cookies] == [cookie]
        assert cookies[0].kind == "u32"

    def test_safeseh_and_cfg_symbols(self, tmp_path: Path) -> None:
        path, handlers, targets, _cookie = _load_config_pe(tmp_path)
        table = pe_symbols(path)
        safeseh = [s.va for s in table.symbols if s.origin == "safeseh"]
        cfg = [s.va for s in table.symbols if s.origin == "cfg_target"]
        assert safeseh == handlers
        assert cfg == targets
        assert [s.name for s in table.symbols if s.origin == "safeseh"] == [
            "safeseh_0",
            "safeseh_1",
        ]

    def test_delay_import_symbols_use_their_own_prefix(self, tmp_path: Path) -> None:
        path, slots = _delay_import_pe(tmp_path)
        table = pe_symbols(path)
        delay = [s for s in table.symbols if s.origin == "delay_import"]
        assert [symbol.va for symbol in delay] == slots
        assert delay[0].name == "__dimp_delaydll_DelayApiA"
        assert delay[2].name == "__dimp_delaydll_ord7"

    def test_no_load_config_means_no_load_config_symbols(self) -> None:
        origins = {symbol.origin for symbol in pe_symbols(MINI_PE).symbols}
        assert "security_cookie" not in origins
        assert "safeseh" not in origins
        assert "cfg_target" not in origins

    def test_missing_binary_is_an_empty_table(self, tmp_path: Path) -> None:
        table = pe_symbols(tmp_path / "absent.exe")
        assert table.symbols == ()
        assert "binary not found" in table.notes[0]

    def test_symbols_are_deterministic(self, tmp_path: Path) -> None:
        path, _handlers, _targets, _cookie = _load_config_pe(tmp_path)
        assert pe_symbols(path) == pe_symbols(path)


# ---------------------------------------------------------------------------
# Naming helpers
# ---------------------------------------------------------------------------


class TestSymbolNaming:
    @pytest.mark.parametrize(
        ("dll", "name", "ordinal", "expected"),
        [
            ("KERNEL32.dll", "GetTickCount", None, "__imp_kernel32_GetTickCount"),
            ("MFC42u.DLL", "", 4717, "__imp_mfc42u_ord4717"),
            (
                "api-ms-win-crt-heap-l1-1-0.dll",
                "free",
                None,
                "__imp_api_ms_win_crt_heap_l1_1_0_free",
            ),
            ("", "ExitProcess", None, "__imp_sym_ExitProcess"),
        ],
    )
    def test_iat_names(self, dll: str, name: str, ordinal: int | None, expected: str) -> None:
        assert iat_symbol_name(dll, name, ordinal) == expected

    def test_delay_names_do_not_collide_with_iat(self) -> None:
        assert delay_import_symbol_name("KERNEL32.dll", "Sleep", None) == "__dimp_kernel32_Sleep"
        assert delay_import_symbol_name("KERNEL32.dll", "Sleep", None) != iat_symbol_name(
            "KERNEL32.dll", "Sleep", None
        )
