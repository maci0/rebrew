"""Tests for rebrew binary imports — import-table symbol recovery."""

import struct
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from bin_util import make_elf, make_pe
from cli_json import cli_payload
from hypothesis import given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from rebrew.binary.imports import imports_payload
from rebrew.formats.import_table import find_import_stubs, parse_import_table, parse_imports

IMAGE_BASE = 0x400000
TEXT_VA = 0x1000


def _pe_with_stub(work_dir: Path) -> tuple[bytes, int, int]:
    """A PE whose .text starts with ``jmp dword ptr [iat]`` at TEXT_VA.

    Returns (pe_bytes, stub_len, iat_va).  LIEF's ``iat_address`` is not
    byte-exact with the hand-rolled layout, so the IAT slot VA is learned
    from a probe build with identical code length, written under *work_dir*.
    """
    stub_len = 8
    tail = b"\x55\x8b\xec\x5d\xc3"  # a normal function after the stub
    imports = [("KERNEL32.dll", ["MessageBoxA", "GetProcAddress"])]
    probe = make_pe(
        b"\x90" * stub_len + tail,
        image_base=IMAGE_BASE,
        text_va=TEXT_VA,
        imports=imports,
    )
    probe_path = work_dir / "probe.exe"
    probe_path.write_bytes(probe)
    table = parse_import_table(probe_path)
    iat_va = min(table)
    stub = b"\xff\x25" + struct.pack("<I", iat_va) + b"\x90\x90"
    return (
        make_pe(
            stub + tail,
            image_base=IMAGE_BASE,
            text_va=TEXT_VA,
            imports=imports,
        ),
        stub_len,
        iat_va,
    )


@pytest.fixture
def pe_path(tmp_path: Path) -> Path:
    pe_bytes, _, _ = _pe_with_stub(tmp_path)
    path = tmp_path / "game.exe"
    path.write_bytes(pe_bytes)
    return path


def _pe_with_ordinal_import(tmp_path: Path, *, pe32_plus: bool = False) -> Path:
    """A PE whose first import is by ordinal.

    ``make_pe`` writes only name-based imports, so the first import-lookup
    entry (and its IAT slot) is rewritten to the high-bit ordinal form.  The
    section's raw data sits at file offset 0x200 for RVA ``TEXT_VA``.
    """
    import lief

    pe = make_pe(
        b"\x90" * 16,
        image_base=IMAGE_BASE,
        text_va=TEXT_VA,
        imports=[("KERNEL32.dll", ["MessageBoxA", "GetProcAddress"])],
        pe32_plus=pe32_plus,
    )
    path = tmp_path / "ordinal.exe"
    path.write_bytes(pe)
    parsed = lief.PE.parse(str(path))
    assert parsed is not None
    entry = parsed.imports[0]
    int_rva = int(entry.import_lookup_table_rva)
    iat_rva = min(int(fn.iat_address) for fn in entry.entries)
    ordinal_entry = (1 << (63 if pe32_plus else 31)) | 4717
    patched = bytearray(pe)
    for rva in (int_rva, iat_rva):
        struct.pack_into("<Q" if pe32_plus else "<I", patched, rva - TEXT_VA + 0x200, ordinal_entry)
    path.write_bytes(bytes(patched))
    return path


class TestParseImportTable:
    def test_imports_parsed(self, pe_path: Path) -> None:
        table = parse_import_table(pe_path)
        # IAT slots land right after the stub code inside .text.
        assert "MessageBoxA" in table.values()
        assert "GetProcAddress" in table.values()
        for va in table:
            assert va >= IMAGE_BASE

    def test_named_imports_carry_no_ordinal(self, pe_path: Path) -> None:
        assert all(record["ordinal"] is None for record in parse_imports(pe_path))

    @pytest.mark.parametrize("pe32_plus", [False, True])
    def test_ordinal_only_import_is_reported(self, tmp_path: Path, pe32_plus: bool) -> None:
        path = _pe_with_ordinal_import(tmp_path, pe32_plus=pe32_plus)
        records = parse_imports(path)
        ordinals = [record for record in records if record["ordinal"] is not None]
        assert len(ordinals) == 1
        # A record with no name in the hint/name table still has to be visible:
        # it gets a synthetic name and its ordinal, which is what a caller
        # needs to spell the linker's __imp_<dll>_ord<N> symbol.
        assert ordinals[0]["name"] == "ordinal_4717"
        assert ordinals[0]["iat_va"] >= IMAGE_BASE
        assert ordinals[0]["hint_name_rva"] is None
        assert imports_payload(path)["imports"][0]["hint_name_rva"] is None
        assert [record["name"] for record in records if record["ordinal"] is None] == [
            "GetProcAddress"
        ]

    @pytest.mark.parametrize("pe32_plus", [False, True])
    def test_hint_name_rvas_preserve_physical_order(self, tmp_path: Path, pe32_plus: bool) -> None:
        """IAT order may differ from physical hint/name order on either PE width."""
        import lief

        blob = make_pe(
            b"\x90" * 16,
            imports=[("KERNEL32.dll", ["MessageBoxA", "GetProcAddress"])],
            pe32_plus=pe32_plus,
        )
        path = tmp_path / "reordered.exe"
        path.write_bytes(blob)
        pe = lief.PE.parse(str(path))
        assert pe is not None
        entry = pe.imports[0]
        expected = [int(fn.data) for fn in entry.entries][::-1]
        patched = bytearray(blob)
        width = 8 if pe32_plus else 4
        for rva in (entry.import_lookup_table_rva, entry.import_address_table_rva):
            off = pe.rva_to_offset(rva)
            patched[off : off + 2 * width] = (
                blob[off + width : off + 2 * width] + blob[off : off + width]
            )
        path.write_bytes(patched)

        records = parse_imports(path)
        assert [r["name"] for r in records] == ["GetProcAddress", "MessageBoxA"]
        assert [r["hint_name_rva"] for r in records] == expected
        assert expected[0] > expected[1]
        for record in records:
            off = pe.rva_to_offset(record["hint_name_rva"]) + 2
            assert patched[off:].split(b"\0", 1)[0].decode() == record["name"]
        assert [r["hint_name_rva"] for r in imports_payload(path)["imports"]] == [
            f"0x{rva:08x}" for rva in expected
        ]

    def test_non_pe_returns_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "not_a_pe.bin"
        path.write_bytes(b"\x00" * 64)
        assert parse_import_table(path) == {}

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert parse_import_table(tmp_path / "nope.exe") == {}


class TestFindImportStubs:
    @pytest.mark.parametrize("blob", [b"\xff\x25", b"\xff\x25\0\0\0", b"\xff\x25\0\0\0\0"])
    def test_truncated_and_complete_stub_at_section_end(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, blob: bytes
    ) -> None:
        from rebrew.formats.binary_model import BinaryInfo, SectionInfo

        path = tmp_path / "text.bin"
        path.write_bytes(blob)
        info = BinaryInfo(
            path=path,
            format="pe",
            sections={".text": SectionInfo(".text", IMAGE_BASE, len(blob), 0, len(blob))},
        )
        monkeypatch.setattr("rebrew.formats.import_table.parse_import_table", lambda _: {0: "api"})
        monkeypatch.setattr("rebrew.formats.binary_loader.load_binary", lambda _: info)
        assert find_import_stubs(path) == ({IMAGE_BASE: "api"} if len(blob) == 6 else {})

    def test_detects_jmp_stub(self, tmp_path: Path) -> None:
        pe_bytes, _, iat_va = _pe_with_stub(tmp_path)
        pe_path = tmp_path / "game.exe"
        pe_path.write_bytes(pe_bytes)
        stubs = find_import_stubs(pe_path)
        # The stub lives at .text start (full VA = imagebase + RVA) and
        # names the import whose IAT slot its jmp dereferences.
        stub_va = IMAGE_BASE + TEXT_VA
        assert stubs == {stub_va: parse_import_table(pe_path)[iat_va]}

    def test_no_imports_no_stubs(self, tmp_path: Path) -> None:
        plain = tmp_path / "plain.exe"
        plain.write_bytes(make_pe(b"\x90" * 16))
        assert find_import_stubs(plain) == {}

    def test_detects_pe32_plus_rip_relative_stub(self, tmp_path: Path) -> None:
        """A PE32+ stub's ``FF 25`` operand is a RIP-relative displacement.

        Read as an absolute slot VA the operand names nothing, so a
        PE32-only reader reports zero stubs for every 64-bit image.
        """
        stub_len = 6
        tail = b"\x55\x8b\xec\x5d\xc3"
        imports = [("KERNEL32.dll", ["MessageBoxA", "GetProcAddress"])]
        probe_path = tmp_path / "probe64.exe"
        probe_path.write_bytes(
            make_pe(
                b"\x90" * stub_len + tail,
                image_base=IMAGE_BASE,
                text_va=TEXT_VA,
                imports=imports,
                pe32_plus=True,
            )
        )
        iat_va = min(parse_import_table(probe_path))
        disp = iat_va - (IMAGE_BASE + TEXT_VA + stub_len)
        stub = b"\xff\x25" + struct.pack("<i", disp)
        path = tmp_path / "game64.exe"
        path.write_bytes(
            make_pe(
                stub + tail,
                image_base=IMAGE_BASE,
                text_va=TEXT_VA,
                imports=imports,
                pe32_plus=True,
            )
        )
        stubs = find_import_stubs(path)
        assert stubs == {IMAGE_BASE + TEXT_VA: parse_import_table(path)[iat_va]}

    def test_detects_pe32_stub_with_high_image_base(self, tmp_path: Path) -> None:
        """A PE32 stub above 0x80000000 names its slot with a negative operand.

        The ``FF 25`` operand is unpacked signed, so an absolute slot VA with
        the top bit set used to look up a negative key and the stub vanished
        from the table with no error.
        """
        high_base = 0x80000000
        stub_len = 6
        tail = b"\x55\x8b\xec\x5d\xc3"
        imports = [("KERNEL32.dll", ["MessageBoxA"])]
        probe_path = tmp_path / "probe_hi.exe"
        probe_path.write_bytes(
            make_pe(
                b"\x90" * stub_len + tail,
                image_base=high_base,
                text_va=TEXT_VA,
                imports=imports,
            )
        )
        iat_va = min(parse_import_table(probe_path))
        assert iat_va > 0x7FFFFFFF, "fixture must exercise the signed-operand path"
        stub = b"\xff\x25" + struct.pack("<I", iat_va)
        path = tmp_path / "game_hi.exe"
        path.write_bytes(
            make_pe(stub + tail, image_base=high_base, text_va=TEXT_VA, imports=imports)
        )
        stubs = find_import_stubs(path)
        assert stubs == {high_base + TEXT_VA: parse_import_table(path)[iat_va]}


class TestImportsCli:
    def test_terminal_output(self, pe_path: Path) -> None:
        from rebrew.binary.imports import app

        result = CliRunner().invoke(app, ["list", str(pe_path)])
        assert result.exit_code == 0
        assert "MessageBoxA" in result.output
        assert "KERNEL32.dll" in result.output

    def test_json_output(self, pe_path: Path) -> None:
        from rebrew.binary.imports import app

        result = CliRunner().invoke(app, ["list", "--json", str(pe_path)])
        assert result.exit_code == 0
        payload = cli_payload(result)
        assert any(i["name"] == "MessageBoxA" for i in payload["imports"])
        assert payload["stubs"]  # stub VA → name present
        # VAs are hex strings, consistent with every other rebrew JSON.
        assert all(s["va"].startswith("0x") for s in payload["stubs"])
        assert all(str(i["iat_va"]).startswith("0x") for i in payload["imports"])

    def test_a_tail_jump_through_a_slot_is_not_a_stub(self, tmp_path: Path) -> None:
        """MSVC's getSystemCP ends two branches with ``jmp [GetOEMCP]`` and
        ``jmp [GetACP]``: those are tail calls inside the function, which the
        analysis stored as 6-byte import thunks.  A stub is called, follows
        padding or a ``ret``, opens the section, or sits beside another stub."""
        from bin_util import IMPORT_CALL_NAMES, le32, make_import_call_pe

        from rebrew.binary.imports import app

        def assemble(slot_a: int, slot_b: int) -> str:
            return (
                "8b442404 83f8fe 7506"  # 0x00 mov eax, [esp+4]; cmp eax, -2; jne 0x0f
                f"ff25{le32(slot_a)}"  # 0x09 tail call
                "e8 03000000 c20400"  # 0x0f call 0x17; ret 4
                f"ff25{le32(slot_b)}"  # 0x17 called stub after ret's 00 byte
                f"ff25{le32(slot_a)}"  # 0x1d stub beside it
            )

        binary, _a, _b = make_import_call_pe(tmp_path, assemble)
        result = CliRunner().invoke(app, ["list", "--json", str(binary)])
        assert result.exit_code == 0, result.output
        assert cli_payload(result)["stubs"] == [
            {"va": "0x00401017", "name": IMPORT_CALL_NAMES[1]},
            {"va": "0x0040101d", "name": IMPORT_CALL_NAMES[0]},
        ]

    def test_missing_binary_errors(self, tmp_path: Path) -> None:
        from rebrew.binary.imports import app

        result = CliRunner().invoke(app, ["list", str(tmp_path / "nope.exe")])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_registered_in_umbrella(self) -> None:
        from rebrew.app.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["binary", "--help"])
        assert result.exit_code == 0
        assert "imports" in result.output


ELF_IMAGE_BASE = 0x8048000
ELF_TEXT_VA = 0x8049000
ELF_CODE = b"\x55\x8b\xec\x5d\xc3\x90" * 8
ELF_IMPORTS = (
    ("printf", "libc.so.6", "GLIBC_2.0"),
    ("puts", "libc.so.6", "GLIBC_2.0"),
    ("sqrt", "libm.so.6", "GLIBC_2.2"),
    ("plain_sym", "", ""),
)


def _elf_with_imports(tmp_path: Path) -> Path:
    """A dynamic ELF32 importing from two libraries, one symbol unversioned."""
    path = tmp_path / "game.elf"
    path.write_bytes(
        make_elf(
            ELF_CODE,
            image_base=ELF_IMAGE_BASE,
            text_va=ELF_TEXT_VA,
            needed_libraries=("libc.so.6", "libm.so.6"),
            imported_symbols=ELF_IMPORTS,
        )
    )
    return path


class TestElfImports:
    def test_needed_libraries_lead_the_records(self, tmp_path: Path) -> None:
        records = parse_imports(_elf_with_imports(tmp_path))
        assert all(r["hint_name_rva"] is None for r in records)
        assert [(r["dll"], r["name"]) for r in records[:2]] == [
            ("libc.so.6", ""),
            ("libm.so.6", ""),
        ]

    def test_versioned_symbols_take_their_library(self, tmp_path: Path) -> None:
        records = parse_imports(_elf_with_imports(tmp_path))
        by_name = {r["name"]: r for r in records if r["name"]}
        assert by_name["printf"]["dll"] == "libc.so.6"
        assert by_name["puts"]["dll"] == "libc.so.6"
        # The second requirement's own library, not the first one's.
        assert by_name["sqrt"]["dll"] == "libm.so.6"

    def test_unversioned_symbol_stays_unattributed(self, tmp_path: Path) -> None:
        """DT_NEEDED names the libraries but not which exports which symbol."""
        records = parse_imports(_elf_with_imports(tmp_path))
        by_name = {r["name"]: r for r in records if r["name"]}
        assert by_name["plain_sym"]["dll"] == ""

    def test_relocation_slots_are_image_relative(self, tmp_path: Path) -> None:
        records = parse_imports(_elf_with_imports(tmp_path))
        slots = {r["name"]: r["iat_va"] for r in records if r["name"]}
        # One GOT slot per symbol, in symbol-table order, right after .text.
        assert slots["printf"] == ELF_IMAGE_BASE + 0x1000 + len(ELF_CODE)
        assert slots["plain_sym"] == slots["printf"] + 3 * 4

    def test_elf_without_dynamic_tables_has_no_imports(self, tmp_path: Path) -> None:
        path = tmp_path / "static.elf"
        path.write_bytes(make_elf(ELF_CODE))
        assert parse_imports(path) == []

    def test_json_output_lists_elf_imports(self, tmp_path: Path) -> None:
        from rebrew.binary.imports import app

        result = CliRunner().invoke(app, ["list", "--json", str(_elf_with_imports(tmp_path))])
        assert result.exit_code == 0
        payload = cli_payload(result)
        names = {i["name"] for i in payload["imports"]}
        assert {"printf", "puts", "sqrt", "plain_sym"} <= names
        assert all(str(i["iat_va"]).startswith("0x") for i in payload["imports"])

    def test_terminal_output_lists_elf_imports(self, tmp_path: Path) -> None:
        from rebrew.binary.imports import app

        result = CliRunner().invoke(app, ["list", str(_elf_with_imports(tmp_path))])
        assert result.exit_code == 0
        assert "sqrt" in result.output
        assert "libm.so.6" in result.output


def _build_elf32_with_plt(symbols: list[str], *, base: int = 0x08048000) -> tuple[bytes, int, int]:
    """Build a minimal dynamic ELF32 with ``.plt``, ``.got.plt``, ``.rel.plt``, ``.dynsym``."""
    dynstr = bytearray(b"\x00libc.so.6\x00")
    sym_name_offs: list[int] = []
    for sym in symbols:
        sym_name_offs.append(len(dynstr))
        dynstr.extend(sym.encode("ascii") + b"\x00")

    dynsym = bytearray(b"\x00" * 16)
    for off in sym_name_offs:
        dynsym.extend(struct.pack("<IIIBBH", off, 0, 0, 0x12, 0, 0))

    text_off = 0x1000
    text_blob = b"\xc3" * 16
    plt_off = 0x1020
    plt_va = base + plt_off
    got_off = 0x2000
    got_va = base + got_off
    got_size = 4 * max(len(symbols), 1)
    dynstr_off = 0x2100
    dynsym_off = (dynstr_off + len(dynstr) + 3) & ~3
    rel_off = dynsym_off + len(dynsym)

    # PLT0 (16 bytes of nop) + 16-byte stubs: jmp dword ptr [got_slot] + pad
    plt_blob = bytearray(b"\x90" * 16)
    rel_blob = bytearray()
    for idx in range(len(symbols)):
        slot_va = got_va + 4 * idx
        stub = b"\xff\x25" + struct.pack("<I", slot_va) + b"\x68" + struct.pack("<I", idx * 8)
        stub += b"\x90" * (16 - len(stub))
        plt_blob.extend(stub)
        rel_blob.extend(struct.pack("<II", slot_va, ((idx + 1) << 8) | 7))

    dyn_off = rel_off + len(rel_blob)
    dynamic_entries = [
        (1, 1),  # DT_NEEDED libc.so.6
        (5, base + dynstr_off),  # DT_STRTAB
        (6, base + dynsym_off),  # DT_SYMTAB
        (10, len(dynstr)),  # DT_STRSZ
        (11, 16),  # DT_SYMENT
        (23, base + rel_off),  # DT_JMPREL
        (2, len(rel_blob)),  # DT_PLTRELSZ
        (20, 17),  # DT_PLTREL = DT_REL
        (0, 0),
    ]
    dynamic = b"".join(struct.pack("<iI", tag, val) for tag, val in dynamic_entries)

    shstr_off = dyn_off + len(dynamic)
    names = (
        b"\x00.text\x00.plt\x00.got.plt\x00.dynstr\x00.dynsym\x00"
        b".rel.plt\x00.dynamic\x00.shstrtab\x00"
    )
    shoff = (shstr_off + len(names) + 3) & ~3
    filesz = shoff + 9 * 40

    def _no(s: str) -> int:
        return names.index(s.encode("ascii") + b"\x00")

    def _sh(
        name: int,
        stype: int,
        flags: int,
        addr: int,
        off: int,
        size: int,
        link: int = 0,
        info: int = 0,
        entsize: int = 0,
    ) -> bytes:
        return struct.pack(
            "<IIIIIIIIII", name, stype, flags, addr, off, size, link, info, 4, entsize
        )

    shdrs = b"".join(
        [
            b"\x00" * 40,
            _sh(_no(".text"), 1, 6, base + text_off, text_off, len(text_blob)),
            _sh(_no(".plt"), 1, 6, plt_va, plt_off, len(plt_blob), entsize=16),
            _sh(_no(".got.plt"), 1, 3, got_va, got_off, got_size),
            _sh(_no(".dynstr"), 3, 2, base + dynstr_off, dynstr_off, len(dynstr)),
            _sh(
                _no(".dynsym"),
                11,
                2,
                base + dynsym_off,
                dynsym_off,
                len(dynsym),
                link=4,
                info=1,
                entsize=16,
            ),
            _sh(
                _no(".rel.plt"),
                9,
                2,
                base + rel_off,
                rel_off,
                len(rel_blob),
                link=5,
                info=3,
                entsize=8,
            ),
            _sh(_no(".dynamic"), 6, 3, base + dyn_off, dyn_off, len(dynamic), link=4, entsize=8),
            _sh(_no(".shstrtab"), 3, 0, 0, shstr_off, len(names)),
        ]
    )
    e_ident = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH", e_ident, 2, 3, 1, base + text_off, 52, shoff, 0, 52, 32, 2, 40, 9, 8
    )
    ph_load = struct.pack("<IIIIIIII", 1, 0, base, base, filesz, filesz, 7, 0x1000)
    ph_dyn = struct.pack(
        "<IIIIIIII", 2, dyn_off, base + dyn_off, base + dyn_off, len(dynamic), len(dynamic), 6, 4
    )
    buf = bytearray(ehdr + ph_load + ph_dyn)
    buf += b"\x00" * (text_off - len(buf)) + text_blob
    buf += b"\x00" * (plt_off - len(buf)) + plt_blob
    buf += b"\x00" * (got_off - len(buf)) + b"\x00" * got_size
    buf += b"\x00" * (dynstr_off - len(buf)) + dynstr
    buf += b"\x00" * (dynsym_off - len(buf)) + dynsym
    buf += b"\x00" * (rel_off - len(buf)) + rel_blob
    buf += b"\x00" * (dyn_off - len(buf)) + dynamic
    buf += b"\x00" * (shstr_off - len(buf)) + names
    buf += b"\x00" * (shoff - len(buf)) + shdrs
    return bytes(buf), plt_va, got_va


def _build_elf64_with_plt_sec(
    symbols: list[str], *, base: int = 0x400000
) -> tuple[bytes, int, int]:
    """Build a minimal dynamic ELF64 with ``.plt.sec`` (``endbr64; bnd jmp [rip+disp]``)."""
    dynstr = bytearray(b"\x00libc.so.6\x00")
    sym_name_offs: list[int] = []
    for sym in symbols:
        sym_name_offs.append(len(dynstr))
        dynstr.extend(sym.encode("ascii") + b"\x00")

    dynsym = bytearray(24)
    for off in sym_name_offs:
        dynsym.extend(struct.pack("<IBBHQQ", off, 0x12, 0, 0, 0, 0))

    text_off = 0x1000
    text_blob = b"\xc3" * 16
    plt_sec_off = 0x1020
    plt_sec_va = base + plt_sec_off
    got_off = 0x2000
    got_va = base + got_off
    got_size = 8 * max(len(symbols), 1)
    dynstr_off = 0x2100
    dynsym_off = (dynstr_off + len(dynstr) + 7) & ~7
    rela_off = dynsym_off + len(dynsym)

    plt_sec_blob = bytearray()
    rela_blob = bytearray()
    for idx in range(len(symbols)):
        stub_va = plt_sec_va + 16 * idx
        slot_va = got_va + 8 * idx
        # endbr64 (4B) + bnd jmp qword ptr [rip + disp32] (7B) + 5B nop
        disp = slot_va - (stub_va + 11)
        stub = b"\xf3\x0f\x1e\xfa\xf2\xff\x25" + struct.pack("<i", disp) + b"\x90" * 5
        plt_sec_blob.extend(stub)
        rela_blob.extend(struct.pack("<QQq", slot_va, ((idx + 1) << 32) | 7, 0))

    dyn_off = (rela_off + len(rela_blob) + 7) & ~7
    dynamic_entries = [
        (1, 1),  # DT_NEEDED
        (5, base + dynstr_off),  # DT_STRTAB
        (6, base + dynsym_off),  # DT_SYMTAB
        (10, len(dynstr)),  # DT_STRSZ
        (11, 24),  # DT_SYMENT
        (23, base + rela_off),  # DT_JMPREL
        (2, len(rela_blob)),  # DT_PLTRELSZ
        (20, 7),  # DT_PLTREL = DT_RELA
        (0, 0),
    ]
    dynamic = b"".join(struct.pack("<qQ", tag, val) for tag, val in dynamic_entries)

    shstr_off = dyn_off + len(dynamic)
    names = (
        b"\x00.text\x00.plt.sec\x00.got.plt\x00.dynstr\x00.dynsym\x00"
        b".rela.plt\x00.dynamic\x00.shstrtab\x00"
    )
    shoff = (shstr_off + len(names) + 7) & ~7
    filesz = shoff + 9 * 64

    def _no(s: str) -> int:
        return names.index(s.encode("ascii") + b"\x00")

    def _sh(
        name: int,
        stype: int,
        flags: int,
        addr: int,
        off: int,
        size: int,
        link: int = 0,
        info: int = 0,
        entsize: int = 0,
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ", name, stype, flags, addr, off, size, link, info, 8, entsize
        )

    shdrs = b"".join(
        [
            b"\x00" * 64,
            _sh(_no(".text"), 1, 6, base + text_off, text_off, len(text_blob)),
            _sh(_no(".plt.sec"), 1, 6, plt_sec_va, plt_sec_off, len(plt_sec_blob), entsize=16),
            _sh(_no(".got.plt"), 1, 3, got_va, got_off, got_size),
            _sh(_no(".dynstr"), 3, 2, base + dynstr_off, dynstr_off, len(dynstr)),
            _sh(
                _no(".dynsym"),
                11,
                2,
                base + dynsym_off,
                dynsym_off,
                len(dynsym),
                link=4,
                info=1,
                entsize=24,
            ),
            _sh(
                _no(".rela.plt"),
                4,
                2,
                base + rela_off,
                rela_off,
                len(rela_blob),
                link=5,
                info=3,
                entsize=24,
            ),
            _sh(_no(".dynamic"), 6, 3, base + dyn_off, dyn_off, len(dynamic), link=4, entsize=16),
            _sh(_no(".shstrtab"), 3, 0, 0, shstr_off, len(names)),
        ]
    )
    e_ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        2,
        62,
        1,
        base + text_off,
        64,
        shoff,
        0,
        64,
        56,
        2,
        64,
        9,
        8,
    )
    ph_load = struct.pack("<IIQQQQQQ", 1, 7, 0, base, base, filesz, filesz, 0x1000)
    ph_dyn = struct.pack(
        "<IIQQQQQQ", 2, 6, dyn_off, base + dyn_off, base + dyn_off, len(dynamic), len(dynamic), 8
    )
    buf = bytearray(ehdr + ph_load + ph_dyn)
    buf += b"\x00" * (text_off - len(buf)) + text_blob
    buf += b"\x00" * (plt_sec_off - len(buf)) + plt_sec_blob
    buf += b"\x00" * (got_off - len(buf)) + b"\x00" * got_size
    buf += b"\x00" * (dynstr_off - len(buf)) + dynstr
    buf += b"\x00" * (dynsym_off - len(buf)) + dynsym
    buf += b"\x00" * (rela_off - len(buf)) + rela_blob
    buf += b"\x00" * (dyn_off - len(buf)) + dynamic
    buf += b"\x00" * (shstr_off - len(buf)) + names
    buf += b"\x00" * (shoff - len(buf)) + shdrs
    return bytes(buf), plt_sec_va, got_va


class TestElfPltStubs:
    def test_elf32_plt_stubs_detected(self, tmp_path: Path) -> None:
        from rebrew.formats.import_table import find_import_stub_slots

        blob, plt_va, got_va = _build_elf32_with_plt(["puts", "malloc"])
        path = tmp_path / "plt32.elf"
        path.write_bytes(blob)
        assert find_import_stub_slots(path) == {
            plt_va + 16: got_va,
            plt_va + 32: got_va + 4,
        }
        assert find_import_stubs(path) == {
            plt_va + 16: "puts",
            plt_va + 32: "malloc",
        }

    def test_elf64_plt_sec_endbr_bnd_jmp_detected(self, tmp_path: Path) -> None:
        from rebrew.formats.import_table import find_import_stub_slots

        blob, plt_sec_va, got_va = _build_elf64_with_plt_sec(["printf", "free"])
        path = tmp_path / "plt64.elf"
        path.write_bytes(blob)
        assert find_import_stub_slots(path) == {
            plt_sec_va: got_va,
            plt_sec_va + 16: got_va + 8,
        }
        assert find_import_stubs(path) == {
            plt_sec_va: "printf",
            plt_sec_va + 16: "free",
        }

    def test_elf_mips_stubs_lui_lw_detected(self, tmp_path: Path) -> None:
        from rebrew.formats.binary_model import BinaryInfo, SectionInfo
        from rebrew.formats.import_table import find_import_stub_slots

        slot_va = 0x00410010
        stub_va = 0x00401200
        # Big-endian MIPS: lui $t9, 0x0041; lw $t9, 0x0010($t9); jr $t9; nop
        mips_stub = b"".join(
            w.to_bytes(4, "big") for w in (0x3C190041, 0x8F390010, 0x03200008, 0x00000000)
        )
        elf_path = tmp_path / "mips_stubs.elf"
        elf_path.write_bytes(mips_stub)
        info = BinaryInfo(
            path=elf_path,
            format="elf",
            arch="mips32",
            endian="big",
            pointer_size=4,
            sections={
                ".MIPS.stubs": SectionInfo(
                    ".MIPS.stubs", stub_va, len(mips_stub), 0, len(mips_stub), is_code=True
                )
            },
            _data=mips_stub,
        )
        with (
            patch(
                "rebrew.formats.import_table.parse_import_table",
                return_value={0: "", slot_va: "printf"},
            ),
            patch("rebrew.formats.binary_loader.load_binary", return_value=info),
        ):
            assert find_import_stub_slots(elf_path) == {stub_va: slot_va}
            assert find_import_stubs(elf_path) == {stub_va: "printf"}


def _ne_with_modules(tmp_path: Path, modules: list[str]) -> Path:
    """Minimal MZ+NE carrying a module ref table + imported names table (the
    16-bit SkiFree shape: no classic import table, so only module names are
    recoverable)."""
    raw = bytearray(0x100)
    raw[0:2] = b"MZ"
    raw[0x3C:0x40] = (0x100).to_bytes(4, "little")
    raw += b"NE" + b"\x00" * 0x3E
    payload = bytearray()
    for m in modules:
        payload += bytes([len(m)]) + m.encode()
    impnames_off = 0x40
    modref_off = impnames_off + len(payload)
    struct.pack_into("<H", raw, 0x100 + 0x28, modref_off)
    struct.pack_into("<H", raw, 0x100 + 0x2A, impnames_off)
    struct.pack_into("<H", raw, 0x100 + 0x1E, len(modules))
    struct.pack_into("<H", raw, 0x100 + 0x04, 0)  # entry table offset
    struct.pack_into("<H", raw, 0x100 + 0x06, 0)  # entry table length
    modtab = bytearray()
    for i, _m in enumerate(modules):
        off = sum(1 + len(x) for x in modules[:i])
        modtab += struct.pack("<H", off)
    p = tmp_path / "app.ne"
    p.write_bytes(bytes(raw) + bytes(payload) + bytes(modtab))
    return p


class TestNeImports:
    def test_module_level_imports(self, tmp_path: Path) -> None:
        from rebrew.formats.import_table import parse_imports

        p = _ne_with_modules(tmp_path, ["KERNEL", "GDI", "USER"])
        recs = parse_imports(p)
        # Modules surface even though there is no classic import table
        # (regression: MSVC-built NEs used to fabricate thousands of fake
        # ordinal imports from the non-resident name table bytes).
        assert [r["dll"] for r in recs] == ["KERNEL", "GDI", "USER"]
        assert all(r["name"] == "" for r in recs)
        assert all(r["hint_name_rva"] is None for r in recs)

    def test_pe_imports_unchanged(self, tmp_path: Path) -> None:
        from rebrew.formats.import_table import parse_imports

        pe_bytes, _, _ = _pe_with_stub(tmp_path)
        p = tmp_path / "game.exe"
        p.write_bytes(pe_bytes)
        recs = parse_imports(p)
        dlls = {r["dll"] for r in recs}
        assert "KERNEL32.dll" in dlls
        assert any(r["name"] == "MessageBoxA" for r in recs)


class TestImportsMark:
    """binary imports mark writes LIBRARY annotations for detected stubs."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            module="SERVER",
            target_name="server.dll",
            reversed_dir=tmp_path / "src" / "SERVER",
            metadata_dir=tmp_path / "src",
            root=tmp_path,
        )

    def test_mark_writes_library_header(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.binary.imports import mark_import_stubs

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True)
        from rebrew.metadata.functions import get_entry

        added = mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, dry_run=False)
        assert added == 1
        out = cfg.reversed_dir / "library_imports.h"
        assert out.is_file()
        text = out.read_text(encoding="utf-8")
        assert text == "/* Auto-generated by rebrew binary imports mark. DO NOT EDIT. */\n"
        assert "// LIBRARY:" not in text
        entry = get_entry(cfg.metadata_dir, 0x401000, "SERVER")
        assert entry["kind"] == "LIBRARY"
        assert entry["symbol"] == "MessageBoxA"
        assert entry["name"] == "MessageBoxA"
        assert entry["file"] == "SERVER/library_imports.h"

    @pytest.mark.parametrize(
        ("encoding", "comment"),
        [("cp1252", "Café"), ("shift_jis", "日本語"), ("utf-8", "Café 日本語")],
    )
    def test_mark_preserves_existing_encoding(
        self, tmp_path: Path, encoding: str, comment: str
    ) -> None:
        from rebrew.binary.imports import mark_import_stubs
        from rebrew.metadata.functions import get_entry

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True)
        out = cfg.reversed_dir / "library_imports.h"
        comment_line = f"// {comment}\n".encode(encoding)
        original = comment_line
        out.write_bytes(original)
        from rebrew.metadata.functions import identity_file, record_function_identity

        record_function_identity(
            cfg.metadata_dir,
            module="SERVER",
            va=0x401000,
            file=identity_file(out, cfg.metadata_dir),
            kind="LIBRARY",
            name="Existing",
            symbol="Existing",
        )

        assert mark_import_stubs(cfg, {0x401000: "Existing", 0x402000: "MessageBoxA"}) == 1
        # The existing LIBRARY row is kept. The header's comment stays in the
        # encoding it was written in, and the new VA is added as a store row.
        assert out.read_bytes() == comment_line
        migrated = get_entry(cfg.metadata_dir, 0x401000, "SERVER")
        assert migrated["kind"] == "LIBRARY"
        assert migrated["file"] == "SERVER/library_imports.h"
        added = get_entry(cfg.metadata_dir, 0x402000, "SERVER")
        assert added["kind"] == "LIBRARY"
        assert added["symbol"] == "MessageBoxA"
        assert added["name"] == "MessageBoxA"
        assert mark_import_stubs(cfg, {0x402000: "MessageBoxA"}) == 0
        assert out.read_bytes() == comment_line

    def test_mark_dry_run_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.binary.imports import mark_import_stubs

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True)
        added = mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, dry_run=True)
        assert added == 1
        assert not (cfg.reversed_dir / "library_imports.h").exists()

    def test_mark_skips_existing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.binary.imports import mark_import_stubs

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True)
        mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, dry_run=False)
        added = mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, dry_run=False)
        assert added == 0  # already annotated

    def test_mark_ignores_a_va_mentioned_outside_a_marker(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A prose mention of a VA is not an annotation; the stub still gets marked."""
        from rebrew.binary.imports import mark_import_stubs
        from rebrew.metadata.functions import get_entry

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True)
        out = cfg.reversed_dir / "library_imports.h"
        original = b"// thunk at 0x00401000 per the disassembly\n"
        out.write_bytes(original)

        assert mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, dry_run=False) == 1
        # A markerless header is left byte-for-byte. The stub is a store row.
        assert out.read_bytes() == original
        entry = get_entry(cfg.metadata_dir, 0x401000, "SERVER")
        assert entry["kind"] == "LIBRARY"
        assert entry["symbol"] == "MessageBoxA"
        assert entry["name"] == "MessageBoxA"
        assert mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, dry_run=False) == 0
        assert out.read_bytes() == original

    def test_decorated_stub_name_is_the_c_name(self, tmp_path: Path) -> None:
        """A decorated import stub is named as C, and the symbol stays.

        ``lstrip("_")`` stored ``hook@@12`` and ``@keeps@4`` as the row
        name, and it stored ``__foo`` as ``foo``. ``_foo`` is still
        ``foo``. ``MessageBoxA`` is unchanged.
        """
        from rebrew.binary.imports import mark_import_stubs
        from rebrew.metadata.functions import get_entry

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True)
        stubs = {
            0x401000: "hook@@12",
            0x401010: "@keeps@4",
            0x401020: "_sleepish@4",
            0x401030: "__foo",
            0x401040: "_foo",
            0x401050: "MessageBoxA",
        }
        assert mark_import_stubs(cfg, stubs, dry_run=False) == 6
        expect = {
            0x401000: ("hook@@12", "hook"),
            0x401010: ("@keeps@4", "keeps"),
            0x401020: ("_sleepish@4", "sleepish"),
            0x401030: ("__foo", "_foo"),
            0x401040: ("_foo", "foo"),
            0x401050: ("MessageBoxA", "MessageBoxA"),
        }
        for va, (symbol, name) in expect.items():
            entry = get_entry(cfg.metadata_dir, va, "SERVER")
            assert entry is not None
            assert entry["symbol"] == symbol
            assert entry["name"] == name, symbol

    def test_mark_writes_the_store_once_for_all_stubs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One identity edit for the whole stub set, not one per stub."""
        from rebrew.binary import imports as imports_module
        from rebrew.metadata import functions as functions_module
        from rebrew.metadata.functions import get_entry

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True)
        calls: list[int] = []
        original = functions_module.record_function_rows

        def counted(metadata_dir: Any, rows: list[dict[str, Any]], **kwargs: Any) -> None:
            calls.append(len(rows))
            original(metadata_dir, rows, **kwargs)

        monkeypatch.setattr(functions_module, "record_function_rows", counted)
        stubs = {0x401000: "A", 0x401010: "B", 0x401020: "C"}
        assert imports_module.mark_import_stubs(cfg, stubs, dry_run=False) == 3
        assert calls == [3]
        for va, symbol in stubs.items():
            assert get_entry(cfg.metadata_dir, va, "SERVER")["symbol"] == symbol

    def test_matches_cli_json(self, pe_path: Path) -> None:
        """``imports_payload()`` is the importable form of ``rebrew binary imports list --json``."""
        from rebrew.binary.imports import app

        payload = imports_payload(pe_path)
        result = CliRunner().invoke(app, ["list", "--json", str(pe_path)])
        assert result.exit_code == 0
        assert payload == cli_payload(result)
        assert any(i["name"] == "MessageBoxA" for i in payload["imports"])
        assert all(s["va"].startswith("0x") for s in payload["stubs"])
        assert all(str(i["iat_va"]).startswith("0x") for i in payload["imports"])

    def test_accepts_precomputed_stubs(self, pe_path: Path) -> None:
        stubs = find_import_stubs(pe_path)
        assert imports_payload(pe_path, stubs)["stubs"] == imports_payload(pe_path)["stubs"]

    def test_non_pe_yields_empty_lists(self, tmp_path: Path) -> None:
        path = tmp_path / "not_a_pe.bin"
        path.write_bytes(b"\x00" * 64)
        assert imports_payload(path) == {"binary": str(path), "imports": [], "stubs": []}


# ---------------------------------------------------------------------------
# Hypothesis fuzz — untrusted binary import-table and stub parsing
# ---------------------------------------------------------------------------


@settings(max_examples=150, deadline=None)
@given(st.binary(min_size=0, max_size=1024))
def test_parse_imports_random_bytes_no_crash(blob: bytes) -> None:
    """Random bytes passed to parse_imports / parse_import_table / find_import_stubs
    must return valid typed structures or empty collections — never unhandled exceptions.
    """
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
        fh.write(blob)
        tmp = Path(fh.name)
    try:
        recs = parse_imports(tmp)
        assert isinstance(recs, list)
        for r in recs:
            assert isinstance(r, dict)
            assert isinstance(r.get("dll"), str)
            assert isinstance(r.get("name"), str)
            assert isinstance(r.get("iat_va"), int)
            assert r["iat_va"] >= 0
            if "ordinal" in r:
                assert r["ordinal"] is None or isinstance(r["ordinal"], int)

        table = parse_import_table(tmp)
        assert isinstance(table, dict)
        for va, name in table.items():
            assert isinstance(va, int) and va >= 0
            assert isinstance(name, str)

        stubs = find_import_stubs(tmp)
        assert isinstance(stubs, dict)
        for sva, sname in stubs.items():
            assert isinstance(sva, int) and sva >= 0
            assert isinstance(sname, str)
            # Invariant: any stub recognized must reference an imported API in table
            assert sname in table.values()
    finally:
        tmp.unlink(missing_ok=True)


class TestParseFailureIsNotMemoized:
    """A failed parse must not be cached as "this image has no imports".

    ``parse_imports`` memoizes per (path, mtime, size, ino), and the toolchain
    detector reads an empty import table as evidence about the compiler.  A
    transient parse failure pinned in the memo would feed the detector a
    confident, wrong answer for the rest of the run.
    """

    def test_failed_parse_is_retried_not_cached(self, tmp_path, monkeypatch, caplog) -> None:
        import logging

        from rebrew.formats import import_table

        target = tmp_path / "app.exe"
        target.write_bytes(b"MZ" + b"\x00" * 64)
        calls = {"n": 0}

        def _fail(_path: Path) -> None:
            # _parse_imports' "the image did not parse" answer is None.
            calls["n"] += 1

        monkeypatch.setattr(import_table, "_parse_imports", _fail)
        with caplog.at_level(logging.WARNING, logger="rebrew.formats.import_table"):
            assert import_table.parse_imports(target) == []
        assert calls["n"] == 1
        assert import_table.parse_imports(target) == []
        assert calls["n"] == 2, "a failed parse was memoized as an empty import table"

    def test_partial_pe_enumeration_is_retried_not_cached(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import lief

        from rebrew.formats import import_table

        target = tmp_path / "partial.exe"
        target.write_bytes(b"MZ" + b"\x00" * 64)
        calls = {"n": 0}

        def _entries():
            yield SimpleNamespace(
                name="Sleep", iat_address=0x1000, ordinal=0, is_ordinal=False, data=0x2000
            )
            raise RuntimeError("truncated import table")

        def _parse(_path: str):
            calls["n"] += 1
            return SimpleNamespace(
                optional_header=SimpleNamespace(imagebase=IMAGE_BASE),
                imports=[SimpleNamespace(name="KERNEL32.dll", entries=_entries())],
            )

        monkeypatch.setattr(lief.PE, "parse", _parse)
        assert import_table.parse_imports(target) == []
        assert import_table.parse_imports(target) == []
        assert calls["n"] == 2, "a partial PE import table was memoized as a successful parse"

    def test_successful_parse_is_memoized(self, tmp_path, monkeypatch) -> None:
        from rebrew.formats import import_table

        target = tmp_path / "app.exe"
        target.write_bytes(b"MZ" + b"\x00" * 64)
        calls = {"n": 0}
        record = {"dll": "KERNEL32.dll", "name": "Sleep", "iat_va": 0x1000, "ordinal": None}

        def _ok(_path: Path):
            calls["n"] += 1
            return [record]

        monkeypatch.setattr(import_table, "_parse_imports", _ok)
        assert import_table.parse_imports(target) == [record]
        assert import_table.parse_imports(target) == [record]
        assert calls["n"] == 1

    def test_in_place_rewrite_with_restored_mtime_reparses(self, tmp_path, monkeypatch) -> None:
        import os

        from rebrew.formats import import_table

        target = tmp_path / "app.exe"
        target.write_bytes(b"MZ" + b"\x00" * 64)
        calls = {"n": 0}
        record = {"dll": "KERNEL32.dll", "name": "Sleep", "iat_va": 0x1000, "ordinal": None}

        def _ok(_path: Path):
            calls["n"] += 1
            return [record]

        monkeypatch.setattr(import_table, "_parse_imports", _ok)
        assert import_table.parse_imports(target) == [record]
        old = target.stat()
        target.write_bytes(b"MZ" + b"\x01" * 64)
        os.utime(target, ns=(old.st_atime_ns, old.st_mtime_ns))
        after = target.stat()
        assert (after.st_mtime_ns, after.st_size, after.st_ino) == (
            old.st_mtime_ns,
            old.st_size,
            old.st_ino,
        )
        assert import_table.parse_imports(target) == [record]
        assert calls["n"] == 2


@settings(max_examples=100, deadline=None)
@given(st.binary(min_size=1, max_size=64), st.integers(min_value=1, max_value=8))
def test_imports_fixture_mutation_no_crash(noise: bytes, n_flips: int) -> None:
    """Mutating a valid PE with import stubs must either preserve import/stub
    table invariants or degrade cleanly."""
    with tempfile.TemporaryDirectory() as td:
        pe_bytes, _, _ = _pe_with_stub(Path(td))
        data = bytearray(pe_bytes)
        for i, b in enumerate(noise[:n_flips]):
            idx = (b + i * 23) % len(data)
            data[idx] ^= 0xFF if (b & 1) else (b or 1)
        if len(noise) >= 2 and (noise[0] & 0x40):
            cut = noise[1] % max(1, len(data) // 2)
            del data[len(data) - cut :]

        p = Path(td) / "mutated.exe"
        p.write_bytes(bytes(data))

        recs = parse_imports(p)
        assert isinstance(recs, list)
        for r in recs:
            assert isinstance(r, dict)
            assert isinstance(r.get("dll"), str)
            assert isinstance(r.get("name"), str)
            assert isinstance(r.get("iat_va"), int)
            assert r["iat_va"] >= 0
        table = parse_import_table(p)
        assert isinstance(table, dict)
        stubs = find_import_stubs(p)
        assert isinstance(stubs, dict)
        for sname in stubs.values():
            assert sname in table.values()


class TestImportsMarkRebindRetired:
    """imports --mark --rebind-retired replaces retired claims with LIBRARY rows."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            module="SERVER",
            target_name="server.dll",
            reversed_dir=tmp_path / "src" / "SERVER",
            metadata_dir=tmp_path / "src",
            root=tmp_path,
        )

    def _retired_row(self, tmp_path: Path) -> SimpleNamespace:
        from rebrew.metadata.binding_history import change_source_binding
        from rebrew.metadata.functions import identity_file, record_function_identity

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True)
        skeleton = cfg.reversed_dir / "fcn_00401000.c"
        skeleton.write_text("/* ADDRESS: SERVER 0x401000 */\nvoid fcn_00401000(void) {}\n")
        record_function_identity(
            cfg.metadata_dir,
            module="SERVER",
            va=0x401000,
            file=identity_file(skeleton, cfg.metadata_dir),
            kind="FUNCTION",
            name="fcn_00401000",
            symbol="_fcn_00401000",
        )
        change_source_binding(
            cfg.metadata_dir,
            "SERVER",
            0x401000,
            reason="0x401000 is a linker import forwarder, not game source",
            project_root=cfg.root,
        )
        return cfg

    def test_mark_refuses_retired_without_the_flag(self, tmp_path: Path) -> None:
        from rebrew.binary.imports import mark_import_stubs

        cfg = self._retired_row(tmp_path)
        with pytest.raises(ValueError, match="--rebind-retired"):
            mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, dry_run=False)

    @pytest.mark.parametrize("module", ["SERVER", "server"])
    def test_mark_rebinds_retired_with_the_flag(self, tmp_path: Path, module: str) -> None:
        from rebrew.binary.imports import mark_import_stubs
        from rebrew.metadata.functions import get_entry

        cfg = self._retired_row(tmp_path)
        cfg.module = module
        added = mark_import_stubs(
            cfg, {0x401000: "MessageBoxA"}, dry_run=False, rebind_retired=True
        )
        assert added == 1
        entry = get_entry(cfg.metadata_dir, 0x401000, "SERVER")
        assert entry["kind"] == "LIBRARY"
        assert entry["symbol"] == "MessageBoxA"
        assert entry["name"] == "MessageBoxA"
        assert entry["file"] == "src/SERVER/library_imports.h"
        history = entry["binding_history"]
        assert [event["action"] for event in history] == ["retire", "rebind"]
        assert history[-1]["replacement"]["kind"] == "LIBRARY"
        assert history[-1]["replacement"]["symbol"] == "MessageBoxA"
        header = cfg.reversed_dir / "library_imports.h"
        assert header.read_text(encoding="utf-8").startswith("/* Auto-generated")

    def test_mark_refuses_concurrent_metadata_changes(self, tmp_path: Path) -> None:
        from rebrew.binary.imports import mark_import_stubs
        from rebrew.metadata.functions import get_entry, update_field
        from rebrew.naming import load_existing_vas

        cfg = self._retired_row(tmp_path)

        def scan(*args: Any) -> Any:
            result = load_existing_vas(*args)
            update_field(cfg.metadata_dir, 0x401000, "size", 6, module="SERVER")
            return result

        with (
            patch("rebrew.naming.load_existing_vas", side_effect=scan),
            pytest.raises(ValueError, match="source bindings changed"),
        ):
            mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, rebind_retired=True)
        assert len(get_entry(cfg.metadata_dir, 0x401000, "SERVER")["binding_history"]) == 1
        assert not (cfg.reversed_dir / "library_imports.h").exists()

    def test_mark_rebind_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        from rebrew.binary.imports import mark_import_stubs
        from rebrew.metadata.functions import get_entry

        cfg = self._retired_row(tmp_path)
        added = mark_import_stubs(cfg, {0x401000: "MessageBoxA"}, dry_run=True, rebind_retired=True)
        assert added == 1
        assert not (cfg.reversed_dir / "library_imports.h").exists()
        entry = get_entry(cfg.metadata_dir, 0x401000, "SERVER")
        assert "kind" not in entry
        assert len(entry["binding_history"]) == 1
