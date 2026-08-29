"""Tests for multi-arch Phase 0 — arch presets, detection, the arch-aware
extent walker, per-arch reloc tables, and the non-x86 discovery/jump-table
gates.  Synthetic bytes only (no cross compilers in CI); the first real
MIPS/PPC fixtures land with Phase 1's gcc-mips target."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.config import _ARCH_PRESETS, ProjectConfig


class TestArchPresets:
    def test_mips32_preset(self) -> None:
        p = _ARCH_PRESETS["mips32"]
        assert p["capstone_arch"] == "CS_ARCH_MIPS"
        assert p["capstone_mode"] == "CS_MODE_MIPS32"
        assert p["pointer_size"] == 4
        assert 0x00 in p["padding_bytes"]

    def test_ppc32_preset(self) -> None:
        p = _ARCH_PRESETS["ppc32"]
        assert p["capstone_arch"] == "CS_ARCH_PPC"
        assert p["pointer_size"] == 4
        assert bytes(p["padding_bytes"]) == b"\x60\x00\x00\x00"  # `nop`

    def test_sh2_preset(self) -> None:
        p = _ARCH_PRESETS["sh2"]
        assert p["capstone_arch"] == "CS_ARCH_SH"
        assert p["capstone_mode"] == "CS_MODE_SH2"
        assert p["pointer_size"] == 4

    def test_presets_drive_capstone_properties(self) -> None:
        cfg = SimpleNamespace(arch="mips32")
        assert ProjectConfig.capstone_arch.__get__(cfg) == _CS("CS_ARCH_MIPS")
        assert ProjectConfig.capstone_mode.__get__(cfg) == _CS("CS_MODE_MIPS32")


def _CS(name: str) -> int:
    import capstone

    return int(getattr(capstone, name))


class TestArchDetection:
    def test_elf_machine_maps(self) -> None:
        import lief

        from rebrew.binary_loader import _ELF_MACHINE_TO_ARCH

        assert _ELF_MACHINE_TO_ARCH[lief.ELF.ARCH.MIPS] == "mips32"
        assert _ELF_MACHINE_TO_ARCH[lief.ELF.ARCH.PPC] == "ppc32"
        assert _ELF_MACHINE_TO_ARCH[lief.ELF.ARCH.PPC64] == "ppc64"
        assert _ELF_MACHINE_TO_ARCH[lief.ELF.ARCH.SH] == "sh2"

    def test_macho_ppc_map(self) -> None:
        import lief

        from rebrew.binary_loader import _MACHO_CPU_TO_ARCH

        assert _MACHO_CPU_TO_ARCH[lief.MachO.Header.CPU_TYPE.POWERPC] == "ppc32"

    def test_load_binary_sets_arch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.binary_loader as bl

        bin_path = tmp_path / "x.elf"
        bin_path.write_bytes(b"\x7fELF")
        fake = SimpleNamespace(
            arch="mips32",
            format="elf",
            image_base=0,
            sections={},
            text_va=0,
            text_size=0,
            text_raw_offset=0,
        )
        monkeypatch.setattr(bl, "_parse_regular", lambda p, f: fake)
        info = bl.load_binary(bin_path)
        assert info.arch == "mips32"


class TestExtentWalker:
    def _extent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arch: str, fmt: str, raw: bytes
    ) -> int:
        import rebrew.binary_loader as bl

        bin_path = tmp_path / "x.bin"
        bin_path.write_bytes(raw)
        info = SimpleNamespace(
            arch=arch,
            format=fmt,
            image_base=0,
            sections={},
            text_va=0x1000,
            text_size=len(raw),
            text_raw_offset=0,
            data=raw,
        )
        monkeypatch.setattr(bl, "load_binary", lambda p: info)
        monkeypatch.setattr(bl, "extract_bytes_at_va", lambda info, va, size, **kw: raw)
        return bl.function_extent_from_disasm(bin_path, 0x1000)

    def test_x86_ret_regression(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # `ret` (c3) — the historical x86 walker still terminates at 1.
        assert self._extent(tmp_path, monkeypatch, "x86_32", "pe", b"\xb8\x01\x00\x00\x00\xc3") == 6

    def test_mips_jr_ra(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # `nop; jr $ra` (00000000 03e00008) — extent ends after the jr.
        assert (
            self._extent(
                tmp_path, monkeypatch, "mips32", "elf", b"\x00\x00\x00\x00\x03\xe0\x00\x08"
            )
            == 8
        )

    def test_ppc_blr(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # `nop; blr` (60000000 4e800020).
        assert (
            self._extent(tmp_path, monkeypatch, "ppc32", "elf", b"\x60\x00\x00\x00\x4e\x80\x00\x20")
            == 8
        )

    def test_mips_tail_jump(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # `j 0x2000` (08000800) — unconditional jump = tail terminator.
        ext, kind = self._extent_kind(tmp_path, monkeypatch, "mips32", "elf", b"\x08\x00\x08\x00")
        assert ext == 4
        assert kind == "jmp"

    def _extent_kind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arch: str, fmt: str, raw: bytes
    ) -> tuple[int, str]:
        import rebrew.binary_loader as bl

        bin_path = tmp_path / "x.bin"
        bin_path.write_bytes(raw)
        info = SimpleNamespace(
            arch=arch,
            format=fmt,
            image_base=0,
            sections={},
            text_va=0x1000,
            text_size=len(raw),
            text_raw_offset=0,
            data=raw,
        )
        monkeypatch.setattr(bl, "load_binary", lambda p: info)
        monkeypatch.setattr(bl, "extract_bytes_at_va", lambda info, va, size, **kw: raw)
        return bl.function_extent_from_disasm(bin_path, 0x1000, with_kind=True)


class TestRelocTables:
    def _apply(self, relocs, table: str) -> bytes:
        from rebrew.core.matching import apply_coff_relocations

        return apply_coff_relocations(
            b"\x00\x00\x00\x00",
            relocs,
            lambda sym: 0x2000,
            section_va=0x1000,
            reloc_table=table,
        )

    def test_elf_mips_abs32(self) -> None:
        from rebrew.core.matching import CoffRelocRecord

        out = self._apply([CoffRelocRecord(0, 2, "sym")], "elf-mips")  # R_MIPS_32
        assert out == (0x2000).to_bytes(4, "little")

    def test_elf_ppc_abs32(self) -> None:
        from rebrew.core.matching import CoffRelocRecord

        out = self._apply([CoffRelocRecord(0, 1, "sym")], "elf-ppc")  # R_PPC_ADDR32
        assert out == (0x2000).to_bytes(4, "little")

    def test_unsupported_mips_type_raises(self) -> None:
        from rebrew.core.matching import CoffRelocRecord, apply_coff_relocations

        with pytest.raises(NotImplementedError):
            apply_coff_relocations(
                b"\x00\x00\x00\x00",
                [CoffRelocRecord(0, 4, "sym")],  # R_MIPS_26 — Phase 1
                lambda sym: 0x2000,
                section_va=0x1000,
                reloc_table="elf-mips",
            )

    def test_real_ido_reloc_types_mask_in_compare(self) -> None:
        """IDO 7.1 objects carry HI16/LO16 (global data) and GOT16/CALL16
        (external calls, O32 GOT convention) — the *compare* path must mask
        these slots (they hold link-time addresses), never raise.  Verified
        against a real `rebrew/ido:7.1-linux` object: relocs at 0x0/0x4
        (sym 6), 0xc (sym 3), 0x28 (sym 5), 0x3c (sym 3)."""
        from rebrew.core.matching import CoffRelocRecord, smart_reloc_compare

        obj = bytearray(0x40)
        target = bytearray(0x40)
        for off in (0x0, 0x4, 0xC, 0x28, 0x3C):
            target[off : off + 4] = b"\x12\x34\x56\x78"  # link-time addresses
        relocs = [
            CoffRelocRecord(0x0, 5, "g_counter"),  # R_MIPS_HI16
            CoffRelocRecord(0x4, 6, "g_counter"),  # R_MIPS_LO16
            CoffRelocRecord(0xC, 9, "ext_fn"),  # R_MIPS_GOT16
            CoffRelocRecord(0x28, 11, "ext_fn"),  # R_MIPS_CALL16
            CoffRelocRecord(0x3C, 9, "ext_fn"),  # R_MIPS_GOT16
        ]
        matched, _mcount, _total, valid, invalid = smart_reloc_compare(
            bytes(obj),
            bytes(target),
            relocs,
            name_to_va={"g_counter": 0x80001000, "ext_fn": 0x80002000},
            section_va=0x80000100,
            reloc_table="elf-mips",
        )
        assert matched
        assert len(valid) == 5
        assert invalid == []


class TestNonX86Gates:
    def test_discover_non_x86_minimal_sweep(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.discover as d

        info = SimpleNamespace(
            arch="mips32",
            format="elf",
            data=b"\x00" * 16,
            sections={"S1": SimpleNamespace(name=".text", size=16, file_offset=0, va=0x1000)},
            text_va=0x1000,
            text_size=16,
        )
        monkeypatch.setattr(d, "load_binary", lambda p: info)
        monkeypatch.setattr(d, "iter_instructions", lambda info, va, size: [])
        funcs = d._capstone_sweep(tmp_path / "x.elf")
        assert funcs == [(0x1000, 0, "fcn.00001000")]  # .text base only

    def test_is_jump_table_non_x86_no_prefix_skip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A MIPS-style table whose first bytes look like x86 padding must NOT
        have them skipped as an alignment prefix (multi-arch gate)."""
        from rebrew.catalog.registry import is_jump_table

        # 0x90 0x90 0x90 0x90 then two .text pointers at 0x1000.
        data = b"\x90\x90\x90\x90" + (0x1000).to_bytes(4, "little") * 2
        # x86: the 4-byte 0x90 run is skipped, pointers land aligned → True.
        assert is_jump_table(data, 0x1000, 0x100, arch="x86_32") is True
        # mips: no prefix skip; the table starts with 0x90909090 (not a .text
        # pointer) → False.
        assert is_jump_table(data, 0x1000, 0x100, arch="mips32") is False
