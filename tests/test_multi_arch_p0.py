"""Tests for multi-arch Phase 0 — arch presets, detection, the arch-aware
extent walker, per-arch reloc tables, and the non-x86 discovery/jump-table
gates.  Synthetic bytes only (no cross compilers in CI); the first real
MIPS/PPC fixtures land with Phase 1's gcc-mips target.

These tests assert public behavior (load_config values, detect/discover
results, reloc application), never private table contents.
"""

from types import SimpleNamespace
from typing import Any
lazy from pathlib import Path

import pytest


def _CS(name: str) -> int:
    import capstone

    return int(getattr(capstone, name))


# Arch-aware behavior goes through load_config (public): per-arch values
# land on the cfg the rest of the pipeline reads.


def _make_project(tmp_path: Path, arch: str) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(
        '[project]\ndefault_target = "T"\n'
        '[targets.T]\nbinary = "x.bin"\nreversed_dir = "src"\n'
        f'arch = "{arch}"\n'
    )
    return tmp_path


class TestArchPresets:
    """Per-arch values surface on load_config (public), driving capstone props."""

    @pytest.mark.parametrize(
        ("arch", "capstone_arch", "capstone_mode", "pointer_size"),
        [
            ("mips32", "CS_ARCH_MIPS", "CS_MODE_MIPS32", 4),
            ("ppc32", "CS_ARCH_PPC", "CS_MODE_32", 4),
            ("sh2", "CS_ARCH_SH", "CS_MODE_SH2", 4),
            ("x86_32", "CS_ARCH_X86", "CS_MODE_32", 4),
            ("x86_64", "CS_ARCH_X86", "CS_MODE_64", 8),
        ],
    )
    def test_load_config_arch_values(
        self, tmp_path: Path, arch: str, capstone_arch: str, capstone_mode: str, pointer_size: int
    ) -> None:
        from rebrew.config import ProjectConfig, load_config

        cfg = load_config(_make_project(tmp_path, arch))
        assert cfg.pointer_size == pointer_size
        cap = SimpleNamespace(arch=cfg.arch)
        assert ProjectConfig.capstone_arch.__get__(cap) == _CS(capstone_arch)
        # No image header: MIPS/PPC/SH2 default to big-endian.  Capstone's
        # own default is little-endian, and that bit is not part of the
        # preset's base mode name.
        expected_mode = _CS(capstone_mode)
        if arch in ("mips32", "mips64", "ppc32", "ppc64", "sh2"):
            expected_mode |= _CS("CS_MODE_BIG_ENDIAN")
        assert ProjectConfig.capstone_mode.__get__(cap) == expected_mode

    def test_mips_padding_is_zero_byte(self, tmp_path: Path) -> None:
        from rebrew.config import load_config

        assert 0x00 in load_config(_make_project(tmp_path, "mips32")).padding_bytes

    def test_unknown_arch_raises(self, tmp_path: Path) -> None:
        from rebrew.config import load_config

        with pytest.raises(ValueError, match="unknown arch 'notanarch'"):
            load_config(_make_project(tmp_path, "notanarch"))


class TestArchDetection:
    def test_detect_pe_i386_end_to_end(self) -> None:
        """The checked-in mini PE detects as (pe, x86_32) via the public API."""
        from pathlib import Path as _Path

        from rebrew.formats.binary_loader import detect_format_and_arch

        fmt, arch = detect_format_and_arch(_Path(__file__).parent / "fixtures" / "mini_pe.exe")
        assert fmt == "pe"
        assert arch == "x86_32"

    def test_detect_unknown_format_raises(self, tmp_path: Path) -> None:
        from rebrew.formats.binary_loader import detect_format_and_arch

        blob = tmp_path / "x.bin"
        blob.write_bytes(b"\x00" * 64)
        with pytest.raises(ValueError, match="Cannot detect"):
            detect_format_and_arch(blob)

    def test_detect_missing_file_raises(self, tmp_path: Path) -> None:
        from rebrew.formats.binary_loader import detect_format_and_arch

        with pytest.raises(FileNotFoundError):
            detect_format_and_arch(tmp_path / "nope.exe")

    def test_load_binary_sets_arch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.formats.binary_loader as bl

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
    @pytest.mark.parametrize("endian", ["little", "big"])
    @pytest.mark.parametrize(
        ("terminator", "kind"), [(0x000B, "ret"), (0xA7FF, "jmp"), (0x402B, "jmp")]
    )
    @pytest.mark.parametrize("with_kind", [False, True])
    def test_sh2_extent_includes_the_executed_delay_slot(
        self, endian: str, terminator: int, kind: str, with_kind: bool
    ) -> None:
        from rebrew.formats.binary_loader import function_extent_from_bytes

        # nop; RTS/BRA/JMP; add #1,r0 (delay slot); a later function.
        data = b"".join(
            word.to_bytes(2, endian)
            for word in (0x0009, terminator, 0x7001, 0x0009, 0x000B, 0x0009)
        )
        info = SimpleNamespace(arch="sh2", endian=endian, format="elf")
        extent = function_extent_from_bytes(info, data, 0x1000, with_kind=with_kind)
        assert extent == ((6, kind) if with_kind else 6)

    @pytest.mark.parametrize("endian", ["little", "big"])
    @pytest.mark.parametrize("with_kind", [False, True])
    @pytest.mark.parametrize(
        ("words", "size", "kind"),
        [
            ((0xE1A00000, 0xE12FFF1E), 8, "ret"),  # nop; bx lr
            ((0xE1A00000, 0xE12FFF10), 8, "jmp"),  # nop; bx r0
            ((0xE1A00000, 0xE8BD8010), 8, "ret"),  # nop; pop {r4, pc}
            ((0xE1A00000, 0xE8BD0010, 0xE1A00000, 0xE12FFF1E), 16, "ret"),
        ],
    )
    def test_arm_return_detection_uses_the_branch_register_or_pop_list(
        self, endian: str, with_kind: bool, words: tuple[int, ...], size: int, kind: str
    ) -> None:
        from rebrew.formats.binary_loader import function_extent_from_bytes

        data = b"".join(word.to_bytes(4, endian) for word in words)
        info = SimpleNamespace(arch="arm32", endian=endian, format="elf")
        assert function_extent_from_bytes(info, data, 0x1000, with_kind=with_kind) == (
            (size, kind) if with_kind else size
        )

    def _extent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arch: str, fmt: str, raw: bytes
    ) -> int:
        import rebrew.formats.binary_loader as bl

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
        raw = bytes.fromhex("00000000 03e00008 00000000")  # nop; jr $ra; nop
        assert self._extent(tmp_path, monkeypatch, "mips32", "elf", raw) == 12

    def test_ppc_blr(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # `nop; blr` (60000000 4e800020).
        assert (
            self._extent(tmp_path, monkeypatch, "ppc32", "elf", b"\x60\x00\x00\x00\x4e\x80\x00\x20")
            == 8
        )

    def test_sh2_rts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        raw = bytes.fromhex("000b0009")  # Big-endian RTS followed by its delay slot.
        assert self._extent(tmp_path, monkeypatch, "sh2", "elf", raw) == 4

    def test_ppc_capstone_decodes_blr_big_endian(self) -> None:
        import capstone

        from rebrew.formats.binary_loader import capstone_config_for

        info = SimpleNamespace(arch="ppc32", endian="big", format="elf")
        cs_arch, mode = capstone_config_for(info)
        insns = list(capstone.Cs(cs_arch, mode).disasm(bytes.fromhex("4e800020"), 0x80000000))
        assert [(insn.mnemonic, insn.op_str) for insn in insns] == [("blr", "")]

    def test_arm_big_endian_image_sets_the_bit(self) -> None:
        import capstone

        from rebrew.formats.binary_loader import capstone_config_for

        info = SimpleNamespace(arch="arm32", endian="big", format="elf")
        _arch, mode = capstone_config_for(info)
        assert mode & capstone.CS_MODE_BIG_ENDIAN
        insns = list(capstone.Cs(_arch, mode).disasm(bytes.fromhex("e3a00001"), 0))
        assert [(insn.mnemonic, insn.op_str) for insn in insns] == [("mov", "r0, #1")]

    def test_little_endian_mips_image_clears_the_default(self, tmp_path: Path) -> None:
        import capstone

        from rebrew.config import ProjectConfig

        blob = bytearray(16)
        blob[:4] = b"\x7fELF"
        blob[5] = 1  # ELFDATA2LSB
        path = tmp_path / "psx.elf"
        path.write_bytes(bytes(blob))
        cfg = ProjectConfig(root=tmp_path, arch="mips32", target_binary=path, binary_format="elf")
        assert not cfg.capstone_mode & capstone.CS_MODE_BIG_ENDIAN
        insns = list(
            capstone.Cs(cfg.capstone_arch, cfg.capstone_mode).disasm(
                bytes.fromhex("0800e003"), 0x80000000
            )
        )
        assert [(insn.mnemonic, insn.op_str) for insn in insns] == [("jr", "$ra")]

    def test_mips_tail_jump(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        raw = bytes.fromhex("08000800 00000000")  # j 0x2000; nop
        ext, kind = self._extent_kind(tmp_path, monkeypatch, "mips32", "elf", raw)
        assert ext == 8
        assert kind == "jmp"

    def _extent_kind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arch: str, fmt: str, raw: bytes
    ) -> tuple[int, str]:
        import rebrew.formats.binary_loader as bl

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
        from rebrew.compare.coff_reloc import apply_coff_relocations

        return apply_coff_relocations(
            b"\x00\x00\x00\x00",
            relocs,
            lambda sym: 0x2000,
            section_va=0x1000,
            reloc_table=table,
        )

    def test_elf_mips_abs32(self) -> None:
        from rebrew.compare.coff_reloc import CoffRelocRecord

        out = self._apply([CoffRelocRecord(0, 2, "sym")], "elf-mips")  # R_MIPS_32
        assert out == (0x2000).to_bytes(4, "big")

    def test_elf_ppc_abs32(self) -> None:
        from rebrew.compare.coff_reloc import CoffRelocRecord

        out = self._apply([CoffRelocRecord(0, 1, "sym")], "elf-ppc")  # R_PPC_ADDR32
        assert out == (0x2000).to_bytes(4, "big")

    def test_coff_abs32_stays_little_endian(self) -> None:
        from rebrew.compare.coff_reloc import CoffRelocRecord

        out = self._apply([CoffRelocRecord(0, 0x0006, "sym")], "coff-i386")  # DIR32
        assert out == (0x2000).to_bytes(4, "little")

    def test_big_endian_addend_is_read_in_target_order(self) -> None:
        """An R_MIPS_32 slot holding addend 0x10 must read as 0x10, not 0x10000000."""
        from rebrew.compare.coff_reloc import CoffRelocRecord, apply_coff_relocations

        text = (0x10).to_bytes(4, "big")
        out = apply_coff_relocations(
            text,
            [CoffRelocRecord(0, 2, "sym")],
            lambda sym: 0x2000,
            section_va=0x1000,
            reloc_table="elf-mips",
        )
        assert out == (0x2010).to_bytes(4, "big")

    def test_elf_mips_26_jump(self) -> None:
        from rebrew.compare.coff_reloc import CoffRelocRecord, apply_coff_relocations

        # `jal 0` (0x0C000000) patched to target 0x80012340 -> instr_index = (0x80012340 >> 2) & 0x03FFFFFF = 0x00048D0
        word = (0x0C000000).to_bytes(4, "big")
        out = apply_coff_relocations(
            word,
            [CoffRelocRecord(0, 4, "callee")],  # R_MIPS_26
            lambda _sym: 0x80012340,
            section_va=0x80010000,
            reloc_table="elf-mips",
        )
        assert int.from_bytes(out, "big") == (0x0C000000 | ((0x80012340 >> 2) & 0x03FFFFFF))

    def test_elf_mips_hi16_lo16_pair_with_sign_carry(self) -> None:
        from rebrew.compare.coff_reloc import CoffRelocRecord, apply_coff_relocations

        # Target 0x80008000 has signed negative low half (-0x8000), so HI16 gets 0x8001
        # lui $t0, 0 (0x3C080000); lw $t0, 0($t0) (0x8D080000)
        code = (0x3C080000).to_bytes(4, "big") + (0x8D080000).to_bytes(4, "big")
        relocs = [
            CoffRelocRecord(0, 5, "g_buf"),  # R_MIPS_HI16
            CoffRelocRecord(4, 6, "g_buf"),  # R_MIPS_LO16
        ]
        out = apply_coff_relocations(
            code,
            relocs,
            lambda _sym: 0x80008000,
            section_va=0x80000000,
            reloc_table="elf-mips",
        )
        hi = int.from_bytes(out[:4], "big")
        lo = int.from_bytes(out[4:8], "big")
        assert hi == 0x3C088001
        assert lo == 0x8D088000

    def test_elf_ppc_rel24(self) -> None:
        from rebrew.compare.coff_reloc import CoffRelocRecord, apply_coff_relocations

        # `nop; bl .+0` at 0x1004 calling 0x1020 -> delta = +0x1C -> 0x4800001D
        code = (0x60000000).to_bytes(4, "big") + (0x48000001).to_bytes(4, "big")
        out = apply_coff_relocations(
            code,
            [CoffRelocRecord(4, 10, "callee")],  # R_PPC_REL24
            lambda _sym: 0x1020,
            section_va=0x1000,
            reloc_table="elf-ppc",
        )
        assert int.from_bytes(out[4:8], "big") == 0x4800001D

    def test_unsupported_mips_type_raises(self) -> None:
        from rebrew.compare.coff_reloc import CoffRelocRecord, apply_coff_relocations

        with pytest.raises(NotImplementedError):
            apply_coff_relocations(
                b"\x00\x00\x00\x00",
                [CoffRelocRecord(0, 9, "sym")],  # R_MIPS_GOT16
                lambda sym: 0x2000,
                section_va=0x1000,
                reloc_table="elf-mips",
            )

    def test_mips_scoring_skips_x86_pattern_normalization(self) -> None:
        import capstone

        from rebrew.matcher.scoring import score_candidate

        # 0x0c100400 (`jal 0x401000`) + `nop` — non-x86 bytes must not be damaged by x86 heuristics
        target = bytes.fromhex("24820001 0c100400 00000000 03e00008 00000000")
        cand = bytes.fromhex("24820002 0c100400 00000000 03e00008 00000000")
        sc = score_candidate(
            target,
            cand,
            cs_arch=capstone.CS_ARCH_MIPS,
            cs_mode=capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN,
        )
        assert sc.reloc_score == 1.0
        assert sc.mnemonic_score == 0.0

    def test_real_ido_reloc_types_mask_in_compare(self) -> None:
        """IDO 7.1 objects carry HI16/LO16 (global data) and GOT16/CALL16
        (external calls, O32 GOT convention) — the *compare* path must mask
        these slots (they hold link-time addresses), never raise.  Verified
        against a real `rebrew/ido:7.1-linux` object: relocs at 0x0/0x4
        (sym 6), 0xc (sym 3), 0x28 (sym 5), 0x3c (sym 3)."""
        from rebrew.compare.coff_reloc import CoffRelocRecord, smart_reloc_compare

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
        import rebrew.binary.discover as d

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

    def test_arm_blx_target_is_a_function_start(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An ARM BLX immediate is a direct call. Capstone prints it as ``blx #0xNNNN``."""
        import rebrew.binary.discover as d

        # BLX at 0x1000, H=0, imm=2: target = 0x1000 + 8 + 8 = 0x1010. Then a callee.
        code = (
            (0xFA000002).to_bytes(4, "little") + b"\x00\x00\xa0\xe1" * 3 + bytes.fromhex("1eff2fe1")
        )
        info = SimpleNamespace(
            arch="arm32",
            endian="little",
            format="elf",
            data=code,
            sections={
                ".text": SimpleNamespace(
                    name=".text", size=len(code), file_offset=0, raw_size=len(code), va=0x1000
                )
            },
            text_va=0x1000,
            text_size=len(code),
            text_raw_offset=0,
        )
        monkeypatch.setattr(d, "load_binary", lambda _path: info)
        funcs = d._capstone_sweep(tmp_path / "arm.elf")
        assert 0x1010 in [va for va, _size, _name in funcs]

    def test_sh2_bsr_target_is_a_function_start(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SH2 BSR is a direct call. The mnemonic is ``bsr``, not ``bl`` or ``jal``."""
        import rebrew.binary.discover as d

        # bsr from 0x1000 to 0x1008: disp = (0x1008 - (0x1000+4)) / 2 = 2. Opcode B002.
        code = bytes.fromhex("b0020000000000000900")
        info = SimpleNamespace(
            arch="sh2",
            endian="big",
            format="elf",
            data=code,
            sections={
                ".text": SimpleNamespace(
                    name=".text", size=len(code), file_offset=0, raw_size=len(code), va=0x1000
                )
            },
            text_va=0x1000,
            text_size=len(code),
            text_raw_offset=0,
        )
        monkeypatch.setattr(d, "load_binary", lambda _path: info)
        funcs = d._capstone_sweep(tmp_path / "sh.elf")
        assert 0x1008 in [va for va, _size, _name in funcs]

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


class TestMipsElfEndToEnd:
    """Real checked-in ``tests/fixtures/mini_mips32.elf`` pipeline checks."""

    def test_mips32_fixture_detect_discover_extent_and_cfg(self) -> None:
        from pathlib import Path as _Path

        import capstone

        from rebrew.binary.cfg_ged import build_cfg, cfg_similarity
        from rebrew.binary.discover import _capstone_sweep
        from rebrew.formats.binary_loader import (
            detect_format_and_arch,
            extract_bytes_at_va,
            function_extent_from_disasm,
            load_binary,
        )

        fixture = _Path(__file__).parent / "fixtures" / "mini_mips32.elf"
        fmt, arch = detect_format_and_arch(fixture)
        assert (fmt, arch) == ("elf", "mips32")

        info = load_binary(fixture)
        assert info.endian == "big"
        assert info.text_va == 0x00401000

        swept = _capstone_sweep(fixture)
        assert [va for va, _s, _n in swept] == [0x00401000]
        assert function_extent_from_disasm(fixture, 0x00401000) == 12
        assert function_extent_from_disasm(fixture, 0x00401010) == 28

        fn1 = extract_bytes_at_va(info, 0x00401000, 12)
        fn2 = extract_bytes_at_va(info, 0x00401010, 28)
        mode = capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN
        cfg1 = build_cfg(fn1, 0x00401000, cs_mode=mode, cs_arch=capstone.CS_ARCH_MIPS)
        assert len(cfg1["blocks"]) == 1
        sim = cfg_similarity(fn2, fn2, 0x00401010, cs_mode=mode, cs_arch=capstone.CS_ARCH_MIPS)
        assert sim["overall"] == 100.0


class TestMipsObjectComparison:
    @pytest.mark.parametrize(("triple", "order"), [("mips", "big"), ("mipsel", "little")])
    def test_linked_jump_compares_opcode_and_destination(
        self, tmp_path: Path, triple: str, order: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import shutil
        import subprocess

        from rebrew.compare import coff_reloc
        from rebrew.compiler.compile import compile_and_compare
        from rebrew.matcher import compiler
        from rebrew.matcher.core import EXACT_SCORE_THRESHOLD, BuildResult
        from rebrew.matcher.parsers import parse_obj_symbol_and_relocs
        from rebrew.matching.ga import BinaryMatchingGA

        clang = shutil.which("clang")
        if clang is None:
            pytest.skip("clang is needed to assemble the MIPS fixture")
        source = tmp_path / "caller.s"
        source.write_text(
            ".text\n.set noreorder\n.globl caller\n.type caller,@function\n"
            "caller:\n jal callee\n nop\n.size caller, .-caller\n"
        )
        obj = tmp_path / "caller.o"
        compiled = subprocess.run(
            [
                clang,
                f"--target={triple}-linux-gnu",
                "-fno-pic",
                "-mno-abicalls",
                "-c",
                str(source),
                "-o",
                str(obj),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if "unknown target triple" in compiled.stderr:
            pytest.skip(compiled.stderr)
        assert compiled.returncode == 0, compiled.stderr

        code, offsets, typed = parse_obj_symbol_and_relocs(obj, "caller")
        assert code is not None
        assert typed
        monkeypatch.setattr(coff_reloc, "build_name_to_va", lambda _cfg: {"callee": 0x2000})
        monkeypatch.setattr(compiler, "generate_flag_combinations", lambda **_: [""])
        monkeypatch.setattr(
            compiler,
            "build_candidate_obj_only",
            lambda *args, **kwargs: BuildResult(
                ok=True, obj_bytes=code, reloc_offsets=offsets, typed_relocs=typed
            ),
        )
        for check_known_bindings in (False, True):
            cfg = SimpleNamespace(
                arch="mips32",
                target_binary=tmp_path / "absent",
                check_known_bindings=check_known_bindings,
            )
            for instruction, matches in [
                (0x0C000800, True),
                (0x08000800, False),
                (0x0C000801, False),
            ]:
                result = compile_and_compare(
                    cfg,
                    source,
                    "caller",
                    instruction.to_bytes(4, order) + bytes(4),
                    "",
                    _precompiled_obj=str(obj),
                    name_to_va={"callee": 0x2000},
                    section_va=0x1000,
                )
                assert result.matched is matches
                if matches:
                    assert result.status == "RELOC"

                if not check_known_bindings:
                    reference = instruction.to_bytes(4, order) + bytes(4)
                    with BinaryMatchingGA(
                        "", reference, "", "", "", "caller", tmp_path, cfg=cfg
                    ) as ga:
                        build = BuildResult(
                            ok=True, obj_bytes=code, reloc_offsets=offsets, typed_relocs=typed
                        )
                        assert (
                            ga._compute_fitness(build, "seed", "") < EXACT_SCORE_THRESHOLD
                        ) is matches
                    [(score, _)] = compiler.flag_sweep("", reference, "", "", "", "caller", cfg=cfg)
                    assert (score < EXACT_SCORE_THRESHOLD) is matches


_MIPS_PAIR_SOURCE = """\
.text
.set noreorder
.globl caller
.type caller,@function
caller:
 jal helper
 nop
 jal ext
 nop
.size caller, .-caller
.type helper,@function
helper:
 jr $ra
 nop
.size helper, .-helper
.globl load
.type load,@function
load:
 lui $v0, %hi(g_var)
 addiu $v0, $v0, %lo(g_var)
 jr $ra
 nop
.size load, .-load
"""


def _assemble_mips(tmp_path: Path, triple: str) -> Path:
    import shutil
    import subprocess

    clang = shutil.which("clang")
    if clang is None:
        pytest.skip("clang is needed to assemble the MIPS fixture")
    source = tmp_path / "pair.s"
    source.write_text(_MIPS_PAIR_SOURCE)
    obj = tmp_path / "pair.o"
    compiled = subprocess.run(
        [clang, f"--target={triple}-linux-gnu", "-fno-pic", "-mno-abicalls", "-c"]
        + [str(source), "-o", str(obj)],
        capture_output=True,
        text=True,
        check=False,
    )
    if "unknown target triple" in compiled.stderr:
        pytest.skip(compiled.stderr)
    assert compiled.returncode == 0, compiled.stderr
    return obj


def _mips_words(order: str, *words: int) -> bytes:
    return b"".join(word.to_bytes(4, order) for word in words)


class TestMipsHalfWordAndLocalJumps:
    """HI16/LO16 patch 16 bits; a jal to a static function names the section symbol."""

    _G_VAR = 0x80129000  # %lo is negative, so %hi carries to 0x8013
    _LUI_V0, _LUI_V1, _ADDIU_V0, _LW_V0 = 0x3C020000, 0x3C030000, 0x24420000, 0x8C420000
    _JR_RA = 0x03E00008

    def _compare(self, tmp_path: Path, triple: str, symbol: str, target: bytes, **cfg: Any) -> Any:
        from rebrew.compiler.compile import compile_and_compare

        obj = _assemble_mips(tmp_path, triple)
        config = SimpleNamespace(arch="mips32", target_binary=tmp_path / "absent", **cfg)
        return compile_and_compare(
            config,
            tmp_path / "pair.s",
            symbol,
            target,
            "",
            _precompiled_obj=str(obj),
            name_to_va={"g_var": self._G_VAR, "ext": 0x2000},
            section_va=0x1000,
        )

    @pytest.mark.parametrize(("triple", "order"), [("mips", "big"), ("mipsel", "little")])
    @pytest.mark.parametrize("check_known_bindings", [False, True])
    def test_linked_hi_lo_pair_matches(
        self, tmp_path: Path, triple: str, order: str, check_known_bindings: bool
    ) -> None:
        target = _mips_words(order, self._LUI_V0 | 0x8013, self._ADDIU_V0 | 0x9000, self._JR_RA, 0)
        result = self._compare(
            tmp_path, triple, "load", target, check_known_bindings=check_known_bindings
        )
        assert result.matched, result.message
        assert result.status == "RELOC"
        assert [row["status"] for row in result.relocation_bindings] == ["VALIDATED"] * 2

    @pytest.mark.parametrize(("triple", "order"), [("mips", "big"), ("mipsel", "little")])
    @pytest.mark.parametrize(
        ("hi", "lo"),
        [
            (0x3C030000 | 0x8013, 0x24420000 | 0x9000),  # lui $v1, not $v0
            (0x3C020000 | 0x8013, 0x8C420000 | 0x9000),  # lw, not addiu
        ],
    )
    def test_hi_lo_opcode_and_register_bits_are_compared(
        self, tmp_path: Path, triple: str, order: str, hi: int, lo: int
    ) -> None:
        target = _mips_words(order, hi, lo, self._JR_RA, 0)
        assert not self._compare(tmp_path, triple, "load", target).matched

    @pytest.mark.parametrize(("triple", "order"), [("mips", "big"), ("mipsel", "little")])
    def test_known_binding_rejects_wrong_hi_lo_address(
        self, tmp_path: Path, triple: str, order: str
    ) -> None:
        target = _mips_words(order, self._LUI_V0 | 0x8013, self._ADDIU_V0 | 0x9004, self._JR_RA, 0)
        result = self._compare(tmp_path, triple, "load", target, check_known_bindings=True)
        assert not result.matched
        assert [row["status"] for row in result.relocation_bindings] == [
            "VALIDATED",
            "CONFLICT",
        ]

    @pytest.mark.parametrize(("triple", "order"), [("mips", "big"), ("mipsel", "little")])
    def test_jal_to_static_function_binds_through_section_offset(
        self, tmp_path: Path, triple: str, order: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.compare import coff_reloc
        from rebrew.compare.coff_reloc import binding_evidence_current
        from rebrew.matcher.core import EXACT_SCORE_THRESHOLD, BuildResult
        from rebrew.matcher.parsers import parse_obj_symbol_and_relocs
        from rebrew.matching.ga import BinaryMatchingGA

        # caller at 0x1000, helper 0x10 bytes after it, ext at 0x2000
        target = _mips_words(order, 0x0C000404, 0, 0x0C000800, 0)
        result = self._compare(tmp_path, triple, "caller", target, check_known_bindings=True)
        assert result.matched, result.message
        rows = result.relocation_bindings
        assert [row["status"] for row in rows] == ["VALIDATED"] * 2
        assert binding_evidence_current(rows, {"g_var": self._G_VAR, "ext": 0x2000})

        wrong = _mips_words(order, 0x0C000405, 0, 0x0C000800, 0)
        assert not self._compare(tmp_path, triple, "caller", wrong).matched

        # The GA scores without the function VA: the local destination is masked.
        code, offsets, typed = parse_obj_symbol_and_relocs(tmp_path / "pair.o", "caller")
        cfg = SimpleNamespace(arch="mips32", target_binary=tmp_path / "absent")
        monkeypatch.setattr(coff_reloc, "build_name_to_va", lambda _cfg: {"ext": 0x2000})
        with BinaryMatchingGA("", target, "", "", "", "caller", tmp_path, cfg=cfg) as ga:
            build = BuildResult(ok=True, obj_bytes=code, reloc_offsets=offsets, typed_relocs=typed)
            assert ga._compute_fitness(build, "seed", "") < EXACT_SCORE_THRESHOLD
