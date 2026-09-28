"""Tests for binary_loader.py internals — PE/ELF loaders and size guard."""

import enum
from pathlib import Path
from types import SimpleNamespace

import lief
import pytest

import rebrew.binary_loader as bl

#: The bit ``_load_pe`` asks every section whether it carries.
_PE_EXECUTE = lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE


def _mock_section(
    name: str,
    va: int,
    vsize: int,
    raw_offset: int,
    raw_size: int,
    executable: bool = False,
) -> SimpleNamespace:
    # ``_load_pe`` reads the execute bit off every section to alias the largest
    # executable one to ``.text``, so the double carries it rather than leaving
    # the loader to raise on a stand-in it cannot interrogate.
    return SimpleNamespace(
        name=name,
        virtual_address=va,
        virtual_size=vsize,
        pointerto_raw_data=raw_offset,
        sizeof_raw_data=raw_size,
        has_characteristic=lambda flag: bool(executable) and flag == _PE_EXECUTE,
    )


def _mock_elf_section(
    name: str,
    va: int,
    size: int,
    offset: int,
    flags: int = 0x4,  # SHF_EXECINSTR
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        virtual_address=va,
        size=size,
        original_size=size,
        offset=offset,
        flags=flags,
    )


class _FakeELFData(enum.Enum):
    """Stand-in for the LIEF ``ELF_DATA`` enum (not importable by name)."""

    LSB = 1
    MSB = 2


class _FakeELFClass(enum.Enum):
    """Stand-in for the LIEF ``CLASS`` enum (not importable by name)."""

    ELF32 = 1
    ELF64 = 2


def _mock_elf_header() -> SimpleNamespace:
    return SimpleNamespace(
        machine_type=0,
        identity_data=_FakeELFData.LSB,
        identity_class=_FakeELFClass.ELF32,
    )


class TestLoadPe:
    def test_sections_and_text(self) -> None:
        pe = SimpleNamespace(
            header=SimpleNamespace(machine=0),
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
            header=SimpleNamespace(machine=0),
            optional_header=SimpleNamespace(imagebase=0x400000),
            sections=[_mock_section(".data", 0x2000, 0x100, 0x600, 0x100)],
        )
        info = bl._load_pe(pe, Path("/tmp/x.exe"))
        assert info.text_va == 0x400000  # falls back to image base
        assert info.text_size == 0

    def test_largest_executable_section_aliases_text(self) -> None:
        """Borland/Delphi/Watcom name the code section ``CODE``, not ``.text``.

        Without the alias every consumer that reads the text window (the FLIRT
        scan, the jump-table probe behind ``_resolve_canonical_size``) sees an
        empty code region, so the execute bit is what the aliasing reads.
        """
        pe = SimpleNamespace(
            header=SimpleNamespace(machine=0),
            optional_header=SimpleNamespace(imagebase=0x400000),
            sections=[
                _mock_section("CODE", 0x1000, 0x200, 0x400, 0x200, executable=True),
                _mock_section("CODE2", 0x2000, 0x40, 0x600, 0x40, executable=True),
                _mock_section("DATA", 0x3000, 0x100, 0x700, 0x100),
            ],
        )
        info = bl._load_pe(pe, Path("/tmp/x.exe"))
        assert (info.text_va, info.text_size) == (0x401000, 0x200)
        assert info.text_raw_offset == 0x400

    def test_data_only_image_gets_no_code_alias(self) -> None:
        """The alias follows the execute bit, not the section's name.

        A section called ``CODE`` that is not executable is data, and aliasing
        it would point the text window at bytes that never run.
        """
        pe = SimpleNamespace(
            header=SimpleNamespace(machine=0),
            optional_header=SimpleNamespace(imagebase=0x400000),
            sections=[_mock_section("CODE", 0x1000, 0x200, 0x400, 0x200)],
        )
        info = bl._load_pe(pe, Path("/tmp/x.exe"))
        assert info.text_va == 0x400000
        assert info.text_size == 0


class TestLoadElf:
    def test_sections_and_image_base(self) -> None:
        elf = SimpleNamespace(
            header=_mock_elf_header(),
            segments=[SimpleNamespace(type=1, virtual_address=0x1000)],  # PT_LOAD
            sections=[_mock_elf_section(".text", 0x1000, 0x200, 0x400)],
        )
        info = bl._load_elf(elf, Path("/tmp/x.so"))
        assert info.format == "elf"
        assert info.image_base == 0x1000  # lowest PT_LOAD VA
        assert info.text_va == 0x1000
        assert info.text_size == 0x200

    def test_sectionless_exec_segment_becomes_code(self) -> None:
        """sstrip'd ELFs (every OpenWrt package) have PT_LOAD and no sections."""
        elf = SimpleNamespace(
            header=_mock_elf_header(),
            segments=[
                SimpleNamespace(
                    type=1,
                    virtual_address=0x2000,
                    flags=1,  # X
                    physical_size=0x400,
                    virtual_size=0x400,
                    file_offset=0x1000,
                ),
                SimpleNamespace(
                    type=1,
                    virtual_address=0x3000,
                    flags=6,  # R|W, not executable
                    physical_size=0x200,
                    virtual_size=0x200,
                    file_offset=0x1400,
                ),
            ],
            sections=[],
        )
        info = bl._load_elf(elf, Path("/tmp/x"))
        assert "SEG0" in info.sections
        assert info.sections["SEG0"].is_code
        assert info.sections["SEG0"].raw_size == 0x400
        assert "SEG1" not in info.sections  # data segment stays out of the scan
        # `.text` alias for consumers that ask by name; not flagged code, so the
        # scanner does not visit the same bytes twice.
        assert ".text" in info.sections
        assert not info.sections[".text"].is_code
        assert info.text_va == 0x2000
        assert info.text_size == 0x400

    def test_sectionless_zero_size_segment_skipped(self) -> None:
        elf = SimpleNamespace(
            header=_mock_elf_header(),
            segments=[
                SimpleNamespace(
                    type=1,
                    virtual_address=0x1000,
                    flags=1,
                    physical_size=0,
                    virtual_size=0x100,
                    file_offset=0x400,
                )
            ],
            sections=[],
        )
        info = bl._load_elf(elf, Path("/tmp/x"))
        assert not [name for name in info.sections if name.startswith("SEG")]

    def test_load_segment_image_base(self) -> None:
        elf = SimpleNamespace(
            header=_mock_elf_header(),
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
            header=_mock_elf_header(),
            segments=[],
            sections=[SimpleNamespace(name="", virtual_address=0, size=0, offset=0)],
        )
        info = bl._load_elf(elf, Path("/tmp/x.so"))
        assert info.sections == {}


class TestElfWordSize:
    """``EM_MIPS`` covers both 32- and 64-bit images; EI_CLASS decides."""

    @staticmethod
    def _header(elf_class: int) -> bytes:
        """A minimal header-only ELF for *elf_class* (``1`` = ELF32, ``2`` = ELF64)."""
        import struct

        ident = b"\x7fELF" + bytes([elf_class, 1, 1, 0]) + b"\0" * 8  # EI_DATA = LSB
        if elf_class == 2:
            rest = struct.pack(
                "<HHIQQQIHHHHHH",
                2,
                8,
                1,  # ET_EXEC, EM_MIPS, EV_CURRENT
                0x400000,
                0x400078,
                0,
                0,  # entry, phoff, shoff, flags
                64,
                56,
                0,
                0,
                64,
                0,
            )
        else:
            rest = struct.pack(
                "<HHIIIIIHHHHHH",
                2,
                8,
                1,  # ET_EXEC, EM_MIPS, EV_CURRENT
                0x400000,
                0x400034,
                0,
                0,
                52,
                32,
                0,
                0,
                40,
                0,
            )
        return ident + rest

    @pytest.mark.parametrize(("elf_class", "expected"), [(1, "mips32"), (2, "mips64")])
    def test_mips_class_byte_picks_the_width(
        self, tmp_path: Path, elf_class: int, expected: str
    ) -> None:
        f = tmp_path / f"mips{elf_class * 32}.elf"
        f.write_bytes(self._header(elf_class))
        assert bl.load_binary(f).arch == expected

    @pytest.mark.parametrize(("elf_class", "expected"), [(1, 4), (2, 8)])
    def test_pointer_size_comes_from_the_class_byte(
        self, tmp_path: Path, elf_class: int, expected: int
    ) -> None:
        f = tmp_path / f"mips{elf_class * 32}.elf"
        f.write_bytes(self._header(elf_class))
        assert bl.load_binary(f).pointer_size == expected

    def test_mips64_loader_reports_arch_and_width(self) -> None:
        """``.eh_frame`` sizing reads pointer_size, not the arch name suffix."""
        import lief

        elf = SimpleNamespace(
            header=SimpleNamespace(
                machine_type=lief.ELF.ARCH.MIPS,
                identity_data=_FakeELFData.LSB,
                identity_class=_FakeELFClass.ELF64,
            ),
            segments=[SimpleNamespace(type=1, virtual_address=0x1000)],
            sections=[],
        )
        info = bl._load_elf(elf, Path("/tmp/mips64.elf"))
        assert (info.arch, info.pointer_size) == ("mips64", 8)

    def test_x86_64_elf_keeps_its_map_name_and_width(self) -> None:
        """EI_CLASS must not rewrite an arch the machine enum already split."""
        import lief

        elf = SimpleNamespace(
            header=SimpleNamespace(
                machine_type=lief.ELF.ARCH.X86_64,
                identity_data=_FakeELFData.LSB,
                identity_class=_FakeELFClass.ELF64,
            ),
            segments=[SimpleNamespace(type=1, virtual_address=0x1000)],
            sections=[],
        )
        info = bl._load_elf(elf, Path("/tmp/x86_64.so"))
        assert (info.arch, info.pointer_size) == ("x86_64", 8)


class TestBinaryInfoData:
    def test_oversized_file_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew import binary_model

        f = tmp_path / "big.bin"
        f.write_bytes(b"\x00" * 16)
        info = binary_model.BinaryInfo(
            path=f,
            format="raw",
            image_base=0,
            text_va=0,
            text_size=0,
            text_raw_offset=0,
            sections={},
        )
        monkeypatch.setattr(binary_model, "MAX_BINARY_SIZE", 4)  # 16-byte file exceeds 4
        with pytest.raises(ValueError, match="too large"):
            _ = info.data


class TestObjectArch:
    """An archive member's ISA, read from its own header."""

    FIXTURES = Path(__file__).parent / "fixtures"

    @pytest.mark.parametrize(
        ("name", "expected"),
        [("mini.obj", ("x86_32", "little")), ("thumb_arm.o", ("arm32", "little"))],
    )
    def test_elf_and_coff_objects(self, name: str, expected: tuple[str, str]) -> None:
        from rebrew.binary_loader import object_arch

        assert object_arch((self.FIXTURES / name).read_bytes()) == expected

    def test_an_omf_or_junk_object_is_unknown(self) -> None:
        from rebrew.binary_loader import object_arch

        assert object_arch((self.FIXTURES / "tg_watcom.o").read_bytes()) is None
        assert object_arch(b"\x7fELF" + b"\x00" * 8) is None
