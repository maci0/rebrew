"""Real linked-image relocation tables, rebuilt with LIEF without executing a fixture."""

from pathlib import Path

import lief
import pytest

from rebrew.binary_loader import extract_bytes_at_va, load_binary
from rebrew.binary_model import BinaryInfo
from rebrew.relocations import relocation_spans

_FIXTURE = Path(__file__).parent / "fixtures" / "mini_pe.exe"


def _image(tmp_path: Path, kind: lief.PE.RelocationEntry.BASE_TYPES) -> BinaryInfo:
    if kind == lief.PE.RelocationEntry.BASE_TYPES.DIR64:
        factory = lief.PE.Factory.create(lief.PE.PE_TYPE.PE32_PLUS)
        assert factory is not None
        section = lief.PE.Section(".text")
        section.content = [0x90] * 16
        section.virtual_size = 16
        section.sizeof_raw_data = 512
        flags = lief.PE.Section.CHARACTERISTICS
        section.characteristics = int(flags.CNT_CODE) | int(flags.MEM_READ) | int(flags.MEM_EXECUTE)
        factory.add_section(section)
        binary = factory.get()
        assert binary is not None
        binary.optional_header.addressof_entrypoint = 0x1000
    else:
        binary = lief.PE.parse(_FIXTURE)
        assert binary is not None
        section = binary.get_section(".text")
        assert section is not None
        section.virtual_size = 16
    block = lief.PE.Relocation()
    block.virtual_address = 0x1000
    block.add_entry(lief.PE.RelocationEntry(4, kind))
    binary.add_relocation(block)
    path = tmp_path / "relocations.exe"
    binary.write(path)
    return load_binary(path)


class TestRelocationSpans:
    @pytest.mark.parametrize(
        ("kind", "width"),
        [
            (lief.PE.RelocationEntry.BASE_TYPES.HIGHLOW, 4),
            (lief.PE.RelocationEntry.BASE_TYPES.DIR64, 8),
        ],
    )
    def test_typed_width_and_absolute_address(
        self, tmp_path: Path, kind: lief.PE.RelocationEntry.BASE_TYPES, width: int
    ) -> None:
        info = _image(tmp_path, kind)
        assert info.arch == ("x86_64" if width == 8 else "x86_32")
        assert relocation_spans(info) == [(info.image_base + 0x1004, width)]

    def test_unknown_fixup_refuses_the_entire_map(self, tmp_path: Path) -> None:
        info = _image(tmp_path, lief.PE.RelocationEntry.BASE_TYPES.HIGHADJ)
        with pytest.raises(NotImplementedError, match="unsupported PE relocation"):
            relocation_spans(info)

    def test_no_fixups_is_an_empty_map(self) -> None:
        assert relocation_spans(load_binary(_FIXTURE)) == []

    def test_unsupported_format_is_not_an_empty_map(self, tmp_path: Path) -> None:
        with pytest.raises(NotImplementedError, match="unavailable"):
            relocation_spans(BinaryInfo(path=tmp_path / "unused", format="macho", arch="x86_64"))

    def test_mismatched_layout_and_unmapped_fixup_refuse(self, tmp_path: Path) -> None:
        info = _image(tmp_path, lief.PE.RelocationEntry.BASE_TYPES.HIGHLOW)
        info.image_base += 1
        with pytest.raises(ValueError, match="loaded layout"):
            relocation_spans(info)
        info.image_base -= 1
        info.sections.clear()
        with pytest.raises(ValueError, match="file-backed"):
            relocation_spans(info)

    def test_span_limit_refuses_instead_of_truncating(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        info = _image(tmp_path, lief.PE.RelocationEntry.BASE_TYPES.HIGHLOW)
        monkeypatch.setattr("rebrew.relocations._MAX_SPANS", 0)
        with pytest.raises(ValueError, match="limit exceeded"):
            relocation_spans(info)

    def test_rebased_pointer_masks_only_the_declared_field(self, tmp_path: Path) -> None:
        info = _image(tmp_path, lief.PE.RelocationEntry.BASE_TYPES.HIGHLOW)
        address, width = relocation_spans(info)[0]
        raw = extract_bytes_at_va(info, info.image_base + 0x1000, 16, trim_padding=False)
        assert raw is not None and len(raw) == 16
        offset = address - (info.image_base + 0x1000)
        rebased = bytearray(raw)
        rebased[offset : offset + width] = (0x12345678).to_bytes(width, "little")
        masked = bytearray(raw)
        masked[offset : offset + width] = bytes(width)
        rebased[offset : offset + width] = bytes(width)
        assert masked == rebased
        rebased[0] ^= 1
        assert masked != rebased


class TestElfRelocationSpans:
    def test_real_dynamic_relocation(self, tmp_path: Path) -> None:
        info = _elf_image(tmp_path, lief.ELF.Relocation.TYPE.X86_RELATIVE)
        assert relocation_spans(info) == [(0x401004, 4)]

    def test_unknown_kind_refuses(self, tmp_path: Path) -> None:
        info = _elf_image(tmp_path, lief.ELF.Relocation.TYPE.X86_COPY)
        with pytest.raises(NotImplementedError, match="unsupported ELF relocation"):
            relocation_spans(info)

    def test_empty_linked_image(self) -> None:
        assert relocation_spans(load_binary(_FIXTURE.with_name("mini.elf"))) == []

    def test_layout_and_unmapped_fixup(self, tmp_path: Path) -> None:
        info = _elf_image(tmp_path, lief.ELF.Relocation.TYPE.X86_RELATIVE)
        info.image_base += 1
        with pytest.raises(ValueError, match="loaded layout"):
            relocation_spans(info)
        info.image_base -= 1
        info.sections.clear()
        with pytest.raises(ValueError, match="file-backed"):
            relocation_spans(info)


def _elf_image(tmp_path: Path, kind: lief.ELF.Relocation.TYPE) -> BinaryInfo:
    binary = lief.ELF.parse(_FIXTURE.with_name("mini.elf"))
    assert binary is not None
    section = lief.ELF.Section(".dynamic", lief.ELF.Section.TYPE.DYNAMIC)
    section.content = [0] * 128
    section.flags = int(lief.ELF.Section.FLAGS.ALLOC) | int(lief.ELF.Section.FLAGS.WRITE)
    section.entry_size = 8
    binary.add(section)
    path = tmp_path / "relocations.elf"
    binary.write(path)
    binary = lief.ELF.parse(path)
    assert binary is not None
    section = binary.get_section(".dynamic")
    assert section is not None
    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPE.DYNAMIC
    segment.flags = lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.W
    segment.content = list(section.content)
    segment.virtual_address = section.virtual_address
    segment.physical_address = section.virtual_address
    segment.file_offset = section.offset
    segment.alignment = 4
    binary.add(segment)
    binary.write(path)
    binary = lief.ELF.parse(path)
    assert binary is not None
    tags = lief.ELF.DynamicEntry.TAG
    for tag, value in ((tags.REL, 0), (tags.RELSZ, 8), (tags.RELENT, 8)):
        binary.add(lief.ELF.DynamicEntry(tag, value))
    binary.add_dynamic_relocation(
        lief.ELF.Relocation(0x401004, kind, lief.ELF.Relocation.ENCODING.REL)
    )
    binary.write(path)
    return load_binary(path)
