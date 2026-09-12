"""Tests for rebrew.pe_headers — PE header field read/patch/parity."""

from pathlib import Path

from rebrew.pe_headers import (
    PATCHABLE,
    header_parity,
    patch_pe_headers,
    read_pe_header_fields,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "mini_pe.exe"


def _fixture() -> bytes:
    return _FIXTURE.read_bytes()


class TestReadFields:
    def test_reads_known_fields(self) -> None:
        fields = read_pe_header_fields(_fixture())
        assert fields is not None
        assert fields.get("stack_reserve") == 0x100000
        assert fields.get("timestamp") == 0

    def test_non_pe_returns_none(self) -> None:
        assert read_pe_header_fields(b"\x00" * 256) is None
        assert read_pe_header_fields(b"MZ" + b"\x00" * 62) is None

    def test_truncated_pe_returns_none(self) -> None:
        assert read_pe_header_fields(b"MZ") is None


class TestPatchHeaders:
    def test_patch_roundtrip(self) -> None:
        data = _fixture()
        patched = patch_pe_headers(data, {"stack_reserve": 0x200000})
        assert read_pe_header_fields(patched).get("stack_reserve") == 0x200000  # type: ignore[union-attr]
        # Original untouched.
        assert read_pe_header_fields(data).get("stack_reserve") == 0x100000  # type: ignore[union-attr]

    def test_characteristics_is_patchable(self) -> None:
        """COFF Characteristics carries DEBUG_STRIPPED (0x0200); a relink that
        drops it is patched to match the reference header."""
        assert "characteristics" in PATCHABLE
        data = _fixture()
        before = read_pe_header_fields(data).get("characteristics")
        assert before is not None
        patched = patch_pe_headers(data, {"characteristics": before | 0x0200})
        assert read_pe_header_fields(patched).get("characteristics") == before | 0x0200

    def test_file_align_not_patchable(self) -> None:
        assert "file_align" not in PATCHABLE
        data = _fixture()
        before = read_pe_header_fields(data).get("file_align")  # type: ignore[union-attr]
        patched = patch_pe_headers(data, {"file_align": 0x1000})
        assert read_pe_header_fields(patched).get("file_align") == before  # type: ignore[union-attr]

    def test_non_pe_passthrough(self) -> None:
        blob = b"\x00" * 64
        assert patch_pe_headers(blob, {"stack_reserve": 1}) == blob

    def test_truncated_optional_header_does_not_raise(self) -> None:
        """A PE cut before the checksum field must not raise struct.error."""
        data = _fixture()
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        truncated = data[: e_lfanew + 0x20]
        assert patch_pe_headers(truncated, {"stack_reserve": 0x200000}) == truncated


class TestPeChecksum:
    def test_large_file_checksum_keeps_the_length_term(self) -> None:
        """The spec ends with folded-sum + FileLength (the value may exceed
        0xFFFF).  An extra fold reduced a 108 KB file's 0x2A492 to 0xA494."""
        from rebrew.pe_headers import _pe_checksum

        data = _fixture() + b"\x00" * 200_000
        assert _pe_checksum(data) > 0xFFFF

    def test_checksum_verifies_with_pefile(self) -> None:
        """pefile recomputes the checksum independently; its verifier must
        accept the value patch_pe_headers writes."""
        import pytest

        pefile = pytest.importorskip("pefile")

        from rebrew.pe_headers import _pe_checksum

        data = _fixture() + b"\x00" * 200_000
        patched = patch_pe_headers(data, {"checksum": _pe_checksum(data)})
        assert pefile.PE(data=patched, fast_load=True).verify_checksum() is True


class TestHeaderParity:
    def test_identical_matches(self) -> None:
        data = _fixture()
        rows = header_parity(data, data)
        assert rows
        assert all(r["match"] for r in rows)

    def test_patched_field_mismatches(self) -> None:
        data = _fixture()
        patched = patch_pe_headers(data, {"stack_reserve": 0x200000})
        rows = {r["field"]: r for r in header_parity(data, patched)}
        assert rows["stack_reserve"]["match"] is False
        assert rows["timestamp"]["match"] is True

    def test_non_pe_returns_empty(self) -> None:
        assert header_parity(b"\x00" * 64, _fixture()) == []


class TestPeLayout:
    def test_pe_lfanew_on_fixture(self) -> None:
        from rebrew.pe_headers import pe_lfanew

        e = pe_lfanew(_fixture())
        assert e is not None and e > 0

    def test_pe_lfanew_non_pe(self) -> None:
        from rebrew.pe_headers import pe_lfanew

        assert pe_lfanew(b"\x00" * 256) is None
        assert pe_lfanew(b"MZ" + b"\x00" * 62) is None
        # NE images carry "NE" at e_lfanew, not "PE\0\0".
        ne = bytearray(b"MZ" + b"\x00" * 62)
        ne[0x3C:0x40] = (0x40).to_bytes(4, "little")
        ne[0x40:0x42] = b"NE"
        assert pe_lfanew(bytes(ne)) is None

    def test_pe_layout_geometry(self) -> None:
        from rebrew.pe_headers import SECTION_ENTRY_SIZE, pe_layout

        layout = pe_layout(_fixture())
        assert layout is not None
        assert layout.magic == 0x10B
        assert layout.optional_header_offset == layout.e_lfanew + 0x18
        assert (
            layout.section_table_offset
            == layout.optional_header_offset + layout.size_of_optional_header
        )
        assert len(layout.sections) == layout.number_of_sections
        assert layout.sections
        for index, section in enumerate(layout.sections):
            assert section.header_offset == layout.section_table_offset + SECTION_ENTRY_SIZE * index

    def test_pe_layout_non_pe(self) -> None:
        from rebrew.pe_headers import pe_layout

        assert pe_layout(b"\x00" * 256) is None

    def test_find_section(self) -> None:
        from rebrew.pe_headers import find_section

        data = _fixture()
        first = find_section(data, ".text")
        assert first is not None
        assert first.name == ".text"
        assert find_section(data, ".nope") is None

    def test_sections_at_clips_short_buffer(self) -> None:
        from rebrew.pe_headers import SECTION_ENTRY_SIZE, pe_layout, sections_at

        layout = pe_layout(_fixture())
        assert layout is not None
        assert sections_at(_fixture(), layout.section_table_offset, 0) == ()
        # Only one entry fits before the buffer ends, so a request for more
        # stops there instead of reading past the image.
        truncated = _fixture()[: layout.section_table_offset + SECTION_ENTRY_SIZE]
        assert len(sections_at(truncated, layout.section_table_offset, 5)) == 1
