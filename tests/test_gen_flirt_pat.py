"""Tests for rebrew.gen_flirt_pat — archive parsing and PAT line generation."""

from pathlib import Path

import pytest

from rebrew.gen_flirt_pat import bytes_to_pat_line, parse_archive

# ---------------------------------------------------------------------------
# parse_archive
# ---------------------------------------------------------------------------


class TestParseArchive:
    """Tests for parse_archive()."""

    def _make_archive(self, members: list[tuple[str, bytes]], path: Path) -> Path:
        """Build a minimal COFF archive (.lib) file."""
        buf = bytearray(b"!<arch>\n")
        for name, data in members:
            # Archive member header is exactly 60 bytes
            name_field = (name + "/").ljust(16).encode("ascii")[:16]
            # date, uid, gid, mode fields (all spaces)
            filler = b"0           0     0     100644  "
            size_field = str(len(data)).ljust(10).encode("ascii")
            end = b"`\n"
            header = name_field + filler + size_field + end
            assert len(header) == 60
            buf += header
            buf += data
            if len(data) % 2 == 1:
                buf += b"\n"  # padding
        out = path / "test.lib"
        out.write_bytes(bytes(buf))
        return out

    def test_valid_archive(self, tmp_path: Path) -> None:
        """Parses a valid archive and yields members."""
        lib = self._make_archive([("foo.obj", b"\x00" * 20)], tmp_path)
        members = list(parse_archive(str(lib)))
        assert len(members) == 1
        assert members[0][0] == "foo.obj"
        assert members[0][1] == b"\x00" * 20

    def test_multiple_members(self, tmp_path: Path) -> None:
        """Multiple members are all yielded."""
        lib = self._make_archive(
            [("a.obj", b"\x01\x02"), ("b.obj", b"\x03\x04\x05")],
            tmp_path,
        )
        members = list(parse_archive(str(lib)))
        assert len(members) == 2
        assert members[0][0] == "a.obj"
        assert members[1][0] == "b.obj"

    def test_skips_special_members(self, tmp_path: Path) -> None:
        """Special archive members (/, //) are skipped."""
        # Build archive with a "/" member (symbol table) and a real member
        buf = bytearray(b"!<arch>\n")
        # "/" member
        name_field = "/               ".encode("ascii")[:16]
        filler = b"0           0     0     100644  "
        data = b"\x00" * 4
        size_field = str(len(data)).ljust(10).encode("ascii")
        end = b"`\n"
        buf += name_field + filler + size_field + end + data
        # Real member
        name_field = "real.obj/       ".encode("ascii")[:16]
        data = b"\xff" * 10
        size_field = str(len(data)).ljust(10).encode("ascii")
        buf += name_field + filler + size_field + end + data
        lib = tmp_path / "test.lib"
        lib.write_bytes(bytes(buf))

        members = list(parse_archive(str(lib)))
        assert len(members) == 1
        assert members[0][0] == "real.obj"

    def test_invalid_magic_raises(self, tmp_path: Path) -> None:
        """Non-archive file raises ValueError."""
        bad = tmp_path / "bad.lib"
        bad.write_bytes(b"not an archive")
        with pytest.raises(ValueError, match="not a valid archive"):
            list(parse_archive(str(bad)))

    def test_empty_archive(self, tmp_path: Path) -> None:
        """Archive with only magic header yields no members."""
        lib = tmp_path / "empty.lib"
        lib.write_bytes(b"!<arch>\n")
        members = list(parse_archive(str(lib)))
        assert members == []


# ---------------------------------------------------------------------------
# bytes_to_pat_line
# ---------------------------------------------------------------------------


class TestBytesToPatLine:
    """Tests for bytes_to_pat_line()."""

    def test_basic_format(self) -> None:
        """Output has correct FLIRT .pat format structure."""
        code = b"\x55\x8b\xec\x83\xec\x08"
        line = bytes_to_pat_line("_my_func", code, set())
        # Format: <hex_lead> <crc_len> <crc> <total_size> :0000 <name>
        parts = line.split()
        assert parts[-2] == ":0000"
        assert parts[-1] == "_my_func"

    def test_reloc_bytes_masked(self) -> None:
        """Relocation offsets produce '..' in the leading portion."""
        code = b"\x55\x8b\xec\xe8\x00\x00\x00\x00"
        relocs = {3, 4, 5, 6, 7}  # call target bytes
        line = bytes_to_pat_line("_foo", code, relocs)
        lead = line.split()[0]
        # Bytes 0-2 are hex, bytes 3-7 are masked
        assert lead[:6] == "558BEC"
        assert ".." in lead

    def test_no_relocs_all_hex(self) -> None:
        """Without relocations, all leading bytes are hex."""
        code = b"\x55\x8b\xec\xc3"
        line = bytes_to_pat_line("_bar", code, set())
        lead = line.split()[0]
        assert lead == "558BECC3"
        assert ".." not in lead

    def test_max_lead_32(self) -> None:
        """Default max_lead=32 limits leading hex to 32 bytes."""
        code = bytes(range(64))
        line = bytes_to_pat_line("_long", code, set())
        lead = line.split()[0]
        # 32 bytes × 2 hex chars = 64 chars
        assert len(lead) == 64

    def test_custom_max_lead(self) -> None:
        """Custom max_lead parameter is respected."""
        code = bytes(range(64))
        line = bytes_to_pat_line("_short", code, set(), max_lead=8)
        lead = line.split()[0]
        assert len(lead) == 16  # 8 bytes × 2 hex chars

    def test_short_code_uses_full_length(self) -> None:
        """Code shorter than max_lead uses full length."""
        code = b"\xc3"
        line = bytes_to_pat_line("_tiny", code, set())
        lead = line.split()[0]
        assert lead == "C3"

    def test_total_size_field(self) -> None:
        """Total size field matches actual code length."""
        code = b"\x55\x8b\xec\xc3"
        line = bytes_to_pat_line("_sz", code, set())
        # Total size is the 4th field (0-indexed: lead, crc_len, crc, total_size)
        parts = line.split()
        total_size = int(parts[3], 16)
        assert total_size == len(code)

    def test_crc_deterministic(self) -> None:
        """Same input produces same CRC."""
        code = b"\x55\x8b\xec\x83\xec\x08\x56\x57"
        line1 = bytes_to_pat_line("_det", code, set())
        line2 = bytes_to_pat_line("_det", code, set())
        assert line1 == line2

    def test_crc_differs_with_different_code(self) -> None:
        """Different code bytes beyond the lead produce different CRC."""
        # Make code longer than max_lead so CRC portion differs
        code1 = bytes(range(64))
        code2 = bytes(range(64))
        code2_list = list(code2)
        code2_list[40] = 0xFF
        code2_mod = bytes(code2_list)
        line1 = bytes_to_pat_line("_d", code1, set())
        line2 = bytes_to_pat_line("_d", code2_mod, set())
        # CRC field (3rd field) should differ
        crc1 = line1.split()[2]
        crc2 = line2.split()[2]
        assert crc1 != crc2
