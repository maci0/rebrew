"""Tests for rebrew.gen_flirt_pat — archive parsing and PAT line generation."""

import struct
from types import SimpleNamespace
lazy from pathlib import Path

import pytest
from bin_util import make_coff_obj, make_lib_archive
from cli_json import cli_payload
from hypothesis import strategies as st

from rebrew.compiler.toolchain_paths import toolchains_repo
from rebrew.gen_flirt_pat import ObjectFunction, _crc16_flirt, bytes_to_pat_line, parse_archive

#: MSVC 6.0's multithreaded static CRT, where the recompile-toolchains checkout
#: (REBREW_TOOLCHAINS_DIR) vendors the compiler.
_VC98_LIBCMT = toolchains_repo() / "msvc" / "6.0-win32" / "source" / "VC98" / "Lib" / "LIBCMT.LIB"

#: One assembly routine ``_copy`` with a jump table ``Vec`` and labels
#: ``Case0``-``Case2`` and ``Tail``, then ``_next``, which calls ``Helper``.
_ASM_ROUTINE = bytes.fromhex(
    "8b442404"  # 00 mov eax, [esp+4]
    "83f802"  # 04 cmp eax, 2
    "7723"  # 07 ja Tail
    "ff248500000000"  # 09 jmp [eax*4 + Vec]   (DIR32 at 0c)
    "000000000000000000000000"  # 10 Vec: dd Case0, Case1, Case2
    "31c0c3"  # 1c Case0: xor eax, eax; ret
    "b801000000c3"  # 1f Case1: mov eax, 1; ret
    "b802000000eb00"  # 25 Case2: mov eax, 2; jmp Tail
    "40c3"  # 2c Tail: inc eax; ret
    "e801000000c3"  # 2e _next: call Helper; ret
    "40c3"  # 34 Helper: inc eax; ret
)

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

    @pytest.mark.parametrize("consumer", ["parse", "cache"])
    @pytest.mark.parametrize("terminator", [b"`\n", b"\0\0", b"\n\n", b"`x"])
    def test_member_header_terminator_is_validated(
        self, tmp_path: Path, consumer: str, terminator: bytes
    ) -> None:
        from rebrew.formats.archives import stock_lib_valid

        archive = self._make_archive([("foo.obj", b"body")], tmp_path)
        data = bytearray(archive.read_bytes())
        data[66:68] = terminator
        archive.write_bytes(data)
        valid = terminator == b"`\n"
        if consumer == "cache":
            assert stock_lib_valid(archive) is valid
        elif valid:
            assert list(parse_archive(str(archive))) == [("foo.obj", b"body")]
        else:
            with pytest.raises(ValueError, match="archive member header"):
                list(parse_archive(str(archive)))

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

    @pytest.mark.parametrize("name", ["foo.obj", "/", ""])
    @pytest.mark.parametrize("remaining", [0, 3])
    def test_rejects_truncated_member_body(self, tmp_path: Path, name: str, remaining: int) -> None:
        lib = self._make_archive([(name, b"1234")], tmp_path)
        lib.write_bytes(lib.read_bytes()[: 68 + remaining])
        with pytest.raises(ValueError, match="truncated archive member"):
            list(parse_archive(str(lib)))

    def test_empty_archive(self, tmp_path: Path) -> None:
        """Archive with only magic header yields no members."""
        lib = tmp_path / "empty.lib"
        lib.write_bytes(b"!<arch>\n")
        members = list(parse_archive(str(lib)))
        assert members == []

    @pytest.mark.parametrize("delimiter", [b"\0", b"/\n"])
    def test_resolves_long_member_names(self, tmp_path: Path, delimiter: bytes) -> None:
        first = b"build/intel/mt_obj/fread.obj"
        second = b"build/intel/mt_obj/fwrite.obj"
        table = first + delimiter + second + delimiter
        offset = len(first) + len(delimiter)
        lib = self._make_archive(
            [("/", table), ("/0", b"read"), (f"/{offset}", b"write")], tmp_path
        )
        assert list(parse_archive(str(lib))) == [
            (first.decode(), b"read"),
            (second.decode(), b"write"),
        ]

    def test_mixed_names_and_interior_offsets(self, tmp_path: Path) -> None:
        table = b"prefix/name\0second/name/\nlast\0"
        lib = self._make_archive(
            [("/", table), ("/7", b"a"), ("/12", b"b"), ("/25", b"c")], tmp_path
        )
        assert list(parse_archive(str(lib))) == [
            ("name", b"a"),
            ("second/name", b"b"),
            ("last", b"c"),
        ]

    @pytest.mark.parametrize(
        "table, offset", [(b"", 0), (b"name\0", 99), (b"name", 0), (b"name\0\0", 5)]
    )
    def test_rejects_invalid_long_member_names(
        self, tmp_path: Path, table: bytes, offset: int
    ) -> None:
        lib = self._make_archive([("/", table), (f"/{offset}", b"object")], tmp_path)
        with pytest.raises(ValueError, match="invalid long"):
            list(parse_archive(str(lib)))


# ---------------------------------------------------------------------------
# Hypothesis fuzz — ar archive member-size parser on untrusted .lib bytes
# ---------------------------------------------------------------------------


@st.composite
def _ar_archive_bytes(draw: st.DrawFn) -> bytes:
    """Plausible ``!<arch>`` stream: typed member headers with LE/ASCII sizes,
    occasionally truncated or with a lying size field."""
    out = bytearray(b"!<arch>\n")
    n = draw(st.integers(min_value=0, max_value=12))
    for _ in range(n):
        if len(out) % 2 == 1:
            out.append(0x0A)
        name = draw(st.sampled_from([b"obj.o/", b"foo.obj/", b"/", b"//", b"longname.obj/"]))
        name_field = name.ljust(16, b" ")[:16]
        body = draw(st.binary(min_size=0, max_size=48))
        # Sometimes claim a size larger/smaller than the trailing bytes so the
        # length gate and slice must degrade cleanly.
        claimed = draw(
            st.one_of(
                st.just(len(body)),
                st.integers(min_value=0, max_value=10_000),
                st.sampled_from([b"notadigit  ", b"          "]),
            )
        )
        if isinstance(claimed, bytes):
            size_field = claimed[:10].ljust(10, b" ")
        else:
            size_field = str(claimed).ljust(10).encode("ascii")[:10]
        header = name_field + b"0           0     0     100644  " + size_field + b"`\n"
        assert len(header) == 60
        out += header
        out += body
    if out and draw(st.booleans()):
        cut = draw(st.integers(min_value=0, max_value=len(out)))
        return bytes(out[:cut])
    return bytes(out)


def _consume_archive(path: Path) -> list[tuple[str, bytes]]:
    """Run parse_archive and assert member shape on success."""
    members = list(parse_archive(str(path)))
    for name, data in members:
        assert isinstance(name, str)
        assert isinstance(data, (bytes, bytearray))
    return members


class TestParseArchiveFuzz:
    def test_random_bytes_no_crash(self, tmp_path: Path) -> None:
        """Arbitrary .lib bytes: parse yields members or ValueError — never
        IndexError/struct.error/UnicodeDecodeError."""
        from contextlib import suppress

        from hypothesis import given, settings
        from hypothesis import strategies as st

        @given(st.binary(min_size=0, max_size=512))
        @settings(max_examples=200, deadline=None)
        def _check(blob: bytes) -> None:
            p = tmp_path / f"fuzz_{len(blob)}.lib"
            p.write_bytes(blob)
            with suppress(ValueError):
                _consume_archive(p)

        _check()

    def test_structured_ar_stream_no_crash(self, tmp_path: Path) -> None:
        """Structure-aware ar member streams exercise the size/pad/skip paths."""
        from contextlib import suppress

        from hypothesis import given, settings

        @given(_ar_archive_bytes())
        @settings(max_examples=150, deadline=None)
        def _check(blob: bytes) -> None:
            p = tmp_path / f"ar_{len(blob)}.lib"
            p.write_bytes(blob)
            with suppress(ValueError):
                _consume_archive(p)

        _check()


# ---------------------------------------------------------------------------
# bytes_to_pat_line
# ---------------------------------------------------------------------------


class TestCrc16Flirt:
    """IDA's FLIRT CRC16 — must match what sigmake emits and python-flirt
    verifies.  A wrong variant yields .pat signatures that parse but never
    match (silent false negatives), which is exactly the bug this pins."""

    def test_empty(self) -> None:
        assert _crc16_flirt(b"") == 0

    def test_known_answers(self) -> None:
        # Reflected poly 0x8408 (= reflected 0x1021), init 0xFFFF, final
        # bitwise invert, byte-swapped.  Values computed from the port of
        # flair/crc16.cpp (lancelot flirt::FlirtSignature::crc16).
        assert _crc16_flirt(b"\x01\x02") == 0x8D35
        assert _crc16_flirt(b"123456789") == 0x6E90
        assert _crc16_flirt(b"\x55\x8b\xec\x83\xec\x08") == 0x9762

    def test_differs_from_old_nonreflected_variant(self) -> None:
        """Guard against regression to the old non-reflected-0x8005 CRC."""
        assert _crc16_flirt(b"123456789") != 0xFEE8


class TestElfFixupWidth:
    """LIEF's reloc size is unusable on some targets; the type has to decide."""

    def _reloc(self, type_name, size_bits):
        from types import SimpleNamespace

        return SimpleNamespace(type=type_name, size=size_bits)

    def test_sane_size_wins(self) -> None:
        from rebrew.gen_flirt_pat import _elf_fixup_width

        # 32 bits -> 4 bytes, the ordinary ELF case.
        assert _elf_fixup_width(self._reloc("RISCV_32", 32)) == 4
        assert _elf_fixup_width(self._reloc("X86_64_RELATIVE", 64)) == 8

    def test_riscv_branch_size_minus_one_masks_the_word(self) -> None:
        from rebrew.gen_flirt_pat import _elf_fixup_width

        # LIEF reports size == -1 (2**64-1) for every RISC-V relocation; masking
        # one byte left three bytes of a link-time immediate in the pattern.
        minus_one = (2**64) - 1
        assert _elf_fixup_width(self._reloc("RISCV_BRANCH", minus_one)) == 4
        assert _elf_fixup_width(self._reloc("RISCV_CALL_PLT", minus_one)) == 8
        assert _elf_fixup_width(self._reloc("RISCV_RVC_JUMP", minus_one)) == 2

    def test_unknown_type_falls_back_to_the_instruction_word(self) -> None:
        from rebrew.gen_flirt_pat import _elf_fixup_width

        assert _elf_fixup_width(self._reloc("SOMETHING_NEW", 0)) == 4


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

    def test_property_fields_consistent(self) -> None:
        """Property: for arbitrary code bytes + reloc offsets, the emitted
        line's fields are internally consistent (lead length, CRC window
        length truncated before the first tail reloc, total size) and the
        output is deterministic."""
        from hypothesis import given, settings
        from hypothesis import strategies as st

        @given(
            st.binary(min_size=0, max_size=300), st.sets(st.integers(min_value=0, max_value=299))
        )
        @settings(max_examples=150, deadline=None)
        def _check(code: bytes, relocs: set[int]) -> None:
            line = bytes_to_pat_line("_prop", code, relocs)
            parts = line.split()
            assert parts[-2] == ":0000"
            # A 0-byte function produces an empty lead that vanishes on split
            # (the line starts with a space), shifting the field indices;
            # real functions are >= 1 byte.
            if len(code) == 0:
                assert len(parts) == 5
                assert int(parts[0], 16) == 0  # crc_len
                return
            lead = parts[0]
            crc_len = int(parts[1], 16)
            total_size = int(parts[3], 16)

            lead_len = min(len(code), 32)
            assert len(lead) == 2 * lead_len
            # Lead is all hex except reloc positions, which are ".."
            for i in range(lead_len):
                pair = lead[2 * i : 2 * i + 2]
                if i in relocs:
                    assert pair == "..", (i, pair)
                else:
                    int(pair, 16)  # must be valid hex

            tail_relocs = sorted(r for r in relocs if r >= lead_len)
            expected_crc_len = (
                min(max(tail_relocs[0] - lead_len, 0), len(code) - lead_len, 255)
                if tail_relocs
                else min(len(code) - lead_len, 255)
            )
            assert crc_len == expected_crc_len
            assert total_size == len(code)
            # Determinism
            assert bytes_to_pat_line("_prop", code, relocs) == line

        _check()

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

    def test_crc_window_stops_before_tail_reloc(self) -> None:
        """A tail relocation truncates the CRC window (sigmake rule) so the
        signature can still match a binary whose reloc slot holds an address."""
        code = bytes(range(48))  # 32-byte lead + 16-byte tail
        line = bytes_to_pat_line("_r", code, {40})
        parts = line.split()
        # crc_len covers bytes 32..40 (8 bytes), then stops at the reloc.
        assert int(parts[1], 16) == 8
        assert int(parts[3], 16) == 48  # total size unchanged

    def test_crc_window_full_tail_when_no_tail_relocs(self) -> None:
        code = bytes(range(48))
        line = bytes_to_pat_line("_r", code, set())
        assert int(line.split()[1], 16) == 16  # entire tail

    def test_crc_window_zero_when_reloc_at_window_start(self) -> None:
        code = bytes(range(48))
        line = bytes_to_pat_line("_r", code, {32})
        parts = line.split()
        assert int(parts[1], 16) == 0
        assert parts[2] == "0000"


class TestGenFlirtPatCli:
    def _patch(self, monkeypatch, tmp_path: Path, *, members=None, raise_parse=False) -> None:
        lib = tmp_path / "msvcrt.lib"
        lib.write_bytes(b"fake")
        monkeypatch.setattr(
            "rebrew.gen_flirt_pat.parse_archive",
            lambda p: members if members is not None else [],
        )

        def _parse_coff(obj):
            if raise_parse:
                raise ValueError("corrupt")
            yield ObjectFunction("_my_func", b"\x55\x8b\xec\x5d\xc3", {1, 2}, {}, {})

        monkeypatch.setattr("rebrew.gen_flirt_pat.parse_coff_obj", _parse_coff)
        monkeypatch.setattr(
            "rebrew.gen_flirt_pat.bytes_to_pat_line",
            lambda name, code, relocs, labels: f"LEAD {name}",
        )

    def test_missing_lib_errors(self, tmp_path: Path, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        result = CliRunner().invoke(app, ["--json", str(tmp_path / "nope.lib")])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_json_output(self, tmp_path: Path, monkeypatch) -> None:

        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        self._patch(monkeypatch, tmp_path, members=[("m1", b"data")])
        out = tmp_path / "out.pat"
        result = CliRunner().invoke(app, ["--json", "-o", str(out), str(tmp_path / "msvcrt.lib")])
        assert result.exit_code == 0
        data = cli_payload(result)
        assert data["signatures"] == 1
        assert data["written"] is True
        assert data["skipped_members"] == 0
        # The boundary rule the patterns were cut by, for a producer to record.
        assert data["boundaries"] == 2
        assert out.exists()
        assert "---" in out.read_text(encoding="utf-8")

    def test_corrupt_member_skipped(self, tmp_path: Path, monkeypatch) -> None:

        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        self._patch(monkeypatch, tmp_path, members=[("m1", b"data")], raise_parse=True)
        out = tmp_path / "out.pat"
        result = CliRunner().invoke(app, ["--json", "-o", str(out), str(tmp_path / "msvcrt.lib")])
        assert result.exit_code == 0
        data = cli_payload(result)
        assert data["signatures"] == 0
        assert data["written"] is False
        assert data["skipped_members"] == 1
        assert not out.exists()

    def test_zero_signatures_removes_existing_pat(self, tmp_path: Path, monkeypatch) -> None:
        """A previous ``---``-only output is removed when the lib has no code."""

        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        self._patch(monkeypatch, tmp_path, members=[("m1", b"data")], raise_parse=True)
        out = tmp_path / "out.pat"
        out.write_text("---\n", encoding="utf-8")
        result = CliRunner().invoke(app, ["--json", "-o", str(out), str(tmp_path / "msvcrt.lib")])
        assert result.exit_code == 0
        data = cli_payload(result)
        assert data["written"] is False
        assert not out.exists()


class TestParseCoffObjReal:
    """parse_coff_obj against hand-rolled COFF objects (no MSVC needed)."""

    def test_basic_yield_with_reloc(self) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        code = b"\x90\x90\xa1\x00\x00\x00\x00\xc3"
        blob = make_coff_obj(code, relocs=[(2, 0x0006, "_extern_var")])
        results = list(parse_coff_obj(blob))
        assert len(results) == 1
        name, out_code, relocs = results[0].name, results[0].code, results[0].relocations
        assert name == "_myfunc"
        assert out_code == code
        # DIR32 fixup at 2 covers bytes 2..6 (full 4-byte width, not just
        # the first byte — LIEF reports size=0 for MSVC6 objects).
        assert {2, 3, 4, 5} <= relocs
        assert 6 not in relocs

    def test_multiple_relocs_and_long_name(self) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        blob = make_coff_obj(
            b"\xe8\x00\x00\x00\x00\xa1\x00\x00\x00\x00\xc3",
            relocs=[(1, 0x0014, "_call_target"), (6, 0x0006, "a_very_long_external_name")],
        )
        results = list(parse_coff_obj(blob))
        assert len(results) == 1
        relocs = results[0].relocations
        # REL32 at 1 covers 1..5 excl. (bytes 1-4); DIR32 at 6 covers 6..10 excl.
        assert {1, 2, 3, 4} <= relocs
        assert {6, 7, 8, 9} <= relocs
        assert 5 not in relocs
        assert 10 not in relocs

    @pytest.mark.parametrize("same_name", [False, True])
    @pytest.mark.parametrize("second_start", [4, 12])
    def test_symbol_boundaries_belong_to_section_indices(
        self, same_name: bool, second_start: int
    ) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        first = b"12345678"
        second = b"abcdefghijklmnop"
        raw_start = 20 + 2 * 40
        headers = b""
        for name, payload in ((b".text", first), (b".text" if same_name else b".other", second)):
            headers += struct.pack(
                "<8sIIIIIIHHI", name, 0, 0, len(payload), raw_start, 0, 0, 0, 0, 0x60000020
            )
            raw_start += len(payload)
        file_header = struct.pack("<HHIIIHH", 0x14C, 2, 0, raw_start, 2, 0, 0)
        symbols = struct.pack("<8sIhHBB", b"_first", 0, 1, 0x20, 2, 0)
        symbols += struct.pack("<8sIhHBB", b"_second", second_start, 2, 0x20, 2, 0)
        obj = file_header + headers + first + second + symbols + struct.pack("<I", 4)
        assert list(parse_coff_obj(obj)) == [
            ("_first", first, set(), {}, {}),
            ("_second", second[second_start:], set(), {}, {}),
        ]

    @pytest.mark.parametrize("machine", [0x14C, 0x8664, 0x1C4])
    def test_absolute_padding_relocations_mask_no_bytes(self, machine: int) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        code = b"12345678"
        obj = bytearray(make_coff_obj(code, relocs=[(1, 0, "_unused")]))
        struct.pack_into("<H", obj, 0, machine)
        assert list(parse_coff_obj(bytes(obj))) == [("_myfunc", code, set(), {}, {})]

    @pytest.mark.parametrize(
        "kind,width",
        [
            (1, 8),
            (2, 4),
            (3, 4),
            (4, 4),
            (5, 4),
            (6, 4),
            (7, 4),
            (8, 4),
            (9, 4),
            (10, 2),
            (11, 4),
            (12, 1),
        ],
    )
    def test_amd64_relocations_mask_the_declared_width(self, kind: int, width: int) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        code = b"0123456789abcdef"
        obj = bytearray(make_coff_obj(code, relocs=[(2, kind, "_external")]))
        struct.pack_into("<H", obj, 0, 0x8664)
        assert list(parse_coff_obj(bytes(obj))) == [
            ("_myfunc", code, set(range(2, 2 + width)), {}, {})
        ]

    @pytest.mark.parametrize("machine,kind", [(0x14C, 0x0D), (0x8664, 0x0C)])
    def test_secrel7_masks_only_one_byte(self, machine: int, kind: int) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        code = b"12345678"
        obj = bytearray(make_coff_obj(code, relocs=[(2, kind, "_external")]))
        struct.pack_into("<H", obj, 0, machine)
        assert list(parse_coff_obj(bytes(obj))) == [("_myfunc", code, {2}, {}, {})]

    def test_static_function_symbols_yielded(self) -> None:
        """Regression: MSVC marks CRT helpers such as _initterm and
        _parse_cmdline STATIC, so they never reach the archive symbol index.
        Yielding only EXTERNAL symbols silently drops them from signatures and
        makes callers conclude the function is absent from the library."""
        from rebrew.gen_flirt_pat import parse_coff_obj

        # _myfunc (EXTERNAL) at 0, a STATIC helper at 4.
        blob = make_coff_obj(
            b"\x90\x90\x90\xc3\x31\xc0\x90\xc3",
            section_symbols=[("_static_helper", 4)],
        )
        names = {row.name for row in parse_coff_obj(blob)}
        assert "_myfunc" in names
        assert "_static_helper" in names

    def test_section_symbols_not_yielded_as_functions(self) -> None:
        """Section symbols (".text") share STORAGE_CLASS.STATIC and alias the
        first real function; they must not shadow its name."""
        from rebrew.gen_flirt_pat import parse_coff_obj

        blob = make_coff_obj(b"\x90\x90\x90\xc3", section_symbols=[(".text", 0)])
        names = {row.name for row in parse_coff_obj(blob)}
        assert ".text" not in names
        assert "_myfunc" in names

    def test_non_code_section_skipped(self) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        blob = make_coff_obj(b"\x00" * 8, section_chars=0x40000040)  # DATA|READ
        assert list(parse_coff_obj(blob)) == []

    def test_short_function_yielded_with_padding(self) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        # parse_coff_obj yields whatever the section holds (4-byte aligned);
        # the <4-byte filter lives in the gen_flirt_pat main loop.
        blob = make_coff_obj(b"\xc3\xcc")
        results = list(parse_coff_obj(blob))
        assert len(results) == 1
        assert results[0][1] == b"\xc3\xcc\x00\x00"

    def test_labels_of_an_assembly_routine_stay_inside_it(self) -> None:
        """A hand-written routine whose internal labels are marked as functions
        (MSVC's memcpy.obj) is one function; its labels keep their names."""
        from rebrew.gen_flirt_pat import parse_coff_obj

        blob = make_coff_obj(
            _ASM_ROUTINE,
            func_symbol="_copy",
            extra_funcs=[("_next", 0x2E)],
            section_symbols=[
                ("Vec", 0x10),
                ("Case0", 0x1C),
                ("Case1", 0x1F),
                ("Case2", 0x25),
                ("Tail", 0x2C),
                ("Helper", 0x34),
            ],
            label_relocs=[(0x0C, 6, 0x10), (0x10, 6, 0x1C), (0x14, 6, 0x1F), (0x18, 6, 0x25)],
        )
        rows = {row.name: row for row in parse_coff_obj(blob)}
        assert sorted(rows) == ["Helper", "_copy", "_next"]
        copy = rows["_copy"]
        assert copy.code == _ASM_ROUTINE[:0x2E]
        assert copy.labels == {
            0x10: "Vec",
            0x1C: "Case0",
            0x1F: "Case1",
            0x25: "Case2",
            0x2C: "Tail",
        }
        assert copy.self_relocations == {0x0C: 0x10, 0x10: 0x1C, 0x14: 0x1F, 0x18: 0x25}
        # A routine reached only by a call is a function of its own.
        assert rows["_next"].code == _ASM_ROUTINE[0x2E:0x34]
        assert rows["_next"].labels == {}
        assert rows["Helper"].code.startswith(b"\x40\xc3")

    def test_address_taken_static_function_stays_a_function(self) -> None:
        """``push offset _cb`` takes an address; it does not reach the code."""
        from rebrew.gen_flirt_pat import parse_coff_obj

        code = b"\x68\x00\x00\x00\x00\xc3" + b"\x40\x40\x40\xc3"
        blob = make_coff_obj(code, section_symbols=[("_cb", 6)], label_relocs=[(1, 6, 6)])
        assert [(row.name, row.labels) for row in parse_coff_obj(blob)] == [
            ("_myfunc", {}),
            ("_cb", {}),
        ]

    def test_fall_through_label_is_inside(self) -> None:
        """A STATIC symbol the code before it runs into is a label of that code."""
        from rebrew.gen_flirt_pat import parse_coff_obj

        code = b"\x40\x40\x40\x40" + b"\x48\x48\x48\xc3"
        blob = make_coff_obj(code, section_symbols=[("_loop", 4)])
        assert [(row.name, row.code, row.labels) for row in parse_coff_obj(blob)] == [
            ("_myfunc", code, {4: "_loop"}),
        ]

    def test_line_number_symbols_do_not_end_a_function(self) -> None:
        """``.bf``/``.lf``/``.ef`` (COFF line numbers, MFC's NAFXCW.LIB) are no
        boundary: ``.lf`` at offset 1 cut a 6-byte function to 1 byte, so it
        was dropped."""
        from rebrew.gen_flirt_pat import parse_coff_obj

        code = b"\xb8\x00\x00\x00\x00\xc3"
        blob = make_coff_obj(code, section_symbols=[(".bf", 0), (".lf", 1), (".ef", 6)])
        assert [(row.name, row.code) for row in parse_coff_obj(blob)] == [
            ("_myfunc", code + b"\x00\x00")
        ]

    def test_other_machines_keep_every_symbol(self) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        code = b"\x40\x40\x40\x40" + b"\x48\x48\x48\xc3"
        obj = bytearray(make_coff_obj(code, section_symbols=[("_loop", 4)]))
        struct.pack_into("<H", obj, 0, 0x8664)
        assert [row.name for row in parse_coff_obj(bytes(obj))] == ["_myfunc", "_loop"]

    @pytest.mark.skipif(not _VC98_LIBCMT.is_file(), reason=f"{_VC98_LIBCMT} not on this machine")
    def test_msvc6_memcpy_is_one_function(self) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        [obj] = [o for n, o in parse_archive(str(_VC98_LIBCMT)) if n.endswith("\\memcpy.obj")]
        [row] = parse_coff_obj(obj)
        assert row.name == "_memcpy"
        assert len(row.code) == 821
        assert len(row.labels) == 36
        assert row.labels[0x64] == "LeadUpVec"
        assert row.labels[0x158] == "TrailUp0"

    def test_truncated_and_corrupt_symbol_tables_keep_rows_inside_the_code(self) -> None:
        """Every truncation of the routine's object, and every symbol-table
        byte set to 0x00/0x7F/0xFF, parses or is refused (ValueError), and
        each row's relocations and labels stay inside its code."""
        from rebrew.gen_flirt_pat import parse_coff_obj

        blob = make_coff_obj(
            _ASM_ROUTINE,
            func_symbol="_copy",
            extra_funcs=[("_next", 0x2E)],
            section_symbols=[("Vec", 0x10), ("Case0", 0x1C), ("Tail", 0x2C)],
            label_relocs=[(0x0C, 6, 0x10), (0x10, 6, 0x1C), (0x14, 6, 0x1F), (0x18, 6, 0x25)],
        )
        symtab = struct.unpack_from("<I", blob, 8)[0]
        variants = [blob[:n] for n in range(len(blob))]
        variants += [
            blob[:at] + bytes([value]) + blob[at + 1 :]
            for at in range(symtab, len(blob))
            for value in (0x00, 0x7F, 0xFF)
        ]
        for variant in variants:
            try:
                rows = list(parse_coff_obj(variant))
            except ValueError:
                continue
            for row in rows:
                assert len(row.code) >= 4
                assert all(0 <= at < len(row.code) for at in row.relocations)
                assert all(0 < at < len(row.code) for at in row.labels)

    def test_tiny_blob_returns_nothing(self) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        assert list(parse_coff_obj(b"\x00" * 10)) == []

    def test_function_at_nonzero_offset(self) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        code = b"\x90" * 4 + b"\x55\x8b\xec\x5d\xc3"  # 4 bytes padding then the func
        blob = make_coff_obj(code, func_value=4)
        results = list(parse_coff_obj(blob))
        assert len(results) == 1
        out_code = results[0].code
        # The slice includes trailing 4-byte alignment padding.
        assert out_code.startswith(b"\x55\x8b\xec\x5d\xc3")


class TestGenFlirtPatEndToEnd:
    """Full pipeline: real .lib archive → COFF obj → .pat line (no stubs)."""

    def test_labels_are_local_names_and_do_not_make_a_match_ambiguous(self, tmp_path: Path) -> None:
        """The routine's five labels follow its name as local names, and a
        scan names the routine, not one of more than three candidates."""
        import flirt
        from typer.testing import CliRunner

        from rebrew.flirt import match_text
        from rebrew.gen_flirt_pat import app

        obj = make_coff_obj(
            _ASM_ROUTINE,
            func_symbol="_copy",
            extra_funcs=[("_next", 0x2E)],
            section_symbols=[
                ("Vec", 0x10),
                ("Case0", 0x1C),
                ("Case1", 0x1F),
                ("Case2", 0x25),
                ("Tail", 0x2C),
            ],
            label_relocs=[(0x0C, 6, 0x10), (0x10, 6, 0x1C), (0x14, 6, 0x1F), (0x18, 6, 0x25)],
        )
        lib = tmp_path / "asm.lib"
        lib.write_bytes(make_lib_archive([("asm.obj", obj)]))
        out = tmp_path / "asm.pat"
        assert CliRunner().invoke(app, ["-o", str(out), str(lib)]).exit_code == 0
        [line] = [line for line in out.read_text(encoding="utf-8").splitlines() if "_copy" in line]
        assert line.endswith(
            ":0000 _copy :0010@ Vec :001C@ Case0 :001F@ Case1 :0025@ Case2 :002C@ Tail"
        )
        matcher = flirt.compile(flirt.parse_pat(out.read_text(encoding="utf-8")))
        image = _ASM_ROUTINE[:0x2E] + b"\xcc" * 0x42
        assert [m["name"] for m in match_text(matcher, image, 0x401000)] == ["_copy"]

    def test_generates_pat_from_real_lib(self, tmp_path: Path, monkeypatch) -> None:

        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        code = bytes(range(40))  # 32-byte lead + CRC-protected tail
        obj = make_coff_obj(code, relocs=[(6, 0x0006, "_extern_data")])
        lib_path = tmp_path / "msvcrt.lib"
        lib_path.write_bytes(make_lib_archive([("func.obj", obj)]))
        out = tmp_path / "out.pat"
        result = CliRunner().invoke(app, ["--json", "-o", str(out), str(lib_path)])
        assert result.exit_code == 0
        data = cli_payload(result)
        assert data["signatures"] == 1
        assert data["skipped_members"] == 0
        text = out.read_text(encoding="utf-8")
        assert "_myfunc" in text
        assert text.endswith("---\n")

    def test_empty_symbol_name_skipped(self, tmp_path: Path, monkeypatch) -> None:
        """A nameless COFF symbol must not emit a malformed .pat line.

        ``bytes_to_pat_line`` puts the symbol name as the line's trailing
        field, so an empty name yields a line signature parsers reject.
        With nothing else to emit, no pattern file is written.
        """

        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        code = bytes(range(40))
        obj = make_coff_obj(code, func_symbol="")
        lib_path = tmp_path / "msvcrt.lib"
        lib_path.write_bytes(make_lib_archive([("func.obj", obj)]))
        out = tmp_path / "out.pat"
        result = CliRunner().invoke(app, ["--json", "-o", str(out), str(lib_path)])
        assert result.exit_code == 0
        data = cli_payload(result)
        assert data["signatures"] == 0
        assert data["written"] is False
        assert not out.exists()


class TestWeakSignatureFilter:
    """is_weak_signature: crc_len=0 sigs with <16 literal lead bytes are
    false-positive generators and must be dropped at generation time."""

    def test_weak_when_no_crc_and_few_literals(self) -> None:
        from rebrew.gen_flirt_pat import is_weak_signature

        line = "558BEC83EC0000 00 0000 0008 :0000 _weak"
        assert is_weak_signature(line) is True

    def test_strong_when_no_crc_but_many_literals(self) -> None:
        from rebrew.gen_flirt_pat import is_weak_signature

        line = "558BEC83EC00FF742408E8........5959C300000000 00 0000 0016 :0000 _ok"
        assert is_weak_signature(line) is False

    def test_strong_when_crc_present(self) -> None:
        from rebrew.gen_flirt_pat import is_weak_signature

        # crc_len != 00 → the CRC protects the tail regardless of lead size.
        line = "558BEC83EC0000 08 1234 0010 :0000 _protected"
        assert is_weak_signature(line) is False


class TestWeakSignatureCli:
    def test_weak_functions_filtered_from_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        lib = tmp_path / "msvcrt.lib"
        lib.write_bytes(b"fake")
        monkeypatch.setattr("rebrew.gen_flirt_pat.parse_archive", lambda p: [("m1", b"data")])

        def _parse_coff(obj):
            # Weak: 7-byte prolog-only function → crc_len 0, 7 literal bytes.
            yield ObjectFunction("_weak_fn", b"\x55\x8b\xec\x83\xec\x08\xc3", set(), {}, {})
            # Strong: 40 bytes, tail reloc → crc_len 0 but 32 literal lead bytes.
            yield ObjectFunction("_strong_fn", bytes(range(40)), {32}, {}, {})

        monkeypatch.setattr("rebrew.gen_flirt_pat.parse_coff_obj", _parse_coff)
        out = tmp_path / "out.pat"
        result = CliRunner().invoke(app, ["--json", "-o", str(out), str(lib)])
        assert result.exit_code == 0
        data = cli_payload(result)
        assert data["signatures"] == 1
        assert data["skipped_weak"] == 1
        text = out.read_text(encoding="utf-8")
        assert "_strong_fn" in text
        assert "_weak_fn" not in text


class TestWeakSignatureBoundary:
    """The weak rule: literal<16 AND crc_len<8 — a tiny CRC window protects
    almost nothing."""

    def test_tiny_crc_window_weak(self) -> None:
        from rebrew.gen_flirt_pat import is_weak_signature

        line = "558BEC83EC00 01 1234 0008 :0000 _w"
        assert is_weak_signature(line) is True

    def test_crc_window_of_8_strong(self) -> None:
        from rebrew.gen_flirt_pat import is_weak_signature

        line = "558BEC83EC00 08 1234 000F :0000 _ok"
        assert is_weak_signature(line) is False


_HAS_GCC = bool(__import__("shutil").which("gcc"))


def _compile_elf_object(tmp_path: Path) -> Path:
    """Compile a small C file to an ET_REL object with gcc (test fixture)."""
    src = tmp_path / "fixture.c"
    src.write_text(
        "extern int ext_fn(int);\n"
        "int helper_add(int a, int b) { return a + b; }\n"
        "int helper_mul(int a, int b) { return a * b; }\n"
        "int sum_array(const int *a, int n) {\n"
        "    int s = 0;\n"
        "    for (int i = 0; i < n; i++) s += a[i];\n"
        "    return s + ext_fn(s);\n"
        "}\n",
        encoding="utf-8",
    )
    obj = tmp_path / "fixture.o"
    import subprocess

    subprocess.run(
        [
            "gcc",
            "-c",
            "-O1",
            "-fno-asynchronous-unwind-tables",
            # Ubuntu's gcc defaults to -fcf-protection=full (it patches the
            # default), which prepends endbr64 and changes every function's
            # size — the exact-size assertions below must not depend on the
            # build's defaults.
            "-fcf-protection=none",
            str(src),
            "-o",
            str(obj),
        ],
        check=True,
        capture_output=True,
    )
    return obj


class TestAlternativeImplementations:
    """One symbol, several members: every implementation must be emitted.

    An archive that ships more than one member defining the same symbol -
    picolibc's nano-malloc next to its full allocator, newlib's C and assembly
    ``memcpy`` - contributes one pattern per implementation, because the linker
    picks one of them and there is no way to know which.  Deduping on the
    symbol name kept only the first: measured on a picolibc RV32IMAC firmware,
    the surviving ``malloc`` pattern described a 580-byte function while the
    linked one was 158 bytes.
    """

    @pytest.mark.skipif(not _HAS_GCC, reason="gcc not available")
    def test_both_implementations_are_emitted(self, tmp_path: Path) -> None:
        import subprocess

        from rebrew.gen_flirt_pat import generate_pat

        lib = tmp_path / "libdup.a"
        for tag, body in (("a", "return n + 1;"), ("b", "return n * 3 - 7;")):
            src = tmp_path / f"{tag}.c"
            src.write_text(
                "int shared_entry(int n) {\n"
                "    int total = 0;\n"
                "    for (int i = 0; i < n; i++) total += i * 2 + 1;\n"
                f"    {body}\n"
                "}\n",
                encoding="utf-8",
            )
            obj = tmp_path / f"{tag}.o"
            subprocess.run(
                ["gcc", "-c", "-O1", "-fcf-protection=none", str(src), "-o", str(obj)],
                check=True,
                capture_output=True,
            )
            subprocess.run(["ar", "rcs", str(lib), str(obj)], check=True, capture_output=True)

        out = tmp_path / "out.pat"
        stats = generate_pat(lib, out)
        lines = [
            ln for ln in out.read_text(encoding="utf-8").splitlines() if ln.endswith("shared_entry")
        ]
        assert len(lines) == 2, lines
        assert lines[0] != lines[1]
        assert stats["signatures"] == 2


class TestParseElfObjReal:
    @pytest.mark.skipif(not _HAS_GCC, reason="gcc not available")
    def test_yields_functions_with_relocs(self, tmp_path: Path) -> None:
        from rebrew.gen_flirt_pat import parse_elf_obj

        obj_data = _compile_elf_object(tmp_path).read_bytes()
        results = {f.name: (f.code, f.relocations) for f in parse_elf_obj(obj_data)}
        assert "helper_add" in results
        assert "helper_mul" in results
        assert "sum_array" in results
        # ELF symbol sizes are exact — no next-symbol heuristic.
        assert len(results["helper_add"][0]) == 4
        # The ext_fn call yields a PLT32 fixup (4 bytes) inside sum_array.
        assert results["sum_array"][1]
        assert all(0 <= r < len(results["sum_array"][0]) for r in results["sum_array"][1])

    @pytest.mark.skipif(not _HAS_GCC, reason="gcc not available")
    def test_generate_pat_elf_archive(self, tmp_path: Path) -> None:
        import subprocess

        from rebrew.gen_flirt_pat import generate_pat

        obj = _compile_elf_object(tmp_path)
        lib = tmp_path / "libfixture.a"
        subprocess.run(["ar", "rcs", str(lib), str(obj)], check=True, capture_output=True)
        out = tmp_path / "out.pat"
        stats = generate_pat(lib, out)
        assert stats["signatures"] == 1  # sum_array; tiny funcs are weak-skipped
        assert stats["skipped_members"] == 0
        text = out.read_text(encoding="utf-8")
        assert "sum_array" in text
        assert text.endswith("---\n")

    def test_mips_word_masking(self, monkeypatch) -> None:
        """R_MIPS fixups mask the whole 4-byte instruction word."""
        import lief

        from rebrew.gen_flirt_pat import parse_elf_obj

        section = SimpleNamespace(flags=0x4, content=b"\x00\x00\x00\x00\x00\x00\x00\x00")
        sym = SimpleNamespace(
            name="mips_fn",
            type=lief.ELF.Symbol.TYPE.FUNC,
            binding=lief.ELF.Symbol.BINDING.GLOBAL,
            section=section,
            value=0,
            size=8,
        )
        reloc = SimpleNamespace(
            has_section=True,
            section=section,
            address=2,
            size=26,  # R_MIPS_26-ish
        )
        fake = SimpleNamespace(
            header=SimpleNamespace(machine_type=lief.ELF.ARCH.MIPS),
            symbols=[sym],
            relocations=[reloc],
        )
        monkeypatch.setattr(lief.ELF, "parse", lambda path: fake)
        results = list(parse_elf_obj(b"\x7fELF" + b"\x00" * 40))
        assert len(results) == 1
        relocs = results[0].relocations
        # Fixup at byte 2 sits inside word 0 — the whole word is masked.
        assert {0, 1, 2, 3} <= relocs

    def test_non_mips_uses_reloc_size(self, monkeypatch) -> None:
        import lief

        from rebrew.gen_flirt_pat import parse_elf_obj

        section = SimpleNamespace(flags=0x4, content=b"\x00" * 16)
        sym = SimpleNamespace(
            name="x86_fn",
            type=lief.ELF.Symbol.TYPE.FUNC,
            binding=lief.ELF.Symbol.BINDING.GLOBAL,
            section=section,
            value=0,
            size=16,
        )
        reloc = SimpleNamespace(has_section=True, section=section, address=4, size=32)
        fake = SimpleNamespace(
            header=SimpleNamespace(machine_type=lief.ELF.ARCH.X86_64),
            symbols=[sym],
            relocations=[reloc],
        )
        monkeypatch.setattr(lief.ELF, "parse", lambda path: fake)
        results = list(parse_elf_obj(b"\x7fELF" + b"\x00" * 40))
        assert len(results) == 1
        relocs = results[0].relocations
        assert {4, 5, 6, 7} <= relocs
        assert 0 not in relocs


def test_coff_shared_string_suffix_name() -> None:
    from rebrew.gen_flirt_pat import parse_coff_obj

    blob = bytearray(make_coff_obj(b"\xff\x25\0\0\0\0", relocs=[(2, 6, "__imp__socket@12")]))
    offset, count = struct.unpack_from("<II", blob, 8)
    table = offset + count * 18
    suffix = bytes(blob[table:]).index(b"_socket@12")
    struct.pack_into("<II", blob, offset, 0, suffix)
    rows = list(parse_coff_obj(bytes(blob)))
    assert rows[0][0] == "_socket@12"
    assert rows[0][2] == {2, 3, 4, 5}
