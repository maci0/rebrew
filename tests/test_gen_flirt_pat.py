"""Tests for rebrew.gen_flirt_pat — archive parsing and PAT line generation."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from bin_util import make_coff_obj, make_lib_archive

from rebrew.gen_flirt_pat import _crc16_flirt, bytes_to_pat_line, parse_archive

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
            yield "_my_func", b"\x55\x8b\xec\x5d\xc3", {1, 2}

        monkeypatch.setattr("rebrew.gen_flirt_pat.parse_coff_obj", _parse_coff)
        monkeypatch.setattr(
            "rebrew.gen_flirt_pat.bytes_to_pat_line",
            lambda name, code, relocs: f"LEAD {name}",
        )

    def test_missing_lib_errors(self, tmp_path: Path, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        result = CliRunner().invoke(app, ["--json", str(tmp_path / "nope.lib")])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_json_output(self, tmp_path: Path, monkeypatch) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        self._patch(monkeypatch, tmp_path, members=[("m1", b"data")])
        out = tmp_path / "out.pat"
        result = CliRunner().invoke(app, ["--json", "-o", str(out), str(tmp_path / "msvcrt.lib")])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["signatures"] == 1
        assert data["skipped_members"] == 0
        assert out.exists()
        assert "---" in out.read_text(encoding="utf-8")

    def test_corrupt_member_skipped(self, tmp_path: Path, monkeypatch) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        self._patch(monkeypatch, tmp_path, members=[("m1", b"data")], raise_parse=True)
        out = tmp_path / "out.pat"
        result = CliRunner().invoke(app, ["--json", "-o", str(out), str(tmp_path / "msvcrt.lib")])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["signatures"] == 0
        assert data["skipped_members"] == 1


class TestParseCoffObjReal:
    """parse_coff_obj against hand-rolled COFF objects (no MSVC needed)."""

    def test_basic_yield_with_reloc(self) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        code = b"\x90\x90\xa1\x00\x00\x00\x00\xc3"
        blob = make_coff_obj(code, relocs=[(2, 0x0006, "_extern_var")])
        results = list(parse_coff_obj(blob))
        assert len(results) == 1
        name, out_code, relocs = results[0]
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
        _, _, relocs = results[0]
        # REL32 at 1 covers 1..5 excl. (bytes 1-4); DIR32 at 6 covers 6..10 excl.
        assert {1, 2, 3, 4} <= relocs
        assert {6, 7, 8, 9} <= relocs
        assert 5 not in relocs
        assert 10 not in relocs

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

    def test_tiny_blob_returns_nothing(self) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        assert list(parse_coff_obj(b"\x00" * 10)) == []

    def test_function_at_nonzero_offset(self) -> None:
        from rebrew.gen_flirt_pat import parse_coff_obj

        code = b"\x90" * 4 + b"\x55\x8b\xec\x5d\xc3"  # 4 bytes padding then the func
        blob = make_coff_obj(code, func_value=4)
        results = list(parse_coff_obj(blob))
        assert len(results) == 1
        _, out_code, _ = results[0]
        # The slice includes trailing 4-byte alignment padding.
        assert out_code.startswith(b"\x55\x8b\xec\x5d\xc3")


class TestGenFlirtPatEndToEnd:
    """Full pipeline: real .lib archive → COFF obj → .pat line (no stubs)."""

    def test_generates_pat_from_real_lib(self, tmp_path: Path, monkeypatch) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        code = bytes(range(40))  # 32-byte lead + CRC-protected tail
        obj = make_coff_obj(code, relocs=[(6, 0x0006, "_extern_data")])
        lib_path = tmp_path / "msvcrt.lib"
        lib_path.write_bytes(make_lib_archive([("func.obj", obj)]))
        out = tmp_path / "out.pat"
        result = CliRunner().invoke(app, ["--json", "-o", str(out), str(lib_path)])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["signatures"] == 1
        assert data["skipped_members"] == 0
        text = out.read_text(encoding="utf-8")
        assert "_myfunc" in text
        assert text.endswith("---\n")

    def test_empty_symbol_name_skipped(self, tmp_path: Path, monkeypatch) -> None:
        """A nameless COFF symbol must not emit a malformed .pat line.

        ``bytes_to_pat_line`` puts the symbol name as the line's trailing
        field, so an empty name yields ``"<lead> <crc_len> <crc> <size>
        :0000 "`` — a line signature parsers reject, corrupting the whole
        .pat (symptom: "The .pat file is corrupt (or unsupported)").
        """
        import json

        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        code = bytes(range(40))
        obj = make_coff_obj(code, func_symbol="")
        lib_path = tmp_path / "msvcrt.lib"
        lib_path.write_bytes(make_lib_archive([("func.obj", obj)]))
        out = tmp_path / "out.pat"
        result = CliRunner().invoke(app, ["--json", "-o", str(out), str(lib_path)])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["signatures"] == 0
        text = out.read_text(encoding="utf-8")
        assert text == "---\n"
        assert ":0000" not in text


class TestWeakSignatureFilter:
    """_is_weak_signature: crc_len=0 sigs with <16 literal lead bytes are
    false-positive generators and must be dropped at generation time."""

    def test_weak_when_no_crc_and_few_literals(self) -> None:
        from rebrew.gen_flirt_pat import _is_weak_signature

        line = "558BEC83EC0000 00 0000 0008 :0000 _weak"
        assert _is_weak_signature(line) is True

    def test_strong_when_no_crc_but_many_literals(self) -> None:
        from rebrew.gen_flirt_pat import _is_weak_signature

        line = "558BEC83EC00FF742408E8........5959C300000000 00 0000 0016 :0000 _ok"
        assert _is_weak_signature(line) is False

    def test_strong_when_crc_present(self) -> None:
        from rebrew.gen_flirt_pat import _is_weak_signature

        # crc_len != 00 → the CRC protects the tail regardless of lead size.
        line = "558BEC83EC0000 08 1234 0010 :0000 _protected"
        assert _is_weak_signature(line) is False


class TestWeakSignatureCli:
    def test_weak_functions_filtered_from_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.gen_flirt_pat import app

        lib = tmp_path / "msvcrt.lib"
        lib.write_bytes(b"fake")
        monkeypatch.setattr("rebrew.gen_flirt_pat.parse_archive", lambda p: [("m1", b"data")])

        def _parse_coff(obj):
            # Weak: 7-byte prolog-only function → crc_len 0, 7 literal bytes.
            yield "_weak_fn", b"\x55\x8b\xec\x83\xec\x08\xc3", set()
            # Strong: 40 bytes, tail reloc → crc_len 0 but 32 literal lead bytes.
            yield "_strong_fn", bytes(range(40)), {32}

        monkeypatch.setattr("rebrew.gen_flirt_pat.parse_coff_obj", _parse_coff)
        out = tmp_path / "out.pat"
        result = CliRunner().invoke(app, ["--json", "-o", str(out), str(lib)])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["signatures"] == 1
        assert data["skipped_weak"] == 1
        text = out.read_text(encoding="utf-8")
        assert "_strong_fn" in text
        assert "_weak_fn" not in text


class TestWeakSignatureBoundary:
    """The weak rule: literal<16 AND crc_len<8 — a tiny CRC window protects
    almost nothing."""

    def test_tiny_crc_window_weak(self) -> None:
        from rebrew.gen_flirt_pat import _is_weak_signature

        line = "558BEC83EC00 01 1234 0008 :0000 _w"
        assert _is_weak_signature(line) is True

    def test_crc_window_of_8_strong(self) -> None:
        from rebrew.gen_flirt_pat import _is_weak_signature

        line = "558BEC83EC00 08 1234 000F :0000 _ok"
        assert _is_weak_signature(line) is False


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
        ["gcc", "-c", "-O1", "-fno-asynchronous-unwind-tables", str(src), "-o", str(obj)],
        check=True,
        capture_output=True,
    )
    return obj


class TestParseElfObjReal:
    @pytest.mark.skipif(not _HAS_GCC, reason="gcc not available")
    def test_yields_functions_with_relocs(self, tmp_path: Path) -> None:
        from rebrew.gen_flirt_pat import parse_elf_obj

        obj_data = _compile_elf_object(tmp_path).read_bytes()
        results = {name: (code, relocs) for name, code, relocs in parse_elf_obj(obj_data)}
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
        _name, code, relocs = results[0]
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
        _name, code, relocs = results[0]
        assert {4, 5, 6, 7} <= relocs
        assert 0 not in relocs
