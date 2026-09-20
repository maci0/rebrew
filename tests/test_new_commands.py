"""Tests for probe, qual-sweep, gap-trace, residue (pure helpers + CLI wiring)."""

import pytest


class TestQualSweepVariants:
    def test_variants_rewrite_declaration(self) -> None:
        from rebrew.qual_sweep import variants

        out = variants("int x;")
        assert out, "expected at least one qualifier rewrite"
        labels = [label for label, _ in out]
        assert len(set(labels)) == len(labels)
        for _, text in out:
            assert text != "int x;"

    def test_variants_ignore_string_contents(self) -> None:
        from rebrew.qual_sweep import _strip_literals

        assert _strip_literals('char *s = "int x;";') == 'char *s = "";'

    def test_is_decl(self) -> None:
        from rebrew.qual_sweep import _is_decl

        assert _is_decl("int x;")
        assert _is_decl("int x = 1;")
        assert not _is_decl("x = 1;")
        assert not _is_decl("int f(void) { return 1; }")

    def test_function_span(self) -> None:
        from rebrew.qual_sweep import _function_span

        lines = ["int f(void) {", "  return 1;", "}", "int g(void) {", "}"]
        assert _function_span(lines, "f") == (0, 3)


class TestGapTraceHelpers:
    def test_masked_key_reloc(self) -> None:
        from rebrew.gap_trace import _masked_key

        assert _masked_key(b"\x12\x34", True, "mov") == b"\x00\x00"

    def test_masked_key_branch(self) -> None:
        from rebrew.gap_trace import _BRANCHES, _masked_key

        branch = next(iter(_BRANCHES))
        assert _masked_key(b"\x74\x05", False, branch) == b"\x74\x00"

    def test_masked_key_plain(self) -> None:
        from rebrew.gap_trace import _masked_key

        assert _masked_key(b"\x89\xd8", False, "mov") == b"\x89\xd8"


class TestResidueHelpers:
    def test_residue_report_identical(self) -> None:
        import struct

        from rebrew.residue import residue_report

        def _pe_with_text() -> bytes:
            raw = bytearray(0x400)
            raw[0x3C:0x40] = struct.pack("<I", 0x80)
            raw[0x80 + 6 : 0x80 + 8] = struct.pack("<H", 1)
            raw[0x80 + 20 : 0x80 + 22] = struct.pack("<H", 0xE0)
            off = 0x80 + 24 + 0xE0
            raw[off : off + 8] = b".text\x00\x00\x00"
            # (vsize, va, raw_size, raw_ptr) per _sections unpack order
            raw[off + 8 : off + 24] = struct.pack("<IIII", 0x100, 0x1000, 0x100, 0x200)
            return bytes(raw)

        ref = _pe_with_text()
        report = residue_report(ref, ref, [], 0)
        assert report["text_differing"] == 0

    def test_sections_accepts_non_utf8_name(self) -> None:
        """PE section names are 8 raw bytes — a high byte must not crash.

        Concrete input: name bytes ``b'.xyz\\xff\\x00...'``.  Bare
        ``.decode()`` (UTF-8 strict) raises; latin1 matches pe_headers.
        """
        import struct

        from rebrew.residue import _sections

        raw = bytearray(0x400)
        raw[0x3C:0x40] = struct.pack("<I", 0x80)
        raw[0x80 + 6 : 0x80 + 8] = struct.pack("<H", 1)
        raw[0x80 + 20 : 0x80 + 22] = struct.pack("<H", 0xE0)
        off = 0x80 + 24 + 0xE0
        raw[off : off + 8] = b".xyz\xff\x00\x00"
        raw[off + 8 : off + 24] = struct.pack("<IIII", 0x10, 0x1000, 0x10, 0x200)
        sections = _sections(bytes(raw))
        assert ".xyz\xff" in sections

    @pytest.mark.parametrize("first_size", [4, 8, 12])
    def test_residue_report_attributes_until_next_start(
        self, monkeypatch: pytest.MonkeyPatch, first_size: int
    ) -> None:
        from rebrew.residue import residue_report

        monkeypatch.setattr("rebrew.residue._sections", lambda raw: {".text": (0x1000, 16, 0, 16)})
        report = residue_report(
            b"\x01" * 16, bytes(16), [(0, first_size, "first"), (8, 4, "last")], 0x400000
        )
        assert report["text_differing"] == 16
        assert report["inside_nonmatching"] == 12
        assert report["outside"] == 4
        assert report["functions"] == [
            {"name": "first", "bytes": 8, "first_diff_va": "0x401000"},
            {"name": "last", "bytes": 4, "first_diff_va": "0x401008"},
            {
                "name": "<outside the non-matching functions>",
                "bytes": 4,
                "first_diff_va": "0x40100c",
            },
        ]


class TestCommandWiring:
    def test_commands_mounted(self) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app

        for cmd in ("probe", "qual-sweep", "gap-trace"):
            r = CliRunner().invoke(app, [cmd, "--help"])
            assert r.exit_code == 0, cmd
