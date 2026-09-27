"""Tests for binsync/state.py: remote BinSync text reaching local source files."""

from __future__ import annotations

from pathlib import Path


class TestAnalysisMarkerSanitizing:
    def test_comment_newline_cannot_add_source_lines(self, tmp_path: Path) -> None:
        """A collaborator's comment must stay inside the ``//`` marker line."""
        from rebrew.binsync.state import write_analysis_markers

        source = tmp_path / "foo.c"
        source.write_text("int foo(void){return 0;}\n", encoding="utf-8")
        write_analysis_markers(source, {0x1000: "hi\nint injected(void) { return 1; }"})

        text = source.read_text(encoding="utf-8")
        assert "int injected" not in text.split("// ANALYSIS @")[0]
        marker_lines = [line for line in text.splitlines() if "injected" in line]
        assert marker_lines == ["// ANALYSIS @ 0x00001000: hi int injected(void) { return 1; }"]

    def test_marker_comment_text_flattens_control_characters(self) -> None:
        from rebrew.binsync.state import marker_comment_text

        assert marker_comment_text("a\r\nb\x00c\x1bd") == "a  b c d"
        assert marker_comment_text("plain text") == "plain text"
        assert marker_comment_text("tab\there") == "tab\there"

    def test_existing_markers_survive_a_hostile_comment(self, tmp_path: Path) -> None:
        from rebrew.binsync.state import parse_analysis_markers, write_analysis_markers

        source = tmp_path / "foo.c"
        source.write_text(
            "int foo(void){return 0;}\n\n// ANALYSIS @ 0x00001000: local note\n",
            encoding="utf-8",
        )
        assert write_analysis_markers(source, {0x2000: "remote\nnote"})
        assert parse_analysis_markers(source.read_text(encoding="utf-8")) == {
            0x1000: "local note",
            0x2000: "remote note",
        }


class TestDefinitionValidation:
    def test_directive_behind_a_comment_is_refused(self) -> None:
        """The preprocessor reads text with comments removed, so test it that way."""
        from rebrew.binsync.importer import _definition_is_valid

        smuggled = "typedef struct S {\n\tint x;\n/*c*/#define REBREW_PWNED 1\n} S;"
        assert _definition_is_valid(smuggled, "S", {"kind": "struct"}) is False
        # A directive inside a comment is not a directive: comments are removed
        # before the preprocessor reads the line.
        assert (
            _definition_is_valid(
                "// #define X 1\ntypedef struct S { int x; } S;", "S", {"kind": "struct"}
            )
            is True
        )
        assert (
            _definition_is_valid("typedef struct S { int x; } S;", "S", {"kind": "struct"}) is True
        )
