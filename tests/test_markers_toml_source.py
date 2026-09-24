"""Tests for ADR 023: markers as TOML single source.

- parse_c_file_multi synthesizes Annotations for marker-less (pure C)
  files from rebrew-functions.toml `file`-tagged entries.
- Files that still carry markers parse exactly as before.
- VTABLE/STRING markers are legal (parser + VALID_MARKERS).
- match_semantics: the shared effective-match classifier.
- migrate_markers: marker-block stripping state machine.
"""

from pathlib import Path
from typing import Any

from rebrew.annotation import parse_c_file_multi, parse_c_file_text
from rebrew.match_semantics import EFFECTIVE_MATCH_NOTE, is_effective_match
from rebrew.migrate_markers import _strip_marker_blocks


def _write_metadata(metadata_dir: Path, entries: dict[tuple[str, int], dict[str, Any]]) -> None:
    from rebrew.metadata import save_metadata

    metadata_dir.mkdir(parents=True, exist_ok=True)
    save_metadata(metadata_dir, entries)


class TestTomlSynthesis:
    def test_pure_c_file_synthesizes_from_metadata(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "func.c").write_text(
            "int __stdcall myFunc(int a) {\n    return a + 1;\n}\n", encoding="utf-8"
        )
        _write_metadata(
            tmp_path,
            {
                ("S", 0x401000): {
                    "file": "src/func.c",
                    "symbol": "myFunc",
                    "name": "myFunc",
                    "marker_type": "FUNCTION",
                    "size": 12,
                    "cflags": "/O2 /Gz",
                    "status": "EXACT",
                }
            },
        )
        annos = parse_c_file_multi(src / "func.c", metadata_dir=tmp_path)
        assert len(annos) == 1
        ann = annos[0]
        assert ann.va == 0x401000
        assert ann.module == "S"
        assert ann.symbol == "myFunc"
        assert ann.size == 12
        assert ann.cflags == "/O2 /Gz"
        assert ann.status == "EXACT"
        assert ann.marker_type == "FUNCTION"

    def test_bare_filename_entry_matches(self, tmp_path: Path) -> None:
        src = tmp_path / "reversed"
        src.mkdir()
        (src / "f.c").write_text("int x(void) { return 0; }\n", encoding="utf-8")
        _write_metadata(
            tmp_path,
            {("S", 0x1000): {"file": "f.c", "symbol": "x"}},
        )
        (annos,) = parse_c_file_multi(src / "f.c", metadata_dir=tmp_path)
        assert annos.va == 0x1000

    def test_inline_markers_still_win(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "g.c").write_text(
            "// FUNCTION: S 0x2000\n// SIZE: 7\nint g(void) { return 1; }\n",
            encoding="utf-8",
        )
        _write_metadata(
            tmp_path,
            {("S", 0x3000): {"file": "src/g.c", "symbol": "other"}},  # ignored
        )
        annos = parse_c_file_multi(src / "g.c", metadata_dir=tmp_path)
        assert [a.va for a in annos] == [0x2000]

    def test_no_metadata_no_crash(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "h.c").write_text("int h(void) { return 2; }\n", encoding="utf-8")
        assert parse_c_file_multi(src / "h.c", metadata_dir=tmp_path) == []

    def test_parse_c_file_text_fallback(self, tmp_path: Path) -> None:
        _write_metadata(
            tmp_path,
            {("S", 0x4000): {"file": "pure.c", "symbol": "pure", "name": "pure"}},
        )
        annos = parse_c_file_text(
            "int pure(void) { return 3; }\n",
            tmp_path / "pure.c",
            None,
            None,
            tmp_path,
        )
        assert [a.va for a in annos] == [0x4000]
        assert annos[0].symbol == "pure"

    def test_target_filter_applies(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "t.c").write_text("int t(void) { return 4; }\n", encoding="utf-8")
        _write_metadata(
            tmp_path,
            {
                ("OTHER", 0x5000): {"file": "src/t.c", "symbol": "t"},
                ("MINE", 0x6000): {"file": "src/t.c", "symbol": "t"},
            },
        )
        annos = parse_c_file_multi(src / "t.c", target_name="MINE", metadata_dir=tmp_path)
        assert [a.module for a in annos] == ["MINE"]


class TestVtableStringMarkers:
    def test_vtable_marker_parses(self, tmp_path: Path) -> None:
        src = tmp_path / "v.c"
        src.write_text("// VTABLE: S 0x410000\n// SIZE: 0x10\n", encoding="utf-8")
        annos = parse_c_file_multi(src, metadata_dir=tmp_path)
        assert [a.marker_type for a in annos] == ["VTABLE"]
        assert annos[0].va == 0x410000

    def test_string_marker_parses(self, tmp_path: Path) -> None:
        src = tmp_path / "s.c"
        src.write_text('// STRING: S 0x420000\nchar hello[] = "hi";\n', encoding="utf-8")
        annos = parse_c_file_multi(src, metadata_dir=tmp_path)
        assert [a.marker_type for a in annos] == ["STRING"]

    def test_validation_accepts_new_markers(self, tmp_path: Path) -> None:
        from rebrew.annotation import Annotation

        ann = Annotation(va=0x1000, marker_type="VTABLE")
        errors, _ = ann.validate()
        assert not any("marker type" in e for e in errors)
        assert ann.is_data
        assert not ann.is_function

        str_ann = Annotation(va=0x2000, marker_type="STRING")
        errors, _ = str_ann.validate()
        assert not any("marker type" in e for e in errors)
        assert str_ann.is_data
        assert not str_ann.is_function


class TestEffectiveMatchClassifier:
    def test_pure_register_delta(self) -> None:
        assert is_effective_match(structural=0, register=10)

    def test_structural_disqualifies(self) -> None:
        assert not is_effective_match(structural=2, register=10)

    def test_equivalent_disqualifies(self) -> None:
        assert not is_effective_match(structural=0, register=10, equivalent=5)

    def test_no_delta_is_not_effective(self) -> None:
        assert not is_effective_match(structural=0, register=0)

    def test_shared_note_text(self) -> None:
        assert "reccmp counts this as 100%" in EFFECTIVE_MATCH_NOTE
        assert "'rebrew prove'" in EFFECTIVE_MATCH_NOTE


class TestStripMarkerBlocks:
    def test_strips_marker_and_attached_kv(self) -> None:
        src = [
            "// FUNCTION: S 0x1000\n",
            "// SIZE: 12\n",
            "// CFLAGS: /O2\n",
            "int f(void) { return 0; }\n",
            "// not an annotation: this is a plain comment\n",
            "int g(void) { return 1; }\n",
        ]
        out = list(_strip_marker_blocks(src))
        assert "".join(out) == "int f(void) { return 0; }\n" + "".join(src[4:])

    def test_keeps_code_after_marker_block(self) -> None:
        src = [
            "// FUNCTION: S 0x1000\n",
            "int f(void) { return 0; }\n",
            "// STATUS: EXACT\n",  # after code — plain comment, kept
        ]
        assert "".join(_strip_marker_blocks(src)) == "".join(src[1:])

    def test_block_comment_form(self) -> None:
        src = ["/* FUNCTION: S 0x1000 */\n", "/* SIZE: 8 */\n", "int f(void) { return 0; }\n"]
        assert "".join(_strip_marker_blocks(src)) == src[2]

    def test_vtable_marker_stripped(self) -> None:
        src = ["// VTABLE: S 0x1000\n", "void* v[4];\n"]
        assert "".join(_strip_marker_blocks(src)) == src[1]

    def test_idempotent_on_pure_c(self) -> None:
        src = ["int f(void) { return 0; }\n"]
        assert list(_strip_marker_blocks(src)) == src


class TestMigrateCommandRegistered:
    def test_cli_component_registered(self) -> None:
        from rebrew.builtins import BUILTIN_COMPONENTS as CLI_COMPONENTS

        names = {c.name for c in CLI_COMPONENTS}
        assert "migrate-markers" in names
