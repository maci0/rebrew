"""Current canonical metadata bindings, optional address anchors and match accounting."""

from pathlib import Path
from typing import Any

from source_util import write_source

from rebrew.match_semantics import EFFECTIVE_MATCH_NOTE, is_effective_match
from rebrew.metadata.bindings import read_source_bindings, source_bindings


def _write_metadata(metadata_dir: Path, entries: dict[tuple[str, int], dict[str, Any]]) -> None:
    from rebrew.metadata.functions import save_metadata

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
                    "kind": "FUNCTION",
                    "size": 12,
                    "cflags": "/O2 /Gz",
                    "status": "EXACT",
                }
            },
        )
        annos = read_source_bindings(src / "func.c", metadata_dir=tmp_path)
        assert len(annos) == 1
        ann = annos[0]
        assert ann.va == 0x401000
        assert ann.module == "S"
        assert ann.symbol == "myFunc"
        assert ann.size == 12
        assert ann.cflags == "/O2 /Gz"
        assert ann.status == "EXACT"
        assert ann.kind == "FUNCTION"

    def test_bare_filename_entry_matches(self, tmp_path: Path) -> None:
        src = tmp_path / "reversed"
        src.mkdir()
        (src / "f.c").write_text("int x(void) { return 0; }\n", encoding="utf-8")
        _write_metadata(
            tmp_path,
            {("S", 0x1000): {"file": "f.c", "symbol": "x"}},
        )
        (annos,) = read_source_bindings(src / "f.c", metadata_dir=tmp_path)
        assert annos.va == 0x1000

    def test_inline_markers_still_win(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        write_source(
            src / "g.c",
            "/* ADDRESS: S 0x2000 */\n\nint g(void) { return 1; }\n",
            encoding="utf-8",
            metadata_fields={"S.0x2000": {"kind": "FUNCTION", "size": 7}},
            metadata_dir=tmp_path,
        )
        _write_metadata(
            tmp_path,
            {("S", 0x3000): {"file": "src/g.c", "symbol": "other"}},  # ignored
        )
        annos = read_source_bindings(src / "g.c", metadata_dir=tmp_path)
        assert sorted(a.va for a in annos) == [0x2000, 0x3000]

    def test_migrated_function_coexists_with_data_marker(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        write_source(
            src / "g.c",
            "/* ADDRESS: S 0x5000 */\nint value;\nint g(void) { return value; }\n",
            encoding="utf-8",
            metadata_fields={"S.0x5000": {"kind": "DATA"}},
            metadata_dir=tmp_path,
        )
        _write_metadata(tmp_path, {("S", 0x2000): {"file": "src/g.c", "symbol": "g"}})
        annos = read_source_bindings(src / "g.c", metadata_dir=tmp_path)
        assert [(a.kind, a.va) for a in annos] == [
            ("DATA", 0x5000),
            ("FUNCTION", 0x2000),
        ]

    def test_other_target_marker_does_not_hide_migrated_function(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        write_source(
            src / "g.c",
            "/* ADDRESS: OTHER 0x6000 */\nint g(void) { return 1; }\n",
            encoding="utf-8",
            metadata_fields={"OTHER.0x6000": {"kind": "FUNCTION"}},
            metadata_dir=tmp_path,
        )
        _write_metadata(tmp_path, {("S", 0x2000): {"file": "src/g.c", "symbol": "g"}})
        annos = read_source_bindings(src / "g.c", target_name="S", metadata_dir=tmp_path)
        assert [(a.module, a.va) for a in annos] == [("S", 0x2000)]

    def test_no_metadata_no_crash(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "h.c").write_text("int h(void) { return 2; }\n", encoding="utf-8")
        assert read_source_bindings(src / "h.c", metadata_dir=tmp_path) == []

    def test_parse_c_file_text_fallback(self, tmp_path: Path) -> None:
        _write_metadata(
            tmp_path,
            {("S", 0x4000): {"file": "pure.c", "symbol": "pure", "name": "pure"}},
        )
        annos = source_bindings(
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
        annos = read_source_bindings(src / "t.c", target_name="MINE", metadata_dir=tmp_path)
        assert [a.module for a in annos] == ["MINE"]


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
