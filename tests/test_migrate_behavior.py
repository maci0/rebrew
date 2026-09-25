"""Behavioral tests for ADR 023 migration + synthesis: the mixed-tree steady state.

- A migrated file that gains a NEW hand-annotated function migrates again
  cleanly (both entries synthesized back after the second strip).
- A file carrying multiple markers from the start strips all of them.
- The synthesis reader is safe under concurrent threads (PARSE_MEMO +
  metadata cache interplay).
- A TOML-only (markerless) file and a second migration pass are no-ops.
"""

import threading

from rebrew.annotation import parse_c_file_multi
from rebrew.migrate_markers import _migrate_file


class _Cfg:
    def __init__(self, root):
        self.reversed_dir = root / "src"
        self.reversed_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir = root
        self.marker = "S"
        self.source_ext = ".c"


class TestReannotationAfterMigration:
    def test_second_annotation_migrates_cleanly(self, tmp_path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.c").write_text("// FUNCTION: S 0x1000\n// SIZE: 12\nint a(void) { return 0; }\n")
        cfg = _Cfg(tmp_path)
        assert _migrate_file(cfg, src / "a.c", "S", dry_run=False) is not None

        # Hand-annotate a second function on the migrated (pure C) file.
        (src / "a.c").write_text(
            (src / "a.c").read_text() + "\n// FUNCTION: S 0x2000\nint b(void) { return 1; }\n"
        )
        row = _migrate_file(cfg, src / "a.c", "S", dry_run=False)
        assert row is not None

        annos = parse_c_file_multi(src / "a.c", metadata_dir=tmp_path)
        assert sorted(a.va for a in annos) == [0x1000, 0x2000]


class TestMultiMarkerStrip:
    def test_file_with_two_markers_strips_both(self, tmp_path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.c").write_text(
            "// FUNCTION: S 0x1000\n// SIZE: 12\nint a(void) { return 0; }\n"
            "\n// FUNCTION: S 0x2000\nint b(void) { return 1; }\n"
        )
        cfg = _Cfg(tmp_path)
        row = _migrate_file(cfg, src / "a.c", "S", dry_run=False)
        assert row is not None and row["functions"] == 2
        text = (src / "a.c").read_text()
        assert "FUNCTION" not in text
        assert "int a(void) { return 0; }\n" in text
        assert "int b(void) { return 1; }\n" in text


class TestSynthesisConcurrency:
    def test_parse_c_file_multi_threaded(self, tmp_path) -> None:
        """Synthesis under 8 threads: every file parses exactly once, correctly."""
        from rebrew.metadata import save_metadata

        src = tmp_path / "src"
        src.mkdir()
        n = 20
        save_metadata(
            tmp_path,
            {
                ("S", 0x401000 + i): {
                    "file": f"src/f{i}.c",
                    "symbol": f"f{i}",
                    "name": f"f{i}",
                    "marker_type": "FUNCTION",
                    "size": 10 + i,
                }
                for i in range(n)
            },
        )
        for i in range(n):
            (src / f"f{i}.c").write_text(f"int f{i}(void) {{ return {i}; }}\n")

        errors: list[tuple[str, str]] = []

        def worker() -> None:
            for i in range(n):
                try:
                    annos = parse_c_file_multi(src / f"f{i}.c", metadata_dir=tmp_path)
                    assert len(annos) == 1
                    assert annos[0].size == 10 + i
                except Exception as e:
                    errors.append((f"f{i}", repr(e)))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, errors[:5]


class TestMigrateMarkersCliEndToEnd:
    def test_cli_json_round_trip_with_target_filter(self, tmp_path, monkeypatch) -> None:
        """The real CLI migrates only this target's markers and reports JSON."""
        import json as _json

        from typer.testing import CliRunner as _Runner

        from rebrew.migrate_markers import app as _app

        src = tmp_path / "src"
        src.mkdir()
        (src / "a.c").write_text(
            "// FUNCTION: SERVER 0x1000\n// SIZE: 12\nint a(void) { return 0; }\n"
        )
        (src / "b.c").write_text("// LIBRARY: OTHER 0x2000\nint b(void) { return 1; }\n")
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "SERVER"\n'
            '[targets.SERVER]\nbinary = "x.dll"\nreversed_dir = "src"\n'
        )
        (tmp_path / "x.dll").write_bytes(b"MZ\x00" * 32)
        monkeypatch.chdir(tmp_path)

        result = _Runner().invoke(_app, ["--json"])
        assert result.exit_code == 0, result.output
        payload = _json.loads(result.output)
        assert payload["migrated"] == 1
        assert payload["files"][0]["file"].endswith("a.c")

        # The target's source is pure C; the other target's marker is untouched.
        assert "FUNCTION" not in (src / "a.c").read_text()
        assert "LIBRARY: OTHER" in (src / "b.c").read_text()
        from rebrew.metadata import load_metadata

        doc = load_metadata(tmp_path)
        assert ("SERVER", 0x1000) in doc
        assert not any(m == "OTHER" for m, _va in doc)


class TestFileAtomicMigration:
    """Stripping is file-global; recording used to follow the active target only."""

    def test_stacked_targets_are_recorded_together(self, tmp_path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.c").write_text(
            "// FUNCTION: S 0x1000\n// SIZE: 12\nint a(void) { return 0; }\n"
            "\n// FUNCTION: GOLD 0x2000\n// SIZE: 16\nint a(void) { return 1; }\n"
        )
        cfg = _Cfg(tmp_path)
        row = _migrate_file(cfg, src / "a.c", "S", dry_run=False)
        assert row is not None and row["functions"] == 2
        assert "FUNCTION" not in (src / "a.c").read_text()

        from rebrew.metadata import load_metadata

        meta = load_metadata(tmp_path)
        assert meta[("S", 0x1000)]["size"] == 12
        assert meta[("GOLD", 0x2000)]["size"] == 16
        assert meta[("S", 0x1000)]["file"] == meta[("GOLD", 0x2000)]["file"]

        s_annos = parse_c_file_multi(src / "a.c", target_name="S", metadata_dir=tmp_path)
        g_annos = parse_c_file_multi(src / "a.c", target_name="GOLD", metadata_dir=tmp_path)
        assert [(a.va, a.size) for a in s_annos] == [(0x1000, 12)]
        assert [(a.va, a.size) for a in g_annos] == [(0x2000, 16)]

    def test_other_target_only_file_is_out_of_scope(self, tmp_path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        body = "// FUNCTION: GOLD 0x2000\nint b(void) { return 1; }\n"
        (src / "b.c").write_text(body)
        assert _migrate_file(_Cfg(tmp_path), src / "b.c", "S", dry_run=False) is None
        assert (src / "b.c").read_text() == body

    def test_data_only_file_stays_inline(self, tmp_path) -> None:
        from rebrew.metadata import load_metadata

        src = tmp_path / "src"
        src.mkdir()
        body = "// DATA: S 0x10025000\n// SIZE: 256\nextern unsigned char lut[256];\n"
        (src / "d.c").write_text(body)
        assert _migrate_file(_Cfg(tmp_path), src / "d.c", "S", dry_run=False) is None
        assert (src / "d.c").read_text() == body
        assert load_metadata(tmp_path) == {}
        annos = parse_c_file_multi(src / "d.c", metadata_dir=tmp_path)
        assert [a.marker_type for a in annos] == ["DATA"]
        assert annos[0].va == 0x10025000

    def test_mixed_function_and_data_marker_stays_inline(self, tmp_path) -> None:
        from rebrew.metadata import load_metadata

        src = tmp_path / "src"
        src.mkdir()
        body = (
            "// GLOBAL: S 0x1000\nextern int g;\n"
            "\n// FUNCTION: S 0x2000\n// SIZE: 8\nint f(void) { return g; }\n"
        )
        (src / "m.c").write_text(body)
        cfg = _Cfg(tmp_path)
        row = _migrate_file(cfg, src / "m.c", "S", dry_run=True)
        assert row is not None and row["skipped"] == "data-markers"
        assert (src / "m.c").read_text() == body
        assert load_metadata(tmp_path) == {}

        row = _migrate_file(cfg, src / "m.c", "S", dry_run=False)
        assert row is not None and row["skipped"] == "data-markers"
        assert (src / "m.c").read_text() == body
        assert load_metadata(tmp_path) == {}
        annos = parse_c_file_multi(src / "m.c", metadata_dir=tmp_path)
        assert sorted(a.marker_type for a in annos) == ["FUNCTION", "GLOBAL"]

    def test_other_target_data_marker_blocks_the_file(self, tmp_path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        body = (
            "// FUNCTION: S 0x1000\nint f(void) { return 0; }\n"
            "// VTABLE: GOLD 0x2000\nvoid *vt[4];\n"
        )
        (src / "m.c").write_text(body)
        row = _migrate_file(_Cfg(tmp_path), src / "m.c", "S", dry_run=False)
        assert row is not None and row["skipped"] == "data-markers"
        assert (src / "m.c").read_text() == body

    def test_marker_the_parser_misses_is_not_stripped(self, tmp_path) -> None:
        """A trailing marker matches the stripper but not the block parser."""
        from rebrew.metadata import load_metadata

        src = tmp_path / "src"
        src.mkdir()
        body = (
            "// FUNCTION: S 0x1000\nint f(void) { return 0; }\n"
            "int kept(void) { return 1; } // FUNCTION: S 0x2000\n"
        )
        (src / "a.c").write_text(body)
        row = _migrate_file(_Cfg(tmp_path), src / "a.c", "S", dry_run=False)
        assert row is not None and row["skipped"] == "unrecorded-markers"
        assert (src / "a.c").read_text() == body
        assert load_metadata(tmp_path) == {}


class TestMarkerlessAndRerun:
    def test_markerless_project_survives_marker_purge(self, tmp_path) -> None:
        """A file whose only annotations live in TOML is left byte-identical."""
        from rebrew.metadata import load_metadata, save_metadata

        src = tmp_path / "src"
        src.mkdir()
        save_metadata(
            tmp_path,
            {
                ("S", 0x1000): {
                    "file": "src/a.c",
                    "symbol": "a",
                    "marker_type": "FUNCTION",
                    "size": 12,
                }
            },
        )
        body = "int a(void) { return 0; }\n"
        (src / "a.c").write_text(body)
        before = load_metadata(tmp_path)

        assert _migrate_file(_Cfg(tmp_path), src / "a.c", "S", dry_run=False) is None
        assert (src / "a.c").read_text() == body
        assert load_metadata(tmp_path) == before
        annos = parse_c_file_multi(src / "a.c", metadata_dir=tmp_path)
        assert [(a.va, a.size) for a in annos] == [(0x1000, 12)]

    def test_second_migration_is_noop(self, tmp_path) -> None:
        """Re-running migration on its own output changes neither source nor TOML."""
        from rebrew.metadata import load_metadata

        src = tmp_path / "src"
        src.mkdir()
        (src / "a.c").write_text("// FUNCTION: S 0x1000\n// SIZE: 12\nint a(void) { return 0; }\n")
        cfg = _Cfg(tmp_path)
        assert _migrate_file(cfg, src / "a.c", "S", dry_run=False) is not None
        text, meta = (src / "a.c").read_text(), load_metadata(tmp_path)

        assert _migrate_file(cfg, src / "a.c", "S", dry_run=False) is None
        assert (src / "a.c").read_text() == text
        assert load_metadata(tmp_path) == meta
        assert meta[("S", 0x1000)]["size"] == 12
