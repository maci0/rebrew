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
