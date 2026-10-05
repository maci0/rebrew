"""End-to-end test for `rebrew source migrate-markers`: inline markers → TOML,
stripped pure-C sources, and post-migration parsing."""

import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from rebrew.migrate_markers import app

runner = CliRunner()


class TestMigrateMarkersEndToEnd:
    def test_migrate_strip_and_reparses(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "func.c").write_text(
            "// FUNCTION: S 0x401000\n"
            "// SIZE: 12\n"
            "// CFLAGS: /O2 /Gz\n"
            "int __stdcall myFunc(int a) {\n"
            "    return a + 1;\n"
            "}\n",
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="S",
            source_ext=".c",
        )
        # require_config is invoked through the CLI; bypass it by calling
        # the internal path directly with a stub cfg.
        from rebrew.annotation import parse_c_file_multi
        from rebrew.sources import iter_sources

        annos = parse_c_file_multi(src / "func.c", metadata_dir=tmp_path)
        assert annos, "pre-migration: file must parse with inline markers"

        results = []
        from rebrew.migrate_markers import _migrate_file

        for s in iter_sources(src, cfg):
            row = _migrate_file(cfg, s, "S", dry_run=False)
            if row:
                results.append(row)
        assert len(results) == 1

        # Source is now pure C.
        text = (src / "func.c").read_text(encoding="utf-8")
        assert "FUNCTION:" not in text
        assert "SIZE:" not in text
        assert "int __stdcall myFunc" in text

        # Post-migration parse synthesizes the same Annotation from TOML.
        annos2 = parse_c_file_multi(src / "func.c", metadata_dir=tmp_path)
        assert len(annos2) == 1
        ann = annos2[0]
        assert ann.va == 0x401000
        assert ann.module == "S"
        assert ann.symbol == annos[0].symbol  # link-accurate (decorated) symbol preserved
        assert ann.size == 12
        assert ann.cflags == "/O2 /Gz"

        # Idempotent: a second migration is a no-op.
        rows2 = [
            r
            for s in iter_sources(src, cfg)
            if (r := _migrate_file(cfg, s, "S", dry_run=False)) is not None
        ]
        assert rows2 == []

    def test_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "f.c").write_text(
            "// FUNCTION: S 0x1000\nint f(void) { return 0; }\n", encoding="utf-8"
        )
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c"
        )
        from rebrew.migrate_markers import _migrate_file

        row = _migrate_file(cfg, src / "f.c", "S", dry_run=True)
        assert row is not None
        assert "FUNCTION:" in (src / "f.c").read_text(encoding="utf-8")
        from rebrew.metadata import load_metadata

        assert load_metadata(tmp_path) == {}

    def test_pre_migration_copy_survives_a_clean_run(self, tmp_path: Path) -> None:
        """The strip is one-shot, so the pre-migration bytes stay on disk.

        Nothing puts a removed marker line back; a strip that turned out to
        have taken a hand-written line with it has to be undoable from the
        backup the row names, not from memory.
        """
        src = tmp_path / "src"
        src.mkdir()
        original = "// FUNCTION: S 0x1000\n// SIZE: 4\nint a(void) { return 0; }\n"
        (src / "f.c").write_text(original, encoding="utf-8")
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c"
        )
        from rebrew.migrate_markers import _migrate_file

        row = _migrate_file(cfg, src / "f.c", "S", dry_run=False)
        assert row is not None
        backup = Path(str(row["backup"]))
        assert backup.is_file()
        assert backup.read_text(encoding="utf-8") == original
        # A dry run writes nothing, so it names no copy.
        (src / "g.c").write_text(original, encoding="utf-8")
        dry = _migrate_file(cfg, src / "g.c", "S", dry_run=True)
        assert dry is not None and dry["backup"] is None

    def test_legacy_encoding_survives_the_strip(self, tmp_path: Path) -> None:
        """Stripping markers must not transcode the rest of the file.

        The marker lines are ASCII but the body beside them is CP1252; writing
        the stripped text back as UTF-8 would rewrite every high byte in a
        source whose bytes are the match target.
        """
        src = tmp_path / "src"
        src.mkdir()
        body = 'const char *s = "Caf\xe9";\n'
        (src / "f.c").write_bytes(("// FUNCTION: S 0x1000\n// SIZE: 4\n" + body).encode("latin-1"))
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c"
        )
        from rebrew.migrate_markers import _migrate_file

        assert _migrate_file(cfg, src / "f.c", "S", dry_run=False) is not None
        assert (src / "f.c").read_bytes() == body.encode("latin-1")

    def test_concurrent_status_promotion_survives(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.metadata as md
        from rebrew.migrate_markers import _migrate_file

        src = tmp_path / "src"
        src.mkdir()
        (src / "f.c").write_text(
            "// FUNCTION: S 0x1000\n// SIZE: 4\nint f(void) { return 0; }\n", encoding="utf-8"
        )
        md.update_source_status(tmp_path, "STUB", "S", 0x1000)
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c"
        )

        real_record = md.record_migrated_markers
        writer = threading.Thread(
            target=md.update_source_status, args=(tmp_path, "EXACT", "S", 0x1000)
        )

        def _race_then_record(directory: Path, rows: Any) -> None:
            # A verify promotion landing just before the migrate write.
            writer.start()
            writer.join(timeout=0.5)
            real_record(directory, rows)

        monkeypatch.setattr(md, "record_migrated_markers", _race_then_record)
        _migrate_file(cfg, src / "f.c", "S", dry_run=False)
        writer.join(timeout=5)
        assert not writer.is_alive()

        entry = md.load_metadata(tmp_path)[("S", 0x1000)]
        assert entry["status"] == "EXACT"
        assert entry["size"] == 4

    def test_failed_metadata_write_keeps_inline_markers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.metadata as md
        from rebrew.migrate_markers import _migrate_file

        src = tmp_path / "src"
        src.mkdir()
        (src / "f.c").write_text(
            "// FUNCTION: S 0x1000\n// SIZE: 4\nint f(void) { return 0; }\n", encoding="utf-8"
        )
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c"
        )

        def _fail(*_a: Any, **_kw: Any) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(md, "record_migrated_markers", _fail)
        with pytest.raises(OSError, match="disk full"):
            _migrate_file(cfg, src / "f.c", "S", dry_run=False)
        assert "// SIZE: 4" in (src / "f.c").read_text(encoding="utf-8")

    def test_corrupt_store_is_not_overwritten(self, tmp_path: Path) -> None:
        from rebrew.migrate_markers import _migrate_file

        src = tmp_path / "src"
        src.mkdir()
        (src / "f.c").write_text(
            "// FUNCTION: S 0x1000\n// SIZE: 4\nint f(void) { return 0; }\n", encoding="utf-8"
        )
        store = tmp_path / "rebrew-functions.toml"
        corrupt = '["S.0x2000"\nstatus = "EXACT"\n'
        store.write_text(corrupt, encoding="utf-8")
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c"
        )

        with pytest.raises(ValueError, match="unparseable"):
            _migrate_file(cfg, src / "f.c", "S", dry_run=False)
        assert store.read_text(encoding="utf-8") == corrupt
        assert "// SIZE: 4" in (src / "f.c").read_text(encoding="utf-8")

    def test_unrelated_store_content_survives(self, tmp_path: Path) -> None:
        from rebrew.metadata import load_metadata
        from rebrew.migrate_markers import _migrate_file

        src = tmp_path / "src"
        src.mkdir()
        (src / "f.c").write_text(
            "// FUNCTION: S 0x1000\n// SIZE: 4\nint f(void) { return 0; }\n", encoding="utf-8"
        )
        store = tmp_path / "rebrew-functions.toml"
        store.write_text(
            '# hand note kept by tomlkit\n["S.0x2000"]\nstatus = "EXACT"\n\n'
            '["unqualified"]\nnote = "loader skips this key"\n',
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c"
        )

        assert _migrate_file(cfg, src / "f.c", "S", dry_run=False) is not None

        text = store.read_text(encoding="utf-8")
        assert "# hand note kept by tomlkit" in text
        assert '["unqualified"]' in text
        meta = load_metadata(tmp_path)
        assert meta[("S", 0x2000)]["status"] == "EXACT"
        assert meta[("S", 0x1000)]["size"] == 4
        assert meta[("S", 0x1000)]["file"] == "src/f.c"
        assert "status" not in meta[("S", 0x1000)]
        assert oct(store.stat().st_mode & 0o777) == "0o444"

    def test_cli_app_runs_help(self) -> None:
        """The command is registered and advertises the flags it honors: a
        migration tool whose ``--dry-run`` is missing from help is a tool whose
        ``--dry-run`` nobody uses."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0, result.output
        assert "rebrew-functions.toml" in result.output
        for flag in ("--dry-run", "--json", "--target"):
            assert flag in result.output, flag
