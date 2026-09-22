"""End-to-end test for `rebrew migrate-markers`: inline markers → TOML,
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
        cfg = SimpleNamespace(reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c")
        from rebrew.migrate_markers import _migrate_file

        row = _migrate_file(cfg, src / "f.c", "S", dry_run=True)
        assert row is not None
        assert "FUNCTION:" in (src / "f.c").read_text(encoding="utf-8")
        from rebrew.metadata import load_metadata

        assert load_metadata(tmp_path) == {}

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
        cfg = SimpleNamespace(reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c")

        real_save = md.save_metadata
        writer = threading.Thread(
            target=md.update_source_status, args=(tmp_path, "EXACT", "S", 0x1000)
        )

        def _race_then_save(directory: Path, data: Any) -> None:
            # A verify promotion landing between migrate's load and save.
            writer.start()
            writer.join(timeout=0.5)
            real_save(directory, data)

        monkeypatch.setattr(md, "save_metadata", _race_then_save)
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
        cfg = SimpleNamespace(reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c")

        def _fail(*_a: Any, **_kw: Any) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(md, "save_metadata", _fail)
        with pytest.raises(OSError):
            _migrate_file(cfg, src / "f.c", "S", dry_run=False)
        assert "// SIZE: 4" in (src / "f.c").read_text(encoding="utf-8")

    def test_cli_app_runs_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
