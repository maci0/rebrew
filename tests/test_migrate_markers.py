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
        from rebrew.marker_migration import migrate_source_file

        for s in iter_sources(src, cfg):
            row = migrate_source_file(cfg, s, "S", dry_run=False)
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
            if (r := migrate_source_file(cfg, s, "S", dry_run=False)) is not None
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
        from rebrew.marker_migration import migrate_source_file

        row = migrate_source_file(cfg, src / "f.c", "S", dry_run=True)
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
        from rebrew.marker_migration import migrate_source_file

        row = migrate_source_file(cfg, src / "f.c", "S", dry_run=False)
        assert row is not None
        backup = Path(str(row["backup"]))
        assert backup.is_file()
        assert backup.read_text(encoding="utf-8") == original
        # A dry run writes nothing, so it names no copy.
        (src / "g.c").write_text(original, encoding="utf-8")
        dry = migrate_source_file(cfg, src / "g.c", "S", dry_run=True)
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
        from rebrew.marker_migration import migrate_source_file

        assert migrate_source_file(cfg, src / "f.c", "S", dry_run=False) is not None
        assert (src / "f.c").read_bytes() == body.encode("latin-1")

    def test_concurrent_status_promotion_survives(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.metadata as md
        from rebrew.marker_migration import migrate_source_file

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
        migrate_source_file(cfg, src / "f.c", "S", dry_run=False)
        writer.join(timeout=5)
        assert not writer.is_alive()

        entry = md.load_metadata(tmp_path)[("S", 0x1000)]
        assert entry["status"] == "EXACT"
        assert entry["size"] == 4

    def test_failed_metadata_write_keeps_inline_markers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.metadata as md
        from rebrew.marker_migration import migrate_source_file

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
            migrate_source_file(cfg, src / "f.c", "S", dry_run=False)
        assert "// SIZE: 4" in (src / "f.c").read_text(encoding="utf-8")

    def test_corrupt_store_is_not_overwritten(self, tmp_path: Path) -> None:
        from rebrew.marker_migration import migrate_source_file

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
            migrate_source_file(cfg, src / "f.c", "S", dry_run=False)
        assert store.read_text(encoding="utf-8") == corrupt
        assert "// SIZE: 4" in (src / "f.c").read_text(encoding="utf-8")

    def test_unrelated_store_content_survives(self, tmp_path: Path) -> None:
        from rebrew.marker_migration import migrate_source_file
        from rebrew.metadata import load_metadata

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

        assert migrate_source_file(cfg, src / "f.c", "S", dry_run=False) is not None

        text = store.read_text(encoding="utf-8")
        assert "# hand note kept by tomlkit" in text
        assert '["unqualified"]' in text
        meta = load_metadata(tmp_path)
        assert meta[("S", 0x2000)]["status"] == "EXACT"
        assert meta[("S", 0x1000)]["size"] == 4
        assert meta[("S", 0x1000)]["file"] == "src/f.c"
        assert "status" not in meta[("S", 0x1000)]
        assert oct(store.stat().st_mode & 0o777) == "0o444"

    def test_inline_scalars_move_and_file_borne_comments_stay(self, tmp_path: Path) -> None:
        """A blocker on the marker block is metadata. The naked fence is not."""
        from rebrew.annotation import parse_c_file_multi
        from rebrew.marker_migration import migrate_source_file
        from rebrew.metadata import load_metadata

        src = tmp_path / "src"
        src.mkdir()
        original = (
            "// FUNCTION: S 0x1000\n"
            "// SIZE: 4\n"
            "// BLOCKER: far proc has no byte-match profile\n"
            "// NOTE: word sibling\n"
            "// GHIDRA: FUN_1000\n"
            "// SKIP: 1\n"
            "// GLOBALS: g_counter, g_state\n"
            "// BLOCKER_DELTA: 2\n"
            "// SOURCE: naked\n"
            "// STRUCT: Packet\n"
            "// CALLERS: _send\n"
            "int f(void) { return 0; }\n"
        )
        (src / "f.c").write_text(original, encoding="utf-8")
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c"
        )
        row = migrate_source_file(cfg, src / "f.c", "S", dry_run=False)
        assert row is not None
        text = (src / "f.c").read_text(encoding="utf-8")
        assert "FUNCTION:" not in text
        assert "BLOCKER:" not in text
        assert "NOTE:" not in text
        assert "// SOURCE: naked" in text
        assert "// STRUCT: Packet" in text
        assert "// CALLERS: _send" in text
        assert "int f(void)" in text
        entry = load_metadata(tmp_path)[("S", 0x1000)]
        assert entry["blocker"] == "far proc has no byte-match profile"
        assert entry["note"] == "word sibling"
        assert entry["ghidra"] == "FUN_1000"
        assert entry["skip"] == "1"
        assert entry["globals"] == ["g_counter", "g_state"]
        assert entry["blocker_delta"] == 2
        assert "source" not in entry
        ann = parse_c_file_multi(src / "f.c", metadata_dir=tmp_path)[0]
        assert ann.source == "naked"
        assert ann.struct == "Packet"
        assert ann.callers == "_send"
        assert ann.blocker == entry["blocker"]

    def test_stored_blocker_wins_over_the_inline_copy(self, tmp_path: Path) -> None:
        from rebrew.marker_migration import migrate_source_file
        from rebrew.metadata import load_metadata

        src = tmp_path / "src"
        src.mkdir()
        original = "// FUNCTION: S 0x1000\n// BLOCKER: inline reason\nint f(void) { return 0; }\n"
        (src / "f.c").write_text(original, encoding="utf-8")
        (tmp_path / "rebrew-functions.toml").write_text(
            '["S.0x1000"]\nblocker = "stored reason"\n',
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c"
        )
        row = migrate_source_file(cfg, src / "f.c", "S", dry_run=False)
        assert row is not None
        assert load_metadata(tmp_path)[("S", 0x1000)]["blocker"] == "stored reason"
        assert "BLOCKER:" not in (src / "f.c").read_text(encoding="utf-8")
        assert "inline reason" in Path(str(row["backup"])).read_text(encoding="utf-8")

    def test_data_note_is_filled_when_the_row_lacks_one(self, tmp_path: Path) -> None:
        from rebrew.data_metadata import load_data_metadata
        from rebrew.marker_migration import migrate_source_file

        src = tmp_path / "src"
        src.mkdir()
        (src / "d.c").write_text(
            "// DATA: S 0x2000\n// NOTE: sprite table\nextern unsigned char lut[4];\n",
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=src, metadata_dir=tmp_path, marker="S", source_ext=".c"
        )
        assert migrate_source_file(cfg, src / "d.c", "S", dry_run=False) is not None
        entry = load_data_metadata(tmp_path)[("S", 0x2000)]
        assert entry["note"] == "sprite table"
        assert entry["name"] == "lut"
        assert "NOTE:" not in (src / "d.c").read_text(encoding="utf-8")

    def test_cli_app_runs_help(self) -> None:
        """The command is registered and advertises the flags it honors: a
        migration tool whose ``--dry-run`` is missing from help is a tool whose
        ``--dry-run`` nobody uses."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0, result.output
        assert "rebrew-functions.toml" in result.output
        assert "rebrew-data.toml" in result.output
        for flag in ("--dry-run", "--json", "--target"):
            assert flag in result.output, flag


class TestLibraryInventoryMigration:
    @pytest.mark.parametrize(
        ("symbol", "name"),
        [
            ("_fclose", "fclose"),
            ("__fclose_lk", "_fclose_lk"),
            ("_Close@4", "Close"),
            ("@Fast@8", "Fast"),
            ("?WithinEpsilon@@YAHMM@Z", "?WithinEpsilon@@YAHMM@Z"),
        ],
    )
    def test_native_symbols_survive_marker_removal(
        self, tmp_path: Path, symbol: str, name: str
    ) -> None:
        from rebrew.annotation import parse_library_header
        from rebrew.marker_migration import migrate_source_file
        from rebrew.metadata import get_entry

        src = tmp_path / "src"
        src.mkdir()
        header = src / "library_runtime.h"
        original = f"// LIBRARY: S 0x1000\n// {symbol}\n// SIZE: 0x20\n"
        header.write_text(original)
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=src, metadata_dir=src, marker="S", source_ext=".c"
        )
        assert migrate_source_file(cfg, header, "S", dry_run=True) is not None
        assert header.read_text() == original
        assert not (src / "rebrew-functions.toml").exists()
        assert migrate_source_file(cfg, header, "S", dry_run=False) is not None
        entry = get_entry(src, 0x1000, "S")
        assert entry["symbol"] == symbol
        assert entry["name"] == name
        assert entry["size"] == 0x20
        assert header.read_text().strip() == ""
        assert parse_library_header(header, metadata_dir=src)[0].symbol == symbol
        assert migrate_source_file(cfg, header, "S", dry_run=False) is None

    def test_header_removal_preserves_bound_compiled_provider(self, tmp_path: Path) -> None:
        from rebrew.function_providers import compiled_library_annotations
        from rebrew.marker_migration import migrate_source_file
        from rebrew.metadata import get_entry, record_function_identity

        src = tmp_path / "src"
        src.mkdir()
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        (vendor / "provider.c").write_text("int __cdecl fclose(void) { return 0; }\n")
        header = src / "library_runtime.h"
        header.write_text("// LIBRARY: S 0x1000\n// _fclose\n// SIZE: 0x20\n")
        cfg = SimpleNamespace(
            root=tmp_path, reversed_dir=src, metadata_dir=src, marker="S", source_ext=".c"
        )
        record_function_identity(
            src,
            module="S",
            va=0x1000,
            file="vendor/provider.c",
            marker_type="LIBRARY",
            name="fclose",
            symbol="_fclose",
            size=24,
            cflags="/O2 /Gd",
        )
        prior = get_entry(src, 0x1000, "S")
        assert migrate_source_file(cfg, header, "S", dry_run=False) is not None
        assert get_entry(src, 0x1000, "S") == prior
        entries = compiled_library_annotations(cfg)
        assert len(entries) == 1
        assert entries[0].symbol == "_fclose"
        assert (src / entries[0].filepath).resolve() == vendor / "provider.c"


class TestOverlappingLibrarySourceMigration:
    @pytest.mark.parametrize("source_first", [True, False])
    @pytest.mark.parametrize("metadata_in_src", [True, False])
    def test_compiled_function_keeps_library_ancestry(
        self, tmp_path: Path, source_first: bool, metadata_in_src: bool
    ) -> None:
        from rebrew.function_providers import (
            compiled_library_annotations,
            resolve_library_providers,
        )
        from rebrew.marker_migration import migrate_source_file
        from rebrew.metadata import load_metadata
        from rebrew.verify import _library_header_rows

        src = tmp_path / "src"
        src.mkdir()
        provider = src / "provider.c"
        provider.write_text(
            "// FUNCTION: S 0x401000\n// SIZE: 6\nint adapted(void) { return 1; }\n",
            encoding="utf-8",
        )
        header = src / "library_runtime.h"
        header.write_text(
            "// LIBRARY: S 0x401000\n// _original_native\n// SIZE: 6\n",
            encoding="utf-8",
        )
        metadata = src if metadata_in_src else tmp_path
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=metadata,
            marker="S",
            source_ext=".c",
        )
        order = [provider, header] if source_first else [header, provider]
        for source in order:
            before = source.read_bytes()
            assert migrate_source_file(cfg, source, None, dry_run=True) is not None
            assert source.read_bytes() == before
            assert migrate_source_file(cfg, source, None, dry_run=False) is not None
        row = load_metadata(metadata)[("S", 0x401000)]
        assert row["marker_type"] == "LIBRARY"
        assert row["file"] == "src/provider.c"
        assert row["symbol"] == "_adapted"
        assert row["name"] == "adapted"
        entries = compiled_library_annotations(cfg)
        assert len(entries) == 1
        assert (src / entries[0].filepath).resolve() == provider
        headers = _library_header_rows(cfg)
        rows = resolve_library_providers(cfg, entries, headers, frozenset(headers))
        assert rows == [
            {
                "va": "0x00401000",
                "name": "adapted",
                "provider": "compiled",
                "file": "provider.c",
                "symbol": "_adapted",
            }
        ]
        previous = dict(row)
        for source in order:
            assert migrate_source_file(cfg, source, None, dry_run=False) is None
        assert load_metadata(metadata)[("S", 0x401000)] == previous

    @pytest.mark.parametrize("dry_run", [True, False])
    def test_ambiguous_provider_keeps_header_and_store(self, tmp_path: Path, dry_run: bool) -> None:
        from rebrew.marker_migration import migrate_source_file
        from rebrew.metadata import METADATA_FILENAME, record_function_identity

        src = tmp_path / "src"
        src.mkdir()
        for directory in [tmp_path, src]:
            (directory / "provider.c").write_text("int adapted(void) { return 1; }\n")
        header = src / "library_runtime.h"
        header.write_text("// LIBRARY: S 0x401000\n// _original_native\n")
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=src,
            marker="S",
            source_ext=".c",
        )
        record_function_identity(
            src,
            module="S",
            va=0x401000,
            file="provider.c",
            symbol="_adapted",
            name="adapted",
            marker_type="FUNCTION",
        )
        source_before = header.read_bytes()
        store_before = (src / METADATA_FILENAME).read_bytes()
        result = migrate_source_file(cfg, header, None, dry_run=dry_run)
        assert result is not None
        assert result["skipped"].startswith("invalid-library-provider:")
        assert header.read_bytes() == source_before
        assert (src / METADATA_FILENAME).read_bytes() == store_before
