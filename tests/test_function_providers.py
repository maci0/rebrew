"""Compiled library identities and evidence for prebuilt link providers."""

import json
from pathlib import Path

import pytest
from source_util import write_source

from rebrew.catalog.loaders import scan_reversed_dir
from rebrew.config import ProjectConfig
from rebrew.function_providers import bind_library_source, resolve_library_providers
from rebrew.metadata.bindings import SourceBinding
from rebrew.metadata.functions import record_function_rows


def _project(tmp_path: Path) -> ProjectConfig:
    src = tmp_path / "src"
    src.mkdir()
    return ProjectConfig(root=tmp_path, reversed_dir=src, marker="GAME", source_ext=".c")


class TestCompiledSources:
    def test_legacy_header_does_not_hide_explicit_compiled_source(self, tmp_path: Path) -> None:
        from rebrew.naming import load_data

        cfg = _project(tmp_path)
        source = tmp_path / "vendor.c"
        source.write_text("int checksum(void) { return 7; }\n")
        write_source(
            cfg.reversed_dir / "library_vendor.h",
            "\n// _checksum\n\n",
            metadata_fields={
                "GAME.0x10001000": {
                    "kind": "LIBRARY",
                    "size": 7,
                    "name": "checksum",
                    "symbol": "_checksum",
                }
            },
        )
        record_function_rows(
            cfg.metadata_dir,
            [
                {
                    "module": "GAME",
                    "va": 0x10001000,
                    "identity": {
                        "file": "vendor.c",
                        "symbol": "_checksum",
                        "name": "checksum",
                        "kind": "LIBRARY",
                    },
                    "fields": {"size": 7},
                }
            ],
        )
        _, existing, covered = load_data(cfg)
        assert existing[0x10001000]["filename"] == "../vendor.c"
        assert covered[0x10001000] == "../vendor.c"

    @pytest.mark.parametrize("dry_run", [False, True])
    def test_binding_command_preserves_library_origin_and_preview_is_read_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dry_run: bool
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.library import app
        from rebrew.metadata.functions import load_metadata

        cfg = _project(tmp_path)
        source = tmp_path / "vendor.c"
        source.write_text("int checksum(void) { return 7; }\n")
        write_source(
            cfg.reversed_dir / "library_vendor.h",
            "\n// checksum\n\n",
            metadata_fields={
                "GAME.0x10001000": {
                    "kind": "LIBRARY",
                    "size": 7,
                    "name": "checksum",
                    "symbol": "checksum",
                }
            },
        )
        monkeypatch.setattr("rebrew.library.require_config", lambda **_kwargs: cfg)
        args = ["bind-source", "0x10001000", str(source), "--symbol", "_checksum", "--json"]
        if dry_run:
            args.append("--dry-run")
        result = CliRunner().invoke(app, args)
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["provider"] == "compiled"
        metadata = load_metadata(cfg.metadata_dir)
        if dry_run:
            assert metadata[("GAME", 0x10001000)]["file"] == "src/library_vendor.h"
        else:
            assert metadata[("GAME", 0x10001000)]["kind"] == "LIBRARY"
            assert metadata[("GAME", 0x10001000)]["file"] == "vendor.c"
            assert metadata[("GAME", 0x10001000)]["status"] == "STUB"

    def test_header_binding_includes_reference_source_without_an_inline_marker(
        self, tmp_path: Path
    ) -> None:
        cfg = _project(tmp_path)
        source = tmp_path / "references" / "vendor.c"
        source.parent.mkdir()
        source.write_text("int checksum(void) { return 7; }\n")
        write_source(
            cfg.reversed_dir / "library_vendor.h",
            "\n// readable_checksum\n\n\n// other\n\n",
            metadata_fields={
                "GAME.0x10001000": {
                    "kind": "LIBRARY",
                    "size": 7,
                    "name": "readable_checksum",
                    "symbol": "readable_checksum",
                },
                "OTHER.0x10002000": {
                    "kind": "LIBRARY",
                    "size": 5,
                    "name": "other",
                    "symbol": "other",
                },
            },
            metadata_dir=cfg.metadata_dir,
        )
        record_function_rows(
            cfg.metadata_dir,
            [
                {
                    "module": "GAME",
                    "va": 0x10001000,
                    "identity": {
                        "file": "references/vendor.c",
                        "symbol": "_checksum",
                        "kind": "LIBRARY",
                    },
                }
            ],
        )
        entries = scan_reversed_dir(cfg.reversed_dir, cfg)
        assert len(entries) == 1
        entry = entries[0]
        assert entry.filepath == "../references/vendor.c"
        assert entry.symbol == "_checksum"
        assert entry.kind == "LIBRARY"
        assert entry.status == "STUB"  # identification is not source verification

        from rebrew.cli import resolve_source_arg
        from rebrew.metadata.bindings import read_source_bindings

        assert resolve_source_arg(cfg, "0x10001000") == source
        write_source(
            source,
            "/* ADDRESS: GAME 0x10003000 */\nint seed = 7;\nint checksum(void) { return seed; }\n",
            metadata_fields={"GAME.0x10003000": {"kind": "DATA"}},
            metadata_dir=cfg.metadata_dir,
        )
        parsed = read_source_bindings(source, target_name="GAME", metadata_dir=cfg.metadata_dir)
        assert {row.va for row in parsed} == {0x10001000, 0x10003000}

    def test_load_data_counts_compiled_library_outside_the_reversed_tree(
        self, tmp_path: Path
    ) -> None:
        """Status and todo read naming.load_data. A LIBRARY row whose file
        sits outside reversed_dir is still that function: no header and no
        marker in the .c required."""
        from rebrew.naming import load_data

        cfg = _project(tmp_path)
        source = tmp_path / "references" / "zlib" / "adler32.c"
        source.parent.mkdir(parents=True)
        source.write_text("unsigned adler32(void) { return 1; }\n", encoding="utf-8")
        record_function_rows(
            cfg.metadata_dir,
            [
                {
                    "module": "GAME",
                    "va": 0x10001000,
                    "identity": {
                        "file": "references/zlib/adler32.c",
                        "symbol": "_adler32",
                        "name": "adler32",
                        "kind": "LIBRARY",
                    },
                },
                {
                    "module": "OTHER",
                    "va": 0x10002000,
                    "identity": {
                        "file": "references/zlib/adler32.c",
                        "symbol": "_other",
                        "kind": "LIBRARY",
                    },
                },
            ],
        )
        _ghidra, existing, covered = load_data(cfg)
        assert 0x10001000 in existing
        assert 0x10002000 not in existing
        row = existing[0x10001000]
        assert row["kind"] == "LIBRARY"
        assert row["symbol"] == "_adler32"
        assert row["filename"] == "../references/zlib/adler32.c"
        assert covered[0x10001000] == row["filename"]

    def test_migrated_header_binding_survives_catalog_and_verify_scans(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.library import app
        from rebrew.verify import _library_header_rows

        cfg = _project(tmp_path)
        source = tmp_path / "vendor.c"
        source.write_text("int checksum(void) { return 7; }\n")
        header = cfg.reversed_dir / "library_vendor.h"
        header.write_text("int checksum(void);\n")
        record_function_rows(
            cfg.metadata_dir,
            [
                {
                    "module": module,
                    "va": 0x10001000,
                    "identity": {
                        "file": "library_vendor.h",
                        "symbol": "_checksum",
                        "name": "checksum",
                        "kind": "LIBRARY",
                    },
                    "fields": {"size": 7},
                }
                for module in ["GAME", "OTHER"]
            ],
        )
        monkeypatch.setattr("rebrew.library.require_config", lambda **_kwargs: cfg)
        args = ["bind-source", "0x10001000", str(source), "--symbol", "_checksum", "--json"]
        runner = CliRunner()
        for _ in range(2):
            result = runner.invoke(app, args)
            assert result.exit_code == 0, result.output
        entries = scan_reversed_dir(cfg.reversed_dir, cfg)
        assert len(entries) == 1
        entry = entries[0]
        assert entry.module == "GAME" and entry.va == 0x10001000
        assert entry.filepath == "../vendor.c" and entry.symbol == "_checksum"
        assert entry.kind == "LIBRARY" and entry.size == 7
        assert _library_header_rows(cfg)[entry.va]["symbol"] == "_checksum"

        record_function_rows(
            cfg.metadata_dir,
            [{"module": "GAME", "va": entry.va, "identity": {"symbol": "_changed"}}],
        )
        assert _library_header_rows(cfg)[entry.va]["symbol"] == "_changed"

    def test_missing_bound_source_is_still_a_verification_candidate(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        entry = bind_library_source(
            cfg,
            SourceBinding(va=0x10001000, filepath="library_vendor.h", kind="LIBRARY"),
            {"file": "references/missing.c", "symbol": "_missing"},
        )
        from rebrew.verify import verify_entry

        assert verify_entry(entry, cfg).status == "MISSING_FILE"

    @pytest.mark.parametrize("stored", ["../outside.c", "/outside.c"])
    def test_binding_rejects_escaping_identities(self, tmp_path: Path, stored: str) -> None:
        cfg = _project(tmp_path)
        with pytest.raises(ValueError):
            bind_library_source(cfg, SourceBinding(), {"file": stored})

    def test_binding_rejects_a_symlink_outside_the_project(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        source = tmp_path / "vendor.c"
        source.symlink_to(tmp_path.parent / "outside.c")
        with pytest.raises(ValueError):
            bind_library_source(cfg, SourceBinding(), {"file": "vendor.c"})


class TestProviderEvidence:
    def test_library_origin_does_not_establish_a_prebuilt_provider(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        headers = {0x10001000: {"name": "vendor", "symbol": "_vendor"}}
        rows = resolve_library_providers(cfg, [], headers, frozenset(headers))
        assert rows[0]["provider"] == "unresolved"

    def test_sources_and_native_archive_members_have_distinct_providers(
        self, tmp_path: Path
    ) -> None:
        cfg = _project(tmp_path)
        cfg.external_libs = {"LIBCMT": "LIBCMT.lib", "VENDOR": "VENDOR.lib"}
        cfg.raw_link = tmp_path / "build" / "game.dll"
        cfg.raw_link.parent.mkdir()
        cfg.raw_link.with_suffix(".map").write_text(
            " 0001:00000010 _vendor 10001010 f VENDOR:vendor.obj\n"
            " 0001:00000020 _runtime 10001020 f LIBCMT:runtime.obj\n"
            " 0001:00000030 _local 10001030 f local.c.obj\n"
        )
        headers = {
            0x10001000: {"name": "vendor", "symbol": "_vendor"},
            0x10002000: {"name": "runtime", "symbol": "_runtime"},
            0x10003000: {"name": "local", "symbol": "_local"},
        }
        entries = [
            SourceBinding(
                va=0x10001000, name="vendor", symbol="_vendor", filepath="../references/vendor.c"
            )
        ]
        rows = resolve_library_providers(cfg, entries, headers, frozenset(headers))
        assert [row["provider"] for row in rows] == ["compiled", "prebuilt", "unresolved"]
        assert rows[1]["library"] == "LIBCMT"
        # The map's linked VA differs: ownership is by native symbol, not VA.
        assert rows[1]["va"] == "0x10002000"

    def test_colliding_archive_symbols_stay_unresolved(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        cfg.external_libs = {"A": "A.lib", "B": "B.lib"}
        cfg.raw_link = tmp_path / "game.dll"
        cfg.raw_link.with_suffix(".map").write_text(
            " 0001:00000010 _same 10001010 f A:a.obj\n 0001:00000020 _same 10001020 f B:b.obj\n"
        )
        headers = {0x10001000: {"name": "same", "symbol": "_same"}}
        rows = resolve_library_providers(cfg, [], headers, frozenset(headers))
        assert rows[0]["provider"] == "unresolved"

    @pytest.mark.parametrize(
        "origin",
        [
            "BUILT_LOCALLY:local.obj",
            "local.c.obj",
            "LIBCMT:runtime.obj\n 0001:00000020 _same 10001020 f local.c.obj",
        ],
    )
    def test_archive_without_prebuilt_or_unique_provider_evidence_stays_unresolved(
        self, tmp_path: Path, origin: str
    ) -> None:
        cfg = _project(tmp_path)
        cfg.external_libs = {"LIBCMT": "LIBCMT.lib"}
        cfg.raw_link = tmp_path / "game.dll"
        cfg.raw_link.with_suffix(".map").write_text(f" 0001:00000010 _same 10001010 f {origin}\n")
        headers = {0x10001000: {"name": "same", "symbol": "_same"}}
        assert (
            resolve_library_providers(cfg, [], headers, frozenset(headers))[0]["provider"]
            == "unresolved"
        )

    def test_report_keeps_verified_library_counts_separate_from_provider_inventory(self) -> None:
        from rebrew.verify import build_report

        report = build_report(
            ProjectConfig(root=Path(".")),
            [],
            3,
            1,
            4,
            [],
            [],
            [],
            dry_run=False,
            compile_context=None,
            provenance="verify",
            library_passed=1,
            library_total=2,
            library_providers=[
                {"provider": "compiled"},
                {"provider": "compiled"},
                {"provider": "prebuilt"},
                {"provider": "unresolved"},
            ],
        )
        assert report["summary"]["library_providers"] == {
            "compiled": 2,
            "prebuilt": 1,
            "unresolved": 1,
        }
        assert report["summary"]["total"] == 4
        assert report["summary"]["library_total"] == 2
        assert report["summary"]["library_passed"] == 1
