"""Compiled library identities and evidence for prebuilt link providers."""

from pathlib import Path
from typing import Any

import pytest
from cli_json import cli_payload
from source_util import write_source

from rebrew.catalog.loaders import scan_reversed_dir
from rebrew.config import ProjectConfig
from rebrew.function_providers import bind_compiled_source, resolve_library_providers
from rebrew.metadata.bindings import SourceBinding
from rebrew.metadata.functions import record_function_rows


def _project(tmp_path: Path) -> ProjectConfig:
    src = tmp_path / "src"
    src.mkdir()
    return ProjectConfig(root=tmp_path, reversed_dir=src, module="GAME", source_ext=".c")


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
        assert cli_payload(result)["provider"] == "compiled"
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

    @pytest.mark.parametrize("kind", ["FUNCTION", "LIBRARY"])
    def test_load_data_counts_compiled_source_outside_the_reversed_tree(
        self, tmp_path: Path, kind: str
    ) -> None:
        """Status and todo read naming.load_data. A managed row whose file
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
                        "kind": kind,
                    },
                },
                {
                    "module": "OTHER",
                    "va": 0x10002000,
                    "identity": {
                        "file": "references/zlib/adler32.c",
                        "symbol": "_other",
                        "kind": kind,
                    },
                },
            ],
        )
        _ghidra, existing, covered = load_data(cfg)
        assert 0x10001000 in existing
        assert 0x10002000 not in existing
        row = existing[0x10001000]
        assert row["kind"] == kind
        assert row["symbol"] == "_adler32"
        assert row["filename"] == "../references/zlib/adler32.c"
        assert covered[0x10001000] == row["filename"]
        entries = scan_reversed_dir(cfg.reversed_dir, cfg)
        assert [(entry.va, entry.kind) for entry in entries] == [(0x10001000, kind)]
        from rebrew.source_selection import collect_target_sources
        from rebrew.verify import _library_header_rows

        assert collect_target_sources(cfg, "GAME")[0] == [source]
        assert (0x10001000 in _library_header_rows(cfg)) is (kind == "LIBRARY")
        from rebrew.cli import resolve_source_arg

        assert resolve_source_arg(cfg, "0x10001000") == source

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
        entry = bind_compiled_source(
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
            bind_compiled_source(cfg, SourceBinding(), {"file": stored})

    def test_binding_rejects_a_symlink_outside_the_project(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        source = tmp_path / "vendor.c"
        source.symlink_to(tmp_path.parent / "outside.c")
        with pytest.raises(ValueError):
            bind_compiled_source(cfg, SourceBinding(), {"file": "vendor.c"})
        from rebrew.function_providers import compiled_source_annotations

        with pytest.raises(ValueError):
            compiled_source_annotations(
                cfg,
                metadata={
                    ("GAME", 0x1000): {
                        "file": "vendor.c",
                        "kind": "FUNCTION",
                        "name": "vendor",
                        "symbol": "_vendor",
                    }
                },
            )

    def test_plain_rows_do_not_walk_display_paths(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An in-tree row under a real directory resolves its display path by prefix.

        The base containment and display prefix depend only on the project
        paths, so doing them per row made the status binding loop walk the
        filesystem once per function.
        """
        from rebrew import function_providers as providers
        from rebrew.utils import rel_display_path

        cfg = _project(tmp_path)
        for i in range(3):
            (cfg.reversed_dir / f"f{i}.c").write_text(f"int f{i}(void) {{ return {i}; }}\n")
        metadata = {
            ("GAME", 0x1000 + i * 0x10): {
                "file": f"src/f{i}.c",
                "kind": "FUNCTION",
                "name": f"f{i}",
                "symbol": f"_f{i}",
            }
            for i in range(3)
        }
        calls = {"n": 0}
        real = rel_display_path

        def counting(*args: Any, **kwargs: Any) -> str:
            calls["n"] += 1
            return str(real(*args, **kwargs))

        monkeypatch.setattr("rebrew.function_providers.rel_display_path", counting)
        rows = providers.compiled_source_annotations(cfg, metadata=metadata)
        assert [row.filepath for row in rows] == ["f0.c", "f1.c", "f2.c"]
        assert calls["n"] == 0


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


class TestExactProviderPaths:
    @pytest.mark.parametrize("anchored", [False, True])
    def test_nested_metadata_resolves_library_from_project_root(
        self, tmp_path: Path, anchored: bool
    ) -> None:
        from rebrew.metadata.bindings import read_source_bindings

        source = tmp_path / "lib/native/f.c"
        source.parent.mkdir(parents=True)
        prefix = "/* ADDRESS: GAME 0x00401000 */\n" if anchored else ""
        source.write_text(prefix + "int f(void) { return 0; }\n")
        reversed_dir = tmp_path / "src/game"
        reversed_dir.mkdir(parents=True)
        cfg = ProjectConfig(root=tmp_path, reversed_dir=reversed_dir, module="GAME")
        record_function_rows(
            reversed_dir.parent,
            [
                {
                    "module": "GAME",
                    "va": 0x401000,
                    "identity": {
                        "file": "lib/native/f.c",
                        "kind": "LIBRARY",
                        "name": "f",
                        "symbol": "_f",
                    },
                    "fields": {"size": 4},
                }
            ],
        )
        rows = read_source_bindings(
            source, target_name="GAME", metadata_dir=cfg.metadata_dir, project_root=cfg.root
        )
        assert len(rows) == 1
        assert (rows[0].kind, rows[0].symbol, rows[0].size) == ("LIBRARY", "_f", 4)
        assert rows[0].prototype
        from rebrew.metadata.bindings import file_backed_by_metadata, function_rows_for_file
        from rebrew.metadata.functions import load_metadata

        metadata = load_metadata(cfg.metadata_dir)
        assert function_rows_for_file(source, cfg.metadata_dir, metadata, project_root=cfg.root)
        wrong_namespace = cfg.metadata_dir / "lib/native/f.c"
        assert not function_rows_for_file(
            wrong_namespace, cfg.metadata_dir, metadata, project_root=cfg.root
        )
        assert not file_backed_by_metadata(wrong_namespace, cfg.metadata_dir, project_root=cfg.root)
        scanned = scan_reversed_dir(reversed_dir, cfg)
        assert [(row.va, row.filepath) for row in scanned] == [(0x401000, "../../lib/native/f.c")]
        imposter = reversed_dir / "imposter.c"
        imposter.write_text("/* ADDRESS: GAME 0x00401000 */\nint f(void) { return 1; }\n")
        with pytest.raises(ValueError, match="stored source binding"):
            scan_reversed_dir(reversed_dir, cfg)

    def test_invalid_counterpart_does_not_poison_selected_test(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.bindings import read_source_bindings
        from rebrew.test import _run_test_impl

        source = tmp_path / "src/shared/f.c"
        source.parent.mkdir(parents=True)
        source.write_text(
            "/* ADDRESS: A 0x00401000 */\n/* ADDRESS: B 0x00501000 */\nint f(void) { return 0; }\n"
        )
        reversed_dir = tmp_path / "src/game"
        reversed_dir.mkdir()
        cfg = ProjectConfig(
            root=tmp_path, reversed_dir=reversed_dir, module="A", target_binary=tmp_path / "a.exe"
        )
        record_function_rows(
            reversed_dir.parent,
            [
                {
                    "module": module,
                    "va": va,
                    "identity": {"file": file, "kind": "FUNCTION", "name": "f", "symbol": "_f"},
                    "fields": {"size": 4},
                }
                for module, va, file in [
                    ("A", 0x401000, "shared/f.c"),
                    ("B", 0x501000, "other/f.c"),
                ]
            ],
        )
        rows = read_source_bindings(
            source, target_name="A", metadata_dir=cfg.metadata_dir, project_root=cfg.root
        )
        with pytest.raises(ValueError, match="stored source binding"):
            read_source_bindings(
                source, target_name="B", metadata_dir=cfg.metadata_dir, project_root=cfg.root
            )
        monkeypatch.setattr(
            "rebrew.compiler.overrides.resolve_compile_overrides", lambda *args: (None, "")
        )
        monkeypatch.setattr("rebrew.test._cmake_pin_for", lambda *args: (None, None))

        class ReachedSelectedBytes(Exception):
            pass

        def extract(binary: Path, va: int, size: int) -> bytes:
            assert (binary, va, size) == (cfg.target_binary, 0x401000, 4)
            raise ReachedSelectedBytes

        monkeypatch.setattr("rebrew.test.extract_raw_bytes", extract)
        with pytest.raises(ReachedSelectedBytes):
            _run_test_impl(
                cfg, str(source), lint_annos=rows, name_to_va={}, json_output=True, no_promote=True
            )


class TestBindSourceWithoutPriorClaim:
    """bind-source records a LIBRARY row for a VA with no declaration or row."""

    def test_rowles_va_gets_a_library_row(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from rebrew.library import app
        from rebrew.metadata.functions import get_entry, load_metadata

        cfg = _project(tmp_path)
        source = tmp_path / "references" / "zlib-1.1.3" / "adler32.c"
        source.parent.mkdir(parents=True)
        source.write_text(
            "unsigned long adler32(unsigned long a, const void *b, unsigned n)\n{ return a + n; }\n"
        )
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("rebrew.library.require_config", lambda **_kwargs: cfg)
            result = CliRunner().invoke(
                app,
                [
                    "bind-source",
                    "0x10001000",
                    str(source),
                    "--symbol",
                    "_adler32",
                    "--json",
                ],
            )
        assert result.exit_code == 0, result.output
        assert cli_payload(result)["provider"] == "compiled"
        row = get_entry(cfg.metadata_dir, 0x10001000, "GAME")
        assert row["kind"] == "LIBRARY"
        assert row["symbol"] == "_adler32"
        assert row["name"] == "adler32"
        assert row["file"] == "references/zlib-1.1.3/adler32.c"
        assert "binding_history" not in row
        assert ("GAME", 0x10001000) in load_metadata(cfg.metadata_dir)

    def test_active_function_claim_is_refused(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from rebrew.library import app
        from rebrew.metadata.functions import record_function_identity

        cfg = _project(tmp_path)
        source = tmp_path / "references" / "adler32.c"
        source.parent.mkdir(parents=True)
        source.write_text("int f(void) { return 0; }\n")
        record_function_identity(
            cfg.metadata_dir,
            module="GAME",
            va=0x10001000,
            file="src/f.c",
            kind="FUNCTION",
            name="f",
            symbol="_f",
        )
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("rebrew.library.require_config", lambda **_kwargs: cfg)
            result = CliRunner().invoke(
                app,
                ["bind-source", "0x10001000", str(source), "--symbol", "_adler32", "--json"],
            )
        assert result.exit_code == 2
        assert "retire or rebind" in result.output
