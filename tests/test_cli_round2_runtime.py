"""Regression coverage for project scope, compiler defaults, and source selectors."""

import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from cli_json import cli_payload
from source_util import write_source
from typer.testing import CliRunner


class TestPreviewRequirements:
    def test_type_recovery_preview_requires_an_output_before_loading_project(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.app.main import app

        def _unexpected(*args: object, **kwargs: object) -> None:
            pytest.fail("an invalid preview started project/decompiler work")

        monkeypatch.setattr("rebrew.struct_recover.require_config", _unexpected)
        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", _unexpected)
        result = CliRunner().invoke(app, ["types", "recover", "--dry-run", "--json"])
        assert result.exit_code == 2, result.output
        assert cli_payload(result)["error"] == "--dry-run requires --output"


class TestProjectWideRoots:
    @pytest.mark.parametrize("operation", ["stats", "clear"])
    def test_cache_root_reaches_configuration(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
    ) -> None:
        from rebrew import cache_cli

        selected = tmp_path / "project"
        selected.mkdir()
        seen: list[Path] = []

        def _config(*, root: Path | None, json_mode: bool) -> SimpleNamespace:
            assert root is not None
            seen.append(root)
            return SimpleNamespace(root=root)

        monkeypatch.setattr(cache_cli, "require_config", _config)
        result = CliRunner().invoke(cache_cli.app, [operation, "--root", str(selected), "--json"])
        assert result.exit_code == 0, result.output
        assert seen == [selected]
        assert cli_payload(result)["cache_dir"] == str(selected / ".rebrew/compile_cache")

    @pytest.mark.parametrize(
        "route", [["cache", "stats"], ["cache", "clear"], ["source", "findings", "0x1000"]]
    )
    def test_project_wide_commands_reject_ignored_target(self, route: list[str]) -> None:
        from rebrew.app.main import app

        result = CliRunner().invoke(app, [*route, "--target", "unused"])
        assert result.exit_code == 2, result.output
        assert "No such option" in result.output

    def test_findings_can_search_an_explicit_document_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.app.main import app

        selected = tmp_path / "documents"
        selected.mkdir()
        (selected / "goal.md").write_text("0x1000 measured\n")
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(
            app,
            ["source", "findings", "0x1000", "--root", str(selected), "--doc", "goal.md", "--json"],
        )
        assert result.exit_code == 0, result.output
        assert cli_payload(result)["hits"][0]["doc"] == "goal.md"


class TestCmakeProfileDefaults:
    @pytest.mark.parametrize("inside_project", [False, True])
    @pytest.mark.parametrize("explicit", [False, True])
    @pytest.mark.parametrize("dry_run", [False, True])
    def test_profile_precedence_and_artifact_json_shape(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        inside_project: bool,
        explicit: bool,
        dry_run: bool,
    ) -> None:
        from rebrew import cmake_tc

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            cmake_tc, "walk_up_to_root", lambda cwd: tmp_path if inside_project else None
        )
        loaded: list[Path] = []

        def _config(*, root: Path, json_mode: bool) -> SimpleNamespace:
            loaded.append(root)
            return SimpleNamespace(compiler_profile="gcc-14.2.0")

        monkeypatch.setattr(cmake_tc, "require_config", _config)
        monkeypatch.setattr(
            cmake_tc, "_resolve_spec", lambda name, **kw: SimpleNamespace(name=name)
        )

        def _generate(spec: SimpleNamespace, output: Path) -> Path:
            path = output / f"toolchain-{spec.name}-docker.cmake"
            path.parent.mkdir(parents=True)
            path.write_text("toolchain\n")
            return path

        monkeypatch.setattr(cmake_tc, "generate_toolchain_file", _generate)
        args = ["--json"]
        if explicit:
            args.extend(["--toolchain", "msvc-7.1"])
        if dry_run:
            args.append("--dry-run")
        result = CliRunner().invoke(cmake_tc.app, args)
        assert result.exit_code == 0, result.output
        expected = "msvc-7.1" if explicit else "gcc-14.2.0" if inside_project else "msvc-6.0"
        path = Path("cmake") / f"toolchain-{expected}-docker.cmake"
        assert cli_payload(result) == {
            "toolchain": expected,
            "output": str(path),
            "dry_run": dry_run,
        }
        assert path.exists() is not dry_run
        assert loaded == ([tmp_path] if inside_project and not explicit else [])


class _SelectionReached(Exception):
    """Stop before compiler, binary extraction, or upload side effects."""


class TestSourceSelectors:
    @pytest.mark.parametrize("module", ["drift_cli", "climb", "decompme"])
    @pytest.mark.parametrize("selector", ["second", "0x2000"])
    def test_symbol_or_va_selects_the_requested_function_in_a_shared_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module: str, selector: str
    ) -> None:
        owner = importlib.import_module(f"rebrew.{module}")
        src = tmp_path / "src"
        src.mkdir()
        source = src / "duo.c"
        write_source(
            source,
            "// ADDRESS: SERVER 0x1000\nint first(void) { return 1; }\n"
            "// ADDRESS: SERVER 0x2000\nint second(void) { int x; x = 2; return x; }\n",
            metadata_dir=tmp_path,
            metadata_fields={
                "SERVER.0x1000": {
                    "kind": "FUNCTION",
                    "symbol": "_first",
                    "name": "first",
                    "size": 4,
                },
                "SERVER.0x2000": {
                    "kind": "FUNCTION",
                    "symbol": "_second",
                    "name": "second",
                    "size": 8,
                },
            },
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path,
            module="SERVER",
            target_name="server",
            source_ext=".c",
            target_binary=tmp_path / "game.bin",
        )
        monkeypatch.setattr(owner, "require_config", lambda **kw: cfg)
        seen: dict = {}
        if module == "decompme":
            original = owner._resolve_annotation

            def _resolve(*args: object) -> object:
                ann, va, size, symbol = original(*args)
                seen.update(va=va, size=size, symbol=symbol)
                raise _SelectionReached

            monkeypatch.setattr(owner, "_resolve_annotation", _resolve)
        else:
            monkeypatch.setattr(owner, "resolve_compile_overrides", lambda *a: (None, ""))

            def _extract(binary: Path, va: int, size: int) -> bytes:
                seen.update(va=va, size=size)
                raise _SelectionReached

            monkeypatch.setattr(owner, "extract_raw_bytes", _extract)
        result = CliRunner().invoke(owner.app, ["--json", selector])
        assert isinstance(result.exception, _SelectionReached), (result.output, result.exception)
        assert seen["va"] == 0x2000
        assert seen["size"] == 8
        if module == "decompme":
            assert seen["symbol"] == "_second"
        assert source.read_text().count("return") == 2


def test_cmake_does_not_substitute_msvc_for_an_unsupported_project_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rebrew import cmake_tc

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cmake_tc, "walk_up_to_root", lambda cwd: tmp_path)
    monkeypatch.setattr(
        cmake_tc, "require_config", lambda **kw: SimpleNamespace(compiler_profile="gcc-14.2.0")
    )
    result = CliRunner().invoke(cmake_tc.app, ["--dry-run", "--json"])
    assert result.exit_code == 2, result.output
    assert "gcc-14.2.0" in cli_payload(result)["error"]
    assert not (tmp_path / "cmake").exists()
