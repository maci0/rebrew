"""Tests for SDK and library surface usability, exports, and convenience methods."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import rebrew
from rebrew.compile import CompareResult
from rebrew.config import ConfigError, ProjectConfig, find_root, load_config
from rebrew.decompme import DecompmeError
from rebrew.errors import RebrewError
from rebrew.recompile_client import compile_source
from rebrew.sources import iter_library_headers, iter_sources
from rebrew.workspace.config import find_root as workspace_find_root
from rebrew.workspace.config import read_config as workspace_read_config


class TestTopLevelPackageExports:
    def test_top_level_package_all(self) -> None:
        assert rebrew.__all__ == ["__version__"]
        assert isinstance(rebrew.__version__, str)

    def test_top_level_lazy_attribute_access(self) -> None:
        assert rebrew.load_config is load_config
        assert rebrew.RebrewError is RebrewError
        assert rebrew.ProjectConfig is ProjectConfig
        assert rebrew.CompareResult is CompareResult
        assert rebrew.iter_sources is iter_sources
        assert rebrew.iter_library_headers is iter_library_headers

    def test_top_level_dir_includes_lazy_exports(self) -> None:
        d = dir(rebrew)
        assert "load_config" in d
        assert "RebrewError" in d
        assert "CompareResult" in d
        assert "__version__" in d

    def test_top_level_unknown_attribute_raises(self) -> None:
        with pytest.raises(AttributeError, match="has no attribute 'nonexistent_symbol'"):
            _ = rebrew.nonexistent_symbol


class TestErrorsLazyExports:
    def test_lazy_error_imports(self) -> None:
        import rebrew.errors as err_mod

        assert err_mod.ConfigError is ConfigError
        assert err_mod.DecompmeError is DecompmeError
        assert issubclass(err_mod.DecompmeError, RebrewError)
        assert issubclass(err_mod.DecompmeError, RuntimeError)

    def test_errors_dir_and_all(self) -> None:
        import rebrew.errors as err_mod

        d = dir(err_mod)
        assert "ConfigError" in d
        assert "DecompmeError" in d
        assert err_mod.__all__ == ["RebrewError"]

    def test_errors_unknown_attribute_raises(self) -> None:
        import rebrew.errors as err_mod

        with pytest.raises(AttributeError, match="has no attribute 'NonExistentError'"):
            _ = err_mod.NonExistentError


class TestSourcesConvenience:
    def test_iter_sources_accepts_str(self, tmp_path: Path) -> None:
        src = tmp_path / "foo.c"
        src.write_text("int foo(void) { return 1; }\n", encoding="utf-8")
        found = iter_sources(str(tmp_path))
        assert found == [src]

    def test_iter_sources_accepts_cfg_shorthand(self, tmp_path: Path) -> None:
        src = tmp_path / "foo.c"
        src.write_text("int foo(void) { return 1; }\n", encoding="utf-8")
        cfg = SimpleNamespace(reversed_dir=tmp_path, source_ext=".c")
        found = iter_sources(cfg)  # type: ignore[arg-type]
        assert found == [src]

    def test_iter_library_headers_accepts_str(self, tmp_path: Path) -> None:
        hdr = tmp_path / "library_foo.h"
        hdr.write_text("// LIBRARY:\n", encoding="utf-8")
        found = iter_library_headers(str(tmp_path))
        assert found == [hdr]

    def test_iter_library_headers_accepts_cfg_shorthand(self, tmp_path: Path) -> None:
        hdr = tmp_path / "library_foo.h"
        hdr.write_text("// LIBRARY:\n", encoding="utf-8")
        cfg = SimpleNamespace(reversed_dir=tmp_path)
        found = iter_library_headers(cfg)  # type: ignore[arg-type]
        assert found == [hdr]


class TestConfigStringPaths:
    def test_workspace_find_root_accepts_str(self, tmp_path: Path) -> None:
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text("[project]\nname = 'test'\n", encoding="utf-8")
        found = workspace_find_root(str(tmp_path))
        assert found == tmp_path.resolve()

    def test_workspace_read_config_accepts_str(self, tmp_path: Path) -> None:
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text("[project]\nname = 'test'\n", encoding="utf-8")
        cfg_dict = workspace_read_config(str(tmp_path))
        assert cfg_dict["project"]["name"] == "test"

    def test_config_find_root_accepts_str(self, tmp_path: Path) -> None:
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text("[project]\nname = 'test'\n", encoding="utf-8")
        found = find_root(str(tmp_path))
        assert found == tmp_path

    def test_load_config_accepts_str_root(self, tmp_path: Path) -> None:
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text(
            """[project]
name = "demo"
default_target = "game"

[compiler]
profile = "msvc-6.0"

[targets.game]
binary = "game.exe"
reversed_dir = "src/game"
""",
            encoding="utf-8",
        )
        (tmp_path / "game.exe").write_bytes(b"\x00")
        (tmp_path / "src" / "game").mkdir(parents=True)
        cfg = load_config(root=str(tmp_path))
        assert cfg.project_name == "demo"


class TestCompareResultHelpers:
    def test_compare_result_to_dict(self) -> None:
        res = CompareResult(
            matched=True,
            status="EXACT",
            match_percent=100.0,
            delta=0,
            obj_bytes=b"\x90\x90",
            reloc_offsets=[0],
            message="all matched",
            match_count=2,
        )
        d = res.to_dict()
        assert d["matched"] is True
        assert d["status"] == "EXACT"
        assert d["match_percent"] == 100.0
        assert d["delta"] == 0
        assert d["match_count"] == 2
        assert d["reloc_offsets"] == [0]
        assert "obj_bytes" not in d  # raw bytes not dumped in dictionary summary


class TestProjectConfigValidation:
    def test_validate_valid_config(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path, compiler_profile="msvc-6.0", arch="x86_32")
        cfg.validate()  # should not raise

    def test_validate_unknown_arch_raises(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path, arch="mips_64")
        with pytest.raises(ConfigError, match="unknown arch 'mips_64'"):
            cfg.validate()

    def test_validate_unknown_profile_raises(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path, compiler_profile="unknown-compiler-9.9")
        with pytest.raises(ConfigError, match="unknown profile 'unknown-compiler-9.9'"):
            cfg.validate()


class TestRecompileClientFlagsFlexibility:
    def test_compile_source_accepts_string_flags(self) -> None:
        captured: dict[str, object] = {}

        class FakeClient:
            def post(self, url: str, *, json: object = None) -> object:
                captured["url"] = url
                captured["json"] = json
                return SimpleNamespace(
                    status_code=200,
                    json=lambda: {"status": "error", "log": "compiled"},
                    close=lambda: None,
                )

            def get(self, url: str) -> object:
                return SimpleNamespace(status_code=200, content=b"", text="", close=lambda: None)

        res = compile_source(
            base_url="http://localhost:8000",
            compiler="msvc-6.0",
            source="int x = 1;",
            flags="/O2 /nologo",
            client=FakeClient(),  # type: ignore[arg-type]
        )
        assert res.ok is False
        assert captured["json"]["flags"] == ["/O2", "/nologo"]  # type: ignore[index]


class TestDecompmeError:
    def test_error_attributes_and_hierarchy(self) -> None:
        err = DecompmeError("bad slug", kind="protocol", status_code=400, retryable=False)
        assert isinstance(err, RebrewError)
        assert isinstance(err, RuntimeError)
        assert err.kind == "protocol"
        assert err.status_code == 400
        assert err.retryable is False
