"""Tests for SDK and library surface usability, exports, and convenience methods."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import rebrew
from rebrew.compile import CompareResult
from rebrew.config import (
    ConfigError,
    ProjectConfig,
    find_root,
    is_key_safe_endpoint,
    load_config,
    validate_http_url,
    validate_llm_model,
)
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
        from rebrew.compile import compile_and_compare
        from rebrew.toolchain import ToolchainError, get_toolchain

        assert rebrew.load_config is load_config
        assert rebrew.ConfigError is ConfigError
        assert rebrew.RebrewError is RebrewError
        assert rebrew.ProjectConfig is ProjectConfig
        assert rebrew.CompareResult is CompareResult
        assert rebrew.compile_and_compare is compile_and_compare
        assert rebrew.ToolchainError is ToolchainError
        assert rebrew.get_toolchain is get_toolchain
        assert rebrew.iter_sources is iter_sources
        assert rebrew.iter_library_headers is iter_library_headers

    def test_top_level_lazy_exports_snapshot(self) -> None:
        """Gating: prevent accidental dropping or renaming of top-level exports."""
        expected = {
            "CompareResult",
            "ConfigError",
            "ProjectConfig",
            "RebrewError",
            "ToolchainError",
            "compile_and_compare",
            "get_toolchain",
            "iter_library_headers",
            "iter_sources",
            "load_config",
        }
        assert set(rebrew._LAZY_EXPORTS.keys()) == expected

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
        from rebrew.toolchain import ToolchainError

        assert err_mod.ConfigError is ConfigError
        assert err_mod.ToolchainError is ToolchainError
        assert err_mod.DecompmeError is DecompmeError
        assert issubclass(err_mod.DecompmeError, RebrewError)
        assert issubclass(err_mod.DecompmeError, RuntimeError)
        assert issubclass(err_mod.ToolchainError, RebrewError)

    def test_lazy_errors_snapshot(self) -> None:
        """Gating: prevent accidental removal of lazy error exports."""
        import rebrew.errors as err_mod

        expected = {
            "ConfigError",
            "ConfigNotFoundError",
            "ConfigKeyError",
            "DecompmeError",
            "McpApplyAborted",
            "McpError",
            "MetadataValidationError",
            "RecompileError",
            "RegistryError",
            "ToolchainError",
            "WorkspaceNotFound",
        }
        assert set(err_mod._LAZY_ERRORS.keys()) == expected

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

    def test_compare_result_from_dict_roundtrip(self) -> None:
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
        restored = CompareResult.from_dict(d)
        assert restored.matched is True
        assert restored.status == "EXACT"
        assert restored.match_percent == 100.0
        assert restored.delta == 0
        assert restored.match_count == 2
        assert restored.reloc_offsets == [0]
        assert restored.obj_bytes is None

    def test_compare_result_from_dict_extra_fields(self) -> None:
        d = {
            "matched": False,
            "status": "NEAR_MATCHING",
            "match_percent": 80.0,
            "delta": 4,
            "unknown_extra_field": "ignore me",
        }
        res = CompareResult.from_dict(d)
        assert res.matched is False
        assert res.status == "NEAR_MATCHING"
        assert res.delta == 4
        assert res.match_percent == 80.0


class TestProjectConfigValidation:
    def test_validate_valid_config(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(
            root=tmp_path,
            compiler_profile="msvc-6.0",
            arch="x86_32",
            recompile_url="http://localhost:8080",
            llm_endpoint="http://localhost:11434/v1",
            llm_model="qwen-2.5-coder",
            llm_api_key="sk-test",
        )
        assert cfg.validate() is None
        assert cfg.compiler_profile == "msvc-6.0"
        assert cfg.arch == "x86_32"

    def test_validate_unknown_arch_raises(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path, arch="mips_64")
        with pytest.raises(ConfigError, match="unknown arch 'mips_64'"):
            cfg.validate()

    def test_validate_unknown_profile_raises(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path, compiler_profile="unknown-compiler-9.9")
        with pytest.raises(ConfigError, match="unknown profile 'unknown-compiler-9.9'"):
            cfg.validate()

    def test_validate_invalid_recompile_url_raises(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path, recompile_url="ftp://invalid")
        with pytest.raises(ConfigError, match="compiler.recompile_url must be an http"):
            cfg.validate()

    def test_validate_invalid_llm_endpoint_raises(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path, llm_endpoint="invalid://endpoint")
        with pytest.raises(ConfigError, match="llm.endpoint must be an http"):
            cfg.validate()

    def test_validate_unpinned_llm_model_raises(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path, llm_model="latest")
        with pytest.raises(ConfigError, match="unpinned alias"):
            cfg.validate()

    def test_validate_llm_api_key_on_insecure_remote_http_raises(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(
            root=tmp_path,
            llm_endpoint="http://remote.api.com/v1",
            llm_api_key="secret-key",
        )
        with pytest.raises(ConfigError, match="LLM endpoint must use https when an API key is set"):
            cfg.validate()

    def test_project_config_to_dict_matches_as_dict(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path)
        assert cfg.to_dict() == cfg.as_dict()

    def test_project_config_coerces_str_paths(self) -> None:
        cfg = ProjectConfig(
            root="/tmp/project",
            target_binary="bin/game.exe",
            reversed_dir="src/game",
            shared_dir="src/shared",
            bin_dir="bin",
            db_dir=".rebrew",
            output_dir="out",
            compiler_includes="include",
            compiler_libs="lib",
        )
        assert isinstance(cfg.root, Path)
        assert isinstance(cfg.target_binary, Path)
        assert isinstance(cfg.reversed_dir, Path)
        assert isinstance(cfg.shared_dir, Path)
        assert isinstance(cfg.bin_dir, Path)
        assert isinstance(cfg.db_dir, Path)
        assert isinstance(cfg.output_dir, Path)
        assert isinstance(cfg.compiler_includes, Path)
        assert isinstance(cfg.compiler_libs, Path)


class TestUrlAndModelValidation:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("http://localhost:8080", "http://localhost:8080"),
            ("https://api.example.com/v1", "https://api.example.com/v1"),
            ("  http://example.com/path  ", "http://example.com/path"),
            ("", ""),
            ("   ", ""),
        ],
    )
    def test_validate_http_url_valid(self, url: str, expected: str) -> None:
        assert validate_http_url(url, "test_field") == expected

    @pytest.mark.parametrize(
        "bad_url",
        [
            "ftp://example.com",
            "http:///no-host",
            "http://example.com:99999",
            "http://example.com:0",
            "http://example .com",
            "http://example.com/path\x00evil",
        ],
    )
    def test_validate_http_url_invalid(self, bad_url: str) -> None:
        with pytest.raises(ConfigError, match="test_field must be an http"):
            validate_http_url(bad_url, "test_field")

    @pytest.mark.parametrize(
        ("endpoint", "safe"),
        [
            ("https://remote-api.com/v1", True),
            ("http://localhost:11434", True),
            ("http://127.0.0.1:8000", True),
            ("http://[::1]:8000", True),
            ("http://remote-api.com/v1", False),
            ("http://192.168.1.1:8000", False),
            ("not-a-url", False),
        ],
    )
    def test_is_key_safe_endpoint(self, endpoint: str, safe: bool) -> None:
        assert is_key_safe_endpoint(endpoint) is safe

    @pytest.mark.parametrize(
        "model",
        [
            "gpt-4o",
            "claude-3-5-sonnet-20241022",
            "qwen-2.5-coder:32b",
            "meta-llama/Llama-3-70b-chat",
        ],
    )
    def test_validate_llm_model_valid(self, model: str) -> None:
        assert validate_llm_model(model) == model

    @pytest.mark.parametrize("unpinned", ["latest", "auto", "default", "LATEST", "Auto"])
    def test_validate_llm_model_unpinned_rejected(self, unpinned: str) -> None:
        with pytest.raises(ConfigError, match="unpinned alias"):
            validate_llm_model(unpinned)

    @pytest.mark.parametrize("bad_name", ["", "model with spaces", "bad$character", "a" * 129])
    def test_validate_llm_model_invalid_characters_rejected(self, bad_name: str) -> None:
        with pytest.raises(ConfigError, match="invalid characters or length"):
            validate_llm_model(bad_name)


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
            client=FakeClient(),
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


class TestMetadataConvenience:
    def test_metadata_accepts_str_and_config(self, tmp_path: Path) -> None:
        from rebrew.metadata import (
            get_entry,
            load_metadata,
            metadata_path,
            save_metadata,
            update_field,
        )

        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path / "src" / "game")
        cfg.metadata_dir.mkdir(parents=True, exist_ok=True)

        # metadata_path
        assert metadata_path(str(cfg.metadata_dir)) == cfg.metadata_dir / "rebrew-functions.toml"
        assert metadata_path(cfg) == cfg.metadata_dir / "rebrew-functions.toml"

        # save and load with str
        save_metadata(str(cfg.metadata_dir), {("SERVER", 0x1000): {"size": 32}})
        loaded = load_metadata(str(cfg.metadata_dir))
        assert ("SERVER", 0x1000) in loaded

        # load and get_entry with config
        loaded_cfg = load_metadata(cfg)
        assert ("SERVER", 0x1000) in loaded_cfg
        entry = get_entry(cfg, 0x1000, "SERVER")
        assert entry["size"] == 32

        # update_field with str
        update_field(str(cfg.metadata_dir), 0x1000, "note", "test note", module="SERVER")
        assert get_entry(cfg, 0x1000, "SERVER")["note"] == "test note"

    def test_data_metadata_accepts_str_and_config(self, tmp_path: Path) -> None:
        from rebrew.data_metadata import (
            get_data_entry,
            load_data_metadata,
            set_data_field,
        )

        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path / "src" / "game")
        cfg.metadata_dir.mkdir(parents=True, exist_ok=True)

        # set with str
        set_data_field(str(cfg.metadata_dir), 0x2000, "size", 64, module="SERVER")

        # load with config
        data = load_data_metadata(cfg)
        assert ("SERVER", 0x2000) in data
        assert data[("SERVER", 0x2000)]["size"] == 64

        # get with str
        entry = get_data_entry(str(cfg.metadata_dir), 0x2000, "SERVER")
        assert entry["size"] == 64


class TestGhidraClientInjection:
    def test_apply_commands_via_mcp_accepts_client(self) -> None:
        from rebrew.ghidra.client import apply_commands_via_mcp

        class FakeMcpClient:
            def __init__(self) -> None:
                self.calls: list[str] = []

            def post(self, url: str, **kwargs: object) -> object:
                self.calls.append(url)
                return SimpleNamespace(
                    status_code=200,
                    headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
                    json=lambda: {
                        "jsonrpc": "2.0",
                        "result": {"content": [{"type": "text", "text": "ok"}]},
                    },
                    text='{"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": "ok"}]}}',
                    raise_for_status=lambda: None,
                    close=lambda: None,
                )

            def delete(self, url: str, **kwargs: object) -> object:
                return SimpleNamespace(status_code=200, close=lambda: None)

        fake = FakeMcpClient()
        cmd = {"tool": "create-function", "args": {"address": "0x1000"}}
        success, errors = apply_commands_via_mcp([cmd], client=fake)  # type: ignore[arg-type]
        assert success == 1
        assert errors == 0
        assert len(fake.calls) >= 2  # init + command
