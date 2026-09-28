"""Tests for SDK and library surface usability, exports, and convenience methods."""

from __future__ import annotations

import ast
import importlib
import importlib.util
import inspect
import json
import pkgutil
import re
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import rebrew
from rebrew.compile import CompareResult, CompareStatus
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

ROOT = Path(__file__).resolve().parents[1]


class TestTopLevelPackageExports:
    def test_top_level_package_all(self) -> None:
        assert rebrew.__all__ == ["__version__", *sorted(rebrew._LAZY_EXPORTS)]
        assert isinstance(rebrew.__version__, str)

    def test_top_level_lazy_attribute_access(self) -> None:
        from rebrew.compile import compile_and_compare
        from rebrew.toolchain import ToolchainError, get_toolchain

        assert rebrew.load_config is load_config
        assert rebrew.ConfigError is ConfigError
        assert rebrew.RebrewError is RebrewError
        assert rebrew.ProjectConfig is ProjectConfig
        assert rebrew.CompareResult is CompareResult
        assert rebrew.CompareStatus is CompareStatus
        assert rebrew.compile_and_compare is compile_and_compare
        assert rebrew.ToolchainError is ToolchainError
        assert rebrew.get_toolchain is get_toolchain
        assert rebrew.iter_sources is iter_sources
        assert rebrew.iter_library_headers is iter_library_headers

    def test_top_level_lazy_exports_snapshot(self) -> None:
        """Gating: prevent accidental dropping or renaming of top-level exports."""
        expected = {
            "CompareResult",
            "CompareStatus",
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
        """Gating: prevent accidental removal of lazy error exports.

        The expected set is the module's own surface from 2.14.0 on, when
        ``__all__`` was widened to name every lazy export
        (``tests/test_errors.py::test_all_covers_every_lazy_export`` pins it to
        ``_LAZY_ERRORS`` / ``_LAZY_ERROR_KINDS``); this literal stays an
        independent copy so a removal on either side fails a test.
        """
        import rebrew.errors as err_mod

        expected = {
            "CatalogScanError",
            "CompareResultError",
            "ComponentError",
            "ConfigError",
            "ConfigKeyError",
            "ConfigNotFoundError",
            "DecompmeError",
            "Delphi16Error",
            "DosboxError",
            "FingerprintError",
            "LibraryOverrideError",
            "McpApplyAborted",
            "McpError",
            "MetadataValidationError",
            "Msvc16Error",
            "NeParseError",
            "NoDecompilationError",
            "NotLzexeError",
            "Omf16Error",
            "OrphanInventoryError",
            "RecompileError",
            "RegistryError",
            "RenameError",
            "ResidueError",
            "SimilarityUnavailable",
            "Tc16Error",
            "ToolchainError",
            "UnresolvedSymbolError",
            "WorkspaceConfigError",
            "WorkspaceNotFound",
        }
        assert set(err_mod._LAZY_ERRORS.keys()) == expected

    def test_errors_dir_and_all(self) -> None:
        """``__all__`` is the declared star-import surface, not the 5 aliases.

        2.14.0 widened it to every lazy export: a star-import or docs
        generator reading it saw 5 of the 32 names the module documents as
        importable from this one place.  The literal below mirrors
        ``rebrew.errors.__all__`` so narrowing it again is a test failure.
        """
        import rebrew.errors as err_mod

        d = dir(err_mod)
        assert "ConfigError" in d
        assert "DecompmeError" in d
        assert err_mod.__all__ == [
            "CatalogScanError",
            "CompareResultError",
            "ComponentError",
            "ConfigError",
            "ConfigKeyError",
            "ConfigNotFoundError",
            "DecompmeError",
            "DecompmeErrorKind",
            "Delphi16Error",
            "DosboxError",
            "FingerprintError",
            "LibraryOverrideError",
            "McpApplyAborted",
            "McpError",
            "McpErrorKind",
            "MetadataValidationError",
            "Msvc16Error",
            "NeParseError",
            "NoDecompilationError",
            "NotLzexeError",
            "Omf16Error",
            "OrphanInventoryError",
            "RebrewError",
            "RecompileError",
            "RecompileErrorKind",
            "RegistryError",
            "RenameError",
            "ResidueError",
            "SimilarityUnavailable",
            "Tc16Error",
            "ToolchainError",
            "ToolchainErrorKind",
            "UnresolvedSymbolError",
            "WorkspaceConfigError",
            "WorkspaceNotFound",
        ]

    def test_error_kind_aliases_import_from_rebrew_errors(self) -> None:
        """Branching on ``exc.kind`` needs its alias from the same place."""
        import importlib

        import rebrew.errors as err_mod
        from rebrew.ghidra.client import McpErrorKind
        from rebrew.toolchain import ToolchainErrorKind

        assert err_mod.McpErrorKind is McpErrorKind
        assert err_mod.ToolchainErrorKind is ToolchainErrorKind
        for name, (module_name, attr) in err_mod._LAZY_ERROR_KINDS.items():
            assert getattr(err_mod, name) is getattr(importlib.import_module(module_name), attr)
            assert name in dir(err_mod)

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

    def test_compare_result_from_dict_missing_required_field_raises_rebrew_error(self) -> None:
        from rebrew.compile import CompareResultError

        with pytest.raises(CompareResultError) as excinfo:
            CompareResult.from_dict({"matched": False, "status": "EXACT", "delta": 0})
        assert "from_dict" in str(excinfo.value)

    def test_compare_result_from_dict_unknown_status_raises_rebrew_error(self) -> None:
        from rebrew.compile import CompareResultError

        with pytest.raises(CompareResultError) as excinfo:
            CompareResult.from_dict(
                {
                    "matched": False,
                    "status": "MOSTLY_MATCHED",
                    "match_percent": 90.0,
                    "delta": 1,
                }
            )
        assert "MOSTLY_MATCHED" in str(excinfo.value)

    def test_unbuildable_payload_is_caught_by_one_rebrew_error_clause(self) -> None:
        try:
            CompareResult.from_dict({"status": "EXACT"})
        except RebrewError:
            return
        pytest.fail("an unbuildable payload escaped the RebrewError handler")


class TestErrorStructuredRoundTrip:
    """A persisted failure must still be branchable after a JSON round trip."""

    @staticmethod
    def _failed_result() -> CompareResult:
        from rebrew.recompile_client import RecompileError

        return CompareResult(
            matched=False,
            status="COMPILE_ERROR",
            match_percent=0.0,
            delta=0,
            obj_bytes=None,
            reloc_offsets=None,
            message="compile service unreachable",
            error=RecompileError("connect error", kind="network", status_code=None, retryable=True),
        )

    def test_to_dict_serializes_the_structured_error(self) -> None:
        payload = self._failed_result().to_dict()
        assert payload["error"] == {
            "type": "RecompileError",
            "message": "connect error",
            "retryable": True,
            "kind": "network",
        }

    def test_to_dict_error_is_json_serializable(self) -> None:
        assert json.loads(json.dumps(self._failed_result().to_dict()))["error"]["kind"] == "network"

    def test_from_dict_restores_the_error_type_and_fields(self) -> None:
        from rebrew.recompile_client import RecompileError

        restored = CompareResult.from_dict(json.loads(json.dumps(self._failed_result().to_dict())))
        assert isinstance(restored.error, RecompileError)
        assert restored.error is not None
        assert restored.error.retryable is True
        assert restored.error.kind == "network"
        assert str(restored.error) == "connect error"

    def test_to_dict_error_none_round_trips_as_none(self) -> None:
        restored = CompareResult.from_dict(self._failed_result().to_dict())
        assert restored.error is not None
        restored.error = None
        assert CompareResult.from_dict(restored.to_dict()).error is None

    def test_unknown_error_type_degrades_to_the_base_class(self) -> None:
        payload = self._failed_result().to_dict()
        payload["error"]["type"] = "ErrorFromANewerRebrew"
        restored = CompareResult.from_dict(payload)
        assert type(restored.error) is RebrewError
        assert restored.error is not None
        assert restored.error.retryable is True

    def test_non_mapping_error_raises_a_rebrew_error(self) -> None:
        from rebrew.compile import CompareResultError

        payload = self._failed_result().to_dict()
        payload["error"] = "connect error"
        with pytest.raises(CompareResultError) as excinfo:
            CompareResult.from_dict(payload)
        assert "error" in str(excinfo.value)

    def test_error_to_dict_from_dict_round_trip_keeps_structured_fields(self) -> None:
        from rebrew.recompile_client import RecompileError

        exc = RecompileError("503", kind="http", status_code=503, retryable=True)
        rebuilt = RebrewError.from_dict(exc.to_dict())
        assert isinstance(rebuilt, RecompileError)
        assert rebuilt.status_code == 503
        assert rebuilt.retryable is True
        assert str(rebuilt) == "503"


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


class TestRecompileResultSerialization:
    """The remote-compile verdict serializes like the local one does."""

    def test_round_trip_keeps_the_verdict_and_drops_the_bytes(self) -> None:
        from rebrew.recompile_client import RecompileResult

        res = RecompileResult(ok=True, obj_bytes=b"\x90\x90", log="ok", compiler_version="6.0")
        payload = res.to_dict()
        assert "obj_bytes" not in payload
        assert json.loads(json.dumps(payload)) == {
            "ok": True,
            "log": "ok",
            "compiler_version": "6.0",
        }
        restored = RecompileResult.from_dict(payload)
        assert restored.ok is True
        assert restored.log == "ok"
        assert restored.compiler_version == "6.0"
        assert restored.obj_bytes is None

    def test_failed_result_round_trips(self) -> None:
        from rebrew.recompile_client import RecompileResult

        res = RecompileResult(ok=False, log="C2065: syntax error")
        assert RecompileResult.from_dict(res.to_dict()) == res

    def test_missing_ok_raises_a_rebrew_error(self) -> None:
        from rebrew.recompile_client import RecompileError, RecompileResult

        with pytest.raises(RecompileError) as excinfo:
            RecompileResult.from_dict({"log": "ok"})
        assert excinfo.value.kind == "protocol"


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
        from rebrew.ghidra.client import McpResponse, apply_commands_via_mcp

        ok_body = '{"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": "ok"}]}}'

        class FakeResponse:
            """A reply shaped like the five fields rebrew reads off a response."""

            def __init__(self, body: str) -> None:
                self.status_code = 200
                self.headers = {"content-type": "application/json", "mcp-session-id": "sess-1"}
                self.text = body

            def json(self) -> object:
                return json.loads(self.text)

            def raise_for_status(self) -> None:
                return None

            def close(self) -> None:
                return None

        class FakeMcpClient:
            def __init__(self) -> None:
                self.calls: list[str] = []

            def post(self, url: str, **kwargs: object) -> McpResponse:
                self.calls.append(url)
                return FakeResponse(ok_body)

            def delete(self, url: str, **kwargs: object) -> McpResponse:
                return FakeResponse("")

        fake = FakeMcpClient()
        cmd = {"tool": "create-function", "args": {"address": "0x1000"}}
        # No ``# type: ignore``: the stand-in is typed against the same
        # protocol the implementation calls, so the injection point checks.
        result = apply_commands_via_mcp([cmd], client=fake)
        # Both counts are ints: a named record keeps a transposition visible,
        # and the 2-tuple form above still destructures.
        success, errors = result
        assert success == 1
        assert errors == 0
        assert (result.success, result.errors) == (1, 0)
        assert len(fake.calls) >= 2  # init + command


class TestDocumentedLibrarySurface:
    """Every import a doc shows must resolve against the shipped package.

    The README's Library usage block and the ``rebrew`` package docstring are
    the only map a consumer has of the import surface.  A module move or a
    rename that leaves them behind is a broken quickstart, not a stale
    sentence, so the docs are walked the way a reader would.
    """

    _IMPORT_RE = re.compile(r"(?m)^[ \t]*from[ \t]+(rebrew[\w.]*)[ \t]+import[ \t]+([^\n#]+)")
    #: Parenthesized form (``from rebrew.x import (a, b)``), which the
    #: single-line pattern above cannot read the names out of.
    _PAREN_IMPORT_RE = re.compile(
        r"(?ms)^[ \t]*from[ \t]+(rebrew[\w.]*)[ \t]+import[ \t]+\(([^)]*)\)"
    )
    #: Zero dotted segments too, so a bare ``rebrew`` in the package
    #: docstring is checked like every ``rebrew.x`` beside it.
    _MODULE_RE = re.compile(r"`(rebrew(?:\.[a-z_][a-z_0-9]*)*)`")

    def _doc_paths(self) -> list[Path]:
        return [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]

    def test_documented_imports_resolve(self) -> None:
        missing: list[str] = []
        checked = 0
        for path in self._doc_paths():
            text = path.read_text(encoding="utf-8")
            pairs = list(self._IMPORT_RE.findall(text)) + list(self._PAREN_IMPORT_RE.findall(text))
            for mod_name, raw in pairs:
                mod = importlib.import_module(mod_name)
                for name in raw.replace("(", "").replace(")", "").split(","):
                    name = name.partition(" as ")[0].strip()
                    if not name.isidentifier():
                        continue
                    checked += 1
                    if not hasattr(mod, name):
                        missing.append(f"{path.name}: from {mod_name} import {name}")
        assert checked >= 8, f"only {checked} documented imports found; the regex drifted"
        assert missing == [], "documented imports do not exist: " + ", ".join(missing)

    def test_documented_modules_exist(self) -> None:
        """Every ``rebrew.x`` the README and package docstring name is importable."""
        sources = {"README.md": (ROOT / "README.md").read_text(encoding="utf-8")}
        sources["rebrew/__init__.py"] = rebrew.__doc__ or ""
        missing: list[str] = []
        for label, text in sources.items():
            for name in sorted(set(self._MODULE_RE.findall(text))):
                if importlib.util.find_spec(name) is None:
                    missing.append(f"{label}: {name}")
        assert missing == [], "documented modules do not exist: " + ", ".join(missing)


class TestPublicFailuresAreRecoverable:
    """Every public failure a consumer can hit is a ``RebrewError``.

    The README tells an embedding program that one ``except RebrewError``
    clause covers whatever rebrew raises.  A bare ``RuntimeError`` /
    ``ValueError`` from a public entry point escapes that handler, so both
    are pinned here.
    """

    def test_contradictory_compare_result_raises_a_rebrew_error(self) -> None:
        from rebrew.compile import CompareResultError
        from rebrew.errors import CompareResultError as ExportedError

        assert ExportedError is CompareResultError
        assert issubclass(CompareResultError, RebrewError)
        assert issubclass(CompareResultError, ValueError)

        with pytest.raises(CompareResultError) as excinfo:
            CompareResult(
                matched=True,
                status="STUB",
                match_percent=12.0,
                delta=40,
                obj_bytes=None,
                reloc_offsets=None,
            )
        # Branch on the fields, not on the message text.
        assert (excinfo.value.matched, excinfo.value.status) == (True, "STUB")

    def test_one_except_clause_catches_a_contradictory_result(self) -> None:
        try:
            CompareResult(
                matched=False,
                status="EXACT",
                match_percent=0.0,
                delta=0,
                obj_bytes=None,
                reloc_offsets=None,
            )
        except RebrewError:
            return
        pytest.fail("contradictory CompareResult escaped the RebrewError handler")

    def test_missing_resembl_raises_a_rebrew_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A missing optional extra is a rebrew failure, not a bare RuntimeError.

        ``None`` in ``sys.modules`` makes the guarded import raise
        ``ImportError``, which is the branch the real uninstalled install
        takes; the test therefore runs whether or not ``resembl`` is present.
        """
        from rebrew.errors import SimilarityUnavailable
        from rebrew.matcher.scoring import code_similarity

        assert issubclass(SimilarityUnavailable, RebrewError)
        monkeypatch.setitem(sys.modules, "rapidfuzz", None)
        monkeypatch.setitem(sys.modules, "resembl.scoring", None)
        with pytest.raises(SimilarityUnavailable):
            code_similarity(b"\x90\x90", b"\x90\x90\x90")


class TestMatcherLazyExportsStayTyped:
    """``rebrew.matcher``'s lazy names must be typed for consumers.

    Without the ``if TYPE_CHECKING`` mirror, a consumer type-checking
    ``from rebrew.matcher import build_candidate`` gets ``Any`` back from
    ``__getattr__`` in a py.typed package.
    """

    def _type_checking_imports(self) -> set[str]:
        import rebrew.matcher as matcher_mod

        source = Path(matcher_mod.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        names: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.If) or not isinstance(node.test, ast.Name):
                continue
            if node.test.id != "TYPE_CHECKING":
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.ImportFrom):
                    for alias in stmt.names:
                        names.add(alias.asname or alias.name)
        return names

    def test_every_lazy_export_has_a_type_checking_re_export(self) -> None:
        import rebrew.matcher as matcher_mod

        assert self._type_checking_imports() == set(matcher_mod._LAZY_EXPORTS)

    def test_lazy_export_resolves_to_the_typed_attribute(self) -> None:
        import rebrew.matcher as matcher_mod
        from rebrew.matcher.compiler import build_candidate

        assert matcher_mod.build_candidate is build_candidate


class TestGhidraLazyExportsStayTyped:
    """``rebrew.ghidra``'s lazy names must be typed and resolvable.

    Same contract as the matcher facade: a consumer type-checking
    ``from rebrew.ghidra import fetch_mcp_tool_raw`` gets the real signature,
    and every name the facade advertises resolves to the attribute its owning
    submodule defines.
    """

    def _type_checking_imports(self) -> set[str]:
        import rebrew.ghidra as ghidra_mod

        source = Path(ghidra_mod.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        names: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.If) or not isinstance(node.test, ast.Name):
                continue
            if node.test.id != "TYPE_CHECKING":
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.ImportFrom):
                    for alias in stmt.names:
                        names.add(alias.asname or alias.name)
        return names

    def test_every_lazy_export_has_a_type_checking_re_export(self) -> None:
        import rebrew.ghidra as ghidra_mod

        assert self._type_checking_imports() == set(ghidra_mod._LAZY_EXPORTS)

    def test_all_matches_the_lazy_exports(self) -> None:
        import rebrew.ghidra as ghidra_mod

        assert ghidra_mod.__all__ == sorted(ghidra_mod._LAZY_EXPORTS)

    def test_lazy_export_resolves_to_the_defining_submodule(self) -> None:
        import rebrew.ghidra as ghidra_mod
        from rebrew.ghidra.client import fetch_mcp_tool_raw

        assert ghidra_mod.fetch_mcp_tool_raw is fetch_mcp_tool_raw

    def test_reads_through_to_a_swapped_submodule_attribute(self, monkeypatch) -> None:
        """A transport stand-in swapped in on the submodule is seen by the facade."""
        import rebrew.ghidra as ghidra_mod
        import rebrew.ghidra.client as client_mod

        sentinel = object()
        monkeypatch.setattr(client_mod, "init_mcp_session", sentinel)
        assert ghidra_mod.init_mcp_session is sentinel


class TestDocumentedTransportInjection:
    """The README's fake-service snippet must work as written.

    The library-usage section tells a consumer that a stand-in taking
    ``**kwargs`` satisfies both ``HttpClient`` protocols and drives a remote
    compile with no live service.  A protocol that grew a required keyword,
    or a call that stopped passing the payload as ``json=``, would leave the
    documented quickstart broken, so the snippet's own shape is pinned here.
    """

    def test_kwargs_fake_satisfies_both_client_protocols(self) -> None:
        from rebrew.decompme import HttpClient as DecompmeHttpClient
        from rebrew.recompile_client import HttpClient

        class _Response:
            def __init__(self, status_code: int, payload: object) -> None:
                self.status_code = status_code
                self._payload = payload
                self.content = payload if isinstance(payload, bytes) else b""
                self.text = str(payload)

            def json(self) -> object:
                return self._payload

            def close(self) -> None:
                return None

        class FakeService:
            def post(self, url: str, **kwargs: object) -> _Response:
                return _Response(200, {"status": "ok", "artifact_url": "/api/v1/artifacts/1.obj"})

            def get(self, url: str, **kwargs: object) -> _Response:
                return _Response(200, b"\x90" * 8)

        fake = FakeService()
        assert isinstance(fake, HttpClient)
        assert isinstance(fake, DecompmeHttpClient)

        result = compile_source(
            "http://localhost:8080",
            "msvc-6.0",
            "int f(void) { return 0; }",
            ["/O2"],
            client=fake,
        )
        assert result.ok is True
        assert result.obj_bytes == b"\x90" * 8

    def test_one_reply_satisfies_both_response_protocols(self) -> None:
        """The same reply covers both HTTP transports, as the README says.

        ``rebrew.recompile_client`` additionally reads ``content`` (the
        artifact bytes); ``rebrew.decompme`` does not, but its module-level
        ``httpx`` calls hand back a reply that owns a connection, so it
        releases ``close()``.  A reply carrying all five members serves both.
        """
        from rebrew.decompme import HttpResponse as DecompmeHttpResponse
        from rebrew.recompile_client import HttpResponse

        class _Response:
            status_code = 200
            text = ""
            content = b"\x90" * 8

            def json(self) -> object:
                return {"status": "ok"}

            def close(self) -> None:
                return None

        assert isinstance(_Response(), HttpResponse)
        assert isinstance(_Response(), DecompmeHttpResponse)

        # A reply without ``content`` is not a recompile reply: obj_bytes
        # would come back holding whatever the stand-in had in its place.
        # One without ``close()`` is not a decomp.me reply either.
        class _NoContent:
            status_code = 200
            text = ""

            def json(self) -> object:
                return {"status": "ok"}

        assert not isinstance(_NoContent(), HttpResponse)
        assert not isinstance(_NoContent(), DecompmeHttpResponse)

    def test_kwargs_fake_satisfies_the_mcp_client_protocol(self) -> None:
        """The same stand-in shape also drives the ReVa MCP client.

        The README says one ``**kwargs`` fake covers rebrew's HTTP clients.
        The MCP one also terminates its session with ``DELETE``, so the
        stand-in needs that method too — a consumer reading the quickstart
        should not have to discover it from a traceback.
        """
        from rebrew.ghidra.client import McpHttpClient

        class _McpFake:
            def post(self, url: str, **kwargs: object) -> object:
                return SimpleNamespace(
                    status_code=200,
                    headers={"content-type": "application/json", "mcp-session-id": "sess-1"},
                    text='{"jsonrpc": "2.0", "result": {"content": []}}',
                    json=lambda: {"jsonrpc": "2.0", "result": {"content": []}},
                    raise_for_status=lambda: None,
                    close=lambda: None,
                )

            def delete(self, url: str, **kwargs: object) -> object:
                return SimpleNamespace(status_code=200, close=lambda: None)

        assert isinstance(_McpFake(), McpHttpClient)

        # A stand-in with only post/get is not an MCP client; the protocol
        # says so before a session teardown raises AttributeError.
        class _RecompileFake:
            def post(self, url: str, **kwargs: object) -> object: ...

            def get(self, url: str, **kwargs: object) -> object: ...

        assert not isinstance(_RecompileFake(), McpHttpClient)


class TestAllListsDeclareTheirModuleSurface:
    """A module that declares ``__all__`` declares the whole public surface.

    ``AGENTS.md`` makes a public name that another module imports a member of
    the owning module's ``__all__``.  An unlisted one is a star-import hole,
    so it is gated rather than left to review.
    """

    @staticmethod
    def _modules() -> list[ModuleType]:
        found: list[ModuleType] = []
        for info in pkgutil.walk_packages(rebrew.__path__, "rebrew."):
            try:
                module = importlib.import_module(info.name)
            except ImportError:
                # A module behind an uninstalled extra ([prove] / [binsync])
                # declares its surface without needing to be importable.
                continue
            if isinstance(module, ModuleType) and hasattr(module, "__all__"):
                found.append(module)
        return found

    def test_every_public_name_is_listed(self) -> None:
        unlisted: list[str] = []
        modules = self._modules()
        for module in modules:
            listed = set(module.__all__)
            for name, value in vars(module).items():
                if name.startswith("_") or name in listed or inspect.ismodule(value):
                    continue
                # An imported re-export is not this module's own surface:
                # ``rebrew.errors`` owns it, and the names it does own are
                # listed there.
                if getattr(value, "__module__", None) != module.__name__:
                    continue
                unlisted.append(f"{module.__name__}.{name}")
        assert unlisted == [], "public names missing from __all__: " + ", ".join(unlisted)

    def test_the_gate_covers_the_public_modules(self) -> None:
        """A walk that stopped importing packages would gate almost nothing."""
        names = {module.__name__ for module in self._modules()}
        for expected in (
            "rebrew.annotation",
            "rebrew.cli",
            "rebrew.compile",
            "rebrew.config",
            "rebrew.errors",
            "rebrew.metadata",
            "rebrew.toolchain",
        ):
            assert expected in names, f"{expected} is not covered by the __all__ gate"
        assert len(names) >= 15, f"only {len(names)} modules declare __all__; the walk drifted"
