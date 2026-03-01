"""Tests for rebrew.decompiler backend dispatch and helpers."""

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from rebrew.config import ProjectConfig
from rebrew.decompiler import (
    _BACKEND_MAP,
    _DEFAULT_MCP_ENDPOINT,
    BACKENDS,
    _clean_output,
    _find_re_tool,
    _strip_ansi,
    fetch_decompilation,
    fetch_ghidra,
    fetch_r2dec,
    fetch_r2ghidra,
)


class TestStripAnsi:
    def test_basic_escape(self) -> None:
        assert _strip_ansi("\x1b[31mhello\x1b[0m") == "hello"

    def test_no_escape(self) -> None:
        assert _strip_ansi("plain text") == "plain text"

    def test_multiple_escapes(self) -> None:
        assert _strip_ansi("\x1b[1m\x1b[32mint\x1b[0m x;") == "int x;"


class TestCleanOutput:
    def test_strips_and_trims(self) -> None:
        text = "\n\n\x1b[32mint main() {\x1b[0m\n  return 0;\n}\n\n"
        assert _clean_output(text) == "int main() {\n  return 0;\n}"

    def test_empty_input(self) -> None:
        assert _clean_output("") is None

    def test_only_whitespace(self) -> None:
        assert _clean_output("\n  \n  \n") is None


class TestBackendDispatch:
    def test_backends_list(self) -> None:
        assert "r2ghidra" in BACKENDS
        assert "r2dec" in BACKENDS
        # ghidra backend excluded from auto-probe (not yet implemented)
        assert "ghidra" not in BACKENDS
        assert "ghidra" in _BACKEND_MAP  # still registered for explicit use

    @patch("rebrew.decompiler.shutil.which", return_value=None)
    def test_r2ghidra_no_tool(self, mock_which) -> None:
        result = fetch_r2ghidra(Path("/fake/binary"), 0x1000, Path("/fake"))
        assert result is None

    @patch("rebrew.decompiler.shutil.which", return_value=None)
    def test_r2dec_no_tool(self, mock_which) -> None:
        result = fetch_r2dec(Path("/fake/binary"), 0x1000, Path("/fake"))
        assert result is None

    def test_unknown_backend(self, capsys) -> None:
        code, name = fetch_decompilation("nonexistent", Path("/f"), 0x1000, Path("/f"))
        assert code is None
        assert name == "nonexistent"
        captured = capsys.readouterr()
        assert "unknown backend" in captured.err

    @patch(
        "rebrew.decompiler.shutil.which", side_effect=lambda x: "/usr/bin/r2" if x == "r2" else None
    )
    @patch("rebrew.decompiler.subprocess.run")
    def test_r2ghidra_uses_r2(self, mock_run, _mock_which, tmp_path: Path) -> None:
        binary = tmp_path / "target.bin"
        binary.write_bytes(b"MZ")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="int foo() {\n  return 1;\n}\n",
            stderr="",
        )

        result = fetch_r2ghidra(binary, 0x1000, tmp_path)

        assert result == "int foo() {\n  return 1;\n}"
        args, kwargs = mock_run.call_args
        assert args[0][:4] == ["r2", "-q", "-c", "aaa; s 0x00001000; af; pdg"]
        assert args[0][4] == str(binary)
        assert kwargs["cwd"] == tmp_path
        assert kwargs["timeout"] == 120

    @patch(
        "rebrew.decompiler.shutil.which", side_effect=lambda x: "/usr/bin/rz" if x == "rz" else None
    )
    @patch("rebrew.decompiler.subprocess.run")
    def test_r2ghidra_uses_rz(self, mock_run, _mock_which, tmp_path: Path) -> None:
        binary = tmp_path / "target.bin"
        binary.write_bytes(b"MZ")
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="int bar() {\n  return 2;\n}\n",
            stderr="",
        )

        result = fetch_r2ghidra(binary, 0x1000, tmp_path)

        assert result == "int bar() {\n  return 2;\n}"
        args, _kwargs = mock_run.call_args
        assert args[0][0] == "rz"


class TestFindReTool:
    @patch("rebrew.decompiler.shutil.which", return_value=None)
    def test_neither_installed(self, _mock_which) -> None:
        assert _find_re_tool() is None

    @patch(
        "rebrew.decompiler.shutil.which", side_effect=lambda x: "/usr/bin/r2" if x == "r2" else None
    )
    def test_only_r2(self, _mock_which) -> None:
        assert _find_re_tool() == "r2"

    @patch(
        "rebrew.decompiler.shutil.which", side_effect=lambda x: "/usr/bin/rz" if x == "rz" else None
    )
    def test_only_rz(self, _mock_which) -> None:
        assert _find_re_tool() == "rz"

    @patch(
        "rebrew.decompiler.shutil.which",
        side_effect=lambda x: f"/usr/bin/{x}" if x in ("rz", "r2") else None,
    )
    def test_both_prefers_rz(self, _mock_which) -> None:
        assert _find_re_tool() == "rz"


class TestAutoFallback:
    @patch.dict(
        "rebrew.decompiler._BACKEND_MAP",
        {"r2ghidra": lambda *a: None, "r2dec": lambda *a: None, "ghidra": lambda *a: None},
    )
    def test_all_fail(self) -> None:
        code, name = fetch_decompilation("auto", Path("/f"), 0x1000, Path("/f"))
        assert code is None
        assert name == "auto"

    @patch.dict(
        "rebrew.decompiler._BACKEND_MAP",
        {"r2ghidra": lambda *a: None, "r2dec": lambda *a: "int x;", "ghidra": lambda *a: None},
    )
    def test_r2dec_fallback(self) -> None:
        code, name = fetch_decompilation("auto", Path("/f"), 0x1000, Path("/f"))
        assert code == "int x;"
        assert name == "r2dec"

    @patch.dict(
        "rebrew.decompiler._BACKEND_MAP",
        {"r2ghidra": lambda *a: "void f() {}", "r2dec": lambda *a: None, "ghidra": lambda *a: None},
    )
    def test_r2ghidra_first(self) -> None:
        code, name = fetch_decompilation("auto", Path("/f"), 0x1000, Path("/f"))
        assert code == "void f() {}"
        assert name == "r2ghidra"

    @patch.dict(
        "rebrew.decompiler._BACKEND_MAP",
        {"r2ghidra": lambda *a: "void f() {}"},
    )
    def test_explicit_backend(self) -> None:
        code, name = fetch_decompilation("r2ghidra", Path("/f"), 0x1000, Path("/f"))
        assert code == "void f() {}"
        assert name == "r2ghidra"


class TestGenerateSkeletonWithDecomp:
    """Test that generate_skeleton embeds decompilation correctly."""

    def test_no_decomp_default(self) -> None:
        """Without decomp_code, skeleton has TODO placeholder."""
        from rebrew.skeleton import generate_skeleton

        cfg = ProjectConfig(root=Path("/fake"))
        cfg.cflags_presets = {"GAME": "/O2 /Gd"}
        cfg.target_binary = Path("/fake/bin")

        result = generate_skeleton(cfg, 0x10001000, 100, "FUN_10001000", "GAME")
        assert "/* TODO:" in result
        assert "Decompilation" not in result

    def test_with_decomp_code(self) -> None:
        """With decomp_code, skeleton embeds the decompilation block."""
        from rebrew.skeleton import generate_skeleton

        cfg = ProjectConfig(root=Path("/fake"))
        cfg.cflags_presets = {"GAME": "/O2 /Gd"}
        cfg.target_binary = Path("/fake/bin")

        result = generate_skeleton(
            cfg,
            0x10001000,
            100,
            "FUN_10001000",
            "GAME",
            decomp_code="int foo() { return 42; }",
            decomp_backend="r2ghidra",
        )
        assert "/* === Decompilation (r2ghidra) === */" in result
        assert "int foo() { return 42; }" in result
        assert "/* === End decompilation === */" in result
        # No TODO placeholder when decomp is present
        assert "/* TODO:" not in result.split("/* === End decompilation === */")[-1]

    def test_msvcrt_with_decomp(self) -> None:
        """MSVCRT origin also embeds decompilation."""
        from rebrew.skeleton import generate_skeleton

        cfg = ProjectConfig(root=Path("/fake"))
        cfg.cflags_presets = {"MSVCRT": "/O1"}
        cfg.target_binary = Path("/fake/bin")

        result = generate_skeleton(
            cfg,
            0x1001E000,
            50,
            "crt_init",
            "MSVCRT",
            decomp_code="void crt_init() {}",
            decomp_backend="r2dec",
        )
        assert "CRT function" in result
        assert "/* === Decompilation (r2dec) === */" in result
        assert "void crt_init() {}" in result


_real_import_module = __import__("importlib").import_module


def _make_sync_import_mock() -> Any:
    """Build an importlib.import_module side_effect that returns real sync module."""
    from rebrew import sync as _sync_mod

    def _side_effect(name: str) -> Any:
        if name == "rebrew.sync":
            return _sync_mod
        return _real_import_module(name)

    return _side_effect


def _mock_httpx_client(response_json: dict | None, status_code: int = 200) -> MagicMock:
    """Build a mock httpx.Client context manager returning *response_json*."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = {"Mcp-Session-Id": "test-session", "content-type": "application/json"}
    if response_json is not None:
        mock_resp.json.return_value = response_json
        mock_resp.text = "{}"
    else:
        mock_resp.json.side_effect = ValueError
        mock_resp.text = ""
    mock_client = MagicMock()
    mock_client.post.return_value = mock_resp
    mock_client.__enter__ = lambda self: mock_client
    mock_client.__exit__ = lambda self, *a: None
    return mock_client


def _mcp_result(text_content: str) -> dict:
    """Wrap *text_content* in the MCP JSON-RPC result envelope."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{"type": "text", "text": text_content}],
        },
    }


class TestGhidraBackend:
    def test_returns_string_result(self) -> None:
        import json

        mock_client = _mock_httpx_client(_mcp_result(json.dumps("int foo() {\n  return 42;\n}")))

        with (
            patch(
                "rebrew.decompiler.importlib.import_module",
                side_effect=_make_sync_import_mock(),
            ),
            patch("rebrew.decompiler.httpx.Client", return_value=mock_client),
        ):
            result = fetch_ghidra(Path("/fake/target.dll"), 0x1000, Path("/fake"))

        assert result == "int foo() {\n  return 42;\n}"

    def test_returns_dict_with_decompilation_key(self) -> None:
        import json

        mock_client = _mock_httpx_client(
            _mcp_result(json.dumps({"decompilation": "void bar() {}"}))
        )

        with (
            patch(
                "rebrew.decompiler.importlib.import_module",
                side_effect=_make_sync_import_mock(),
            ),
            patch("rebrew.decompiler.httpx.Client", return_value=mock_client),
        ):
            result = fetch_ghidra(Path("/fake/target.dll"), 0x1000, Path("/fake"))

        assert result == "void bar() {}"

    def test_returns_dict_with_text_key(self) -> None:
        import json

        mock_client = _mock_httpx_client(_mcp_result(json.dumps({"text": "int baz();"})))

        with (
            patch(
                "rebrew.decompiler.importlib.import_module",
                side_effect=_make_sync_import_mock(),
            ),
            patch("rebrew.decompiler.httpx.Client", return_value=mock_client),
        ):
            result = fetch_ghidra(Path("/fake/target.dll"), 0x1000, Path("/fake"))

        assert result == "int baz();"

    def test_returns_none_on_empty_response(self) -> None:
        mock_client = _mock_httpx_client(None, status_code=200)

        with (
            patch(
                "rebrew.decompiler.importlib.import_module",
                side_effect=_make_sync_import_mock(),
            ),
            patch("rebrew.decompiler.httpx.Client", return_value=mock_client),
        ):
            result = fetch_ghidra(Path("/fake/target.dll"), 0x1000, Path("/fake"))

        assert result is None

    def test_returns_none_on_connection_error(self) -> None:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(side_effect=ConnectionError)
        mock_client.__exit__ = lambda *a: None

        with (
            patch(
                "rebrew.decompiler.importlib.import_module",
                side_effect=_make_sync_import_mock(),
            ),
            patch("rebrew.decompiler.httpx.Client", return_value=mock_client),
        ):
            result = fetch_ghidra(Path("/fake/target.dll"), 0x1000, Path("/fake"))

        assert result is None

    def test_uses_custom_endpoint(self) -> None:
        import json

        mock_client = _mock_httpx_client(_mcp_result(json.dumps("int x;")))

        custom_ep = "http://myhost:9999/mcp/message"
        with (
            patch(
                "rebrew.decompiler.importlib.import_module",
                side_effect=_make_sync_import_mock(),
            ),
            patch("rebrew.decompiler.httpx.Client", return_value=mock_client),
        ):
            fetch_ghidra(Path("/fake/target.dll"), 0x1000, Path("/fake"), endpoint=custom_ep)

        post_calls = mock_client.post.call_args_list
        assert any(custom_ep in str(call) for call in post_calls)

    def test_uses_default_endpoint(self) -> None:
        import json

        mock_client = _mock_httpx_client(_mcp_result(json.dumps("int x;")))

        with (
            patch(
                "rebrew.decompiler.importlib.import_module",
                side_effect=_make_sync_import_mock(),
            ),
            patch("rebrew.decompiler.httpx.Client", return_value=mock_client),
        ):
            fetch_ghidra(Path("/fake/target.dll"), 0x1000, Path("/fake"))

        post_calls = mock_client.post.call_args_list
        assert any(_DEFAULT_MCP_ENDPOINT in str(call) for call in post_calls)

    def test_sends_correct_program_path(self) -> None:
        import json

        mock_client = _mock_httpx_client(_mcp_result(json.dumps("int x;")))

        with (
            patch(
                "rebrew.decompiler.importlib.import_module",
                side_effect=_make_sync_import_mock(),
            ),
            patch("rebrew.decompiler.httpx.Client", return_value=mock_client),
        ):
            fetch_ghidra(Path("/some/dir/LEGO1.DLL"), 0xABCD, Path("/some/dir"))

        post_calls = mock_client.post.call_args_list
        tool_call = [c for c in post_calls if "get-decompilation" in str(c)]
        assert len(tool_call) >= 1
        payload = tool_call[0][1]["json"] if "json" in tool_call[0][1] else tool_call[0][0][1]
        assert payload["params"]["arguments"]["programPath"] == "/LEGO1.DLL"
        assert payload["params"]["arguments"]["functionNameOrAddress"] == "0x0000ABCD"

    def test_dispatch_passes_endpoint_for_ghidra(self) -> None:
        mock_fn = MagicMock(return_value="int x;")
        with patch.dict("rebrew.decompiler._BACKEND_MAP", {"ghidra": mock_fn}):
            code, name = fetch_decompilation(
                "ghidra", Path("/f"), 0x1000, Path("/f"), endpoint="http://custom:8080/mcp"
            )
        assert code == "int x;"
        assert name == "ghidra"
        mock_fn.assert_called_once_with(
            Path("/f"), 0x1000, Path("/f"), endpoint="http://custom:8080/mcp"
        )

    def test_dispatch_does_not_pass_endpoint_for_r2(self) -> None:
        mock_fn = MagicMock(return_value="int y;")
        with patch.dict("rebrew.decompiler._BACKEND_MAP", {"r2ghidra": mock_fn}):
            code, name = fetch_decompilation(
                "r2ghidra", Path("/f"), 0x1000, Path("/f"), endpoint="http://unused"
            )
        assert code == "int y;"
        assert name == "r2ghidra"
        mock_fn.assert_called_once_with(Path("/f"), 0x1000, Path("/f"))

    def test_cleans_ansi_from_mcp_response(self) -> None:
        import json

        raw = "\x1b[32mint foo() {\x1b[0m\n  return 1;\n}\n"
        mock_client = _mock_httpx_client(_mcp_result(json.dumps(raw)))

        with (
            patch(
                "rebrew.decompiler.importlib.import_module",
                side_effect=_make_sync_import_mock(),
            ),
            patch("rebrew.decompiler.httpx.Client", return_value=mock_client),
        ):
            result = fetch_ghidra(Path("/fake/target.dll"), 0x1000, Path("/fake"))

        assert result == "int foo() {\n  return 1;\n}"
