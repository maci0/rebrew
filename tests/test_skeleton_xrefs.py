import importlib
from pathlib import Path

from rebrew.config import ProjectConfig
from rebrew.skeleton import fetch_xref_context, generate_skeleton


class _DummyClient:
    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    def __enter__(self) -> "_DummyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class _DummyHttpx:
    Client = _DummyClient


def _make_import_mock(sync_mod: object) -> object:
    """Return an import_module replacement that dispatches httpx vs rebrew.sync."""

    def _import(name: str) -> object:
        if name == "rebrew.sync":
            return sync_mod
        return _DummyHttpx

    return _import


class TestFetchXrefContext:
    def test_returns_formatted_comment(self, monkeypatch) -> None:
        import rebrew.sync as sync_mod

        monkeypatch.setattr(importlib, "import_module", _make_import_mock(sync_mod))
        monkeypatch.setattr(sync_mod, "_init_mcp_session", lambda client, endpoint: "sid")

        def _mock_fetch(client, endpoint, tool_name, arguments, request_id, session_id=""):
            if tool_name == "find-cross-references":
                return {
                    "referencesTo": [
                        {
                            "fromAddress": "0x00402abc",
                            "toAddress": "0x00401000",
                            "referenceType": "UNCONDITIONAL_CALL",
                            "isCall": True,
                            "isData": False,
                            "fromSymbol": {"name": "caller_fn", "type": "Function"},
                            "fromFunction": {
                                "name": "caller_fn",
                                "entry": "0x00402a00",
                                "context": "  MyFunc(arg);",
                            },
                        }
                    ],
                    "pagination": {"totalToCount": 1, "hasMoreTo": False},
                }
            if tool_name == "get-decompilation":
                return "int caller_fn(void) {\n    MyFunc(arg);\n    return 0;\n}"
            return None

        monkeypatch.setattr(sync_mod, "_fetch_mcp_tool_raw", _mock_fetch)

        result = fetch_xref_context("http://localhost:8080/mcp/message", "/server.dll", 0x00401000)
        assert result is not None
        assert "Cross-references (1 callers)" in result
        assert "Caller 1: caller_fn (0x00402abc)" in result
        assert "MyFunc(arg);" in result
        assert "Caller: caller_fn (0x00402abc) - decompilation" in result

    def test_no_callers_returns_none(self, monkeypatch) -> None:
        import rebrew.sync as sync_mod

        monkeypatch.setattr(importlib, "import_module", _make_import_mock(sync_mod))
        monkeypatch.setattr(sync_mod, "_init_mcp_session", lambda client, endpoint: "sid")
        monkeypatch.setattr(
            sync_mod, "_fetch_mcp_tool_raw", lambda *args, **kwargs: {"referencesTo": []}
        )

        result = fetch_xref_context("http://localhost:8080/mcp/message", "/server.dll", 0x00401000)
        assert result is None

    def test_mcp_unreachable_returns_none(self, monkeypatch) -> None:
        import rebrew.sync as sync_mod

        monkeypatch.setattr(importlib, "import_module", _make_import_mock(sync_mod))

        def _raise(*args, **kwargs):
            raise RuntimeError("mcp down")

        monkeypatch.setattr(sync_mod, "_init_mcp_session", _raise)

        result = fetch_xref_context("http://localhost:8080/mcp/message", "/server.dll", 0x00401000)
        assert result is None

    def test_httpx_not_installed_returns_none(self, monkeypatch, capsys) -> None:
        def _missing(name: str):
            raise ModuleNotFoundError("no module named httpx")

        monkeypatch.setattr(importlib, "import_module", _missing)

        result = fetch_xref_context("http://localhost:8080/mcp/message", "/server.dll", 0x00401000)
        captured = capsys.readouterr()
        assert result is None
        assert "httpx required for --xrefs" in captured.err

    def test_max_callers_limit(self, monkeypatch) -> None:
        import rebrew.sync as sync_mod

        monkeypatch.setattr(importlib, "import_module", _make_import_mock(sync_mod))
        monkeypatch.setattr(sync_mod, "_init_mcp_session", lambda client, endpoint: "sid")

        calls: list[str] = []

        def _mock_fetch(client, endpoint, tool_name, arguments, request_id, session_id=""):
            if tool_name == "find-cross-references":
                return {
                    "referencesTo": [
                        {
                            "fromAddress": "0x00402000",
                            "isCall": True,
                            "isData": False,
                            "fromFunction": {"name": "caller_a", "context": "MyFunc(1);"},
                        },
                        {
                            "fromAddress": "0x00403000",
                            "isCall": True,
                            "isData": False,
                            "fromFunction": {"name": "caller_b", "context": "MyFunc(2);"},
                        },
                        {
                            "fromAddress": "0x00404000",
                            "isCall": True,
                            "isData": False,
                            "fromFunction": {"name": "caller_c", "context": "MyFunc(3);"},
                        },
                    ]
                }
            if tool_name == "get-decompilation":
                target = arguments.get("functionNameOrAddress", "")
                calls.append(target)
                return f"void f(void) {{ {target}; }}"
            return None

        monkeypatch.setattr(sync_mod, "_fetch_mcp_tool_raw", _mock_fetch)

        result = fetch_xref_context(
            "http://localhost:8080/mcp/message", "/server.dll", 0x00401000, max_callers=2
        )
        assert result is not None
        assert "Cross-references (2 callers)" in result
        assert len(calls) == 2
        assert calls == ["0x00402000", "0x00403000"]

    def test_data_refs_included(self, monkeypatch) -> None:
        import rebrew.sync as sync_mod

        monkeypatch.setattr(importlib, "import_module", _make_import_mock(sync_mod))
        monkeypatch.setattr(sync_mod, "_init_mcp_session", lambda client, endpoint: "sid")

        def _mock_fetch(client, endpoint, tool_name, arguments, request_id, session_id=""):
            if tool_name == "find-cross-references":
                return {
                    "referencesTo": [
                        {
                            "fromAddress": "0x00405000",
                            "referenceType": "READ",
                            "isCall": False,
                            "isData": True,
                            "fromFunction": {"name": "global_reader", "context": "x = *ptr;"},
                        }
                    ]
                }
            return None

        monkeypatch.setattr(sync_mod, "_fetch_mcp_tool_raw", _mock_fetch)

        result = fetch_xref_context("http://localhost:8080/mcp/message", "/server.dll", 0x00401000)
        assert result is not None
        assert "Data references: 1" in result
        assert "global_reader (0x00405000) [READ]" in result


class TestSkeletonWithXrefs:
    def _cfg(self) -> ProjectConfig:
        cfg = ProjectConfig(root=Path("/tmp"))
        cfg.marker = "SERVER"
        cfg.cflags_presets = {"GAME": "/O2 /Gd"}
        return cfg

    def test_xref_context_in_template(self, tmp_path) -> None:
        cfg = self._cfg()
        xref_block = "/* === Cross-references (1 callers) ===\n * Caller 1: main (0x00401000)\n */"
        content = generate_skeleton(
            cfg,
            0x10001000,
            64,
            "FUN_10001000",
            "GAME",
            xref_context=xref_block,
        )
        assert xref_block in content

    def test_xref_context_none_omitted(self, tmp_path) -> None:
        cfg = self._cfg()
        content = generate_skeleton(cfg, 0x10001000, 64, "FUN_10001000", "GAME", xref_context=None)
        assert "Cross-references" not in content

    def test_both_xrefs_and_decomp(self, tmp_path) -> None:
        cfg = self._cfg()
        xref_block = "/* === Cross-references (1 callers) ===\n * Caller 1: main (0x00401000)\n */"
        content = generate_skeleton(
            cfg,
            0x10001000,
            64,
            "FUN_10001000",
            "GAME",
            xref_context=xref_block,
            decomp_code="int fn(void) { return 1; }",
            decomp_backend="r2ghidra",
        )
        assert "Cross-references (1 callers)" in content
        assert "Decompilation (r2ghidra)" in content
