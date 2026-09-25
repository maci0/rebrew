"""Tests for ghidra/client.py — SSE parsing and MCP tool calls."""

import json
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from rebrew.ghidra.client import _call_mcp_tool, _parse_sse_response


def test_ghidra_client_public_all() -> None:
    """Star-imports must not leak typing/stdlib names into consumer namespaces."""
    import rebrew.ghidra.client as client

    assert client.__all__ == [
        "MAX_MCP_PAGES",
        "MCP_HEADERS",
        "MCP_REQUEST_TIMEOUT_S",
        "McpApplyAborted",
        "McpError",
        "McpErrorKind",
        "apply_commands_via_mcp",
        "end_mcp_session",
        "fetch_all_functions",
        "fetch_all_symbols",
        "fetch_mcp_tool",
        "fetch_mcp_tool_raw",
        "init_mcp_session",
    ]
    for name in client.__all__:
        assert getattr(client, name, None) is not None, name
    ns: dict[str, Any] = {}
    exec("from rebrew.ghidra.client import *", ns)  # noqa: S102
    exported = {k for k in ns if not k.startswith("_")}
    assert exported == set(client.__all__)


def test_ghidra_package_exports_mcp_errors() -> None:
    """Integrators catch MCP failures from ``rebrew.ghidra``, not a submodule."""
    import rebrew.ghidra as ghidra

    assert "McpError" in ghidra.__all__
    assert "McpApplyAborted" in ghidra.__all__
    assert "McpErrorKind" in ghidra.__all__
    assert ghidra.McpError is not None
    assert issubclass(ghidra.McpError, RuntimeError)
    # Kind alias must be importable alongside the exception for typed branching.
    assert ghidra.McpErrorKind == ghidra.client.McpErrorKind


class TestParseSseResponse:
    def test_valid_data_line(self) -> None:
        payload = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        resp = _parse_sse_response(f"event: message\ndata: {json.dumps(payload)}\n\n")
        assert resp is not None
        assert resp.result == {"ok": True}

    def test_no_space_data_line(self) -> None:
        payload = {"jsonrpc": "2.0", "id": 2, "result": {}}
        resp = _parse_sse_response(f"data:{json.dumps(payload)}\n")
        assert resp is not None
        assert resp.id == 2

    def test_invalid_json_skipped(self) -> None:
        resp = _parse_sse_response("data: {not json\n")
        assert resp is None

    def test_no_data_lines(self) -> None:
        assert _parse_sse_response("event: ping\n\n") is None


def _mock_client(status_code: int = 200, text: str = "", content_type: str = "application/json"):
    resp = SimpleNamespace(
        status_code=status_code,
        text=text,
        headers={"content-type": content_type},
        json=lambda: json.loads(text),
        closed=False,
    )

    def _close() -> None:
        resp.closed = True

    resp.close = _close
    client = SimpleNamespace(post=lambda *a, **k: resp)
    return client, resp


class TestCallMcpTool:
    def test_json_response(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }
        client, resp = _mock_client(text=json.dumps(payload))
        result = _call_mcp_tool(client, "http://x", "get-functions", {}, 1, "")
        assert result is not None
        assert result.isError is False
        assert [(c.type, c.text) for c in result.content] == [("text", "ok")]
        assert resp.closed is True

    def test_sse_response(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }
        client, _ = _mock_client(
            text=f"data: {json.dumps(payload)}\n\n", content_type="text/event-stream"
        )
        result = _call_mcp_tool(client, "http://x", "get-functions", {}, 1, "")
        assert result is not None
        assert result.isError is False
        assert [(c.type, c.text) for c in result.content] == [("text", "ok")]

    def test_non_200_returns_none(self) -> None:
        client, _ = _mock_client(status_code=500, text="boom")
        assert _call_mcp_tool(client, "http://x", "t", {}, 1, "") is None

    def test_invalid_json_returns_none(self) -> None:
        client, _ = _mock_client(text="{not json")
        assert _call_mcp_tool(client, "http://x", "t", {}, 1, "") is None

    def test_empty_body_returns_none(self) -> None:
        client, _ = _mock_client(text="")
        assert _call_mcp_tool(client, "http://x", "t", {}, 1, "") is None

    def test_jsonrpc_error_returns_none(self) -> None:
        client, _ = _mock_client(
            text=json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "e"}})
        )
        assert _call_mcp_tool(client, "http://x", "t", {}, 1, "") is None


class TestCallMcpToolBranches:
    """Remaining _call_mcp_tool branches: SSE misses, isError, missing content."""

    def test_session_id_header(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }
        captured: dict[str, dict] = {}

        def _post(*a: object, **kw: object) -> object:
            captured["headers"] = kw.get("headers", {})  # type: ignore[assignment]
            return SimpleNamespace(
                status_code=200,
                text=json.dumps(payload),
                headers={"content-type": "application/json"},
                json=lambda: json.loads(json.dumps(payload)),
            )

        client = SimpleNamespace(post=_post)
        result = _call_mcp_tool(client, "http://x", "t", {}, 1, "abc123")
        assert result is not None
        assert captured["headers"]["Mcp-Session-Id"] == "abc123"

    def test_sse_unparseable_returns_none(self) -> None:
        client, _ = _mock_client(
            text="event: message\ndata: {not json\n\n", content_type="text/event-stream"
        )
        assert _call_mcp_tool(client, "http://x", "t", {}, 1, "") is None

    def test_result_without_content_returns_none(self) -> None:
        client, _ = _mock_client(
            text=json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
        )
        assert _call_mcp_tool(client, "http://x", "t", {}, 1, "") is None

    def test_iserror_tool_result_returns_none(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "isError": True,
                "content": [{"type": "text", "text": "symbol not found"}],
            },
        }
        client, _ = _mock_client(text=json.dumps(payload))
        assert _call_mcp_tool(client, "http://x", "t", {}, 1, "") is None

    def test_iserror_without_content_returns_none(self) -> None:
        payload = {"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": []}}
        client, _ = _mock_client(text=json.dumps(payload))
        assert _call_mcp_tool(client, "http://x", "t", {}, 1, "") is None


class TestFetchMcpTool:
    """fetch_mcp_tool shape handling: single/multi text items, JSON failures."""

    def _client(self, content: list[dict]) -> tuple[SimpleNamespace, SimpleNamespace]:
        payload = {"jsonrpc": "2.0", "id": 1, "result": {"content": content}}
        resp = SimpleNamespace(
            status_code=200,
            text=json.dumps(payload),
            headers={"content-type": "application/json"},
            json=lambda: json.loads(json.dumps(payload)),
        )
        return SimpleNamespace(post=lambda *a, **k: resp), resp

    def test_single_text_list(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool

        client, _ = self._client([{"type": "text", "text": '[{"a": 1}]'}])
        assert fetch_mcp_tool(client, "http://x", "t", {}, 1) == [{"a": 1}]

    def test_single_text_dict_wrapped(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool

        client, _ = self._client([{"type": "text", "text": '{"a": 1}'}])
        assert fetch_mcp_tool(client, "http://x", "t", {}, 1) == [{"a": 1}]

    def test_multiple_text_items(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool

        client, _ = self._client(
            [{"type": "text", "text": '{"a": 1}'}, {"type": "text", "text": '{"b": 2}'}]
        )
        assert fetch_mcp_tool(client, "http://x", "t", {}, 1) == [{"a": 1}, {"b": 2}]

    def test_multiple_text_all_invalid(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool

        client, _ = self._client(
            [{"type": "text", "text": "oops"}, {"type": "text", "text": "nope"}]
        )
        assert fetch_mcp_tool(client, "http://x", "t", {}, 1) == []

    def test_invalid_single_json_returns_empty(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool

        client, _ = self._client([{"type": "text", "text": "not json"}])
        assert fetch_mcp_tool(client, "http://x", "t", {}, 1) == []

    def test_no_text_items(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool

        client, _ = self._client([{"type": "image", "text": "x"}])
        assert fetch_mcp_tool(client, "http://x", "t", {}, 1) == []

    def test_call_failure_returns_empty(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool

        client, _ = _mock_client(status_code=500, text="boom")
        assert fetch_mcp_tool(client, "http://x", "t", {}, 1) == []


class TestFetchMcpToolRaw:
    """fetch_mcp_tool_raw returns the raw parsed value, not a list wrapper."""

    def _client(self, content: list[dict]) -> SimpleNamespace:
        payload = {"jsonrpc": "2.0", "id": 1, "result": {"content": content}}
        resp = SimpleNamespace(
            status_code=200,
            text=json.dumps(payload),
            headers={"content-type": "application/json"},
            json=lambda: json.loads(json.dumps(payload)),
        )
        return SimpleNamespace(post=lambda *a, **k: resp)

    def test_single_dict_returned_directly(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool_raw

        client = self._client([{"type": "text", "text": '{"x": 1}'}])
        assert fetch_mcp_tool_raw(client, "http://x", "t", {}, 1) == {"x": 1}

    def test_invalid_json_returns_raw_string(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool_raw

        client = self._client([{"type": "text", "text": "plain text"}])
        assert fetch_mcp_tool_raw(client, "http://x", "t", {}, 1) == "plain text"

    def test_multiple_items_list(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool_raw

        client = self._client([{"type": "text", "text": '{"a": 1}'}, {"type": "text", "text": "2"}])
        assert fetch_mcp_tool_raw(client, "http://x", "t", {}, 1) == [{"a": 1}, 2]

    def test_multiple_items_all_invalid_none(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool_raw

        client = self._client([{"type": "text", "text": "a"}, {"type": "text", "text": "b"}])
        assert fetch_mcp_tool_raw(client, "http://x", "t", {}, 1) is None

    def test_no_text_items_none(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool_raw

        client = self._client([{"type": "image", "text": "x"}])
        assert fetch_mcp_tool_raw(client, "http://x", "t", {}, 1) is None

    def test_call_failure_none(self) -> None:
        from rebrew.ghidra.client import fetch_mcp_tool_raw

        client, _ = _mock_client(status_code=500, text="boom")
        assert fetch_mcp_tool_raw(client, "http://x", "t", {}, 1) is None


class TestInitMcpSession:
    def test_returns_session_header(self) -> None:
        from rebrew.ghidra.client import init_mcp_session

        resp = SimpleNamespace(
            status_code=200,
            text="",
            headers={"Mcp-Session-Id": "sess-1"},
            raise_for_status=lambda: None,
        )
        client = SimpleNamespace(post=lambda *a, **k: resp)
        assert init_mcp_session(client, "http://x") == "sess-1"

    def test_missing_header_empty(self) -> None:
        from rebrew.ghidra.client import init_mcp_session

        resp = SimpleNamespace(status_code=200, text="", headers={}, raise_for_status=lambda: None)
        client = SimpleNamespace(post=lambda *a, **k: resp)
        assert init_mcp_session(client, "http://x") == ""

    def test_connect_error_is_retryable_mcp_error(self) -> None:
        import httpx

        from rebrew.ghidra.client import McpError, init_mcp_session

        def _post(*_a: object, **_k: object) -> object:
            raise httpx.ConnectError("conn refused")

        client = SimpleNamespace(post=_post)
        with pytest.raises(McpError, match="Failed to initialize MCP session") as ei:
            init_mcp_session(client, "http://x")  # type: ignore[arg-type]
        assert ei.value.kind == "network"
        assert ei.value.retryable is True
        assert ei.value.status_code is None
        assert isinstance(ei.value.__cause__, httpx.ConnectError)

    def test_http_status_is_mcp_error(self) -> None:
        import httpx

        from rebrew.ghidra.client import McpError, init_mcp_session

        request = httpx.Request("POST", "http://x")
        response = httpx.Response(503, request=request)
        closed = {"n": 0}

        def _raise_for_status() -> None:
            raise httpx.HTTPStatusError("err", request=request, response=response)

        def _close() -> None:
            closed["n"] += 1

        resp = SimpleNamespace(
            status_code=503,
            text="",
            headers={},
            raise_for_status=_raise_for_status,
            close=_close,
        )
        client = SimpleNamespace(post=lambda *_a, **_k: resp)
        with pytest.raises(McpError, match="HTTP 503") as ei:
            init_mcp_session(client, "http://x")  # type: ignore[arg-type]
        assert ei.value.kind == "http"
        assert ei.value.status_code == 503
        assert ei.value.retryable is True
        assert closed["n"] == 1


class TestFetchAllPaginated:
    """Pagination drivers fetch_all_symbols / fetch_all_functions."""

    def test_symbols_single_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import fetch_all_symbols

        monkeypatch.setattr(
            "rebrew.ghidra.client.fetch_mcp_tool",
            lambda client, ep, tool, args, rid, session_id="": [
                {"totalCount": 2, "nextStartIndex": 2},
                {"address": "0x1000", "name": "sym_a"},
                {"address": "0x1001", "name": "sym_b"},
            ],
        )
        syms = fetch_all_symbols(None, "http://x", "/prog", "s")  # type: ignore[arg-type]
        assert len(syms) == 2
        assert syms[0]["name"] == "sym_a"

    def test_symbols_multiple_pages(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import fetch_all_symbols

        pages = [
            [{"totalCount": 4, "nextStartIndex": 2}, {"address": "0x1000", "name": "a"}],
            [{"totalCount": 4, "nextStartIndex": 4}, {"address": "0x1001", "name": "b"}],
        ]

        def _fake(*_a: object, **_k: object) -> list:
            return pages.pop(0) if pages else []

        monkeypatch.setattr("rebrew.ghidra.client.fetch_mcp_tool", _fake)
        syms = fetch_all_symbols(None, "http://x", "/prog", "s", batch_size=1)  # type: ignore[arg-type]
        assert len(syms) == 2

    def test_symbols_no_metadata_stops(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import fetch_all_symbols

        monkeypatch.setattr(
            "rebrew.ghidra.client.fetch_mcp_tool",
            lambda client, ep, tool, args, rid, session_id="": [{"address": "0x1000", "name": "a"}],
        )
        assert fetch_all_symbols(None, "http://x", "/prog", "s") == [  # type: ignore[arg-type]
            {"address": "0x1000", "name": "a"}
        ]

    def test_functions_normalizes_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import fetch_all_functions

        monkeypatch.setattr(
            "rebrew.ghidra.client.fetch_mcp_tool",
            lambda client, ep, tool, args, rid, session_id="": [
                {"totalCount": 1, "nextStartIndex": 1},
                {"address": "0x2000", "name": "func_a", "sizeInBytes": 42},
            ],
        )
        funcs = fetch_all_functions(None, "http://x", "/prog", "s")  # type: ignore[arg-type]
        assert funcs == [{"va": "0x2000", "tool_name": "func_a", "size": 42}]

    def test_functions_non_dict_items_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import fetch_all_functions

        monkeypatch.setattr(
            "rebrew.ghidra.client.fetch_mcp_tool",
            lambda client, ep, tool, args, rid, session_id="": [
                "junk",
                {"totalCount": 1},
                {"address": "0x2000", "name": "func_a"},
            ],
        )
        funcs = fetch_all_functions(None, "http://x", "/prog", "s")  # type: ignore[arg-type]
        assert funcs == [{"va": "0x2000", "tool_name": "func_a", "size": 0}]

    def test_sse_data_no_space_invalid_json_skipped(self) -> None:
        """A 'data:' (no space) line with invalid JSON is skipped, later lines parsed."""
        resp = _parse_sse_response('event: x\ndata:{bad json\ndata: {"jsonrpc":"2.0","id":3}\n')
        assert resp is not None
        assert resp.id == 3

    def test_symbols_metadata_without_page_stops(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import fetch_all_symbols

        monkeypatch.setattr(
            "rebrew.ghidra.client.fetch_mcp_tool",
            lambda client, ep, tool, args, rid, session_id="": [{"totalCount": 5}],
        )
        assert fetch_all_symbols(None, "http://x", "/prog", "s") == []  # type: ignore[arg-type]

    def test_symbols_name_only_entry_collected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A symbol dict with only 'name' (no 'address') still enters page_syms."""
        from rebrew.ghidra.client import fetch_all_symbols

        monkeypatch.setattr(
            "rebrew.ghidra.client.fetch_mcp_tool",
            lambda client, ep, tool, args, rid, session_id="": [
                "junk",  # non-dict item skipped
                {"totalCount": 1, "nextStartIndex": 1},
                {"name": "sym_only"},
            ],
        )
        syms = fetch_all_symbols(None, "http://x", "/prog", "s")  # type: ignore[arg-type]
        assert syms == [{"name": "sym_only"}]

    def test_functions_metadata_without_page_stops(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import fetch_all_functions

        monkeypatch.setattr(
            "rebrew.ghidra.client.fetch_mcp_tool",
            lambda client, ep, tool, args, rid, session_id="": [{"totalCount": 5}],
        )
        assert fetch_all_functions(None, "http://x", "/prog", "s") == []  # type: ignore[arg-type]

    def test_non_positive_batch_size_is_validation_error(self) -> None:
        from rebrew.ghidra.client import McpError, fetch_all_functions, fetch_all_symbols

        for fetch in (fetch_all_symbols, fetch_all_functions):
            with pytest.raises(McpError, match="batch_size must be positive") as ei:
                fetch(None, "http://x", "/prog", "s", batch_size=0)  # type: ignore[arg-type]
            assert ei.value.kind == "validation"
            assert ei.value.retryable is False


class _FakeResp:
    """Scripted HTTP response for apply_commands_via_mcp tests."""

    def __init__(
        self,
        text: str = "",
        *,
        headers: dict | None = None,
        status: int = 200,
    ) -> None:
        self.text = text
        self.headers = headers or {"content-type": "application/json"}
        self.status_code = status
        self.closed = False

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "err",
                request=None,
                response=None,  # type: ignore[arg-type]
            )

    def json(self) -> Any:
        return json.loads(self.text)

    def close(self) -> None:
        self.closed = True


class _FakeClient:
    """httpx.Client stand-in: pops scripted responses in order."""

    def __init__(self, script: list[object]) -> None:
        self._script = list(script)
        #: ``Mcp-Session-Id`` of every DELETE (session termination).
        self.deleted: list[str] = []

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def post(self, *_a: object, **_k: object) -> object:
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def delete(self, *_a: object, headers: dict[str, str], **_k: object) -> _FakeResp:
        self.deleted.append(headers["Mcp-Session-Id"])
        return _FakeResp(text="")


def _ok_rpc() -> _FakeResp:
    return _FakeResp(text=json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}))


def _err_rpc(message: str = "boom", *, is_error: bool = False) -> _FakeResp:
    if is_error:
        return _FakeResp(
            text=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"isError": True, "content": [{"type": "text", "text": message}]},
                }
            )
        )
    return _FakeResp(
        text=json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": message}})
    )


class TestApplyCommandsViaMcp:
    """Scripted-client coverage for apply_commands_via_mcp."""

    def _cmd(self, tool: str, **args: object) -> dict:
        return {"tool": tool, "args": args}

    def test_session_init_failure_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        from rebrew.ghidra.client import McpError, apply_commands_via_mcp

        script: list[object] = [httpx.ConnectError("conn refused")]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        with pytest.raises(McpError, match="Failed to initialize MCP session") as ei:
            apply_commands_via_mcp([self._cmd("create-function", address="0x1000")])
        assert ei.value.kind == "network"
        assert ei.value.retryable is True
        assert ei.value.status_code is None

    def test_no_session_id_warns_and_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"content-type": "application/json"}),  # init, no session id
            _ok_rpc(),  # initialized notification
            _ok_rpc(),  # the one command
        ]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        success, errors = apply_commands_via_mcp([self._cmd("create-function", address="0x1000")])
        assert (success, errors) == (1, 0)

    def test_success_flow_with_progress_and_rate_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),  # init
            _ok_rpc(),  # initialized
        ] + [_ok_rpc()] * 100  # 100 create-function commands
        fake = _FakeClient(script)
        monkeypatch.setattr("httpx.Client", lambda **kw: fake)
        cmds = [self._cmd("create-function", address=f"0x{i:x}") for i in range(100)]
        success, errors = apply_commands_via_mcp(cmds)
        assert (success, errors) == (100, 0)
        # The server-side session is terminated, not left to accumulate.
        assert fake.deleted == ["s1"]

    def test_phase_transition_and_tool_error_suppression(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
        ] + [_err_rpc()] * 31  # 31 failing commands of two tools
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        cmds = [self._cmd("create-function", address="0x1")] * 30 + [
            self._cmd("create-label", address="0x2")
        ]
        success, errors = apply_commands_via_mcp(cmds)
        assert (success, errors) == (0, 31)

    def test_already_exists_counts_as_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
            _err_rpc("Label already exists", is_error=True),
        ]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        success, errors = apply_commands_via_mcp([self._cmd("create-label", address="0x1000")])
        assert (success, errors) == (1, 0)

    def test_result_without_content_is_not_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A JSON-RPC success with no tool-result content cannot confirm the op
        landed; it counts as an error rather than as applied."""
        from rebrew.ghidra.client import apply_commands_via_mcp

        no_content = _FakeResp(text=json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}))
        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
            no_content,
        ]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        success, errors = apply_commands_via_mcp([self._cmd("create-function", address="0x1000")])
        assert (success, errors) == (0, 1)

    def test_struct_failure_retried_and_resolved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
            _err_rpc("parse error", is_error=True),  # first attempt fails
            _ok_rpc(),  # retry succeeds
        ]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        cmd = self._cmd("parse-c-structure", address="0x1000", cDefinition="struct A { int x; };")
        success, errors = apply_commands_via_mcp([cmd])
        assert (success, errors) == (1, 0)

    def test_struct_permanent_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Three failing structs, each pass resolves one → retry 2 hits PERMANENT FAIL."""
        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
            # cmd loop: A, B, C all fail
            _err_rpc("no such struct"),
            _err_rpc("no such struct"),
            _err_rpc("no such struct"),
            # retry 0: A, B fail; C resolves → still_failing=[A, B]
            _err_rpc("no such struct"),
            _err_rpc("no such struct"),
            _ok_rpc(),
            # retry 1: A fails; B resolves → still_failing=[A]
            _err_rpc("no such struct"),
            _ok_rpc(),
            # retry 2 (last): A fails → PERMANENT FAIL
            _err_rpc("no such struct"),
        ]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        cmds = [
            self._cmd("parse-c-structure", address="0x1", cDefinition="struct A { int x; };"),
            self._cmd("parse-c-structure", address="0x2", cDefinition="struct B { int y; };"),
            self._cmd("parse-c-structure", address="0x3", cDefinition="struct C { int z; };"),
        ]
        success, errors = apply_commands_via_mcp(cmds)
        # B and C resolve on retry passes; A permanently fails.
        assert (success, errors) == (2, 1)

    def test_metadata_next_start_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No nextStartIndex in metadata → advances by batch_size and stops at total."""
        from rebrew.ghidra.client import fetch_all_symbols

        pages = [
            [{"totalCount": 2}, {"address": "0x1000", "name": "a"}],
            [{"totalCount": 2}, {"address": "0x1001", "name": "b"}],
            [],  # should not be reached
        ]

        def _fake(*_a: object, **_k: object) -> list:
            return pages.pop(0)

        monkeypatch.setattr("rebrew.ghidra.client.fetch_mcp_tool", _fake)
        syms = fetch_all_symbols(None, "http://x", "/prog", "s", batch_size=1)  # type: ignore[arg-type]
        assert len(syms) == 2

    def test_missing_sse_response_is_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
            _FakeResp(
                text="event: x\ndata: {bad\n\n", headers={"content-type": "text/event-stream"}
            ),
        ]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        success, errors = apply_commands_via_mcp([self._cmd("create-function", address="0x1")])
        assert (success, errors) == (0, 1)

    def test_iserror_without_content_uses_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
            _FakeResp(
                text=json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": []}}
                )
            ),
        ]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        success, errors = apply_commands_via_mcp([self._cmd("create-function", address="0x1")])
        assert (success, errors) == (0, 1)

    def test_http_error_on_struct_command(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
            httpx.ConnectError("socket closed"),  # cmd loop
            httpx.ConnectError("socket closed"),  # retry 0 → no resolve → break
        ]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        success, errors = apply_commands_via_mcp(
            [self._cmd("parse-c-structure", address="0x1", cDefinition="struct A { int x; };")]
        )
        assert (success, errors) == (0, 1)

    def test_http_error_suppression_threshold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
        ] + [httpx.ConnectError("socket closed")] * 31
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        cmds = [self._cmd("set-bookmark", address=f"0x{i:x}") for i in range(31)]
        success, errors = apply_commands_via_mcp(cmds)
        assert (success, errors) == (0, 31)

    def test_empty_body_and_invalid_json_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
            _FakeResp(text=""),  # empty body
            _FakeResp(text="not json"),  # invalid JSON
        ]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        cmds = [
            self._cmd("create-function", address="0x1"),
            self._cmd("create-function", address="0x2"),
        ]
        success, errors = apply_commands_via_mcp(cmds)
        assert (success, errors) == (0, 2)

    def test_sse_response_and_http_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        from rebrew.ghidra.client import McpApplyAborted, apply_commands_via_mcp

        sse_ok = _FakeResp(
            text='data: {"jsonrpc":"2.0","id":1,"result":{"content":[]}}\n\n',
            headers={"content-type": "text/event-stream"},
        )
        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
            sse_ok,  # command ok via SSE body
            httpx.ConnectError("socket closed"),  # command raises HTTPError
        ]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        cmds = [
            self._cmd("set-comment", address="0x1"),
            self._cmd("set-comment", address="0x2"),
        ]
        # The first op landed before the transport died: abort with progress
        # instead of returning counts a fallback would re-apply.
        with pytest.raises(McpApplyAborted) as excinfo:
            apply_commands_via_mcp(cmds)
        assert excinfo.value.applied == 2
        assert excinfo.value.errors == 1


class TestIdempotentSuccess:
    """_is_idempotent_success pins the error to the op: same noun/address,
    never a substring match on unrelated errors."""

    def test_label_noun_match_counts(self) -> None:
        from rebrew.ghidra.client import _is_idempotent_success

        op = {"tool": "create-label", "args": {"addressOrSymbol": "0x1000"}}
        assert _is_idempotent_success(op, "Label already exists") is True

    def test_op_plus_address_match_counts(self) -> None:
        from rebrew.ghidra.client import _is_idempotent_success

        op = {"tool": "create-function", "args": {"address": "0x1000"}}
        assert _is_idempotent_success(op, "create-function 0x1000: already exists") is True

    def test_different_address_rejected(self) -> None:
        from rebrew.ghidra.client import _is_idempotent_success

        op = {"tool": "create-label", "args": {"addressOrSymbol": "0x1000"}}
        assert _is_idempotent_success(op, "create-label 0x2000 already exists") is False

    def test_different_operation_rejected(self) -> None:
        from rebrew.ghidra.client import _is_idempotent_success

        op = {"tool": "create-label", "args": {"addressOrSymbol": "0x1000"}}
        assert _is_idempotent_success(op, "create-function 0x1000 already exists") is False

    def test_different_operation_space_form_rejected(self) -> None:
        """The server may spell the other op with a space — it must still be
        rejected (only the hyphenated slug was matched before)."""
        from rebrew.ghidra.client import _is_idempotent_success

        op = {"tool": "create-label", "args": {"addressOrSymbol": "0x1000"}}
        assert _is_idempotent_success(op, "create function 0x1000 already exists") is False
        assert _is_idempotent_success(op, "create_function 0x1000: duplicate") is False

    def test_different_operation_bare_noun_rejected(self) -> None:
        """The server may name the other op without its slug."""
        from rebrew.ghidra.client import _is_idempotent_success

        op = {"tool": "create-label", "args": {"addressOrSymbol": "0x1000"}}
        assert _is_idempotent_success(op, "function 0x1000 already exists") is False

    def test_padded_address_is_the_same_address(self) -> None:
        """Addresses compare numerically: an op carrying 0x00001000 matches a
        server payload echoing 0x1000."""
        from rebrew.ghidra.client import _is_idempotent_success

        op = {"tool": "create-function", "args": {"address": "0x00001000"}}
        assert _is_idempotent_success(op, "create-function 0x1000 already exists") is True

    def test_unrelated_error_with_substring_rejected(self) -> None:
        from rebrew.ghidra.client import _is_idempotent_success

        op = {"tool": "set-comment", "args": {"addressOrSymbol": "0x1000"}}
        assert _is_idempotent_success(op, "failed: output file already exists on disk") is False

    def test_no_marker_rejected(self) -> None:
        from rebrew.ghidra.client import _is_idempotent_success

        op = {"tool": "create-label", "args": {"addressOrSymbol": "0x1000"}}
        assert _is_idempotent_success(op, "connection reset") is False

    def test_parse_c_structure_duplicate_name_counts(self) -> None:
        """A sync re-push / dependency retry that hits Ghidra's typed
        DuplicateNameException must count as success (type already present)."""
        from rebrew.ghidra.client import _is_idempotent_success

        op = {
            "tool": "parse-c-structure",
            "args": {"cDefinition": "struct A { int x; };"},
        }
        assert _is_idempotent_success(op, "DuplicateNameException: already exists") is True

    def test_parse_c_structure_structure_noun_counts(self) -> None:
        from rebrew.ghidra.client import _is_idempotent_success

        op = {
            "tool": "parse-c-structure",
            "args": {"cDefinition": "struct A { int x; };"},
        }
        assert _is_idempotent_success(op, "structure A already exists") is True

    def test_set_comment_noun_counts(self) -> None:
        from rebrew.ghidra.client import _is_idempotent_success

        op = {"tool": "set-comment", "args": {"addressOrSymbol": "0x1000"}}
        assert _is_idempotent_success(op, "comment already exists at 0x1000") is True

    def test_set_bookmark_noun_counts(self) -> None:
        from rebrew.ghidra.client import _is_idempotent_success

        op = {"tool": "set-bookmark", "args": {"addressOrSymbol": "0x1000"}}
        assert _is_idempotent_success(op, "bookmark already exists") is True

    def test_prototype_does_not_false_reject_create_function(self) -> None:
        """``set-function-prototype`` shares the substring ``function`` with
        ``create-function`` — a valid create-function re-apply must still count."""
        from rebrew.ghidra.client import _is_idempotent_success

        op = {"tool": "create-function", "args": {"address": "0x1000"}}
        assert _is_idempotent_success(op, "function 0x1000 already exists") is True


class TestApplyAbort:
    """A transport failure after ops landed raises McpApplyAborted (partial
    progress) instead of silently returning counts the caller would re-apply."""

    def _cmd(self, tool: str, **args: object) -> dict:
        return {"tool": tool, "args": args}

    def test_abort_after_partial_application(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        from rebrew.ghidra.client import McpApplyAborted, apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
            _ok_rpc(),  # first op lands
            httpx.ConnectError("conn reset"),  # transport dies on the second
        ]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        cmds = [
            self._cmd("create-function", address="0x1000"),
            self._cmd("create-function", address="0x2000"),
        ]
        with pytest.raises(McpApplyAborted) as excinfo:
            apply_commands_via_mcp(cmds)
        assert excinfo.value.applied == 2  # 1 success + 1 transport error
        assert excinfo.value.errors == 1

    def test_first_op_failure_still_returns_counts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Nothing applied before the failure: plain (0, 1) counts so the
        caller may fall back safely."""
        import httpx

        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
            httpx.ConnectError("conn refused"),  # first op, nothing applied
        ]
        monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(script))
        success, errors = apply_commands_via_mcp([self._cmd("create-function", address="0x1000")])
        assert (success, errors) == (0, 1)


class TestEndMcpSession:
    """``end_mcp_session`` releases the server-side session, best-effort."""

    def test_sends_delete_with_session_id(self) -> None:
        from rebrew.ghidra.client import end_mcp_session

        fake = _FakeClient([])
        end_mcp_session(fake, "http://x", "sess-9")  # type: ignore[arg-type]
        assert fake.deleted == ["sess-9"]

    def test_empty_session_id_is_noop(self) -> None:
        from rebrew.ghidra.client import end_mcp_session

        fake = _FakeClient([])
        end_mcp_session(fake, "http://x", "")  # type: ignore[arg-type]
        assert fake.deleted == []

    def test_transport_error_is_swallowed(self) -> None:
        import httpx

        from rebrew.ghidra.client import end_mcp_session

        class _Down:
            calls = 0

            def delete(self, *_a: object, **_k: object) -> None:
                self.calls += 1
                raise httpx.ConnectError("refused")

        down = _Down()
        end_mcp_session(down, "http://x", "sess-9")  # type: ignore[arg-type]
        assert down.calls == 1
