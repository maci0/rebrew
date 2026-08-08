"""Tests for ghidra/client.py — SSE parsing and MCP tool calls."""

import json
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from rebrew.ghidra.client import _call_mcp_tool, _parse_sse_response


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
    )
    client = SimpleNamespace(post=lambda *a, **k: resp)
    return client, resp


class TestCallMcpTool:
    def test_json_response(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }
        client, _ = _mock_client(text=json.dumps(payload))
        result = _call_mcp_tool(client, "http://x", "get-functions", {}, 1, "")
        assert result is not None

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

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "err",
                request=None,
                response=None,  # type: ignore[arg-type]
            )

    def json(self) -> Any:
        return json.loads(self.text)


class _FakeClient:
    """httpx.Client stand-in: pops scripted responses in order."""

    def __init__(self, script: list[object]) -> None:
        self._script = list(script)

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def post(self, *_a: object, **_k: object) -> object:
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


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

        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [httpx.ConnectError("conn refused")]
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
        with pytest.raises(RuntimeError, match="Failed to initialize MCP session"):
            apply_commands_via_mcp([self._cmd("create-function", address="0x1000")])

    def test_no_session_id_warns_and_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"content-type": "application/json"}),  # init, no session id
            _ok_rpc(),  # initialized notification
            _ok_rpc(),  # the one command
        ]
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
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
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
        cmds = [self._cmd("create-function", address=f"0x{i:x}") for i in range(100)]
        success, errors = apply_commands_via_mcp(cmds)
        assert (success, errors) == (100, 0)

    def test_phase_transition_and_tool_error_suppression(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
        ] + [_err_rpc()] * 31  # 31 failing commands of two tools
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
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
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
        success, errors = apply_commands_via_mcp([self._cmd("create-label", address="0x1000")])
        assert (success, errors) == (1, 0)

    def test_struct_failure_retried_and_resolved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.ghidra.client import apply_commands_via_mcp

        script: list[object] = [
            _FakeResp(headers={"Mcp-Session-Id": "s1"}),
            _ok_rpc(),
            _err_rpc("parse error", is_error=True),  # first attempt fails
            _ok_rpc(),  # retry succeeds
        ]
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
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
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
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
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
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
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
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
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
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
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
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
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
        cmds = [
            self._cmd("create-function", address="0x1"),
            self._cmd("create-function", address="0x2"),
        ]
        success, errors = apply_commands_via_mcp(cmds)
        assert (success, errors) == (0, 2)

    def test_sse_response_and_http_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        from rebrew.ghidra.client import apply_commands_via_mcp

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
        monkeypatch.setattr("rebrew.ghidra.client.httpx.Client", lambda **kw: _FakeClient(script))
        cmds = [
            self._cmd("set-comment", address="0x1"),
            self._cmd("set-comment", address="0x2"),
        ]
        success, errors = apply_commands_via_mcp(cmds)
        assert (success, errors) == (1, 1)
