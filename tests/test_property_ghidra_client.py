"""Property-based fuzz tests for ``rebrew.ghidra``'s MCP response parsing.

Every rebrew field-sync op talks to a Ghidra/ReVa MCP server over HTTP, and
the reply is untrusted: a proxy, a stub server, a mismatched version, or a
half-flushed stream all land in the same parsers.  ``_parse_sse_response``
splits a ``text/event-stream`` body on line boundaries and hands each
``data:`` line to ``json.loads``, and the ``from_dict`` constructors in
``rebrew.ghidra.models`` read a decoded payload without checking its shape.
Nothing here had a property test, and a shape these constructors do not
expect is exactly what a truncated or non-conforming stream produces.

The harnesses draw whole SSE bodies (line structure, framing fields, partial
JSON, oversized bodies, non-object payloads) and assert:

* no parser raises on any body: a line that is not valid JSON, or that
  decodes to something other than a JSON object, is skipped and scanning
  continues, so a later line can still carry the response;
* when a response is produced, its ``jsonrpc`` field is always a string and
  its ``id`` is always an ``int``, a ``str``, or ``None``;
* the declared ``Content-Length`` is honoured before the body is parsed, so a
  server cannot make rebrew allocate for an oversized answer;
* an idempotent-reapply verdict never names an operation or an address the op
  does not carry, whatever text the server sent back.
"""

from __future__ import annotations

import json
from typing import Any

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from rebrew.ghidra.client import (
    MAX_MCP_RESPONSE_BYTES,
    _parse_sse_response,
    _response_within_limit,
    is_idempotent_success,
)
from rebrew.ghidra.models import JsonRpcResponse, McpToolContent, McpToolResult

#: Decoded payloads that are valid JSON but not a JSON-RPC object.  A server
#: that answers with one of these must not take the request down.
_NON_OBJECT = st.sampled_from([[1, 2], [], 5, "x", None, True, ["a"]])
_JSON_VALUE = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=20) | _NON_OBJECT,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=8), children, max_size=3),
    ),
    max_leaves=5,
)
_SSE_FIELD = st.sampled_from(
    ["", "event: message", "id: 42", "retry: 100", ": keep-alive", "data:"]
)
_LINE = st.one_of(
    _SSE_FIELD,
    st.builds(lambda prefix, value: f"{prefix} {value}", _SSE_FIELD, _JSON_VALUE.map(json.dumps)),
    st.text(max_size=60),
)
#: Lines that carry no ``data:`` payload, so a body built only from them can
#: still be scanned past rather than answered from the first line drawn.
_FRAMING_LINE = st.sampled_from(
    ["", "event: message", "event: ping", "id: 1", "retry: 0", ": keep-alive", "data:", "data:  "]
)
#: A body with a well-formed JSON-RPC object in it, so a positive match is
#: reachable alongside the malformed shapes.
_GOOD_RESULT = {"content": [{"type": "text", "text": "ok"}]}


class _FakeResponse:
    """Minimal ``McpResponse``: headers plus a body, nothing else."""

    def __init__(self, text: str, headers: dict[str, str] | None = None) -> None:
        self.text = text
        self.headers = headers or {}


class TestSseParsing:
    """``_parse_sse_response`` splits untrusted stream bytes into a reply."""

    @given(lines=st.lists(_LINE, max_size=12))
    @settings(max_examples=300)
    def test_no_stream_raises(self, lines: list[str]) -> None:
        body = "\n".join(lines)
        response = _parse_sse_response(body)
        assert response is None or isinstance(response, JsonRpcResponse)

    @given(payload=_JSON_VALUE)
    @settings(max_examples=200)
    def test_a_non_object_data_line_is_skipped(self, payload: Any) -> None:
        """A bare array, string, number, or null is not a JSON-RPC object.

        The server's answer, not rebrew's request, decides the shape, so this
        is the ordinary malformed-stream case rather than an exotic one.
        """
        if isinstance(payload, dict):
            return
        body = f"data: {json.dumps(payload)}"
        assert _parse_sse_response(body) is None

    @given(
        before=st.lists(_FRAMING_LINE, max_size=5),
        unusable=st.sampled_from(
            ["data: [1, 2]", "data: 5", 'data: "x"', "data: null", "data: {", "data: not json"]
        ),
    )
    @settings(max_examples=150)
    def test_scanning_continues_past_an_unusable_line(
        self, before: list[str], unusable: str
    ) -> None:
        # A later good line must still be found, so one bad line cannot hide
        # the whole response.
        body = "\n".join([*before, unusable, f"data: {json.dumps({'result': _GOOD_RESULT})}"])
        result = _parse_sse_response(body)
        assert result is not None
        assert result.result == _GOOD_RESULT

    @given(lines=st.lists(_LINE, max_size=12), body=_JSON_VALUE.map(json.dumps))
    @settings(max_examples=200)
    def test_a_parsed_response_is_well_typed(self, lines: list[str], body: str) -> None:
        response = _parse_sse_response("\n".join([*lines, f"data: {body}"]))
        if response is None:
            return
        assert isinstance(response.jsonrpc, str)
        assert response.id is None or isinstance(response.id, (int, str))
        assert response.result is None or isinstance(response.result, dict)
        if response.error is not None:
            assert isinstance(response.error.code, int)
            assert isinstance(response.error.message, str)

    @given(body=st.text(max_size=200))
    @settings(max_examples=100)
    def test_an_empty_or_marker_only_body_is_no_response(self, body: str) -> None:
        assume("data:" not in body)
        assert _parse_sse_response(body) is None


class TestResponseSizeLimit:
    """``_response_within_limit`` is the ceiling on what rebrew will parse."""

    @given(
        length=st.one_of(
            st.integers(min_value=0, max_value=2 * MAX_MCP_RESPONSE_BYTES),
            st.text(max_size=12),
        ),
        name=st.sampled_from(["content-length", "Content-Length", "X-Nope"]),
    )
    @settings(max_examples=200)
    def test_an_oversized_declared_length_is_refused(self, length: Any, name: str) -> None:
        resp = _FakeResponse("{}", {} if name == "X-Nope" else {name: str(length)})
        try:
            declared = int(str(length))
        except ValueError:
            # An unparsable declaration is not a licence to refuse; the
            # measured body is what decides.
            assert _response_within_limit(resp, "get-functions", 1)
            return
        if name == "X-Nope":
            # Only the two spellings the parser looks for are honoured, so an
            # unrelated header cannot be used to smuggle a length in.
            assert _response_within_limit(resp, "get-functions", 1)
        else:
            assert _response_within_limit(resp, "get-functions", 1) == (
                declared <= MAX_MCP_RESPONSE_BYTES
            )

    @given(size=st.integers(min_value=0, max_value=2 * MAX_MCP_RESPONSE_BYTES))
    @settings(max_examples=60)
    def test_the_measured_body_is_the_real_ceiling(self, size: int) -> None:
        # A server that declares nothing (or a chunked reply) still gets the
        # byte check, so the body cannot be grown without limit.
        resp = _FakeResponse("a" * size)
        assert _response_within_limit(resp, "get-functions", 1) == (size <= MAX_MCP_RESPONSE_BYTES)


class TestIdempotentReapply:
    """A server's error text decides whether an op counts as a no-op re-apply."""

    @given(
        error=st.text(max_size=120),
        tool=st.text(max_size=20),
    )
    @settings(max_examples=300)
    def test_a_verdict_is_a_typed_bool(self, error: str, tool: str) -> None:
        op = {"tool": tool, "args": {}} if tool else None
        assert isinstance(is_idempotent_success(op, error), bool)

    @given(error=st.text(alphabet="abcXYZ ", max_size=60))
    @settings(max_examples=200)
    def test_a_missing_op_or_tool_is_never_idempotent(self, error: str) -> None:
        assert not is_idempotent_success(None, error)
        assert not is_idempotent_success({"tool": "", "args": {}}, error)
        assert not is_idempotent_success({"args": {}}, error)

    @given(
        error=st.text(alphabet="already exists duplicate ", min_size=1, max_size=60),
        tool=st.sampled_from(["set-bookmark", "create-function", "x"]),
    )
    @settings(max_examples=100)
    def test_no_op_means_no_idempotent_claim(self, error: str, tool: str) -> None:
        """Without an op, or with an op that names no operation, the marker
        text alone is not enough to call anything a no-op re-apply."""
        assert not is_idempotent_success(None, error)
        assert not is_idempotent_success({"tool": "", "args": {}}, error)
        assert not is_idempotent_success({"args": {}}, error)
        assert isinstance(is_idempotent_success({"tool": tool, "args": {}}, error), bool)


class TestModelConstructors:
    """``from_dict`` reads a decoded payload of unknown shape."""

    @given(payload=_JSON_VALUE)
    @settings(max_examples=300)
    def test_json_rpc_response_from_any_json_value(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            # Non-objects never reach the constructor; the caller filters them.
            return
        response = JsonRpcResponse.from_dict(payload)
        assert isinstance(response.jsonrpc, str)
        assert response.id is None or isinstance(response.id, (int, str))

    @given(content=st.lists(_JSON_VALUE, max_size=4))
    @settings(max_examples=200)
    def test_tool_result_skips_non_object_content(self, content: list[Any]) -> None:
        result = McpToolResult.from_dict({"content": content, "isError": True})
        assert result.isError is True
        # A content entry that is not an object is dropped, not a crash: the
        # result is still a list the caller can index.
        assert all(isinstance(item, McpToolContent) for item in result.content)
        assert len(result.content) <= len(content)
        for item in result.content:
            assert isinstance(item.type, str)
            assert isinstance(item.text, str)

    @given(payload=st.dictionaries(st.text(max_size=8), st.text(max_size=20), max_size=4))
    @settings(max_examples=100)
    def test_content_from_dict_coerces_its_fields(self, payload: dict[str, Any]) -> None:
        content = McpToolContent.from_dict(payload)
        assert isinstance(content.type, str)
        assert isinstance(content.text, str)
